/**
 * Copyright 2018 VMware
 * Copyright 2018 Ted Yin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cassert>
#include <stack>

#include "hotstuff/util.h"
#include "hotstuff/consensus.h"

#define LOG_INFO HOTSTUFF_LOG_INFO
#define LOG_DEBUG HOTSTUFF_LOG_DEBUG
#define LOG_WARN HOTSTUFF_LOG_WARN
#define LOG_PROTO HOTSTUFF_LOG_PROTO

namespace hotstuff {

/* The core logic of HotStuff, is fairly simple :). */
/*** begin HotStuff protocol logic ***/
HotStuffCore::HotStuffCore(ReplicaID id,
                            privkey_bt &&priv_key):
        b0(new Block(true, 1)),
        hqc(std::make_pair(b0, nullptr)),
        bexec(b0),
        vheight(0),
        view(0),
        view_trans(false),
        conflict_idx(-1),
        priv_key(std::move(priv_key)),
        tails{b0},
        neg_vote(false),
        id(id),
        storage(new EntityStorage()) {
    storage->add_blk(b0);
    b0->qc_ref = b0;
    blame_qc = create_quorum_cert(Blame::proof_text_hash(view));
}

void HotStuffCore::sanity_check_delivered(const block_t &blk) {
    if (!blk->delivered)
        throw std::runtime_error("block not delivered");
}

block_t HotStuffCore::get_delivered_blk(const uint256_t &blk_hash) {
    block_t blk = storage->find_blk(blk_hash);
    if (blk == nullptr || !blk->delivered)
        throw std::runtime_error("block not delivered");
    return std::move(blk);
}

bool HotStuffCore::on_deliver_blk(const block_t &blk) {
    if (blk->delivered)
    {
        LOG_WARN("attempt to deliver a block twice");
        return false;
    }
    blk->parents.clear();
    for (const auto &hash: blk->parent_hashes)
        blk->parents.push_back(get_delivered_blk(hash));
    blk->height = blk->parents[0]->height + 1;

    if (blk->qc)
    {
        block_t _blk = storage->find_blk(blk->qc->get_blk_hash());
        if (_blk == nullptr)
            throw std::runtime_error("block referred by qc not fetched");
        blk->qc_ref = std::move(_blk);
    } // otherwise blk->qc_ref remains null

    for (auto pblk: blk->parents) tails.erase(pblk);
    tails.insert(blk);

    blk->delivered = true;
    LOG_DEBUG("deliver %s", std::string(*blk).c_str());
    return true;
}

void HotStuffCore::check_commit(const block_t &p) {
    std::vector<block_t> commit_queue;
    block_t b;
    for (b = p; b->height > bexec->height; b = b->parents[0])
    { /* TODO: also commit the uncles/aunts */
        commit_queue.push_back(b);
    }
    if (b != bexec)
        throw std::runtime_error("safety breached :( " +
                                std::string(*p) + " " +
                                std::string(*bexec));
    for (auto it = commit_queue.rbegin(); it != commit_queue.rend(); it++)
    {
        const block_t &blk = *it;
        blk->decision = 1;
        LOG_PROTO("commit %s", std::string(*blk).c_str());
        size_t idx = 0;
        for (auto cmd: blk->cmds)
            do_decide(Finality(id, 1, idx, blk->height,
                                cmd, blk->get_hash()));
    }
    bexec = p;
}

// TODO: the following two look okay, but needs some scrutiny

bool HotStuffCore::update_hqc(const block_t &_bqc, const quorum_cert_bt &qc) {
    assert(qc->get_blk_hash() == Vote::proof_text_hash(_bqc->get_hash()));
    if (_bqc->height > hqc.first->height)
    {
        hqc = std::make_pair(_bqc, qc->clone());
        on_hqc_update();
    }
    return true;
}

bool HotStuffCore::update(const uint256_t &bqc_hash) {
    block_t _bqc = get_delivered_blk(bqc_hash);
    if (_bqc->qc_ref == nullptr) return false;
    update_hqc(_bqc->qc_ref, _bqc->qc);
    return true;
}

// 2. Vote
void HotStuffCore::_vote(const block_t &blk) {
    const auto &blk_hash = blk->get_hash();
    Vote vote(id, blk_hash,
            create_part_cert(
                *priv_key,
                Vote::proof_text_hash(blk_hash)), this);
    on_receive_vote(vote);
    do_broadcast_vote(vote);
    set_commit_timer(blk, 2 * config.delta);
    set_blame_timer(3 * config.delta);
}

// 3. Blame
void HotStuffCore::_blame() {
    stop_blame_timer();
    Blame blame(id, view,
            create_part_cert(
                *priv_key,
                Blame::proof_text_hash(view)), this);
    on_receive_blame(blame);
    do_broadcast_blame(blame);
}

// i. New-view
void HotStuffCore::_new_view() {
    if (view_trans) return; // already in view transition
    blame_qc->compute();
    BlameNotify bn(view,
        hqc.first->get_hash(),
        hqc.second->clone(),
        blame_qc->clone(), this);
    on_receive_blamenotify(bn);
    do_broadcast_blamenotify(bn);
    stop_commit_timer_all();
    view_trans = true;
    set_viewtrans_timer(2 * config.delta);
}

void HotStuffCore::on_propose(const std::vector<uint256_t> &cmds,
                            const std::vector<block_t> &parents,
                            bytearray_t &&extra) {
    if (parents.empty())
        throw std::runtime_error("empty parents");
    for (const auto &_: parents) tails.erase(_);
    block_t p = parents[0];
    quorum_cert_bt qc = nullptr;
    block_t qc_ref = nullptr;
    /* a block can optionally carray a QC */
    if (p != b0 && p->voted.size() >= config.nmajority)
    {
        qc = p->self_qc->clone();
        qc_ref = p;
    }
    /* create the new block */
    block_t bnew = storage->add_blk(
        new Block(parents, cmds,
            std::move(qc), std::move(extra),
            p->height + 1,
            qc_ref,
            nullptr
        ));
    const uint256_t bnew_hash = bnew->get_hash();
    bnew->self_qc = create_quorum_cert(Vote::proof_text_hash(bnew_hash));
    on_deliver_blk(bnew);
    Proposal prop(id, bnew, nullptr);
    LOG_PROTO("propose %s", std::string(*bnew).c_str());
    /* self-vote */
    if (bnew->height <= vheight)
        throw std::runtime_error("new block should be higher than vheight");
    vheight = bnew->height;
    _vote(bnew);
    on_propose_(prop);
    /* boradcast to other replicas */
    do_broadcast_proposal(prop);
}

void HotStuffCore::on_receive_proposal(const Proposal &prop) {
    if (!update(prop.bqc_hash)) return;
    LOG_PROTO("got %s", std::string(prop).c_str());
    block_t bnew = prop.blk;
    sanity_check_delivered(bnew);
    bool opinion = false;
    // TODO: shall we still use vheight?

    auto &pslot = proposals[bnew->height];
    if (pslot.size() <= 1)
    {
        pslot.insert(bnew);
        if (pslot.size() > 1)
        {
            // TODO: put equivocating blocks in the Blame msg
            _blame();
        }
        else opinion = true;
    }
    // opinion = false if equivocating

    if (opinion)
    {
        block_t pref = bqc->qc_ref;
        block_t b;
        for (b = bnew;
            b->height > pref->height;
            b = b->parents[0]);
        if (b == pref) /* on the same branch */
            vheight = bnew->height;
        else
            opinion = true;
    }
    LOG_PROTO("now state: %s", std::string(*this).c_str());
    if (bnew->qc_ref)
        on_qc_finish(bnew->qc_ref);
    on_receive_proposal_(prop);
    // check if the proposal extends the highest certified block
    if (opinion) _vote(bnew);
}

// TODO: impl correct blame handler
void HotStuffCore::on_receive_vote(const Vote &vote) {
    if (!update(vote.bqc_hash)) return;
    LOG_PROTO("got %s", std::string(vote).c_str());
    LOG_PROTO("now state: %s", std::string(*this).c_str());
    block_t blk = get_delivered_blk(vote.blk_hash);
    if (!finished_propose[blk])
    {
        // FIXME: fill voter as proposer as a quickfix here, may be inaccurate
        // for some PaceMakers
        on_receive_proposal(Proposal(vote.voter, blk, nullptr));
        finished_propose[blk] = true;
    }
    size_t qsize = blk->voted.size();
    if (qsize >= config.nmajority) return;
    if (!blk->voted.insert(vote.voter).second)
    {
        LOG_WARN("duplicate vote from %d", vote.voter);
        return;
    }
    auto &qc = blk->self_qc;
    if (qc == nullptr)
    {
        LOG_WARN("vote for block not proposed by itself");
        qc = create_quorum_cert(Vote::proof_text_hash(blk->get_hash()));
    }
    qc->add_part(vote.voter, *vote.cert);
    if (++qsize == config.nmajority)
    {
        qc->compute();
        update_hqc(blk, qc);
        // no need to have extra Notify process
        //Notify notify(vote.blk_hash, qc->clone(), this);
        //on_receive_notify(notify); // deliver to itself
        //do_broadcast_notify(notify); // notify the others
        on_qc_finish(blk);
    }
}

// NOTE: Taken care of by BlameNotify
//void HotStuffCore::on_receive_notify(const Notify &notify) {
//}

void HotStuffCore::on_receive_blame(const Blame &blame) {
    size_t qsize = blamed.size();
    if (qsize >= config.nmajority) return;
    if (!blamed.insert(blame.blamer).second)
    {
        LOG_WARN("duplicate blame from %d", blame.blamer);
        return;
    }
    assert(blame_qc);
    blame_qc->add_part(blame.blamer, *blame.cert);
    if (++qsize == config.nmajority)
        _new_view();
}

void HotStuffCore::on_receive_blamenotify(const BlameNotify &bn) { _new_view(); }

void HotStuffCore::on_commit_timeout(const block_t &blk) { check_commit(blk); }

void HotStuffCore::on_blame_timeout() { _blame(); }

void HotStuffCore::on_viewtrans_timeout() {
    // view change
    view++;
    view_trans = false;
    proposals.clear();
    blame_qc = create_quorum_cert(Blame::proof_text_hash(view));
    blamed.clear();
    set_blame_timer(3 * config.delta);
    // TODO: send hqc to the next leader
}

/*** end HotStuff protocol logic ***/

void HotStuffCore::prune(uint32_t staleness) {
    block_t start;
    /* skip the blocks */
    for (start = bexec; staleness; staleness--, start = start->parents[0])
        if (!start->parents.size()) return;
    std::stack<block_t> s;
    start->qc_ref = nullptr;
    s.push(start);
    while (!s.empty())
    {
        auto &blk = s.top();
        if (blk->parents.empty())
        {
            storage->try_release_blk(blk);
            s.pop();
            continue;
        }
        blk->qc_ref = nullptr;
        s.push(blk->parents.back());
        blk->parents.pop_back();
    }
}

void HotStuffCore::add_replica(ReplicaID rid, const NetAddr &addr,
                                pubkey_bt &&pub_key) {
    config.add_replica(rid, 
            ReplicaInfo(rid, addr, std::move(pub_key)));
    b0->voted.insert(rid);
}

promise_t HotStuffCore::async_qc_finish(const block_t &blk) {
    if (blk->voted.size() >= config.nmajority)
        return promise_t([](promise_t &pm) {
            pm.resolve();
        });
    auto it = qc_waiting.find(blk);
    if (it == qc_waiting.end())
        it = qc_waiting.insert(std::make_pair(blk, promise_t())).first;
    return it->second;
}

void HotStuffCore::on_qc_finish(const block_t &blk) {
    auto it = qc_waiting.find(blk);
    if (it != qc_waiting.end())
    {
        it->second.resolve();
        qc_waiting.erase(it);
    }
}

promise_t HotStuffCore::async_wait_proposal() {
    return propose_waiting.then([](const Proposal &prop) {
        return prop;
    });
}

promise_t HotStuffCore::async_wait_receive_proposal() {
    return receive_proposal_waiting.then([](const Proposal &prop) {
        return prop;
    });
}

promise_t HotStuffCore::async_bqc_update() {
    return bqc_update_waiting.then([this]() {
        return bqc;
    });
}

void HotStuffCore::on_propose_(const Proposal &prop) {
    auto t = std::move(propose_waiting);
    propose_waiting = promise_t();
    t.resolve(prop);
}

void HotStuffCore::on_receive_proposal_(const Proposal &prop) {
    auto t = std::move(receive_proposal_waiting);
    receive_proposal_waiting = promise_t();
    t.resolve(prop);
}

void HotStuffCore::on_hqc_update() {
    auto t = std::move(bqc_update_waiting);
    bqc_update_waiting = promise_t();
    t.resolve();
}

HotStuffCore::operator std::string () const {
    DataStream s;
    s << "<hotstuff "
      << "hqc.qc_ref=" << get_hex10(hqc->qc_ref->get_hash()) << " "
      << "hqc.qc_ref.height=" << std::to_string(bqc->qc_ref->height) << " "
      << "bexec=" << get_hex10(bexec->get_hash()) << " "
      << "vheight=" << std::to_string(vheight) << " "
      << "view=" << std::to_string(view) << " "
      << "tails=" << std::to_string(tails.size()) << ">";
    return std::move(s);
}

}
