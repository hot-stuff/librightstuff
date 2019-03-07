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

#ifndef _HOTSTUFF_LIVENESS_H
#define _HOTSTUFF_LIVENESS_H

#include "salticidae/util.h"
#include "hotstuff/consensus.h"

namespace hotstuff {

using salticidae::_1;
using salticidae::_2;

/** Abstraction for liveness gadget (oracle). */
class PaceMaker {
    protected:
    HotStuffCore *hsc;
    public:
    virtual ~PaceMaker() = default;
    /** Initialize the PaceMaker. A derived class should also call the
     * default implementation to set `hsc`. */
    virtual void init(HotStuffCore *_hsc) { hsc = _hsc; }
    /** Get a promise resolved when the pace maker thinks it is a *good* time
     * to issue new commands. When promise is resolved, the replica should
     * propose the command. */
    virtual promise_t beat() = 0;
    /** Get the current proposer. */
    virtual ReplicaID get_proposer() = 0;
    /** Select the parent blocks for a new block.
     * @return Parent blocks. The block at index 0 is the direct parent, while
     * the others are uncles/aunts. The returned vector should be non-empty. */
    virtual std::vector<block_t> get_parents() = 0;
    /** Get a promise resolved when the pace maker thinks it is a *good* time
     * to vote for a block. The promise is resolved with the next proposer's ID
     * */
    virtual promise_t beat_resp(ReplicaID last_proposer) = 0;
    /** Impeach the current proposer. */
    virtual void impeach() {}
};

using pacemaker_bt = BoxObj<PaceMaker>;

/** Parent selection implementation for PaceMaker: select all parents.
 * PaceMakers derived from this class will select the highest block as the
 * direct parent, while including other tail blocks (up to parent_limit) as
 * uncles/aunts. */
class PMAllParents: public virtual PaceMaker {
    block_t bqc_tail;
    const int32_t parent_limit;         /**< maximum number of parents */
    
    void reg_bqc_update() {
        hsc->async_bqc_update().then([this](const block_t &bqc) {
            //const auto &pref = bqc->get_qc_ref();
            const auto &pref = bqc;
            for (const auto &blk: hsc->get_tails())
            {
                block_t b;
                for (b = blk;
                    b->get_height() > pref->get_height();
                    b = b->get_parents()[0]);
                if (b == pref && blk->get_height() > bqc_tail->get_height())
                    bqc_tail = blk;
            }
            reg_bqc_update();
        });
    }

    void reg_proposal() {
        hsc->async_wait_proposal().then([this](const Proposal &prop) {
            bqc_tail = prop.blk;
            reg_proposal();
        });
    }

    void reg_receive_proposal() {
        hsc->async_wait_receive_proposal().then([this](const Proposal &prop) {
            //const auto &pref = hsc->get_bqc()->get_qc_ref();
            const auto &pref = hsc->get_bqc();
            const auto &blk = prop.blk;
            block_t b;
            for (b = blk;
                b->get_height() > pref->get_height();
                b = b->get_parents()[0]);
            if (b == pref && blk->get_height() > bqc_tail->get_height())
                bqc_tail = blk;
            reg_receive_proposal();
        });
    }

    public:
    PMAllParents(int32_t parent_limit): parent_limit(parent_limit) {}
    void init() {
        bqc_tail = hsc->get_genesis();
        reg_bqc_update();
        reg_proposal();
        reg_receive_proposal();
    }

    std::vector<block_t> get_parents() override {
        const auto &tails = hsc->get_tails();
        std::vector<block_t> parents{bqc_tail};
        auto nparents = tails.size();
        if (parent_limit > 0)
            nparents = std::min(nparents, (size_t)parent_limit);
        nparents--;
        /* add the rest of tails as "uncles/aunts" */
        for (const auto &blk: tails)
        {
            if (blk != bqc_tail)
            {
                parents.push_back(blk);
                if (!--nparents) break;
            }
        }
        return std::move(parents);
    }
};

/** Beat implementation for PaceMaker: simply wait for the QC of last proposed
 * block.  PaceMakers derived from this class will beat only when the last
 * block proposed by itself gets its QC. */
class PMWaitQC: public virtual PaceMaker {
    std::queue<promise_t> pending_beats;
    block_t last_proposed;
    bool locked;
    promise_t pm_qc_finish;
    promise_t pm_wait_propose;

    protected:
    void schedule_next() {
        if (!pending_beats.empty() && !locked)
        {
            auto pm = pending_beats.front();
            pending_beats.pop();
            pm_qc_finish.reject();
            (pm_qc_finish = hsc->async_qc_finish(last_proposed))
                .then([this, pm]() {
                    pm.resolve(get_proposer());
                });
            locked = true;
        }
    }

    void update_last_proposed() {
        pm_wait_propose.reject();
        (pm_wait_propose = hsc->async_wait_proposal()).then(
                [this](const Proposal &prop) {
            last_proposed = prop.blk;
            locked = false;
            schedule_next();
            update_last_proposed();
        });
    }

    public:

    void on_view_trans() { locked = true; }
    void on_view_change() {
        ReplicaID proposer = get_proposer();
        if (proposer != hsc->get_id())
        {
            HOTSTUFF_LOG_INFO("%d drop %zu beats", proposer, pending_beats.size());
            while (!pending_beats.empty())
            {
                auto pm = pending_beats.front();
                pending_beats.pop();
                pm.resolve(proposer);
            }
            last_proposed = hsc->get_genesis();
            locked = false;
        }
        else
        {
            HOTSTUFF_LOG_INFO("resume %zu beats", pending_beats.size());
            last_proposed = hsc->get_genesis();
            locked = false;
            schedule_next();
        }
    }

    void init() {
        last_proposed = hsc->get_genesis();
        locked = false;
        update_last_proposed();
    }

    ReplicaID get_proposer() override {
        return hsc->get_id();
    }

    promise_t beat() override {
        promise_t pm;
        pending_beats.push(pm);
        schedule_next();
        return std::move(pm);
    }

    promise_t beat_resp(ReplicaID last_proposer) override {
        return promise_t([last_proposer](promise_t &pm) {
            pm.resolve(last_proposer);
        });
    }
};

/** Naive PaceMaker where everyone can be a proposer at any moment. */
struct PaceMakerDummy: public PMAllParents, public PMWaitQC {
    PaceMakerDummy(int32_t parent_limit):
        PMAllParents(parent_limit), PMWaitQC() {}
    void init(HotStuffCore *hsc) override {
        PaceMaker::init(hsc);
        PMAllParents::init();
        PMWaitQC::init();
    }
};

/** Naive PaceMaker where everyone can be a proposer at any moment. */
struct PaceMakerRR: public PaceMakerDummy {
    ReplicaID init_proposer;
    promise_t pm_view_change;
    promise_t pm_view_trans;

    void view_change() {
        pm_view_change.reject();
        pm_view_change = hsc->async_wait_view_change().then([this]() {
            PMWaitQC::on_view_change();
            view_change();
        });
    }

    void view_trans() {
        pm_view_trans.reject();
        pm_view_trans = hsc->async_wait_view_trans().then([this]() {
            PMWaitQC::on_view_trans();
            view_trans();
        });
    }

    public:
    PaceMakerRR(ReplicaID init_proposer,
                int32_t parent_limit):
        PaceMakerDummy(parent_limit),
        init_proposer(init_proposer) {}

    void init(HotStuffCore *hsc) override {
        PaceMakerDummy::init(hsc);
        view_change();
        view_trans();
    }
    // TODO: use async_wait_view_change to rotate the proposer

    ReplicaID get_proposer() override {
        return (init_proposer + hsc->get_view()) % hsc->get_config().nreplicas;
    }

    promise_t beat_resp(ReplicaID) override {
        return promise_t([this](promise_t &pm) {
            pm.resolve(get_proposer());
        });
    }
};

}

#endif
