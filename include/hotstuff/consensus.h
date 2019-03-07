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

#ifndef _HOTSTUFF_CONSENSUS_H
#define _HOTSTUFF_CONSENSUS_H

#include <cassert>
#include <set>
#include <unordered_map>

#include "hotstuff/promise.hpp"
#include "hotstuff/type.h"
#include "hotstuff/entity.h"
#include "hotstuff/crypto.h"

namespace hotstuff {

struct Proposal;
struct Vote;
struct Notify;
struct Blame;
struct BlameNotify;
struct Finality;

/** Abstraction for HotStuff protocol state machine (without network implementation). */
class HotStuffCore {
    block_t b0;                                  /** the genesis block */
    /* === state variables === */
    /** block containing the QC for the highest block having one */
    std::pair<block_t, quorum_cert_bt> hqc;
    block_t bexec;                            /**< last executed block */
    uint32_t vheight;          /**< height of the block last voted for */
    uint32_t nheight;          /**< height of the block last notified for */
    uint32_t view;             /**< the current view number */
    /* Q: does the proposer retry the same block in a new view? */
    /* === only valid for the current view === */
    bool progress; /**< whether heard a proposal in the current view: this->view */
    bool view_trans; /**< whether the replica is in-between the views */
    std::unordered_map<uint32_t, std::unordered_set<block_t>> proposals;
    std::unordered_map<block_t, bool> finished_propose;
    quorum_cert_bt blame_qc;
    std::unordered_set<ReplicaID> blamed;

    /* === auxilliary variables === */
    privkey_bt priv_key;            /**< private key for signing votes */
    std::set<block_t, BlockHeightCmp> tails;   /**< set of tail blocks */
    ReplicaConfig config;                   /**< replica configuration */
    /* === async event queues === */
    std::unordered_map<block_t, promise_t> qc_waiting;
    promise_t propose_waiting;
    promise_t receive_proposal_waiting;
    promise_t bqc_update_waiting;
    promise_t view_change_waiting;
    /* == feature switches == */
    /** always vote negatively, useful for some PaceMakers */
    bool neg_vote;

    block_t get_delivered_blk(const uint256_t &blk_hash);
    void sanity_check_delivered(const block_t &blk);
    void check_commit(const block_t &_bqc);
    bool update_hqc(const block_t &_hqc, const quorum_cert_bt &qc);
    void on_hqc_update();
    void on_qc_finish(const block_t &blk);
    void on_propose_(const Proposal &prop);
    void on_receive_proposal_(const Proposal &prop);
    void on_view_change();
    void _vote(const block_t &blk);
    void _blame();
    void _new_view();

    protected:
    ReplicaID id;                  /**< identity of the replica itself */

    public:
    BoxObj<EntityStorage> storage;

    HotStuffCore(ReplicaID id, privkey_bt &&priv_key);
    virtual ~HotStuffCore() {
        b0->qc_ref = nullptr;
    }

    /* Inputs of the state machine triggered by external events, should called
     * by the class user, with proper invariants. */

    /** Call to initialize the protocol, should be called once before all other
     * functions. */
    void on_init(uint32_t nfaulty, double delta);

    /* TODO: better name for "delivery" ? */
    /** Call to inform the state machine that a block is ready to be handled.
     * A block is only delivered if itself is fetched, the block for the
     * contained qc is fetched and all parents are delivered. The user should
     * always ensure this invariant. The invalid blocks will be dropped by this
     * function.
     * @return true if valid */
    bool on_deliver_blk(const block_t &blk);

    /** Call upon the delivery of a proposal message.
     * The block mentioned in the message should be already delivered. */
    void on_receive_proposal(const Proposal &prop);

    /** Call upon the delivery of a vote message.
     * The block mentioned in the message should be already delivered. */
    void on_receive_vote(const Vote &vote);
    void on_receive_notify(const Notify &notify);
    void on_receive_blame(const Blame &blame);
    void on_receive_blamenotify(const BlameNotify &blame);
    void on_commit_timeout(const block_t &blk);
    void on_blame_timeout();
    void on_viewtrans_timeout();

    /** Call to submit new commands to be decided (executed). "Parents" must
     * contain at least one block, and the first block is the actual parent,
     * while the others are uncles/aunts */
    void on_propose(const std::vector<uint256_t> &cmds,
                    const std::vector<block_t> &parents,
                    bytearray_t &&extra = bytearray_t());

    /* Functions required to construct concrete instances for abstract classes.
     * */

    /* Outputs of the state machine triggering external events.  The virtual
     * functions should be implemented by the user to specify the behavior upon
     * the events. */
    protected:
    /** Called by HotStuffCore upon the decision being made for cmd. */
    virtual void do_decide(Finality &&fin) = 0;
    /** Called by HotStuffCore upon broadcasting a new proposal.
     * The user should send the proposal message to all replicas except for
     * itself. */
    virtual void do_broadcast_proposal(const Proposal &prop) = 0;
    virtual void do_broadcast_vote(const Vote &vote) = 0;
    virtual void do_broadcast_blame(const Blame &blame) = 0;
    virtual void do_broadcast_blamenotify(const BlameNotify &bn) = 0;
    virtual void do_notify(const Notify &notify) = 0;
    virtual void set_commit_timer(const block_t &blk, double t_sec) = 0;
    virtual void set_blame_timer(double t_sec) = 0;
    virtual void stop_commit_timer(uint32_t height) = 0;
    virtual void stop_commit_timer_all() = 0;
    virtual void stop_blame_timer() = 0;
    virtual void set_viewtrans_timer(double t_sec) = 0;
    virtual void stop_viewtrans_timer() = 0;

    /* The user plugs in the detailed instances for those
     * polymorphic data types. */
    public:
    /** Create a partial certificate that proves the vote for a block. */
    virtual part_cert_bt create_part_cert(const PrivKey &priv_key, const uint256_t &blk_hash) = 0;
    /** Create a partial certificate from its seralized form. */
    virtual part_cert_bt parse_part_cert(DataStream &s) = 0;
    /** Create a quorum certificate that proves 2f+1 votes for a block. */
    virtual quorum_cert_bt create_quorum_cert(const uint256_t &blk_hash) = 0;
    /** Create a quorum certificate from its serialized form. */
    virtual quorum_cert_bt parse_quorum_cert(DataStream &s) = 0;
    /** Create a command object from its serialized form. */
    //virtual command_t parse_cmd(DataStream &s) = 0;

    public:
    /** Add a replica to the current configuration. This should only be called
     * before running HotStuffCore protocol. */
    void add_replica(ReplicaID rid, const NetAddr &addr, pubkey_bt &&pub_key);
    /** Try to prune blocks lower than last committed height - staleness. */
    void prune(uint32_t staleness);

    /* PaceMaker can use these functions to monitor the core protocol state
     * transition */
    /** Get a promise resolved when the block gets a QC. */
    promise_t async_qc_finish(const block_t &blk);
    /** Get a promise resolved when a new block is proposed. */
    promise_t async_wait_proposal();
    /** Get a promise resolved when a new proposal is received. */
    promise_t async_wait_receive_proposal();
    /** Get a promise resolved when bqc is updated. */
    promise_t async_bqc_update();
    /** Get a promise resolved after a view change. */
    promise_t async_wait_view_change();

    /* Other useful functions */
    const block_t &get_genesis() { return b0; }
    // NOTE: this "bqc" is actual "hqc" in Sync HotStuff
    const block_t &get_bqc() { return hqc.first; }
    const ReplicaConfig &get_config() { return config; }
    ReplicaID get_id() const { return id; }
    const std::set<block_t, BlockHeightCmp> get_tails() const { return tails; }
    operator std::string () const;
    void set_neg_vote(bool _neg_vote) { neg_vote = _neg_vote; }
};


enum ProofType {
    VOTE = 0x00,
    BLAME = 0x01
};

/** Abstraction for proposal messages. */
struct Proposal: public Serializable {
    ReplicaID proposer;
    /** block being proposed */
    block_t blk;
    /** handle of the core object to allow polymorphism. The user should use
     * a pointer to the object of the class derived from HotStuffCore */
    HotStuffCore *hsc;

    Proposal(): blk(nullptr), hsc(nullptr) {}
    Proposal(ReplicaID proposer,
            const block_t &blk,
            HotStuffCore *hsc):
        proposer(proposer),
        blk(blk),
        hsc(hsc) {}

    Proposal(const Proposal &other):
        proposer(other.proposer),
        blk(other.blk),
        hsc(other.hsc) {}

    void serialize(DataStream &s) const override {
        s << proposer
          << *blk;
    }

    inline void unserialize(DataStream &s) override;

    operator std::string () const {
        DataStream s;
        s << "<proposal "
          << "rid=" << std::to_string(proposer) << " "
          << "blk=" << get_hex10(blk->get_hash()) << ">";
        return std::move(s);
    }
};

/** Abstraction for vote messages. */
struct Vote: public Serializable {
    ReplicaID voter;
    /** block being voted */
    uint256_t blk_hash;
    /** proof of validity for the vote */
    part_cert_bt cert;
    
    /** handle of the core object to allow polymorphism */
    HotStuffCore *hsc;

    Vote(): cert(nullptr), hsc(nullptr) {}
    Vote(ReplicaID voter,
        const uint256_t &blk_hash,
        part_cert_bt &&cert,
        HotStuffCore *hsc):
        voter(voter),
        blk_hash(blk_hash),
        cert(std::move(cert)), hsc(hsc) {}

    Vote(const Vote &other):
        voter(other.voter),
        blk_hash(other.blk_hash),
        cert(other.cert ? other.cert->clone() : nullptr),
        hsc(other.hsc) {}

    Vote(Vote &&other) = default;
    
    void serialize(DataStream &s) const override {
        s << voter << blk_hash << *cert;
    }

    void unserialize(DataStream &s) override {
        assert(hsc != nullptr);
        s >> voter >> blk_hash;
        cert = hsc->parse_part_cert(s);
    }

    static uint256_t proof_text_hash(const uint256_t &blk_hash) {
        DataStream p;
        p << (uint8_t)ProofType::VOTE << blk_hash;
        return p.get_hash();
    }

    bool verify() const {
        assert(hsc != nullptr);
        return cert->verify(hsc->get_config().get_pubkey(voter)) &&
                cert->get_blk_hash() == proof_text_hash(blk_hash);
    }

    promise_t verify(VeriPool &vpool) const {
        assert(hsc != nullptr);
        return cert->verify(hsc->get_config().get_pubkey(voter), vpool).then([this](bool result) {
            return result && cert->get_blk_hash() == proof_text_hash(blk_hash);
        });
    }

    operator std::string () const {
        DataStream s;
        s << "<vote "
          << "rid=" << std::to_string(voter) << " "
          << "blk=" << get_hex10(blk_hash) << ">";
        return std::move(s);
    }
};

struct Notify: public Serializable {
    uint256_t blk_hash;
    quorum_cert_bt qc;
    
    /** handle of the core object to allow polymorphism */
    HotStuffCore *hsc;

    Notify(): qc(nullptr), hsc(nullptr) {}
    Notify(const uint256_t blk_hash,
           quorum_cert_bt &&qc,
           HotStuffCore *hsc):
        blk_hash(blk_hash),
        qc(std::move(qc)), hsc(hsc) {}

    Notify(const Notify &other):
        blk_hash(other.blk_hash),
        qc(other.qc ? other.qc->clone() : nullptr), hsc(other.hsc) {}

    Notify(Notify &&other) = default;
    
    void serialize(DataStream &s) const override {
        s << blk_hash << *qc;
    }

    void unserialize(DataStream &s) override {
        s >> blk_hash;
        qc = hsc->parse_quorum_cert(s);
    }

    bool verify() const {
        assert(hsc != nullptr);
        return qc->verify(hsc->get_config()) &&
            qc->get_blk_hash() == Vote::proof_text_hash(blk_hash);
    }

    promise_t verify(VeriPool &vpool) const {
        assert(hsc != nullptr);
        return qc->verify(hsc->get_config(), vpool).then([this](bool result) {
            return result && qc->get_blk_hash() == Vote::proof_text_hash(blk_hash);
        });
    }

    operator std::string () const {
        DataStream s;
        s << "<notify "
          << "blk=" << get_hex10(blk_hash) << ">";
        return std::move(s);
    }
};

struct Blame: public Serializable {
    ReplicaID blamer;
    uint32_t view;
    part_cert_bt cert;
    
    /** handle of the core object to allow polymorphism */
    HotStuffCore *hsc;

    Blame(): cert(nullptr), hsc(nullptr) {}
    Blame(ReplicaID blamer,
        uint32_t view,
        part_cert_bt &&cert,
        HotStuffCore *hsc):
        blamer(blamer),
        view(view),
        cert(std::move(cert)), hsc(hsc) {}

    Blame(const Blame &other):
        blamer(other.blamer),
        view(other.view),
        cert(other.cert ? other.cert->clone() : nullptr),
        hsc(other.hsc) {}

    Blame(Blame &&other) = default;
    
    void serialize(DataStream &s) const override {
        s << blamer << view << *cert;
    }

    void unserialize(DataStream &s) override {
        assert(hsc != nullptr);
        s >> blamer >> view;
        cert = hsc->parse_part_cert(s);
    }

    static uint256_t proof_text_hash(uint32_t view) {
        DataStream p;
        p << (uint8_t)ProofType::BLAME << view;
        return p.get_hash();
    }

    bool verify() const {
        assert(hsc != nullptr);
        return cert->verify(hsc->get_config().get_pubkey(blamer)) &&
                cert->get_blk_hash() == proof_text_hash(view);
    }

    promise_t verify(VeriPool &vpool) const {
        assert(hsc != nullptr);
        return cert->verify(hsc->get_config().get_pubkey(blamer), vpool).then([this](bool result) {
            return result && cert->get_blk_hash() == proof_text_hash(view);
        });
    }

    operator std::string () const {
        DataStream s;
        s << "<blame "
          << "rid=" << std::to_string(blamer) << " "
          << "view=" << std::to_string(view) << ">";
        return std::move(s);
    }
};

struct BlameNotify: public Serializable {
    uint32_t view;
    uint256_t hqc_hash;
    quorum_cert_bt hqc_qc;
    quorum_cert_bt qc;
    
    /** handle of the core object to allow polymorphism */
    HotStuffCore *hsc;

    BlameNotify(): hqc_qc(nullptr), qc(nullptr), hsc(nullptr) {}
    BlameNotify(uint32_t view,
                const uint256_t &hqc_hash,
                quorum_cert_bt &&hqc_qc,
                quorum_cert_bt &&qc,
                HotStuffCore *hsc):
        view(view),
        hqc_hash(hqc_hash),
        hqc_qc(std::move(hqc_qc)),
        qc(std::move(qc)), hsc(hsc) {}

    BlameNotify(const BlameNotify &other):
        view(other.view),
        hqc_hash(other.hqc_hash),
        hqc_qc(other.hqc_qc ? other.hqc_qc->clone() : nullptr),
        qc(other.qc ? other.qc->clone() : nullptr), hsc(other.hsc) {}

    BlameNotify(BlameNotify &&other) = default;
    
    void serialize(DataStream &s) const override {
        s << view << hqc_hash << *hqc_qc << *qc;
    }

    void unserialize(DataStream &s) override {
        s >> view >> hqc_hash;
        hqc_qc = hsc->parse_quorum_cert(s);
        qc = hsc->parse_quorum_cert(s);
    }

    bool verify() const {
        assert(hsc != nullptr);
        return qc->verify(hsc->get_config()) &&
            qc->get_blk_hash() == Blame::proof_text_hash(view) &&
            hqc_qc->get_blk_hash() == Vote::proof_text_hash(hqc_hash);
    }

    promise_t verify(VeriPool &vpool) const {
        assert(hsc != nullptr);
        if (qc->get_blk_hash() != Blame::proof_text_hash(view) ||
            hqc_qc->get_blk_hash() != Vote::proof_text_hash(hqc_hash))
            return promise_t([](promise_t &){ return false; });
        return promise::all(std::vector<promise_t>{
            qc->verify(hsc->get_config(), vpool),
            hqc_qc->verify(hsc->get_config(), vpool),
        }).then([](const promise::values_t &values) {
            return promise::any_cast<bool>(values[0]) &&
                promise::any_cast<bool>(values[1]);
        });
    }

    operator std::string () const {
        DataStream s;
        s << "<blame notify "
          << "view=" << std::to_string(view) << ">";
        return std::move(s);
    }
};

inline void Proposal::unserialize(DataStream &s) {
    assert(hsc != nullptr);
    s >> proposer;
    Block _blk;
    _blk.unserialize(s, hsc);
    blk = hsc->storage->add_blk(std::move(_blk), hsc->get_config());
}

struct Finality: public Serializable {
    ReplicaID rid;
    int8_t decision;
    uint32_t cmd_idx;
    uint32_t cmd_height;
    uint256_t cmd_hash;
    uint256_t blk_hash;
    
    public:
    Finality() = default;
    Finality(ReplicaID rid,
            int8_t decision,
            uint32_t cmd_idx,
            uint32_t cmd_height,
            uint256_t cmd_hash,
            uint256_t blk_hash):
        rid(rid), decision(decision),
        cmd_idx(cmd_idx), cmd_height(cmd_height),
        cmd_hash(cmd_hash), blk_hash(blk_hash) {}

    void serialize(DataStream &s) const override {
        s << rid << decision
          << cmd_idx << cmd_height
          << cmd_hash;
        if (decision == 1) s << blk_hash;
    }

    void unserialize(DataStream &s) override {
        s >> rid >> decision
          >> cmd_idx >> cmd_height
          >> cmd_hash;
        if (decision == 1) s >> blk_hash;
    }

    operator std::string () const {
        DataStream s;
        s << "<fin "
          << "decision=" << std::to_string(decision) << " "
          << "cmd_idx=" << std::to_string(cmd_idx) << " "
          << "cmd_height=" << std::to_string(cmd_height) << " "
          << "cmd=" << get_hex10(cmd_hash) << " "
          << "blk=" << get_hex10(blk_hash) << ">";
        return std::move(s);
    }
};

}

#endif
