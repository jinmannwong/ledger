#include "dkg/dkg.hpp"
#include "core/service_ids.hpp"
#include "dkg/dkg_rpc_protocol.hpp"

namespace fetch {
namespace dkg {

    constexpr char const *LOGGING_NAME = "DKG";
    bn::G2 DKG::zeroG2_;
    bn::Fr DKG::zeroFr_;
    bn::G2 DKG::G;
    bn::G2 DKG::H;

    DKG::DKG(Endpoint &endpoint, MuddleAddress address, CabinetMembers cabinet, uint32_t threshold)
            : rbc_{endpoint, address, cabinet, threshold}, cabinet_{std::move(cabinet)}
            , threshold_{threshold}
            , address_{std::move(address)}
            , rpc_server_{endpoint, SERVICE_DKG, CHANNEL_RPC}
            , rpc_client_{"dkg", endpoint, SERVICE_DKG, CHANNEL_RPC}
            {
        static bool once = []() {
            bn::initPairing();
            zeroG2_.clear();
            zeroFr_.clear();
            G.clear();
            H.clear();
            // Values taken from TMCG main.cpp
            const bn::Fp2 g("1380305877306098957770911920312855400078250832364663138573638818396353623780",
                            "14633108267626422569982187812838828838622813723380760182609272619611213638781");
            const bn::Fp2 h("6798148801244076840612542066317482178930767218436703568023723199603978874964",
                            "12726557692714943631796519264243881146330337674186001442981874079441363994424");
            bn::mapToG2(G, g);
            bn::mapToG2(H, h);
            return true;
        }();
        if (!once)
            std::cerr << "Node::initPairing failed.\n"; // just to eliminate warnings from the compiler.
        assert((threshold_ * 2) < cabinet_.size());
        assert(cabinet_.find(address_) != cabinet_.end()); // We should be in the cabinet
        cabinet_index_ = static_cast<uint32_t>(std::distance(cabinet_.begin(), cabinet_.find(address_)));
        init(y_i, cabinet_.size());
        init(v_i, cabinet_.size());
        init(C_ik, cabinet_.size(), threshold_ + 1);
        init(A_ik, cabinet_.size(), threshold_ + 1);
        init(s_ij, cabinet_.size(), cabinet_.size());
        init(sprime_ij, cabinet_.size(), cabinet_.size());
        init(z_i, cabinet_.size());
        init(g__s_ij, cabinet_.size(), cabinet_.size());
        g__a_i.resize(threshold_ + 1);
        for (auto &i : g__a_i)
            i.clear();
    }

    void DKG::sendBroadcast(DKGEnvelop const &env) {
        DKGSerializer serialiser;
        env.serialize(serialiser);
        rbc_.sendRBroadcast(serialiser.data());
    }

    void DKG::broadcastShares() {
        std::vector<bn::Fr> a_i(threshold_ + 1, zeroFr_), b_i(threshold_ + 1, zeroFr_);

        // 1. Each party $P_i$ performs a Pedersen-VSS of a random
        //    value $z_i$ as a dealer:
        // (a) $P_i$ chooses two random polynomials $f_i(z)$ and
        //     $f\prime_i(z)$ over $\mathbb{Z}_q$ of degree $t$ where
        //     $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t$ and
        //     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t$
        for (size_t k = 0; k <= threshold_; k++) {
            a_i[k].setRand();
            b_i[k].setRand();
        }
        // Let $z_i = a_{i0} = f_i(0)$.
        z_i[cabinet_index_] = a_i[0];
        // $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$
        // for $k = 0, \ldots, t$.

        std::vector<bn::G2> coefficients;
        for (size_t k = 0; k <= threshold_; k++) {
            C_ik[cabinet_index_][k] = computeLHS(g__a_i[k], G, H, a_i[k], b_i[k]);
            coefficients.push_back(C_ik[cabinet_index_][k]);
        }
        sendBroadcast(DKGEnvelop{Coefficients{static_cast<uint8_t>(State::WAITING_FOR_SHARE), coefficients, "signature"}});

        // $P_i$ computes the shares $s_{ij} = f_i(j) \bmod q$,
        // $s\prime_{ij} = f\prime_i(j) \bmod q$ and
        // sends $s_{ij}$, $s\prime_{ij}$ to party $P_j$.
        size_t j = 0;
        for (auto &cab_i : cabinet_) {
            computeShares(s_ij[cabinet_index_][j], sprime_ij[cabinet_index_][j], a_i, b_i, j);
            if (j != cabinet_index_) {
                std::pair<bn::Fr, bn::Fr> shares {s_ij[cabinet_index_][j], sprime_ij[cabinet_index_][j]};
                //rpc_client_.CallSpecificAddress(cab_i, RPC_DKG_BEACON,
                                                //DkgRpcProtocol::SUBMIT_SHARE, address_, shares);
            }
            ++j;
        }
        state_ = State::WAITING_FOR_SHARE;
    }

    void DKG::broadcastComplaints() {
        std::unordered_set<MuddleAddress> complaints_local;
        uint32_t i = 0;
        for (auto &cab : cabinet_) {
            if (i != cabinet_index_) {
                // Can only require this if G, H do not take the default values from clear()
                if (C_ik[i][0] != zeroG2_ && s_ij[i][cabinet_index_] != zeroFr_) {
                    bn::G2 rhs, lhs;
                    lhs = computeLHS(g__s_ij[i][cabinet_index_], G, H, s_ij[i][cabinet_index_], sprime_ij[i][cabinet_index_]);
                    rhs = computeRHS(cabinet_index_, C_ik[i]);
                    if (lhs != rhs)
                        complaints_local.insert(cab);
                } else {
                    complaints_local.insert(cab);
                    ++complaints_counter[cab];
                }
            }
            ++i;
        }

        sendBroadcast(DKGEnvelop{Complaints{complaints_local, "signature"}});
        state_ = State::WAITING_FOR_COMPLAINTS;
    }

    void DKG::broadcastComplaintsAnswer() {
        std::unordered_map<MuddleAddress, std::pair<bn::Fr, bn::Fr>> complaints_answer;
        for (const auto &reporter : complaints_from) {
            uint32_t from_index {cabinetIndex(reporter)};
            complaints_answer.insert({reporter, {s_ij[cabinet_index_][from_index], sprime_ij[cabinet_index_][from_index]}});
        }
        sendBroadcast(DKGEnvelop{Shares{static_cast<uint64_t>(State::WAITING_FOR_COMPLAINT_ANSWERS), complaints_answer, "signature"}});
        state_ = State::WAITING_FOR_COMPLAINT_ANSWERS;
    }

    void DKG::broadcastQUALComplaints() {
        std::unordered_set<MuddleAddress> complaints_local;
        uint32_t i = 0;
        auto iq = cabinet_.begin();
        for (const auto &miner : QUAL) {
            while (*iq != miner) {
                ++iq;
                ++i;
            }
            if (i != cabinet_index_) {
                // Can only require this if G, H do not take the default values from clear()
                if (A_ik[i][0] != zeroG2_) {
                    bn::G2 rhs, lhs;
                    lhs = g__s_ij[i][cabinet_index_];
                    rhs = computeRHS(cabinet_index_, A_ik[i]);
                    if (lhs != rhs)
                        complaints_local.insert(miner);
                } else {
                    complaints_local.insert(miner);
                }
            }
        }

        std::unordered_map<MuddleAddress, std::pair<bn::Fr, bn::Fr>> QUAL_complaints;
        for (auto &c : complaints_local) {
            uint32_t c_index {cabinetIndex(c)};
            //logger.trace("node {} exposes shares of node {}", cabinet_index_, c_index);
            QUAL_complaints.insert({c, {s_ij[cabinet_index_][c_index], sprime_ij[cabinet_index_][c_index]}});
        }
        sendBroadcast(DKGEnvelop{Shares{static_cast<uint64_t>(State::WAITING_FOR_QUAL_COMPLAINTS), QUAL_complaints, "signature"}});
        state_ = State::WAITING_FOR_QUAL_COMPLAINTS;
    }

    void DKG::broadcastReconstructionShares() {
        std::lock_guard<std::mutex> lock{mutex_};

        std::unordered_map<MuddleAddress, std::pair<bn::Fr, bn::Fr>> complaint_shares;
        for (const auto &in : complaints) {
            assert(QUAL.find(in) != QUAL.end());
            uint32_t in_index{cabinetIndex(in)};
            reconstruction_shares.insert({in, {{}, std::vector<bn::Fr>(cabinet_.size(), zeroFr_)}});
            reconstruction_shares.at(in).first.push_back(cabinet_index_);
            reconstruction_shares.at(in).second[cabinet_index_] = s_ij[in_index][cabinet_index_];
            complaint_shares.insert({in, {s_ij[in_index][cabinet_index_], sprime_ij[in_index][cabinet_index_]}});
        }
        sendBroadcast(DKGEnvelop{Shares{static_cast<uint64_t>(State::WAITING_FOR_RECONSTRUCTION_SHARES), complaint_shares, "signature"}});
        state_ = State::WAITING_FOR_RECONSTRUCTION_SHARES;
    }

    void DKG::onNewShares(MuddleAddress from, std::pair<bn::Fr, bn::Fr> const &shares) {
        uint32_t from_index{cabinetIndex(from)};
        s_ij[from_index][cabinet_index_] = (shares.first);
        sprime_ij[from_index][cabinet_index_] = shares.second;

        msg_counter_.inc(MsgCounter::Message::INITIAL_SHARE);
        if ((state_ == State::WAITING_FOR_SHARE) and (msg_counter_.count(MsgCounter::Message::INITIAL_SHARE) == cabinet_.size() - 1)
            and (msg_counter_.count(MsgCounter::Message::INITIAL_COEFFICIENT)) == cabinet_.size() - 1) {
            broadcastComplaints();
        }
    }

    /*
    void Committee::onNewCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                                      const std::string &from_id) {
        uint32_t from_index{node_.miner_index(from_id)};
        if (coefficients.phase() == static_cast<uint64_t>(State::WAITING_FOR_SHARE)) {
            bn::G2 zero;
            zero.clear();
            for (uint32_t ii = 0; ii <= threshold_; ++ii) {
                if (C_ik[from_index][ii] == zero) {
                    C_ik[from_index][ii].setStr(coefficients.coefficients(ii));
                }
            }
            ++C_ik_received;
            if ((state_ == State::WAITING_FOR_SHARE) and (C_ik_received.load() == committee_size_ - 1) and
                (shares_received.load()) == committee_size_ - 1) {
                broadcastComplaints();
            }
        } else if (coefficients.phase() == static_cast<uint64_t>(State::WAITING_FOR_QUAL_SHARES)) {
            bn::G2 zero;
            zero.clear();
            for (uint32_t ii = 0; ii <= threshold_; ++ii) {
                if (A_ik[from_index][ii] == zero) {
                    A_ik[from_index][ii].setStr(coefficients.coefficients(ii));
                }
            }
            ++A_ik_received;
            if ((state_ == State::WAITING_FOR_QUAL_SHARES) and (A_ik_received.load() == committee_size_ - 1)) {
                broadcastQUALComplaints();
            }
        }
    }

    void
    Committee::onComplaints(const fetch::consensus::pb::Broadcast_Complaints &complaint, const std::string &from_id) {
        uint32_t from_index{node_.miner_index(from_id)};
        std::lock_guard<std::mutex> lock{mutex_};
        // Check if we have received a complaints message from this node before and if not log that we received
        // a complaint message
        if (!complaints_received[from_index]) {
            complaints_received[from_index] = true;
        } else {
            complaints.insert(from_id);
            return;
        }

        std::unordered_set<std::string> complaints_from_sender;
        for (auto ii = 0; ii < complaint.nodes_size(); ++ii) {
            // Keep track of the nodes which are included in complaint. If there are duplicates then we add the sender
            // to complaints
            if (complaints_from_sender.find(complaint.nodes(ii)) != complaints_from_sender.end()) {
                complaints.insert(from_id);
            } else {
                complaints_from_sender.insert(complaint.nodes(ii));
                ++complaints_counter[complaint.nodes(ii)];
            }
            // If a node receives complaint against itself then store in complaints from
            // for answering later
            if (complaint.nodes(ii) == node_.id()) {
                complaints_from.insert(from_id);
            }
        }
        ++complaints_received_counter;
        if (state_ == State::WAITING_FOR_COMPLAINTS and
            (complaints_received_counter.load() == committee_size_ - 1)) {
            // Add miners which did not send a complaint to complaints (redundant for now but will be necessary when
            // we do not wait for a message from everyone)
            auto miner_it = node_.miners().begin();
            for (uint32_t ii = 0; ii < complaints_received.size(); ++ii) {
                if (!complaints_received[ii] and ii != node_.miner_index()) {
                    complaints.insert(*miner_it);
                }
                ++miner_it;
            }
            //All miners who have received over t complaints are also disqualified
            auto miner_iter{node_.miners().begin()};
            for (const auto &node_complaints : complaints_counter) {
                if (node_complaints.second > threshold_) {
                    complaints.insert(*miner_iter);
                }
                ++miner_iter;
            }
            broadcastComplaintsAnswer();
        }
    }

    void Committee::onExposedShares(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from_id) {
        uint64_t phase{shares.phase()};
        if (phase == static_cast<uint64_t>(State::WAITING_FOR_COMPLAINT_ANSWERS)) {
            logger.info("complaint answer {} from {}", node_.id(), from_id);
            onComplaintsAnswer(shares, from_id);
        } else if (phase == static_cast<uint64_t>(State::WAITING_FOR_QUAL_COMPLAINTS)) {
            logger.info("QUAL complaint {} from {}", node_.id(), from_id);
            onQUALComplaints(shares, from_id);
        } else if (phase == static_cast<uint64_t>(State::WAITING_FOR_RECONSTRUCTION_SHARES)) {
            logger.info("Reconstruction shares {} from {}", node_.id(), from_id);
            onReconstructionShares(shares, from_id);
        }
    }

    void
    Committee::onComplaintsAnswer(const fetch::consensus::pb::Broadcast_Shares &answer, const std::string &from_id) {
        uint32_t from_index{node_.miner_index(from_id)};
        uint32_t rank{node_.miner_index()};
        // If a fields are not all complete we complain against the sender and do not process
        if (answer.first_size() != answer.second_size() or answer.first_size() != answer.reporter_size()) {
            complaints.insert(from_id);
        } else {
            for (auto ii = 0; ii < answer.first_size(); ++ii) {
                uint32_t reporter_index{node_.miner_index(answer.reporter(ii))};
                //Verify shares received
                bn::Fr s, sprime;
                bn::G2 lhsG, rhsG;
                s.clear();
                sprime.clear();
                lhsG.clear();
                rhsG.clear();
                s.setStr(answer.first(ii));
                sprime.setStr(answer.second(ii));
                rhsG = fetch::consensus::computeRHS(from_index, C_ik[reporter_index]);
                lhsG = fetch::consensus::computeLHS(G, H, s, sprime);
                if (lhsG != rhsG) {
                    logger.error("node {} verification for node {} complaint answer failed", node_.id(), from_index);
                    complaints.insert(from_id);
                } else {
                    logger.info("node {} verification for node {} complaint answer succeeded", node_.id(), from_index);
                    if (reporter_index == rank) {
                        s_ij[from_index][rank] = s;
                        sprime_ij[from_index][rank] = sprime;
                    }
                }
            }
        }
        complaint_answers_received[from_index] = true;
        ++complaint_answers_received_counter;
        if (state_ == State::WAITING_FOR_COMPLAINT_ANSWERS and
            (complaint_answers_received_counter.load() == committee_size_ - 1)) {
            // Add miners which did not send a complaint to complaints (redundant for now but will be necessary when
            // we do not wait for a message from everyone)
            auto miner_it = node_.miners().begin();
            for (uint32_t ii = 0; ii < complaint_answers_received.size(); ++ii) {
                if (!complaint_answers_received[ii] and ii != node_.miner_index()) {
                    complaints.insert(*miner_it);
                }
                ++miner_it;
            }
            if (buildQual()) {
                logger.info("Node {} build QUAL of size {}", node_.id(), QUAL.size());
                computeSecretShare();
            } else {
                //TODO: procedure failed for this node
            }
        }
    }

    bool Committee::buildQual() {
        //Altogether, complaints consists of
        // 1. Nodes who did not send, sent too many or sent duplicate complaints
        // 2. Nodes which received over t complaints
        // 3. Nodes who did not complaint answers
        // 4. Complaint answers which were false
        for (const auto &node : node_.miners()) {
            if (complaints.find(node) == complaints.end()) {
                QUAL.insert(node);
            }
        }
        if (QUAL.find(node_.id()) == QUAL.end() or QUAL.size() <= threshold_) {
            if (QUAL.find(node_.id()) == QUAL.end()) {
                logger.error("Node {} build QUAL failed as not in QUAL", node_.id());
            } else {
                logger.error("Node {} build QUAL failed as size {} less than threshold {}", node_.id(), QUAL.size(),
                             threshold_);
            }
            return false;
        }
        return true;
    }

    void Committee::computeSecretShare() {
        // 3. Each party $P_i$ sets their share of the secret as
        //    $x_i = \sum_{j \in QUAL} s_{ji} \bmod q$ and the value
        //    $x\prime_i = \sum_{j \in QUAL} s\prime_{ji} \bmod q$.
        x_i = 0;
        xprime_i = 0;
        uint32_t rank = node_.miner_index();
        for (const auto &iq : QUAL) {
            uint32_t iq_index = node_.miner_index(iq);
            bn::Fr::add(x_i, x_i, s_ij[iq_index][rank]);
            bn::Fr::add(xprime_i, xprime_i, sprime_ij[iq_index][rank]);
        }
        // 4. Each party $i \in QUAL$ exposes $y_i = g^{z_i} \bmod p$
        //    via Feldman-VSS:
        // (a) Each party $P_i$, $i \in QUAL$, broadcasts $A_{ik} =
        //     g^{a_{ik}} \bmod p$ for $k = 0, \ldots, t$.
        fetch::consensus::pb::Broadcast msg;
        auto *coefficients{msg.mutable_coefficients()};
        coefficients->set_phase(static_cast<uint64_t>(State::WAITING_FOR_QUAL_SHARES));
        msg.set_signature("signature");
        for (size_t k = 0; k <= threshold_; k++) {
            A_ik[rank][k] = g__a_i[k];
            coefficients->add_coefficients(A_ik[rank][k].getStr());
        }
        node_.sendBroadcast(msg);
        state_ = State::WAITING_FOR_QUAL_SHARES;
        complaints.clear();
    }

    void Committee::onQUALComplaints(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from_id) {
        uint32_t from_index{node_.miner_index(from_id)};
        uint32_t rank{node_.miner_index()};
        // If not all fields are complete we complain against the sender
        if (shares.first_size() != shares.second_size() or shares.first_size() != shares.reporter_size()) {
            complaints.insert(from_id);
        } else {
            for (auto ii = 0; ii < shares.first_size(); ++ii) {
                //Check person who's shares are being exposed is not in QUAL then don't bother with checks
                if (QUAL.find(shares.reporter(ii)) != QUAL.end()) {
                    // verify complaint, i.e. (4) holds (5) not
                    bn::G2 lhs, rhs;
                    bn::Fr s, sprime;
                    lhs.clear();
                    rhs.clear();
                    s.clear();
                    sprime.clear();
                    s.setStr(shares.first(ii));
                    sprime.setStr(shares.second(ii));
                    // check equation (4)
                    lhs = fetch::consensus::computeLHS(G, H, s, sprime);
                    rhs = fetch::consensus::computeRHS(node_.miner_index(shares.reporter(ii)), C_ik[from_index]);
                    if (lhs != rhs) {
                        complaints.insert(from_id);
                    }
                    // check equation (5)
                    bn::G2::mul(lhs, G, s);//G^s
                    rhs = fetch::consensus::computeRHS(rank, A_ik[from_index]);
                    if (lhs != rhs) {
                        complaints.insert(shares.reporter(ii));
                    } else {
                        complaints.insert(from_id);
                    }
                }
            }
        }
        QUAL_complaints_received.insert(from_id);
        if (state_ == State::WAITING_FOR_QUAL_COMPLAINTS and (QUAL_complaints_received.size() == QUAL.size() - 1)) {
            // Add QUAL members which did not send a complaint to complaints (redundant for now but will be necessary when
            // we do not wait for a message from everyone)
            for (const auto &iq : QUAL) {
                if (iq != node_.id() and QUAL_complaints_received.find(iq) == QUAL_complaints_received.end()) {
                    complaints.insert(iq);
                }
            }

            if (complaints.size() > threshold_) {
                logger.error("Node {} protocol has failed: complaints size {}", node_.id(), complaints.size());
                return;
            } else if (complaints.find(node_.id()) != complaints.end()) {
                logger.error("Node {} protocol has failed: in complaints", node_.id());
                return;
            }
            assert(QUAL.find(node_.id()) != QUAL.end());
            broadcastReconstructionShares();
        }
    }

    void Committee::onReconstructionShares(const fetch::consensus::pb::Broadcast_Shares &shares,
                                           const std::string &from_id) {
        //Return if the sender is in complaints, or not in QUAL
        if (complaints.find(from_id) != complaints.end() or QUAL.find(from_id) == QUAL.end()) {
            return;
        }
        uint32_t from_index{node_.miner_index(from_id)};
        for (auto ii = 0; ii < shares.first_size(); ++ii) {
            uint32_t victim_index{node_.miner_index(shares.reporter(ii))};
            assert(complaints.find(shares.reporter(ii)) != complaints.end());
            bn::G2 lhs, rhs;
            bn::Fr s, sprime;
            lhs.clear();
            rhs.clear();
            s.clear();
            sprime.clear();

            s.setStr(shares.first(ii));
            sprime.setStr(shares.second(ii));
            lhs = fetch::consensus::computeLHS(G, H, s, sprime);
            rhs = fetch::consensus::computeRHS(from_index, C_ik[victim_index]);
            // check equation (4)
            if (lhs == rhs and reconstruction_shares.at(shares.reporter(ii)).second[from_index] == zeroFr_) {
                std::lock_guard<std::mutex> lock{mutex_};
                reconstruction_shares.at(shares.reporter(ii)).first.push_back(from_index); // good share received
                reconstruction_shares.at(shares.reporter(ii)).second[from_index] = s;
            }
        }
        ++reconstruction_shares_received;
        if (state_ == State::WAITING_FOR_RECONSTRUCTION_SHARES and
            reconstruction_shares_received.load() == QUAL.size() - complaints.size() - 1) {
            if (!runReconstruction()) {
                logger.error("Node {} DKG failed due to reconstruction failure", node_.id());
            } else {
                computePublicKeys();
                complaints.clear();
            }
        }
    }

    bool Committee::runReconstruction() {
        std::vector<std::vector<bn::Fr>> a_ik;
        init(a_ik, committee_size_, threshold_ + 1);
        for (const auto &in : reconstruction_shares) {
            std::vector<std::size_t> parties{in.second.first};
            std::vector<bn::Fr> shares{in.second.second};
            if (parties.size() <= threshold_) {
                // Do not have enough good shares to be able to do reconstruction
                logger.error("Node {} reconstruction for {} failed with party size {}", node_.id(), in.first,
                             parties.size());
                return false;
            }
            // compute $z_i$ using Lagrange interpolation (without corrupted parties)
            uint32_t victim_index{node_.miner_index(in.first)};
            z_i[victim_index] = fetch::consensus::computeZi(in.second.first, in.second.second);
            std::vector<bn::Fr> points(parties.size(), 0), shares_f(parties.size(), 0);
            for (size_t k = 0; k < parties.size(); k++) {
                points[k] = parties[k] + 1;  // adjust index in computation
                shares_f[k] = shares[parties[k]];
            }
            a_ik[victim_index] = fetch::consensus::interpolatePolynom(points, shares_f);
            // compute $A_{ik} = g^{a_{ik}} \bmod p$
            for (size_t k = 0; k <= threshold_; k++) {
                bn::G2::mul(A_ik[victim_index][k], G, a_ik[victim_index][k]);
            }
        }
        return true;
    }

    void Committee::computePublicKeys() {
        logger.info("Node {} compute public keys", node_.id());
        // For all parties in $QUAL$, set $y_i = A_{i0} = g^{z_i} \bmod p$.
        for (const auto &iq : QUAL) {
            uint32_t it{node_.miner_index(iq)};
            y_i[it] = A_ik[it][0];
        }
        // Compute $y = \prod_{i \in QUAL} y_i \bmod p$
        y_.clear();
        for (const auto &iq : QUAL) {
            uint32_t it{node_.miner_index(iq)};
            bn::G2::add(y_, y_, y_i[it]);
        }
        // Compute public verification keys $v_j = \prod_{i \in QUAL} \prod_{k=0}^t (A_{ik})^{j^k} \bmod p$
        for (const auto &jq : QUAL) {
            uint32_t jt{node_.miner_index(jq)};
            for (const auto &iq : QUAL) {
                uint32_t it{node_.miner_index(iq)};
                bn::G2::add(v_i[jt], v_i[jt], A_ik[it][0]);
                fetch::consensus::updateRHS(jt, v_i[jt], A_ik[it]);
            }
        }
        DKGComplete = true;
    }

     */

    uint32_t DKG::cabinetIndex(const MuddleAddress &other_address) const {
        return static_cast<uint32_t>(std::distance(cabinet_.begin(), cabinet_.find(other_address)));
    }
}
}
