#pragma once

#include "crypto/bls_base.hpp"
#include "network/muddle/rpc/client.hpp"
#include "network/muddle/rpc/server.hpp"
#include "dkg/dkg_messages.hpp"
#include "dkg/rbc.hpp"
#include "dkg/dkg_helper.hpp"

#include <set>
#include <iostream>
#include <atomic>

namespace fetch {
namespace muddle {

    class MuddleEndpoint;
    //class Subscription;

}  // namespace muddle

namespace dkg {

    class DKG {
        using MuddleAddress = byte_array::ConstByteArray;
        using CabinetMembers = std::set<MuddleAddress>;
        using Endpoint       = muddle::MuddleEndpoint;
        using RBC = rbc::RBC;

        enum class State : uint8_t {
            INITIAL,
            WAITING_FOR_SHARE,
            WAITING_FOR_COMPLAINTS,
            WAITING_FOR_COMPLAINT_ANSWERS,
            WAITING_FOR_QUAL_SHARES,
            WAITING_FOR_QUAL_COMPLAINTS,
            WAITING_FOR_RECONSTRUCTION_SHARES
        };
        static bn::G2 zeroG2_;
        static bn::Fr zeroFr_;
        static bn::G2 G;
        static bn::G2 H;

        CabinetMembers cabinet_;
        uint32_t threshold_;
        State state_{State::INITIAL};
        std::mutex mutex_;
        MuddleAddress address_;         ///< Our muddle address
        uint32_t cabinet_index_;
        std::atomic<bool> DKGComplete{false};
        RBC rbc_;

        muddle::rpc::Server   rpc_server_;
        muddle::rpc::Client   rpc_client_;      ///< The services' RPC client


        // What the DKG should return
        bn::Fr x_i, xprime_i;
        bn::G2 y_;
        std::vector<bn::G2> y_i, v_i;
        std::set<MuddleAddress> QUAL;

        // Temporary for DKG construction
        std::vector<std::vector<bn::Fr> > s_ij, sprime_ij;
        std::vector<bn::Fr> z_i;
        std::vector<std::vector<bn::G2>> C_ik;
        std::vector<std::vector<bn::G2>> A_ik; //Used in reconstruction phase
        std::vector<std::vector<bn::G2>> g__s_ij;
        std::vector<bn::G2> g__a_i;

        // Complaints round 2
        std::unordered_map<MuddleAddress, uint32_t> complaints_counter;
        std::set<MuddleAddress> complaints;
        std::set<MuddleAddress> complaints_from;
        //std::vector<bool> complaints_received = std::vector<bool>(committee_size_, false);
        //std::vector<bool> complaint_answers_received = std::vector<bool>(committee_size_, false);
        //std::set<MuddleAddress> QUAL_complaints_received;

        class MsgCounter {
        public:
            enum class Message {
                INITIAL_SHARE,
                INITIAL_COEFFICIENT,
                COMPLAINT,
                COMPLAINT_ANSWER,
                RECONSTRUCTION_SHARE
            };

            void inc(Message msg) {
                std::lock_guard<std::mutex> lock{mutex};
                if (counter_.find(msg) == counter_.end()) {
                    counter_.insert({msg, 0});
                }
                ++counter_.at(msg);
            }
            void erase(Message msg) {
                std::lock_guard<std::mutex> lock{mutex};
                counter_.erase(msg);
            }
            uint32_t count(Message msg) {
                std::lock_guard<std::mutex> lock{mutex};
                if (counter_.find(msg) == counter_.end()) {
                    counter_.insert({msg, 0});
                }
                return counter_.at(msg);
            }
        private:
            std::mutex mutex;
            std::unordered_map<Message, uint32_t> counter_;
        };

        MsgCounter msg_counter_;

        //std::atomic<uint32_t> shares_received{0};
        //std::atomic<uint32_t> C_ik_received{0};
        //std::atomic<uint32_t> A_ik_received{0};
        //std::atomic<uint32_t> complaints_received_counter{0};
        //std::atomic<uint32_t> complaint_answers_received_counter{0};

        //Reconstruction
        // Map from id of node_i in complaints to a pair
        // 1. parties which exposed shares of node_i
        // 2. the shares that were exposed
        std::unordered_map<MuddleAddress, std::pair<std::vector<std::size_t>, std::vector<bn::Fr>>> reconstruction_shares;
        //std::atomic<uint32_t> reconstruction_shares_received{0};

        template<typename T>
        void init(std::vector<std::vector<T>> &data, std::size_t i, std::size_t j) {
            data.resize(i);
            for (auto &data_i : data) {
                data_i.resize(j);
                for (auto &data_ij : data_i) {
                    data_ij.clear();
                }
            }
        }

        template<typename T>
        void init(std::vector<T> &data, std::size_t i) {
            data.resize(i);
            for (auto &data_i : data) {
                data_i.clear();
            }
        }

        uint32_t cabinetIndex(const MuddleAddress &other_address) const;

        void sendBroadcast(DKGEnvelop const &env);
        void broadcastComplaints();
        void broadcastComplaintsAnswer();
        void broadcastQUALComplaints();
        void broadcastReconstructionShares();


        /*
        void onComplaintsAnswer(const fetch::consensus::pb::Broadcast_Shares &answer, const std::string &from_id);

        bool buildQual();

        void computeSecretShare();

        void onQUALComplaints(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from_id);

        void
        onReconstructionShares(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from_id);

        bool runReconstruction();

        void computePublicKeys();

        void addGroupSignature(const std::string &message, const std::pair<std::size_t, bn::G1> &share);

        */
    public:
        explicit DKG(Endpoint &endpoint, MuddleAddress address, CabinetMembers cabinet, uint32_t threshold);

        void broadcastShares();

        void onNewShares(MuddleAddress from_id, std::pair<bn::Fr, bn::Fr> const &shares);

        /*
        void onNewCoefficients(const fetch::consensus::pb::Broadcast_Coefficients &coefficients,
                               const std::string &from_id);

        void onComplaints(const fetch::consensus::pb::Broadcast_Complaints &complaint, const std::string &from_id);

        void onExposedShares(const fetch::consensus::pb::Broadcast_Shares &shares, const std::string &from_id);

        bool DKGCompleted() const {
            return DKGComplete;
        }
         */

    };

} //dkg
} //fetch