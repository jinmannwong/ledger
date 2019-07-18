#pragma once
//------------------------------------------------------------------------------
//
//   Copyright 2018-2019 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "dkg/dkg_helper.hpp"
#include "dkg/dkg_messages.hpp"
#include "network/muddle/rpc/client.hpp"

#include <atomic>
#include <iostream>
#include <set>

namespace fetch {
namespace muddle {

class MuddleEndpoint;

}  // namespace muddle

namespace dkg {

class DkgService;

class DKG
{
  using MuddleAddress  = byte_array::ConstByteArray;
  using CabinetMembers = std::set<MuddleAddress>;
  using Endpoint       = muddle::MuddleEndpoint;
  using MsgShare       = std::string;

  enum class State : uint8_t
  {
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
  static bn::G2 group_g_;
  static bn::G2 group_h_;

  CabinetMembers &   cabinet_;
  std::size_t &      threshold_;
  std::atomic<State> state_{State::INITIAL};
  std::mutex         mutex_;
  MuddleAddress      address_;  ///< Our muddle address
  uint32_t           cabinet_index_;
  DkgService &       dkg_service_;

  // What the DKG should return
  std::atomic<bool>       finished_{false};
  bn::Fr                  secret_share_, xprime_i;  // x_i
  bn::G2                  public_key_;              // y
  std::vector<bn::G2>     y_i, public_key_shares_;  // v_i
  std::set<MuddleAddress> qual_;  ///< Set of cabinet members who take part in the public key
                                  ///< generation after complaints

  // Temporary for DKG construction
  std::vector<std::vector<bn::Fr>> s_ij, sprime_ij;
  std::vector<bn::Fr>              z_i;
  std::vector<std::vector<bn::G2>> C_ik;
  std::vector<std::vector<bn::G2>> A_ik;  // Used in reconstruction phase
  std::vector<std::vector<bn::G2>> g__s_ij;
  std::vector<bn::G2>              g__a_i;

  // Complaints round 2
  std::unordered_map<MuddleAddress, uint32_t> complaints_counter;
  std::set<MuddleAddress>                     complaints;
  std::set<MuddleAddress>                     complaints_from;
  std::vector<bool>                           complaints_received;
  std::vector<bool>                           complaint_answers_received;
  std::set<MuddleAddress>                     qual_complaints_received;

  class MsgCounter
  {
  public:
    enum class Message
    {
      INITIAL_SHARE,
      INITIAL_COEFFICIENT,
      COMPLAINT,
      COMPLAINT_ANSWER,
      QUAL_COEFFICIENT,
      RECONSTRUCTION_SHARE
    };

    void Increment(Message msg)
    {
      std::lock_guard<std::mutex> lock{mutex};
      if (counter_.find(msg) == counter_.end())
      {
        counter_.insert({msg, 0});
      }
      ++counter_.at(msg);
    }
    void Erase(Message msg)
    {
      std::lock_guard<std::mutex> lock{mutex};
      counter_.erase(msg);
    }
    uint32_t Count(Message msg)
    {
      std::lock_guard<std::mutex> lock{mutex};
      if (counter_.find(msg) == counter_.end())
      {
        counter_.insert({msg, 0});
      }
      return counter_.at(msg);
    }
    void Clear()
    {
      counter_.clear();
    }

  private:
    std::mutex                            mutex;
    std::unordered_map<Message, uint32_t> counter_;
  };

  MsgCounter msg_counter_;

  // Reconstruction
  // Map from id of node_i in complaints to a pair
  // 1. parties which exposed shares of node_i
  // 2. the shares that were exposed
  std::unordered_map<MuddleAddress, std::pair<std::vector<uint32_t>, std::vector<bn::Fr>>>
      reconstruction_shares;

  template <typename T>
  void Init(std::vector<std::vector<T>> &data, uint32_t i, uint32_t j)
  {
    data.resize(i);
    for (auto &data_i : data)
    {
      data_i.resize(j);
      for (auto &data_ij : data_i)
      {
        data_ij.clear();
      }
    }
  }

  template <typename T>
  void Init(std::vector<T> &data, uint32_t i)
  {
    data.resize(i);
    for (auto &data_i : data)
    {
      data_i.clear();
    }
  }

  uint32_t CabinetIndex(MuddleAddress const &other_address) const;

  void ReceivedCoefficientsAndShares();
  void SendCoefficients(std::vector<bn::Fr> const &a_i, std::vector<bn::Fr> const &b_i);
  void SendShares(std::vector<bn::Fr> const &a_i, std::vector<bn::Fr> const &b_i);
  std::unordered_set<MuddleAddress> ComputeComplaints();
  void CheckComplaintAnswer(std::shared_ptr<SharesMessage> const &answer,
                            MuddleAddress const &from_id, uint32_t from_index);

  void SendBroadcast(DKGEnvelop const &env);
  void BroadcastComplaints();
  void BroadcastComplaintsAnswer();
  void BroadcastQualComplaints();
  void BroadcastReconstructionShares();
  void OnNewCoefficients(std::shared_ptr<CoefficientsMessage> const &coefficients,
                         MuddleAddress const &                       from_id);
  void OnComplaints(std::shared_ptr<ComplaintsMessage> const &complaint,
                    MuddleAddress const &                     from_id);
  void OnExposedShares(std::shared_ptr<SharesMessage> const &shares, MuddleAddress const &from_id);
  void OnComplaintsAnswer(std::shared_ptr<SharesMessage> const &answer,
                          MuddleAddress const &                 from_id);
  void OnQualComplaints(std::shared_ptr<SharesMessage> const &shares, MuddleAddress const &from_id);
  void OnReconstructionShares(std::shared_ptr<SharesMessage> const &shares,
                              MuddleAddress const &                 from_id);

  bool BuildQual();
  void ComputeSecretShare();
  bool RunReconstruction();
  void ComputePublicKeys();
  void Clear();

public:
  explicit DKG(MuddleAddress address, CabinetMembers &cabinet, std::size_t &threshold,
               DkgService &dkg_service);

  void   BroadcastShares();
  void   ResetCabinet();
  void   OnNewShares(MuddleAddress from_id, std::pair<MsgShare, MsgShare> const &shares);
  void   OnDkgMessage(MuddleAddress const &from, std::shared_ptr<DKGMessage> msg_ptr);
  void   SetDkgOutput(bn::G2 &public_key, bn::Fr &secret_share,
                      std::vector<bn::G2> &public_key_shares, std::set<MuddleAddress> &qual) const;
  bool   finished() const;
  bn::G2 group() const
  {
    return group_g_;
  }
};
}  // namespace dkg
}  // namespace fetch
