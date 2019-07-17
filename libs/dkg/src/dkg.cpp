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

#include "dkg/dkg.hpp"
#include "dkg/dkg_service.hpp"

namespace fetch {
namespace dkg {

using MsgCoefficient = std::string;

constexpr char const *LOGGING_NAME = "DKG";
bn::G2                DKG::zeroG2_;
bn::Fr                DKG::zeroFr_;
bn::G2                DKG::group_g_;
bn::G2                DKG::group_h_;

DKG::DKG(MuddleAddress address, CabinetMembers &cabinet, std::size_t &threshold,
         DkgService &dkg_service)
  : cabinet_{cabinet}
  , threshold_{threshold}
  , address_{std::move(address)}
  , dkg_service_{dkg_service}
{
  static bool once = []() {
    bn::initPairing();
    zeroG2_.clear();
    zeroFr_.clear();
    group_g_.clear();
    group_h_.clear();
    // Values taken from TMCG main.cpp
    const bn::Fp2 g(
        "1380305877306098957770911920312855400078250832364663138573638818396353623780",
        "14633108267626422569982187812838828838622813723380760182609272619611213638781");
    const bn::Fp2 h(
        "6798148801244076840612542066317482178930767218436703568023723199603978874964",
        "12726557692714943631796519264243881146330337674186001442981874079441363994424");
    bn::mapToG2(group_g_, g);
    bn::mapToG2(group_h_, h);

    return true;
  }();
  if (!once)
  {
    std::cerr << "Node::initPairing failed.\n";  // just to eliminate warnings from the compiler.
  }
}

void DKG::ResetCabinet()
{
  assert((threshold_ * 2) < cabinet_.size());
  assert(cabinet_.find(address_) != cabinet_.end());  // We should be in the cabinet
  finished_      = false;
  state_         = State::INITIAL;
  cabinet_index_ = static_cast<uint32_t>(std::distance(cabinet_.begin(), cabinet_.find(address_)));
  auto cabinet_size{static_cast<uint32_t>(cabinet_.size())};
  auto polynomial_size{static_cast<uint32_t>(threshold_ + 1)};
  Init(y_i, cabinet_size);
  Init(public_key_shares_, cabinet_size);
  Init(s_ij, cabinet_size, cabinet_size);
  Init(sprime_ij, cabinet_size, cabinet_size);
  Init(z_i, cabinet_size);
  Init(C_ik, cabinet_size, polynomial_size);
  Init(A_ik, cabinet_size, polynomial_size);
  Init(g__s_ij, cabinet_size, cabinet_size);
  Init(g__a_i, polynomial_size);

  complaints_received        = std::vector<bool>(cabinet_.size(), false);
  complaint_answers_received = std::vector<bool>(cabinet_.size(), false);
}

void DKG::SendBroadcast(DKGEnvelop const &env)
{
  dkg_service_.SendReliableBroadcast(env);
}

void DKG::OnDkgMessage(MuddleAddress const &from, std::shared_ptr<DKGMessage> msg_ptr)
{
  uint32_t senderIndex{CabinetIndex(from)};
  switch (msg_ptr->type())
  {
  case DKGMessage::MessageType::COEFFICIENT:
    FETCH_LOG_TRACE(LOGGING_NAME, "Node: ", cabinet_index_, " received RBroadcast from node ",
                    senderIndex);
    OnNewCoefficients(std::dynamic_pointer_cast<CoefficientsMessage>(msg_ptr), from);
    break;
  case DKGMessage::MessageType::SHARE:
    FETCH_LOG_TRACE(LOGGING_NAME, "Node: ", cabinet_index_, " received REcho from node ",
                    senderIndex);
    OnExposedShares(std::dynamic_pointer_cast<SharesMessage>(msg_ptr), from);
    break;
  case DKGMessage::MessageType::COMPLAINT:
    FETCH_LOG_TRACE(LOGGING_NAME, "Node: ", cabinet_index_, " received RReady from node ",
                    senderIndex);
    OnComplaints(std::dynamic_pointer_cast<ComplaintsMessage>(msg_ptr), from);
    break;
  default:
    FETCH_LOG_ERROR(LOGGING_NAME, "Node: ", cabinet_index_, " can not process payload from node ",
                    senderIndex);
  }
}

void DKG::BroadcastShares()
{
  std::vector<bn::Fr> a_i(threshold_ + 1, zeroFr_), b_i(threshold_ + 1, zeroFr_);

  // 1. Each party $P_i$ performs a Pedersen-VSS of a random
  //    value $z_i$ as a dealer:
  // (a) $P_i$ chooses two random polynomials $f_i(z)$ and
  //     $f\prime_i(z)$ over $\mathbb{Z}_q$ of degree $t$ where
  //     $f_i(z) = a_{i0} + a_{i1}z + \ldots + a_{it}z^t$ and
  //     $f\prime_i(z) = b_{i0} + b_{i1}z + \ldots + b_{it}z^t$
  for (size_t k = 0; k <= threshold_; k++)
  {
    a_i[k].setRand();
    b_i[k].setRand();
  }
  // Let $z_i = a_{i0} = f_i(0)$.
  z_i[cabinet_index_] = a_i[0];
  // $P_i$ broadcasts $C_{ik} = g^{a_{ik}} h^{b_{ik}} \bmod p$
  // for $k = 0, \ldots, t$.

  std::vector<MsgCoefficient> coefficients;
  for (size_t k = 0; k <= threshold_; k++)
  {
    C_ik[cabinet_index_][k] = ComputeLHS(g__a_i[k], group_g_, group_h_, a_i[k], b_i[k]);
    coefficients.push_back(C_ik[cabinet_index_][k].getStr());
  }
  SendBroadcast(DKGEnvelop{CoefficientsMessage{static_cast<uint8_t>(State::WAITING_FOR_SHARE),
                                               coefficients, "signature"}});

  // $P_i$ computes the shares $s_{ij} = f_i(j) \bmod q$,
  // $s\prime_{ij} = f\prime_i(j) \bmod q$ and
  // sends $s_{ij}$, $s\prime_{ij}$ to party $P_j$.
  uint32_t j = 0;
  for (auto &cab_i : cabinet_)
  {
    ComputeShares(s_ij[cabinet_index_][j], sprime_ij[cabinet_index_][j], a_i, b_i, j);
    if (j != cabinet_index_)
    {
      std::pair<MsgShare, MsgShare> shares{s_ij[cabinet_index_][j].getStr(),
                                           sprime_ij[cabinet_index_][j].getStr()};
      dkg_service_.SendShares(cab_i, shares);
    }
    ++j;
  }
  state_ = State::WAITING_FOR_SHARE;
}

void DKG::BroadcastComplaints()
{
  std::unordered_set<MuddleAddress> complaints_local;
  assert(complaints_local.empty());
  uint32_t i = 0;
  for (auto &cab : cabinet_)
  {
    if (i != cabinet_index_)
    {
      // Can only require this if G, H do not take the default values from clear()
      if (C_ik[i][0] != zeroG2_ && s_ij[i][cabinet_index_] != zeroFr_)
      {
        bn::G2 rhs, lhs;
        lhs = ComputeLHS(g__s_ij[i][cabinet_index_], group_g_, group_h_, s_ij[i][cabinet_index_],
                         sprime_ij[i][cabinet_index_]);
        rhs = ComputeRHS(cabinet_index_, C_ik[i]);
        if (lhs != rhs)
        {
          FETCH_LOG_WARN(LOGGING_NAME, "Node ", cabinet_index_,
                         " received bad coefficients/shares from ", CabinetIndex(cab));
          complaints_local.insert(cab);
        }
      }
      else
      {
        FETCH_LOG_WARN(LOGGING_NAME, "Node ", cabinet_index_,
                       " received vanishing coefficients/shares from ", i);
        complaints_local.insert(cab);
        ++complaints_counter[cab];
      }
    }
    ++i;
  }

  FETCH_LOG_INFO(LOGGING_NAME, "Node ", cabinet_index_, " broadcasts complaints size ",
                 complaints_local.size());
  SendBroadcast(DKGEnvelop{ComplaintsMessage{complaints_local, "signature"}});
  state_ = State::WAITING_FOR_COMPLAINTS;
}

void DKG::BroadcastComplaintsAnswer()
{
  std::unordered_map<MuddleAddress, std::pair<MsgShare, MsgShare>> complaints_answer;
  for (const auto &reporter : complaints_from)
  {
    uint32_t from_index{CabinetIndex(reporter)};
    complaints_answer.insert({reporter,
                              {s_ij[cabinet_index_][from_index].getStr(),
                               sprime_ij[cabinet_index_][from_index].getStr()}});
  }
  SendBroadcast(
      DKGEnvelop{SharesMessage{static_cast<uint64_t>(State::WAITING_FOR_COMPLAINT_ANSWERS),
                               complaints_answer, "signature"}});
  state_ = State::WAITING_FOR_COMPLAINT_ANSWERS;
}

void DKG::BroadcastQualComplaints()
{
  std::unordered_set<MuddleAddress> complaints_local;
  uint32_t                          i  = 0;
  auto                              iq = cabinet_.begin();
  for (const auto &miner : qual_)
  {
    while (*iq != miner)
    {
      ++iq;
      ++i;
    }
    if (i != cabinet_index_)
    {
      // Can only require this if G, H do not take the default values from clear()
      if (A_ik[i][0] != zeroG2_)
      {
        bn::G2 rhs, lhs;
        lhs = g__s_ij[i][cabinet_index_];
        rhs = ComputeRHS(cabinet_index_, A_ik[i]);
        if (lhs != rhs)
        {
          complaints_local.insert(miner);
        }
      }
      else
      {
        complaints_local.insert(miner);
      }
    }
  }

  std::unordered_map<MuddleAddress, std::pair<MsgShare, MsgShare>> QUAL_complaints;
  for (auto &c : complaints_local)
  {
    uint32_t c_index{CabinetIndex(c)};
    // logger.trace("node {} exposes shares of node {}", cabinet_index_, c_index);
    QUAL_complaints.insert(
        {c, {s_ij[cabinet_index_][c_index].getStr(), sprime_ij[cabinet_index_][c_index].getStr()}});
  }
  SendBroadcast(DKGEnvelop{SharesMessage{static_cast<uint64_t>(State::WAITING_FOR_QUAL_COMPLAINTS),
                                         QUAL_complaints, "signature"}});
  state_ = State::WAITING_FOR_QUAL_COMPLAINTS;
}

void DKG::BroadcastReconstructionShares()
{
  std::lock_guard<std::mutex> lock{mutex_};

  std::unordered_map<MuddleAddress, std::pair<MsgShare, MsgShare>> complaint_shares;
  for (const auto &in : complaints)
  {
    assert(qual_.find(in) != qual_.end());
    uint32_t in_index{CabinetIndex(in)};
    reconstruction_shares.insert({in, {{}, std::vector<bn::Fr>(cabinet_.size(), zeroFr_)}});
    reconstruction_shares.at(in).first.push_back(cabinet_index_);
    reconstruction_shares.at(in).second[cabinet_index_] = s_ij[in_index][cabinet_index_];
    complaint_shares.insert(
        {in,
         {s_ij[in_index][cabinet_index_].getStr(), sprime_ij[in_index][cabinet_index_].getStr()}});
  }
  SendBroadcast(
      DKGEnvelop{SharesMessage{static_cast<uint64_t>(State::WAITING_FOR_RECONSTRUCTION_SHARES),
                               complaint_shares, "signature"}});
  state_ = State::WAITING_FOR_RECONSTRUCTION_SHARES;
}

void DKG::OnNewShares(MuddleAddress from, std::pair<MsgShare, MsgShare> const &shares)
{
  uint32_t from_index{CabinetIndex(from)};
  s_ij[from_index][cabinet_index_].setStr(shares.first);
  sprime_ij[from_index][cabinet_index_].setStr(shares.second);

  msg_counter_.Increment(MsgCounter::Message::INITIAL_SHARE);
  if ((state_ == State::WAITING_FOR_SHARE) and
      (msg_counter_.Count(MsgCounter::Message::INITIAL_SHARE) == cabinet_.size() - 1) and
      (msg_counter_.Count(MsgCounter::Message::INITIAL_COEFFICIENT)) == cabinet_.size() - 1)
  {
    BroadcastComplaints();
  }
}

void DKG::OnNewCoefficients(const std::shared_ptr<CoefficientsMessage> &msg_ptr,
                            const MuddleAddress &                       from_id)
{
  uint32_t from_index{CabinetIndex(from_id)};
  if (msg_ptr->phase() == static_cast<uint64_t>(State::WAITING_FOR_SHARE))
  {
    bn::G2 zero;
    zero.clear();
    for (uint32_t ii = 0; ii <= threshold_; ++ii)
    {
      if (C_ik[from_index][ii] == zero)
      {
        C_ik[from_index][ii].setStr((msg_ptr->coefficients())[ii]);
      }
    }
    msg_counter_.Increment(MsgCounter::Message::INITIAL_COEFFICIENT);
    if ((state_ == State::WAITING_FOR_SHARE) and
        (msg_counter_.Count(MsgCounter::Message::INITIAL_SHARE) == cabinet_.size() - 1) and
        (msg_counter_.Count(MsgCounter::Message::INITIAL_COEFFICIENT)) == cabinet_.size() - 1)
    {
      BroadcastComplaints();
    }
  }
  else if (msg_ptr->phase() == static_cast<uint64_t>(State::WAITING_FOR_QUAL_SHARES))
  {
    bn::G2 zero;
    zero.clear();
    for (uint32_t ii = 0; ii <= threshold_; ++ii)
    {
      if (A_ik[from_index][ii] == zero)
      {
        A_ik[from_index][ii].setStr((msg_ptr->coefficients())[ii]);
      }
    }
    msg_counter_.Increment(MsgCounter::Message::QUAL_COEFFICIENT);
    if ((state_ == State::WAITING_FOR_QUAL_SHARES) and
        (msg_counter_.Count(MsgCounter::Message::QUAL_COEFFICIENT) == cabinet_.size() - 1))
    {
      BroadcastQualComplaints();
    }
  }
}

void DKG::OnComplaints(const std::shared_ptr<ComplaintsMessage> &msg_ptr,
                       const MuddleAddress &                     from_id)
{
  uint32_t                    from_index{CabinetIndex(from_id)};
  std::lock_guard<std::mutex> lock{mutex_};
  // Check if we have received a complaints message from this node before and if not log that we
  // received a complaint message
  if (!complaints_received[from_index])
  {
    complaints_received[from_index] = true;
  }
  else
  {
    complaints.insert(from_id);
    FETCH_LOG_WARN(LOGGING_NAME, "Node ", cabinet_index_, " received multiple complaints from ",
                   from_index);
    return;
  }

  for (const auto &bad_node : msg_ptr->complaints())
  {
    /* Obsolete as the message now contains a set
    // Keep track of the nodes which are included in complaint. If there are duplicates then we add
    the sender
    // to complaints
    if (complaints_from_sender.find(complaint.nodes(ii)) != complaints_from_sender.end()) {
        complaints.insert(from_id);
    } else {
        complaints_from_sender.insert(complaint.nodes(ii));
        ++complaints_counter[complaint.nodes(ii)];
    }
     */
    ++complaints_counter[bad_node];
    // If a node receives complaint against itself then store in complaints from
    // for answering later
    if (bad_node == address_)
    {
      FETCH_LOG_INFO(LOGGING_NAME, "Node ", cabinet_index_, " received complaint from node ",
                     from_index);
      complaints_from.insert(from_id);
    }
  }
  msg_counter_.Increment(MsgCounter::Message::COMPLAINT);
  if (state_ == State::WAITING_FOR_COMPLAINTS and
      (msg_counter_.Count(MsgCounter::Message::COMPLAINT) == cabinet_.size() - 1))
  {
    // Add miners which did not send a complaint to complaints (redundant for now but will be
    // necessary when we do not wait for a message from everyone)
    auto miner_it = cabinet_.begin();
    for (uint32_t ii = 0; ii < complaints_received.size(); ++ii)
    {
      if (!complaints_received[ii] and ii != cabinet_index_)
      {
        FETCH_LOG_WARN(LOGGING_NAME, "Node ", cabinet_index_, "received no complaint from node ",
                       ii);
        complaints.insert(*miner_it);
      }
      ++miner_it;
    }
    // All miners who have received over t complaints are also disqualified
    for (const auto &node_complaints : complaints_counter)
    {
      if (node_complaints.second > threshold_)
      {
        FETCH_LOG_INFO(LOGGING_NAME, "Node ", cabinet_index_,
                       "received greater than threshold complaints for node ",
                       CabinetIndex(node_complaints.first));
        complaints.insert(node_complaints.first);
      }
    }
    BroadcastComplaintsAnswer();
  }
}

void DKG::OnExposedShares(const std::shared_ptr<SharesMessage> &shares,
                          const MuddleAddress &                 from_id)
{
  uint64_t phase1{shares->phase()};
  if (phase1 == static_cast<uint64_t>(State::WAITING_FOR_COMPLAINT_ANSWERS))
  {
    FETCH_LOG_INFO(LOGGING_NAME, "Node: ", cabinet_index_, " received complaint answer from ",
                   CabinetIndex(from_id));
    OnComplaintsAnswer(shares, from_id);
  }
  else if (phase1 == static_cast<uint64_t>(State::WAITING_FOR_QUAL_COMPLAINTS))
  {
    FETCH_LOG_INFO(LOGGING_NAME, "Node: ", cabinet_index_, " received QUAL complaint from ",
                   CabinetIndex(from_id));
    OnQualComplaints(shares, from_id);
  }
  else if (phase1 == static_cast<uint64_t>(State::WAITING_FOR_RECONSTRUCTION_SHARES))
  {
    FETCH_LOG_INFO(LOGGING_NAME, "Node: ", cabinet_index_, " received reconstruction share from ",
                   CabinetIndex(from_id));
    OnReconstructionShares(shares, from_id);
  }
}

void DKG::OnComplaintsAnswer(const std::shared_ptr<SharesMessage> &answer,
                             const MuddleAddress &                 from_id)
{
  uint32_t from_index{CabinetIndex(from_id)};
  for (const auto &share : answer->shares())
  {
    uint32_t reporter_index{CabinetIndex(share.first)};
    // Verify shares received
    bn::Fr s, sprime;
    bn::G2 lhsG, rhsG;
    s.clear();
    sprime.clear();
    lhsG.clear();
    rhsG.clear();
    s.setStr(share.second.first);
    sprime.setStr(share.second.second);
    rhsG = ComputeRHS(from_index, C_ik[reporter_index]);
    lhsG = ComputeLHS(group_g_, group_h_, s, sprime);
    if (lhsG != rhsG)
    {
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_, " verification for node ",
                     CabinetIndex(from_id), " complaint answer failed");
      complaints.insert(from_id);
    }
    else
    {
      FETCH_LOG_INFO(LOGGING_NAME, "Node: ", cabinet_index_, " verification for node ",
                     CabinetIndex(from_id), " complaint answer succeeded");
      if (reporter_index == cabinet_index_)
      {
        s_ij[from_index][cabinet_index_]      = s;
        sprime_ij[from_index][cabinet_index_] = sprime;
      }
    }
  }
  complaint_answers_received[from_index] = true;
  msg_counter_.Increment(MsgCounter::Message::COMPLAINT_ANSWER);
  assert(complaints.empty());
  if (state_ == State::WAITING_FOR_COMPLAINT_ANSWERS and
      (msg_counter_.Count(MsgCounter::Message::COMPLAINT_ANSWER) == cabinet_.size() - 1))
  {
    // Add miners which did not send a complaint to complaints (redundant for now but will be
    // necessary when we do not wait for a message from everyone)
    auto miner_it = cabinet_.begin();
    for (uint32_t ii = 0; ii < complaint_answers_received.size(); ++ii)
    {
      if (!complaint_answers_received[ii] and ii != cabinet_index_)
      {
        FETCH_LOG_INFO(LOGGING_NAME, "Node ", cabinet_index_,
                       " received no complaint answer from node ", ii);
        complaints.insert(*miner_it);
      }
      ++miner_it;
    }
    if (BuildQual())
    {
      FETCH_LOG_INFO(LOGGING_NAME, "Node: ", cabinet_index_, " build QUAL of size ", qual_.size());
      ComputeSecretShare();
    }
    else
    {
      // TODO(jmw): procedure failed for this node
    }
  }
}

bool DKG::BuildQual()
{
  // Altogether, complaints consists of
  // 1. Nodes who did not send, sent too many or sent duplicate complaints
  // 2. Nodes which received over t complaints
  // 3. Nodes who did not complaint answers
  // 4. Complaint answers which were false
  FETCH_LOG_INFO(LOGGING_NAME, "Node ", cabinet_index_, " has complaints size ", complaints.size());
  for (const auto &node : cabinet_)
  {
    if (complaints.find(node) == complaints.end())
    {
      qual_.insert(node);
    }
  }
  if (qual_.find(address_) == qual_.end() or qual_.size() <= threshold_)
  {
    if (qual_.find(address_) == qual_.end())
    {
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_, " build QUAL failed as not in QUAL");
    }
    else
    {
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_, " build QUAL failed as size ",
                     qual_.size(), " less than threshold ", threshold_);
    }
    return false;
  }
  return true;
}

void DKG::ComputeSecretShare()
{
  // 3. Each party $P_i$ sets their secret_share = x_i as
  //    $x_i = \sum_{j \in QUAL} s_{ji} \bmod q$ and the value
  //    $x\prime_i = \sum_{j \in QUAL} s\prime_{ji} \bmod q$.
  secret_share_.clear();
  xprime_i = 0;
  for (const auto &iq : qual_)
  {
    uint32_t iq_index = CabinetIndex(iq);
    bn::Fr::add(secret_share_, secret_share_, s_ij[iq_index][cabinet_index_]);
    bn::Fr::add(xprime_i, xprime_i, sprime_ij[iq_index][cabinet_index_]);
  }
  // 4. Each party $i \in QUAL$ exposes $y_i = g^{z_i} \bmod p$
  //    via Feldman-VSS:
  // (a) Each party $P_i$, $i \in QUAL$, broadcasts $A_{ik} =
  //     g^{a_{ik}} \bmod p$ for $k = 0, \ldots, t$.

  std::vector<MsgCoefficient> coefficients;
  for (size_t k = 0; k <= threshold_; k++)
  {
    A_ik[cabinet_index_][k] = g__a_i[k];
    coefficients.push_back(A_ik[cabinet_index_][k].getStr());
  }
  SendBroadcast(DKGEnvelop{CoefficientsMessage{static_cast<uint8_t>(State::WAITING_FOR_QUAL_SHARES),
                                               coefficients, "signature"}});
  state_ = State::WAITING_FOR_QUAL_SHARES;
  complaints.clear();
}

void DKG::OnQualComplaints(const std::shared_ptr<SharesMessage> &shares_ptr,
                           const MuddleAddress &                 from_id)
{
  uint32_t from_index{CabinetIndex(from_id)};
  for (const auto &share : shares_ptr->shares())
  {
    // Check person who's shares are being exposed is not in QUAL then don't bother with checks
    if (qual_.find(share.first) != qual_.end())
    {
      // verify complaint, i.e. (4) holds (5) not
      bn::G2 lhs, rhs;
      bn::Fr s, sprime;
      lhs.clear();
      rhs.clear();
      s.clear();
      sprime.clear();
      s.setStr(share.second.first);
      sprime.setStr(share.second.second);
      // check equation (4)
      lhs = ComputeLHS(group_g_, group_h_, s, sprime);
      rhs = ComputeRHS(CabinetIndex(share.first), C_ik[from_index]);
      if (lhs != rhs)
      {
        complaints.insert(from_id);
      }
      // check equation (5)
      bn::G2::mul(lhs, group_g_, s);  // G^s
      rhs = ComputeRHS(cabinet_index_, A_ik[from_index]);
      if (lhs != rhs)
      {
        complaints.insert(share.first);
      }
      else
      {
        complaints.insert(from_id);
      }
    }
  }
  qual_complaints_received.insert(from_id);
  if (state_ == State::WAITING_FOR_QUAL_COMPLAINTS and
      (qual_complaints_received.size() == qual_.size() - 1))
  {
    // Add QUAL members which did not send a complaint to complaints (redundant for now but will be
    // necessary when we do not wait for a message from everyone)
    for (const auto &iq : qual_)
    {
      if (iq != address_ and qual_complaints_received.find(iq) == qual_complaints_received.end())
      {
        complaints.insert(iq);
      }
    }

    if (complaints.size() > threshold_)
    {
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_,
                     " protocol has failed: complaints size ", complaints.size());
      return;
    }
    else if (complaints.find(address_) != complaints.end())
    {
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_, " protocol has failed: in complaints");
      return;
    }
    assert(qual_.find(address_) != qual_.end());
    BroadcastReconstructionShares();
  }
}

void DKG::OnReconstructionShares(const std::shared_ptr<SharesMessage> &shares_ptr,
                                 const MuddleAddress &                 from_id)
{
  // Return if the sender is in complaints, or not in QUAL
  if (complaints.find(from_id) != complaints.end() or qual_.find(from_id) == qual_.end())
  {
    return;
  }
  uint32_t from_index{CabinetIndex(from_id)};
  for (const auto &share : shares_ptr->shares())
  {
    uint32_t victim_index{CabinetIndex(share.first)};
    assert(complaints.find(share.first) != complaints.end());
    bn::G2 lhs, rhs;
    bn::Fr s, sprime;
    lhs.clear();
    rhs.clear();
    s.clear();
    sprime.clear();

    s.setStr(share.second.first);
    sprime.setStr(share.second.second);
    lhs = ComputeLHS(group_g_, group_h_, s, sprime);
    rhs = ComputeRHS(from_index, C_ik[victim_index]);
    // check equation (4)
    if (lhs == rhs and reconstruction_shares.at(share.first).second[from_index] == zeroFr_)
    {
      std::lock_guard<std::mutex> lock{mutex_};
      reconstruction_shares.at(share.first).first.push_back(from_index);  // good share received
      reconstruction_shares.at(share.first).second[from_index] = s;
    }
  }
  msg_counter_.Increment(MsgCounter::Message::RECONSTRUCTION_SHARE);
  if (state_ == State::WAITING_FOR_RECONSTRUCTION_SHARES and
      msg_counter_.Count(MsgCounter::Message::RECONSTRUCTION_SHARE) ==
          qual_.size() - complaints.size() - 1)
  {
    if (!RunReconstruction())
    {
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_,
                     " DKG failed due to reconstruction failure");
    }
    else
    {
      ComputePublicKeys();
      finished_ = true;
      Clear();
    }
  }
}

bool DKG::RunReconstruction()
{
  std::vector<std::vector<bn::Fr>> a_ik;
  Init(a_ik, static_cast<uint32_t>(cabinet_.size()), static_cast<uint32_t>(threshold_ + 1));
  for (const auto &in : reconstruction_shares)
  {
    std::vector<uint32_t> parties{in.second.first};
    std::vector<bn::Fr>   shares{in.second.second};
    if (parties.size() <= threshold_)
    {
      // Do not have enough good shares to be able to do reconstruction
      FETCH_LOG_WARN(LOGGING_NAME, "Node: ", cabinet_index_, " reconstruction for ", in.first,
                     " failed with party size ", parties.size());
      return false;
    }
    // compute $z_i$ using Lagrange interpolation (without corrupted parties)
    uint32_t victim_index{CabinetIndex(in.first)};
    z_i[victim_index] = ComputeZi(in.second.first, in.second.second);
    std::vector<bn::Fr> points(parties.size(), 0), shares_f(parties.size(), 0);
    for (size_t k = 0; k < parties.size(); k++)
    {
      points[k]   = parties[k] + 1;  // adjust index in computation
      shares_f[k] = shares[parties[k]];
    }
    a_ik[victim_index] = InterpolatePolynom(points, shares_f);
    // compute $A_{ik} = g^{a_{ik}} \bmod p$
    for (size_t k = 0; k <= threshold_; k++)
    {
      bn::G2::mul(A_ik[victim_index][k], group_g_, a_ik[victim_index][k]);
    }
  }
  return true;
}

void DKG::ComputePublicKeys()
{
  FETCH_LOG_INFO(LOGGING_NAME, "Node: ", cabinet_index_, " compute public keys");
  // For all parties in $QUAL$, set $y_i = A_{i0} = g^{z_i} \bmod p$.
  for (const auto &iq : qual_)
  {
    uint32_t it{CabinetIndex(iq)};
    y_i[it] = A_ik[it][0];
  }
  // Compute $y = \prod_{i \in QUAL} y_i \bmod p$
  public_key_.clear();
  for (const auto &iq : qual_)
  {
    uint32_t it{CabinetIndex(iq)};
    bn::G2::add(public_key_, public_key_, y_i[it]);
  }
  // Compute public_key_shares_ $v_j = \prod_{i \in QUAL} \prod_{k=0}^t (A_{ik})^{j^k} \bmod
  // p$
  for (const auto &jq : qual_)
  {
    uint32_t jt{CabinetIndex(jq)};
    for (const auto &iq : qual_)
    {
      uint32_t it{CabinetIndex(iq)};
      bn::G2::add(public_key_shares_[jt], public_key_shares_[jt], A_ik[it][0]);
      UpdateRHS(jt, public_key_shares_[jt], A_ik[it]);
    }
  }
}

uint32_t DKG::CabinetIndex(const MuddleAddress &other_address) const
{
  return static_cast<uint32_t>(std::distance(cabinet_.begin(), cabinet_.find(other_address)));
}

void DKG::Clear()
{
  complaints_counter.clear();
  complaints.clear();
  complaints_from.clear();
  complaints_received.clear();
  complaint_answers_received.clear();
  qual_complaints_received.clear();
  msg_counter_.Clear();
}

bool DKG::finished() const
{
  return finished_.load();
}
}  // namespace dkg
}  // namespace fetch
