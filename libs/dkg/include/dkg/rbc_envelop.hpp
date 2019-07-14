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

#include "core/serializers/byte_array.hpp"
#include "dkg/rbc_messages.hpp"
#include "network/muddle/packet.hpp"

namespace fetch {
namespace dkg {
namespace rbc {

class RBCEnvelop
{
  using MessageType = RBCMessage::MessageType;
  using Payload     = byte_array::ConstByteArray;

public:
  RBCEnvelop() = default;

  explicit RBCEnvelop(const RBCMessage &msg)
    : type_{msg.Type()}
    , serialisedMessage_{msg.Serialize().data()} {};

  template <typename T>
  void Serialize(T &serialiser) const
  {
    serialiser << (uint8_t)type_ << serialisedMessage_;
  }

  template <typename T>
  void Deserialize(T &serialiser)
  {
    uint8_t val;
    serialiser >> val;
    type_ = (MessageType)val;
    serialiser >> serialisedMessage_;
  }

  std::shared_ptr<RBCMessage> Message() const;

private:
  RBCMessage::MessageType type_;
  Payload                 serialisedMessage_;
};

template <typename T>
inline void Serialize(T &serializer, RBCEnvelop const &env)
{
  env.Serialize(serializer);
}

template <typename T>
inline void Deserialize(T &serializer, RBCEnvelop &env)
{
  env.Deserialize(serializer);
}
}  // namespace rbc
}  // namespace dkg
}  // namespace fetch
