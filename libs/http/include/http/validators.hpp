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

#include "core/byte_array/const_byte_array.hpp"
#include "variant/variant.hpp"

#include <functional>

namespace fetch {
namespace http {
namespace validators {

struct Validator
{
  byte_array::ConstByteArray                      description;
  std::function<bool(byte_array::ConstByteArray)> validator;
  variant::Variant                                schema;
};

Validator StringValue(uint16_t min_length = 0, uint16_t max_length = uint16_t(-1));

}  // namespace validators
}  // namespace http
}  // namespace fetch
