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

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <mcl/bn256.hpp>
#include <sstream>
#include <unordered_map>

namespace bn = mcl::bn256;

namespace fetch {
namespace dkg {

bn::G2 computeLHS(bn::G2 &tmpG, const bn::G2 &G, const bn::G2 &H, const bn::Fr &share1,
                  const bn::Fr &share2);

bn::G2 computeLHS(const bn::G2 &G, const bn::G2 &H, const bn::Fr &share1, const bn::Fr &share2);

void updateRHS(size_t rank, bn::G2 &rhsG, const std::vector<bn::G2> &input);

bn::G2 computeRHS(size_t rank, const std::vector<bn::G2> &input);

void computeShares(bn::Fr &s_i, bn::Fr &sprime_i, const std::vector<bn::Fr> &a_i,
                   const std::vector<bn::Fr> &b_i, size_t rank);

bn::Fr computeZi(const std::vector<size_t> &parties, const std::vector<bn::Fr> &shares);

std::vector<bn::Fr> interpolatePolynom(const std::vector<bn::Fr> &a, const std::vector<bn::Fr> &b);

bn::G1 signShare(const std::string &message, const bn::Fr &x_i);

bool verifyShare(const bn::G2 &v_i, const std::string &message, const bn::G1 &sign,
                 const bn::G2 &G);

bool verifySign(const bn::G2 &y, const std::string &message, const bn::G1 &sign, const bn::G2 &G);

bn::G1 lagrangeInterpolation(const std::unordered_map<size_t, bn::G1> &shares);
}  // namespace dkg
}  // namespace fetch
