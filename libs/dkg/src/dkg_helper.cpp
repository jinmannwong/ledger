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
#include <cstddef>
#include <iostream>
#include <mcl/bn256.hpp>

namespace bn = mcl::bn256;

namespace fetch {
namespace dkg {
bn::G2 computeLHS(bn::G2 &tmpG, const bn::G2 &G, const bn::G2 &H, const bn::Fr &share1,
                  const bn::Fr &share2)
{
  bn::G2 tmp2G, lhsG;
  tmp2G.clear();
  lhsG.clear();
  bn::G2::mul(tmpG, G, share1);
  bn::G2::mul(tmp2G, H, share2);
  bn::G2::add(lhsG, tmpG, tmp2G);

  return lhsG;
}

bn::G2 computeLHS(const bn::G2 &G, const bn::G2 &H, const bn::Fr &share1, const bn::Fr &share2)
{
  bn::G2 tmpG;
  tmpG.clear();
  return computeLHS(tmpG, G, H, share1, share2);
}

void updateRHS(size_t rank, bn::G2 &rhsG, const std::vector<bn::G2> &input)
{
  bn::Fr tmpF{1};
  bn::G2 tmpG;
  tmpG.clear();
  assert(input.size() > 0);
  for (size_t k = 1; k < input.size(); k++)
  {
    bn::Fr::pow(tmpF, rank + 1, k);  // adjust index $i$ in computation
    bn::G2::mul(tmpG, input[k], tmpF);
    bn::G2::add(rhsG, rhsG, tmpG);
  }
}

bn::G2 computeRHS(size_t rank, const std::vector<bn::G2> &input)
{
  bn::Fr tmpF;
  bn::G2 tmpG, rhsG;
  tmpG.clear();
  rhsG.clear();
  assert(input.size() > 0);
  // initialize rhsG
  rhsG = input[0];
  updateRHS(rank, rhsG, input);
  return rhsG;
}

void computeShares(bn::Fr &s_i, bn::Fr &sprime_i, const std::vector<bn::Fr> &a_i,
                   const std::vector<bn::Fr> &b_i, size_t rank)
{
  bn::Fr pow, tmpF;
  assert(a_i.size() == b_i.size());
  assert(a_i.size() > 0);
  s_i      = a_i[0];
  sprime_i = b_i[0];
  for (size_t k = 1; k < a_i.size(); k++)
  {
    bn::Fr::pow(pow, rank + 1, k);   // adjust index $j$ in computation
    bn::Fr::mul(tmpF, pow, b_i[k]);  // j^k * b_i[k]
    bn::Fr::add(sprime_i, sprime_i, tmpF);
    bn::Fr::mul(tmpF, pow, a_i[k]);  // j^k * a_i[k]
    bn::Fr::add(s_i, s_i, tmpF);
  }
}

bn::Fr computeZi(const std::vector<size_t> &parties, const std::vector<bn::Fr> &shares)
{
  // compute $z_i$ using Lagrange interpolation (without corrupted parties)
  bn::Fr z{0};
  for (auto jt : parties)
  {
    // compute optimized Lagrange coefficients
    bn::Fr rhsF{1}, lhsF{1}, tmpF;
    for (auto lt : parties)
    {
      if (lt != jt)
        // adjust index in computation
        bn::Fr::mul(rhsF, rhsF, lt + 1);
    }
    for (auto lt : parties)
    {
      if (lt != jt)
      {
        tmpF = (lt + 1);
        bn::Fr::sub(tmpF, tmpF, (jt + 1));
        bn::Fr::mul(lhsF, lhsF, tmpF);
      }
    }
    bn::Fr::neg(lhsF, lhsF);

    bn::Fr::mul(rhsF, rhsF, lhsF);
    bn::Fr::mul(tmpF, rhsF, shares[jt]);  // use the provided shares (interpolation points)
    bn::Fr::add(z, z, tmpF);
  }
  return z;
}

std::vector<bn::Fr> interpolatePolynom(const std::vector<bn::Fr> &a, const std::vector<bn::Fr> &b)
{
  size_t m = a.size();
  if ((b.size() != m) || (m == 0))
    throw std::invalid_argument("mcl_interpolate_polynom: bad m");
  std::vector<bn::Fr> prod{a}, res(m, 0);
  bn::Fr              t1, t2;
  for (size_t k = 0; k < m; k++)
  {
    t1 = 1;
    for (long i = k - 1; i >= 0; i--)
    {
      bn::Fr::mul(t1, t1, a[k]);
      bn::Fr::add(t1, t1, prod[i]);
    }

    t2 = 0;
    for (long i = k - 1; i >= 0; i--)
    {
      bn::Fr::mul(t2, t2, a[k]);
      bn::Fr::add(t2, t2, res[i]);
    }
    //	throw false;
    bn::Fr::neg(t1, t1);

    bn::Fr::sub(t2, b[k], t2);
    bn::Fr::mul(t1, t1, t2);

    for (size_t i = 0; i < k; i++)
    {
      bn::Fr::mul(t2, prod[i], t1);
      bn::Fr::add(res[i], res[i], t2);
    }
    res[k] = t1;
    if (k < (m - 1))
    {
      if (k == 0)
        bn::Fr::neg(prod[0], prod[0]);
      else
      {
        bn::Fr::neg(t1, a[k]);
        bn::Fr::add(prod[k], t1, prod[k - 1]);
        for (long i = k - 1; i >= 1; i--)
        {
          bn::Fr::mul(t2, prod[i], t1);
          bn::Fr::add(prod[i], t2, prod[i - 1]);
        }
        bn::Fr::mul(prod[0], prod[0], t1);
      }
    }
  }
  return res;
}

bn::G1 signShare(const std::string &message, const bn::Fr &x_i)
{
  bn::Fp Hm;
  bn::G1 PH;
  bn::G1 sign;
  sign.clear();
  Hm.setHashOf(message);
  bn::mapToG1(PH, Hm);
  bn::G1::mul(sign, PH, x_i);  // sign = s H(m)
  return sign;
}

bool verifyShare(const bn::G2 &v_i, const std::string &message, const bn::G1 &sign, const bn::G2 &G)
{
  bn::Fp12 e1, e2;
  bn::Fp   Hm;
  bn::G1   PH;
  Hm.setHashOf(message);
  bn::mapToG1(PH, Hm);

  bn::pairing(e1, sign, G);  // should this be H?
  bn::pairing(e2, PH, v_i);
  return e1 == e2;
}

bool verifySign(const bn::G2 &y, const std::string &message, const bn::G1 &sign, const bn::G2 &G)
{
  bn::Fp12 e1, e2;
  bn::Fp   Hm;
  bn::G1   PH;
  Hm.setHashOf(message);
  bn::mapToG1(PH, Hm);

  bn::pairing(e1, sign, G);
  bn::pairing(e2, PH, y);

  return e1 == e2;
}

bn::G1 lagrangeInterpolation(const std::unordered_map<size_t, bn::G1> &shares)
{
  assert(shares.size() > 0);
  if (shares.size() == 1)
  {
    return shares.begin()->second;
  }
  bn::G1 res;
  res.clear();
  /*
    delta_{i,S}(0) = prod_{j != i} S[j] / (S[j] - S[i]) = a / b
    where a = prod S[j], b = S[i] * prod_{j != i} (S[j] - S[i])
  */
  bn::Fr a{1};
  for (auto &p : shares)
  {
    a *= bn::Fr(p.first + 1);
  }
  /*
    f(0) = sum_i f(S[i]) delta_{i,S}(0)
  */
  for (auto &p1 : shares)
  {
    bn::Fr b(p1.first + 1);
    for (auto &p2 : shares)
    {
      if (p2.first != p1.first)
      {
        b *= bn::Fr(p2.first - p1.first);
      }
    }
    bn::G1 t;
    bn::G1::mul(t, p1.second, a / b);
    res += t;
  }
  return res;
}
}  // namespace dkg
}  // namespace fetch
