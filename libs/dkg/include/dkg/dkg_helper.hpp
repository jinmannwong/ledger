#pragma once

#include <array>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstddef>
#include <mcl/bn256.hpp>

namespace bn = mcl::bn256;

namespace fetch {
namespace dkg {


    bn::G2 computeLHS(bn::G2 &tmpG, const bn::G2 &G, const bn::G2 &H, const bn::Fr &share1, const bn::Fr &share2);

    bn::G2 computeLHS(const bn::G2 &G, const bn::G2 &H, const bn::Fr &share1, const bn::Fr &share2);

    void updateRHS(size_t rank, bn::G2 &rhsG, const std::vector<bn::G2> &input);

    bn::G2 computeRHS(size_t rank, const std::vector<bn::G2> &input);

    void computeShares(bn::Fr &s_i, bn::Fr &sprime_i, const std::vector<bn::Fr> &a_i, const std::vector<bn::Fr> &b_i,
                       size_t rank);

    bn::Fr computeZi(const std::vector<size_t> &parties, const std::vector<bn::Fr> &shares);

    std::vector<bn::Fr> interpolatePolynom(const std::vector<bn::Fr> &a, const std::vector<bn::Fr> &b);

    bn::G1 signShare(const std::string &message, const bn::Fr &x_i);

    bool verifyShare(const bn::G2 &v_i, const std::string &message, const bn::G1 &sign, const bn::G2 &G);

    bool verifySign(const bn::G2 &y, const std::string &message, const bn::G1 &sign, const bn::G2 &G);

    bn::G1 lagrangeInterpolation(const std::unordered_map<size_t, bn::G1> &shares);
}
}
