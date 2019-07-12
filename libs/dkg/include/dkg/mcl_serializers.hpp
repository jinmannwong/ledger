#pragma once

#include "mcl/bn256.hpp"

template<typename T>
void Serialize(T &serializer, mcl::bn256::Fr const &x) {
    serializer << x.getStr();
}

template<typename T>
void Deserialize(T &serializer, mcl::bn256::Fr &x) {
    std::string x_str;
    serializer >> x_str;
    x.setStr(x_str);
}

template<typename T>
void Serialize(T &serializer, mcl::bn256::G2 const &x) {
    serializer << x.getStr();
}

template<typename T>
void Deserialize(T &serializer, mcl::bn256::G2 &x) {
    std::string x_str;
    serializer >> x_str;
    x.setStr(x_str);
}