/*
 * @Author: RyanCLQ
 * @Date: 2023-03-31 11:14:15
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-04 18:06:19
 * @Description: 请填写简介
 */
#pragma once

#include "prng.hh"
#include "hgd.hh"
#include "aes.hh"
#include "sm4_bs.hh"
#include "sha.hh"
#include "hmac.hh"
#include "zz.hh"

#include <string>
#include <map>

#include <NTL/ZZ.h>

class ope_domain_range {
 public:
    ope_domain_range(const NTL::ZZ &d_arg,
                     const NTL::ZZ &r_lo_arg,
                     const NTL::ZZ &r_hi_arg)
        : d(d_arg), r_lo(r_lo_arg), r_hi(r_hi_arg) {}
    NTL::ZZ d, r_lo, r_hi;
};

class OPE {
 public:
    OPE(const std::string &keyarg, size_t plainbits, size_t cipherbits)
    : key(keyarg), pbits(plainbits), cbits(cipherbits), block_key(seed(key)) {}

    NTL::ZZ encrypt(const NTL::ZZ &ptext);
    NTL::ZZ encrypt(int ptext);
    NTL::ZZ decrypt(const NTL::ZZ &ctext);

 private:
    static std::string seed(const std::string &key) {
        auto v = sha256::hash(key);
        v.resize(16);
        return v;
    }

    std::string key;
    size_t pbits, cbits;

    SM4BS block_key;
    std::map<NTL::ZZ, NTL::ZZ> dgap_cache;

    template<class CB>
    ope_domain_range search(CB go_low);

    template<class CB>
    ope_domain_range lazy_sample(const NTL::ZZ &d_lo, const NTL::ZZ &d_hi,
                                 const NTL::ZZ &r_lo, const NTL::ZZ &r_hi,
                                 CB go_low, blockrng<SM4BS> *prng);
};