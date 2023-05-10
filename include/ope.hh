/*
 * @Author: RyanCLQ
 * @Date: 2023-03-31 11:14:15
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-09 16:55:12
 * @Description: 请填写简介
 */
#pragma once

#include "prng.hh"
#include "hgd.hh"
#include "aes.hh"
#include "sm4_bs.hh"
#include "wbsm4_se.hh"
#include "sha.hh"
#include "hmac.hh"
#include "zz.hh"

#include <string>
#include <map>

#include <NTL/ZZ.h>
#include <NTL/RR.h>

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
    : key(keyarg), pbits(plainbits), cbits(cipherbits), block_key1(seed(key)), block_key2(seed(key)){}//哈希处理密钥，使得可以输入不同长度的密钥

    NTL::ZZ encrypt_sm4(const NTL::ZZ &ptext);
    NTL::ZZ encrypt_wbsm4(const NTL::ZZ &ptext);
    NTL::ZZ encrypt_sm4(int ptext);
    NTL::ZZ encrypt_wbsm4(int ptext);
    NTL::RR encrypt_sm4(const NTL::RR &ptext);
    NTL::RR encrypt_wbsm4(const NTL::RR &ptext);
    NTL::RR encrypt_sm4(float ptext);
    NTL::RR encrypt_wbsm4(float ptext);

    NTL::ZZ decrypt_sm4(const NTL::ZZ &ctext);
    NTL::ZZ decrypt_wbsm4(const NTL::ZZ &ctext);
    NTL::RR decrypt_sm4(const NTL::RR &ctext);
    NTL::RR decrypt_wbsm4(const NTL::RR &ctext);

 private:
    static std::string seed(const std::string &key) {
        auto v = sha256::hash(key);
        v.resize(16);
        return v;
    }

    std::string key;
    size_t pbits, cbits;

    SM4BS block_key1;
    WBSM4SE block_key2;
    std::map<NTL::ZZ, NTL::ZZ> dgap_cache;

    template<class CB>
    ope_domain_range search_sm4(CB go_low);

    template<class CB>
    ope_domain_range search_wbsm4(CB go_low);

    template<class CB>
    ope_domain_range lazy_sample_sm4(const NTL::ZZ &d_lo, const NTL::ZZ &d_hi,
                                 const NTL::ZZ &r_lo, const NTL::ZZ &r_hi,
                                 CB go_low, blockrng<SM4BS> *prng);
    
    template<class CB>
    ope_domain_range lazy_sample_wbsm4(const NTL::ZZ &d_lo, const NTL::ZZ &d_hi,
                                const NTL::ZZ &r_lo, const NTL::ZZ &r_hi,
                                CB go_low, blockrng<WBSM4SE> *prng);
};
