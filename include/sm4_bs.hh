/*
 * @Author: RyanCLQ
 * @Date: 2023-05-04 17:02:24
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-04 18:04:03
 * @Description: 请填写简介
 */
#pragma once

#include <stdint.h>
#include <string>
#include <cstring>
#include <vector>
#include "sm4_bs.h"
#include "errstream.hh"

class SM4BS {
 public:
    SM4BS(const std::string &key) {
        throw_c(key.size() == 16);
        std::vector<uint8_t> key_vector(key.begin(), key.end());
        uint8_t* key_data = key_vector.data();
        sm4_bs256_key_schedule(key_data,rk);
    }

    void block_encrypt(const void *ptext, void *ctext, int size)  {
        sm4_bs256_ecb_encrypt((uint8_t*) ctext,(uint8_t*) ptext,size,rk);
    }


    static const size_t blocksize = 16;

 private:
    __m256i rk[32][32];
};

