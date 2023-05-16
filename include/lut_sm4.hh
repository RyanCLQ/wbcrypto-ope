/*
 * @Author: RyanCLQ
 * @Date: 2023-05-16 19:54:54
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-16 20:00:42
 * @Description: 请填写简介
 */
#pragma once

#include <stdint.h>
#include <string>
#include <cstring>
#include <vector>
#include "crypto/lut_sm4.h"
#include "errstream.hh"

class LUTSM4 {
 public:
    LUTSM4(const std::string &key) {
        throw_c(key.size() == 16);
        std::vector<uint8_t> key_vector(key.begin(), key.end());
        uint8_t* key_data = key_vector.data();
        SM4_KeyInit(key_data,&sm4_key);
    }

    void block_encrypt(const void *ptext, void *ctext)  {
        SM4_Encrypt((uint8_t*) ptext,(uint8_t*) ctext, sm4_key);
    }


    static const size_t blocksize = 16;

 private:
    SM4_Key sm4_key;
};

