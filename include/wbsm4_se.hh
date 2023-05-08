/*
 * @Author: RyanCLQ
 * @Date: 2023-05-05 15:43:20
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-05 16:21:46
 * @Description: 请填写简介
 */
#pragma once

#include <stdint.h>
#include <string>
#include <cstring>
#include <vector>
#include "crypto/wbsm4_se.h"
#include "errstream.hh"

class WBSM4SE {
 public:
    WBSM4SE(const std::string &key) {
        throw_c(key.size() == 16);
        std::vector<uint8_t> key_vector(key.begin(), key.end());
        uint8_t* key_data = key_vector.data();
        wbsm4_gen(key_data);
    }

    void block_encrypt(const void *ptext, void *ctext, int size)  {
        wbsm4_encrypt((uint8_t*) ptext,(uint8_t*) ctext);
    }


    static const size_t blocksize = 16;

};

