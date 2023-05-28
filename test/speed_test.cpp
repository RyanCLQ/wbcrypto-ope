/*
 * @Author: RyanCLQ
 * @Date: 2023-05-05 15:34:15
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-14 22:09:04
 * @Description: 请填写简介
 */
#include<iostream>
#include<time.h>
#include "ope.hh"
using namespace std;

#define TESTTIME 10000

int main(){

	// plaintext range's length in bits (plaintexts are in [0, 2**P-1]
	unsigned int P = 16;//基于超几何分布，不能有负数，可以取模后加密？？
	// ciphertext range's length in bits (ciphertexts are in [0, 2**C-1]
	unsigned int C = 64;
	

	OPESM4 o("S0M3 $TR@NG Key", P, C);

	//it works with ZZ instead of usual integers
	NTL::ZZ m1 = NTL::to_ZZ(2000);
    NTL::ZZ c1,c2;

    int i;
    clock_t program_start, program_end;
    double ts;

    program_start = clock();
    for (i = 0; i < TESTTIME; i++) {
        c1 = o.encrypt_sm4(m1);
    }
    program_end = clock();
    ts = program_end - program_start;
    ts = ts / CLOCKS_PER_SEC;
    printf("[OPE SEWBSM4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
           1 / (ts / TESTTIME));
    printf("times/s:%f",TESTTIME/(ts+0.06));
    // program_start = clock();
    // for (i = 0; i < TESTTIME; i++) {
    //     c2 = o.encrypt_wbsm4(m1);
    // }
    // program_end = clock();
    // ts = program_end - program_start;
    // ts = ts / CLOCKS_PER_SEC;
    // printf("[OPE SE-WBSM4] Time cost: %lf s, it means that the encryption speed is: %f MByte/s\n", ts / TESTTIME,
    //        1 / (ts / TESTTIME));

	return 0;
}
