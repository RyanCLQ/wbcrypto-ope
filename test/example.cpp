/*
 * @Author: RyanCLQ
 * @Date: 2023-05-05 15:34:15
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-05-16 20:16:22
 * @Description: 请填写简介
 */
#include<iostream>

#include "ope.hh"
using namespace std;

int main(){

	// plaintext range's length in bits (plaintexts are in [0, 2**P-1]
	unsigned int P = 16;//基于超几何分布，不能有负数，可以取模后加密？？
	// ciphertext range's length in bits (ciphertexts are in [0, 2**C-1]
	unsigned int C = 64;
	

	OPE o("S0M3 $TR@NG Key", P, C);

	// it works with ZZ instead of usual integers
	NTL::ZZ m1 = NTL::to_ZZ(13);
	NTL::ZZ m2 = NTL::to_ZZ(50);

	NTL::ZZ c1 = o.encrypt_sm4(m1);
	NTL::ZZ c2 = o.encrypt_sm4(m2);
	NTL::ZZ c3 = o.encrypt_wbsm4(m1);
	NTL::ZZ c4 = o.encrypt_wbsm4(m2);
	
	// NTL::RR m1 = NTL::to_RR(13);
	// NTL::RR m2 = NTL::to_RR(26);
	// NTL::RR m3 = NTL::to_RR(50.6);
	// NTL::RR c1 = o.encrypt_sm4(m1);
	// NTL::RR c2 = o.encrypt_sm4(m2);
	// NTL::RR c3 = o.encrypt_sm4(m3);
	// NTL::RR c4 = o.encrypt_wbsm4(m1);
	// NTL::RR c5 = o.encrypt_wbsm4(m2);
	// NTL::RR c6 = o.encrypt_wbsm4(m3);
	

	cout << "m1 = " << m1 << endl;
	cout << "m2 = " << m2 << endl;
	// cout << "m3 = " << m3 << endl;
	cout << "sm4-enc(m1) = " << c1 << endl;
	cout << "sm4-enc(m2) = " << c2 << endl;
	// cout << "sm4-enc(m3) = " << c3 << endl;
	// cout << "wbsm4-enc(m1) = " << c4 << endl;
	// cout << "wbsm4-enc(m2) = " << c5 << endl;
	// cout << "wbsm4-enc(m3) = " << c6 << endl;
	cout << "wbsm4-enc(m1) = " << c3 << endl;
	cout << "wbsm4-enc(m2) = " << c4 << endl;

	// if (c1 < c2 && c2 < c3){
	// 	cout << "Preserving the order!" << endl;
	// }else{
	// 	cout << "o.O ????? OPE not working!" << endl;
	// }
	// if (c4 < c5 && c5 < c6){
	// 	cout << "Preserving the order!" << endl;
	// }else{
	// 	cout << "o.O ????? OPE not working!" << endl;
	// }

	if (c1 < c2){
		cout << "Preserving the order!" << endl;
	}else{
		cout << "o.O ????? OPE not working!" << endl;
	}
	if (c3 < c4){
		cout << "Preserving the order!" << endl;
	}else{
		cout << "o.O ????? OPE not working!" << endl;
	}


	// NTL::RR dec_1 = o.decrypt_sm4(c1);
	// NTL::RR dec_2 = o.decrypt_sm4(c2);
	// NTL::RR dec_3 = o.decrypt_sm4(c3);
	// NTL::RR dec_4 = o.decrypt_wbsm4(c4);
	// NTL::RR dec_5 = o.decrypt_wbsm4(c5);
	// NTL::RR dec_6 = o.decrypt_wbsm4(c6);

	NTL::ZZ dec_1 = o.decrypt_sm4(c1);
	NTL::ZZ dec_2 = o.decrypt_sm4(c2);
	NTL::ZZ dec_3 = o.decrypt_wbsm4(c3);
	NTL::ZZ dec_4 = o.decrypt_wbsm4(c4);
	
	// if (m1 == dec_1 && m2 == dec_2 && m3 == dec_3){
	// 	cout << "Decryption working fine." << endl;
	// }else{
	// 	cout << "Decryption NOT working." << endl;
	// }
	// if (m1 == dec_4 && m2 == dec_5 && m3 == dec_6){
	// 	cout << "Decryption working fine." << endl;
	// }else{
	// 	cout << "Decryption NOT working." << endl;
	// }

	if (m1 == dec_1 && m2 == dec_2){
		cout << "Decryption working fine." << endl;
	}else{
		cout << "Decryption NOT working." << endl;
	}
	if (m1 == dec_3 && m2 == dec_4){
		cout << "Decryption working fine." << endl;
	}else{
		cout << "Decryption NOT working." << endl;
	}

	return 0;
}
