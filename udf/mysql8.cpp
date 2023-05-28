#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mysql/mysql.h>
#include "ope.hh"

const std::string key= "S0M3 $TR@NG Key";
const uint8_t d_size = 16;
const uint8_t r_size = 32;

extern "C" {
    bool ope_sm4_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void ope_sm4_deinit(UDF_INIT *initid);
    long long ope_sm4(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);
    bool ope_sewbsm4_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    void ope_sewbsm4_deinit(UDF_INIT *initid);
    long long ope_sewbsm4(UDF_INIT *initid, UDF_ARGS *args,  char *is_null, char *error);
    // bool ope_xlwbsm4_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
    // void ope_xlwbsm4_deinit(UDF_INIT *initid);
    // char *ope_xlwbsm4(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);
}

/*
 * fpe(plain, mode, sample)
 * fpe(plain, phone/idcard/address)
 * fpe(plain, phone/idcard/address, "*********")
 */
bool ope_sm4_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1) {
        strcpy(message, "requires one argument");
        return 1;
    }

    if (args->arg_type[0] != INT_RESULT) {
        strcpy(message, "requires int as argument");
        return 1;
    }

    initid->const_item = 0;
    initid->maybe_null = args->maybe_null;
    initid->ptr = nullptr;

    return 0;
}

void ope_sm4_deinit(UDF_INIT *initid) {
    free(initid->ptr);
}

long long ope_sm4(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    
    long long plain = *(long long*)args->args[0];

    OPESM4 sm4(key,d_size,r_size);
    NTL::ZZ m = NTL::to_ZZ((long)plain);
    long  c = NTL::to_ulong(sm4.encrypt_sm4(m));

    return (long long)c;
}
bool ope_sewbsm4_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1) {
        strcpy(message, "requires one argument");
        return 1;
    }

    if (args->arg_type[0] != INT_RESULT) {
        strcpy(message, "requires int as argument");
        return 1;
    }

    initid->const_item = 0;
    initid->maybe_null = args->maybe_null;
    initid->ptr = nullptr;

    return 0;
}

void ope_sewbsm4_deinit(UDF_INIT *initid) {
    free(initid->ptr);
}

long long ope_sewbsm4(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    long long plain = *(long long*)args->args[0];

    OPEWBSM4 wbsm4(key,d_size,r_size);
    NTL::ZZ m = NTL::to_ZZ((long)plain);
    long  c = NTL::to_ulong(wbsm4.encrypt_wbsm4(m));
    
    return (long long)c;
}
