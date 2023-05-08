/**
 * \file sm4.h
 *
 * \brief This file contains the SM4 algorithm definitions and functions.
 *
 */
#ifndef WBCRYPTO_SM4_H
#define WBCRYPTO_SM4_H



#include <stdint.h>
#include <stdlib.h>


# define WBCRYPTO_SM4_ENCRYPT     1
# define WBCRYPTO_SM4_DECRYPT     0

#define WBCRYPTO_SM4_KEY_LENGTH		16
#define WBCRYPTO_SM4_BLOCK_SIZE		16
#define WBCRYPTO_SM4_IV_LENGTH		(WBCRYPTO_SM4_BLOCK_SIZE)
#define WBCRYPTO_SM4_NUM_ROUNDS		32

#define WBCRYPTO_ERR_SM4_INVALID_INPUT_LENGTH                  -0x0200

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           The SM4 key context structure
 */
typedef struct wbcrypto_sm4_context
{
    int mode;                   /*!<  encrypt/decrypt   */
    uint32_t sk[32];           /*!<  SM4 subkeys       */
}
wbcrypto_sm4_context;

typedef struct wbcrypto_sm4_context WBCRYPTO_SM4_KEY;


/**
 * \brief           This function will load the user_key to sm4 encrypt key context
 *
 * \param user_key  length 16 bytes
 *
 */
void wbcrypto_sm4_setkey_enc(wbcrypto_sm4_context *ctx, const unsigned char *user_key);

/**
* \brief           This function will load the user_key to sm4 decrypt key context
*
* \param user_key  length 16 bytes
*
*/
void wbcrypto_sm4_setkey_dec(wbcrypto_sm4_context *ctx, const unsigned char *user_key);

/**
* \brief           Run SM4 encryption and decryption algorithm
*
* \param in        plaintext
* \param out       cipher
* \param ctx       for encrypt , the key is sm4 encryption key context, otherwise decryption key context
*
*/
void wbcrypto_sm4_encrypt(const unsigned char *in, unsigned char *out, const wbcrypto_sm4_context *ctx);
#define wbcrypto_sm4_decrypt(in,out,ctx)  wbcrypto_sm4_encrypt(in,out,ctx)



/**
* \brief          This function performs an SM4 single-block encryption or decryption operation
*
* \param ctx      The SM4 context to use for encryption or decryption.
*                 It must be initialized and bound to a key.
* \param mode     The SM4 operation: #WBCRYPTO_SM4_ENCRYPT or #WBCRYPTO_SM4_DECRYPT
* \param input    The buffer holding the input data.
*                 It must be readable and at least \c 16 Bytes long
* \apram output   The buffer where the output data will be written.
                  It must be writeable and at least \c 16 Bytes long.

* \return         \c 0 on success.

* \return         #WBCRYPTO_ERR_SM4_INVALID_INPUT_LENGTH
*/
int wbcrypto_sm4_crypt_ecb(const wbcrypto_sm4_context *ctx,
                           int mode,
                           const unsigned char *input,
                           unsigned char *output);

#if defined(WBCRYPTO_SELF_TEST)
/**
	 * \brief           sm4 test
	 *
	 * \param verbose   0 is nothing ;
	 *                  1 is test encrypt and decrypt;
	 *
	 * @return          0 if successful
	 */
	int wbcrypto_sm4_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif /* sm4.h */