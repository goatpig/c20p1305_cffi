////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2024, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#ifndef _H_BIP15X
#define _H_BIP15X

#include <stdbool.h>
#include <chachapoly_aead.h>
#include <btc/ecc_key.h>
#include <btc/hmac.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BIP15X_API
# if defined(_WIN32)
#  define BIP15X_API __declspec(dllexport)
# else
#  define BIP15X_API __attribute__ ((visibility ("default")))
# endif
#endif

#define BIP151PUBKEYSIZE 33
#define BIP151PRVKEYSIZE 32
#define AAD_LEN 4

BIP15X_API int lib_init(void);
BIP15X_API struct chachapolyaead_ctx* new_chacha_ctx(void);
BIP15X_API bool chacha_ctx_init(struct chachapolyaead_ctx*, const uint8_t *key, int keylen);

BIP15X_API btc_key* new_privkey(void);
BIP15X_API void privkey_cleanse(btc_key*);
BIP15X_API uint8_t* random_bytes(size_t);
BIP15X_API uint8_t* pubkey_from_privkey(const btc_key*);
BIP15X_API int _pubkey_from_privkey(const btc_key*, uint8_t* dest);
BIP15X_API int ecdh_multiply(const btc_key*, const uint8_t* pubkey, uint8_t* dest);

BIP15X_API bool verify_sig(uint8_t* payload, size_t len, const uint8_t* hash, const uint8_t* pubkey);
BIP15X_API uint8_t* sign(const btc_key*, const uint8_t* hash);

BIP15X_API void hkdf(uint8_t *result, size_t resultSize,
   const uint8_t *salt, size_t ssize,
   const uint8_t *key, size_t ksize,
   const uint8_t *info, size_t isize);
BIP15X_API void hash256(const uint8_t* in, size_t len, uint8_t* out);

BIP15X_API bool chacha_getlen(struct chachapolyaead_ctx*,
   const uint8_t* payload, uint32_t seqNum, uint32_t* outLen);
BIP15X_API bool chacha_crypt(struct chachapolyaead_ctx*,
   uint32_t seqNum, uint8_t *dest, const uint8_t *src, uint32_t len, int is_encrypt);

#ifdef __cplusplus
}
#endif //__cplusplus
#endif //_H_BIP15X