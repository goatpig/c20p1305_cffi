////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2024, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#undef NDEBUG
#include <assert.h>

#include <secp256k1.h>
#include <btc/ecc.h>
#include <btc/random.h>
#include <btc/ecc_key.h>
#include <btc/hash.h>
#include <btc/sha2.h>
#include <hkdf.h>
#include <poly1305.h>

#include "bip15x.h"

#define DERSIG_SIZE 72

secp256k1_context* lib_ctx = NULL;

//// context setup ////
int lib_init()
{
   //call this once before using any other calls
   uint8_t seed[32];
   if (lib_ctx != NULL) {
      return 0;
   }

   btc_ecc_start();
   lib_ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

   assert(btc_random_bytes(seed, 32, 0));
   assert(secp256k1_context_randomize(lib_ctx, seed));
   return POLY1305_TAGLEN;
}

void lib_free(void* buffer)
{
   if (buffer == NULL) {
      return;
   }
   free(buffer);
}

struct chachapolyaead_ctx* new_chacha_ctx()
{
   struct chachapolyaead_ctx* ctx = (struct chachapolyaead_ctx*)malloc(
      sizeof(struct chachapolyaead_ctx));
   memset(ctx, 0, sizeof(struct chachapolyaead_ctx));
   return ctx;
}

bool chacha_ctx_init(struct chachapolyaead_ctx* ctx, const uint8_t *key, int len)
{
   if (chacha20poly1305_init(ctx, key, len) != 0) {
      return false;
   }
   return true;
}

uint8_t* random_bytes(size_t len)
{
   uint8_t* randomBytes = (uint8_t*)malloc(len);
   if (!btc_random_bytes(randomBytes, len, 0))
   {
      free(randomBytes);
      return 0;
   }

   return randomBytes;
}

//// pubkey functions ////
uint8_t* pubkey_from_privkey(const btc_key* privkey)
{
   uint8_t* pubkey = (uint8_t*)malloc(BIP151PUBKEYSIZE);
   if (_pubkey_from_privkey(privkey, pubkey) == 0) {
      free(pubkey);
      return NULL;
   }
   return pubkey;
}

int _pubkey_from_privkey(const btc_key* privkey, uint8_t* dest)
{
   secp256k1_pubkey btcPubKey;
   size_t pubKeySize = BIP151PUBKEYSIZE;

   if (secp256k1_ec_pubkey_create(
      lib_ctx,
      &btcPubKey, privkey->privkey) == 0) {
      return 0;
   }

   secp256k1_ec_pubkey_serialize(
      lib_ctx,
      dest, &pubKeySize,
      &btcPubKey, SECP256K1_EC_COMPRESSED);

   if (pubKeySize != BIP151PUBKEYSIZE) {
      return 0;
   }

   return 1;
}

int ecdh_multiply(const btc_key* privkey, const uint8_t* pubkey, uint8_t* dest)
{
   //check provided pubkey
   secp256k1_pubkey peerECDHPK;
   if (secp256k1_ec_pubkey_parse(
      lib_ctx, &peerECDHPK, pubkey, BIP151PUBKEYSIZE) == 0) {
      return 0;
   }

   //ecdh with channel priv key
   if (secp256k1_ec_pubkey_tweak_mul(
      lib_ctx, &peerECDHPK, privkey->privkey) == 0) {
      return 0;
   }

   size_t destSize = BIP151PUBKEYSIZE;
   return secp256k1_ec_pubkey_serialize(
      lib_ctx, dest, &destSize,
      &peerECDHPK, SECP256K1_EC_COMPRESSED);
}

//// privkey functions ////
btc_key* new_privkey()
{
   btc_key* key = malloc(sizeof(btc_key));
   btc_privkey_init(key);
   if (!btc_privkey_gen(key)) {
      free(key);
      return NULL;
   }
   return key;
}

bool verify_sig(uint8_t* payload, size_t len, const uint8_t* hash, const uint8_t* pubkey)
{
   uint8_t derSig[DERSIG_SIZE];
   size_t derSigSize = DERSIG_SIZE;

   if (len != 64) {
      return false;
   }

   if (btc_ecc_compact_to_der_normalized(payload, derSig, &derSigSize) == false) {
      return false;
   }
   return btc_ecc_verify_sig(pubkey, true, hash, derSig, derSigSize);
}

uint8_t* sign(const btc_key* privkey, const uint8_t* hash)
{
   uint8_t* sig = (uint8_t*)malloc(BIP151PRVKEYSIZE*2);
   size_t sigSize = 0;

   if (btc_ecc_sign_compact(
      privkey->privkey, hash, sig, &sigSize) == false) {
      return NULL;
   }
   return sig;
}

void privkey_cleanse(btc_key* key)
{
   btc_privkey_cleanse(key);
}

//// hashes ////
void hkdf(uint8_t *result, size_t resultSize,
   const uint8_t *salt, size_t ssize,
   const uint8_t *key, size_t ksize,
   const uint8_t *info, size_t isize)
{
   hkdf_sha256(result, resultSize, salt, ssize, key, ksize, info, isize);
}

void hash256(const uint8_t* in, size_t len, uint8_t* out)
{
   btc_hash(in, len, out);
}

//// aead ////
bool chacha_getlen(struct chachapolyaead_ctx* ctx,
   const uint8_t* payload, uint32_t seqNum, uint32_t* outLen)
{
   if (chacha20poly1305_get_length(ctx, outLen, seqNum, payload, AAD_LEN) != 0) {
      return false;
   }
   return true;
}

bool chacha_crypt(struct chachapolyaead_ctx* ctx,
   uint32_t seqNum, uint8_t *dest, const uint8_t *src, uint32_t len, int is_encrypt)
{
   if (chacha20poly1305_crypt(ctx, seqNum, dest, src, len, AAD_LEN, is_encrypt) != 0) {
      return false;
   }
   return true;
}
