////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2021, goatpig.                                              //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <string.h>
#include "cffi_cdecl.h"

//so that assert isn't a no-op in release builds
#undef NDEBUG
#include <assert.h>

#define CIPHERSUITE_CHACHA20POLY1305_OPENSSH 0

typedef struct chachapolyaead_ctx chachapolyaead_ctx;

bool bip151_channel_generate_secret_chacha20poly1305_openssh(
   bip151_channel*, const uint8_t*, size_t);
void calc_chacha20poly1305_keys(bip151_channel*);
void calc_sessionid(bip151_channel*);

////////////////////////////////////////////////////////////////////////////////
//
// Utils
//
////////////////////////////////////////////////////////////////////////////////
btc_key* get_new_privkey()
{
   return new_privkey();
}

////
uint8_t* compute_pubkey(const btc_key* privkey)
{
   return pubkey_from_privkey(privkey);
}

////////////////////////////////////////////////////////////////////////////////
bool isNull(const void* ptr)
{
   return ptr == NULL;
}

////////////////////////////////////////////////////////////////////////////////
void freeCffiBuffer(void* buffer)
{
   if (buffer == NULL) {
      return;
   }
   free(buffer);
}

void freeLibBuffer(void* buffer)
{
   lib_free(buffer);
}

////////////////////////////////////////////////////////////////////////////////
//
// bip151 channel setup
//
////////////////////////////////////////////////////////////////////////////////
size_t bip15x_init_lib()
{
   return lib_init();
}

////////////////////////////////////////////////////////////////////////////////
bip151_channel* bip151_channel_makenew()
{
   bip151_channel* channel = (bip151_channel*)malloc(sizeof(bip151_channel));
   channel->ctx_ = new_chacha_ctx();
   channel->privkey_ = new_privkey();
   channel->seqNum_ = 0;
   return channel;
}

void bip151_cleanup_channel(bip151_channel* channel)
{
   if (channel == NULL) {
      return;
   }

   if (channel->privkey_ != NULL) {
      lib_free(channel->privkey_);
      channel->privkey_ = NULL;
   }

   if (channel->ctx_ != NULL) {
      lib_free(channel->ctx_);
      channel->ctx_ = NULL;
   }

   free (channel);
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip151_channel_getencinit(bip151_channel* channel)
{
   uint8_t* encinit = (uint8_t*)malloc(BIP151PUBKEYSIZE + 1);
   if (_pubkey_from_privkey(channel->privkey_, encinit) == 0) {
      free(encinit);
      return NULL;
   }

   //append cipher suite flag to the pubkey
   channel->cipherSuite_ = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;
   encinit[33] = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;
   return encinit;
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_channel_processencinit(
   bip151_channel* channel, const uint8_t* payload, size_t len)
{
   uint8_t cipherSuite;
   if (payload == NULL || len < 1) {
      return false;
   }

   //check cipher suite flag
   cipherSuite = payload[len - 1];
   switch (cipherSuite)
   {
      case CIPHERSUITE_CHACHA20POLY1305_OPENSSH:
      {
         channel->cipherSuite_ = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;
         if (!bip151_channel_generate_secret_chacha20poly1305_openssh(
            channel, payload, len - 1)) {
            return false;
         }

         calc_chacha20poly1305_keys(channel);
         calc_sessionid(channel);
         return true;
      }

      default:
         break;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip151_channel_getencack(bip151_channel* channel)
{
   uint8_t* encinit = (uint8_t*)malloc(BIP151PUBKEYSIZE);
   switch (channel->cipherSuite_)
   {
      case CIPHERSUITE_CHACHA20POLY1305_OPENSSH:
      {
         if (_pubkey_from_privkey(channel->privkey_, encinit) == 0) {
            break;
         }

         //grabbing encack wipes the private key
         privkey_cleanse(channel->privkey_);
         return encinit;
      }

      default:
         break;
   }

   free(encinit);
   return NULL;
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_channel_processencack(
   bip151_channel* channel, const uint8_t* payload, size_t len)
{
   switch (channel->cipherSuite_)
   {
   case CIPHERSUITE_CHACHA20POLY1305_OPENSSH:
   {
      if (!bip151_channel_generate_secret_chacha20poly1305_openssh(
         channel, payload, len)) {
         return false;
      }

      calc_chacha20poly1305_keys(channel);
      calc_sessionid(channel);
      return true;
   }

   default:
      break;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_channel_generate_secret_chacha20poly1305_openssh(
   bip151_channel* channel, const uint8_t* pubkey, size_t len)
{
   uint8_t parseECDHMulRes[BIP151PUBKEYSIZE];

   //sanity checks
   if (len != BIP151PUBKEYSIZE) {
      return false;
   }

   if (channel == 0 || pubkey == 0) {
      return false;
   }

   if (ecdh_multiply(channel->privkey_, pubkey, parseECDHMulRes) == 0) {
      return false;
   }
   memcpy(channel->sharedSecret_, parseECDHMulRes + 1, 32);
   return true;
}

////////////////////////////////////////////////////////////////////////////////
void calc_chacha20poly1305_keys(bip151_channel* channel)
{
   char salt[] = "bitcoinecdh";
   char info1[] = "BitcoinK1";
   char info2[] = "BitcoinK2";
   uint8_t ikm[33];

   memcpy(ikm, channel->sharedSecret_, 32);
   ikm[32] = CIPHERSUITE_CHACHA20POLY1305_OPENSSH;

   hkdf(
      channel->hkdfSet_, BIP151PRVKEYSIZE,
      (const uint8_t*)salt, strlen(salt),
      ikm, 33,
      (const uint8_t*)info2, strlen(info2));

   hkdf(
      channel->hkdfSet_ + BIP151PRVKEYSIZE, BIP151PRVKEYSIZE,
      (const uint8_t*)salt, strlen(salt),
      ikm, 33,
      (const uint8_t*)info1, strlen(info1));

   chacha_ctx_init(channel->ctx_, channel->hkdfSet_, 64);
}

////////////////////////////////////////////////////////////////////////////////
void calc_sessionid(bip151_channel* channel)
{
   char salt[] = "bitcoinecdh";
   char info[] = "BitcoinSessionID";
   uint8_t ikm[33];

   memcpy(ikm, channel->sharedSecret_, 32);
   ikm[32] = channel->cipherSuite_;

   hkdf(
      channel->sessionID_, BIP151PRVKEYSIZE,
      (const uint8_t*)salt, strlen(salt),
      ikm, 33,
      (const uint8_t*)info, strlen(info));
}

////////////////////////////////////////////////////////////////////////////////
void bip151_channel_rekey(bip151_channel* channel)
{
   uint8_t preimage[BIP151PRVKEYSIZE*2];
   memcpy(preimage, channel->sessionID_, BIP151PRVKEYSIZE);

   for (int i=0; i<2; i++) {
      uint8_t* ptr = channel->hkdfSet_ + (BIP151PRVKEYSIZE * i);
      memcpy(preimage + BIP151PRVKEYSIZE, ptr, BIP151PRVKEYSIZE);
      hash256(preimage, BIP151PRVKEYSIZE*2, ptr);
   }

   chacha_ctx_init(channel->ctx_, channel->hkdfSet_, 64);
}

////////////////////////////////////////////////////////////////////////////////
void bip151_channel_initial_keying(
   bip151_channel* origin, const uint8_t* oppositeKdfKeys,
   const uint8_t* ownPubkey, const uint8_t* counterpartyPubkey)
{
   uint8_t preimage[162];
   memcpy (preimage, origin->sessionID_, BIP151PRVKEYSIZE);

   for (int i=0; i<2; i++) {
      size_t offset = BIP151PRVKEYSIZE;
      uint8_t* originKey = origin->hkdfSet_ + (BIP151PRVKEYSIZE * i);
      const uint8_t* oppositeKey = oppositeKdfKeys + (BIP151PRVKEYSIZE * i);

      //current symkey
      memcpy(preimage + offset, originKey, BIP151PRVKEYSIZE);
      offset += BIP151PRVKEYSIZE;

      //opposite channel symkeys
      memcpy(preimage + offset, oppositeKey, BIP151PRVKEYSIZE);
      offset += BIP151PRVKEYSIZE;

      //own pubkey
      memcpy(preimage + offset, ownPubkey, BIP151PUBKEYSIZE);
      offset += BIP151PUBKEYSIZE;

      //client pubkey
      memcpy(preimage + offset, counterpartyPubkey, BIP151PUBKEYSIZE);
      offset += BIP151PUBKEYSIZE;

      hash256(preimage, offset, originKey);
   }

   chacha_ctx_init(origin->ctx_, origin->hkdfSet_, 64);
}

////////////////////////////////////////////////////////////////////////////////
void bip151_channel_initial_rekey(
   bip151_channel* inSession, bip151_channel* outSession,
   const uint8_t* ownPubkey, const uint8_t* counterpartyPubkey)
{
   uint8_t outSessionKeysCopy[64];
   memcpy(outSessionKeysCopy, outSession->hkdfSet_, 64);

   bip151_channel_initial_keying(outSession, inSession->hkdfSet_,
      ownPubkey, counterpartyPubkey);

   bip151_channel_initial_keying(inSession, outSessionKeysCopy,
      counterpartyPubkey, ownPubkey);
}

////////////////////////////////////////////////////////////////////////////////
bool bip151_isrekeymsg(const uint8_t* rekey_message, size_t len)
{
   if (len != 33) {
      return false;
   }

   for (unsigned i=0; i<len; i++) {
      if (rekey_message[i] != 0) {
         return false;
      }
   }

   return true;
}


////////////////////////////////////////////////////////////////////////////////
//
// bip150 auth
//
////////////////////////////////////////////////////////////////////////////////
uint8_t* hash_authstring(const uint8_t* sessionID, const uint8_t* pubkey,
   char step)
{
   uint8_t preimage[66];
   uint8_t* result = (uint8_t*)malloc(32);

   memcpy(preimage, sessionID, BIP151PRVKEYSIZE);
   memset(preimage + BIP151PRVKEYSIZE, step, 1);
   memcpy(preimage + BIP151PRVKEYSIZE + 1, pubkey, BIP151PUBKEYSIZE);

   hash256(preimage, 66, result);
   return result;
}

////////////////////////////////////////////////////////////////////////////////
bool check_authstring(const uint8_t* payload, const uint8_t* sessionID,
   const uint8_t* pubkey, char step)
{
   uint8_t* myHash = hash_authstring(sessionID, pubkey, step);
   int result = memcmp(payload, myHash, 32);
   free(myHash);

   return (result == 0);
}

////////////////////////////////////////////////////////////////////////////////
bool bip150_check_authchallenge(const uint8_t* payload, size_t len,
   const bip151_channel* channel, const uint8_t* pubkey)
{
   if (len != 32) {
      return false;
   }
   return check_authstring(payload, channel->sessionID_, pubkey, 'i');
}

////////////////////////////////////////////////////////////////////////////////
bool bip150_check_authpropose(const uint8_t* payload, size_t len,
   const bip151_channel* channel, const uint8_t* pubkey)
{
   if (len != 32) {
      return false;
   }
   return check_authstring(payload, channel->sessionID_, pubkey, 'p');
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip150_get_authreply(
   const bip151_channel* channel, const btc_key* privkey)
{
   return sign(privkey, channel->sessionID_);
}

////////////////////////////////////////////////////////////////////////////////
uint8_t* bip150_get_authchallenge(
   const bip151_channel* channel, const uint8_t* pubkey)
{
   return hash_authstring(channel->sessionID_, pubkey, 'r');
}

////////////////////////////////////////////////////////////////////////////////
bool bip150_check_authreply(uint8_t* payload, size_t len,
   const bip151_channel* channel, const uint8_t* pubkey)
{
   return verify_sig(payload, len, channel->sessionID_, pubkey);
}

////////////////////////////////////////////////////////////////////////////////
//
// encryption routines
//
////////////////////////////////////////////////////////////////////////////////
uint32_t bip15x_get_length(bip151_channel* channel, const uint8_t* payload)
{
   //payload has to be AAD_LEN long

   unsigned decryptedLen;
   if (!chacha_getlen(channel->ctx_, payload, channel->seqNum_, &decryptedLen)) {
      return 0;
   }
   return decryptedLen;
}

////////////////////////////////////////////////////////////////////////////////
bool bip15x_decrypt(bip151_channel* channel,
   const uint8_t* cipherText, uint32_t len, uint8_t* clearText)
{
   uint32_t decryptedLen = bip15x_get_length(channel, cipherText);
   if (decryptedLen != len) {
      return false;
   }
   return chacha_crypt(channel->ctx_, channel->seqNum_++,
      clearText, cipherText, len, 0);
}

////////////////////////////////////////////////////////////////////////////////
bool bip15x_encrypt(bip151_channel* channel,
   const uint8_t* clearText, uint32_t len, uint8_t* cipherText)
{
   //prepend payload size
   memcpy(cipherText, &len, AAD_LEN);

   //copy clear text in
   memcpy(cipherText + AAD_LEN, clearText, len);

   //encrypt, increment sequence number
   return chacha_crypt(channel->ctx_, channel->seqNum_++,
      cipherText, cipherText, len, 1);
}
