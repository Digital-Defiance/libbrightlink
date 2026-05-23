/*
 * brightlink_crypto.h — primitives backing libBrightLink.
 *
 * Exposed as a public header because two consumer types want them:
 *
 *   1. Test harnesses and conformance mocks that need to speak the
 *      bridge half of BrightLink (encrypt where libBrightLink decrypts,
 *      sign transcripts where libBrightLink verifies). The mock-
 *      brightnexus binary in tests/ is one example.
 *
 *   2. Tools that need DD-ECIES envelopes outside of BrightLink — e.g.
 *      a credential-import flow that wants to wrap something for a
 *      published bridge identity without holding a registered session.
 *
 * Every function is a pure transformation over byte buffers. Higher-level
 * BrightLink layout (the §4.5.3 transcript, the §4.6.3 AAD, JSON wire
 * shapes) lives in brightlink.c, not here.
 *
 * Stability. These primitives stabilise faster than the high-level API
 * (they're standardised crypto, not protocol-shaped). v0.1.x preserves
 * source compatibility; v1.0.0 will preserve it permanently.
 */

#ifndef BRIGHTLINK_CRYPTO_H
#define BRIGHTLINK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#define BLC_PUB_UNCOMPRESSED 65
#define BLC_PUB_COMPRESSED   33
#define BLC_GCM_IV_LEN       12
#define BLC_GCM_TAG_LEN      16

/* DD-ECIES Basic mode (cipher suite 0x21). */
#define DD_ECIES_VERSION_BYTE 0x01
#define DD_ECIES_CIPHER_SUITE 0x01
#define DD_ECIES_TYPE_BASIC   0x21
#define DD_ECIES_HKDF_INFO    "ecies-v2-key-derivation"
#define DD_ECIES_HKDF_INFO_LEN (sizeof(DD_ECIES_HKDF_INFO) - 1)

#ifdef __cplusplus
extern "C" {
#endif

/* secp256k1 context, lazily initialised on first call and blinded with
 * 32 random bytes per RAND_bytes. The returned pointer is owned by the
 * library; callers MUST NOT call secp256k1_context_destroy on it. */
secp256k1_context *blc_secp(void);

/* ECDH callback that writes the raw 32-byte X coordinate verbatim. Pass
 * to secp256k1_ecdh as the `hashfp` argument when you need the unhashed
 * shared point (the DD-ECIES Basic profile requires this). */
int blc_ecdh_xonly_cb(unsigned char *output,
                      const unsigned char *x32,
                      const unsigned char *y32,
                      void *data);

/* Generate a uniformly-random valid secp256k1 private key. */
int blc_secp_random_priv(unsigned char priv32[32]);

/* Public-key serialisation. */
int blc_secp_pub_uncompressed(const unsigned char priv32[32],
                              unsigned char pub65_out[BLC_PUB_UNCOMPRESSED]);
int blc_secp_pub_compressed(const unsigned char priv32[32],
                            unsigned char pub33_out[BLC_PUB_COMPRESSED]);

/* HKDF-SHA256 with explicit salt and info (RFC 5869). */
int blc_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                    const unsigned char *salt, size_t salt_len,
                    const unsigned char *info, size_t info_len,
                    unsigned char *out, size_t out_len);

/* AES-256-GCM. iv_len MUST be 12, tag is 16 bytes. */
int blc_aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                        const unsigned char *iv, size_t iv_len,
                        const unsigned char *aad, size_t aad_len,
                        const unsigned char *pt, size_t pt_len,
                        unsigned char *ct,
                        unsigned char *tag);
int blc_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                        const unsigned char *iv, size_t iv_len,
                        const unsigned char *aad, size_t aad_len,
                        const unsigned char *ct, size_t ct_len,
                        const unsigned char *tag,
                        unsigned char *pt);

/* DD-ECIES Basic-mode envelope. Envelope is heap-allocated; caller frees. */
int blc_ecies_encrypt(const unsigned char *recipient_pub65,
                      const unsigned char *plaintext, size_t pt_len,
                      unsigned char **envelope_out, size_t *envelope_len);
int blc_ecies_decrypt(const unsigned char *recipient_priv32,
                      const unsigned char *envelope, size_t envelope_len,
                      unsigned char **plaintext_out, size_t *pt_len);

/* P-256 ECDSA-DER sign and verify, with internal SHA-256 prehash. */
int blc_sign_p256(const unsigned char priv32[32],
                  const unsigned char *msg, size_t msg_len,
                  unsigned char *sig_der_out, size_t sig_cap, size_t *sig_len);
int blc_verify_p256(const unsigned char pub65[BLC_PUB_UNCOMPRESSED],
                    const unsigned char *msg, size_t msg_len,
                    const unsigned char *sig_der, size_t sig_der_len);

/* P-256 keypair generation. */
int blc_p256_keygen(unsigned char priv32_out[32],
                    unsigned char pub65_out[BLC_PUB_UNCOMPRESSED]);

/* Base64 (RFC 4648 §4). blc_b64decode handles padded inputs without
 * overrunning dst when caller sized dst_cap to the post-padding-trim
 * length. */
int blc_b64encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_cap);
int blc_b64decode(const char *src, size_t src_len, unsigned char *dst,
                  size_t dst_cap, size_t *dst_len);

/* Endian helpers used by transcript and AAD construction. */
void blc_le32(unsigned char *out, uint32_t v);
void blc_be64(unsigned char *out, uint64_t v);

#ifdef __cplusplus
}
#endif

#endif /* BRIGHTLINK_CRYPTO_H */
