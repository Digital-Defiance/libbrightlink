/*
 * brightlink_crypto.c — primitives shared by the BrightLink client
 * (brightlink.c) and the mock-brightnexus test bridge.
 *
 * See brightlink_crypto.h. All functions are pure over byte buffers.
 */

#include "brightlink/brightlink_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  secp256k1 context                                                   */
/* ------------------------------------------------------------------ */

static secp256k1_context *g_blc_secp = NULL;

secp256k1_context *blc_secp(void)
{
    if (g_blc_secp == NULL) {
        g_blc_secp = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (g_blc_secp != NULL) {
            unsigned char seed[32];
            if (RAND_bytes(seed, sizeof(seed)) == 1) {
                /* Best-effort blinding. Failure to randomize is non-
                 * fatal — the context still functions; we just don't
                 * benefit from the side-channel hardening. We capture
                 * the return value to suppress warn_unused_result on
                 * newer libsecp256k1 headers. */
                int rand_ok = secp256k1_context_randomize(g_blc_secp, seed);
                (void)rand_ok;
            }
            OPENSSL_cleanse(seed, sizeof(seed));
        }
    }
    return g_blc_secp;
}

int blc_ecdh_xonly_cb(unsigned char *output,
                      const unsigned char *x32,
                      const unsigned char *y32,
                      void *data)
{
    (void)y32; (void)data;
    memcpy(output, x32, 32);
    return 1;
}

int blc_secp_random_priv(unsigned char priv32[32])
{
    secp256k1_context *ctx = blc_secp();
    if (ctx == NULL) return 0;
    for (int attempts = 0; attempts < 16; attempts++) {
        if (RAND_bytes(priv32, 32) != 1) return 0;
        if (secp256k1_ec_seckey_verify(ctx, priv32) == 1) return 1;
    }
    return 0;
}

int blc_secp_pub_uncompressed(const unsigned char priv32[32],
                              unsigned char pub65_out[BLC_PUB_UNCOMPRESSED])
{
    secp256k1_context *ctx = blc_secp();
    if (ctx == NULL) return 0;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(ctx, &pk, priv32) != 1) return 0;
    size_t outlen = BLC_PUB_UNCOMPRESSED;
    if (secp256k1_ec_pubkey_serialize(ctx, pub65_out, &outlen, &pk,
                                      SECP256K1_EC_UNCOMPRESSED) != 1) return 0;
    return outlen == BLC_PUB_UNCOMPRESSED ? 1 : 0;
}

int blc_secp_pub_compressed(const unsigned char priv32[32],
                            unsigned char pub33_out[BLC_PUB_COMPRESSED])
{
    secp256k1_context *ctx = blc_secp();
    if (ctx == NULL) return 0;
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(ctx, &pk, priv32) != 1) return 0;
    size_t outlen = BLC_PUB_COMPRESSED;
    if (secp256k1_ec_pubkey_serialize(ctx, pub33_out, &outlen, &pk,
                                      SECP256K1_EC_COMPRESSED) != 1) return 0;
    return outlen == BLC_PUB_COMPRESSED ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/*  HKDF-SHA256 / AES-256-GCM                                            */
/* ------------------------------------------------------------------ */

int blc_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                    const unsigned char *salt, size_t salt_len,
                    const unsigned char *info, size_t info_len,
                    unsigned char *out, size_t out_len)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) return 0;
    int ok = 0;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto end;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto end;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto end;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto end;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto end;
    size_t outlen = out_len;
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) goto end;
    if (outlen != out_len) goto end;
    ok = 1;
end:
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

int blc_aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                        const unsigned char *iv, size_t iv_len,
                        const unsigned char *aad, size_t aad_len,
                        const unsigned char *pt, size_t pt_len,
                        unsigned char *ct,
                        unsigned char *tag)
{
    if (key_len != 32 || iv_len != BLC_GCM_IV_LEN) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int ok = 0;
    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto end;
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto end;
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto end;
    int totallen = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) goto end;
    totallen += len;
    if ((size_t)totallen != pt_len) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, BLC_GCM_TAG_LEN, tag) != 1) goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int blc_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                        const unsigned char *iv, size_t iv_len,
                        const unsigned char *aad, size_t aad_len,
                        const unsigned char *ct, size_t ct_len,
                        const unsigned char *tag,
                        unsigned char *pt)
{
    if (key_len != 32 || iv_len != BLC_GCM_IV_LEN) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return 0;
    int ok = 0;
    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto end;
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto end;
    }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, BLC_GCM_TAG_LEN, (void *)tag) != 1) goto end;
    int finallen = 0;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &finallen) != 1) goto end;
    if ((size_t)(len + finallen) != ct_len) goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  DD-ECIES Basic envelope                                              */
/* ------------------------------------------------------------------ */

int blc_ecies_encrypt(const unsigned char *recipient_pub65,
                      const unsigned char *plaintext, size_t pt_len,
                      unsigned char **envelope_out, size_t *envelope_len)
{
    if (envelope_out) *envelope_out = NULL;

    unsigned char eph_priv[32];
    if (!blc_secp_random_priv(eph_priv)) return 0;
    unsigned char eph_pub_compressed[BLC_PUB_COMPRESSED];
    if (!blc_secp_pub_compressed(eph_priv, eph_pub_compressed)) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    secp256k1_context *ctx = blc_secp();
    secp256k1_pubkey peer_pk;
    if (secp256k1_ec_pubkey_parse(ctx, &peer_pk, recipient_pub65, BLC_PUB_UNCOMPRESSED) != 1) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }
    unsigned char shared_x[32];
    if (secp256k1_ecdh(ctx, shared_x, &peer_pk, eph_priv,
                       blc_ecdh_xonly_cb, NULL) != 1) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        return 0;
    }

    unsigned char aes_key[32];
    if (!blc_hkdf_sha256(shared_x, sizeof(shared_x),
                         (const unsigned char *)"", 0,
                         (const unsigned char *)DD_ECIES_HKDF_INFO,
                         DD_ECIES_HKDF_INFO_LEN,
                         aes_key, sizeof(aes_key))) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        return 0;
    }

    unsigned char iv[BLC_GCM_IV_LEN];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }

    unsigned char aad[3 + BLC_PUB_COMPRESSED];
    aad[0] = DD_ECIES_VERSION_BYTE;
    aad[1] = DD_ECIES_CIPHER_SUITE;
    aad[2] = DD_ECIES_TYPE_BASIC;
    memcpy(aad + 3, eph_pub_compressed, BLC_PUB_COMPRESSED);

    unsigned char *ct = malloc(pt_len);
    unsigned char tag[BLC_GCM_TAG_LEN];
    if (ct == NULL ||
        !blc_aes_gcm_encrypt(aes_key, sizeof(aes_key),
                             iv, sizeof(iv), aad, sizeof(aad),
                             plaintext, pt_len, ct, tag)) {
        free(ct);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }

    size_t env_len = 64 + pt_len;
    unsigned char *env = malloc(env_len);
    if (env == NULL) {
        free(ct);
        OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }
    size_t pos = 0;
    env[pos++] = DD_ECIES_VERSION_BYTE;
    env[pos++] = DD_ECIES_CIPHER_SUITE;
    env[pos++] = DD_ECIES_TYPE_BASIC;
    memcpy(env + pos, eph_pub_compressed, BLC_PUB_COMPRESSED); pos += BLC_PUB_COMPRESSED;
    memcpy(env + pos, iv, BLC_GCM_IV_LEN); pos += BLC_GCM_IV_LEN;
    memcpy(env + pos, tag, BLC_GCM_TAG_LEN); pos += BLC_GCM_TAG_LEN;
    memcpy(env + pos, ct, pt_len); pos += pt_len;

    free(ct);
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
    OPENSSL_cleanse(shared_x, sizeof(shared_x));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));

    *envelope_out = env;
    *envelope_len = env_len;
    return 1;
}

int blc_ecies_decrypt(const unsigned char *recipient_priv32,
                      const unsigned char *envelope, size_t envelope_len,
                      unsigned char **plaintext_out, size_t *pt_len)
{
    if (plaintext_out) *plaintext_out = NULL;
    if (envelope_len < 64) return 0;
    if (envelope[0] != DD_ECIES_VERSION_BYTE) return 0;
    if (envelope[1] != DD_ECIES_CIPHER_SUITE) return 0;
    if (envelope[2] != DD_ECIES_TYPE_BASIC) return 0;
    if (envelope[3] != 0x02 && envelope[3] != 0x03) return 0;

    const unsigned char *eph_pub = envelope + 3;
    const unsigned char *iv = envelope + 36;
    const unsigned char *tag = envelope + 48;
    const unsigned char *ct = envelope + 64;
    size_t ct_len = envelope_len - 64;

    secp256k1_context *ctx = blc_secp();
    secp256k1_pubkey peer_pk;
    if (secp256k1_ec_pubkey_parse(ctx, &peer_pk, eph_pub, BLC_PUB_COMPRESSED) != 1) return 0;

    unsigned char shared_x[32];
    if (secp256k1_ecdh(ctx, shared_x, &peer_pk, recipient_priv32,
                       blc_ecdh_xonly_cb, NULL) != 1) return 0;

    unsigned char aes_key[32];
    if (!blc_hkdf_sha256(shared_x, sizeof(shared_x),
                         (const unsigned char *)"", 0,
                         (const unsigned char *)DD_ECIES_HKDF_INFO,
                         DD_ECIES_HKDF_INFO_LEN,
                         aes_key, sizeof(aes_key))) {
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        return 0;
    }

    unsigned char aad[3 + BLC_PUB_COMPRESSED];
    aad[0] = DD_ECIES_VERSION_BYTE;
    aad[1] = DD_ECIES_CIPHER_SUITE;
    aad[2] = DD_ECIES_TYPE_BASIC;
    memcpy(aad + 3, eph_pub, BLC_PUB_COMPRESSED);

    unsigned char *pt = malloc(ct_len);
    if (pt == NULL) {
        OPENSSL_cleanse(shared_x, sizeof(shared_x));
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        return 0;
    }
    int ok = blc_aes_gcm_decrypt(aes_key, sizeof(aes_key),
                                 iv, BLC_GCM_IV_LEN, aad, sizeof(aad),
                                 ct, ct_len, tag, pt);
    OPENSSL_cleanse(shared_x, sizeof(shared_x));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    if (!ok) {
        free(pt);
        return 0;
    }
    *plaintext_out = pt;
    *pt_len = ct_len;
    return 1;
}

/* ------------------------------------------------------------------ */
/*  P-256 sign/verify and keygen                                         */
/* ------------------------------------------------------------------ */

#if defined(__GNUC__) || defined(__clang__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

int blc_verify_p256(const unsigned char pub65[BLC_PUB_UNCOMPRESSED],
                    const unsigned char *msg, size_t msg_len,
                    const unsigned char *sig_der, size_t sig_der_len)
{
    if (pub65 == NULL || pub65[0] != 0x04) return 0;
    int ok = 0;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    EC_KEY *eckey = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) goto end;
    point = EC_POINT_new(group);
    if (point == NULL) goto end;
    if (EC_POINT_oct2point(group, point, pub65, BLC_PUB_UNCOMPRESSED, NULL) != 1) goto end;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) goto end;
    if (EC_KEY_set_public_key(eckey, point) != 1) goto end;
    pkey = EVP_PKEY_new();
    if (pkey == NULL) goto end;
    if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) goto end;
    eckey = NULL;
    md = EVP_MD_CTX_new();
    if (md == NULL) goto end;
    if (EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pkey) != 1) goto end;
    if (EVP_DigestVerifyUpdate(md, msg, msg_len) != 1) goto end;
    if (EVP_DigestVerifyFinal(md, sig_der, sig_der_len) == 1) ok = 1;
end:
    if (md != NULL) EVP_MD_CTX_free(md);
    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (eckey != NULL) EC_KEY_free(eckey);
    if (point != NULL) EC_POINT_free(point);
    if (group != NULL) EC_GROUP_free(group);
    return ok;
}

int blc_sign_p256(const unsigned char priv32[32],
                  const unsigned char *msg, size_t msg_len,
                  unsigned char *sig_der_out, size_t sig_cap, size_t *sig_len)
{
    int ok = 0;
    EC_GROUP *group = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *priv_bn = NULL;
    EC_POINT *pub_point = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) goto end;
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) goto end;
    priv_bn = BN_bin2bn(priv32, 32, NULL);
    if (priv_bn == NULL) goto end;
    if (EC_KEY_set_private_key(eckey, priv_bn) != 1) goto end;
    pub_point = EC_POINT_new(group);
    if (pub_point == NULL) goto end;
    if (EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL) != 1) goto end;
    if (EC_KEY_set_public_key(eckey, pub_point) != 1) goto end;
    pkey = EVP_PKEY_new();
    if (pkey == NULL) goto end;
    if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) goto end;
    eckey = NULL;
    md = EVP_MD_CTX_new();
    if (md == NULL) goto end;
    if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, pkey) != 1) goto end;
    if (EVP_DigestSignUpdate(md, msg, msg_len) != 1) goto end;
    size_t actual = sig_cap;
    if (EVP_DigestSignFinal(md, sig_der_out, &actual) != 1) goto end;
    *sig_len = actual;
    ok = 1;
end:
    if (md != NULL) EVP_MD_CTX_free(md);
    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (eckey != NULL) EC_KEY_free(eckey);
    if (pub_point != NULL) EC_POINT_free(pub_point);
    if (priv_bn != NULL) BN_clear_free(priv_bn);
    if (group != NULL) EC_GROUP_free(group);
    return ok;
}

int blc_p256_keygen(unsigned char priv32_out[32],
                    unsigned char pub65_out[BLC_PUB_UNCOMPRESSED])
{
    int ok = 0;
    EC_KEY *eckey = NULL;
    const BIGNUM *priv_bn = NULL;
    const EC_POINT *pub_point = NULL;
    EC_GROUP *group = NULL;

    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (eckey == NULL) goto end;
    if (EC_KEY_generate_key(eckey) != 1) goto end;
    priv_bn = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);
    if (priv_bn == NULL || pub_point == NULL) goto end;

    /* Big-endian fixed-width private serialisation. */
    int bn_bytes = BN_num_bytes(priv_bn);
    if (bn_bytes > 32 || bn_bytes <= 0) goto end;
    memset(priv32_out, 0, 32);
    if (BN_bn2bin(priv_bn, priv32_out + (32 - bn_bytes)) != bn_bytes) goto end;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) goto end;
    size_t n = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                  pub65_out, BLC_PUB_UNCOMPRESSED, NULL);
    if (n != BLC_PUB_UNCOMPRESSED) goto end;
    ok = 1;
end:
    if (eckey != NULL) EC_KEY_free(eckey);
    if (group != NULL) EC_GROUP_free(group);
    return ok;
}

#if defined(__GNUC__) || defined(__clang__)
# pragma GCC diagnostic pop
#endif

/* ------------------------------------------------------------------ */
/*  Base64                                                              */
/* ------------------------------------------------------------------ */

int blc_b64encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_cap)
{
    int needed = 4 * ((int)((src_len + 2) / 3)) + 1;
    if ((size_t)needed > dst_cap) return -1;
    int n = EVP_EncodeBlock((unsigned char *)dst, src, (int)src_len);
    if (n < 0) return -1;
    dst[n] = '\0';
    return n;
}

int blc_b64decode(const char *src, size_t src_len, unsigned char *dst,
                  size_t dst_cap, size_t *dst_len)
{
    size_t pad = 0;
    if (src_len >= 1 && src[src_len - 1] == '=') pad++;
    if (src_len >= 2 && src[src_len - 2] == '=') pad++;
    size_t pre_trim = (src_len * 3) / 4;
    if (pre_trim < pad) return -1;
    size_t real = pre_trim - pad;
    if (real > dst_cap) return -1;

    unsigned char scratch[8192];
    if (pre_trim > sizeof(scratch)) {
        unsigned char *heap = malloc(pre_trim);
        if (heap == NULL) return -1;
        int n = EVP_DecodeBlock(heap, (const unsigned char *)src, (int)src_len);
        if (n < 0 || (size_t)n != pre_trim) { free(heap); return -1; }
        memcpy(dst, heap, real);
        free(heap);
    } else {
        int n = EVP_DecodeBlock(scratch, (const unsigned char *)src, (int)src_len);
        if (n < 0 || (size_t)n != pre_trim) return -1;
        memcpy(dst, scratch, real);
    }
    if (dst_len) *dst_len = real;
    return (int)real;
}

/* ------------------------------------------------------------------ */
/*  Endian helpers                                                       */
/* ------------------------------------------------------------------ */

void blc_le32(unsigned char *out, uint32_t v)
{
    out[0] = (unsigned char)(v & 0xff);
    out[1] = (unsigned char)((v >> 8) & 0xff);
    out[2] = (unsigned char)((v >> 16) & 0xff);
    out[3] = (unsigned char)((v >> 24) & 0xff);
}

void blc_be64(unsigned char *out, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        out[7 - i] = (unsigned char)((v >> (i * 8)) & 0xff);
    }
}
