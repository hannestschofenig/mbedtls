/*
 *  Example EAT implementation for attested TLS
 *
 * Copyright 2022, Hannes Tschofenig
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include "ctoken/ctoken_encode.h"
#include "ctoken/ctoken_decode.h"

#include "mbedtls/eat.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/q_useful_buf.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"
#include "common.h"

#include "mbedtls/x509_crt.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */


/* Function signatures */

#if !defined(MBEDTLS_PARSEC_ATTESTATION)
int32_t create_eat( uint8_t *ptr, size_t *len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair );

int32_t
ctoken_encode_claim(struct ctoken_encode_ctx *me,
                    int label,
                    uint8_t type,
                    struct q_useful_buf_c    content); 

int32_t kat_encode(struct t_cose_key signing_key,
                   struct q_useful_buf_c nonce,
                   struct q_useful_buf_c ik_pub,
                   struct q_useful_buf_c kak_pub,
                   struct q_useful_buf output_buffer,
                   struct q_useful_buf_c *completed_token);
#endif

int32_t verify_eat( uint8_t *ptr, size_t len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair );

int32_t kat_verify(struct t_cose_key     kak,
                   struct q_useful_buf_c kat,
                   struct q_useful_buf_c *nonce,
                   struct q_useful_buf_c *ik_pub,
                   struct q_useful_buf_c *kak_pub);


enum t_cose_err_t fetch_key(uint8_t            key_type,
                            int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair);

int32_t
ctoken_decode_claim(struct ctoken_decode_ctx *me,
                    int label,
                    uint8_t type,
                    struct q_useful_buf_c    *content);

void free_psa_ecdsa_key_pair(struct t_cose_key key_pair);

#if !defined(MBEDTLS_PARSEC_ATTESTATION)
/**
 * \brief  Print a q_useful_buf_c on stdout in hex ASCII text.
 *
 * \param[in] string_label   A string label to output first
 * \param[in] buf            The q_useful_buf_c to output.
 *
 * This is just for pretty printing.
 */
static void print_useful_buf(const char *string_label, struct q_useful_buf_c buf)
{
    if(string_label) {
        mbedtls_printf("%s", string_label);
    }

    mbedtls_printf("    %ld bytes\n", buf.len);

    mbedtls_printf("    ");

    size_t i;
    for(i = 0; i < buf.len; i++) {
        uint8_t Z = ((uint8_t *)buf.ptr)[i];
        mbedtls_printf("%02x ", Z);
        if((i % 32) == 31) {
            mbedtls_printf("\n    ");
        }
    }
    mbedtls_printf("\n");

    fflush(stdout);
}

int32_t create_kat( const uint8_t *nonce,   // nonce
                    size_t nonce_len,       // nonce length
                    uint8_t *ik,            // identity key
                    size_t ik_len,          // identity key length
                    struct t_cose_key *kak, // key attestation key handle
                    uint8_t *kat,           // key attestation token
                    size_t kat_buf_len,     // kat buffer size (input)
                    size_t *kat_len )       // kat size (output)
{
    int return_value;
    uint8_t kak_pk[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t kak_pk_len;
    psa_status_t status;
    struct q_useful_buf_c completed_token;

    MakeUsefulBufOnStack( token_buffer, 1500);

    /* Fetch the public key of the KAK */
     status = psa_export_public_key( (mbedtls_svc_key_id_t) kak->k.key_handle,
                                     kak_pk,
                                     sizeof(kak_pk),
                                     &kak_pk_len
                                   );

    if( status != PSA_SUCCESS )
    {
        return( status );
    }

    /* Make KAT */
    return_value = kat_encode(*kak,
                              (struct q_useful_buf_c)
                              {
                                .len = nonce_len,
                                .ptr = nonce
                              },
                              (struct q_useful_buf_c)
                              {
                                .len = ik_len,
                                .ptr = ik
                              },
                              (struct q_useful_buf_c)
                              {
                                .len = kak_pk_len,
                                .ptr = kak_pk
                              },
                              token_buffer,
                             &completed_token);

    if(return_value) {
        return(return_value);
    }

    print_useful_buf("KAT:\n", completed_token);

    *kat_len = completed_token.len;

    memcpy(kat, (uint8_t *) completed_token.ptr, *kat_len);

    return(return_value);
}


psa_status_t parsec_attest_key( psa_key_id_t ik,                // public key of the identity key
                                parsec_attest_mechanism_t mech, // attestation mechanism
                                const uint8_t *nonce,           // nonce
                                size_t nonce_len,               // nonce length
                                uint8_t *kat_bundle,            // KAT Bundle buffer
                                size_t kat_bundle_size,         // KAT Bundle buffer length (input)
                                size_t *kat_bundle_len)         // KAT Bundle length (output)

{
    enum t_cose_err_t return_value;
    uint8_t *pat[1000]={0};
    size_t pat_len = sizeof(pat);
    uint8_t kat[1000]={0};
    size_t kat_len = sizeof(kat);
    struct t_cose_key pak;
    struct t_cose_key kak;
    psa_status_t status;
    uint8_t ik_pk[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t ik_pk_len;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    memset( hash,0,sizeof( hash ) );
    size_t hash_size = 0;

    switch( mech )
    {
    case 0: /* EAT-based approach */
        break;
    default: /* Nothing else is supported */
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Fetch the public key of the IK */
     status = psa_export_public_key( ik,
                                     ik_pk,
                                     sizeof(ik_pk),
                                     &ik_pk_len
                                   );

    if( status != PSA_SUCCESS )
    {
        return( status );
    }

    /* Hash the IK public key and use it as input to the PAT (via the nonce) */
    status = psa_hash_compute( PSA_ALG_SHA_256,
                               ik_pk, ik_pk_len,
                               hash, sizeof( hash ),
                               &hash_size );
    if( status != PSA_SUCCESS )
    {
        return( status );
    }

    /* Fetch PAK private key used to sign the Platform Attestation Token (PAT) */
    return_value = fetch_key(EAT_KEY_TYPE_PAK, T_COSE_ALGORITHM_ES256, &pak);

    if ( return_value != T_COSE_SUCCESS )
    {
        return( PSA_ERROR_GENERIC_ERROR );
    }

    /* Create PAT (in form of an EAT) */
    if ( create_eat( (uint8_t *) pat, &pat_len, hash, hash_size, &pak ) != 0 )
    {
        free_psa_ecdsa_key_pair(pak);
        return( PSA_ERROR_GENERIC_ERROR );
    }

    /* Fetch KAK private key used to sign the Key Attestation Token (KAK) */
    return_value = fetch_key(EAT_KEY_TYPE_KAK, T_COSE_ALGORITHM_ES256, &kak);

    if ( return_value != T_COSE_SUCCESS )
    {
        free_psa_ecdsa_key_pair(pak);
        return( PSA_ERROR_GENERIC_ERROR );
    }

    /* Create KAT
     *
     * kat = {
     *   &(eat_nonce: 10) => bstr .size (8..64)
     *   &(cnf: 8) => ik-pub
     *   &(kak-pub: 2500) => COSE_Key
     * }
     *
     * ak-pub = cnf-map
     *
     * cnf-map = {
     *    &(cose-key: 1) => COSE_Key
     * }
     *
     */

    if ( create_kat( nonce,               // nonce
                     nonce_len,           // nonce length
                     ik_pk,               // identity key (public key)
                     ik_pk_len,           // identity key length
                     &kak,                // key attestation key
                     kat,                 // key attestation token
                     sizeof( kat ),       // kat buffer size (input)
                     &kat_len             // kat output length
                   ) != 0 )
    {
        free_psa_ecdsa_key_pair(pak);
        free_psa_ecdsa_key_pair(kak);
        return( PSA_ERROR_GENERIC_ERROR );
    }

    /* Put the PAT and the KAT inside the CAB (KAT-PAT Bundle)
     *
     * kat-bundle = {
     *   &(eat_profile: 265) =>
     *     "https://datatracker.ietf.org/doc/draft-bft-rats-kat",
     *   "kat" => COSE-Sign1-kat
     *   "pat" => EAT-CBOR-Token
     * }
     *
     */
    if( kat_bundle_size < ( 1 + kat_len + pat_len ) )
    {
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    }

    // TBD: Create a KAT-Bundle in a simplistic format.
    *kat_bundle_len = 1 + kat_len + pat_len + 2 + 2;
    kat_bundle[0] = 1;

    MBEDTLS_PUT_UINT16_BE( kat_len, kat_bundle, 1 );
    memcpy( &kat_bundle[1+2], kat, kat_len );

    MBEDTLS_PUT_UINT16_BE( pat_len, kat_bundle, 1 + 2 + kat_len );
    memcpy( &kat_bundle[1+ 2 + kat_len + 2], pat, pat_len );

    free_psa_ecdsa_key_pair(pak);
    free_psa_ecdsa_key_pair(kak);
    return( PSA_SUCCESS );
}


/**
 \brief Example to encode an EAT token

 @param[in] signing_key    The private key to sign with. This must be in the
                           format of the crypto library that is integrated.
                           See definition in t_cose interface.
 @param[in] nonce          Pointer and length of nonce claim.
 @param[in] output_buffer  Pointer and length of the buffer to output to. Must
                           be big enough to hold the EAT, or an error occurs.
 @param[out] completed_token  Pointer and length of the completed token.
 @return                      0 on success.

 output_buffer is the pointer and length of a buffer to write
 into. The pointer is not const indicating it is for writing.

 completed_token is the const pointer and length of the completed
 token. The storage pointed to by completed_token is inside
 output_buffer, usually the first part, so the pointers point
 to the same place.

 No storage allocation is done and malloc is not used.
 */
int32_t eat_encode(struct t_cose_key signing_key,
                   struct q_useful_buf_c nonce,
                   struct q_useful_buf output_buffer,
                   struct q_useful_buf_c *completed_token)
{
    struct ctoken_encode_ctx encode_ctx;
    int                      return_value;

    /* UEID is hard-coded. A real implementation would fetch it from
     * storage or read it from a register or compute it or such.
     */
    const struct q_useful_buf_c ueid = Q_USEFUL_BUF_FROM_SZ_LITERAL("ueid_ueid");

    /* Initialize, telling is the option (there are none) and
     * the signing algorithm to use.
     */
    ctoken_encode_init(&encode_ctx,
                       0, /* No t_cose options */
                       0, /* No ctoken options */
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    /* Next give it the signing key. No kid (key id) is given so
     * NULL_Q_USEFUL_BUF_C is passed.
     */
    ctoken_encode_set_key(&encode_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    /* Pass in the output buffer and get the encoding started.
     * The output buffer must be big enough for EAT payload, COSE
     * formatting and signature. (There is a way to call
     * ctoken_encode_start() to have this computed which is th
     * same as that used by t_cose and QCBOR, but that is not
     * done in this simple example. */
    ctoken_encode_start(&encode_ctx, output_buffer);

    /* Now start adding the claims into the token. Eat claims
     * can be mixed with PSA IA claims and with CWT claims.
     * You can even make up your own claims.
     */

    return_value = ctoken_encode_claim(&encode_ctx,CTOKEN_EAT_LABEL_NONCE, CLAIM_TYPE_BSTR, nonce);
    if( return_value != 0 ) return( return_value );

    ctoken_encode_ueid(&encode_ctx, ueid);

    /* Finally completed it. This invokes the signing and
     * ties everything off and outputs the completed token.
     * The variable completed_token has the pointer and length
     * of the result that are in output_buffer.
     */
    return_value = ctoken_encode_finish(&encode_ctx, completed_token);

    return return_value;
}


int32_t kat_encode(struct t_cose_key signing_key,
                   struct q_useful_buf_c nonce,
                   struct q_useful_buf_c ik_pub,
                   struct q_useful_buf_c kak_pub,
                   struct q_useful_buf output_buffer,
                   struct q_useful_buf_c *completed_token)
{
    struct ctoken_encode_ctx encode_ctx;
    int                      return_value;

    /* Initialize, telling is the option (there are none) and
     * the signing algorithm to use.
     */
    ctoken_encode_init(&encode_ctx,
                       0, /* No t_cose options */
                       0, /* No ctoken options */
                       CTOKEN_PROTECTION_COSE_SIGN1,
                       T_COSE_ALGORITHM_ES256);

    /* Next give it the signing key. No kid (key id) is given so
     * NULL_Q_USEFUL_BUF_C is passed.
     */
    ctoken_encode_set_key(&encode_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    /* Pass in the output buffer and get the encoding started.
     * The output buffer must be big enough for EAT payload, COSE
     * formatting and signature. (There is a way to call
     * ctoken_encode_start() to have this computed which is th
     * same as that used by t_cose and QCBOR, but that is not
     * done in this simple example. */
    ctoken_encode_start(&encode_ctx, output_buffer);

    /* Add nonce claim */
    return_value = ctoken_encode_claim(&encode_ctx, CTOKEN_EAT_LABEL_NONCE, CLAIM_TYPE_BSTR, nonce);
    if( return_value != 0 ) return( return_value );

    /* Add IK public key claim */
    return_value = ctoken_encode_claim(&encode_ctx, CTOKEN_LABEL_CNF, CLAIM_TYPE_BSTR, ik_pub);
    if( return_value != 0 ) return( return_value );

    /* Add KAK public key claim */
    return_value = ctoken_encode_claim(&encode_ctx, CTOKEN_TEMP_LABEL_KAK_PUB, CLAIM_TYPE_BSTR, kak_pub);
    if( return_value != 0 ) return( return_value );

    /* Finally completed it. This invokes the signing and
     * ties everything off and outputs the completed token.
     * The variable completed_token has the pointer and length
     * of the result that are in output_buffer.
     */
    return_value = ctoken_encode_finish(&encode_ctx, completed_token);

    return return_value;
}


int32_t
ctoken_encode_claim(struct ctoken_encode_ctx *me,
                    int label,
                    uint8_t type,
                    struct q_useful_buf_c    content)
{
    switch(type)
    {
        case CLAIM_TYPE_INT:
           ctoken_encode_int(me, label, (int64_t) content.ptr);
           break;
        case CLAIM_TYPE_BSTR:
           ctoken_encode_bstr(me, label, content);
           break;
        case CLAIM_TYPE_TSTR:
           ctoken_encode_tstr(me, label, content);
           break;
        case CLAIM_TYPE_UINT:
           ctoken_encode_unsigned(me, label,  (int64_t) content.ptr);
           break;
        default:
            /* Unknown claim */
            return( -1 );
    }

    return 0;
}


int32_t create_eat( uint8_t *ptr, size_t *len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair)
{
    /* Call to macro to make a 500 byte struct useful_buf on the stack
     * named token_buffer. The expected token is less than 200 bytes.
     */
    MakeUsefulBufOnStack( token_buffer, 500 );
    struct q_useful_buf_c completed_token;
    int return_value;

    /* Make the token */
    return_value = eat_encode( *key_pair,
                               ( struct q_useful_buf_c )
                               {
                                 .len = nonce_len,
                                 .ptr = nonce
                               },
                               token_buffer,
                               &completed_token);

    if( return_value ) {
        return (return_value);
    }

    *len = completed_token.len;

    memcpy(ptr, (uint8_t *) completed_token.ptr, *len);

    return(return_value);
}
#endif /* MBEDTLS_PARSEC_ATTESTATION */

int32_t verify_eat( uint8_t *ptr, size_t len, const uint8_t *nonce, size_t nonce_len, struct t_cose_key *key_pair)
{
    struct q_useful_buf_c completed_token;
    struct q_useful_buf_c decoded_nonce;
    int return_value;

    completed_token.len = len;
    completed_token.ptr = ptr;

    return_value = eat_decode( *key_pair,
                              completed_token,
                               &decoded_nonce);

    if( return_value != 0 ) {
        return( return_value );
    }

    if( memcmp( decoded_nonce.ptr, nonce, nonce_len ) != 0 )
    {
        return( CTOKEN_ERR_TAMPERING_DETECTED );
    }

    return( return_value );
}

/**
 * \brief Fetch key
 *
 * \param[in] key_type           key type (KAK, PAK)
 * \param[in] cose_algorithm_id  Algorithn
 *                               \ref T_COSE_ALGORITHM_ES256.
 * \param[out] key_pair          The key pair. This must be freed.
 *
 * The key made here is fixed and just useful for testing.
 */
enum t_cose_err_t fetch_key(uint8_t            key_type,
                            int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    psa_key_type_t      type;
    psa_status_t        crypto_result;
    psa_key_handle_t    key_handle;
    psa_algorithm_t     key_alg;
    const uint8_t      *private_key;
    size_t              private_key_len;

    /* There is not a 1:1 mapping from alg to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

#ifdef T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
#define PSA_KEY_TYPE_ECC_KEY_PAIR PSA_KEY_TYPE_ECC_KEYPAIR
#endif /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */

    /* Only two types of signing keys supported: KAK and PAK */
    if( key_type != EAT_KEY_TYPE_KAK &&
        key_type != EAT_KEY_TYPE_PAK )
    {
        return T_COSE_ERR_FAIL;
    }

    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_ES256:
            if( key_type == EAT_KEY_TYPE_KAK ){
                private_key_len = sizeof(kak_private_key_256);
                private_key     = kak_private_key_256;
            } else {
                private_key_len = sizeof(pak_private_key_256);
                private_key     = pak_private_key_256;
            }
            type            = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
            break;

        case T_COSE_ALGORITHM_ES384:
            if( key_type == EAT_KEY_TYPE_KAK ){
                private_key_len = sizeof(kak_private_key_384);
                private_key     = kak_private_key_384;
            } else {
                private_key_len = sizeof(pak_private_key_384);
                private_key     = pak_private_key_384;
            }
            type            = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
            break;

        case T_COSE_ALGORITHM_ES512:
            if( key_type == EAT_KEY_TYPE_KAK ){
                private_key_len = sizeof(kak_private_key_521);
                private_key     = kak_private_key_521;
            } else {
                private_key_len = sizeof(pak_private_key_521);
                private_key     = pak_private_key_521;
            }
            type            = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
            key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
            break;

        default:
            return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data. The variable key_type contains
     * that information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     *
     * How this is done varies quite a lot in the newer
     * PSA Crypto API compared to the older.
     */

#ifdef T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11
    /* Allocate for the key pair in the Crypto service */
    crypto_result = psa_allocate_key(&key_handle);
    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* Say what algorithm and operations the key can be used with / for */
    psa_key_policy_t policy = psa_key_policy_init();
    psa_key_policy_set_usage(&policy,
                             PSA_KEY_USAGE_SIGN | PSA_KEY_USAGE_VERIFY,
                             key_alg);
    crypto_result = psa_set_key_policy(key_handle, &policy);
    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    /* key_type has the type of key including the EC curve */
    crypto_result = psa_import_key(key_handle,
                                   key_type,
                                   private_key,
                                   private_key_len);

#else /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */
    psa_key_attributes_t key_attributes;

    key_attributes = psa_key_attributes_init();

    /* Say what algorithm and operations the key can be used with / for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, type);

    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. (With ECDSA the public key is always
     * deterministically derivable from the private key).
     */
    crypto_result = psa_import_key(&key_attributes,
                                   private_key,
                                   private_key_len,
                                   &key_handle);

#endif /* T_COSE_USE_PSA_CRYPTO_FROM_MBED_CRYPTO11 */

    if (crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    key_pair->k.key_handle = key_handle;
    key_pair->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}


/**
 * \brief  Free a PSA / MBed key.
 *
 * \param[in] key_pair   The key pair to close / deallocate / free.
 */
void free_psa_ecdsa_key_pair(struct t_cose_key key_pair)
{
    psa_close_key((psa_key_handle_t) key_pair.k.key_handle);
}

/**
 Simple EAT decode and verify example.

 @param[in] verification_key  The public key to verify the token with. It must
                              be in the format for the crypto library that
                              ctoken and t_cose are integrated with. See
                              the t_cose headers.
 @param[in] token             Pointer and length of the token to verify.
 @param[out] nonce            Place to return pointer and length of the
                              nonce.
 @return                      0 on success.

 This only retrieves the nonce claim from the token (so far).
 */
int32_t eat_decode(struct t_cose_key     verification_key,
                   struct q_useful_buf_c token,
                   struct q_useful_buf_c *nonce)
{
    struct ctoken_decode_ctx decode_context;
    int result_value;

    /* Initialize the decoding context. No options are given.
     * The algorithm in use comes from the header in the token
     * so it is not specified here
     */
    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_BY_TAG);

    /* Set the verification key to use. It must be a key that works
     * with the algorithm the token was signed with. (This can be
     * be retrieved, but it is not shown here.)
     */
    ctoken_decode_set_verification_key(&decode_context, verification_key);

    /* Validate the signature on the token */
    ctoken_decode_validate_token(&decode_context, token);

    /* Parse the nonce out of the token */
    result_value = ctoken_decode_claim(&decode_context, CTOKEN_EAT_LABEL_NONCE, CLAIM_TYPE_BSTR, nonce);
    if( result_value != 0 ) return( result_value );

    return ctoken_decode_get_and_reset_error(&decode_context);
}

int32_t pat_verify(struct t_cose_key     pak,
                   struct q_useful_buf_c pat,
                   struct q_useful_buf_c *hash_ik_pub)
{
    struct ctoken_decode_ctx decode_context;
    int32_t return_result;

    /* Initialize the decoding context. No options are given.
     * The algorithm in use comes from the header in the token
     * so it is not specified here
     */
    ctoken_decode_init(&decode_context,
                       0,
                       0,
                       CTOKEN_PROTECTION_BY_TAG);

    /* Set the verification key to use. It must be a key that works
     * with the algorithm the token was signed with. (This can be
     * be retrieved, but it is not shown here.)
     */
    ctoken_decode_set_verification_key(&decode_context, pak);

    /* Validate the signature on the token */
    ctoken_decode_validate_token(&decode_context, pat);

    if( decode_context.last_error == CTOKEN_ERR_SUCCESS)
    {
        return( decode_context.last_error );
    }

    /* Obtain hashed IK public key */
    return_result = ctoken_decode_claim(&decode_context, CTOKEN_EAT_LABEL_NONCE, CLAIM_TYPE_BSTR, hash_ik_pub);
    if( return_result != 0 ) return( return_result );

    return ctoken_decode_get_and_reset_error(&decode_context);
}


int32_t kat_verify(struct t_cose_key     kak,
                   struct q_useful_buf_c kat,
                   struct q_useful_buf_c *nonce,
                   struct q_useful_buf_c *ik_pub,
                   struct q_useful_buf_c *kak_pub)
{
    int result_value;
    struct ctoken_decode_ctx decode_context;

    /* Initialize the decoding context. No options are given.
     * The algorithm in use comes from the header in the token
     * so it is not specified here
     */
    ctoken_decode_init( &decode_context,
                        0,
                        0,
                        CTOKEN_PROTECTION_BY_TAG );

    /* Set the verification key to use. */
    ctoken_decode_set_verification_key( &decode_context, kak );

    /* Validate the signature on the token */
    ctoken_decode_validate_token( &decode_context, kat );

    /* Obtain nonce */
    result_value = ctoken_decode_claim( &decode_context, CTOKEN_EAT_LABEL_NONCE, CLAIM_TYPE_BSTR, nonce);
    if( result_value != 0) return( result_value );

    /* Obtain IK public key */
    result_value = ctoken_decode_claim( &decode_context, CTOKEN_LABEL_CNF, CLAIM_TYPE_BSTR, ik_pub);
    if( result_value != 0) return( result_value );

    /* Obtain KAK public key */
    result_value = ctoken_decode_claim( &decode_context, CTOKEN_TEMP_LABEL_KAK_PUB, CLAIM_TYPE_BSTR, kak_pub);
    if( result_value != 0) return( result_value );

    return ctoken_decode_get_and_reset_error( &decode_context);
}

int32_t
ctoken_decode_claim(struct ctoken_decode_ctx *me,
                    int label,
                    uint8_t type,
                    struct q_useful_buf_c    *content)
{
    switch(type)
    {
        case CLAIM_TYPE_INT:
           ctoken_decode_int(me, label, (int64_t*) content->ptr);
           break;
        case CLAIM_TYPE_BSTR:
           ctoken_decode_bstr(me, label, content);
           break;
        case CLAIM_TYPE_TSTR:
           ctoken_decode_tstr(me, label, content);
           break;
        case CLAIM_TYPE_UINT:
           ctoken_decode_uint(me, label, (int64_t*) content->ptr);
           break;
        default:
            /* Unknown claim */
            return( -1 );
    }

    return 0;
}

int32_t verify_kat_bundle( uint8_t *kat_bundle, size_t kat_bundle_len,
                    const uint8_t *nonce, size_t nonce_len,
                    uint8_t *ik_pub, size_t ik_pub_len,
                    size_t *ik_pub_size)
{
    struct q_useful_buf_c decoded_nonce;
    struct q_useful_buf_c decoded_ik_pub;
    struct q_useful_buf_c decoded_kak_pub;
    struct q_useful_buf_c kat;
    struct q_useful_buf_c pat;
    struct q_useful_buf_c hash_ik_pub_struct;
    struct t_cose_key pak;
    struct t_cose_key kak;

    int return_value;
    psa_status_t status;

    uint8_t hash_ik_pub[PSA_HASH_MAX_SIZE];
    memset( hash_ik_pub,0,sizeof( hash_ik_pub ) );
    size_t hash_ik_pub_len;

    status = fetch_key(EAT_KEY_TYPE_PAK, T_COSE_ALGORITHM_ES256, &pak);

    if( status != PSA_SUCCESS )
        return( -1 );

    status = fetch_key(EAT_KEY_TYPE_KAK, T_COSE_ALGORITHM_ES256, &kak);

    if( status != PSA_SUCCESS ) {
        free_psa_ecdsa_key_pair( pak );
        return( -1 );
    }

    /* Extract KAT */
    kat.len = MBEDTLS_GET_UINT16_BE( kat_bundle, 1 );
    kat.ptr = &kat_bundle[1 + 2];

    /* Extract PAT */
    pat.len = MBEDTLS_GET_UINT16_BE( kat_bundle, 1 + 2 + kat.len );
    pat.ptr = &kat_bundle[1 + 2 + kat.len + 2];

    /* Verify the KAT */
    return_value = kat_verify( kak,
                               kat,
                              &decoded_nonce,
                              &decoded_ik_pub,
                               &decoded_kak_pub);

    if( return_value ) {
        free_psa_ecdsa_key_pair( pak );
        free_psa_ecdsa_key_pair( kak );
        return( return_value );
    }

    /* Check nonce */
    if ( memcmp(decoded_nonce.ptr, nonce, nonce_len) != 0 )
    {
        free_psa_ecdsa_key_pair( pak );
        free_psa_ecdsa_key_pair( kak );
        return( CTOKEN_ERR_TAMPERING_DETECTED );
    }

    /* Hash IK pub */
    status = psa_hash_compute( PSA_ALG_SHA_256,
                               decoded_ik_pub.ptr, decoded_ik_pub.len,
                               hash_ik_pub, sizeof( hash_ik_pub ),
                               &hash_ik_pub_len );
    if( status != PSA_SUCCESS )
    {
        free_psa_ecdsa_key_pair( pak );
        free_psa_ecdsa_key_pair( kak );
        return( status );
    }

    hash_ik_pub_struct.len = hash_ik_pub_len;
    hash_ik_pub_struct.ptr = hash_ik_pub;

    /* Verify the PAT */
    return_value = pat_verify( pak,
                               pat,
                               &hash_ik_pub_struct );

    if( return_value != CTOKEN_ERR_SUCCESS ) {
        free_psa_ecdsa_key_pair( pak );
        free_psa_ecdsa_key_pair( kak );
        return( return_value );
    }

    if( decoded_ik_pub.len > ik_pub_len ) {
        free_psa_ecdsa_key_pair( pak );
        free_psa_ecdsa_key_pair( kak );
        return(CTOKEN_ERR_INSUFFICIENT_MEMORY);
    }

    /* Return IK public key */
    *ik_pub_size = decoded_ik_pub.len;
    memcpy( ik_pub,decoded_ik_pub.ptr,decoded_ik_pub.len );

    free_psa_ecdsa_key_pair( pak );
    free_psa_ecdsa_key_pair( kak );

    return( return_value );
}
