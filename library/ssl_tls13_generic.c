/*
 *  TLS 1.3 functionality shared between client and server
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "ssl_misc.h"

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include <string.h>

#include "mbedtls/error.h"
#include "debug_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"
#include "mbedtls/constant_time.h"
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"

#include "ssl_tls13_invasive.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"

#include "psa/crypto.h"
#include "psa_util_internal.h"

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
/* Define a local translating function to save code size by not using too many
 * arguments in each translating place. */
static int local_err_translation(psa_status_t status)
{
    return psa_status_to_mbedtls(status, psa_to_ssl_errors,
                                 ARRAY_LENGTH(psa_to_ssl_errors),
                                 psa_generic_status_to_mbedtls);
}
#define PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#endif

const uint8_t mbedtls_ssl_tls13_hello_retry_request_magic[
    MBEDTLS_SERVER_HELLO_RANDOM_LEN] =
{ 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
  0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
  0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
  0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

int mbedtls_ssl_tls13_fetch_handshake_msg(mbedtls_ssl_context *ssl,
                                          unsigned hs_type,
                                          unsigned char **buf,
                                          size_t *buf_len)
{
    int ret;

    if ((ret = mbedtls_ssl_read_record(ssl, 0)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        goto cleanup;
    }

    if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0]  != hs_type) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Receive unexpected handshake message."));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    /*
     * Jump handshake header (4 bytes, see Section 4 of RFC 8446).
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf = ssl->in_msg   + 4;
    *buf_len = ssl->in_hslen - 4;

cleanup:

    return ret;
}

#if defined(MBEDTLS_KEY_UPDATE)
/* TLS 1.3 KeyUpdate (RFC 8446, Section 4.6.3). */
#define MBEDTLS_SSL_TLS1_3_KEY_UPDATE_NOT_REQUESTED 0
#define MBEDTLS_SSL_TLS1_3_KEY_UPDATE_REQUESTED     1

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_key_update(const unsigned char *buf,
                                      const unsigned char *end,
                                      uint8_t *request_update)
{
    if ((size_t) (end - buf) != 1) {
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    if (buf[0] != MBEDTLS_SSL_TLS1_3_KEY_UPDATE_NOT_REQUESTED &&
        buf[0] != MBEDTLS_SSL_TLS1_3_KEY_UPDATE_REQUESTED) {
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    *request_update = buf[0];
    return 0;
}

int mbedtls_ssl_tls13_process_key_update(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    uint8_t request_update = 0;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> process KeyUpdate"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_KEY_UPDATE, &buf, &buf_len));

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_key_update(buf, buf + buf_len,
                                                    &request_update));

    MBEDTLS_SSL_DEBUG_MSG(3, ("KeyUpdate: request_update=%u",
                              (unsigned) request_update));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_update_application_keys(
                             ssl, MBEDTLS_SSL_TLS1_3_KEY_UPDATE_RX));

    if (request_update == MBEDTLS_SSL_TLS1_3_KEY_UPDATE_REQUESTED) {
        ssl->handshake->tls13_key_update_out_request =
            MBEDTLS_SSL_TLS1_3_KEY_UPDATE_NOT_REQUESTED;
        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_KEY_UPDATE_SEND);
    } else {
        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_HANDSHAKE_OVER);
    }

cleanup:
    if (ret != 0) {
        if (ret == MBEDTLS_ERR_SSL_DECODE_ERROR) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR, ret);
        } else if (ret == MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER, ret);
        }
    }

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= process KeyUpdate"));
    return ret;
}

int mbedtls_ssl_tls13_write_key_update(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write KeyUpdate"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_KEY_UPDATE,
                             &buf, &buf_len));

    MBEDTLS_SSL_CHK_BUF_PTR(buf, buf + buf_len, 1);
    buf[0] = ssl->handshake->tls13_key_update_out_request;

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, 1));

    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_KEY_UPDATE_SEND_FLUSH);

cleanup:
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write KeyUpdate"));
    return ret;
}

int mbedtls_ssl_tls13_key_update_send_flush(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> KeyUpdate send flush"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_update_application_keys(
                             ssl, MBEDTLS_SSL_TLS1_3_KEY_UPDATE_TX));

    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_HANDSHAKE_OVER);
    ret = 0;

cleanup:
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= KeyUpdate send flush"));
    return ret;
}
#endif /* MBEDTLS_KEY_UPDATE */

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)
#if defined(MBEDTLS_EXTENDED_KEY_UPDATE)
/* TLS 1.3 Extended Key Update (EKU) (draft-ietf-tls-extended-key-update). */

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_eku_parse_body(const unsigned char *buf,
                                    const unsigned char *end,
                                    uint8_t *eku_type,
                                    uint16_t *group,
                                    const unsigned char **key_exchange,
                                    size_t *key_exchange_len)
{
    const unsigned char *p = buf;

    if ((size_t) (end - p) < 1) {
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    *eku_type = p[0];
    p += 1;

    if (*eku_type == MBEDTLS_SSL_TLS1_3_EKU_TYPE_NEW_KEY_UPDATE) {
        if (p != end) {
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        *group = 0;
        *key_exchange = NULL;
        *key_exchange_len = 0;
        return 0;
    }

    if (*eku_type != MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_REQUEST &&
        *eku_type != MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_RESPONSE) {
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    if ((size_t) (end - p) < 4) {
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    *group = MBEDTLS_GET_UINT16_BE(p, 0);
    *key_exchange_len = MBEDTLS_GET_UINT16_BE(p, 2);
    p += 4;

    if ((size_t) (end - p) < *key_exchange_len) {
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (p + *key_exchange_len != end) {
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    *key_exchange = p;
    return 0;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_eku_extract_secret(psa_algorithm_t hash_alg,
                                        const unsigned char *salt,
                                        size_t salt_len,
                                        const unsigned char *ikm,
                                        size_t ikm_len,
                                        unsigned char *out,
                                        size_t out_len)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_derivation_operation_t operation =
        PSA_KEY_DERIVATION_OPERATION_INIT;

    status = psa_key_derivation_setup(&operation,
                                      PSA_ALG_HKDF_EXTRACT(hash_alg));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&operation,
                                            PSA_KEY_DERIVATION_INPUT_SECRET,
                                            ikm, ikm_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_output_bytes(&operation, out, out_len);

cleanup:
    abort_status = psa_key_derivation_abort(&operation);
    status = (status == PSA_SUCCESS ? abort_status : status);
    return PSA_TO_MBEDTLS_ERR(status);
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_eku_compute_shared_secret(mbedtls_ssl_context *ssl,
                                              uint16_t named_group,
                                              unsigned char **shared_secret,
                                              size_t *shared_secret_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_NONE;

    *shared_secret = NULL;
    *shared_secret_len = 0;

    if (mbedtls_ssl_tls13_named_group_is_ecdhe(named_group)) {
        alg = PSA_ALG_ECDH;
    } else if (mbedtls_ssl_tls13_named_group_is_ffdh(named_group)) {
        alg = PSA_ALG_FFDH;
    } else {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    status = psa_get_key_attributes(ssl->handshake->xxdh_psa_privkey,
                                    &key_attributes);
    if (status != PSA_SUCCESS) {
        return PSA_TO_MBEDTLS_ERR(status);
    }

    *shared_secret_len = PSA_BITS_TO_BYTES(psa_get_key_bits(&key_attributes));
    *shared_secret = mbedtls_calloc(1, *shared_secret_len);
    if (*shared_secret == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    status = psa_raw_key_agreement(
        alg, ssl->handshake->xxdh_psa_privkey,
        ssl->handshake->xxdh_psa_peerkey, ssl->handshake->xxdh_psa_peerkey_len,
        *shared_secret, *shared_secret_len, shared_secret_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = psa_destroy_key(ssl->handshake->xxdh_psa_privkey);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    ssl->handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;

    ret = 0;

cleanup:
    if (ret != 0 && *shared_secret != NULL) {
        mbedtls_zeroize_and_free(*shared_secret, *shared_secret_len);
        *shared_secret = NULL;
        *shared_secret_len = 0;
    }
    return ret;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_eku_hash_message(psa_hash_operation_t *operation,
                                      unsigned hs_type,
                                      const unsigned char *msg,
                                      size_t msg_len)
{
    unsigned char hs_hdr[4];
    psa_status_t status;

    hs_hdr[0] = MBEDTLS_BYTE_0(hs_type);
    hs_hdr[1] = MBEDTLS_BYTE_2(msg_len);
    hs_hdr[2] = MBEDTLS_BYTE_1(msg_len);
    hs_hdr[3] = MBEDTLS_BYTE_0(msg_len);

    status = psa_hash_update(operation, hs_hdr, sizeof(hs_hdr));
    if (status != PSA_SUCCESS) {
        return PSA_TO_MBEDTLS_ERR(status);
    }

    status = psa_hash_update(operation, msg, msg_len);
    return PSA_TO_MBEDTLS_ERR(status);
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_eku_compute_transcript_hash_next(
    psa_algorithm_t hash_alg,
    const unsigned char *transcript_hash,
    size_t transcript_hash_len,
    const unsigned char *req,
    size_t req_len,
    const unsigned char *resp,
    size_t resp_len,
    unsigned char *out,
    size_t out_size,
    size_t *out_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;

    if (transcript_hash == NULL || transcript_hash_len == 0 ||
        req == NULL || req_len == 0 || resp == NULL || resp_len == 0 ||
        out == NULL || out_len == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (out_size < PSA_HASH_LENGTH(hash_alg)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    status = psa_hash_setup(&operation, hash_alg);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = psa_hash_update(&operation, transcript_hash, transcript_hash_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = ssl_tls13_eku_hash_message(&operation, MBEDTLS_SSL_HS_EXTENDED_KEY_UPDATE,
                                     req, req_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = ssl_tls13_eku_hash_message(&operation, MBEDTLS_SSL_HS_EXTENDED_KEY_UPDATE,
                                     resp, resp_len);
    if (ret != 0) {
        goto cleanup;
    }

    status = psa_hash_finish(&operation, out, out_size, out_len);
    ret = PSA_TO_MBEDTLS_ERR(status);

cleanup:
    abort_status = psa_hash_abort(&operation);
    if (ret == 0 && abort_status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(abort_status);
    }

    return ret;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_eku_derive_next_secrets(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    psa_algorithm_t hash_alg;
    size_t hash_len;
    unsigned char main_secret_next[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char *shared_secret = NULL;
    size_t shared_secret_len = 0;
    unsigned char transcript_hash[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_hash_len = 0;
    size_t dump_len = 0;

    if (ssl->handshake->tls13_eku_req_len == 0 ||
        ssl->handshake->tls13_eku_resp_len == 0 ||
        ssl->handshake->tls13_eku_salt_len == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(ssl->session->ciphersuite);
    if (ciphersuite_info == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    hash_alg = mbedtls_md_psa_alg_from_type((mbedtls_md_type_t) ciphersuite_info->mac);
    hash_len = PSA_HASH_LENGTH(hash_alg);

    if (hash_len > sizeof(main_secret_next) ||
        ssl->handshake->tls13_eku_salt_len < hash_len ||
        ssl->handshake->tls13_eku_transcript_hash_len != hash_len) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = ssl_tls13_eku_compute_shared_secret(ssl, ssl->handshake->offered_group_id,
                                              &shared_secret, &shared_secret_len);
    if (ret != 0) {
        return ret;
    }
    dump_len = shared_secret_len > 16 ? 16 : shared_secret_len;
    MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: shared_secret_len=%" MBEDTLS_PRINTF_SIZET,
                              shared_secret_len));
    MBEDTLS_SSL_DEBUG_BUF(4, "EKU: shared_secret prefix",
                          shared_secret, dump_len);

    ret = ssl_tls13_eku_extract_secret(hash_alg,
                                       ssl->handshake->tls13_eku_salt, hash_len,
                                       shared_secret, shared_secret_len,
                                       main_secret_next, hash_len);
    if (ret != 0) {
        goto cleanup;
    }

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_compute_transcript_hash_next(
                             hash_alg,
                             ssl->handshake->tls13_eku_transcript_hash,
                             ssl->handshake->tls13_eku_transcript_hash_len,
                             ssl->handshake->tls13_eku_req,
                             ssl->handshake->tls13_eku_req_len,
                             ssl->handshake->tls13_eku_resp,
                             ssl->handshake->tls13_eku_resp_len,
                             transcript_hash, sizeof(transcript_hash),
                             &transcript_hash_len));

    MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: req_len=%" MBEDTLS_PRINTF_SIZET
                              " resp_len=%" MBEDTLS_PRINTF_SIZET,
                              ssl->handshake->tls13_eku_req_len,
                              ssl->handshake->tls13_eku_resp_len));
    if (transcript_hash_len < hash_len) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    dump_len = transcript_hash_len > 16 ? 16 : transcript_hash_len;
    MBEDTLS_SSL_DEBUG_BUF(4, "EKU: transcript hash prefix",
                          transcript_hash, dump_len);

    ret = mbedtls_ssl_tls13_derive_secret(
        hash_alg, main_secret_next, hash_len,
        MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(c_ap_traffic),
        transcript_hash, transcript_hash_len,
        MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        ssl->handshake->tls13_eku_next_client_app_secret, hash_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_derive_secret(
        hash_alg, main_secret_next, hash_len,
        MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(s_ap_traffic),
        transcript_hash, transcript_hash_len,
        MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        ssl->handshake->tls13_eku_next_server_app_secret, hash_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_derive_secret(
        hash_alg, main_secret_next, hash_len,
        MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(exp_master),
        transcript_hash, transcript_hash_len,
        MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        ssl->handshake->tls13_eku_next_exporter_master_secret, hash_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_derive_secret(
        hash_alg, main_secret_next, hash_len,
        MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(res_master),
        transcript_hash, transcript_hash_len,
        MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
        ssl->handshake->tls13_eku_next_resumption_master_secret, hash_len);
    if (ret != 0) {
        goto cleanup;
    }

    /* Update EKU salt for the next generation: Derive-Secret(main_secret_next, "derived", ""). */
    ret = mbedtls_ssl_tls13_derive_secret(
        hash_alg, main_secret_next, hash_len,
        MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(derived),
        NULL, 0,
        MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
        ssl->handshake->tls13_eku_salt, hash_len);
    if (ret != 0) {
        goto cleanup;
    }

    ssl->handshake->tls13_eku_salt_len = hash_len;
    ssl->handshake->tls13_eku_hash_len = hash_len;
    ssl->handshake->tls13_eku_secrets_ready = 1;
    memcpy(ssl->handshake->tls13_eku_transcript_hash, transcript_hash, hash_len);
    ssl->handshake->tls13_eku_transcript_hash_len = hash_len;
    dump_len = hash_len > 16 ? 16 : hash_len;
    MBEDTLS_SSL_DEBUG_BUF(4, "EKU: salt prefix",
                          ssl->handshake->tls13_eku_salt, dump_len);
    MBEDTLS_SSL_DEBUG_BUF(4, "EKU: next client app secret prefix",
                          ssl->handshake->tls13_eku_next_client_app_secret, dump_len);
    MBEDTLS_SSL_DEBUG_BUF(4, "EKU: next server app secret prefix",
                          ssl->handshake->tls13_eku_next_server_app_secret, dump_len);
    ret = 0;

cleanup:
    mbedtls_platform_zeroize(main_secret_next, sizeof(main_secret_next));
    if (shared_secret != NULL) {
        mbedtls_zeroize_and_free(shared_secret, shared_secret_len);
    }
    mbedtls_platform_zeroize(transcript_hash, sizeof(transcript_hash));
    return ret;
}

static void ssl_tls13_eku_commit_exporter_and_resumption(mbedtls_ssl_context *ssl)
{
    size_t hash_len = ssl->handshake->tls13_eku_hash_len;

    memcpy(ssl->session->app_secrets.eku_previous_exporter_master_secret,
           ssl->session->app_secrets.eku_current_exporter_master_secret, hash_len);
    ssl->session->app_secrets.eku_previous_exporter_epoch =
        ssl->session->app_secrets.eku_current_exporter_epoch;
    ssl->session->app_secrets.eku_previous_exporter_valid = 1;

    memcpy(ssl->session->app_secrets.eku_current_exporter_master_secret,
           ssl->handshake->tls13_eku_next_exporter_master_secret, hash_len);
    ssl->session->app_secrets.eku_current_exporter_epoch++;
    memcpy(ssl->session->app_secrets.resumption_master_secret,
           ssl->handshake->tls13_eku_next_resumption_master_secret, hash_len);
}

static int ssl_tls13_eku_update_direction(mbedtls_ssl_context *ssl, int direction)
{
    const unsigned char *new_secret = NULL;
    unsigned char *dst_secret = NULL;
    size_t hash_len = ssl->handshake->tls13_eku_hash_len;

    if (!ssl->handshake->tls13_eku_secrets_ready) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    MBEDTLS_SSL_DEBUG_MSG(2, ("EKU: update direction=%s endpoint=%s hash_len=%" MBEDTLS_PRINTF_SIZET,
                              direction == MBEDTLS_SSL_TLS1_3_KEY_UPDATE_TX ? "TX" : "RX",
                              ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ? "client" : "server",
                              hash_len));

    if (direction == MBEDTLS_SSL_TLS1_3_KEY_UPDATE_TX) {
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            new_secret = ssl->handshake->tls13_eku_next_client_app_secret;
            dst_secret = ssl->session->app_secrets.client_application_traffic_secret_N;
        } else {
            new_secret = ssl->handshake->tls13_eku_next_server_app_secret;
            dst_secret = ssl->session->app_secrets.server_application_traffic_secret_N;
        }
    } else if (direction == MBEDTLS_SSL_TLS1_3_KEY_UPDATE_RX) {
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            new_secret = ssl->handshake->tls13_eku_next_server_app_secret;
            dst_secret = ssl->session->app_secrets.server_application_traffic_secret_N;
        } else {
            new_secret = ssl->handshake->tls13_eku_next_client_app_secret;
            dst_secret = ssl->session->app_secrets.client_application_traffic_secret_N;
        }
    } else {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    /* Install keys first, then commit the secret to the session state. */
    int ret = mbedtls_ssl_tls13_set_application_keys_from_secret(ssl, direction,
                                                                  new_secret, hash_len);
    if (ret != 0) {
        return ret;
    }

    MBEDTLS_SSL_DEBUG_BUF(4, "EKU: new traffic secret (first 16 bytes)",
                          new_secret, hash_len > 16 ? 16 : hash_len);

    memcpy(dst_secret, new_secret, hash_len);
    return 0;
}

int mbedtls_ssl_tls13_process_extended_key_update(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf = NULL;
    size_t buf_len = 0;
    uint8_t eku_type = 0;
    uint16_t group = 0;
    const unsigned char *key_exchange = NULL;
    size_t key_exchange_len = 0;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> process ExtendedKeyUpdate"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    if (!ssl->tls13_eku_negotiated) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    while (1) {
        if ((ret = mbedtls_ssl_read_record(ssl, 0)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
            goto cleanup;
        }

        if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
            ssl->in_hslen == mbedtls_ssl_hs_hdr_len(ssl)) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("Receive unexpected post-handshake message."));
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                         MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
            ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
            goto cleanup;
        }

#if defined(MBEDTLS_SSL_CLI_C)
        /*
         * NewSessionTicket is a legal post-handshake message and can be
         * interleaved with EKU. We currently ignore tickets while an EKU
         * exchange is in progress.
         */
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
            ssl->in_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: ignoring NewSessionTicket"));
            continue;
        }
#endif /* MBEDTLS_SSL_CLI_C */

        if (ssl->in_msg[0] != MBEDTLS_SSL_HS_EXTENDED_KEY_UPDATE) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("Receive unexpected handshake message."));
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                         MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
            ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
            goto cleanup;
        }

        buf = ssl->in_msg + 4;
        buf_len = ssl->in_hslen - 4;
        break;
    }

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_parse_body(buf, buf + buf_len,
                                                  &eku_type, &group,
                                                  &key_exchange, &key_exchange_len));

    MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: type=%u state=%u group=%u kx_len=%" MBEDTLS_PRINTF_SIZET,
                              (unsigned) eku_type,
                              (unsigned) ssl->handshake->tls13_eku_state,
                              (unsigned) group,
                              key_exchange_len));
    if (key_exchange_len > 0 && key_exchange != NULL) {
        size_t dump_len = key_exchange_len > 16 ? 16 : key_exchange_len;
        MBEDTLS_SSL_DEBUG_BUF(4, "EKU: key_exchange prefix", key_exchange, dump_len);
    }

    if (eku_type == MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_REQUEST) {
        /* Tie-break if we also initiated and requests crossed. */
        if (ssl->handshake->tls13_eku_state == MBEDTLS_SSL_TLS1_3_EKU_INITIATOR_WAIT_RESP) {
            int cmp;

            if (ssl->handshake->tls13_eku_own_req_key_exchange_len != key_exchange_len) {
                size_t min_len = ssl->handshake->tls13_eku_own_req_key_exchange_len;
                if (key_exchange_len < min_len) {
                    min_len = key_exchange_len;
                }
                cmp = memcmp(ssl->handshake->tls13_eku_own_req_key_exchange,
                             key_exchange, min_len);
                if (cmp == 0) {
                    cmp = (ssl->handshake->tls13_eku_own_req_key_exchange_len < key_exchange_len) ?
                          -1 : 1;
                }
            } else {
                cmp = memcmp(ssl->handshake->tls13_eku_own_req_key_exchange,
                             key_exchange, key_exchange_len);
            }

            if (cmp == 0) {
                MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                             MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
                return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
            }

            /* Lower key_exchange MUST be ignored. */
            if (cmp < 0) {
                MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: ignoring own request (tie-break)"));
                /*
                 * No EKU transcript rollback is needed here: transcript_hash_N
                 * is only advanced when an accepted req/resp pair is processed
                 * in ssl_tls13_eku_derive_next_secrets().
                 */
                psa_destroy_key(ssl->handshake->xxdh_psa_privkey);
                ssl->handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
                ssl->handshake->tls13_eku_state = MBEDTLS_SSL_TLS1_3_EKU_IDLE;
            } else {
                MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: ignoring peer request (tie-break)"));
                mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU);
                return 0;
            }
        }

        if (ssl->handshake->tls13_eku_state != MBEDTLS_SSL_TLS1_3_EKU_IDLE) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                         MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
            return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        }

        if (group != ssl->handshake->offered_group_id) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                         MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
            return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }

        if (buf_len > sizeof(ssl->handshake->tls13_eku_req)) {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        memcpy(ssl->handshake->tls13_eku_req, buf, buf_len);
        ssl->handshake->tls13_eku_req_len = buf_len;

        MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: stored request len=%" MBEDTLS_PRINTF_SIZET, buf_len));

        /* Store peer key_exchange bytes. */
        MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_read_public_xxdhe_share(
                                 ssl,
                                 (const unsigned char *) (key_exchange - 2),
                                 2 + key_exchange_len));

        /* Build response body: type + KeyShareEntry. */
        {
            unsigned char *p = ssl->handshake->tls13_eku_resp;
            unsigned char *end = ssl->handshake->tls13_eku_resp + sizeof(ssl->handshake->tls13_eku_resp);
            size_t kx_len = 0;

            *p++ = MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_RESPONSE;
            MBEDTLS_SSL_CHK_BUF_PTR(p, end, 4);
            MBEDTLS_PUT_UINT16_BE(group, p, 0);
            p += 4;

            ret = mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
                ssl, group, p, end, &kx_len);
            if (ret != 0) {
                goto cleanup;
            }
            MBEDTLS_PUT_UINT16_BE(kx_len, p - 2, 0);
            p += kx_len;

            ssl->handshake->tls13_eku_resp_len = p - ssl->handshake->tls13_eku_resp;
        }

        MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: built response len=%" MBEDTLS_PRINTF_SIZET,
                                  ssl->handshake->tls13_eku_resp_len));

        /* Derive secrets and commit exporter/resumption. */
        MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_derive_next_secrets(ssl));
        ssl_tls13_eku_commit_exporter_and_resumption(ssl);

        ssl->handshake->tls13_eku_outgoing_type =
            MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_RESPONSE;
        ssl->handshake->tls13_eku_outgoing_updates_tx = 1;
        ssl->handshake->tls13_eku_state = MBEDTLS_SSL_TLS1_3_EKU_RESPONDER_WAIT_NKU;

        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU_SEND_RESPONSE);
        ret = 0;
        goto cleanup;
    }

    if (eku_type == MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_RESPONSE) {
        if (ssl->handshake->tls13_eku_state != MBEDTLS_SSL_TLS1_3_EKU_INITIATOR_WAIT_RESP) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                         MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
            return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        }

        if (group != ssl->handshake->offered_group_id) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                         MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
            return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }

        if (buf_len > sizeof(ssl->handshake->tls13_eku_resp)) {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        memcpy(ssl->handshake->tls13_eku_resp, buf, buf_len);
        ssl->handshake->tls13_eku_resp_len = buf_len;

        MBEDTLS_SSL_DEBUG_MSG(3, ("EKU: stored response len=%" MBEDTLS_PRINTF_SIZET, buf_len));

        /* Store peer key_exchange bytes. */
        MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_read_public_xxdhe_share(
                                 ssl,
                                 (const unsigned char *) (key_exchange - 2),
                                 2 + key_exchange_len));

        /* Derive secrets and update RX. */
        MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_derive_next_secrets(ssl));
        ssl_tls13_eku_commit_exporter_and_resumption(ssl);

        MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_update_direction(ssl,
                                                            MBEDTLS_SSL_TLS1_3_KEY_UPDATE_RX));

        ssl->handshake->tls13_eku_outgoing_type =
            MBEDTLS_SSL_TLS1_3_EKU_TYPE_NEW_KEY_UPDATE;
        ssl->handshake->tls13_eku_outgoing_updates_tx = 1;

        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU_SEND_NKU);
        ret = 0;
        goto cleanup;
    }

    /* NKU */
    if (ssl->handshake->tls13_eku_state != MBEDTLS_SSL_TLS1_3_EKU_RESPONDER_WAIT_NKU) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                     MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_update_direction(ssl,
                                                        MBEDTLS_SSL_TLS1_3_KEY_UPDATE_RX));

    ssl->handshake->tls13_eku_state = MBEDTLS_SSL_TLS1_3_EKU_IDLE;
    ssl->handshake->tls13_eku_secrets_ready = 0;
    ssl->handshake->tls13_eku_req_len = 0;
    ssl->handshake->tls13_eku_resp_len = 0;
    ssl->handshake->tls13_eku_own_req_key_exchange_len = 0;
    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_HANDSHAKE_OVER);
    ret = 0;

cleanup:
    if (ret != 0) {
        if (ret == MBEDTLS_ERR_SSL_DECODE_ERROR) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR, ret);
        } else if (ret == MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER, ret);
        }
    }

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= process ExtendedKeyUpdate"));
    return ret;
}

int mbedtls_ssl_tls13_write_extended_key_update_request(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;
    uint16_t group;
    unsigned char *p;
    unsigned char *end;
    size_t kx_len = 0;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write EKU request"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->handshake->tls13_eku_state != MBEDTLS_SSL_TLS1_3_EKU_IDLE) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    group = ssl->handshake->offered_group_id;
    if (!mbedtls_ssl_tls13_named_group_is_ecdhe(group) &&
        !mbedtls_ssl_tls13_named_group_is_ffdh(group)) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_EXTENDED_KEY_UPDATE,
                             &buf, &buf_len));

    p = buf;
    end = buf + buf_len;

    MBEDTLS_SSL_CHK_BUF_PTR(p, end, 1 + 4);
    *p++ = MBEDTLS_SSL_TLS1_3_EKU_TYPE_KEY_UPDATE_REQUEST;
    MBEDTLS_PUT_UINT16_BE(group, p, 0);
    p += 4; /* group + key_exchange_length */

    ret = mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
        ssl, group, p, end, &kx_len);
    if (ret != 0) {
        goto cleanup;
    }

    /* Backfill key_exchange_length. */
    MBEDTLS_PUT_UINT16_BE(kx_len, p - 2, 0);

    /* Cache request body and tie-break material. */
    if ((size_t) (1 + 4 + kx_len) > sizeof(ssl->handshake->tls13_eku_req)) {
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }
    memcpy(ssl->handshake->tls13_eku_req, buf, 1 + 4 + kx_len);
    ssl->handshake->tls13_eku_req_len = 1 + 4 + kx_len;
    memcpy(ssl->handshake->tls13_eku_own_req_key_exchange, p, kx_len);
    ssl->handshake->tls13_eku_own_req_key_exchange_len = kx_len;

    ssl->handshake->tls13_eku_state = MBEDTLS_SSL_TLS1_3_EKU_INITIATOR_WAIT_RESP;

    p += kx_len;

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, (size_t) (p - buf)));

    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU_SEND_REQUEST_FLUSH);

cleanup:
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write EKU request"));
    return ret;
}

int mbedtls_ssl_tls13_write_extended_key_update_response(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write EKU response"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->handshake->tls13_eku_resp_len == 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_EXTENDED_KEY_UPDATE,
                             &buf, &buf_len));

    MBEDTLS_SSL_CHK_BUF_PTR(buf, buf + buf_len, ssl->handshake->tls13_eku_resp_len);
    memcpy(buf, ssl->handshake->tls13_eku_resp, ssl->handshake->tls13_eku_resp_len);

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, ssl->handshake->tls13_eku_resp_len));

    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU_SEND_RESPONSE_FLUSH);

cleanup:
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write EKU response"));
    return ret;
}

int mbedtls_ssl_tls13_write_extended_key_update_nku(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write EKU NKU"));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_EXTENDED_KEY_UPDATE,
                             &buf, &buf_len));

    MBEDTLS_SSL_CHK_BUF_PTR(buf, buf + buf_len, 1);
    buf[0] = MBEDTLS_SSL_TLS1_3_EKU_TYPE_NEW_KEY_UPDATE;

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, 1));

    mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU_SEND_NKU_FLUSH);

cleanup:
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write EKU NKU"));
    return ret;
}

int mbedtls_ssl_tls13_eku_send_flush(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> EKU send flush"));

    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    if (ssl->state == MBEDTLS_SSL_TLS1_3_EKU_SEND_RESPONSE_FLUSH ||
        ssl->state == MBEDTLS_SSL_TLS1_3_EKU_SEND_NKU_FLUSH) {
        if (ssl->handshake->tls13_eku_outgoing_updates_tx) {
            MBEDTLS_SSL_PROC_CHK(ssl_tls13_eku_update_direction(ssl,
                                                                MBEDTLS_SSL_TLS1_3_KEY_UPDATE_TX));
            ssl->handshake->tls13_eku_outgoing_updates_tx = 0;
        }
    }

    if (ssl->state == MBEDTLS_SSL_TLS1_3_EKU_SEND_NKU_FLUSH) {
        ssl->handshake->tls13_eku_state = MBEDTLS_SSL_TLS1_3_EKU_IDLE;
        ssl->handshake->tls13_eku_secrets_ready = 0;
        ssl->handshake->tls13_eku_req_len = 0;
        ssl->handshake->tls13_eku_resp_len = 0;
        ssl->handshake->tls13_eku_own_req_key_exchange_len = 0;
        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_HANDSHAKE_OVER);
    } else if (ssl->state == MBEDTLS_SSL_TLS1_3_EKU_SEND_RESPONSE_FLUSH) {
        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_HANDSHAKE_OVER);
    } else { /* request flush */
        mbedtls_ssl_handshake_set_state(ssl, MBEDTLS_SSL_TLS1_3_EKU);
    }

    ret = 0;

cleanup:
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= EKU send flush"));
    return ret;
}
#endif /* MBEDTLS_EXTENDED_KEY_UPDATE */
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */

int mbedtls_ssl_tls13_is_supported_versions_ext_present_in_exts(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, const unsigned char *end,
    const unsigned char **supported_versions_data,
    const unsigned char **supported_versions_data_end)
{
    const unsigned char *p = buf;
    size_t extensions_len;
    const unsigned char *extensions_end;

    *supported_versions_data = NULL;
    *supported_versions_data_end = NULL;

    /* Case of no extension */
    if (p == end) {
        return 0;
    }

    /* ...
     * Extension extensions<x..2^16-1>;
     * ...
     * struct {
     *      ExtensionType extension_type; (2 bytes)
     *      opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    extensions_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Check extensions do not go beyond the buffer of data. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, extensions_len);
    extensions_end = p + extensions_len;

    while (p < extensions_end) {
        unsigned int extension_type;
        size_t extension_data_len;

        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
        extension_type = MBEDTLS_GET_UINT16_BE(p, 0);
        extension_data_len = MBEDTLS_GET_UINT16_BE(p, 2);
        p += 4;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);

        if (extension_type == MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS) {
            *supported_versions_data = p;
            *supported_versions_data_end = p + extension_data_len;
            return 1;
        }
        p += extension_data_len;
    }

    return 0;
}

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 * STATE HANDLING: Read CertificateVerify
 */
/* Macro to express the maximum length of the verify structure.
 *
 * The structure is computed per TLS 1.3 specification as:
 *   - 64 bytes of octet 32,
 *   - 33 bytes for the context string
 *        (which is either "TLS 1.3, client CertificateVerify"
 *         or "TLS 1.3, server CertificateVerify"),
 *   - 1 byte for the octet 0x0, which serves as a separator,
 *   - 32 or 48 bytes for the Transcript-Hash(Handshake Context, Certificate)
 *     (depending on the size of the transcript_hash)
 *
 * This results in a total size of
 * - 130 bytes for a SHA256-based transcript hash, or
 *   (64 + 33 + 1 + 32 bytes)
 * - 146 bytes for a SHA384-based transcript hash.
 *   (64 + 33 + 1 + 48 bytes)
 *
 */
#define SSL_VERIFY_STRUCT_MAX_SIZE  (64 +                          \
                                     33 +                          \
                                     1 +                          \
                                     MBEDTLS_TLS1_3_MD_MAX_SIZE    \
                                     )

/*
 * The ssl_tls13_create_verify_structure() creates the verify structure.
 * As input, it requires the transcript hash.
 *
 * The caller has to ensure that the buffer has size at least
 * SSL_VERIFY_STRUCT_MAX_SIZE bytes.
 */
static void ssl_tls13_create_verify_structure(const unsigned char *transcript_hash,
                                              size_t transcript_hash_len,
                                              unsigned char *verify_buffer,
                                              size_t *verify_buffer_len,
                                              int from)
{
    size_t idx;

    /* RFC 8446, Section 4.4.3:
     *
     * The digital signature [in the CertificateVerify message] is then
     * computed over the concatenation of:
     * -  A string that consists of octet 32 (0x20) repeated 64 times
     * -  The context string
     * -  A single 0 byte which serves as the separator
     * -  The content to be signed
     */
    memset(verify_buffer, 0x20, 64);
    idx = 64;

    if (from == MBEDTLS_SSL_IS_CLIENT) {
        memcpy(verify_buffer + idx, mbedtls_ssl_tls13_labels.client_cv,
               MBEDTLS_SSL_TLS1_3_LBL_LEN(client_cv));
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN(client_cv);
    } else { /* from == MBEDTLS_SSL_IS_SERVER */
        memcpy(verify_buffer + idx, mbedtls_ssl_tls13_labels.server_cv,
               MBEDTLS_SSL_TLS1_3_LBL_LEN(server_cv));
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN(server_cv);
    }

    verify_buffer[idx++] = 0x0;

    memcpy(verify_buffer + idx, transcript_hash, transcript_hash_len);
    idx += transcript_hash_len;

    *verify_buffer_len = idx;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_certificate_verify(mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              const unsigned char *end,
                                              const unsigned char *verify_buffer,
                                              size_t verify_buffer_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t algorithm;
    size_t signature_len;
    mbedtls_pk_type_t sig_alg;
    mbedtls_md_type_t md_alg;
    psa_algorithm_t hash_alg = PSA_ALG_NONE;
    unsigned char verify_hash[PSA_HASH_MAX_SIZE];
    size_t verify_hash_len;

    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    algorithm = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* RFC 8446 section 4.4.3
     *
     * If the CertificateVerify message is sent by a server, the signature
     * algorithm MUST be one offered in the client's "signature_algorithms"
     * extension unless no valid certificate chain can be produced without
     * unsupported algorithms
     *
     * RFC 8446 section 4.4.2.2
     *
     * If the client cannot construct an acceptable chain using the provided
     * certificates and decides to abort the handshake, then it MUST abort the
     * handshake with an appropriate certificate-related alert
     * (by default, "unsupported_certificate").
     *
     * Check if algorithm is an offered signature algorithm.
     */
    if (!mbedtls_ssl_sig_alg_is_offered(ssl, algorithm)) {
        /* algorithm not in offered signature algorithms list */
        MBEDTLS_SSL_DEBUG_MSG(1, ("Received signature algorithm(%04x) is not "
                                  "offered.",
                                  (unsigned int) algorithm));
        goto error;
    }

    if (mbedtls_ssl_get_pk_type_and_md_alg_from_sig_alg(
            algorithm, &sig_alg, &md_alg) != 0) {
        goto error;
    }

    hash_alg = mbedtls_md_psa_alg_from_type(md_alg);
    if (hash_alg == 0) {
        goto error;
    }

    MBEDTLS_SSL_DEBUG_MSG(3, ("Certificate Verify: Signature algorithm ( %04x )",
                              (unsigned int) algorithm));

    /*
     * Check the certificate's key type matches the signature alg
     */
    if (!mbedtls_pk_can_do(&ssl->session_negotiate->peer_cert->pk, sig_alg)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("signature algorithm doesn't match cert key"));
        goto error;
    }

    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    signature_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, signature_len);

    status = psa_hash_compute(hash_alg,
                              verify_buffer,
                              verify_buffer_len,
                              verify_hash,
                              sizeof(verify_hash),
                              &verify_hash_len);
    if (status != PSA_SUCCESS) {
        MBEDTLS_SSL_DEBUG_RET(1, "hash computation PSA error", status);
        goto error;
    }

    MBEDTLS_SSL_DEBUG_BUF(3, "verify hash", verify_hash, verify_hash_len);

    if ((ret = mbedtls_pk_verify_ext(sig_alg, NULL,
                                     &ssl->session_negotiate->peer_cert->pk,
                                     md_alg, verify_hash, verify_hash_len,
                                     p, signature_len)) == 0) {
        return 0;
    }
    MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_pk_verify_ext", ret);

error:
    /* RFC 8446 section 4.4.3
     *
     * If the verification fails, the receiver MUST terminate the handshake
     * with a "decrypt_error" alert.
     */
    MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                 MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
    return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;

}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

int mbedtls_ssl_tls13_process_certificate_verify(mbedtls_ssl_context *ssl)
{

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
    size_t verify_buffer_len;
    unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));

    MBEDTLS_SSL_PROC_CHK(
        mbedtls_ssl_tls13_fetch_handshake_msg(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len));

    /* Need to calculate the hash of the transcript first
     * before reading the message since otherwise it gets
     * included in the transcript
     */
    ret = mbedtls_ssl_get_handshake_transcript(
        ssl,
        (mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac,
        transcript, sizeof(transcript),
        &transcript_len);
    if (ret != 0) {
        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
            MBEDTLS_ERR_SSL_INTERNAL_ERROR);
        return ret;
    }

    MBEDTLS_SSL_DEBUG_BUF(3, "handshake hash", transcript, transcript_len);

    /* Create verify structure */
    ssl_tls13_create_verify_structure(transcript,
                                      transcript_len,
                                      verify_buffer,
                                      &verify_buffer_len,
                                      (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) ?
                                      MBEDTLS_SSL_IS_SERVER :
                                      MBEDTLS_SSL_IS_CLIENT);

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_certificate_verify(
                             ssl, buf, buf + buf_len,
                             verify_buffer, verify_buffer_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                             buf, buf_len));

cleanup:

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate verify"));
    MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_tls13_process_certificate_verify", ret);
    return ret;
#else
    ((void) ssl);
    MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */
}

/*
 *
 * STATE HANDLING: Incoming Certificate.
 *
 */

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/*
 * Structure of Certificate message:
 *
 * enum {
 *     X509(0),
 *     RawPublicKey(2),
 *     (255)
 * } CertificateType;
 *
 * struct {
 *     select (certificate_type) {
 *         case RawPublicKey:
 *           * From RFC 7250 ASN.1_subjectPublicKeyInfo *
 *           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *         case X509:
 *           opaque cert_data<1..2^24-1>;
 *     };
 *     Extension extensions<0..2^16-1>;
 * } CertificateEntry;
 *
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     CertificateEntry certificate_list<0..2^24-1>;
 * } Certificate;
 *
 */

/* Parse certificate chain send by the server. */
MBEDTLS_CHECK_RETURN_CRITICAL
MBEDTLS_STATIC_TESTABLE
int mbedtls_ssl_tls13_parse_certificate(mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t certificate_request_context_len = 0;
    size_t certificate_list_len = 0;
    const unsigned char *p = buf;
    const unsigned char *certificate_list_end;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 4);
    certificate_request_context_len = p[0];
    certificate_list_len = MBEDTLS_GET_UINT24_BE(p, 1);
    p += 4;

    /* In theory, the certificate list can be up to 2^24 Bytes, but we don't
     * support anything beyond 2^16 = 64K.
     */
    if ((certificate_request_context_len != 0) ||
        (certificate_list_len >= 0x10000)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     MBEDTLS_ERR_SSL_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    /* In case we tried to reuse a session but it failed */
    if (ssl->session_negotiate->peer_cert != NULL) {
        mbedtls_x509_crt_free(ssl->session_negotiate->peer_cert);
        mbedtls_free(ssl->session_negotiate->peer_cert);
    }

    /* This is used by ssl_tls13_validate_certificate() */
    if (certificate_list_len == 0) {
        ssl->session_negotiate->peer_cert = NULL;
        ret = 0;
        goto exit;
    }

    if ((ssl->session_negotiate->peer_cert =
             mbedtls_calloc(1, sizeof(mbedtls_x509_crt))) == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc( %" MBEDTLS_PRINTF_SIZET " bytes ) failed",
                                  sizeof(mbedtls_x509_crt)));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                     MBEDTLS_ERR_SSL_ALLOC_FAILED);
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }

    mbedtls_x509_crt_init(ssl->session_negotiate->peer_cert);

    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, certificate_list_len);
    certificate_list_end = p + certificate_list_len;
    while (p < certificate_list_end) {
        size_t cert_data_len, extensions_len;
        const unsigned char *extensions_end;

        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, 3);
        cert_data_len = MBEDTLS_GET_UINT24_BE(p, 0);
        p += 3;

        /* In theory, the CRT can be up to 2^24 Bytes, but we don't support
         * anything beyond 2^16 = 64K. Otherwise as in the TLS 1.2 code,
         * check that we have a minimum of 128 bytes of data, this is not
         * clear why we need that though.
         */
        if ((cert_data_len < 128) || (cert_data_len >= 0x10000)) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad Certificate message"));
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                         MBEDTLS_ERR_SSL_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }

        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, cert_data_len);
        ret = mbedtls_x509_crt_parse_der(ssl->session_negotiate->peer_cert,
                                         p, cert_data_len);

        switch (ret) {
            case 0: /*ok*/
                break;
            case MBEDTLS_ERR_X509_UNKNOWN_OID:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case MBEDTLS_ERR_X509_ALLOC_FAILED:
                MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                             MBEDTLS_ERR_X509_ALLOC_FAILED);
                MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;

            case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                                             MBEDTLS_ERR_X509_UNKNOWN_VERSION);
                MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;

            default:
                MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_BAD_CERT,
                                             ret);
                MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;
        }

        p += cert_data_len;

        /* Certificate extensions length */
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, 2);
        extensions_len = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, certificate_list_end, extensions_len);

        extensions_end = p + extensions_len;
        handshake->received_extensions = MBEDTLS_SSL_EXT_MASK_NONE;

        while (p < extensions_end) {
            unsigned int extension_type;
            size_t extension_data_len;

            /*
             * struct {
             *     ExtensionType extension_type; (2 bytes)
             *     opaque extension_data<0..2^16-1>;
             * } Extension;
             */
            MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
            extension_type = MBEDTLS_GET_UINT16_BE(p, 0);
            extension_data_len = MBEDTLS_GET_UINT16_BE(p, 2);
            p += 4;

            MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);

            ret = mbedtls_ssl_tls13_check_received_extension(
                ssl, MBEDTLS_SSL_HS_CERTIFICATE, extension_type,
                MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CT);
            if (ret != 0) {
                return ret;
            }

            switch (extension_type) {
                default:
                    MBEDTLS_SSL_PRINT_EXT(
                        3, MBEDTLS_SSL_HS_CERTIFICATE,
                        extension_type, "( ignored )");
                    break;
            }

            p += extension_data_len;
        }

        MBEDTLS_SSL_PRINT_EXTS(3, MBEDTLS_SSL_HS_CERTIFICATE,
                               handshake->received_extensions);
    }

exit:
    /* Check that all the message is consumed. */
    if (p != end) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad Certificate message"));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     MBEDTLS_ERR_SSL_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    MBEDTLS_SSL_DEBUG_CRT(3, "peer certificate",
                          ssl->session_negotiate->peer_cert);

    return ret;
}
#else
MBEDTLS_CHECK_RETURN_CRITICAL
MBEDTLS_STATIC_TESTABLE
int mbedtls_ssl_tls13_parse_certificate(mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end)
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/* Validate certificate chain sent by the server. */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_validate_certificate(mbedtls_ssl_context *ssl)
{
    /* Authmode: precedence order is SNI if used else configuration */
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const int authmode = ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET
                       ? ssl->handshake->sni_authmode
                       : ssl->conf->authmode;
#else
    const int authmode = ssl->conf->authmode;
#endif

    /*
     * If the peer hasn't sent a certificate ( i.e. it sent
     * an empty certificate chain ), this is reflected in the peer CRT
     * structure being unset.
     * Check for that and handle it depending on the
     * authentication mode.
     */
    if (ssl->session_negotiate->peer_cert == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("peer has no certificate"));

#if defined(MBEDTLS_SSL_SRV_C)
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
            /* The client was asked for a certificate but didn't send
             * one. The client should know what's going on, so we
             * don't send an alert.
             */
            ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
            if (authmode == MBEDTLS_SSL_VERIFY_OPTIONAL) {
                return 0;
            } else {
                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_NO_CERT,
                    MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE);
                return MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
            }
        }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
        /* Regardless of authmode, the server is not allowed to send an empty
         * certificate chain. (Last paragraph before 4.4.2.1 in RFC 8446: "The
         * server's certificate_list MUST always be non-empty.") With authmode
         * optional/none, we continue the handshake if we can't validate the
         * server's cert, but we still break it if no certificate was sent. */
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_NO_CERT,
                                         MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE);
            return MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE;
        }
#endif /* MBEDTLS_SSL_CLI_C */
    }

    return mbedtls_ssl_verify_certificate(ssl, authmode,
                                          ssl->session_negotiate->peer_cert,
                                          NULL, NULL);
}
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_validate_certificate(mbedtls_ssl_context *ssl)
{
    ((void) ssl);
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

int mbedtls_ssl_tls13_process_certificate(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                             &buf, &buf_len));

    /* Parse the certificate chain sent by the peer. */
    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_parse_certificate(ssl, buf,
                                                             buf + buf_len));
    /* Validate the certificate chain and set the verification results. */
    MBEDTLS_SSL_PROC_CHK(ssl_tls13_validate_certificate(ssl));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE, buf, buf_len));

cleanup:
#else /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */
    (void) ssl;
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate"));
    return ret;
}
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 *  enum {
 *        X509(0),
 *        RawPublicKey(2),
 *        (255)
 *    } CertificateType;
 *
 *    struct {
 *        select (certificate_type) {
 *            case RawPublicKey:
 *              // From RFC 7250 ASN.1_subjectPublicKeyInfo
 *              opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *
 *            case X509:
 *              opaque cert_data<1..2^24-1>;
 *        };
 *        Extension extensions<0..2^16-1>;
 *    } CertificateEntry;
 *
 *    struct {
 *        opaque certificate_request_context<0..2^8-1>;
 *        CertificateEntry certificate_list<0..2^24-1>;
 *    } Certificate;
 */
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_certificate_body(mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *out_len)
{
    const mbedtls_x509_crt *crt = mbedtls_ssl_own_cert(ssl);
    unsigned char *p = buf;
    unsigned char *certificate_request_context =
        ssl->handshake->certificate_request_context;
    unsigned char certificate_request_context_len =
        ssl->handshake->certificate_request_context_len;
    unsigned char *p_certificate_list_len;


    /* ...
     * opaque certificate_request_context<0..2^8-1>;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_PTR(p, end, certificate_request_context_len + 1);
    *p++ = certificate_request_context_len;
    if (certificate_request_context_len > 0) {
        memcpy(p, certificate_request_context, certificate_request_context_len);
        p += certificate_request_context_len;
    }

    /* ...
     * CertificateEntry certificate_list<0..2^24-1>;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_PTR(p, end, 3);
    p_certificate_list_len = p;
    p += 3;

    MBEDTLS_SSL_DEBUG_CRT(3, "own certificate", crt);

    while (crt != NULL) {
        size_t cert_data_len = crt->raw.len;

        MBEDTLS_SSL_CHK_BUF_PTR(p, end, cert_data_len + 3 + 2);
        MBEDTLS_PUT_UINT24_BE(cert_data_len, p, 0);
        p += 3;

        memcpy(p, crt->raw.p, cert_data_len);
        p += cert_data_len;
        crt = crt->next;

        /* Currently, we don't have any certificate extensions defined.
         * Hence, we are sending an empty extension with length zero.
         */
        MBEDTLS_PUT_UINT16_BE(0, p, 0);
        p += 2;
    }

    MBEDTLS_PUT_UINT24_BE(p - p_certificate_list_len - 3,
                          p_certificate_list_len, 0);

    *out_len = p - buf;

    MBEDTLS_SSL_PRINT_EXTS(
        3, MBEDTLS_SSL_HS_CERTIFICATE, ssl->handshake->sent_extensions);

    return 0;
}

int mbedtls_ssl_tls13_write_certificate(mbedtls_ssl_context *ssl)
{
    int ret;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate"));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE, &buf, &buf_len));

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_certificate_body(ssl,
                                                          buf,
                                                          buf + buf_len,
                                                          &msg_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE, buf, msg_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, msg_len));
cleanup:

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate"));
    return ret;
}

/*
 * STATE HANDLING: Output Certificate Verify
 */
int mbedtls_ssl_tls13_check_sig_alg_cert_key_match(uint16_t sig_alg,
                                                   mbedtls_pk_context *key)
{
    mbedtls_pk_type_t pk_type = (mbedtls_pk_type_t) mbedtls_ssl_sig_from_pk(key);
    size_t key_size = mbedtls_pk_get_bitlen(key);

    switch (pk_type) {
        case MBEDTLS_SSL_SIG_ECDSA:
            switch (key_size) {
                case 256:
                    return
                        sig_alg == MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256;

                case 384:
                    return
                        sig_alg == MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384;

                case 521:
                    return
                        sig_alg == MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512;
                default:
                    break;
            }
            break;

        case MBEDTLS_SSL_SIG_RSA:
            switch (sig_alg) {
                case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256: /* Intentional fallthrough */
                case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384: /* Intentional fallthrough */
                case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512:
                    return 1;

                default:
                    break;
            }
            break;

        default:
            break;
    }

    return 0;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_certificate_verify_body(mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *out_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    mbedtls_pk_context *own_key;

    unsigned char handshake_hash[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t handshake_hash_len;
    unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
    size_t verify_buffer_len;

    uint16_t *sig_alg = ssl->handshake->received_sig_algs;
    size_t signature_len = 0;

    *out_len = 0;

    own_key = mbedtls_ssl_own_key(ssl);
    if (own_key == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    ret = mbedtls_ssl_get_handshake_transcript(
        ssl, (mbedtls_md_type_t) ssl->handshake->ciphersuite_info->mac,
        handshake_hash, sizeof(handshake_hash), &handshake_hash_len);
    if (ret != 0) {
        return ret;
    }

    MBEDTLS_SSL_DEBUG_BUF(3, "handshake hash",
                          handshake_hash,
                          handshake_hash_len);

    ssl_tls13_create_verify_structure(handshake_hash, handshake_hash_len,
                                      verify_buffer, &verify_buffer_len,
                                      ssl->conf->endpoint);

    /*
     *  struct {
     *    SignatureScheme algorithm;
     *    opaque signature<0..2^16-1>;
     *  } CertificateVerify;
     */
    /* Check there is space for the algorithm identifier (2 bytes) and the
     * signature length (2 bytes).
     */
    MBEDTLS_SSL_CHK_BUF_PTR(p, end, 4);

    for (; *sig_alg != MBEDTLS_TLS1_3_SIG_NONE; sig_alg++) {
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
        mbedtls_pk_type_t pk_type = MBEDTLS_PK_NONE;
        mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
        psa_algorithm_t psa_algorithm = PSA_ALG_NONE;
        unsigned char verify_hash[PSA_HASH_MAX_SIZE];
        size_t verify_hash_len;

        if (!mbedtls_ssl_sig_alg_is_offered(ssl, *sig_alg)) {
            continue;
        }

        if (!mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported(*sig_alg)) {
            continue;
        }

        if (!mbedtls_ssl_tls13_check_sig_alg_cert_key_match(*sig_alg, own_key)) {
            continue;
        }

        if (mbedtls_ssl_get_pk_type_and_md_alg_from_sig_alg(
                *sig_alg, &pk_type, &md_alg) != 0) {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }

        /* Hash verify buffer with indicated hash function */
        psa_algorithm = mbedtls_md_psa_alg_from_type(md_alg);
        status = psa_hash_compute(psa_algorithm,
                                  verify_buffer,
                                  verify_buffer_len,
                                  verify_hash, sizeof(verify_hash),
                                  &verify_hash_len);
        if (status != PSA_SUCCESS) {
            return PSA_TO_MBEDTLS_ERR(status);
        }

        MBEDTLS_SSL_DEBUG_BUF(3, "verify hash", verify_hash, verify_hash_len);

        if ((ret = mbedtls_pk_sign_ext(pk_type, own_key,
                                       md_alg, verify_hash, verify_hash_len,
                                       p + 4, (size_t) (end - (p + 4)), &signature_len)) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(2, ("CertificateVerify signature failed with %s",
                                      mbedtls_ssl_sig_alg_to_str(*sig_alg)));
            MBEDTLS_SSL_DEBUG_RET(2, "mbedtls_pk_sign_ext", ret);

            /* The signature failed. This is possible if the private key
             * was not suitable for the signature operation as purposely we
             * did not check its suitability completely. Let's try with
             * another signature algorithm.
             */
            continue;
        }

        MBEDTLS_SSL_DEBUG_MSG(2, ("CertificateVerify signature with %s",
                                  mbedtls_ssl_sig_alg_to_str(*sig_alg)));

        break;
    }

    if (*sig_alg == MBEDTLS_TLS1_3_SIG_NONE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("no suitable signature algorithm"));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                     MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    MBEDTLS_PUT_UINT16_BE(*sig_alg, p, 0);
    MBEDTLS_PUT_UINT16_BE(signature_len, p, 2);

    *out_len = 4 + signature_len;

    return 0;
}

int mbedtls_ssl_tls13_write_certificate_verify(mbedtls_ssl_context *ssl)
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate verify"));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                             &buf, &buf_len));

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_certificate_verify_body(
                             ssl, buf, buf + buf_len, &msg_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                             buf, msg_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, msg_len));

cleanup:

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate verify"));
    return ret;
}

#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

/*
 *
 * STATE HANDLING: Incoming Finished message.
 */
/*
 * Implementation
 */

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_preprocess_finished_message(mbedtls_ssl_context *ssl)
{
    int ret;

    ret = mbedtls_ssl_tls13_calculate_verify_data(
        ssl,
        ssl->handshake->state_local.finished_in.digest,
        sizeof(ssl->handshake->state_local.finished_in.digest),
        &ssl->handshake->state_local.finished_in.digest_len,
        ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ?
        MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_tls13_calculate_verify_data", ret);
        return ret;
    }

    return 0;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_parse_finished_message(mbedtls_ssl_context *ssl,
                                            const unsigned char *buf,
                                            const unsigned char *end)
{
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    const unsigned char *expected_verify_data =
        ssl->handshake->state_local.finished_in.digest;
    size_t expected_verify_data_len =
        ssl->handshake->state_local.finished_in.digest_len;
    /* Structural validation */
    if ((size_t) (end - buf) != expected_verify_data_len) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));

        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     MBEDTLS_ERR_SSL_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }

    MBEDTLS_SSL_DEBUG_BUF(4, "verify_data (self-computed):",
                          expected_verify_data,
                          expected_verify_data_len);
    MBEDTLS_SSL_DEBUG_BUF(4, "verify_data (received message):", buf,
                          expected_verify_data_len);

    /* Semantic validation */
    if (mbedtls_ct_memcmp(buf,
                          expected_verify_data,
                          expected_verify_data_len) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));

        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                     MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    return 0;
}

int mbedtls_ssl_tls13_process_finished_message(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse finished message"));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_tls13_fetch_handshake_msg(
                             ssl, MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len));

    /* Preprocessing step: Compute handshake digest */
    MBEDTLS_SSL_PROC_CHK(ssl_tls13_preprocess_finished_message(ssl));

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_parse_finished_message(
                             ssl, buf, buf + buf_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(
                             ssl, MBEDTLS_SSL_HS_FINISHED, buf, buf_len));

cleanup:

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse finished message"));
    return ret;
}

/*
 *
 * STATE HANDLING: Write and send Finished message.
 *
 */
/*
 * Implement
 */

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_prepare_finished_message(mbedtls_ssl_context *ssl)
{
    int ret;

    /* Compute transcript of handshake up to now. */
    ret = mbedtls_ssl_tls13_calculate_verify_data(ssl,
                                                  ssl->handshake->state_local.finished_out.digest,
                                                  sizeof(ssl->handshake->state_local.finished_out.
                                                         digest),
                                                  &ssl->handshake->state_local.finished_out.digest_len,
                                                  ssl->conf->endpoint);

    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "calculate_verify_data failed", ret);
        return ret;
    }

    return 0;
}

MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_finished_message_body(mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *out_len)
{
    size_t verify_data_len = ssl->handshake->state_local.finished_out.digest_len;
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    MBEDTLS_SSL_CHK_BUF_PTR(buf, end, verify_data_len);

    memcpy(buf, ssl->handshake->state_local.finished_out.digest,
           verify_data_len);

    *out_len = verify_data_len;
    return 0;
}

/* Main entry point: orchestrates the other functions */
int mbedtls_ssl_tls13_write_finished_message(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write finished message"));

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_prepare_finished_message(ssl));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_start_handshake_msg(ssl,
                                                         MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len));

    MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_finished_message_body(
                             ssl, buf, buf + buf_len, &msg_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_add_hs_msg_to_checksum(ssl,
                                                            MBEDTLS_SSL_HS_FINISHED, buf, msg_len));

    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_finish_handshake_msg(
                             ssl, buf_len, msg_len));
cleanup:

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write finished message"));
    return ret;
}

void mbedtls_ssl_tls13_handshake_wrapup(mbedtls_ssl_context *ssl)
{

    MBEDTLS_SSL_DEBUG_MSG(3, ("=> handshake wrapup"));

    MBEDTLS_SSL_DEBUG_MSG(1, ("Switch to application keys for inbound traffic"));
    mbedtls_ssl_set_inbound_transform(ssl, ssl->transform_application);

    MBEDTLS_SSL_DEBUG_MSG(1, ("Switch to application keys for outbound traffic"));
    mbedtls_ssl_set_outbound_transform(ssl, ssl->transform_application);

    /*
     * Free the previous session and switch to the current one.
     */
    if (ssl->session) {
        mbedtls_ssl_session_free(ssl->session);
        mbedtls_free(ssl->session);
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    MBEDTLS_SSL_DEBUG_MSG(3, ("<= handshake wrapup"));
}

/*
 *
 * STATE HANDLING: Write ChangeCipherSpec
 *
 */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_write_change_cipher_spec_body(mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *olen)
{
    ((void) ssl);

    MBEDTLS_SSL_CHK_BUF_PTR(buf, end, 1);
    buf[0] = 1;
    *olen = 1;

    return 0;
}

int mbedtls_ssl_tls13_write_change_cipher_spec(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write change cipher spec"));

    /* Only one CCS to send. */
    if (ssl->handshake->ccs_sent) {
        ret = 0;
        goto cleanup;
    }

    /* Write CCS message */
    MBEDTLS_SSL_PROC_CHK(ssl_tls13_write_change_cipher_spec_body(
                             ssl, ssl->out_msg,
                             ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN,
                             &ssl->out_msglen));

    ssl->out_msgtype = MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;

    /* Dispatch message */
    MBEDTLS_SSL_PROC_CHK(mbedtls_ssl_write_record(ssl, 0));

    ssl->handshake->ccs_sent = 1;

cleanup:

    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write change cipher spec"));
    return ret;
}

#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

/* Early Data Indication Extension
 *
 * struct {
 *   select ( Handshake.msg_type ) {
 *     case new_session_ticket:   uint32 max_early_data_size;
 *     case client_hello:         Empty;
 *     case encrypted_extensions: Empty;
 *   };
 * } EarlyDataIndication;
 */
#if defined(MBEDTLS_SSL_EARLY_DATA)
int mbedtls_ssl_tls13_write_early_data_ext(mbedtls_ssl_context *ssl,
                                           int in_new_session_ticket,
                                           unsigned char *buf,
                                           const unsigned char *end,
                                           size_t *out_len)
{
    unsigned char *p = buf;

#if defined(MBEDTLS_SSL_SRV_C)
    const size_t needed = in_new_session_ticket ? 8 : 4;
#else
    const size_t needed = 4;
    ((void) in_new_session_ticket);
#endif

    *out_len = 0;

    MBEDTLS_SSL_CHK_BUF_PTR(p, end, needed);

    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_EARLY_DATA, p, 0);
    MBEDTLS_PUT_UINT16_BE(needed - 4, p, 2);

#if defined(MBEDTLS_SSL_SRV_C)
    if (in_new_session_ticket) {
        MBEDTLS_PUT_UINT32_BE(ssl->conf->max_early_data_size, p, 4);
        MBEDTLS_SSL_DEBUG_MSG(
            4, ("Sent max_early_data_size=%u",
                (unsigned int) ssl->conf->max_early_data_size));
    }
#endif

    *out_len = needed;

    mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, MBEDTLS_TLS_EXT_EARLY_DATA);

    return 0;
}

#if defined(MBEDTLS_SSL_SRV_C)
int mbedtls_ssl_tls13_check_early_data_len(mbedtls_ssl_context *ssl,
                                           size_t early_data_len)
{
    /*
     * This function should be called only while an handshake is in progress
     * and thus a session under negotiation. Add a sanity check to detect a
     * misuse.
     */
    if (ssl->session_negotiate == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

    /* RFC 8446 section 4.6.1
     *
     * A server receiving more than max_early_data_size bytes of 0-RTT data
     * SHOULD terminate the connection with an "unexpected_message" alert.
     * Note that if it is still possible to send early_data_len bytes of early
     * data, it means that early_data_len is smaller than max_early_data_size
     * (type uint32_t) and can fit in an uint32_t. We use this further
     * down.
     */
    if (early_data_len >
        (ssl->session_negotiate->max_early_data_size -
         ssl->total_early_data_size)) {

        MBEDTLS_SSL_DEBUG_MSG(
            2, ("EarlyData: Too much early data received, "
                "%lu + %" MBEDTLS_PRINTF_SIZET " > %lu",
                (unsigned long) ssl->total_early_data_size,
                early_data_len,
                (unsigned long) ssl->session_negotiate->max_early_data_size));

        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
            MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }

    /*
     * early_data_len has been checked to be less than max_early_data_size
     * that is uint32_t. Its cast to an uint32_t below is thus safe. We need
     * the cast to appease some compilers.
     */
    ssl->total_early_data_size += (uint32_t) early_data_len;

    return 0;
}
#endif /* MBEDTLS_SSL_SRV_C */
#endif /* MBEDTLS_SSL_EARLY_DATA */

/* Reset SSL context and update hash for handling HRR.
 *
 * Replace Transcript-Hash(X) by
 * Transcript-Hash( message_hash     ||
 *                 00 00 Hash.length ||
 *                 X )
 * A few states of the handshake are preserved, including:
 *   - session ID
 *   - session ticket
 *   - negotiated ciphersuite
 */
int mbedtls_ssl_reset_transcript_for_hrr(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char hash_transcript[PSA_HASH_MAX_SIZE + 4];
    size_t hash_len;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    MBEDTLS_SSL_DEBUG_MSG(3, ("Reset SSL session for HRR"));

    ret = mbedtls_ssl_get_handshake_transcript(ssl, (mbedtls_md_type_t) ciphersuite_info->mac,
                                               hash_transcript + 4,
                                               PSA_HASH_MAX_SIZE,
                                               &hash_len);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_get_handshake_transcript", ret);
        return ret;
    }

    hash_transcript[0] = MBEDTLS_SSL_HS_MESSAGE_HASH;
    hash_transcript[1] = 0;
    hash_transcript[2] = 0;
    hash_transcript[3] = (unsigned char) hash_len;

    hash_len += 4;

    MBEDTLS_SSL_DEBUG_BUF(4, "Truncated handshake transcript",
                          hash_transcript, hash_len);

    /* Reset running hash and replace it with a hash of the transcript */
    ret = mbedtls_ssl_reset_checksum(ssl);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_reset_checksum", ret);
        return ret;
    }
    ret = ssl->handshake->update_checksum(ssl, hash_transcript, hash_len);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "update_checksum", ret);
        return ret;
    }

    return ret;
}

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED)

int mbedtls_ssl_tls13_read_public_xxdhe_share(mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len)
{
    uint8_t *p = (uint8_t *) buf;
    const uint8_t *end = buf + buf_len;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Get size of the TLS opaque key_exchange field of the KeyShareEntry struct. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    uint16_t peerkey_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;

    /* Check if key size is consistent with given buffer length. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, peerkey_len);

    /* Store peer's ECDH/FFDH public key. */
    if (peerkey_len > sizeof(handshake->xxdh_psa_peerkey)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid public key length: %u > %" MBEDTLS_PRINTF_SIZET,
                                  (unsigned) peerkey_len,
                                  sizeof(handshake->xxdh_psa_peerkey)));
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    memcpy(handshake->xxdh_psa_peerkey, p, peerkey_len);
    handshake->xxdh_psa_peerkey_len = peerkey_len;

    return 0;
}

#if defined(PSA_WANT_ALG_FFDH)
static psa_status_t  mbedtls_ssl_get_psa_ffdh_info_from_tls_id(
    uint16_t tls_id, size_t *bits, psa_key_type_t *key_type)
{
    switch (tls_id) {
#if defined(PSA_WANT_DH_RFC7919_2048)
        case MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048:
            *bits = 2048;
            *key_type = PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
            return PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_2048 */
#if defined(PSA_WANT_DH_RFC7919_3072)
        case MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072:
            *bits = 3072;
            *key_type =  PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
            return PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_3072 */
#if defined(PSA_WANT_DH_RFC7919_4096)
        case MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096:
            *bits = 4096;
            *key_type =  PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
            return PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_4096 */
#if defined(PSA_WANT_DH_RFC7919_6144)
        case MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144:
            *bits = 6144;
            *key_type =  PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
            return PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_6144 */
#if defined(PSA_WANT_DH_RFC7919_8192)
        case MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192:
            *bits = 8192;
            *key_type =  PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
            return PSA_SUCCESS;
#endif /* PSA_WANT_DH_RFC7919_8192 */
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif /* PSA_WANT_ALG_FFDH */

int mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
    mbedtls_ssl_context *ssl,
    uint16_t named_group,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    psa_key_attributes_t key_attributes;
    size_t own_pubkey_len;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    size_t bits = 0;
    psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
    psa_algorithm_t alg = PSA_ALG_NONE;
    size_t buf_size = (size_t) (end - buf);

    MBEDTLS_SSL_DEBUG_MSG(1, ("Perform PSA-based ECDH/FFDH computation."));

    /* Convert EC's TLS ID to PSA key type. */
#if defined(PSA_WANT_ALG_ECDH)
    if (mbedtls_ssl_get_psa_curve_info_from_tls_id(
            named_group, &key_type, &bits) == PSA_SUCCESS) {
        alg = PSA_ALG_ECDH;
    }
#endif
#if defined(PSA_WANT_ALG_FFDH)
    if (mbedtls_ssl_get_psa_ffdh_info_from_tls_id(named_group, &bits,
                                                  &key_type) == PSA_SUCCESS) {
        alg = PSA_ALG_FFDH;
    }
#endif

    if (key_type == PSA_KEY_TYPE_NONE) {
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

    if (buf_size < PSA_BITS_TO_BYTES(bits)) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }

    handshake->xxdh_psa_type = key_type;
    ssl->handshake->xxdh_psa_bits = bits;

    key_attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attributes, alg);
    psa_set_key_type(&key_attributes, handshake->xxdh_psa_type);
    psa_set_key_bits(&key_attributes, handshake->xxdh_psa_bits);

    /* Generate ECDH/FFDH private key. */
    status = psa_generate_key(&key_attributes,
                              &handshake->xxdh_psa_privkey);
    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_generate_key", ret);
        return ret;

    }

    /* Export the public part of the ECDH/FFDH private key from PSA. */
    status = psa_export_public_key(handshake->xxdh_psa_privkey,
                                   buf, buf_size,
                                   &own_pubkey_len);

    if (status != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_export_public_key", ret);
        return ret;
    }

    *out_len = own_pubkey_len;

    return 0;
}
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED */

/* RFC 8446 section 4.2
 *
 * If an implementation receives an extension which it recognizes and which is
 * not specified for the message in which it appears, it MUST abort the handshake
 * with an "illegal_parameter" alert.
 *
 */
int mbedtls_ssl_tls13_check_received_extension(
    mbedtls_ssl_context *ssl,
    int hs_msg_type,
    unsigned int received_extension_type,
    uint32_t hs_msg_allowed_extensions_mask)
{
    uint32_t extension_mask = mbedtls_ssl_get_extension_mask(
        received_extension_type);

    MBEDTLS_SSL_PRINT_EXT(
        3, hs_msg_type, received_extension_type, "received");

    if ((extension_mask & hs_msg_allowed_extensions_mask) == 0) {
        MBEDTLS_SSL_PRINT_EXT(
            3, hs_msg_type, received_extension_type, "is illegal");
        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ssl->handshake->received_extensions |= extension_mask;
    /*
     * If it is a message containing extension responses, check that we
     * previously sent the extension.
     */
    switch (hs_msg_type) {
        case MBEDTLS_SSL_HS_SERVER_HELLO:
        case MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST:
        case MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS:
        case MBEDTLS_SSL_HS_CERTIFICATE:
            /* Check if the received extension is sent by peer message.*/
            if ((ssl->handshake->sent_extensions & extension_mask) != 0) {
                return 0;
            }
            break;
        default:
            return 0;
    }

    MBEDTLS_SSL_PRINT_EXT(
        3, hs_msg_type, received_extension_type, "is unsupported");
    MBEDTLS_SSL_PEND_FATAL_ALERT(
        MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
        MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION);
    return MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION;
}

#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)

/* RFC 8449, section 4:
 *
 * The ExtensionData of the "record_size_limit" extension is
 * RecordSizeLimit:
 *     uint16 RecordSizeLimit;
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_parse_record_size_limit_ext(mbedtls_ssl_context *ssl,
                                                  const unsigned char *buf,
                                                  const unsigned char *end)
{
    const unsigned char *p = buf;
    uint16_t record_size_limit;
    const size_t extension_data_len = end - buf;

    if (extension_data_len !=
        MBEDTLS_SSL_RECORD_SIZE_LIMIT_EXTENSION_DATA_LENGTH) {
        MBEDTLS_SSL_DEBUG_MSG(2,
                              ("record_size_limit extension has invalid length: %"
                               MBEDTLS_PRINTF_SIZET " Bytes",
                               extension_data_len));

        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    record_size_limit = MBEDTLS_GET_UINT16_BE(p, 0);

    MBEDTLS_SSL_DEBUG_MSG(2, ("RecordSizeLimit: %u Bytes", record_size_limit));

    /* RFC 8449, section 4:
     *
     * Endpoints MUST NOT send a "record_size_limit" extension with a value
     * smaller than 64.  An endpoint MUST treat receipt of a smaller value
     * as a fatal error and generate an "illegal_parameter" alert.
     */
    if (record_size_limit < MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid record size limit : %u Bytes",
                                  record_size_limit));
        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
            MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ssl->session_negotiate->record_size_limit = record_size_limit;

    return 0;
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_record_size_limit_ext(mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  const unsigned char *end,
                                                  size_t *out_len)
{
    unsigned char *p = buf;
    *out_len = 0;

    MBEDTLS_STATIC_ASSERT(MBEDTLS_SSL_IN_CONTENT_LEN >= MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN,
                          "MBEDTLS_SSL_IN_CONTENT_LEN is less than the "
                          "minimum record size limit");

    MBEDTLS_SSL_CHK_BUF_PTR(p, end, 6);

    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT, p, 0);
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_SSL_RECORD_SIZE_LIMIT_EXTENSION_DATA_LENGTH,
                          p, 2);
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_SSL_IN_CONTENT_LEN, p, 4);

    *out_len = 6;

    MBEDTLS_SSL_DEBUG_MSG(2, ("Sent RecordSizeLimit: %d Bytes",
                              MBEDTLS_SSL_IN_CONTENT_LEN));

    mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT);

    return 0;
}

#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#endif /* MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_PROTO_TLS1_3 */
