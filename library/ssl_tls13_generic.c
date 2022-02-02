/*
 *  TLS 1.3 functionality shared between client and server
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "common.h"

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#include "mbedtls/ssl_ticket.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/ssl.h"
#include "mbedtls/hkdf.h"
#include <string.h>

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#if defined(MBEDTLS_SSL_USE_MPS)
#include "mps_all.h"
#endif /* MBEDTLS_SSL_USE_MPS */

#include "ecp_internal.h"

#if defined(MBEDTLS_SSL_USE_MPS)
int mbedtls_ssl_tls13_fetch_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps->l4 ) );

    if( ret != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps->l4,
                                                      &msg ) );

    if( msg.type != hs_type )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    ret = mbedtls_mps_reader_get( msg.handle,
                                  msg.length,
                                  buf,
                                  NULL );

    if( ret == MBEDTLS_ERR_MPS_READER_OUT_OF_DATA )
    {
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_pause( &ssl->mps->l4 ) );
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK( ret );

        /* *buf already set in mbedtls_mps_reader_get() */
        *buf_len = msg.length;
    }

cleanup:

    return( ret );
}

int mbedtls_ssl_mps_hs_consume_full_hs_msg( mbedtls_ssl_context *ssl )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps->l4,
                                                      &msg ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit( msg.handle ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps->l4 ) );

cleanup:

    return( ret );
}

int mbedtls_ssl_tls13_start_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mps_handshake_out * const msg = &ssl->handshake->hs_msg_out;

    msg->type   = hs_type;
    msg->length = MBEDTLS_MPS_SIZE_UNKNOWN;
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps->l4,
                                                       msg, NULL, NULL ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get( msg->handle,
                                              MBEDTLS_MPS_SIZE_MAX,
                                              buf, buf_len ) );

cleanup:
    return( ret );
}

int mbedtls_ssl_tls13_finish_handshake_msg( mbedtls_ssl_context *ssl,
                                            size_t buf_len,
                                            size_t msg_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mps_handshake_out * const msg = &ssl->handshake->hs_msg_out;

    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial( msg->handle,
                                                         buf_len - msg_len ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps->l4 ) );

cleanup:
    return( ret );
}

#else /* MBEDTLS_SSL_USE_MPS */
int mbedtls_ssl_tls13_fetch_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0]  != hs_type )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Receive unexpected handshake message." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
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

    return( ret );
}

int mbedtls_ssl_tls13_start_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
{
    /*
     * Reserve 4 bytes for hanshake header. ( Section 4,RFC 8446 )
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf = ssl->out_msg + 4;
    *buf_len = MBEDTLS_SSL_OUT_CONTENT_LEN - 4;

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = hs_type;

    return( 0 );
}

int mbedtls_ssl_tls13_finish_handshake_msg( mbedtls_ssl_context *ssl,
                                            size_t buf_len,
                                            size_t msg_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t msg_with_header_len;
    ((void) buf_len);

    /* Add reserved 4 bytes for handshake header */
    msg_with_header_len = msg_len + 4;
    ssl->out_msglen = msg_with_header_len;
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg_ext( ssl, 0 ) );

cleanup:
    return( ret );
}

#endif /* MBEDTLS_SSL_USE_MPS */

void mbedtls_ssl_tls13_add_hs_msg_to_checksum( mbedtls_ssl_context *ssl,
                                               unsigned hs_type,
                                               unsigned char const *msg,
                                               size_t msg_len )
{
    mbedtls_ssl_tls13_add_hs_hdr_to_checksum( ssl, hs_type, msg_len );
    ssl->handshake->update_checksum( ssl, msg, msg_len );
}

void mbedtls_ssl_tls13_add_hs_hdr_to_checksum( mbedtls_ssl_context *ssl,
                                               unsigned hs_type,
                                               size_t total_hs_len )
{
    unsigned char hs_hdr[4];

    /* Build HS header for checksum update. */
    hs_hdr[0] = MBEDTLS_BYTE_0( hs_type );
    hs_hdr[1] = MBEDTLS_BYTE_2( total_hs_len );
    hs_hdr[2] = MBEDTLS_BYTE_1( total_hs_len );
    hs_hdr[3] = MBEDTLS_BYTE_0( total_hs_len );

    ssl->handshake->update_checksum( ssl, hs_hdr, sizeof( hs_hdr ) );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/*
 * mbedtls_ssl_tls13_write_sig_alg_ext( )
 *
 * enum {
 *    ....
 *   ecdsa_secp256r1_sha256( 0x0403 ),
 *   ecdsa_secp384r1_sha384( 0x0503 ),
 *   ecdsa_secp521r1_sha512( 0x0603 ),
 *    ....
 * } SignatureScheme;
 *
 * struct {
 *    SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 *
 * Only if we handle at least one key exchange that needs signatures.
 */
int mbedtls_ssl_tls13_write_sig_alg_ext( mbedtls_ssl_context *ssl,
                                         unsigned char *buf,
                                         unsigned char *end,
                                         size_t *out_len )
{
    unsigned char *p = buf;
    unsigned char *supported_sig_alg; /* Start of supported_signature_algorithms */
    size_t supported_sig_alg_len = 0; /* Length of supported_signature_algorithms */

    *out_len = 0;

    /* Skip the extension on the client if all allowed key exchanges
     * are PSK-based. */
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
    {
        return( 0 );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding signature_algorithms extension" ) );

    /* Check if we have space for header and length field:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - supported_signature_algorithms_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    /*
     * Write supported_signature_algorithms
     */
    supported_sig_alg = p;
    for( const uint16_t *sig_alg = ssl->conf->tls13_sig_algs;
         *sig_alg != MBEDTLS_TLS1_3_SIG_NONE; sig_alg++ )
    {
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( *sig_alg, p, 0 );
        p += 2;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "signature scheme [%x]", *sig_alg ) );
    }

    /* Length of supported_signature_algorithms */
    supported_sig_alg_len = p - supported_sig_alg;
    if( supported_sig_alg_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No signature algorithms defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SIG_ALG, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( supported_sig_alg_len + 2, buf, 2 );
    /* Write length of supported_signature_algorithms */
    MBEDTLS_PUT_UINT16_BE( supported_sig_alg_len, buf, 4 );

    /* Output the total length of signature algorithms extension. */
    *out_len = p - buf;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIG_ALG;

    return( 0 );
}

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
#define SSL_VERIFY_STRUCT_MAX_SIZE  ( 64 +                          \
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
static void ssl_tls13_create_verify_structure( const unsigned char *transcript_hash,
                                               size_t transcript_hash_len,
                                               unsigned char *verify_buffer,
                                               size_t *verify_buffer_len,
                                               int from )
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
    memset( verify_buffer, 0x20, 64 );
    idx = 64;

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        memcpy( verify_buffer + idx, MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( client_cv ) );
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN( client_cv );
    }
    else
    { /* from == MBEDTLS_SSL_IS_SERVER */
        memcpy( verify_buffer + idx, MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( server_cv ) );
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN( server_cv );
    }

    verify_buffer[idx++] = 0x0;

    memcpy( verify_buffer + idx, transcript_hash, transcript_hash_len );
    idx += transcript_hash_len;

    *verify_buffer_len = idx;
}

static int ssl_tls13_sig_alg_is_offered( const mbedtls_ssl_context *ssl,
                                         uint16_t sig_alg )
{
    const uint16_t *tls13_sig_alg = ssl->conf->tls13_sig_algs;

    for( ; *tls13_sig_alg != MBEDTLS_TLS1_3_SIG_NONE ; tls13_sig_alg++ )
    {
        if( *tls13_sig_alg == sig_alg )
            return( 1 );
    }
    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/* Coordinate: Check whether a certificate verify message is expected.
 * Returns a negative value on failure, and otherwise
 * - SSL_CERTIFICATE_VERIFY_SKIP
 * - SSL_CERTIFICATE_VERIFY_READ
 * to indicate if the CertificateVerify message should be present or not.
 */
#define SSL_CERTIFICATE_VERIFY_SKIP 0
#define SSL_CERTIFICATE_VERIFY_READ 1
static int ssl_tls13_read_certificate_verify_coordinate( mbedtls_ssl_context *ssl )
{
    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
        return( SSL_CERTIFICATE_VERIFY_SKIP );

#if !defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
    if( ssl->session_negotiate->peer_cert == NULL )
        return( SSL_CERTIFICATE_VERIFY_SKIP );

    return( SSL_CERTIFICATE_VERIFY_READ );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/* Parse and validate CertificateVerify message
 *
 * Note: The size of the hash buffer is assumed to be large enough to
 *       hold the transcript given the selected hash algorithm.
 *       No bounds-checking is done inside the function.
 */
static int ssl_tls13_parse_certificate_verify( mbedtls_ssl_context *ssl,
                                               const unsigned char *buf,
                                               const unsigned char *end,
                                               const unsigned char *verify_buffer,
                                               size_t verify_buffer_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t algorithm;
    size_t signature_len;
    mbedtls_pk_type_t sig_alg;
    mbedtls_md_type_t md_alg;
    unsigned char verify_hash[MBEDTLS_MD_MAX_SIZE];
    size_t verify_hash_len;

    void const *options = NULL;
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_pk_rsassa_pss_options rsassa_pss_options;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    algorithm = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* RFC 8446 section 4.4.3
     *
     * If the CertificateVerify message is sent by a server, the signature algorithm
     * MUST be one offered in the client's "signature_algorithms" extension unless
     * no valid certificate chain can be produced without unsupported algorithms
     *
     * RFC 8446 section 4.4.2.2
     *
     * If the client cannot construct an acceptable chain using the provided
     * certificates and decides to abort the handshake, then it MUST abort the handshake
     * with an appropriate certificate-related alert (by default, "unsupported_certificate").
     *
     * Check if algorithm is an offered signature algorithm.
     */
    if( ! ssl_tls13_sig_alg_is_offered( ssl, algorithm ) )
    {
        /* algorithm not in offered signature algorithms list */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Received signature algorithm(%04x) is not "
                                    "offered.",
                                    ( unsigned int ) algorithm ) );
        goto error;
    }

    /* We currently only support ECDSA-based signatures */
    switch( algorithm )
    {
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256:
            md_alg = MBEDTLS_MD_SHA256;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384:
            md_alg = MBEDTLS_MD_SHA384;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512:
            md_alg = MBEDTLS_MD_SHA512;
            sig_alg = MBEDTLS_PK_ECDSA;
            break;
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256:
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Certificate Verify: using RSA PSS" ) );
            md_alg = MBEDTLS_MD_SHA256;
            sig_alg = MBEDTLS_PK_RSASSA_PSS;
            break;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */
        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Certificate Verify: Unknown signature algorithm." ) );
            goto error;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate Verify: Signature algorithm ( %04x )",
                                ( unsigned int ) algorithm ) );

    /*
     * Check the certificate's key type matches the signature alg
     */
    if( !mbedtls_pk_can_do( &ssl->session_negotiate->peer_cert->pk, sig_alg ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "signature algorithm doesn't match cert key" ) );
        goto error;
    }

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    signature_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, signature_len );

    /* Hash verify buffer with indicated hash function */
    switch( md_alg )
    {
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA256:
            verify_hash_len = 32;
            ret = mbedtls_sha256( verify_buffer, verify_buffer_len, verify_hash, 0 );
            break;
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA384_C)
        case MBEDTLS_MD_SHA384:
            verify_hash_len = 48;
            ret = mbedtls_sha512( verify_buffer, verify_buffer_len, verify_hash, 1 );
            break;
#endif /* MBEDTLS_SHA384_C */

#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA512:
            verify_hash_len = 64;
            ret = mbedtls_sha512( verify_buffer, verify_buffer_len, verify_hash, 0 );
            break;
#endif /* MBEDTLS_SHA512_C */

        default:
            ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            break;
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "hash computation error", ret );
        goto error;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if( sig_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        const mbedtls_md_info_t *md_info;
        rsassa_pss_options.mgf1_hash_id = md_alg;
        if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        {
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        rsassa_pss_options.expected_salt_len = mbedtls_md_get_size( md_info );
        options = (const void*) &rsassa_pss_options;
    }
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    if( ( ret = mbedtls_pk_verify_ext( sig_alg, options,
                                       &ssl->session_negotiate->peer_cert->pk,
                                       md_alg, verify_hash, verify_hash_len,
                                       p, signature_len ) ) == 0 )
    {
        return( 0 );
    }
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_verify_ext", ret );

error:
    /* RFC 8446 section 4.4.3
     *
     * If the verification fails, the receiver MUST terminate the handshake
     * with a "decrypt_error" alert.
    */
    MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                  MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );

}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

int mbedtls_ssl_tls13_process_certificate_verify( mbedtls_ssl_context *ssl )
{

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
    size_t verify_buffer_len;
    unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate verify" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_read_certificate_verify_coordinate( ssl ) );
    if( ret == SSL_CERTIFICATE_VERIFY_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate verify" ) );
        ret = 0;
        goto cleanup;
    }
    else if( ret != SSL_CERTIFICATE_VERIFY_READ )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto cleanup;
    }

    MBEDTLS_SSL_PROC_CHK(
        mbedtls_ssl_tls13_fetch_handshake_msg( ssl,
                MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len ) );

    ret = mbedtls_ssl_get_handshake_transcript( ssl,
                            ssl->handshake->ciphersuite_info->mac,
                            transcript, sizeof( transcript ),
                            &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
            MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        goto cleanup;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash", transcript, transcript_len );

    /* Create verify structure */
    ssl_tls13_create_verify_structure( transcript,
                                       transcript_len,
                                       verify_buffer,
                                       &verify_buffer_len,
                                       ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) ?
                                         MBEDTLS_SSL_IS_SERVER :
                                         MBEDTLS_SSL_IS_CLIENT );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_certificate_verify( ssl, buf,
                            buf + buf_len, verify_buffer, verify_buffer_len ) );

    mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl,
                        MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, buf, buf_len );
#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate verify" ) );
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_process_certificate_verify", ret );
    return( ret );
#else
    ((void) ssl);
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}

/*
 *
 * STATE HANDLING: Incoming Certificate
 *
 */

/* Coordination: Check if a certificate is expected.
 * Returns a negative error code on failure, and otherwise
 * SSL_CERTIFICATE_EXPECTED or
 * SSL_CERTIFICATE_SKIP
 * indicating whether a Certificate message is expected or not.
 */
#define SSL_CERTIFICATE_EXPECTED   0
#define SSL_CERTIFICATE_SKIP       1

static int ssl_tls13_read_certificate_coordinate( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    int authmode = ssl->conf->authmode;
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to handshake keys for inbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        {
            int ret;
            ret = mbedtls_mps_set_incoming_keys( &ssl->mps->l4,
                                                 ssl->handshake->epoch_handshake );
            if( ret != 0 )
                return( ret );
        }
#else
        mbedtls_ssl_set_inbound_transform( ssl, ssl->handshake->transform_handshake );
#endif /* MBEDTLS_SSL_USE_MPS */
    }
#endif /* MBEDTLS_SSL_SRV_C */

    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
        return( SSL_CERTIFICATE_SKIP );

#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    ( ( void )authmode );
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        /* If SNI was used, overwrite authentication mode
         * from the configuration. */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
            authmode = ssl->handshake->sni_authmode;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

        if( authmode == MBEDTLS_SSL_VERIFY_NONE )
        {
            /* NOTE: Is it intentional that we set verify_result
             * to SKIP_VERIFY on server-side only? */
            ssl->session_negotiate->verify_result =
                MBEDTLS_X509_BADCERT_SKIP_VERIFY;
            return( SSL_CERTIFICATE_SKIP );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    return( SSL_CERTIFICATE_EXPECTED );
#endif /* !MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
}

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
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

/* Parse certificate chain send by the peer. */
static int ssl_tls13_parse_certificate( mbedtls_ssl_context *ssl,
                                        unsigned char const *buf,
                                        unsigned char const *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t certificate_request_context_len = 0;
    size_t certificate_list_len = 0;
    const unsigned char *p = buf;
    const unsigned char *certificate_list_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    certificate_request_context_len = p[0];
    p++;

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end,
                                      certificate_request_context_len + 3 );

        /* check whether we got an empty certificate message */
        if( memcmp( p + certificate_request_context_len , "\0\0\0", 3 ) == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1,
                ( "client has no certificate - empty certificate message received" ) );

            ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
            if( ssl->conf->authmode == MBEDTLS_SSL_VERIFY_OPTIONAL )
                return( 0 );
            else
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "client certificate required" ) );
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_REQUIRED,
                                              MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
                return( MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
            }
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 3 );
    certificate_list_len = MBEDTLS_GET_UINT24_BE( p, 0 );
    p += 3;

    /* In theory, the certificate list can be up to 2^24 Bytes, but we don't
     * support anything beyond 2^16 = 64K.
     */
    if( ( ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) &&
          ( certificate_request_context_len != 0 ) )
        ||
        ( certificate_list_len >= 0x10000 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* In case we tried to reuse a session but it failed */
    if( ssl->session_negotiate->peer_cert != NULL )
    {
        mbedtls_x509_crt_free( ssl->session_negotiate->peer_cert );
        mbedtls_free( ssl->session_negotiate->peer_cert );
    }

    if( ( ssl->session_negotiate->peer_cert =
              mbedtls_calloc( 1, sizeof( mbedtls_x509_crt ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc( %" MBEDTLS_PRINTF_SIZET " bytes ) failed",
                                    sizeof( mbedtls_x509_crt ) ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                      MBEDTLS_ERR_SSL_ALLOC_FAILED );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    mbedtls_x509_crt_init( ssl->session_negotiate->peer_cert );

    certificate_list_end = p + certificate_list_len;
    while( p < certificate_list_end )
    {
        size_t cert_data_len, extensions_len;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, 3 );
        cert_data_len = MBEDTLS_GET_UINT24_BE( p, 0 );
        p += 3;

        /* In theory, the CRT can be up to 2^24 Bytes, but we don't support
         * anything beyond 2^16 = 64K. Otherwise as in the TLS 1.2 code,
         * check that we have a minimum of 128 bytes of data, this is not
         * clear why we need that though.
         */
        if( ( cert_data_len < 128 ) || ( cert_data_len >= 0x10000 ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad Certificate message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, cert_data_len );
        ret = mbedtls_x509_crt_parse_der( ssl->session_negotiate->peer_cert,
                                          p, cert_data_len );

        switch( ret )
        {
            case 0: /*ok*/
            case MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case MBEDTLS_ERR_X509_ALLOC_FAILED:
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                              MBEDTLS_ERR_X509_ALLOC_FAILED );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );

            case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                                              MBEDTLS_ERR_X509_UNKNOWN_VERSION );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );

            default:
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_BAD_CERT,
                                              ret );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );
        }

        p += cert_data_len;

        /* Certificate extensions length */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, 2 );
        extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, extensions_len );
        p += extensions_len;
    }

    /* Check that all the message is consumed. */
    if( p != end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad Certificate message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR, \
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_CRT( 3, "peer certificate", ssl->session_negotiate->peer_cert );

    return( ret );
}
#else
static int ssl_tls13_parse_certificate( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/* Validate certificate chain sent by the server. */
static int ssl_tls13_validate_certificate( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    int authmode = ssl->conf->authmode;
    mbedtls_x509_crt *ca_chain;
    mbedtls_x509_crl *ca_crl;
    uint32_t verify_result = 0;

    /* If SNI was used, overwrite authentication mode
     * from the configuration. */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
        authmode = ssl->handshake->sni_authmode;
#endif

    /*
     * If the client hasn't sent a certificate ( i.e. it sent
     * an empty certificate chain ), this is reflected in the peer CRT
     * structure being unset.
     * Check for that and handle it depending on the
     * server's authentication mode.
     */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
        ssl->session_negotiate->peer_cert == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "client has no certificate" ) );

        /* The client was asked for a certificate but didn't send
           one. The client should know what's going on, so we
           don't send an alert. */

        /* Note that for authmode == VERIFY_NONE we don't end up in this
         * routine in the first place, because ssl_tls13_read_certificate_coordinate
         * will return CERTIFICATE_SKIP. */
        ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
        if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL )
            return( 0 );
        else
            return( MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE );
    }
#endif /* MBEDTLS_SSL_SRV_C */


    if( authmode == MBEDTLS_SSL_VERIFY_NONE )
    {
        /* NOTE: This happens on client-side only, with the
         * server-side case of VERIFY_NONE being handled earlier
         * and leading to `ssl->verify_result` being set to
         * MBEDTLS_X509_BADCERT_SKIP_VERIFY --
         * is this difference intentional? */
        return( 0 );
    }

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_ca_chain != NULL )
    {
        ca_chain = ssl->handshake->sni_ca_chain;
        ca_crl = ssl->handshake->sni_ca_crl;
    }
    else
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
    {
        ca_chain = ssl->conf->ca_chain;
        ca_crl = ssl->conf->ca_crl;
    }

    /*
     * Main check: verify certificate
     */
    ret = mbedtls_x509_crt_verify_with_profile(
        ssl->session_negotiate->peer_cert,
        ca_chain, ca_crl,
        ssl->conf->cert_profile,
        ssl->hostname,
        &verify_result,
        ssl->conf->f_vrfy, ssl->conf->p_vrfy );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "x509_verify_cert", ret );
    }

    /*
     * Secondary checks: always done, but change 'ret' only if it was 0
     */

#if defined(MBEDTLS_ECP_C)
    {
        const mbedtls_pk_context *pk = &ssl->session_negotiate->peer_cert->pk;

        /* If certificate uses an EC key, make sure the curve is OK */
        if( mbedtls_pk_can_do( pk, MBEDTLS_PK_ECKEY ) &&
            mbedtls_ssl_check_curve( ssl, mbedtls_pk_ec( *pk )->grp.id ) != 0 )
        {
            ssl->session_negotiate->verify_result |= MBEDTLS_X509_BADCERT_BAD_KEY;

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate ( EC key curve )" ) );
            if( ret == 0 )
                ret = MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
        }
    }
#endif /* MBEDTLS_ECP_C */

    if( mbedtls_ssl_check_cert_usage( ssl->session_negotiate->peer_cert,
                                      ssl->handshake->key_exchange,
                                      !ssl->conf->endpoint,
                                      &verify_result ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate ( usage extensions )" ) );
        if( ret == 0 )
            ret = MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
    }

    /* mbedtls_x509_crt_verify_with_profile is supposed to report a
     * verification failure through MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
     * with details encoded in the verification flags. All other kinds
     * of error codes, including those from the user provided f_vrfy
     * functions, are treated as fatal and lead to a failure of
     * ssl_tls13_parse_certificate even if verification was optional. */
    if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL &&
        ( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
          ret == MBEDTLS_ERR_SSL_BAD_CERTIFICATE ) )
    {
        ret = 0;
    }

    if( ca_chain == NULL && authmode == MBEDTLS_SSL_VERIFY_REQUIRED )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
        ret = MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED;
    }

    if( ret != 0 )
    {
        /* The certificate may have been rejected for several reasons.
           Pick one and send the corresponding alert. Which alert to send
           may be a subject of debate in some cases. */
        if( verify_result & MBEDTLS_X509_BADCERT_OTHER )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_BAD_CERT, ret );
        else if( verify_result & ( MBEDTLS_X509_BADCERT_KEY_USAGE |
                                   MBEDTLS_X509_BADCERT_EXT_KEY_USAGE |
                                   MBEDTLS_X509_BADCERT_NS_CERT_TYPE |
                                   MBEDTLS_X509_BADCERT_BAD_PK |
                                   MBEDTLS_X509_BADCERT_BAD_KEY ) )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_EXPIRED )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_REVOKED )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA, ret );
        else
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN, ret );
    }

#if defined(MBEDTLS_DEBUG_C)
    if( verify_result != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "! Certificate verification flags %x",
                                    ssl->session_negotiate->verify_result ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate verification flags clear" ) );
    }
#endif /* MBEDTLS_DEBUG_C */

    ssl->session_negotiate->verify_result = verify_result;
    return( ret );
}
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
static int ssl_tls13_validate_certificate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

int mbedtls_ssl_tls13_process_certificate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    /* Coordination:
     * Check if we expect a certificate, and if yes,
     * check if a non-empty certificate has been sent. */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_read_certificate_coordinate( ssl ) );
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    if( ret == SSL_CERTIFICATE_EXPECTED )
    {
        unsigned char *buf;
        size_t buf_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                              ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                              &buf, &buf_len ) );

        /* Parse the certificate chain sent by the peer. */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_certificate( ssl, buf,
                                                           buf + buf_len ) );
        /* Validate the certificate chain and set the verification results. */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_validate_certificate( ssl ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                                                  buf, buf_len );
#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
    if( ret == SSL_CERTIFICATE_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ret = 0;
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );
    return( ret );
}

/*
 *
 * STATE HANDLING: Incoming Finished message.
 */
/*
 * Implementation
 */

static int ssl_tls13_preprocess_finished_message( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_calculate_verify_data( ssl,
                    ssl->handshake->state_local.finished_in.digest,
                    sizeof( ssl->handshake->state_local.finished_in.digest ),
                    &ssl->handshake->state_local.finished_in.digest_len,
                    ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ?
                        MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_calculate_verify_data", ret );
        return( ret );
    }

    return( 0 );
}

static int ssl_tls13_parse_finished_message( mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             const unsigned char *end )
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
    if( (size_t)( end - buf ) != expected_verify_data_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "verify_data (self-computed):",
                           expected_verify_data,
                           expected_verify_data_len );
    MBEDTLS_SSL_DEBUG_BUF( 4, "verify_data (received message):", buf,
                           expected_verify_data_len );

    /* Semantic validation */
    if( mbedtls_ct_memcmp( buf,
                           expected_verify_data,
                           expected_verify_data_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( 0 );
}

#if defined(MBEDTLS_SSL_CLI_C)
static int ssl_tls13_postprocess_server_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_key_set traffic_keys;
    mbedtls_ssl_transform *transform_application = NULL;

    ret = mbedtls_ssl_tls13_key_schedule_stage_application( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
           "mbedtls_ssl_tls13_key_schedule_stage_application", ret );
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_generate_application_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
            "mbedtls_ssl_tls13_generate_application_keys", ret );
        goto cleanup;
    }

    transform_application =
        mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_application == NULL )
    {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_populate_transform(
                                    transform_application,
                                    ssl->conf->endpoint,
                                    ssl->session_negotiate->ciphersuite,
                                    &traffic_keys,
                                    ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        goto cleanup;
    }

#if !defined(MBEDTLS_SSL_USE_MPS)
    ssl->transform_application = transform_application;
#else /* MBEDTLS_SSL_USE_MPS */
    ret = mbedtls_mps_add_key_material( &ssl->mps->l4,
                                        transform_application,
                                        &ssl->epoch_application );
    if( ret != 0 )
        goto cleanup;
#endif /* MBEDTLS_SSL_USE_MPS */

cleanup:

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );
    if( ret != 0 )
    {
        mbedtls_free( transform_application );
        MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( ret );
}
#endif /* MBEDTLS_SSL_CLI_C */

static int ssl_tls13_postprocess_finished_message( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    int ret;
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        /* Compute resumption_master_secret */
        ret = mbedtls_ssl_tls13_generate_resumption_master_secret( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
               "mbedtls_ssl_tls13_generate_resumption_master_secret ", ret );
            return( ret );
        }

        return( 0 );
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        return( ssl_tls13_postprocess_server_finished_message( ssl ) );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

int mbedtls_ssl_tls13_process_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse finished message" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg( ssl,
                                              MBEDTLS_SSL_HS_FINISHED,
                                              &buf, &buf_len ) );
    /* Preprocessing step: Compute handshake digest */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_preprocess_finished_message( ssl ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_finished_message( ssl, buf, buf + buf_len ) );
    mbedtls_ssl_tls13_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_FINISHED, buf, buf_len );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_finished_message( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse finished message" ) );
    return( ret );
}

/*
 *
 * STATE HANDLING: Write and send Finished message.
 *
 */
/*
 * Implement
 */

static int ssl_tls13_prepare_finished_message( mbedtls_ssl_context *ssl )
{
    int ret;

    /* Compute transcript of handshake up to now. */
    ret = mbedtls_ssl_tls13_calculate_verify_data( ssl,
                    ssl->handshake->state_local.finished_out.digest,
                    sizeof( ssl->handshake->state_local.finished_out.digest ),
                    &ssl->handshake->state_local.finished_out.digest_len,
                    ssl->conf->endpoint );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "calculate_verify_data failed", ret );
        return( ret );
    }

    return( 0 );
}

static int ssl_tls13_finalize_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = 0;

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        /* Compute resumption_master_secret */
        ret = mbedtls_ssl_tls13_generate_resumption_master_secret( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                    "mbedtls_ssl_tls13_generate_resumption_master_secret ", ret );
            return ( ret );
        }

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_FLUSH_BUFFERS );
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        mbedtls_ssl_key_set traffic_keys;
        mbedtls_ssl_transform *transform_application;

        ret = mbedtls_ssl_tls13_key_schedule_stage_application( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
               "mbedtls_ssl_tls13_key_schedule_stage_application", ret );
            return( ret );
        }

        ret = mbedtls_ssl_tls13_generate_application_keys(
                     ssl, &traffic_keys );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                  "mbedtls_ssl_tls13_generate_application_keys", ret );
            return( ret );
        }

        transform_application =
            mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
        if( transform_application == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        ret = mbedtls_ssl_tls13_populate_transform(
            transform_application, ssl->conf->endpoint,
            ssl->session_negotiate->ciphersuite,
            &traffic_keys, ssl );
        if( ret != 0 )
            return( ret );

#if !defined(MBEDTLS_SSL_USE_MPS)
        ssl->transform_application = transform_application;
#else /* MBEDTLS_SSL_USE_MPS */
        /* Register transform with MPS. */
        ret = mbedtls_mps_add_key_material( &ssl->mps->l4,
                                            transform_application,
                                            &ssl->epoch_application );
        if( ret != 0 )
            return( ret );
#endif /* MBEDTLS_SSL_USE_MPS */

        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );
    }
    else
#endif /* MBEDTLS_SSL_SRV_C */
    {
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( 0 );
}

static int ssl_tls13_write_finished_message_body( mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  unsigned char *end,
                                                  size_t *out_len )
{
    size_t verify_data_len = ssl->handshake->state_local.finished_out.digest_len;
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, verify_data_len );

    memcpy( buf, ssl->handshake->state_local.finished_out.digest,
            verify_data_len );

    *out_len = verify_data_len;
    return( 0 );
}

/* Main entry point: orchestrates the other functions */
int mbedtls_ssl_tls13_write_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write finished message" ) );

    if( !ssl->handshake->state_local.finished_out.preparation_done )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_finished_message( ssl ) );
        ssl->handshake->state_local.finished_out.preparation_done = 1;
    }

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg( ssl,
                              MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_finished_message_body(
                              ssl, buf, buf + buf_len, &msg_len ) );

    mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_FINISHED,
                                              buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_finished_message( ssl ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg( ssl,
                                              buf_len, msg_len ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write finished message" ) );
    return( ret );
}

void mbedtls_ssl_tls13_handshake_wrapup( mbedtls_ssl_context *ssl )
{

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup" ) );

    /*
     * Free the previous session and switch to the current one.
     */
    if( ssl->session )
    {
        mbedtls_ssl_session_free( ssl->session );
        mbedtls_free( ssl->session );
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup" ) );
}

/*
 *
 * STATE HANDLING: Write ChangeCipherSpec
 *
 */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)

#define SSL_WRITE_CCS_NEEDED     0
#define SSL_WRITE_CCS_SKIP       1
static int ssl_tls13_write_change_cipher_spec_coordinate( mbedtls_ssl_context *ssl )
{
    int ret = SSL_WRITE_CCS_NEEDED;

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( ssl->state == MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO )
        {
            /* Only transmit the CCS if we have not done so
             * earlier already after the HRR.
             */
            if( ssl->handshake->hello_retry_requests_sent == 0 )
                ret = SSL_WRITE_CCS_NEEDED;
            else
                ret = SSL_WRITE_CCS_SKIP;
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
#if defined(MBEDTLS_ZERO_RTT)
        switch( ssl->state )
        {
            case MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO:
                if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
                    ret = SSL_WRITE_CCS_SKIP;
                break;

            case MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO:
            case MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED:
                if( ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON )
                    ret = SSL_WRITE_CCS_SKIP;
                break;

            default:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
#else /* MBEDTLS_ZERO_RTT */
        if( ssl->state == MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO )
            ret = SSL_WRITE_CCS_SKIP;
#endif /* MBEDTLS_ZERO_RTT */
    }
#endif /* MBEDTLS_SSL_CLI_C */
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_tls13_write_change_cipher_spec_body( mbedtls_ssl_context *ssl,
                                                    unsigned char *buf,
                                                    unsigned char *end,
                                                    size_t *olen )
{
    ((void) ssl);

    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, 1 );
    buf[0] = 1;
    *olen = 1;

    return( 0 );
}
#endif /* !MBEDTLS_SSL_USE_MPS */

static int ssl_tls13_write_change_cipher_spec_postprocess( mbedtls_ssl_context *ssl )
{

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        switch( ssl->state )
        {
            case MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
                ssl->handshake->ccs_sent++;
                break;

            case MBEDTLS_SSL_SERVER_CCS_AFTER_HRR:
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_CLIENT_HELLO );
                ssl->handshake->ccs_sent++;
                break;

            default:
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
#else
    (void)ssl;
#endif /* MBEDTLS_SSL_SRV_C */

    return( 0 );
}

int mbedtls_ssl_tls13_write_change_cipher_spec_process( mbedtls_ssl_context *ssl )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write change cipher spec" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_change_cipher_spec_coordinate( ssl ) );

    if( ret == SSL_WRITE_CCS_NEEDED )
    {
#if defined(MBEDTLS_SSL_USE_MPS)

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps->l4 ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_ccs( &ssl->mps->l4 ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps->l4 ) );
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_change_cipher_spec_postprocess( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */
        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* Write CCS message */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_change_cipher_spec_body(
                                  ssl, ssl->out_msg,
                                  ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN,
                                  &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_change_cipher_spec_postprocess( ssl ) );

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) );

#endif /* MBEDTLS_SSL_USE_MPS */
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write change cipher spec" ) );
        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_change_cipher_spec_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write change cipher spec" ) );
    return( ret );
}
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

int mbedtls_ssl_tls13_parse_signature_algorithms_ext( mbedtls_ssl_context *ssl,
                                                      const unsigned char *buf,
                                                      size_t buf_len )
{
    size_t sig_alg_list_size; /* size of receive signature algorithms list */
    const unsigned char *p; /* pointer to individual signature algorithm */
    const unsigned char *end = buf + buf_len; /* end of buffer */
    const uint16_t *sig_alg; /* iterate through configured signature schemes */
    int signature_scheme; /* store received signature algorithm scheme */
    uint32_t common_idx = 0; /* iterate through received_signature_schemes_list */

    if( buf_len < 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad signature_algorithms extension" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    sig_alg_list_size = MBEDTLS_GET_UINT16_BE( buf, 0 );
    if( sig_alg_list_size + 2 != buf_len ||
        sig_alg_list_size % 2 != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad signature_algorithms extension" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }
    memset( ssl->handshake->received_signature_schemes_list,
        0, sizeof( ssl->handshake->received_signature_schemes_list ) );

    for( p = buf + 2; p < end && common_idx + 1 < MBEDTLS_SIGNATURE_SCHEMES_SIZE; p += 2 )
    {
        signature_scheme = MBEDTLS_GET_UINT16_BE( p, 0 );

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "received signature algorithm: 0x%x", signature_scheme ) );

        for( sig_alg = ssl->conf->tls13_sig_algs;
             *sig_alg != MBEDTLS_TLS1_3_SIG_NONE; sig_alg++ )
        {
            if( *sig_alg == signature_scheme )
            {
                ssl->handshake->received_signature_schemes_list[common_idx] = signature_scheme;
                common_idx++;
                break;
            }
        }
    }

    if( common_idx == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "no signature algorithm in common" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    ssl->handshake->received_signature_schemes_list[common_idx] =
        MBEDTLS_TLS1_3_SIG_NONE;

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 *
 * STATE HANDLING: Write CertificateVerify
 *
 */

/*
 * Overview
 */

/* Main entry point: orchestrates the other functions. */
int mbedtls_ssl_tls13_write_certificate_verify_process( mbedtls_ssl_context *ssl );

/* Coordinate: Check whether a certificate verify message should be sent.
 * Returns a negative value on failure, and otherwise
 * - SSL_WRITE_CERTIFICATE_VERIFY_SKIP
 * - SSL_WRITE_CERTIFICATE_VERIFY_SEND
 * to indicate if the CertificateVerify message should be sent or not.
 */
#define SSL_WRITE_CERTIFICATE_VERIFY_SKIP 0
#define SSL_WRITE_CERTIFICATE_VERIFY_SEND 1
static int ssl_tls13_write_certificate_verify_coordinate( mbedtls_ssl_context *ssl );
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_tls13_certificate_verify_write( mbedtls_ssl_context *ssl,
                                               unsigned char *buf,
                                               size_t buf_len,
                                               size_t *out_len );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
static int ssl_tls13_certificate_verify_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

int mbedtls_ssl_tls13_write_certificate_verify_process( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate verify" ) );

    /* Coordination step: Check if we need to send a CertificateVerify */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_certificate_verify_coordinate( ssl ) );

    if( ret == SSL_WRITE_CERTIFICATE_VERIFY_SEND )
    {
        unsigned char *buf;
        size_t buf_len, msg_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg( ssl,
                   MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_certificate_verify_write(
                                  ssl, buf, buf_len, &msg_len ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, buf, msg_len );
        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_certificate_verify_postprocess( ssl ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg(
                                  ssl, buf_len, msg_len ) );
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_certificate_verify_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate verify" ) );
    return( ret );
}

static int ssl_tls13_write_certificate_verify_coordinate( mbedtls_ssl_context *ssl )
{
    int have_own_cert = 1;
    int ret;

    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
        return( SSL_WRITE_CERTIFICATE_VERIFY_SKIP );
    }

#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
    if( mbedtls_ssl_own_cert( ssl ) == NULL )
        have_own_cert = 0;

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        if( ssl->client_auth == 0 ||
            have_own_cert == 0 ||
            ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
            return( SSL_WRITE_CERTIFICATE_VERIFY_SKIP );
        }
    }

    if( have_own_cert == 0 &&
        ssl->client_auth == 1 &&
        ssl->conf->authmode != MBEDTLS_SSL_VERIFY_NONE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no certificate" ) );
        return( MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    /*
     * Check whether the signature scheme corresponds to the key we are using
     */
    if( mbedtls_ssl_sig_from_pk( mbedtls_ssl_own_key( ssl ) ) !=
        MBEDTLS_SSL_SIG_ECDSA )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Certificate Verify: Only ECDSA signature algorithm is currently supported." ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    /* Calculate the transcript hash */
    ret = mbedtls_ssl_get_handshake_transcript( ssl,
      ssl->handshake->ciphersuite_info->mac,
      ssl->handshake->state_local.certificate_verify_out.handshake_hash,
      sizeof( ssl->handshake->state_local.certificate_verify_out.handshake_hash ),
      &ssl->handshake->state_local.certificate_verify_out.handshake_hash_len );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash",
        ssl->handshake->state_local.certificate_verify_out.handshake_hash,
        ssl->handshake->state_local.certificate_verify_out.handshake_hash_len);

    return( SSL_WRITE_CERTIFICATE_VERIFY_SEND );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
}


#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_tls13_certificate_verify_write( mbedtls_ssl_context *ssl,
                                               unsigned char *buf,
                                               size_t buf_len,
                                               size_t *out_len )
{
    int ret;
    size_t n = 0;
    unsigned char verify_buffer[ MBEDTLS_SSL_VERIFY_STRUCT_MAX_SIZE ];
    const int *sig_scheme; /* iterate through configured signature schemes */
    size_t verify_buffer_len;
    mbedtls_pk_context *own_key;
    size_t own_key_size;
    unsigned int md_alg;
    int sig_alg;
    unsigned char verify_hash[ MBEDTLS_MD_MAX_SIZE ];
    size_t verify_hash_len;
    unsigned char *p;
    const mbedtls_md_info_t *md_info;
    /* Verify whether we can use signature algorithm */
    int signature_scheme_client;
    unsigned char * const end = buf + buf_len;

    p = buf;
    if( buf_len < 2 + MBEDTLS_MD_MAX_SIZE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too short" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Create verify structure */
    ssl_tls13_create_verify_structure(
            ssl->handshake->state_local.certificate_verify_out.handshake_hash,
            ssl->handshake->state_local.certificate_verify_out.handshake_hash_len,
            verify_buffer,
            &verify_buffer_len,
            ssl->conf->endpoint );

    /*
     *  struct {
     *    SignatureScheme algorithm;
     *    opaque signature<0..2^16-1>;
     *  } CertificateVerify;
     */

    /* Determine size of key */
    own_key = mbedtls_ssl_own_key( ssl );
    if( own_key != NULL)
    {
        own_key_size = mbedtls_pk_get_bitlen( own_key );
        switch( own_key_size)
        {
            case 256:
                md_alg  = MBEDTLS_MD_SHA256;
                sig_alg = MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256;
                break;
            case 384:
                md_alg  = MBEDTLS_MD_SHA384;
                sig_alg = MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384;
                break;
            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown key size: %" MBEDTLS_PRINTF_SIZET " bits",
                               own_key_size ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    signature_scheme_client = MBEDTLS_TLS1_3_SIG_NONE;

    for( sig_scheme = ssl->handshake->received_signature_schemes_list;
        *sig_scheme != MBEDTLS_TLS1_3_SIG_NONE; sig_scheme++ )
    {
        if( *sig_scheme == sig_alg )
        {
            signature_scheme_client = *sig_scheme;
            break;
        }
    }

    if( signature_scheme_client == MBEDTLS_TLS1_3_SIG_NONE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_PUT_UINT16_BE( signature_scheme_client, p, 0 );
    p += 2;

    /* Hash verify buffer with indicated hash function */
    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ret = mbedtls_md( md_info, verify_buffer, verify_buffer_len, verify_hash );
    if( ret != 0 )
        return( ret );

    verify_hash_len = mbedtls_md_get_size( md_info );
    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );

    if( ( ret = mbedtls_pk_sign( own_key, md_alg,
                                 verify_hash, verify_hash_len,
                                 p + 2, (size_t)( end - ( p + 2 ) ), &n,
                                 ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_sign", ret );
        return( ret );
    }

    MBEDTLS_PUT_UINT16_BE( n, p, 0 );
    p += 2 + n;

    *out_len = (size_t)( p - buf );
    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

static int ssl_tls13_certificate_verify_postprocess( mbedtls_ssl_context *ssl )
{
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );
    }
    else
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    }

    return( 0 );
}

/*
 *
 * STATE HANDLING: Outgoing Certificate
 *
 */

/*
 * Overview
 */

/* Main state-handling entry point; orchestrates the other functions. */
int mbedtls_ssl_tls13_write_certificate_process( mbedtls_ssl_context *ssl );

/* Check if a certificate should be written, and if yes,
 * if it is available.
 * Returns a negative error code on failure ( such as no certificate
 * being available on the server ), and otherwise
 * SSL_WRITE_CERTIFICATE_AVAILABLE or
 * SSL_WRITE_CERTIFICATE_SKIP
 * indicating that a Certificate message should be written based
 * on the configured certificate, or whether it should be silently skipped.
 */

#define SSL_WRITE_CERTIFICATE_AVAILABLE  0
#define SSL_WRITE_CERTIFICATE_SKIP       1
static int ssl_tls13_write_certificate_coordinate( mbedtls_ssl_context *ssl );
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/* Write certificate message based on the configured certificate */
static int ssl_tls13_write_certificate_write( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              size_t buf_len,
                                              size_t *out_len );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
/* Update the state after handling the outgoing certificate message. */
static int ssl_tls13_write_certificate_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

int mbedtls_ssl_tls13_write_certificate_process( mbedtls_ssl_context *ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    /* Coordination: Check if we need to send a certificate. */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_certificate_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( ret == SSL_WRITE_CERTIFICATE_AVAILABLE )
    {
        unsigned char *buf;
        size_t buf_len, msg_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg( ssl,
                   MBEDTLS_SSL_HS_CERTIFICATE, &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_certificate_write(
                                  ssl, buf, buf_len, &msg_len ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE, buf, msg_len );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_certificate_postprocess( ssl ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg(
                                  ssl, buf_len, msg_len ) );
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_certificate_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );
    return( ret );
}


static int ssl_tls13_write_certificate_coordinate( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_SRV_C)
    int have_own_cert = 1;
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
                  ( "Switch to handshake traffic keys for outbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        {
            int ret;

            /* Use new transform for outgoing data. */
            ret = mbedtls_mps_set_outgoing_keys( &ssl->mps->l4,
                                                 ssl->handshake->epoch_handshake );
            if( ret != 0 )
                return( ret );
        }
#else
        mbedtls_ssl_set_outbound_transform( ssl, ssl->handshake->transform_handshake );
#endif /* MBEDTLS_SSL_USE_MPS */
    }
#endif /* MBEDTLS_SSL_CLI_C */

    /* For PSK and ECDHE-PSK ciphersuites there is no certificate to exchange. */
    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        return( SSL_WRITE_CERTIFICATE_SKIP );
    }

#if !defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        /* The client MUST send a Certificate message if and only
         * if the server has requested client authentication via a
         * CertificateRequest message.
         *
         * client_auth indicates whether the server had requested
         * client authentication.
         */
        if( ssl->client_auth == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
            return( SSL_WRITE_CERTIFICATE_SKIP );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( have_own_cert == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no certificate to send" ) );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    return( SSL_WRITE_CERTIFICATE_AVAILABLE );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}



#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
static int ssl_tls13_write_certificate_write( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              size_t buf_len,
                                              size_t *out_len )
{
    size_t i=0, n, total_len;
    const mbedtls_x509_crt *crt;
    unsigned char *start;

    /* TODO: Add bounds checks! Only then remove the next line. */
    ((void) buf_len );

    /* empty certificate_request_context with length 0 */
    buf[i] = 0;
    /* Skip length of certificate_request_context and
     * the length of CertificateEntry
     */
    i += 1;

#if defined(MBEDTLS_SSL_CLI_C)
    /* If the server requests client authentication but no suitable
     * certificate is available, the client MUST send a
     * Certificate message containing no certificates
     * ( i.e., with the "certificate_list" field having length 0 ).
     *
     * authmode indicates whether the client configuration required authentication.
     */
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT && ( ( mbedtls_ssl_own_cert( ssl ) == NULL ) || ssl->conf->authmode == MBEDTLS_SSL_VERIFY_NONE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write empty client certificate" ) );
        buf[i] = 0;
        buf[i + 1] = 0;
        buf[i + 2] = 0;
        i += 3;

        goto empty_cert;
    }
#endif /* MBEDTLS_SSL_CLI_C */

    start = &buf[i];
    crt = mbedtls_ssl_own_cert( ssl );
    MBEDTLS_SSL_DEBUG_CRT( 3, "own certificate", mbedtls_ssl_own_cert( ssl ) );

    i += 3;

    while ( crt != NULL )
    {
        n = crt->raw.len;
        if( n > buf_len - 3 - i )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "certificate too large, %" MBEDTLS_PRINTF_SIZET " > %d",
                                        i + 3 + n, MBEDTLS_SSL_OUT_CONTENT_LEN ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        MBEDTLS_PUT_UINT24_BE( n, buf, i );
        i += 3; memcpy( buf + i, crt->raw.p, n );
        i += n; crt = crt->next;

        /* Currently, we don't have any certificate extensions defined.
         * Hence, we are sending an empty extension with length zero.
         */
        buf[i] = 0;
        buf[i + 1] = 0;
        i += 2;
    }
    total_len = &buf[i] - start - 3;
    MBEDTLS_PUT_UINT24_BE( total_len, start, 0 );

#if defined(MBEDTLS_SSL_CLI_C)
empty_cert:
#endif /* MBEDTLS_SSL_CLI_C */

    *out_len = i;

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/* Update the state after handling the outgoing certificate message. */
static int ssl_tls13_write_certificate_postprocess( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY );
        return( 0 );
    }
    else
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
        {
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );
            return( 0 );
        }
#endif /* MBEDTLS_SSL_SRV_C */

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

#if defined(MBEDTLS_ZERO_RTT)
void mbedtls_ssl_conf_early_data(
    mbedtls_ssl_config *conf,
    int early_data, size_t max_early_data,
    int(*early_data_callback)( mbedtls_ssl_context*,
                               const unsigned char*,
                               size_t ) )
{
#if !defined(MBEDTLS_SSL_SRV_C)
    ( ( void ) max_early_data );
    ( ( void ) early_data_callback );
#endif /* !MBEDTLS_SSL_SRV_C */
    conf->early_data_enabled = early_data;

#if defined(MBEDTLS_SSL_SRV_C)

    if( early_data == MBEDTLS_SSL_EARLY_DATA_ENABLED )
    {
        if( max_early_data > MBEDTLS_SSL_MAX_EARLY_DATA )
            max_early_data = MBEDTLS_SSL_MAX_EARLY_DATA;

        conf->max_early_data = max_early_data;
        conf->early_data_callback = early_data_callback;
        /* Only the server uses the early data callback.
         * For the client this parameter is not used. */
    }
    else
    {
        conf->early_data_callback = NULL;
    }
#endif
}
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
void mbedtls_ssl_conf_signature_algorithms( mbedtls_ssl_config *conf,
                    const uint16_t *sig_algs )
{
    /* TODO: Add available algorithm check */
    conf->tls13_sig_algs = sig_algs;
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/* Early Data Extension
 *
 * struct {} Empty;
 *
 * struct {
 *   select ( Handshake.msg_type ) {
 *     case new_session_ticket:   uint32 max_early_data_size;
 *     case client_hello:         Empty;
 *     case encrypted_extensions: Empty;
 *   };
 * } EarlyDataIndication;
 */
#if defined(MBEDTLS_ZERO_RTT)
int mbedtls_ssl_tls13_write_early_data_ext( mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            const unsigned char *end,
                                            size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        if( !mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) ||
            mbedtls_ssl_get_psk_to_offer( ssl, NULL, NULL, NULL, NULL ) != 0 ||
            ssl->conf->early_data_enabled == MBEDTLS_SSL_EARLY_DATA_DISABLED )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write early_data extension" ) );
            ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_OFF;
            return( 0 );
        }
    }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_EARLY_DATA ) == 0 )
            return( 0 );

        if( ssl->conf->tls13_kex_modes !=
                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK ||
            ssl->conf->early_data_enabled == MBEDTLS_SSL_EARLY_DATA_DISABLED )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write early_data extension" ) );
            ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_OFF;
            return( 0 );
        }
    }
#endif /* MBEDTLS_SSL_SRV_C */

    if( ( end - buf ) < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding early_data extension" ) );
        /* We're using rejected once we send the EarlyData extension,
           and change it to accepted upon receipt of the server extension. */
        ssl->early_data_status = MBEDTLS_SSL_EARLY_DATA_REJECTED;
    }
#endif /* MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding early_data extension" ) );
    }
#endif /* MBEDTLS_SSL_SRV_C */

    ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_ON;

    /* Write extension header */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_EARLY_DATA, p, 0 );

    /* Write total extension length */
    MBEDTLS_PUT_UINT16_BE( 0, p, 2 );

    *out_len = 4;
    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT */


#if defined(MBEDTLS_ECDH_C)
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;
#endif

#define ECDH_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )

static int ecdh_make_tls13_params_internal( mbedtls_ecdh_context_mbed *ctx,
                                      size_t *out_len, int point_format,
                                      unsigned char *buf, size_t blen,
                                      int (*f_rng)(void *,
                                                   unsigned char *,
                                                   size_t),
                                      void *p_rng,
                                      int restart_enabled )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if( ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( restart_enabled )
        rs_ctx = &ctx->rs;
#else
    (void) restart_enabled;
#endif


#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( ( ret = ecdh_gen_public_restartable( &ctx->grp, &ctx->d, &ctx->Q,
                                             f_rng, p_rng, rs_ctx ) ) != 0 )
        return( ret );
#else
    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
                                         f_rng, p_rng ) ) != 0 )
        return( ret );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    ret = mbedtls_ecp_point_write_binary( &ctx->grp, &ctx->Q, point_format,
                                          out_len, buf, blen );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ecdh_make_tls13_params( mbedtls_ecdh_context *ctx, size_t *out_len,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( out_len != NULL );
    ECDH_VALIDATE_RET( buf != NULL );
    ECDH_VALIDATE_RET( f_rng != NULL );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_make_tls13_params_internal( ctx, out_len, ctx->point_format, buf, blen,
                                       f_rng, p_rng, restart_enabled ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_make_params( &ctx->ctx.everest_ecdh, out_len,
                                                 buf, blen, f_rng, p_rng ) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_make_tls13_params_internal( &ctx->ctx.mbed_ecdh, out_len,
                                               ctx->point_format, buf, blen,
                                               f_rng, p_rng,
                                               restart_enabled ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_import_public_raw( mbedtls_ecdh_context_mbed *ctx,
                                   const unsigned char *buf,
                                   const unsigned char *end )
{
    return( mbedtls_ecp_point_read_binary( &ctx->grp, &ctx->Qp,
                                           buf, end - buf ) );
}

#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
static int everest_import_public_raw( mbedtls_x25519_context *ctx,
                        const unsigned char *buf, const unsigned char *end )
{
    if( end - buf != MBEDTLS_X25519_KEY_SIZE_BYTES )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    memcpy( ctx->peer_point, buf, MBEDTLS_X25519_KEY_SIZE_BYTES );
    return( 0 );
}
#endif /* MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED */

int mbedtls_ecdh_import_public_raw( mbedtls_ecdh_context *ctx,
                                    const unsigned char *buf,
                                    const unsigned char *end )
{
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( buf != NULL );
    ECDH_VALIDATE_RET( end != NULL );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_read_tls13_params_internal( ctx, buf, end ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( everest_import_public_raw( &ctx->ctx.everest_ecdh,
                                               buf, end) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_import_public_raw( &ctx->ctx.mbed_ecdh,
                                            buf, end ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_make_tls13_public_internal( mbedtls_ecdh_context_mbed *ctx,
                                      size_t *out_len, int point_format,
                                      unsigned char *buf, size_t blen,
                                      int (*f_rng)(void *,
                                                   unsigned char *,
                                                   size_t),
                                      void *p_rng,
                                      int restart_enabled )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if( ctx->grp.pbits == 0 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( restart_enabled )
        rs_ctx = &ctx->rs;
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if( ( ret = ecdh_gen_public_restartable( &ctx->grp, &ctx->d, &ctx->Q,
                                             f_rng, p_rng, rs_ctx ) ) != 0 )
        return( ret );
#else
    if( ( ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
                                         f_rng, p_rng ) ) != 0 )
        return( ret );
#endif /* MBEDTLS_ECP_RESTARTABLE */

    return mbedtls_ecp_tls13_write_point( &ctx->grp, &ctx->Q, point_format, out_len,
                                        buf, blen );
}

/*
 * Setup and export the client public value
 */
int mbedtls_ecdh_make_tls13_public( mbedtls_ecdh_context *ctx, size_t *out_len,
                              unsigned char *buf, size_t blen,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int restart_enabled = 0;
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( out_len != NULL );
    ECDH_VALIDATE_RET( buf != NULL );
    ECDH_VALIDATE_RET( f_rng != NULL );

#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_make_tls13_public_internal( ctx, out_len, ctx->point_format, buf, blen,
                                       f_rng, p_rng, restart_enabled ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_make_public( &ctx->ctx.everest_ecdh, out_len,
                                                 buf, blen, f_rng, p_rng ) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_make_tls13_public_internal( &ctx->ctx.mbed_ecdh, out_len,
                                               ctx->point_format, buf, blen,
                                               f_rng, p_rng,
                                               restart_enabled ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int ecdh_read_tls13_public_internal( mbedtls_ecdh_context_mbed *ctx,
                                      const unsigned char *buf, size_t blen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;

    if( ( ret = mbedtls_ecp_tls13_read_point( &ctx->grp, &ctx->Qp, &p,
                                            blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Parse and import the client's TLS 1.3 public value
 */
int mbedtls_ecdh_read_tls13_public( mbedtls_ecdh_context *ctx,
                              const unsigned char *buf, size_t blen )
{
    ECDH_VALIDATE_RET( ctx != NULL );
    ECDH_VALIDATE_RET( buf != NULL );

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return( ecdh_read_tls13_public_internal( ctx, buf, blen ) );
#else
    switch( ctx->var )
    {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return( mbedtls_everest_read_public( &ctx->ctx.everest_ecdh,
                                                 buf, blen ) );
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return( ecdh_read_tls13_public_internal( &ctx->ctx.mbed_ecdh,
                                                       buf, blen ) );
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_ECP_C)
#define ECP_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_ECP_BAD_INPUT_DATA )

int mbedtls_ecp_tls13_read_point( const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *pt,
                                  const unsigned char **buf, size_t buf_len )
{
    unsigned char data_len;
    const unsigned char *buf_start;
    ECP_VALIDATE_RET( grp != NULL );
    ECP_VALIDATE_RET( pt  != NULL );
    ECP_VALIDATE_RET( buf != NULL );
    ECP_VALIDATE_RET( *buf != NULL );

    if( buf_len < 3 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    data_len = MBEDTLS_GET_UINT16_BE( *buf, 0 );
    *buf += 2;

    if( data_len < 1 || data_len > buf_len - 2 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Save buffer start for read_binary and update buf
     */
    buf_start = *buf;
    *buf += data_len;

    return( mbedtls_ecp_point_read_binary( grp, pt, buf_start, data_len ) );
}

int mbedtls_ecp_tls13_write_point( const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                                   int format, size_t *out_len,
                                   unsigned char *buf, size_t blen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( pt   != NULL );
    ECP_VALIDATE_RET( out_len != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( format == MBEDTLS_ECP_PF_UNCOMPRESSED ||
                      format == MBEDTLS_ECP_PF_COMPRESSED );

    if( blen < 2 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = mbedtls_ecp_point_write_binary( grp, pt, format,
                    out_len, buf + 2, blen - 2) ) != 0 )
        return( ret );

    // Length
    MBEDTLS_PUT_UINT16_BE( *out_len, buf, 0 );
    *out_len += 2;

    return( 0 );
}

/*
 * Write the ECParameters record corresponding to a group (TLS 1.3)
 */
int mbedtls_ecp_tls13_write_group( const mbedtls_ecp_group *grp, size_t *out_len,
                         unsigned char *buf, size_t blen )
{
    const mbedtls_ecp_curve_info *curve_info;
    ECP_VALIDATE_RET( grp  != NULL );
    ECP_VALIDATE_RET( buf  != NULL );
    ECP_VALIDATE_RET( out_len != NULL );

    if( ( curve_info = mbedtls_ecp_curve_info_from_grp_id( grp->id ) ) == NULL )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    *out_len = 2;
    if( blen < *out_len )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    // Two bytes for named curve
    MBEDTLS_PUT_UINT16_BE( curve_info->tls_id, buf, 0 );

    return( 0 );
}

#endif /* MBEDTLS_ECP_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_SSL_TLS_C */
