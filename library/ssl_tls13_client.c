/*
 *  TLS 1.3 client-side functions
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
 *
 *  This file is part of mbed TLS ( https://tls.mbed.org )
 */

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#include "mbedtls/hkdf.h"

#if defined(MBEDTLS_SSL_CLI_C)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#include "ecdh_misc.h"
#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers_generated.h"

#if defined(MBEDTLS_SSL_USE_MPS)
#include "mps_all.h"
#endif /* MBEDTLS_SSL_USE_MPS */

#include "ecp_internal.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <stdint.h>

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif

#define CLIENT_HELLO_RANDOM_LEN 32

/* Write extensions */

/*
 * ssl_tls13_write_supported_versions_ext():
 *
 * struct {
 *      ProtocolVersion versions<2..254>;
 * } SupportedVersions;
 */
static int ssl_tls13_write_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported versions extension" ) );

    /* Check if we have space to write the extension:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - versions_length        (1 byte )
     * - versions               (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 7 );

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS, p, 0 );

    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( 3, p, 2 );
    p += 4;

    /* Length of versions */
    *p++ = 0x2;

    /* Write values of supported versions.
     *
     * They are defined by the configuration.
     *
     * Currently, only one version is advertised.
     */
    mbedtls_ssl_write_version( ssl->conf->max_major_ver,
                               ssl->conf->max_minor_ver,
                               ssl->conf->transport, p );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "supported version: [%d:%d]",
                                ssl->conf->max_major_ver,
                                ssl->conf->max_minor_ver ) );

    *out_len = 7;

    return( 0 );
}

static int ssl_tls13_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    ((void) ssl);

    MBEDTLS_SSL_CHK_BUF_READ_PTR( buf, end, 2);
    if( buf[0] != MBEDTLS_SSL_MAJOR_VERSION_3 ||
        buf[1] != MBEDTLS_SSL_MINOR_VERSION_4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected version" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
    /* For ticket handling, we need to populate the version
     * and the endpoint information into the session structure
     * since only session information is available in that API.
     */
    ssl->session_negotiate->minor_ver = ssl->minor_ver;
    ssl->session_negotiate->endpoint = ssl->conf->endpoint;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

    return( 0 );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/*
 * Functions for writing supported_groups extension.
 *
 * Stucture of supported_groups:
 *      enum {
 *          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
 *          x25519(0x001D), x448(0x001E),
 *          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
 *          ffdhe6144(0x0103), ffdhe8192(0x0104),
 *          ffdhe_private_use(0x01FC..0x01FF),
 *          ecdhe_private_use(0xFE00..0xFEFF),
 *          (0xFFFF)
 *      } NamedGroup;
 *      struct {
 *          NamedGroup named_group_list<2..2^16-1>;
 *      } NamedGroupList;
 */
#if defined(MBEDTLS_ECDH_C)
/*
 * In versions of TLS prior to TLS 1.3, this extension was named
 * 'elliptic_curves' and only contained elliptic curve groups.
 */
static int ssl_tls13_write_named_group_list_ecdhe( mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    const uint16_t *group_list = mbedtls_ssl_get_groups( ssl );

    if( group_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for ( ; *group_list != 0; group_list++ )
    {
        const mbedtls_ecp_curve_info *curve_info;
        curve_info = mbedtls_ecp_curve_info_from_tls_id( *group_list );
        if( curve_info == NULL )
            continue;

        if( !mbedtls_ssl_tls13_named_group_is_ecdhe( *group_list ) )
            continue;

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2);
        MBEDTLS_PUT_UINT16_BE( *group_list, p, 0 );
        p += 2;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "NamedGroup: %s ( %x )",
                                    curve_info->name, *group_list ) );
    }

    *out_len = p - buf;

    return( 0 );
}
#else
static int ssl_tls13_write_named_group_list_ecdhe( mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *out_len )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *out_len = 0;
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_ECDH_C */

static int ssl_tls13_write_named_group_list_dhe( mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        unsigned char *end,
                                        size_t *out_len )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *out_len = 0;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "write_named_group_dhe is not implemented" ) );
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

static int ssl_tls13_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *out_len )
{
    unsigned char *p = buf ;
    unsigned char *named_group_list; /* Start of named_group_list */
    size_t named_group_list_len;     /* Length of named_group_list */
    size_t output_len = 0;
    int ret_ecdhe, ret_dhe;

    *out_len = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported_groups extension" ) );

    /* Check if we have space for header and length fields:
     * - extension_type            (2 bytes)
     * - extension_data_length     (2 bytes)
     * - named_group_list_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    named_group_list = p;
    ret_ecdhe = ssl_tls13_write_named_group_list_ecdhe( ssl, p, end, &output_len );
    if( ret_ecdhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_named_group_list_ecdhe", ret_ecdhe );
    }
    p += output_len;

    ret_dhe = ssl_tls13_write_named_group_list_dhe( ssl, p, end, &output_len );
    if( ret_dhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_named_group_list_dhe", ret_dhe );
    }
    p += output_len;

    /* Both ECDHE and DHE failed. */
    if( ret_ecdhe != 0 && ret_dhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Both ECDHE and DHE groups are fail. " ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Length of named_group_list*/
    named_group_list_len = p - named_group_list;
    if( named_group_list_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No group available." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_GROUPS, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( named_group_list_len + 2, buf, 2 );
    /* Write length of named_group_list */
    MBEDTLS_PUT_UINT16_BE( named_group_list_len, buf, 4 );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Supported groups extension", buf + 4, named_group_list_len + 2 );

    *out_len = p - buf;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_GROUPS;

    return( 0 );
}

/*
 * Functions for writing key_share extension.
 */
#if defined(MBEDTLS_ECDH_C)
static int ssl_tls13_generate_and_write_ecdh_key_exchange(
                mbedtls_ssl_context *ssl,
                uint16_t named_group,
                unsigned char *buf,
                unsigned char *end,
                size_t *out_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_ecp_curve_info *curve_info =
        mbedtls_ecp_curve_info_from_tls_id( named_group );

    if( curve_info == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "offer curve %s", curve_info->name ) );

    if( ( ret = mbedtls_ecdh_setup_no_everest( &ssl->handshake->ecdh_ctx,
                                               curve_info->grp_id ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_setup_no_everest", ret );
        return( ret );
    }

    ret = mbedtls_ecdh_tls13_make_params( &ssl->handshake->ecdh_ctx, out_len,
                                          buf, end - buf,
                                          ssl->conf->f_rng, ssl->conf->p_rng );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_tls13_make_params", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                            MBEDTLS_DEBUG_ECDH_Q );
    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

static int ssl_tls13_get_default_group_id( mbedtls_ssl_context *ssl,
                                           uint16_t *group_id )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;


#if defined(MBEDTLS_ECDH_C)
    const uint16_t *group_list = mbedtls_ssl_get_groups( ssl );
    /* Pick first available ECDHE group compatible with TLS 1.3 */
    if( group_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for ( ; *group_list != 0; group_list++ )
    {
        const mbedtls_ecp_curve_info *curve_info;
        curve_info = mbedtls_ecp_curve_info_from_tls_id( *group_list );
        if( curve_info != NULL &&
            mbedtls_ssl_tls13_named_group_is_ecdhe( *group_list ) )
        {
            *group_id = *group_list;
            return( 0 );
        }
    }
#else
    ((void) ssl);
    ((void) group_id);
#endif /* MBEDTLS_ECDH_C */

    /*
     * Add DHE named groups here.
     * Pick first available DHE group compatible with TLS 1.3
     */

    return( ret );
}

/*
 * ssl_tls13_write_key_share_ext
 *
 * Structure of key_share extension in ClientHello:
 *
 *  struct {
 *          NamedGroup group;
 *          opaque key_exchange<1..2^16-1>;
 *      } KeyShareEntry;
 *  struct {
 *          KeyShareEntry client_shares<0..2^16-1>;
 *      } KeyShareClientHello;
 */
static int ssl_tls13_write_key_share_ext( mbedtls_ssl_context *ssl,
                                          unsigned char *buf,
                                          unsigned char *end,
                                          size_t *out_len )
{
    unsigned char *p = buf;
    unsigned char *client_shares; /* Start of client_shares */
    size_t client_shares_len;     /* Length of client_shares */
    uint16_t group_id;
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    *out_len = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    /* Check if we have space for header and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - client_shares_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello: adding key share extension" ) );

    /* HRR could already have requested something else. */
    group_id = ssl->handshake->offered_group_id;
    if( !mbedtls_ssl_tls13_named_group_is_ecdhe( group_id ) &&
        !mbedtls_ssl_tls13_named_group_is_dhe( group_id ) )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_get_default_group_id( ssl,
                                                              &group_id ) );
    }

    /*
     * Dispatch to type-specific key generation function.
     *
     * So far, we're only supporting ECDHE. With the introduction
     * of PQC KEMs, we'll want to have multiple branches, one per
     * type of KEM, and dispatch to the corresponding crypto. And
     * only one key share entry is allowed.
     */
    client_shares = p;
#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( group_id ) )
    {
        /* Pointer to group */
        unsigned char *group = p;
        /* Length of key_exchange */
        size_t key_exchange_len;

        /* Check there is space for header of KeyShareEntry
         * - group                  (2 bytes)
         * - key_exchange_length    (2 bytes)
         */
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 4 );
        p += 4;
        ret = ssl_tls13_generate_and_write_ecdh_key_exchange( ssl, group_id,
                                                              p, end,
                                                              &key_exchange_len );
        p += key_exchange_len;
        if( ret != 0 )
            return( ret );

        /* Write group */
        MBEDTLS_PUT_UINT16_BE( group_id, group, 0 );
        /* Write key_exchange_length */
        MBEDTLS_PUT_UINT16_BE( key_exchange_len, group, 2 );
    }
    else
#endif /* MBEDTLS_ECDH_C */
    if( 0 /* other KEMs? */ )
    {
        /* Do something */
    }
    else
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* Length of client_shares */
    client_shares_len = p - client_shares;
    if( client_shares_len == 0)
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No key share defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( client_shares_len + 2, buf, 2 );
    /* Write client_shares_length */
    MBEDTLS_PUT_UINT16_BE( client_shares_len, buf, 4 );

    /* Update offered_group_id field */
    ssl->handshake->offered_group_id = group_id;

    /* Output the total length of key_share extension. */
    *out_len = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, key_share extension", buf, *out_len );

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;

cleanup:

    return( ret );
}

#if defined(MBEDTLS_ECDH_C)

static int ssl_tls13_check_ecdh_params( const mbedtls_ssl_context *ssl )
{
    const mbedtls_ecp_curve_info *curve_info;
    mbedtls_ecp_group_id grp_id;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    grp_id = ssl->handshake->ecdh_ctx.grp.id;
#else
    grp_id = ssl->handshake->ecdh_ctx.grp_id;
#endif

    curve_info = mbedtls_ecp_curve_info_from_grp_id( grp_id );
    if( curve_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );

    if( mbedtls_ssl_check_curve( ssl, grp_id ) != 0 )
        return( -1 );

    MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                            MBEDTLS_DEBUG_ECDH_QP );

    return( 0 );
}

static int ssl_tls13_read_public_ecdhe_share( mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ecdh_tls13_read_public( &ssl->handshake->ecdh_ctx,
                                          buf, buf_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ecdh_tls13_read_public" ), ret );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    if( ssl_tls13_check_ecdh_params( ssl ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_tls13_check_ecdh_params() failed!" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

/*
 * ssl_tls13_parse_key_share_ext()
 *      Parse key_share extension in Server Hello
 *
 * struct {
 *        KeyShareEntry server_share;
 * } KeyShareServerHello;
 * struct {
 *        NamedGroup group;
 *        opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 */
static int ssl_tls13_parse_key_share_ext( mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t group, offered_group;

    /* ...
     * NamedGroup group; (2 bytes)
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    group = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check that the chosen group matches the one we offered. */
    offered_group = ssl->handshake->offered_group_id;
    if( offered_group != group )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Invalid server key share, our group %u, their group %u",
              (unsigned) offered_group, (unsigned) group ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( group ) )
    {
        /* Complete ECDHE key agreement */
        ret = ssl_tls13_read_public_ecdhe_share( ssl, p, end - p );
        if( ret != 0 )
            return( ret );
    }
    else
#endif /* MBEDTLS_ECDH_C */
    if( 0 /* other KEMs? */ )
    {
        /* Do something */
    }
    else
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
    return( ret );
}

static int ssl_tls13_reset_ecdhe_share( mbedtls_ssl_context *ssl )
{
    mbedtls_ecdh_free( &ssl->handshake->ecdh_ctx );
    return( 0 );
}

static int ssl_tls13_reset_key_share( mbedtls_ssl_context *ssl )
{
    uint16_t group_id = ssl->handshake->offered_group_id;
    if( group_id == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    if( mbedtls_ssl_tls13_named_group_is_ecdhe( group_id ) )
        return( ssl_tls13_reset_ecdhe_share( ssl ) );
    else if( 0 /* other KEMs? */ )
    {
        /* Do something */
    }

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/* Write cipher_suites
 * CipherSuite cipher_suites<2..2^16-2>;
 */
static int ssl_tls13_write_client_hello_cipher_suites(
            mbedtls_ssl_context *ssl,
            unsigned char *buf,
            unsigned char *end,
            size_t *out_len )
{
    unsigned char *p = buf;
    const int *ciphersuite_list;
    unsigned char *cipher_suites; /* Start of the cipher_suites list */
    size_t cipher_suites_len;

    *out_len = 0 ;

    /*
     * Ciphersuite list
     *
     * This is a list of the symmetric cipher options supported by
     * the client, specifically the record protection algorithm
     * ( including secret key length ) and a hash to be used with
     * HKDF, in descending order of client preference.
     */
    ciphersuite_list = ssl->conf->ciphersuite_list;

    /* Check there is space for the cipher suite list length (2 bytes). */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p += 2;

    /* Write cipher_suites */
    cipher_suites = p;
    for ( size_t i = 0; ciphersuite_list[i] != 0; i++ )
    {
        int cipher_suite = ciphersuite_list[i];
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
        if( ciphersuite_info == NULL )
            continue;
        if( !( MBEDTLS_SSL_MINOR_VERSION_4 >= ciphersuite_info->min_minor_ver &&
               MBEDTLS_SSL_MINOR_VERSION_4 <= ciphersuite_info->max_minor_ver ) )
            continue;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %04x, %s",
                                    (unsigned int) cipher_suite,
                                    ciphersuite_info->name ) );

        /* Check there is space for the cipher suite identifier (2 bytes). */
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( cipher_suite, p, 0 );
        p += 2;

#if defined(MBEDTLS_ZERO_RTT)
        /* For ZeroRTT we only add a single ciphersuite. */
        break;
#endif /* MBEDTLS_ZERO_RTT */
    }

    /* Write the cipher_suites length in number of bytes */
    cipher_suites_len = p - cipher_suites;
    MBEDTLS_PUT_UINT16_BE( cipher_suites_len, buf, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3,
                           ( "client hello, got %" MBEDTLS_PRINTF_SIZET " cipher suites",
                             cipher_suites_len/2 ) );

    /* Output the total length of cipher_suites field. */
    *out_len = p - buf;

    return( 0 );
}

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)

/*
 * ssl_tls13_write_max_fragment_length_ext():
 *
 * enum{
 *    2^9( 1 ), 2^10( 2 ), 2^11( 3 ), 2^12( 4 ), ( 255 )
 * } MaxFragmentLength;
 *
 */
static int ssl_tls13_write_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                                    unsigned char *buf,
                                                    const unsigned char *end,
                                                    size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    if( ssl->conf->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE )
    {
        return( 0 );
    }

    if( end < p || (size_t)( end - p ) < 5 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding max_fragment_length extension" ) );

    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH, p, 0 );
    MBEDTLS_PUT_UINT16_BE( 1, p, 2 );
    p += 4;

    *p++ = ssl->conf->mfl_code;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Maximum fragment length = %d", ssl->conf->mfl_code ) );

    *out_len = 5;
    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */


#if defined(MBEDTLS_SSL_ALPN)
/*
 * ssl_tls13_write_alpn_ext() structure:
 *
 * opaque ProtocolName<1..2^8-1>;
 *
 * struct {
 *     ProtocolName protocol_name_list<2..2^16-1>
 * } ProtocolNameList;
 *
 */
static int ssl_tls13_write_alpn_ext( mbedtls_ssl_context *ssl,
                                     unsigned char *buf,
                                     const unsigned char *end,
                                     size_t *out_len )
{
    unsigned char *p = buf;
    size_t alpnlen = 0;
    const char **cur;

    *out_len = 0;

    if( ssl->conf->alpn_list == NULL )
    {
        return( 0 );
    }

    for ( cur = ssl->conf->alpn_list; *cur != NULL; cur++ )
        alpnlen += MBEDTLS_BYTE_0( strlen( *cur ) ) + 1;

    if( end < p || (size_t)( end - p ) < 6 + alpnlen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding alpn extension" ) );

    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_ALPN, p, 0 );
    p += 2;

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     */

    /* Skip writing extension and list length for now */
    p += 4;

    for ( cur = ssl->conf->alpn_list; *cur != NULL; cur++ )
    {
        *p = MBEDTLS_BYTE_0( strlen( *cur ) );
        memcpy( p + 1, *cur, *p );
        p += 1 + *p;
    }

    *out_len = p - buf;

    /* List length = out_len - 2 ( ext_type ) - 2 ( ext_len ) - 2 ( list_len ) */
    MBEDTLS_PUT_UINT16_BE( *out_len - 6, buf, 4 );

    /* Extension length = out_len - 2 ( ext_type ) - 2 ( ext_len ) */
    MBEDTLS_PUT_UINT16_BE( *out_len - 4, buf, 2 );

    return( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/*
 * ssl_tls13_write_psk_key_exchange_modes_ext() structure:
 *
 * enum { psk_ke( 0 ), psk_dhe_ke( 1 ), ( 255 ) } PskKeyExchangeMode;
 *
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 */

static int ssl_tls13_write_psk_key_exchange_modes_ext( mbedtls_ssl_context *ssl,
                                                       unsigned char *buf,
                                                       unsigned char *end,
                                                       size_t *out_len )
{
    unsigned char *p;
    int num_modes = 0;

    /* Skip writing extension if no PSK key exchange mode
     * is enabled in the config. */
    if( !mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) )
    {
        *out_len = 0;
        return( 0 );
    }

    /* Require 7 bytes of data, otherwise fail, even if extension might be shorter. */
    if( (size_t)( end - buf ) < 7 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Not enough buffer" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding psk_key_exchange_modes extension" ) );

    /* Extension Type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES, buf, 0 );

    /* Skip extension length (2 byte) and PSK mode list length (1 byte) for now. */
    p = buf + 5;

    if( mbedtls_ssl_conf_tls13_psk_enabled( ssl ) )
    {
        *p++ = MBEDTLS_SSL_TLS1_3_PSK_MODE_PURE;
        num_modes++;

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Adding pure PSK key exchange mode" ) );
    }

    if( mbedtls_ssl_conf_tls13_psk_ephemeral_enabled( ssl ) )
    {
        *p++ = MBEDTLS_SSL_TLS1_3_PSK_MODE_ECDHE;
        num_modes++;

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Adding PSK-ECDHE key exchange mode" ) );
    }

    /* Add extension length: PSK mode list length byte + actual PSK mode list length */
    buf[2] = 0;
    buf[3] = num_modes + 1;
    /* Add PSK mode list length */
    buf[4] = num_modes;

    *out_len = p - buf;
    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES;
    return ( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */


/*
 * mbedtls_ssl_tls13_write_pre_shared_key_ext() structure:
 *
 * struct {
 *   opaque identity<1..2^16-1>;
 *   uint32 obfuscated_ticket_age;
 * } PskIdentity;
 *
 * opaque PskBinderEntry<32..255>;
 *
 * struct {
 *   select ( Handshake.msg_type ) {
 *
 *     case client_hello:
 *       PskIdentity identities<7..2^16-1>;
 *       PskBinderEntry binders<33..2^16-1>;
 *
 *     case server_hello:
 *       uint16 selected_identity;
 *   };
 *
 * } PreSharedKeyExtension;
 *
 *
 * part = 0 ==> everything up to the PSK binder list,
 *              returning the binder list length in `binder_list_length`.
 * part = 1 ==> the PSK binder list
 */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)

#define SSL_WRITE_PSK_EXT_PARTIAL           0
#define SSL_WRITE_PSK_EXT_ADD_PSK_BINDERS   1

int mbedtls_ssl_tls13_write_pre_shared_key_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf, unsigned char *end,
    size_t *bytes_written,
    size_t *total_ext_len,
    int part )
{
    int ret;
    unsigned char *p = (unsigned char *) buf;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    const int *ciphersuites;
    int hash_len;
    const unsigned char *psk;
    size_t psk_len;
    const unsigned char *psk_identity;
    size_t psk_identity_len;

    *total_ext_len = 0;
    *bytes_written = 0;

    if( !mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) )
        return( 0 );

    /* Check if we have any PSKs to offer. If so, return the first.
     *
     * NOTE: Ultimately, we want to be able to offer multiple PSKs,
     *       in which case we want to iterate over them here.
     *
     * As it stands, however, we only ever offer one, chosen
     * by the following heuristic:
     * - If a ticket has been configured, offer the corresponding PSK.
     * - If no ticket has been configured by an external PSK has been
     *   configured, offer that.
     * - Otherwise, skip the PSK extension.
     */

    if( mbedtls_ssl_get_psk_to_offer( ssl, &psk, &psk_len,
                                      &psk_identity, &psk_identity_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "skip pre_shared_key extensions" ) );
        return( 0 );
    }

    /*
     * Ciphersuite list
     */
    ciphersuites = ssl->conf->ciphersuite_list;
    for ( int i = 0; ciphersuites[i] != 0; i++ )
    {
        suite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuites[i] );

        if( suite_info == NULL )
            continue;

        /* In this implementation we only add one pre-shared-key extension. */
        ssl->session_negotiate->ciphersuite = ciphersuites[i];
        ssl->handshake->ciphersuite_info = suite_info;
        break;
    }

    hash_len = mbedtls_hash_size_for_ciphersuite( suite_info );
    if( hash_len == -1 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    size_t const ext_type_bytes           = 2;
    size_t const ext_len_bytes            = 2;
    size_t const psk_identities_len_bytes = 2;
    size_t const psk_identity_len_bytes   = 2;
    size_t const psk_identity_bytes       = psk_identity_len;
    size_t const obfuscated_ticket_bytes  = 4;
    size_t const psk_binders_len_bytes    = 2;
    size_t const psk_binder_len_bytes     = 1;
    size_t const psk_binder_bytes         = hash_len;

    size_t const psk_binder_list_bytes = psk_binders_len_bytes  +
                                           psk_binder_len_bytes +
                                           psk_binder_bytes;

    size_t const ext_len = psk_identities_len_bytes     +
                              psk_identity_len_bytes    +
                              psk_identity_bytes        +
                              obfuscated_ticket_bytes   +
                           psk_binder_list_bytes;

    size_t const ext_len_total = ext_type_bytes +
                                 ext_len_bytes  +
                                   ext_len;

    if( part == SSL_WRITE_PSK_EXT_PARTIAL )
    {
        uint32_t obfuscated_ticket_age = 0;

        MBEDTLS_SSL_DEBUG_MSG( 3,
                     ( "client hello, adding pre_shared_key extension, "
                       "omitting PSK binder list" ) );

        /* Write extension up to but excluding the PSK binders list

         * The length (excluding the extension header) includes:
         *
         *  - 2 bytes for total length of identities
         *     - 2 bytes for length of first identity value
         *     - identity value ( of length len; min( len )>=1 )
         *     - 4 bytes for obfuscated_ticket_age
         *                ...
         *  - 2 bytes for total length of psk binders
         *      - 1 byte for length of first psk binder value
         *      - 32 or 48 bytes (for SHA256/384) for PSK binder value
         *                ...
         *
         * Note: Currently we assume we have only one PSK credential
         * configured per server.
         */

        /* ext_length + Extension Type ( 2 bytes ) + Extension Length ( 2 bytes ) */
        if( end < p || (size_t)( end - p ) < ext_len_total )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too short" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        /* Extension Type */
        MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_PRE_SHARED_KEY, p, 0 );

        /* Extension Length */
        MBEDTLS_PUT_UINT16_BE( ext_len, p, 2 );

        /* 2 bytes length field for array of PskIdentity */
        MBEDTLS_PUT_UINT16_BE( psk_identity_len + 4 + 2, p, 4 );

        /* 2 bytes length field for psk_identity */
        MBEDTLS_PUT_UINT16_BE( psk_identity_len, p, 6 );
        p += 8;

        /* actual psk_identity */
        memcpy( p, psk_identity, psk_identity_len );
        p += psk_identity_len;

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

        /* Calculate obfuscated_ticket_age (omitted for external PSKs). */
        if( ssl->session_negotiate->ticket_age_add > 0 )
        {
            /* TODO: Should we somehow fail if TIME is disabled here?
             * TODO: Use Mbed TLS' time abstraction? */
#if defined(MBEDTLS_HAVE_TIME)
            time_t now = time( NULL );

            if( !( ssl->session_negotiate->ticket_received <= now &&
                   now - ssl->session_negotiate->ticket_received < 7 * 86400 * 1000 ) )
            {
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket expired" ) );
                /* TBD: We would have to fall back to another PSK */
                return( MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED );
            }

            obfuscated_ticket_age =
                (uint32_t)( ( now - ssl->session_negotiate->ticket_received ) * 1000 ) +
                ssl->session_negotiate->ticket_age_add;

            MBEDTLS_SSL_DEBUG_MSG( 4, ( "obfuscated_ticket_age: %u",
                                        obfuscated_ticket_age ) );
#endif /* MBEDTLS_HAVE_TIME */
        }
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

        /* add obfuscated ticket age */
        MBEDTLS_PUT_UINT32_BE( obfuscated_ticket_age, p, 0 );
        p += 4;

        *bytes_written = ext_len_total - psk_binder_list_bytes;
        *total_ext_len = ext_len_total;

        ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PRE_SHARED_KEY;
    }
    else if( part == SSL_WRITE_PSK_EXT_ADD_PSK_BINDERS )
    {
        int psk_type;

        unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
        size_t transcript_len;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding PSK binder list" ) );

        /* 2 bytes length field for array of psk binders */
        MBEDTLS_PUT_UINT16_BE( hash_len + 1, p, 0 );
        p += 2;

        /* 1 bytes length field for next psk binder */
        *p++ = MBEDTLS_BYTE_0( hash_len );

        if( ssl->handshake->resume == 1 )
            psk_type = MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION;
        else
            psk_type = MBEDTLS_SSL_TLS1_3_PSK_EXTERNAL;

        /* Get current state of handshake transcript. */
        ret = mbedtls_ssl_get_handshake_transcript( ssl, suite_info->mac,
                                                    transcript, sizeof( transcript ),
                                                    &transcript_len );
        if( ret != 0 )
            return( ret );

        ret = mbedtls_ssl_tls13_create_psk_binder( ssl,
                                                   suite_info->mac,
                                                   psk, psk_len, psk_type,
                                                   transcript, p );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_create_psk_binder", ret );
            return( ret );
        }

        *bytes_written = psk_binder_list_bytes;
    }

    return( 0 );
}


#endif	/* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED  */


static int ssl_tls13_write_cookie_ext( mbedtls_ssl_context *ssl,
                                       unsigned char *buf,
                                       unsigned char *end,
                                       size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    if( ssl->handshake->verify_cookie == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "no cookie to send; skip extension" ) );
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, cookie",
                          ssl->handshake->verify_cookie,
                          ssl->handshake->verify_cookie_len );

    if( end < p ||
        (size_t)( end - p ) < ( ssl->handshake->verify_cookie_len + 4 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding cookie extension" ) );

    /* Extension Type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_COOKIE, p, 0 );

    /* Extension Length */
    MBEDTLS_PUT_UINT16_BE( ssl->handshake->verify_cookie_len + 2, p, 2 );

    /* Cookie Length */
    MBEDTLS_PUT_UINT16_BE( ssl->handshake->verify_cookie_len, p, 4 );
    p += 6;

    /* Cookie */
    memcpy( p, ssl->handshake->verify_cookie, ssl->handshake->verify_cookie_len );

    *out_len = ssl->handshake->verify_cookie_len + 6;

    return( 0 );
}

/*
 * Functions for writing ClientHello message.
 */

/*
 * Structure of ClientHello message:
 *
 *    struct {
 *        ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *        Random random;
 *        opaque legacy_session_id<0..32>;
 *        CipherSuite cipher_suites<2..2^16-2>;
 *        opaque legacy_compression_methods<1..2^8-1>;
 *        Extension extensions<8..2^16-1>;
 *    } ClientHello;
 */
static int ssl_tls13_write_client_hello_body( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *len_without_binders,
                                              size_t *out_len )
{

    int ret;
    unsigned char *p_extensions_len; /* Pointer to extensions length */
    size_t output_len;               /* Length of buffer used by function */
    size_t extensions_len;           /* Length of the list of extensions*/

    /* Buffer management */
    unsigned char *p = buf;

    *out_len = 0;

    /* No validation needed here. It has been done by ssl_conf_check() */
    ssl->major_ver = ssl->conf->min_major_ver;
    ssl->minor_ver = ssl->conf->min_minor_ver;

    /*
     * Write legacy_version
     *    ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
     *
     *  For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( 0x0303, p, 0 );
    p += 2;

    /* Write the random bytes ( random ).*/
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    memcpy( p, ssl->handshake->randbytes, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    p += MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

    /*
     * Write legacy_session_id
     *
     * Versions of TLS before TLS 1.3 supported a "session resumption" feature
     * which has been merged with pre-shared keys in this version. A client
     * which has a cached session ID set by a pre-TLS 1.3 server SHOULD set
     * this field to that value. In compatibility mode, this field MUST be
     * non-empty, so a client not offering a pre-TLS 1.3 session MUST generate
     * a new 32-byte value. This value need not be random but SHOULD be
     * unpredictable to avoid implementations fixating on a specific value
     * ( also known as ossification ). Otherwise, it MUST be set as a zero-length
     * vector ( i.e., a zero-valued single byte length field ).
     */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, ssl->session_negotiate->id_len + 1 );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    memcpy( p, ssl->session_negotiate->id, ssl->session_negotiate->id_len );
    p += ssl->session_negotiate->id_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                              ssl->session_negotiate->id_len );
#else
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    *p++ = 0; /* session id length set to zero */
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    /* Write cipher_suites */
    ret = ssl_tls13_write_client_hello_cipher_suites( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write legacy_compression_methods
     *
     * For every TLS 1.3 ClientHello, this vector MUST contain exactly
     * one byte set to zero, which corresponds to the 'null' compression
     * method in prior versions of TLS.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    *p++ = 1;
    *p++ = MBEDTLS_SSL_COMPRESS_NULL;

    /* Write extensions */

    /* Keeping track of the included extensions */
    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

    /* First write extensions, then the total length */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p_extensions_len = p;
    p += 2;

    /* Write supported_versions extension
     *
     * Supported Versions Extension is mandatory with TLS 1.3.
     */
    ret = ssl_tls13_write_supported_versions_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* For TLS / DTLS 1.3 we need to support the use of cookies
     * ( if the server provided them ) */
    ret = ssl_tls13_write_cookie_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

#if defined(MBEDTLS_SSL_ALPN)
    ret = ssl_tls13_write_alpn_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    ret = ssl_tls13_write_max_fragment_length_ext( ssl, p, end, &output_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_max_fragment_length_ext", ret );
        return( ret );
    }
    p += output_len;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_ZERO_RTT)
    ret = mbedtls_ssl_tls13_write_early_data_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    /* For PSK-based ciphersuites we don't really need the SNI extension */
    ret = mbedtls_ssl_write_hostname_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* For PSK-based key exchange we need the pre_shared_key extension
     * and the psk_key_exchange_modes extension.
     *
     * The pre_shared_key extension MUST be the last extension in the
     * ClientHello. Servers MUST check that it is the last extension and
     * otherwise fail the handshake with an "illegal_parameter" alert.
     *
     * Add the psk_key_exchange_modes extension.
     */
    ret = ssl_tls13_write_psk_key_exchange_modes_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    /* Write supported_groups extension
     *
     * It is REQUIRED for ECDHE cipher_suites.
     */
    ret = ssl_tls13_write_supported_groups_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write key_share extension
     *
     * We need to send the key shares under three conditions:
     * 1) A certificate-based ciphersuite is being offered. In this case
     *    supported_groups and supported_signature extensions have been
     *    successfully added.
     * 2) A PSK-based ciphersuite with ECDHE is offered. In this case the
     *    psk_key_exchange_modes has been added as the last extension.
     * 3) Or, in case all ciphers are supported ( which includes #1 and #2
     *    from above )
     */
    ret = ssl_tls13_write_key_share_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write signature_algorithms extension
     *
     * It is REQUIRED for certificate authenticated cipher_suites.
     */
    ret = mbedtls_ssl_tls13_write_sig_alg_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

    *len_without_binders = 0;
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    {
        size_t bytes_written;
        /* We need to save the pointer to the pre-shared key extension
         * because it has to be updated later. */
        ret = mbedtls_ssl_tls13_write_pre_shared_key_ext( ssl, p, end,
                                                          &bytes_written,
                                                          &output_len,
                                                          SSL_WRITE_PSK_EXT_PARTIAL );
        if( ret != 0 )
            return( ret );

        *len_without_binders = ( p - buf ) + bytes_written;
        p += output_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    /* Write the length of the list of extensions. */
    extensions_len = p - p_extensions_len - 2;
    MBEDTLS_PUT_UINT16_BE( extensions_len, p_extensions_len, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %" MBEDTLS_PRINTF_SIZET ,
                                extensions_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", p_extensions_len, extensions_len );

    *out_len = p - buf;
    return( 0 );
}

static int ssl_tls13_finalize_client_hello( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    return( 0 );
}

static int ssl_tls13_prepare_client_hello( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                  ssl->handshake->randbytes,
                                  MBEDTLS_CLIENT_HELLO_RANDOM_LEN ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_rng", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    /*
     * Create a session identifier for the purpose of middlebox compatibility
     * only if one has not been created already.
     */
    if( ssl->session_negotiate->id_len == 0 )
    {
        /* Creating a session id with 32 byte length */
        if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                      ssl->session_negotiate->id, 32 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "creating session id failed", ret );
            return( ret );
        }
        ssl->session_negotiate->id_len = 32;
    }
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    return( 0 );
}

/*
 * Write ClientHello handshake message.
 * Handler for MBEDTLS_SSL_CLIENT_HELLO
 */
static int ssl_tls13_write_client_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;
    size_t len_without_binders;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    if( ssl->handshake->state_local.cli_hello_out.preparation_done == 0 )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_client_hello( ssl ) );
        ssl->handshake->state_local.cli_hello_out.preparation_done = 1;
    }

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg(
                                ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_client_hello_body( ssl, buf,
                                                             buf + buf_len,
                                                             &len_without_binders,
                                                             &msg_len ) );

    mbedtls_ssl_tls13_add_hs_hdr_to_checksum( ssl,
                                              MBEDTLS_SSL_HS_CLIENT_HELLO,
                                              msg_len );
    ssl->handshake->update_checksum( ssl, buf, len_without_binders );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* Patch the PSK binder after updating the HS checksum. */
    {
        size_t dummy0, dummy1;
        mbedtls_ssl_tls13_write_pre_shared_key_ext( ssl,
                                                    buf + len_without_binders,
                                                    buf + msg_len,
                                                    &dummy0, &dummy1,
                                                    SSL_WRITE_PSK_EXT_ADD_PSK_BINDERS );

        /* Manually update the checksum with ClientHello using dummy PSK binders. */
        ssl->handshake->update_checksum( ssl, buf + len_without_binders,
                                         msg_len - len_without_binders );
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_client_hello( ssl ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg( ssl,
                                                                  buf_len,
                                                                  msg_len ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );
    return( ret );
}



#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_tls13_parse_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                                    const unsigned char *buf,
                                                    size_t len )
{
    /*
     * server should use the extension only if we did,
     * and if so the server's value should match ours ( and len is always 1 )
     */
    if( ssl->conf->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE ||
        len != 1 ||
        buf[0] != ssl->conf->mfl_code )
    {
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/*
 * struct {
 *   opaque identity<1..2^16-1>;
 *   uint32 obfuscated_ticket_age;
 * } PskIdentity;
 *
 * opaque PskBinderEntry<32..255>;
 *
 * struct {
 *   select ( Handshake.msg_type ) {
 *     case client_hello:
 *          PskIdentity identities<7..2^16-1>;
 *          PskBinderEntry binders<33..2^16-1>;
 *     case server_hello:
 *          uint16 selected_identity;
 *   };
 *
 * } PreSharedKeyExtension;
 *
 */

static int ssl_tls13_parse_server_psk_identity_ext( mbedtls_ssl_context *ssl,
                                                    const unsigned char *buf,
                                                    size_t len )
{
    int ret = 0;
    size_t selected_identity;

    const unsigned char *psk;
    size_t psk_len;
    const unsigned char *psk_identity;
    size_t psk_identity_len;


    /* Check which PSK we've offered.
     *
     * NOTE: Ultimately, we want to offer multiple PSKs, and in this
     *       case, we need to iterate over them here.
     */
    if( mbedtls_ssl_get_psk_to_offer( ssl, &psk, &psk_len,
                                      &psk_identity, &psk_identity_len ) != 0 )
    {
        /* If we haven't offered a PSK, the server must not send
         * a PSK identity extension. */
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    if( len != (size_t) 2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad psk_identity extension in server hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    selected_identity = MBEDTLS_GET_UINT16_BE( buf, 0 );

    /* We have offered only one PSK, so the only valid choice
     * for the server is PSK index 0.
     *
     * This will change once we support multiple PSKs. */
    if( selected_identity > 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Server's chosen PSK identity out of range" ) );

        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                        MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER ) ) != 0 )
        {
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* Set the chosen PSK
     *
     * TODO: We don't have to do this in case we offered 0-RTT and the
     *       server accepted it, because in this case we've already
     *       set the handshake PSK. */
    ret = mbedtls_ssl_set_hs_psk( ssl, psk, psk_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_set_hs_psk", ret );
        return( ret );
    }

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PRE_SHARED_KEY;
    return( 0 );
}

#endif

#if defined(MBEDTLS_ZERO_RTT)
/* Early Data Extension
*
* struct {} Empty;
*
* struct {
*   select (Handshake.msg_type) {
*     case new_session_ticket:   uint32 max_early_data_size;
*     case client_hello:         Empty;
*     case encrypted_extensions: Empty;
*   };
* } EarlyDataIndication;
*
* This function only handles the case of the EncryptedExtensions message.
*/
static int ssl_tls13_parse_encrypted_extensions_early_data_ext(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, size_t len )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
    {
        /* The server must not send the EarlyDataIndication if the
         * client hasn't indicated the use of 0-RTT. */
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    if( len != 0 )
    {
        /* The message must be empty. */
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* Nothing to parse */
    ((void) buf);

    ssl->early_data_status = MBEDTLS_SSL_EARLY_DATA_ACCEPTED;
    return( 0 );
}

int mbedtls_ssl_get_early_data_status( mbedtls_ssl_context *ssl )
{
    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    return( ssl->early_data_status );
}

int mbedtls_ssl_set_early_data( mbedtls_ssl_context *ssl,
                                const unsigned char *buffer, size_t len )
{
    if( buffer == NULL || len == 0 )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl->early_data_buf = buffer;
    ssl->early_data_len = len;
    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_ALPN)
static int ssl_tls13_parse_alpn_ext( mbedtls_ssl_context *ssl,
                                     const unsigned char *buf, size_t len )
{
    size_t list_len, name_len;
    const char **p;

    /* If we didn't send it, the server shouldn't send it */
    if( ssl->conf->alpn_list == NULL )
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     *
     * the "ProtocolNameList" MUST contain exactly one "ProtocolName"
     */

    /* Min length is 2 ( list_len ) + 1 ( name_len ) + 1 ( name ) */
    if( len < 4 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    list_len = MBEDTLS_GET_UINT16_BE( buf, 0 );
    if( list_len != len - 2 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    name_len = buf[2];
    if( name_len != list_len - 1 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    /* Check that the server chosen protocol was in our list and save it */
    for ( p = ssl->conf->alpn_list; *p != NULL; p++ )
    {
        if( name_len == strlen( *p ) &&
            memcmp( buf + 3, *p, name_len ) == 0 )
        {
            ssl->alpn_chosen = *p;
            return( 0 );
        }
    }

    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
}
#endif /* MBEDTLS_SSL_ALPN */

/*
 *
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 *
 */

/* Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO_COORDINATE_HELLO or
 * - SSL_SERVER_HELLO_COORDINATE_HRR
 * to indicate which message is expected and to be parsed next. */
#define SSL_SERVER_HELLO_COORDINATE_HELLO 0
#define SSL_SERVER_HELLO_COORDINATE_HRR 1
static int ssl_tls13_server_hello_is_hrr( mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          const unsigned char *end )
{
    static const unsigned char magic_hrr_string[MBEDTLS_SERVER_HELLO_RANDOM_LEN] =
        { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
          0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
          0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
          0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33 ,0x9C };

    /* Check whether this message is a HelloRetryRequest ( HRR ) message.
     *
     * Server Hello and HRR are only distinguished by Random set to the
     * special value of the SHA-256 of "HelloRetryRequest".
     *
     * struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2^16-1>;
     * } ServerHello;
     *
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( buf, end, 2 + sizeof( magic_hrr_string ) );

    if( memcmp( buf + 2, magic_hrr_string, sizeof( magic_hrr_string ) ) == 0 )
    {
        return( SSL_SERVER_HELLO_COORDINATE_HRR );
    }

    return( SSL_SERVER_HELLO_COORDINATE_HELLO );
}

/* Fetch and preprocess
 * Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO_COORDINATE_HELLO or
 * - SSL_SERVER_HELLO_COORDINATE_HRR
 */
#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_tls13_server_hello_coordinate( mbedtls_ssl_context *ssl,
                                              mbedtls_mps_handshake_in *msg,
                                              unsigned char **buf,
                                              size_t *buf_len )
{
    int ret = 0;
    unsigned char *peak;

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps->l4 ) );

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    if( ret == MBEDTLS_MPS_MSG_CCS )
    {
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps->l4 ) );
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    if( ret != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps->l4,
                                                      msg ) );

    if( msg->type != MBEDTLS_SSL_HS_SERVER_HELLO )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    ret = mbedtls_mps_reader_get( msg->handle,
                                  msg->length,
                                  &peak,
                                  NULL );

    if( ret == MBEDTLS_ERR_MPS_READER_OUT_OF_DATA )
    {
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_pause( &ssl->mps->l4 ) );
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    }
    else
    {
        ret = ssl_tls13_server_hello_is_hrr( ssl, peak, peak + msg->length );
        switch( ret )
        {
            case SSL_SERVER_HELLO_COORDINATE_HELLO:
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "received ServerHello message" ) );
                break;
            case SSL_SERVER_HELLO_COORDINATE_HRR:
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
                break;
            default:
                goto cleanup;
        }

        *buf = peak;
        *buf_len = msg->length;
    }

cleanup:

    return( ret );
}
#else /* MBEDTLS_SSL_USE_MPS */
static int ssl_tls13_server_hello_coordinate( mbedtls_ssl_context *ssl,
                                              unsigned char **buf,
                                              size_t *buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_read_record( ssl, 0 ) );

    /* TBD: If we do an HRR, keep track of the number
     * of ClientHello's we sent, and fail if it
     * exceeds the configured threshold. */

    if( ( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ) ||
        ( ssl->in_msg[0] != MBEDTLS_SSL_HS_SERVER_HELLO ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    *buf = ssl->in_msg + 4;
    *buf_len = ssl->in_hslen - 4;

    ret = ssl_tls13_server_hello_is_hrr( ssl, *buf, *buf + *buf_len );
    switch( ret )
    {
        case SSL_SERVER_HELLO_COORDINATE_HELLO:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "received ServerHello message" ) );
            break;
        case SSL_SERVER_HELLO_COORDINATE_HRR:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
            break;
    }

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_tls13_check_server_hello_session_id_echo( mbedtls_ssl_context *ssl,
                                                         const unsigned char **buf,
                                                         const unsigned char *end )
{
    const unsigned char *p = *buf;
    size_t legacy_session_id_echo_len;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    legacy_session_id_echo_len = *p++ ;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, legacy_session_id_echo_len );

    /* legacy_session_id_echo */
    if( ssl->session_negotiate->id_len != legacy_session_id_echo_len ||
        memcmp( ssl->session_negotiate->id, p , legacy_session_id_echo_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Expected Session ID",
                               ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Received Session ID", p,
                               legacy_session_id_echo_len );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);

        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    p += legacy_session_id_echo_len;
    *buf = p;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Session ID", ssl->session_negotiate->id,
                            ssl->session_negotiate->id_len );
    return( 0 );
}

static int ssl_tls13_cipher_suite_is_offered( mbedtls_ssl_context *ssl,
                                              int cipher_suite )
{
    const int *ciphersuite_list = ssl->conf->ciphersuite_list;

    /* Check whether we have offered this ciphersuite */
    for ( size_t i = 0; ciphersuite_list[i] != 0; i++ )
    {
        if( ciphersuite_list[i] == cipher_suite )
        {
            return( 1 );
        }
    }
    return( 0 );
}

/* Parse ServerHello message and configure context
 *
 * struct {
 *    ProtocolVersion legacy_version = 0x0303; // TLS 1.2
 *    Random random;
 *    opaque legacy_session_id_echo<0..32>;
 *    CipherSuite cipher_suite;
 *    uint8 legacy_compression_method = 0;
 *    Extension extensions<6..2^16-1>;
 * } ServerHello;
 */
static int ssl_tls13_parse_server_hello( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t extensions_len;
    const unsigned char *extensions_end;
    uint16_t cipher_suite;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

    /*
     * Check there is space for minimal fields
     *
     * - legacy_version             ( 2 bytes)
     * - random                     (MBEDTLS_SERVER_HELLO_RANDOM_LEN bytes)
     * - legacy_session_id_echo     ( 1 byte ), minimum size
     * - cipher_suite               ( 2 bytes)
     * - legacy_compression_method  ( 1 byte )
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, MBEDTLS_SERVER_HELLO_RANDOM_LEN + 6 );

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello", p, end - p );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, version", p, 2 );

    /* ...
     * ProtocolVersion legacy_version = 0x0303; // TLS 1.2
     * ...
     * with ProtocolVersion defined as:
     * uint16 ProtocolVersion;
     */
    if( !( p[0] == MBEDTLS_SSL_MAJOR_VERSION_3 &&
           p[1] == MBEDTLS_SSL_MINOR_VERSION_3 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }
    p += 2;

    /* ...
     * Random random;
     * ...
     * with Random defined as:
     * opaque Random[MBEDTLS_SERVER_HELLO_RANDOM_LEN];
     */
    memcpy( &ssl->handshake->randbytes[MBEDTLS_CLIENT_HELLO_RANDOM_LEN], p,
            MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /* ...
     * opaque legacy_session_id_echo<0..32>;
     * ...
     */
    if( ssl_tls13_check_server_hello_session_id_echo( ssl, &p, end ) != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* ...
     * CipherSuite cipher_suite;
     * ...
     * with CipherSuite defined as:
     * uint8 CipherSuite[2];
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    cipher_suite = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;


    /*
     * Check whether this ciphersuite is supported and offered.
     * Via the force_ciphersuite version we may have instructed the client
     * to use a different ciphersuite.
     */
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
    if( ciphersuite_info == NULL ||
        ssl_tls13_cipher_suite_is_offered( ssl, cipher_suite ) == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite(%04x) not found or not offered",
                                    cipher_suite ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }


    /* Configure ciphersuites */
    mbedtls_ssl_optimize_checksum( ssl, ciphersuite_info );

    ssl->handshake->ciphersuite_info = ciphersuite_info;
    ssl->session_negotiate->ciphersuite = cipher_suite;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: ( %04x ) - %s",
                                 cipher_suite, ciphersuite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    /* ...
     * uint8 legacy_compression_method = 0;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    if( p[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad legacy compression method" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }
    p++;

    /* ...
     * Extension extensions<6..2^16-1>;
     * ...
     * struct {
     *      ExtensionType extension_type; (2 bytes)
     *      opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check extensions do not go beyond the buffer of data. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );
    extensions_end = p + extensions_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello extensions", p, extensions_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );

        switch( extension_type )
        {
            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "found supported_versions extension" ) );

                ret = ssl_tls13_parse_supported_versions_ext( ssl,
                                                              p,
                                                              p + extension_data_len );
                if( ret != 0 )
                    return( ret );
                break;

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension" ) );
                if( ( ret = ssl_tls13_parse_server_psk_identity_ext(
                                ssl, p, extension_data_len ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET(
                        1, ( "ssl_tls13_parse_server_psk_identity_ext" ), ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_KEY_SHARE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key_shares extension" ) );
                if( ( ret = ssl_tls13_parse_key_share_ext( ssl,
                                            p, p + extension_data_len ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                           "ssl_tls13_parse_key_share_ext",
                                           ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

            default:
                MBEDTLS_SSL_DEBUG_MSG(
                    3,
                    ( "unknown extension found: %u ( ignoring )",
                      extension_type ) );

                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
                    MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
                return( MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
        }

        p += extension_data_len;
    }

    return( 0 );
}

static int ssl_tls13_hrr_parse( mbedtls_ssl_context *ssl,
                                const unsigned char *buf, size_t buf_len )
{
    int ret; /* return value */
    int i; /* scratch value */
    const unsigned char *msg_end = buf + buf_len; /* pointer to the end of the buffer for length checks */

    size_t ext_len; /* stores length of all extensions */
    unsigned int ext_id; /* id of an extension */
    const unsigned char *ext; /* pointer to an individual extension */
    unsigned int ext_size; /* size of an individual extension */

    const mbedtls_ssl_ciphersuite_t *suite_info; /* pointer to ciphersuite */

#if defined(MBEDTLS_SSL_COOKIE_C)
    size_t cookie_len;
    unsigned char *cookie;
#endif /* MBEDTLS_SSL_COOKIE_C */

    /* Check for minimal length */
    /* struct {
     * 	  ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2 ^ 16 - 1>;
     * } ServerHello;
     *
     *
     * 38 = 32 ( random bytes ) + 2 ( ciphersuite ) + 2 ( version ) +
     *       1 ( legacy_compression_method ) + 1 ( minimum for legacy_session_id_echo )
     */
    if( buf_len < 38 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message - min size not reached" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "hello retry request", buf, buf_len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "hello retry request, version", buf + 0, 2 );
    mbedtls_ssl_read_version( &ssl->major_ver, &ssl->minor_ver,
                              ssl->conf->transport, buf + 0 );

    /* The version field must contain 0x303 */
    if( buf[0] != 0x03 || buf[1] != 0x03 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }

    /* skip version */
    buf += 2;

    /* Internally we use the correct 1.3 version */
    ssl->major_ver = 0x03;
    ssl->minor_ver = 0x04;

    /* store server-provided random values */
    memcpy( ssl->handshake->randbytes + 32, buf, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "hello retry request, random bytes", buf + 2, 32 );

    /* skip random bytes */
    buf += 32;

    if( ssl_tls13_check_server_hello_session_id_echo( ssl, &buf, msg_end ) != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    /* read server-selected ciphersuite, which follows random bytes */
    i = MBEDTLS_GET_UINT16_BE( buf, 0 );

    /* skip ciphersuite */
    buf += 2;

    /* TBD: Check whether we have offered this ciphersuite */
    /* Via the force_ciphersuite version we may have instructed the client */
    /* to use a difference ciphersuite. */

    /* Configure ciphersuites */
    ssl->handshake->ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( i );

    if( ssl->handshake->ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite info for %04x not found", i ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                      MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    mbedtls_ssl_optimize_checksum( ssl, ssl->handshake->ciphersuite_info );

    ssl->session_negotiate->ciphersuite = i;

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "hello retry request, chosen ciphersuite: ( %04x ) - %s", i, suite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    i = 0;
    while ( 1 )
    {
        if( ssl->conf->ciphersuite_list[i] == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                          MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }

        if( ssl->conf->ciphersuite_list[i++] ==
            ssl->session_negotiate->ciphersuite )
        {
            break;
        }
    }

    /* Ensure that compression method is set to zero */
    if( buf[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* skip compression */
    buf++;

    /* Are we reading beyond the message buffer? */
    if( ( buf + 2 ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ext_len = MBEDTLS_GET_UINT16_BE( buf, 0 );
    buf += 2; /* skip extension length */

    /* Are we reading beyond the message buffer? */
    if( ( buf + ext_len ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ext = buf;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "hello retry request, total extension length: %" MBEDTLS_PRINTF_SIZET , ext_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "extensions", ext, ext_len );

    while ( ext_len )
    {
        ext_id = MBEDTLS_GET_UINT16_BE( ext, 0 );
        ext_size = MBEDTLS_GET_UINT16_BE( ext, 2 );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        switch( ext_id )
        {
#if defined(MBEDTLS_SSL_COOKIE_C)
            case MBEDTLS_TLS_EXT_COOKIE:

                /* Retrieve length field of cookie */
                if( ext_size >= 2 )
                {
                    cookie = (unsigned char *) ( ext + 4 );
                    cookie_len = MBEDTLS_GET_UINT16_BE( cookie, 0 );
                    cookie += 2;
                }
                else
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad HRR message - cookie length mismatch" ) );
                    return( MBEDTLS_ERR_SSL_DECODE_ERROR );
                }

                if( ( cookie_len + 2 ) != ext_size )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad HRR message - cookie length mismatch" ) );
                    return( MBEDTLS_ERR_SSL_DECODE_ERROR );
                }

                MBEDTLS_SSL_DEBUG_BUF( 3, "cookie extension", cookie, cookie_len );

                mbedtls_free( ssl->handshake->verify_cookie );

                ssl->handshake->verify_cookie = mbedtls_calloc( 1, cookie_len );
                if( ssl->handshake->verify_cookie == NULL )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc failed ( %" MBEDTLS_PRINTF_SIZET " bytes )", cookie_len ) );
                    return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
                }

                memcpy( ssl->handshake->verify_cookie, cookie, cookie_len );
                ssl->handshake->verify_cookie_len = (unsigned char) cookie_len;
                break;
#endif /* MBEDTLS_SSL_COOKIE_C */

            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported_versions extension" ) );

                ret = ssl_tls13_parse_supported_versions_ext( ssl, ext + 4, ext + 4 + ext_size );
                if( ret != 0 )
                    return( ret );
                break;

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_KEY_SHARE:
            {
                /* Variables for parsing the key_share */
                const uint16_t *group_list;
                const mbedtls_ecp_curve_info *curve_info = NULL;
                int tls_id;
                int found = 0;

                MBEDTLS_SSL_DEBUG_BUF( 3, "key_share extension", ext + 4, ext_size );

                /* Read selected_group */
                tls_id = MBEDTLS_GET_UINT16_BE( ext, 4 );
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "selected_group ( %d )", tls_id ) );

                /* Upon receipt of this extension in a HelloRetryRequest, the
                 * client MUST first verify that the selected_group field
                 * corresponds to a group which was provided in the
                 * "supported_groups" extension in the original ClientHello.
                 * The supported_group was based on the configured list of
                 * groups.
                 *
                 * If the server provided a key share that was not sent in the
                 * ClientHello then the client MUST abort the handshake with an
                 * "illegal_parameter" alert. */
                for( group_list = mbedtls_ssl_get_groups( ssl );
                     *group_list != 0; group_list++ )
                {
                    if( !mbedtls_ssl_tls13_named_group_is_ecdhe( *group_list ) )
                        continue;

                    curve_info =
                        mbedtls_ecp_curve_info_from_tls_id( *group_list );

                    if( ( curve_info == NULL ) ||
                        ( curve_info->tls_id != tls_id ) )
                        continue;

                    /* We found a match */
                    found = 1;
                    break;
                }

                /* Client MUST verify that the selected_group field does not
                 * correspond to a group which was provided in the "key_share"
                 * extension in the original ClientHello. If the server sent an
                 * HRR message with a key share already provided in the
                 * ClientHello then the client MUST abort the handshake with
                 * an "illegal_parameter" alert. */
                if( found == 0 || tls_id == ssl->handshake->offered_group_id )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid key share in HRR" ) );
                    MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                                  MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
                    return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
                }

                /* Remember server's preference for next ClientHello */
                ssl->handshake->offered_group_id = tls_id;
                break;
            }

#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */
            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown extension found: %d ( ignoring )", ext_id ) );
        }

        /* Jump to next extension */
        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

    }

    return( 0 );
}

static int ssl_tls13_finalize_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_key_set traffic_keys;
    mbedtls_ssl_transform *transform_handshake = NULL;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Determine the key exchange mode:
     * 1) If both the pre_shared_key and key_share extensions were received
     *    then the key exchange mode is PSK with EPHEMERAL.
     * 2) If only the pre_shared_key extension was received then the key
     *    exchange mode is PSK-only.
     * 3) If only the key_share extension was received then the key
     *    exchange mode is EPHEMERAL-only.
     */
    switch( handshake->extensions_present &
            ( MBEDTLS_SSL_EXT_PRE_SHARED_KEY | MBEDTLS_SSL_EXT_KEY_SHARE ) )
    {
        /* Only the pre_shared_key extension was received */
        case MBEDTLS_SSL_EXT_PRE_SHARED_KEY:
            handshake->key_exchange = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
            break;

        /* Only the key_share extension was received */
        case MBEDTLS_SSL_EXT_KEY_SHARE:
            handshake->key_exchange = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
            break;

        /* Both the pre_shared_key and key_share extensions were received */
        case ( MBEDTLS_SSL_EXT_PRE_SHARED_KEY | MBEDTLS_SSL_EXT_KEY_SHARE ):
            handshake->key_exchange = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
            break;

        /* Neither pre_shared_key nor key_share extension was received */
        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unknown key exchange." ) );
            ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            goto cleanup;
    }

    /* Start the TLS 1.3 key schedule: Set the PSK and derive early secret.
     *
     * TODO: We don't have to do this in case we offered 0-RTT and the
     *       server accepted it. In this case, we could skip generating
     *       the early secret. */
    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_key_schedule_stage_early_data",
                               ret );
        goto cleanup;
    }

    /* Compute handshake secret */
    ret = mbedtls_ssl_tls13_key_schedule_stage_handshake( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_derive_master_secret", ret );
        goto cleanup;
    }

    /* Next evolution in key schedule: Establish handshake secret and
     * key material. */
    ret = mbedtls_ssl_tls13_generate_handshake_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_generate_handshake_keys",
                               ret );
        goto cleanup;
    }

    transform_handshake = mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_handshake == NULL )
    {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_populate_transform( transform_handshake,
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
    handshake->transform_handshake = transform_handshake;
    mbedtls_ssl_set_inbound_transform( ssl, transform_handshake );
#else /* MBEDTLS_SSL_USE_MPS */
    ret = mbedtls_mps_add_key_material( &ssl->mps->l4,
                                        transform_handshake,
                                        &handshake->epoch_handshake );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_mps_set_incoming_keys( &ssl->mps->l4,
                                         handshake->epoch_handshake );
    if( ret != 0 )
        return( ret );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to handshake keys for inbound traffic" ) );
    ssl->session_in = ssl->session_negotiate;

    /*
     * State machine update
     */
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );

cleanup:

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );
    if( ret != 0 )
    {
        mbedtls_free( transform_handshake );

        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
            MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( ret );
}
static int ssl_tls13_hrr_postprocess( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ssl->handshake->hello_retry_requests_received > 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Multiple HRRs received" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                      MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    ssl->handshake->hello_retry_requests_received++;

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    /* If not offering early data, the client sends a dummy CCS record
     * immediately before its second flight. This may either be before
     * its second ClientHello or before its encrypted handshake flight. */
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    mbedtls_ssl_session_reset_msg_layer( ssl, 0 );

    /* Reset everything that's going to be re-generated in the new ClientHello.
     *
     * Currently, we're always resetting the key share, even if the server
     * was fine with it. Once we have separated key share generation from
     * key share writing, we can confine this to the case where the server
     * requested a different share. */
    ret = ssl_tls13_reset_key_share( ssl );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

/*
 * Wait and parse ServerHello handshake message.
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 */
static int ssl_tls13_process_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_mps_handshake_in msg;
#endif
    unsigned char *buf = NULL;
    size_t buf_len = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> %s", __func__ ) );

    /* Coordination step
     * - Fetch record
     * - Make sure it's either a ServerHello or a HRR.
     * - Switch processing routine in case of HRR
     */

    ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

#if defined(MBEDTLS_SSL_USE_MPS)
    ret = ssl_tls13_server_hello_coordinate( ssl, &msg, &buf, &buf_len );
#else /* MBEDTLS_SSL_USE_MPS */
    ret = ssl_tls13_server_hello_coordinate( ssl, &buf, &buf_len );
#endif /* MBEDTLS_SSL_USE_MPS */

    /* Parsing step
     * We know what message to expect by now and call
     * the respective parsing function.
     */

    if( ret == SSL_SERVER_HELLO_COORDINATE_HELLO )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_server_hello( ssl, buf,
                                                            buf + buf_len ) );
        mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl,
                                                  MBEDTLS_SSL_HS_SERVER_HELLO,
                                                  buf, buf_len );

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit( msg.handle ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps->l4  ) );
#endif /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_server_hello( ssl ) );
    }
    else if( ret == SSL_SERVER_HELLO_COORDINATE_HRR )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_hrr_parse( ssl, buf, buf_len ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_reset_transcript_for_hrr( ssl ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl,
                                                  MBEDTLS_SSL_HS_SERVER_HELLO,
                                                  buf, buf_len );

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit( msg.handle ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps->l4  ) );
#endif /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_hrr_postprocess( ssl ) );
    }


cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= %s", __func__ ) );
    return( ret );
}

/*
 *
 * EncryptedExtensions message
 *
 * The EncryptedExtensions message contains any extensions which
 * should be protected, i.e., any which are not needed to establish
 * the cryptographic context.
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
static int ssl_tls13_process_encrypted_extensions( mbedtls_ssl_context *ssl );

static int ssl_tls13_parse_encrypted_extensions( mbedtls_ssl_context *ssl,
                                                 const unsigned char *buf,
                                                 const unsigned char *end );
static int ssl_tls13_postprocess_encrypted_extensions( mbedtls_ssl_context *ssl );


/*
 * Handler for  MBEDTLS_SSL_ENCRYPTED_EXTENSIONS
 */
static int ssl_tls13_process_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse encrypted extensions" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg( ssl,
                                             MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                                             &buf, &buf_len ) );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK(
        ssl_tls13_parse_encrypted_extensions( ssl, buf, buf + buf_len ) );

    mbedtls_ssl_tls13_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS, buf, buf_len );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_encrypted_extensions( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse encrypted extensions" ) );
    return( ret );

}

/* Parse EncryptedExtensions message
 * struct {
 *     Extension extensions<0..2^16-1>;
 * } EncryptedExtensions;
 */
static int ssl_tls13_parse_encrypted_extensions( mbedtls_ssl_context *ssl,
                                                 const unsigned char *buf,
                                                 const unsigned char *end )
{
    int ret = 0;
    size_t extensions_len;
    const unsigned char *p = buf;
    const unsigned char *extensions_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    MBEDTLS_SSL_DEBUG_BUF( 3, "encrypted extensions", p, extensions_len );
    extensions_end = p + extensions_len;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;

        /*
         * struct {
         *     ExtensionType extension_type; (2 bytes)
         *     opaque extension_data<0..2^16-1>;
         * } Extension;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );

        /* The client MUST check EncryptedExtensions for the
         * presence of any forbidden extensions and if any are found MUST abort
         * the handshake with an "unsupported_extension" alert.
         */
        switch( extension_type )
        {

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
            case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found max_fragment_length extension" ) );

                ret = ssl_tls13_parse_max_fragment_length_ext( ssl, p,
                                                               extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_parse_max_fragment_length_ext", ret );
                    return( ret );
                }

                break;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found extensions supported groups" ) );
                break;

#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found alpn extension" ) );

                ret = ssl_tls13_parse_alpn_ext( ssl, p, extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_parse_alpn_ext", ret );
                    return( ret );
                }

                break;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
            case MBEDTLS_TLS_EXT_SERVERNAME:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found server_name extension" ) );

                /* The server_name extension should be an empty extension */

                break;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_ZERO_RTT)
            case MBEDTLS_TLS_EXT_EARLY_DATA:
                MBEDTLS_SSL_DEBUG_MSG(3, ( "found early_data extension" ));

                ret = ssl_tls13_parse_encrypted_extensions_early_data_ext(
                    ssl, p, extension_data_len );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_parse_encrypted_extensions_early_data_ext", ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_ZERO_RTT */

            default:
                MBEDTLS_SSL_DEBUG_MSG(
                    3, ( "unsupported extension found: %u ", extension_type) );
                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,   \
                    MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
                return ( MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
                break;
        }

        p += extension_data_len;
    }

    /* Check that we consumed all the message. */
    if( p != end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "EncryptedExtension lengths misaligned" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,   \
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    return( ret );
}

static int ssl_tls13_postprocess_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );
    return( 0 );
}

/*
 *
 * STATE HANDLING: Write Early-Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_tls13_write_early_data_process( mbedtls_ssl_context *ssl );

#define SSL_EARLY_DATA_WRITE 0
#define SSL_EARLY_DATA_SKIP  1
static int ssl_tls13_write_early_data_coordinate( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_tls13_write_early_data_prepare( mbedtls_ssl_context *ssl );

/* Write early-data message */
static int ssl_tls13_write_early_data_write( mbedtls_ssl_context *ssl,
    unsigned char *buf,
    size_t buf_len,
    size_t *out_len );
#endif /* MBEDTLS_ZERO_RTT */

/* Update the state after handling the outgoing early-data message. */
static int ssl_tls13_write_early_data_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

int ssl_tls13_write_early_data_process( mbedtls_ssl_context *ssl )
{
    int ret;
#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_writer *msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#endif /* MBEDTLS_SSL_USE_MPS */
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write early data" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_early_data_coordinate( ssl ) );
    if( ret == SSL_EARLY_DATA_WRITE )
    {
#if defined(MBEDTLS_ZERO_RTT)

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_early_data_prepare( ssl ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_application( &ssl->mps->l4,
                                                             &msg ) );

        /* Request write-buffer */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get( msg, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_early_data_write(
                                  ssl, buf, buf_len, &msg_len ) );

        /* Commit message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial( msg,
                                                             buf_len - msg_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps->l4 ) );

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_early_data_postprocess( ssl ) );

#else  /* MBEDTLS_SSL_USE_MPS */

        /* Write early-data to message buffer. */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_early_data_write( ssl, ssl->out_msg,
                                                                MBEDTLS_SSL_OUT_CONTENT_LEN,
                                                                &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_early_data_postprocess( ssl ) );

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) );

#endif /* MBEDTLS_SSL_USE_MPS */

#else /* MBEDTLS_ZERO_RTT */
        ((void) buf);
        ((void) buf_len);
        ((void) msg);
        ((void) msg_len);
        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#endif /* MBEDTLS_ZERO_RTT */
    }
    else
    {
        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_early_data_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write early data" ) );
    return( ret );
}

#if defined(MBEDTLS_ZERO_RTT)

static int ssl_tls13_write_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_EARLY_DATA_SKIP );

    return( SSL_EARLY_DATA_WRITE );
}

static int ssl_tls13_write_early_data_prepare( mbedtls_ssl_context *ssl )
{
    int ret;
    mbedtls_ssl_key_set traffic_keys;

    const unsigned char *psk;
    size_t psk_len;
    const unsigned char *psk_identity;
    size_t psk_identity_len;

    mbedtls_ssl_transform *transform_earlydata;

    /* From RFC 8446:
     * "The PSK used to encrypt the
     *  early data MUST be the first PSK listed in the client's
     *  'pre_shared_key' extension."
     */

    if( mbedtls_ssl_get_psk_to_offer( ssl, &psk, &psk_len,
                                      &psk_identity, &psk_identity_len ) != 0 )
    {
        /* This should never happen: We can only have gone past
         * ssl_tls13_write_early_data_coordinate() if we have offered a PSK. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ( ret = mbedtls_ssl_set_hs_psk( ssl, psk, psk_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_set_hs_psk", ret );
        return( ret );
    }

    /* Start the TLS 1.3 key schedule: Set the PSK and derive early secret. */
    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
             "mbedtls_ssl_tls13_key_schedule_stage_early", ret );
        return( ret );
    }

    /* Derive 0-RTT key material */
    ret = mbedtls_ssl_tls13_generate_early_data_keys(
        ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
            "mbedtls_ssl_tls13_generate_early_data_keys", ret );
        return( ret );
    }

    transform_earlydata =
        mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_earlydata == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    ret = mbedtls_ssl_tls13_populate_transform(
                          transform_earlydata,
                          ssl->conf->endpoint,
                          ssl->session_negotiate->ciphersuite,
                          &traffic_keys,
                          ssl );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_SSL_USE_MPS)
    /* Register transform with MPS. */
    ret = mbedtls_mps_add_key_material( &ssl->mps->l4,
                                        transform_earlydata,
                                        &ssl->handshake->epoch_earlydata );
    if( ret != 0 )
        return( ret );

    /* Use new transform for outgoing data. */
    ret = mbedtls_mps_set_outgoing_keys( &ssl->mps->l4,
                                         ssl->handshake->epoch_earlydata );
    if( ret != 0 )
        return( ret );
#else /* MBEDTLS_SSL_USE_MPS */

    /* Activate transform */
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to 0-RTT keys for outbound traffic" ) );
    ssl->handshake->transform_earlydata = transform_earlydata;
    mbedtls_ssl_set_outbound_transform( ssl, ssl->handshake->transform_earlydata );

#endif /* MBEDTLS_SSL_USE_MPS */

    return( 0 );
}

static int ssl_tls13_write_early_data_write( mbedtls_ssl_context *ssl,
    unsigned char *buf,
    size_t buf_len,
    size_t *out_len )
{
    if( ssl->early_data_len > buf_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }
    else
    {
        memcpy( buf, ssl->early_data_buf, ssl->early_data_len );

#if defined(MBEDTLS_SSL_USE_MPS)
        *out_len = ssl->early_data_len;
        MBEDTLS_SSL_DEBUG_BUF( 3, "Early Data", buf, ssl->early_data_len );
#else
        buf[ssl->early_data_len] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
        *out_len = ssl->early_data_len + 1;

        MBEDTLS_SSL_DEBUG_BUF( 3, "Early Data", ssl->out_msg, *out_len );
#endif /* MBEDTLS_SSL_USE_MPS */
    }

    return( 0 );
}

#else /* MBEDTLS_ZERO_RTT */

static int ssl_tls13_write_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( SSL_EARLY_DATA_SKIP );
}

#endif /* MBEDTLS_ZERO_RTT */

static int ssl_tls13_write_early_data_postprocess( mbedtls_ssl_context *ssl )
{
    /* Clear PSK we've used for the 0-RTT. */
    mbedtls_ssl_remove_hs_psk( ssl );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    return ( 0 );
}

/*
 *
 * STATE HANDLING: Write End-of-Early-Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_tls13_write_end_of_early_data_process( mbedtls_ssl_context *ssl );

#define SSL_END_OF_EARLY_DATA_WRITE 0
#define SSL_END_OF_EARLY_DATA_SKIP  1
static int ssl_tls13_write_end_of_early_data_coordinate( mbedtls_ssl_context *ssl );

/* Update the state after handling the outgoing end-of-early-data message. */
static int ssl_tls13_write_end_of_early_data_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

int ssl_tls13_write_end_of_early_data_process( mbedtls_ssl_context *ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write EndOfEarlyData" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_write_end_of_early_data_coordinate( ssl ) );
    if( ret == SSL_END_OF_EARLY_DATA_WRITE )
    {
        unsigned char *buf;
        size_t buf_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg( ssl,
                          MBEDTLS_SSL_HS_END_OF_EARLY_DATA, &buf, &buf_len ) );

        mbedtls_ssl_tls13_add_hs_hdr_to_checksum(
            ssl, MBEDTLS_SSL_HS_END_OF_EARLY_DATA, 0 );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_end_of_early_data_postprocess( ssl ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg( ssl, buf_len, 0 ) );
    }
    else
    {
        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_end_of_early_data_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write EndOfEarlyData" ) );
    return( ret );
}

static int ssl_tls13_write_end_of_early_data_coordinate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);

#if defined(MBEDTLS_ZERO_RTT)
    if( ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON )
    {
        if( ssl->early_data_status == MBEDTLS_SSL_EARLY_DATA_ACCEPTED )
            return( SSL_END_OF_EARLY_DATA_WRITE );

        /*
         * RFC 8446:
         * "If the server does not send an "early_data"
         *  extension in EncryptedExtensions, then the client MUST NOT send an
         *  EndOfEarlyData message."
         */

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "skip EndOfEarlyData, server rejected" ) );
    }
#endif /* MBEDTLS_ZERO_RTT */

    return( SSL_END_OF_EARLY_DATA_SKIP );
}

static int ssl_tls13_write_end_of_early_data_postprocess( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    mbedtls_ssl_handshake_set_state( ssl,
                        MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CERTIFICATE_REQUEST
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
static int ssl_tls13_process_certificate_request( mbedtls_ssl_context *ssl );

/* Coordination:
 * Deals with the ambiguity of not knowing if a CertificateRequest
 * will be sent. Returns a negative code on failure, or
 * - SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST
 * - SSL_CERTIFICATE_REQUEST_SKIP
 * indicating if a Certificate Request is expected or not.
 */
#define SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST 0
#define SSL_CERTIFICATE_REQUEST_SKIP    1
static int ssl_tls13_certificate_request_coordinate( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_tls13_certificate_request_parse( mbedtls_ssl_context *ssl,
                                                unsigned char const *buf,
                                                size_t buf_len );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
static int ssl_tls13_certificate_request_postprocess( mbedtls_ssl_context *ssl );

/*
 * Implementation
 */

/* Main entry point; orchestrates the other functions */
static int ssl_tls13_process_certificate_request( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate request" ) );

    /* Coordination step
     * - Fetch record
     * - Make sure it's either a CertificateRequest or a ServerHelloDone
     */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_certificate_request_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    if( ret == SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST )
    {
        unsigned char *buf;
        size_t buf_len;

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                                  ssl, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                                  &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_certificate_request_parse( ssl, buf, buf_len ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST, buf, buf_len );
#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif
    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
    if( ret == SSL_CERTIFICATE_REQUEST_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate request" ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_certificate_request_postprocess( ssl ) );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "got %s certificate request",
                                ssl->client_auth ? "a" : "no" ) );

cleanup:

    /* In the MPS one would close the read-port here to
     * ensure there's no overlap of reading and writing. */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate request" ) );
    return( ret );
}

#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_tls13_certificate_request_coordinate( mbedtls_ssl_context *ssl )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= skip parse certificate request" ) );
        return( SSL_CERTIFICATE_REQUEST_SKIP );
    }

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps->l4 ) );
    if( ret != MBEDTLS_MPS_MSG_HS )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps->l4, &msg ) );

    if( msg.type == MBEDTLS_SSL_HS_CERTIFICATE_REQUEST )
        return( SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST );

    return( SSL_CERTIFICATE_REQUEST_SKIP );

cleanup:
    return( ret);
}

#else /* MBEDTLS_SSL_USE_MPS */

static int ssl_tls13_certificate_request_coordinate( mbedtls_ssl_context *ssl )
{
    int ret;

    if( mbedtls_ssl_tls13_kex_with_psk( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= skip parse certificate request" ) );
        return( SSL_CERTIFICATE_REQUEST_SKIP );
    }

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }
    ssl->keep_current_message = 1;

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] == MBEDTLS_SSL_HS_CERTIFICATE_REQUEST )
    {
        return( SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST );
    }

    return( SSL_CERTIFICATE_REQUEST_SKIP );
}
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_tls13_certificate_request_parse( mbedtls_ssl_context *ssl,
                                                const unsigned char *buf,
                                                size_t buf_len )
{
    int ret;
    const unsigned char *p;
    const unsigned char *ext;
    size_t ext_len = 0;
    size_t context_len = 0;

    if( buf_len < 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /*
     * struct {
     *   opaque certificate_request_context<0..2^8-1>;
     *   Extension extensions<2..2^16-1>;
     * } CertificateRequest;
     */

    p = buf;

    /*
     * Parse certificate_request_context
     */
    context_len = (size_t) p[0];

    /* skip context_len */
    p++;

    /* Fixed length fields are:
     *  - 1 for length of context
     *  - 2 for length of extensions
     * -----
     *    3 bytes
     */

    if( buf_len < (size_t) ( 3 + context_len ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* store context ( if necessary ) */
    if( context_len > 0 )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Certificate Request Context",
            p, context_len );

        ssl->handshake->certificate_request_context =
          mbedtls_calloc( context_len, 1 );
        if( ssl->handshake->certificate_request_context == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
            return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
        }
        memcpy( ssl->handshake->certificate_request_context, p, context_len );

        /* jump over certificate_request_context */
        p += context_len;
    }

    /*
     * Parse extensions
     */
    ext_len = MBEDTLS_GET_UINT16_BE( p, 0 );

    /* At least one extension needs to be present,
     * namely signature_algorithms ext. */
    if( ext_len < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* skip total extension length */
    p += 2;

    ext = p; /* jump to extensions */
    while( ext_len )
    {
        size_t ext_id = MBEDTLS_GET_UINT16_BE( ext, 0 );
        size_t ext_size = MBEDTLS_GET_UINT16_BE( ext, 2 );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        switch( ext_id )
        {
            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                    ( "found signature_algorithms extension" ) );

                if( ( ret = mbedtls_ssl_tls13_parse_signature_algorithms_ext(
                        ssl, ext + 4, (size_t) ext_size ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                        "mbedtls_ssl_tls13_parse_signature_algorithms_ext", ret );
                    MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                                  ret );
                    return( ret );
                }
                break;

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                    ( "unknown extension found: %" MBEDTLS_PRINTF_SIZET " ( ignoring )", ext_id ) );
                break;
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }
    }

    ssl->client_auth = 1;
    return( 0 );
}
#endif /* ( MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ) */


static int ssl_tls13_certificate_request_postprocess( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CERTIFICATE );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_SERVER_CERTIFICATE
 */
static int ssl_tls13_process_server_certificate( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_process_certificate( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CERTIFICATE_VERIFY
 */
static int ssl_tls13_process_certificate_verify( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_process_certificate_verify( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_SERVER_FINISHED
 */
static int ssl_tls13_process_server_finished( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_process_finished_message( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_END_OF_EARLY_DATA );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_CERTIFICATE
 */
static int ssl_tls13_write_client_certificate( mbedtls_ssl_context *ssl )
{
    return( mbedtls_ssl_tls13_write_certificate_process( ssl ) );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY
 */
static int ssl_tls13_write_client_certificate_verify( mbedtls_ssl_context *ssl )
{
    return( mbedtls_ssl_tls13_write_certificate_verify_process( ssl ) );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_FINISHED
 */
static int ssl_tls13_write_client_finished( mbedtls_ssl_context *ssl )
{
    return( mbedtls_ssl_tls13_write_finished_message( ssl ) );
}

/*
 * Handler for MBEDTLS_SSL_FLUSH_BUFFERS
 */
static int ssl_tls13_flush_buffers( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake: done" ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_HANDSHAKE_WRAPUP
 */
static int ssl_tls13_handshake_wrapup( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for inbound traffic" ) );
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for outbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
    int ret = 0;

    ret = mbedtls_mps_set_incoming_keys( &ssl->mps->l4,
                                                 ssl->epoch_application );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_mps_set_outgoing_keys( &ssl->mps->l4,
                                         ssl->epoch_application );
    if( ret != 0 )
        return( ret );
#else
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for inbound traffic" ) );
    mbedtls_ssl_set_inbound_transform ( ssl, ssl->transform_application );

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for outbound traffic" ) );
    mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_application );
#endif /* MBEDTLS_SSL_USE_MPS */

    mbedtls_ssl_tls13_handshake_wrapup( ssl );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );

    return( 0 );
}

/*
 *
 * Handler for MBEDTLS_SSL_CLIENT_NEW_SESSION_TICKET
 *
 */

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

static int ssl_tls13_new_session_ticket_early_data_ext_parse(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, size_t ext_size )
{
    /* From RFC 8446:
     *
     * struct {
     *         select (Handshake.msg_type) {
     *            case new_session_ticket:   uint32 max_early_data_size;
     *            case client_hello:         Empty;
     *            case encrypted_extensions: Empty;
     *        };
     *    } EarlyDataIndication;
     */

    if( ext_size == 4 && ssl->session != NULL )
    {
        ssl->session->max_early_data_size = MBEDTLS_GET_UINT32_BE( buf, 0 );
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->max_early_data_size: %u",
                                    ssl->session->max_early_data_size ) );
        ssl->session->ticket_flags |= allow_early_data;
        return( 0 );
    }

    return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
}

static int ssl_tls13_new_session_ticket_extensions_parse(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, size_t buf_remain )
{
    int ret;
    unsigned int ext_id;
    size_t ext_size;

    while( buf_remain != 0 )
    {
        if( buf_remain < 4 )
        {
            /* TODO: Replace with DECODE_ERROR once we have merged 3.0 */
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }

        ext_id   = MBEDTLS_GET_UINT16_BE( buf, 0 );
        ext_size = MBEDTLS_GET_UINT16_BE( buf, 2 );

        buf        += 4;
        buf_remain -= 4;

        if( ext_size > buf_remain )
        {
            /* TODO: Replace with DECODE_ERROR once we have merged 3.0 */
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }

        if( ext_id == MBEDTLS_TLS_EXT_EARLY_DATA )
        {
            ret = ssl_tls13_new_session_ticket_early_data_ext_parse( ssl, buf,
                                                                     ext_size );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_new_session_ticket_early_data_ext_parse", ret );
                return( ret );
            }
        }
        /* Ignore other extensions */

        buf        += ext_size;
        buf_remain -= ext_size;
    }

    return( 0 );
}

static int ssl_tls13_new_session_ticket_parse( mbedtls_ssl_context *ssl,
                                               unsigned char *buf,
                                               size_t buf_len )
{
    int ret;
    size_t ticket_len, ext_len;
    unsigned char *ticket;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    size_t used = 0, i = 0;
    int hash_length;
    size_t ticket_nonce_len;
    unsigned char ticket_nonce[256];

    /*
     * struct {
     *    uint32 ticket_lifetime;
     *    uint32 ticket_age_add;
     *    opaque ticket_nonce<0..255>;
     *    opaque ticket<1..2^16-1>;
     *    Extension extensions<0..2^16-2>;
     * } NewSessionTicket;
     *
     */
    used += 4   /* ticket_lifetime */
          + 4   /* ticket_age_add */
          + 1   /* ticket_nonce length */
          + 2   /* ticket length */
          + 2;  /* extension length */

    if( used > buf_len )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* Ticket lifetime */
    ssl->session->ticket_lifetime = MBEDTLS_GET_UINT32_BE( buf, i );
    i += 4;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->lifetime: %u",
                                ssl->session->ticket_lifetime ) );

    /* Ticket Age Add */
    ssl->session->ticket_age_add = MBEDTLS_GET_UINT32_BE( buf, i );
    i += 4;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->ticket_age_add: %u",
                                ssl->session->ticket_age_add ) );

    ticket_nonce_len = buf[i];
    i++;

    used += ticket_nonce_len;

    if( used > buf_len )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    if( ticket_nonce_len > 0 )
    {
        if( ticket_nonce_len > sizeof( ticket_nonce )  )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "ticket_nonce is too small" ) );
            return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        memcpy( ticket_nonce, &buf[i], ticket_nonce_len );

        MBEDTLS_SSL_DEBUG_BUF( 3, "nonce:", &buf[i],
                               ticket_nonce_len );

    }
    i += ticket_nonce_len;

    /* Ticket */
    ticket_len = MBEDTLS_GET_UINT16_BE( buf, i );
    i += 2;

    used += ticket_len;

    if( used > buf_len )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->length: %" MBEDTLS_PRINTF_SIZET , ticket_len ) );

    /* Check if we previously received a ticket already. */
    if( ssl->session->ticket != NULL || ssl->session->ticket_len > 0 )
    {
        mbedtls_free( ssl->session->ticket );
        ssl->session->ticket = NULL;
        ssl->session->ticket_len = 0;
    }

    if( ( ticket = mbedtls_calloc( 1, ticket_len ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ticket alloc failed" ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    memcpy( ticket, buf + i, ticket_len );
    i += ticket_len;
    ssl->session->ticket = ticket;
    ssl->session->ticket_len = ticket_len;

    MBEDTLS_SSL_DEBUG_BUF( 4, "ticket", ticket, ticket_len );


    /* Ticket Extension */
    ext_len = MBEDTLS_GET_UINT16_BE( buf, i );
    i += 2;

    used += ext_len;
    if( used != buf_len )
    {
         MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad new session ticket message" ) );
         return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "ticket->extension", &buf[i], ext_len );

    ret = ssl_tls13_new_session_ticket_extensions_parse( ssl, &buf[i], ext_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_new_session_ticket_extensions_parse", ret );
        return( ret );
    }
    i += ext_len;

    /* Compute PSK based on received nonce and resumption_master_secret
     * in the following style:
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session->ciphersuite );

    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    hash_length = mbedtls_hash_size_for_ciphersuite( suite_info );

    if( hash_length == -1 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    MBEDTLS_SSL_DEBUG_BUF( 3, "resumption_master_secret",
                           ssl->session->app_secrets.resumption_master_secret,
                           hash_length );

    /* Computer resumption key
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */
    ret = mbedtls_ssl_tls13_hkdf_expand_label( suite_info->mac,
                    ssl->session->app_secrets.resumption_master_secret,
                    hash_length,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( resumption ),
                    ticket_nonce,
                    ticket_nonce_len,
                    ssl->session->key,
                    hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the ticket-resumed PSK failed", ret );
        return( ret );
    }

    ssl->session->key_len = hash_length;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Ticket-resumed PSK", ssl->session->key,
                           ssl->session->key_len );

#if defined(MBEDTLS_HAVE_TIME)
    /* Store ticket creation time */
    ssl->session->ticket_received = time( NULL );
#endif

    return( 0 );
}

static int ssl_tls13_new_session_ticket_postprocess( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
    return( 0 );
}

/* The ssl_tls13_new_session_ticket_process( ) function is used by the
 * client to process the NewSessionTicket message, which contains
 * the ticket and meta-data provided by the server in a post-
 * handshake message.
 */

static int ssl_tls13_new_session_ticket_process( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse new session ticket" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                              ssl, MBEDTLS_SSL_HS_NEW_SESSION_TICKET,
                              &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_new_session_ticket_parse( ssl, buf, buf_len ) );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_new_session_ticket_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse new session ticket" ) );
    return( ret );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

/*
 * TLS and DTLS 1.3 State Maschine -- client side
 */
int mbedtls_ssl_tls13_handshake_client_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Handshake completed but ssl->handshake is NULL.\n" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls13 client state: %s(%d)",
                                mbedtls_ssl_states_str( ssl->state ),
                                ssl->state ) );

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        return( ret );

    switch( ssl->state )
    {
        case MBEDTLS_SSL_HELLO_REQUEST:
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
            break;

        /*
         *  ==>   ClientHello
         *        (EarlyData)
         */
        case MBEDTLS_SSL_CLIENT_HELLO:
            ret = ssl_tls13_write_client_hello( ssl );
            break;

        case MBEDTLS_SSL_EARLY_APP_DATA:
            ret = ssl_tls13_write_early_data_process( ssl );
            break;

        /*
         *  <==   ServerHello / HelloRetryRequest
         *        EncryptedExtensions
         *        (CertificateRequest)
         *        (Certificate)
         *        (CertificateVerify)
         *        Finished
         */
        case MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_tls13_process_server_hello( ssl );
            break;

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls13_process_encrypted_extensions( ssl );
            break;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_tls13_process_certificate_request( ssl );
            break;

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = ssl_tls13_process_server_certificate( ssl );
            break;

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = ssl_tls13_process_certificate_verify( ssl );
            break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = ssl_tls13_process_server_finished( ssl );
            break;

        /*
         *  ==>   (EndOfEarlyData)
         *        (Certificate)
         *        (CertificateVerify)
         *        (Finished)
         */
        case MBEDTLS_SSL_END_OF_EARLY_DATA:
            ret = ssl_tls13_write_end_of_early_data_process( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = ssl_tls13_write_client_certificate( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
            ret = ssl_tls13_write_client_certificate_verify( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_FINISHED:
            ret = ssl_tls13_write_client_finished( ssl );
            break;

        /*
         *  <==   NewSessionTicket
         */
        case MBEDTLS_SSL_CLIENT_NEW_SESSION_TICKET:

            ret = ssl_tls13_new_session_ticket_process( ssl );
            if( ret != 0 )
                break;

            ret = MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
            break;

        /*
         * Injection of dummy-CCS's for middlebox compatibility
         */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO:
        case MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO:
        case MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED:
            ret = mbedtls_ssl_tls13_write_change_cipher_spec_process( ssl );
            break;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

        /*
         * Internal intermediate states
         */

        case MBEDTLS_SSL_FLUSH_BUFFERS:
            ret = ssl_tls13_flush_buffers( ssl );
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            ret = ssl_tls13_handshake_wrapup( ssl );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
