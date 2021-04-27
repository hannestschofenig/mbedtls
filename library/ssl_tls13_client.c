/*
 *  TLS 1.3 client-side functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#define SSL_DONT_FORCE_FLUSH 0
#define SSL_FORCE_FLUSH      1

#include "mbedtls/hkdf.h"

#if defined(MBEDTLS_SSL_CLI_C)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "ssl_tls13_keys.h"

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


#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
static int check_ecdh_params( const mbedtls_ssl_context *ssl )
{
    const mbedtls_ecp_curve_info *curve_info;

    curve_info = mbedtls_ecp_curve_info_from_grp_id( ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].grp.id );
    if( curve_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );

#if defined(MBEDTLS_ECP_C)
    if( mbedtls_ssl_check_curve( ssl, ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].grp.id ) != 0 )
#else
    if( ssl->handshake->ecdh_ctx.grp.nbits < 163 ||
            ssl->handshake->ecdh_ctx.grp.nbits > 521 )
#endif
            return( -1 );

    MBEDTLS_SSL_DEBUG_ECP( 3, "ECDH: Qp", &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].Qp );

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */


/*
 *
 * STATE HANDLING: Write Early-Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_write_early_data_process( mbedtls_ssl_context* ssl );

#define SSL_EARLY_DATA_WRITE 0
#define SSL_EARLY_DATA_SKIP  1
static int ssl_write_early_data_coordinate( mbedtls_ssl_context* ssl );

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_write_early_data_prepare( mbedtls_ssl_context* ssl );

/* Write early-data message */
static int ssl_write_early_data_write( mbedtls_ssl_context* ssl,
    unsigned char* buf,
    size_t buflen,
    size_t* olen );
#endif /* MBEDTLS_ZERO_RTT */

/* Update the state after handling the outgoing early-data message. */
static int ssl_write_early_data_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int ssl_write_early_data_process( mbedtls_ssl_context* ssl )
{
    int ret;
#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_writer *msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#endif /* MBEDTLS_SSL_USE_MPS */
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write early data" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_write_early_data_coordinate( ssl ) );
    if( ret == SSL_EARLY_DATA_WRITE )
    {
#if defined(MBEDTLS_ZERO_RTT)

        MBEDTLS_SSL_PROC_CHK( ssl_write_early_data_prepare( ssl ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_application( &ssl->mps.l4,
                                                             &msg ) );

        /* Request write-buffer */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get( msg, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_write_early_data_write(
                                  ssl, buf, buf_len, &msg_len ) );

        /* Commit message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial( msg,
                                                             buf_len - msg_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

#else  /* MBEDTLS_SSL_USE_MPS */

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* Write early-data to message buffer. */
        MBEDTLS_SSL_PROC_CHK( ssl_write_early_data_write( ssl, ssl->out_msg,
                                                          MBEDTLS_SSL_MAX_CONTENT_LEN,
                                                          &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_record( ssl, SSL_FORCE_FLUSH ) );

#endif /* MBEDTLS_SSL_USE_MPS */

#else /* MBEDTLS_ZERO_RTT */

        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#endif /* MBEDTLS_ZERO_RTT */
    }


    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_write_early_data_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write early data" ) );
    return( ret );
}

#if defined(MBEDTLS_ZERO_RTT)

static int ssl_write_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_EARLY_DATA_SKIP );

    return( SSL_EARLY_DATA_WRITE );
}

static int ssl_write_early_data_prepare( mbedtls_ssl_context* ssl )
{
    int ret;
    mbedtls_ssl_key_set traffic_keys;

    ret = mbedtls_ssl_generate_early_data_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_generate_early_data_keys", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_USE_MPS)
    {
        mbedtls_ssl_transform *transform_earlydata =
            mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
        if( transform_earlydata == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        ret = mbedtls_ssl_tls13_populate_transform(
                              transform_earlydata,
                              ssl->conf->endpoint,
                              ssl->session_negotiate->ciphersuite,
                              &traffic_keys,
                              ssl );

        /* Register transform with MPS. */
        ret = mbedtls_mps_add_key_material( &ssl->mps.l4,
                                            transform_earlydata,
                                            &ssl->epoch_earlydata );
        if( ret != 0 )
            return( ret );

        /* Use new transform for outgoing data. */
        ret = mbedtls_mps_set_outgoing_keys( &ssl->mps.l4,
                                             ssl->epoch_earlydata );
        if( ret != 0 )
            return( ret );
    }

#else /* MBEDTLS_SSL_USE_MPS */

    ret = mbedtls_ssl_tls13_populate_transform(
                              ssl->transform_earlydata,
                              ssl->conf->endpoint,
                              ssl->session_negotiate->ciphersuite,
                              &traffic_keys,
                              ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        return( ret );
    }

    /* Activate transform */
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to 0-RTT keys for outbound traffic" ) );
    mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_earlydata );

#endif /* MBEDTLS_SSL_USE_MPS */

    return( 0 );
}

static int ssl_write_early_data_write( mbedtls_ssl_context* ssl,
    unsigned char* buf,
    size_t buflen,
    size_t* olen )
{
    if ( ssl->conf->early_data_len > buflen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }
    else
    {
        memcpy( buf, ssl->conf->early_data_buf, ssl->conf->early_data_len );

#if !defined(MBEDTLS_SSL_USE_MPS)
        buf[ssl->conf->early_data_len] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
        *olen = ssl->conf->early_data_len + 1;

        MBEDTLS_SSL_DEBUG_BUF( 3, "Early Data", ssl->out_msg, *olen );
#else
        *olen = ssl->conf->early_data_len;
        MBEDTLS_SSL_DEBUG_BUF( 3, "Early Data", buf, ssl->conf->early_data_len );
#endif /* MBEDTLS_SSL_USE_MPS */
    }

    return( 0 );
}

#else /* MBEDTLS_ZERO_RTT */

static int ssl_write_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    ((void) ssl);
    return( SSL_EARLY_DATA_SKIP );
}

#endif /* MBEDTLS_ZERO_RTT */

static int ssl_write_early_data_postprocess( mbedtls_ssl_context* ssl )
{
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
int ssl_write_end_of_early_data_process( mbedtls_ssl_context* ssl );

#define SSL_END_OF_EARLY_DATA_WRITE 0
#define SSL_END_OF_EARLY_DATA_SKIP  1
static int ssl_write_end_of_early_data_coordinate( mbedtls_ssl_context* ssl );

/* Update the state after handling the outgoing end-of-early-data message. */
static int ssl_write_end_of_early_data_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int ssl_write_end_of_early_data_process( mbedtls_ssl_context* ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write EndOfEarlyData" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_write_end_of_early_data_coordinate( ssl ) );
    if( ret == SSL_END_OF_EARLY_DATA_WRITE )
    {
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_handshake_out msg;
        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

        msg.type   = MBEDTLS_SSL_HS_END_OF_EARLY_DATA;
        msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                           &msg, NULL, NULL ) );

        /* EndOfEarlyData message is empty */

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

        mbedtls_ssl_add_hs_hdr_to_checksum(
            ssl, MBEDTLS_SSL_HS_END_OF_EARLY_DATA, 0 );

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_write_end_of_early_data_postprocess( ssl ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

#else  /* MBEDTLS_SSL_USE_MPS */

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* EndOfEarlyData message is empty */

        ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
        ssl->out_msg[0]  = MBEDTLS_SSL_HS_END_OF_EARLY_DATA;
        ssl->out_msglen  = 4;

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_write_end_of_early_data_postprocess( ssl ) );

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */

    }
    else
    {
        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_write_end_of_early_data_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write EndOfEarlyData" ) );
    return( ret );
}

static int ssl_write_end_of_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    ((void) ssl);

#if defined(MBEDTLS_ZERO_RTT)
    if( ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_END_OF_EARLY_DATA_WRITE );
#endif /* MBEDTLS_ZERO_RTT */

    return( SSL_END_OF_EARLY_DATA_SKIP );
}

static int ssl_write_end_of_early_data_postprocess( mbedtls_ssl_context* ssl )
{
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
#if defined(MBEDTLS_ZERO_RTT)
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
#endif /* MBEDTLS_ZERO_RTT */
    {
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED );
        return( 0 );
    }
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
    return ( 0 );
}


#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
static void ssl_write_hostname_ext( mbedtls_ssl_context *ssl,
                                   unsigned char* buf,
                                   unsigned char* end,
                                   size_t* olen )
{
    unsigned char *p = buf;
    size_t hostname_len;

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_pure_ecdhe_enabled( ssl ) )
        return;

    if( ssl->hostname == NULL )
        return;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding server name extension: %s",
                              ssl->hostname ) );

    hostname_len = strlen( ssl->hostname );

    if( end < p || (size_t)( end - p ) < hostname_len + 9 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return;
    }

    /*
     * struct {
     *     NameType name_type;
     *     select ( name_type ) {
     *         case host_name: HostName;
     *     } name;
     * } ServerName;
     *
     * enum {
     *     host_name( 0 ), ( 255 )
     * } NameType;
     *
     * opaque HostName<1..2^16-1>;
     *
     * struct {
     *     ServerName server_name_list<1..2^16-1>
     * } ServerNameList;
     */
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SERVERNAME >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SERVERNAME ) & 0xFF );

    *p++ = (unsigned char)( ( ( hostname_len + 5 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( hostname_len + 5 ) ) & 0xFF );

    *p++ = (unsigned char)( ( ( hostname_len + 3 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( hostname_len + 3 ) ) & 0xFF );

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME ) & 0xFF );
    *p++ = (unsigned char)( ( hostname_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( hostname_len ) & 0xFF );

    memcpy( p, ssl->hostname, hostname_len );

    *olen = hostname_len + 9;
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */


/*
 * ssl_write_supported_versions_ext():
 *
 * struct {
 *      ProtocolVersion versions<2..254>;
 * } SupportedVersions;
 */

static void ssl_write_supported_versions_ext( mbedtls_ssl_context *ssl,
                                             unsigned char* buf,
                                             unsigned char* end,
                                             size_t* olen )
{
    unsigned char *p = buf;

    *olen = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported version extension" ) );

    if( end < p || (size_t)( end - p ) < 7 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return;
    }

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS ) & 0xFF );

    /* total length */
    *p++ = 0x00;
    *p++ = 3;

    /* length of next field */
    *p++ = 0x2;

    /* This implementation only supports a single TLS version, and only
     * advertises a single value.
     */
    mbedtls_ssl_write_version( ssl->conf->max_major_ver, ssl->conf->max_minor_ver,
                              ssl->conf->transport, p );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "supported version: [%d:%d]", ssl->conf->max_major_ver, ssl->conf->max_minor_ver ) );

    *olen = 7;
}

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)

/*
 * ssl_write_max_fragment_length_ext():
 *
 * enum{
 *    2^9( 1 ), 2^10( 2 ), 2^11( 3 ), 2^12( 4 ), ( 255 )
 * } MaxFragmentLength;
 *
 */
static int ssl_write_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                             unsigned char *buf,
                                             size_t buflen,
                                             size_t *olen )
{
    unsigned char *p = buf;
    const unsigned char* end = buf + buflen;

    *olen = 0;

    if( ssl->conf->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE )
    {
        return( 0 );
    }

    if( end < p || (size_t)( end - p ) < 5 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding max_fragment_length extension" ) );

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH ) & 0xFF );

    *p++ = 0x00;
    *p++ = 1;

    *p++ = ssl->conf->mfl_code;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Maximum fragment length = %d", ssl->conf->mfl_code ) );

    *olen = 5;
    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */


#if defined(MBEDTLS_SSL_ALPN)
/*
 * ssl_write_alpn_ext() structure:
 *
 * opaque ProtocolName<1..2^8-1>;
 *
 * struct {
 *     ProtocolName protocol_name_list<2..2^16-1>
 * } ProtocolNameList;
 *
 */
static int ssl_write_alpn_ext( mbedtls_ssl_context *ssl,
                              unsigned char *buf,
                              const unsigned char* end,
                              size_t *olen )
{
    unsigned char *p = buf;
    size_t alpnlen = 0;
    const char **cur;

    *olen = 0;

    if( ssl->conf->alpn_list == NULL )
    {
        return( 0 );
    }

    for ( cur = ssl->conf->alpn_list; *cur != NULL; cur++ )
        alpnlen += (unsigned char)( strlen( *cur ) & 0xFF ) + 1;

    if( end < p || (size_t)( end - p ) < 6 + alpnlen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding alpn extension" ) );

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_ALPN >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_ALPN ) & 0xFF );

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
        *p = (unsigned char)( strlen( *cur ) & 0xFF );
        memcpy( p + 1, *cur, *p );
        p += 1 + *p;
    }

    *olen = p - buf;

    /* List length = olen - 2 ( ext_type ) - 2 ( ext_len ) - 2 ( list_len ) */
    buf[4] = (unsigned char)( ( ( *olen - 6 ) >> 8 ) & 0xFF );
    buf[5] = (unsigned char)( ( *olen - 6 ) & 0xFF );

    /* Extension length = olen - 2 ( ext_type ) - 2 ( ext_len ) */
    buf[2] = (unsigned char)( ( ( *olen - 4 ) >> 8 ) & 0xFF );
    buf[3] = (unsigned char)( ( *olen - 4 ) & 0xFF );

    return( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/*
 * ssl_write_psk_key_exchange_modes_ext() structure:
 *
 * enum { psk_ke( 0 ), psk_dhe_ke( 1 ), ( 255 ) } PskKeyExchangeMode;
 *
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 */

static int ssl_write_psk_key_exchange_modes_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char* buf,
                                                 unsigned char* end,
                                                 size_t* olen )
{
    unsigned char *p;
    int num_modes = 0;

    /* Skip writing extension if no PSK key exchange mode
     * is enabled in the config. */
    if( !mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) )
    {
        *olen = 0;
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
    buf[0] = (unsigned char)( ( MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES >> 8 ) & 0xFF );
    buf[1] = (unsigned char)( ( MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES >> 0 ) & 0xFF );

    /* Skip extension length (2 byte) and PSK mode list length (1 byte) for now. */
    p = buf + 5;

    if( mbedtls_ssl_conf_tls13_pure_psk_enabled( ssl ) )
    {
        *p++ = MBEDTLS_SSL_TLS13_PSK_MODE_PURE;
        num_modes++;

        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Adding pure PSK key exchange mode" ) );
    }

    if( mbedtls_ssl_conf_tls13_psk_ecdhe_enabled( ssl ) )
    {
        *p++ = MBEDTLS_SSL_TLS13_PSK_MODE_ECDHE;
        num_modes++;

        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Adding PSK-ECDHE key exchange mode" ) );
    }

    /* Add extension length: PSK mode list length byte + actual PSK mode list length */
    buf[2] = 0;
    buf[3] = num_modes + 1;
    /* Add PSK mode list length */
    buf[4] = num_modes;

    *olen = p - buf;
    ssl->handshake->extensions_present |= PSK_KEY_EXCHANGE_MODES_EXTENSION;
    return ( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */


/*
 * mbedtls_ssl_write_pre_shared_key_ext() structure:
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

int mbedtls_ssl_write_pre_shared_key_ext( mbedtls_ssl_context *ssl,
                                          unsigned char* buf, unsigned char* end,
                                          size_t *bytes_written,
                                          size_t *total_ext_len,
                                          int part )
{
    int ret;
    unsigned char *p = (unsigned char *) buf;
    const mbedtls_ssl_ciphersuite_t *suite_info;
    const int *ciphersuites;
    int hash_len;
    unsigned char *psk_identity;
    size_t psk_identity_len;
    unsigned char *psk;
    size_t psk_len;

    *total_ext_len = 0;
    *bytes_written = 0;

    if( !mbedtls_ssl_conf_tls13_some_psk_enabled( ssl ) )
        return( 0 );

    /* Check whether we have any PSK credentials configured. */
    if( mbedtls_ssl_get_psk( ssl, (const unsigned char**) &psk, &psk_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, skip pre_shared_key extensions" ) );
        return( 0 );
    }

    /*
     * Ciphersuite list
     */
    ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

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

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
    if( ssl->handshake->resume == 1 )
    {
        psk_identity = ssl->session_negotiate->ticket;
        psk_identity_len = ssl->session_negotiate->ticket_len;
    }
    else
 #endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
    {
        psk_identity = ssl->conf->psk_identity;
        psk_identity_len = ssl->conf->psk_identity_len;
    }

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
        *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_PRE_SHARED_KEY >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_PRE_SHARED_KEY >> 0 ) & 0xFF );

        /* Extension Length */
        *p++ = (unsigned char)( ( ext_len >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ext_len >> 0 ) & 0xFF );

        /* 2 bytes length field for array of PskIdentity */
        *p++ = (unsigned char)( ( ( psk_identity_len + 4 + 2 ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( psk_identity_len + 4 + 2 ) >> 0 ) & 0xFF );

        /* 2 bytes length field for psk_identity */
        *p++ = (unsigned char)( ( ( psk_identity_len ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( psk_identity_len ) >> 0 ) & 0xFF );

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
                (uint32_t)( now - ssl->session_negotiate->ticket_received ) +
                ssl->session_negotiate->ticket_age_add;

            MBEDTLS_SSL_DEBUG_MSG( 5, ( "obfuscated_ticket_age: %u",
                                        obfuscated_ticket_age ) );
#endif /* MBEDTLS_HAVE_TIME */
        }
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

        /* add obfuscated ticket age */
        *p++ = ( obfuscated_ticket_age >> 24 ) & 0xFF;
        *p++ = ( obfuscated_ticket_age >> 16 ) & 0xFF;
        *p++ = ( obfuscated_ticket_age >> 8  ) & 0xFF;
        *p++ = ( obfuscated_ticket_age >> 0  ) & 0xFF;

        *bytes_written = ext_len_total - psk_binder_list_bytes;
        *total_ext_len = ext_len_total;

        ssl->handshake->extensions_present |= PRE_SHARED_KEY_EXTENSION;
    }
    else if( part == SSL_WRITE_PSK_EXT_ADD_PSK_BINDERS )
    {
        int external_psk;

        unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
        size_t transcript_len;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding PSK binder list" ) );

        /* 2 bytes length field for array of psk binders */
        *p++ = (unsigned char)( ( ( hash_len + 1 ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( hash_len + 1 ) >> 0 ) & 0xFF );

        /* 1 bytes length field for next psk binder */
        *p++ = (unsigned char)( ( hash_len ) & 0xFF );

        if( ssl->handshake->resume )
            external_psk = 0;
        else
            external_psk = 1;

        /* Get current state of handshake transcript. */
        ret = mbedtls_ssl_get_handshake_transcript( ssl, suite_info->mac,
                                                    transcript, sizeof( transcript ),
                                                    &transcript_len );
        if( ret != 0 )
            return( ret );

        ret = mbedtls_ssl_tls1_3_create_psk_binder( ssl,
                  external_psk,
                  psk, psk_len,
                  suite_info->mac,
                  transcript, transcript_len, p );

        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_pre_shared_key_ext()", ret );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        *bytes_written = psk_binder_list_bytes;
    }

    return( 0 );
}


#endif	/* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED  */


static int ssl_write_cookie_ext( mbedtls_ssl_context *ssl,
                                unsigned char* buf,
                                unsigned char* end,
                                size_t* olen )
{
    unsigned char *p = buf;

    *olen = 0;

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
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_COOKIE >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_COOKIE ) & 0xFF );

    /* Extension Length */
    *p++ = (unsigned char)( ( ( ssl->handshake->verify_cookie_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ssl->handshake->verify_cookie_len + 2 ) & 0xFF );

    /* Cookie Length */
    *p++ = (unsigned char)( ( ssl->handshake->verify_cookie_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ssl->handshake->verify_cookie_len & 0xFF );

    /* Cookie */
    memcpy( p, ssl->handshake->verify_cookie, ssl->handshake->verify_cookie_len );

    *olen = ssl->handshake->verify_cookie_len + 6;

    return( 0 );
}

#if defined(MBEDTLS_ECDH_C)
/*

  Supported Groups Extension

  In versions of TLS prior to TLS 1.3, this extension was named
  'elliptic_curves' and only contained elliptic curve groups.
*/

static int ssl_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                          unsigned char* buf,
                                          unsigned char* end,
                                          size_t* olen )
{
    unsigned char *p = buf;
    unsigned char *elliptic_curve_list = p + 6;
    size_t elliptic_curve_len = 0;
    const mbedtls_ecp_curve_info *info;
#if defined(MBEDTLS_ECP_C)
    const mbedtls_ecp_group_id *grp_id;
#else
    ((void) ssl);
#endif

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_some_ecdhe_enabled( ssl ) )
        return( 0 );

#if defined(MBEDTLS_ECP_C)
    for ( grp_id = ssl->conf->curve_list;
          *grp_id != MBEDTLS_ECP_DP_NONE;
          grp_id++ )
    {
/*		info = mbedtls_ecp_curve_info_from_grp_id( *grp_id ); */
#else
    for ( info = mbedtls_ecp_curve_list();
          info->grp_id != MBEDTLS_ECP_DP_NONE;
          info++ )
    {
#endif
        elliptic_curve_len += 2;
    }

    if( elliptic_curve_len == 0 )
    {
        /* If we have no curves configured then we are in trouble. */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No curves configured." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( end < p || (size_t)( end - p ) < 6 + elliptic_curve_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported_groups extension" ) );

    elliptic_curve_len = 0;

#if defined(MBEDTLS_ECP_C)
    for ( grp_id = ssl->conf->curve_list;
          *grp_id != MBEDTLS_ECP_DP_NONE;
          grp_id++ )
    {
        info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );

        if( info == NULL )
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else
    for ( info = mbedtls_ecp_curve_list();
          info->grp_id != MBEDTLS_ECP_DP_NONE;
          info++ )
    {
#endif
        elliptic_curve_list[elliptic_curve_len++] = info->tls_id >> 8;
        elliptic_curve_list[elliptic_curve_len++] = info->tls_id & 0xFF;
        MBEDTLS_SSL_DEBUG_MSG( 5, ( "Named Curve: %s ( %x )",
                  mbedtls_ecp_curve_info_from_tls_id( info->tls_id )->name,
                  info->tls_id ) );
    }

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SUPPORTED_GROUPS >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SUPPORTED_GROUPS ) & 0xFF );

    *p++ = (unsigned char)( ( ( elliptic_curve_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( elliptic_curve_len + 2 ) ) & 0xFF );

    *p++ = (unsigned char)( ( ( elliptic_curve_len ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( elliptic_curve_len ) ) & 0xFF );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Supported groups extension", buf + 4, elliptic_curve_len + 2 );

    *olen = 6 + elliptic_curve_len;

    ssl->handshake->extensions_present |= SUPPORTED_GROUPS_EXTENSION;
    return( 0 );
}
#endif /* defined(MBEDTLS_ECDH_C) */

/*

  Key Shares Extension

  enum {
  obsolete_RESERVED( 1..22 ),
  secp256r1( 23 ), secp384r1( 24 ), secp521r1( 25 ),
  obsolete_RESERVED( 26..28 ),
  x25519( 29 ), x448( 30 ),

  ffdhe2048( 256 ), ffdhe3072( 257 ), ffdhe4096( 258 ),
  ffdhe6144( 259 ), ffdhe8192( 260 ),

  ffdhe_private_use( 0x01FC..0x01FF ),
  ecdhe_private_use( 0xFE00..0xFEFF ),
  obsolete_RESERVED( 0xFF01..0xFF02 ),
  ( 0xFFFF )
  } NamedGroup;

  struct {
  NamedGroup group;
  opaque key_exchange<1..2^16-1>;
  } KeyShareEntry;

  struct {
  select ( role ) {
  case client:
  KeyShareEntry client_shares<0..2^16-1>;
  case server:
  KeyShareEntry server_share;
  }
  } KeyShare;
*/

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )

static int ssl_write_key_shares_ext( mbedtls_ssl_context *ssl,
                                     unsigned char* buf,
                                     unsigned char* end,
                                     size_t* olen )
{
    unsigned char* p;
    unsigned char *header = buf; /* Pointer where the header has to go. */
    size_t len;
    int ret;
    int nr;
    /*const int *ciphersuites; */

    /* TODO: Add bounds checks! Only then remove the next line. */
    ( (void ) end );

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_some_ecdhe_enabled( ssl ) )
        return( 0 );

    p = buf + 4;

    const mbedtls_ecp_curve_info *info = NULL;
    const mbedtls_ecp_group_id *grp_id;
    /* int max_size = 0; */
    /*const mbedtls_ssl_ciphersuite_t *suite_info; */

    if( ssl->conf->curve_list == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, key share extension: empty curve list" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding key share extension" ) );

    if( ssl->session_negotiate == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl->session_negotiate == NULL" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /*
     * Ciphersuite list
     *
     ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

     for ( int i = 0; ciphersuites[i] != 0; i++ )
     {
     suite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuites[i] );

     if( suite_info == NULL )
     continue;

     if( suite_info->hash == MBEDTLS_MD_SHA256 ) max_size = 128;
     else if( suite_info->hash == MBEDTLS_MD_SHA384 ) max_size = 384;
     }

     MBEDTLS_SSL_DEBUG_MSG( 3, ( "Ciphersuites require a key length of max %d bits", max_size ) );
    */

    /* The key_shares_curve_list provides us information about what we are expected to
     * send, either based on the info provided by the app or by info offered by the server
     * using the HRR.
     */
    nr = 0;

    for ( grp_id = ssl->handshake->key_shares_curve_list; *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++ ) {

        info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );

        /* Check whether the key share matches the selected ciphersuite
         * in terms of key length.
         *
         * Hence, AES-128 should go with a group bit size of 192 and 224 bits.
         *
         * TBD: Do we need this check?

         switch ( max_size ) {
         case 128: if( info->bit_size != 256 && info->bit_size!=192 && info->bit_size!= 224 ) continue;
         break;
         case 384: if( info->bit_size != 384 ) continue;
         break;
         }
        */

        MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDHE curve: %s", info->name ) );

        if( ( ret = mbedtls_ecp_group_load( &ssl->handshake->ecdh_ctx[nr].grp, info->grp_id ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecp_group_load", ret );
            return( ret );
        }

        if( ( ret = mbedtls_ecdh_make_tls_13_params( &ssl->handshake->ecdh_ctx[nr], &len,
                                              p+2, end - (p+2),
                                              ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_make_tls_13_params", ret );
            return( ret );
        }

        /* Write length of the key_exchange entry */
        *p++ = (unsigned char)( ( ( len ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( len ) ) & 0xFF );

        p += len;
        *olen += len + 2;
        MBEDTLS_SSL_DEBUG_ECP( 3, "ECDHE: Q ", &ssl->handshake->ecdh_ctx[nr].Q );

        nr++;
        if( nr == MBEDTLS_SSL_MAX_KEY_SHARES )
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Reached maximum number of KeyShareEntries: %d", nr ) );
            break;
        }
    }

    /* Write extension header */
    *header++ = (unsigned char)( ( MBEDTLS_TLS_EXT_KEY_SHARES >> 8 ) & 0xFF );
    *header++ = (unsigned char)( ( MBEDTLS_TLS_EXT_KEY_SHARES ) & 0xFF );

    /* Write total extension length */
    *header++ = (unsigned char)( ( *olen >> 8 ) & 0xFF );
    *header++ = (unsigned char)( *olen & 0xFF );

    *olen += 4; /* 4 bytes for fixed header */

    ssl->handshake->extensions_present |= KEY_SHARE_EXTENSION;
    return( 0 );
}

#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECDSA_C */



/* Main entry point; orchestrates the other functions */
static int ssl_client_hello_process( mbedtls_ssl_context* ssl );

static int ssl_client_hello_prepare( mbedtls_ssl_context* ssl );
static int ssl_client_hello_write_partial( mbedtls_ssl_context* ssl,
                                           unsigned char* buf, size_t buflen,
                                           size_t* len_without_binders,
                                           size_t* len_with_binders );

static int ssl_client_hello_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;
#if defined(MBEDTLS_SSL_USE_MPS)
    size_t len_without_binders;
    mbedtls_mps_handshake_out msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#else /* MBEDTLS_SSL_USE_MPS */
    size_t msg_len, len_without_binders;
    unsigned char *buf;
    size_t len;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    if( ssl->handshake->state_local.cli_hello_out.preparation_done == 0 )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_client_hello_prepare( ssl ) );
        ssl->handshake->state_local.cli_hello_out.preparation_done = 1;
    }

#if defined(MBEDTLS_SSL_USE_MPS)

    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

    msg.type   = MBEDTLS_SSL_HS_CLIENT_HELLO;
    msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                       &msg, NULL, NULL ) );

    /* Request write-buffer */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_client_hello_write_partial( ssl, buf, buf_len,
                                                  &len_without_binders,
                                                  &msg_len ) );

    mbedtls_ssl_add_hs_hdr_to_checksum( ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                        msg_len );
    ssl->handshake->update_checksum( ssl, buf, len_without_binders );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* Patch the PSK binder after updating the HS checksum. */
    {

        size_t dummy0, dummy1;
        mbedtls_ssl_write_pre_shared_key_ext( ssl,
                                              buf + len_without_binders,
                                              buf + msg_len,
                                              &dummy0, &dummy1,
                                              SSL_WRITE_PSK_EXT_ADD_PSK_BINDERS );

        /* Manually update the checksum with ClientHello using dummy PSK binders. */
        ssl->handshake->update_checksum( ssl, buf + len_without_binders,
                                         msg_len - len_without_binders );
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    /* Commit message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                             buf_len - msg_len ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */

    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

    /* Prepare ClientHello message in output buffer, up to
     * but excluding the PSK binder list (if present).
     *
     * In contrast to other handshake writing functions, this
     * function returns two length values: Firstly, the length
     * of the message up to the binder's list. And secondly,
     * the total length of the message including the binders
     * list. */
    buf = ssl->out_msg;
    len = MBEDTLS_SSL_MAX_CONTENT_LEN;
    MBEDTLS_SSL_PROC_CHK( ssl_client_hello_write_partial( ssl, buf, len,
                                                  &len_without_binders,
                                                  &msg_len ) );
    ssl->out_msglen = msg_len;

    {
        unsigned char hs_hdr[4];
        size_t const hs_len = msg_len - 4;

        /* Build HS header for checksum update. */
        hs_hdr[0] = MBEDTLS_SSL_HS_CLIENT_HELLO;
        hs_hdr[1] = (unsigned char)( hs_len >> 16 );
        hs_hdr[2] = (unsigned char)( hs_len >>  8 );
        hs_hdr[3] = (unsigned char)( hs_len >>  0 );

        ssl->handshake->update_checksum( ssl, hs_hdr, sizeof( hs_hdr ) );

        /* Manually update the checksum with ClientHello using dummy PSK binders. */
        ssl->handshake->update_checksum( ssl, buf + 4, len_without_binders - 4 );
    }

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* Patch the PSK binder after updating the HS checksum. */
    {

        size_t dummy0, dummy1;
        mbedtls_ssl_write_pre_shared_key_ext( ssl,
                                              buf + len_without_binders,
                                              buf + len,
                                              &dummy0, &dummy1,
                                              SSL_WRITE_PSK_EXT_ADD_PSK_BINDERS );

        /* Manually update the checksum with ClientHello using dummy PSK binders. */
        ssl->handshake->update_checksum( ssl, buf + len_without_binders,
                                         msg_len - len_without_binders );
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED &&
          MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_CLIENT_HELLO;

    MBEDTLS_SSL_DEBUG_BUF( 3, "ClientHello", ssl->out_msg, ssl->out_msglen );


    /* Dispatch message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg_ext(
                              ssl, 0 /* no checksum update */ ) );

#endif /* MBEDTLS_SSL_USE_MPS */

    /* NOTE: With the new messaging layer, the postprocessing
     *       step might come after the dispatching step if the
     *       latter doesn't send the message immediately.
     *       At the moment, we must do the postprocessing
     *       prior to the dispatching because if the latter
     *       returns WANT_WRITE, we want the handshake state
     *       to be updated in order to not enter
     *       this function again on retry.
     *
     *       Further, once the two calls can be re-ordered, the two
     *       calls can be consolidated.
     */

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );
    return( ret );
}

static int ssl_client_hello_prepare( mbedtls_ssl_context* ssl )
{
    int ret;
    size_t rand_bytes_len;

    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

    rand_bytes_len = 32;

    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->handshake->randbytes, rand_bytes_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_generate_random", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
    /* Determine whether session id has not been created already */
    if( ssl->session_negotiate->id_len == 0 )
    {

        /* Creating a session id with 32 byte length */
        if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->session_negotiate->id, 32 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "creating session id failed", ret );
            return( ret );
        }
    }

    ssl->session_negotiate->id_len = 32;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

    return( 0 );
}

static int ssl_client_hello_write_partial( mbedtls_ssl_context* ssl,
                                           unsigned char* buf, size_t buflen,
                                           size_t* len_without_binders,
                                           size_t* len_with_binders )
{
    int ret;

    /* Extensions */

    /* extension_start
     *    Used during extension writing where the
     *    buffer pointer to the beginning of the
     *    extension list must be kept to write
     *    the total extension list size in the end.
     */
    unsigned char* extension_start;
    size_t cur_ext_len;          /* Size of the current extension */
    size_t total_ext_len;        /* Size of list of extensions    */

    /* Length information */
    size_t rand_bytes_len;
    size_t version_len;

    /* Buffer management */
    unsigned char* start = buf;
    unsigned char* end = buf + buflen;

    /* Ciphersuite-related variables */
    const int* ciphersuites;
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info;
    size_t i; /* used to iterate through ciphersuite list */
    /* ciphersuite_start points to the start of the ciphersuite list, i.e. to the length field*/
    unsigned char* ciphersuite_start;
    size_t ciphersuite_count;

    /* Keeping track of the included extensions */
    ssl->handshake->extensions_present = NO_EXTENSION;

    rand_bytes_len = 32;

    /* NOTE:
     * Even for DTLS 1.3, we are writing a TLS handshake header here.
     * The actual DTLS 1.3 handshake header is inserted in
     * the record writing routine mbedtls_ssl_write_record().
     *
     * For cTLS the length, and the version field
     * are elided. The random bytes are shorter.
     */
    version_len = 2;

    /* With MPS we don't need to write the handshake header. */
#if !defined(MBEDTLS_SSL_USE_MPS)
    {
        size_t const tls_hs_hdr_len = 4;

        if( buflen < tls_hs_hdr_len + version_len + rand_bytes_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small to hold ClientHello" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        buf += tls_hs_hdr_len;
        buflen -= tls_hs_hdr_len;
    }
#endif /* MBEDTLS_SSL_USE_MPS */

    if( ssl->conf->max_major_ver == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "configured max major version is invalid, "
                                    "consider using mbedtls_ssl_config_defaults()" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    ssl->major_ver = ssl->conf->min_major_ver;
    ssl->minor_ver = ssl->conf->min_minor_ver;

    /* For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     *
     *  For DTLS 1.3 we use the legacy version number
     *  {254,253}.
     *
     *  In cTLS the version number is elided.
     */
    *buf++ = 0x03;
    *buf++ = 0x03;
    buflen -= version_len;

    /* Write random bytes */
    memcpy( buf, ssl->handshake->randbytes, rand_bytes_len );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes", buf, rand_bytes_len );

    buf += rand_bytes_len;
    buflen -= rand_bytes_len;

    /* Versions of TLS before TLS 1.3 supported a
     * "session resumption" feature which has been merged with pre-shared
     * keys in this version. A client which has a
     * cached session ID set by a pre-TLS 1.3 server SHOULD set this
     * field to that value. In compatibility mode,
     * this field MUST be non-empty, so a client not offering a
     * pre-TLS 1.3 session MUST generate a new 32-byte value. This value
     * need not be random but SHOULD be unpredictable to avoid
     * implementations fixating on a specific value ( also known as
     * ossification ). Otherwise, it MUST be set as a zero-length vector
     * ( i.e., a zero-valued single byte length field ).
     */
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
    if( buflen < ( ssl->session_negotiate->id_len + 1 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small to hold ClientHello" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    *buf++ = (unsigned char)ssl->session_negotiate->id_len; /* write session id length */
    memcpy( buf, ssl->session_negotiate->id, ssl->session_negotiate->id_len ); /* write session id */

    buf += ssl->session_negotiate->id_len;
    buflen -= ssl->session_negotiate->id_len;


    MBEDTLS_SSL_DEBUG_MSG( 3, ( "session id len.: %d", ssl->session_negotiate->id_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id, ssl->session_negotiate->id_len );
#else
    if( buflen < 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small to hold ClientHello" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    *buf++ = 0; /* session id length set to zero */
    buflen -= 1;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

    /*
     * Ciphersuite list
     *
     * This is a list of the symmetric cipher options supported by
     * the client, specifically the record protection algorithm
     * ( including secret key length ) and a hash to be used with
     * HKDF, in descending order of client preference.
     */
    ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];

    if( buflen < 2 /* for ciphersuite list length */ )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small to hold ClientHello" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Skip writing ciphersuite length for now */
    ciphersuite_count = 0;
    ciphersuite_start = buf;
    buf += 2;
    buflen -= 2;

    for ( i = 0; ciphersuites[i] != 0; i++ )
    {
        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuites[i] );

        if( ciphersuite_info == NULL )
            continue;

        if( ciphersuite_info->min_minor_ver != MBEDTLS_SSL_MINOR_VERSION_4 ||
            ciphersuite_info->max_minor_ver != MBEDTLS_SSL_MINOR_VERSION_4 )
            continue;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %04x, %s",
                                    ciphersuites[i], ciphersuite_info->name ) );

        ciphersuite_count++;

        if( buflen < 2 /* for ciphersuite list length */ )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small to hold ClientHello" ) );
            return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
        }

        *buf++ = (unsigned char)( ciphersuites[i] >> 8 );
        *buf++ = (unsigned char)( ciphersuites[i] );

        buflen -= 2;

#if defined(MBEDTLS_ZERO_RTT)
        /* For ZeroRTT we only add a single ciphersuite. */
        break;
#endif /* MBEDTLS_ZERO_RTT */
    }

    /* write ciphersuite length now */
    *ciphersuite_start++ = (unsigned char)( ciphersuite_count*2 >> 8 );
    *ciphersuite_start++ = (unsigned char)( ciphersuite_count*2 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, got %d ciphersuites", ciphersuite_count ) );

    /* For every TLS 1.3 ClientHello, this vector MUST contain exactly
     * one byte set to zero, which corresponds to the 'null' compression
     * method in prior versions of TLS.
     *
     * For cTLS this field is elided.
     */
    if( buflen < 2 /* for ciphersuite list length */ )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small to hold ClientHello" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    *buf++ = 1;
    *buf++ = MBEDTLS_SSL_COMPRESS_NULL;

    buflen -= 2;

    /* First write extensions, then the total length */
    extension_start = buf;
    total_ext_len = 0;
    buf += 2;

    /* Supported Versions Extension is mandatory with TLS 1.3.
     *
     * For cTLS we only need to provide it if there is more than one version
     * and currently there is only one.
     */
    ssl_write_supported_versions_ext( ssl, buf, end, &cur_ext_len );
    total_ext_len += cur_ext_len;
    buf += cur_ext_len;

    /* For TLS / DTLS 1.3 we need to support the use of cookies
     * ( if the server provided them ) */
    ssl_write_cookie_ext( ssl, buf, end, &cur_ext_len );
    total_ext_len += cur_ext_len;
    buf += cur_ext_len;

#if defined(MBEDTLS_SSL_ALPN)
    ssl_write_alpn_ext( ssl, buf, end, &cur_ext_len );
    total_ext_len += cur_ext_len;
    buf += cur_ext_len;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    ssl_write_max_fragment_length_ext( ssl, buf, end, &cur_ext_len );
    total_ext_len += cur_ext_len;
    buf += cur_ext_len;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_ZERO_RTT)
    mbedtls_ssl_write_early_data_ext( ssl, buf, (size_t)( end - buf ),
            &cur_ext_len );
    total_ext_len += cur_ext_len;
    buf += cur_ext_len;
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    /* For PSK-based ciphersuites we don't really need the SNI extension */
    ssl_write_hostname_ext( ssl, buf, end, &cur_ext_len );
    total_ext_len += cur_ext_len;
    buf += cur_ext_len;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* For PSK-based ciphersuites we need the pre-shared-key extension
     * and the psk_key_exchange_modes extension.
     *
     * The pre_shared_key_ext extension MUST be the last extension in the ClientHello.
     * Servers MUST check that it is the last extension and otherwise fail the handshake
     * with an "illegal_parameter" alert.
     */

    /* Add the psk_key_exchange_modes extension.
     */
    ret = ssl_write_psk_key_exchange_modes_ext( ssl, buf, end, &cur_ext_len );
    if( ret != 0 )
        return( ret );

    total_ext_len += cur_ext_len;
    buf += cur_ext_len;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    /* The supported_groups and the key_share extensions are
     * REQUIRED for ECDHE ciphersuites.
     */
    ret = ssl_write_supported_groups_ext( ssl, buf, end, &cur_ext_len );
    if( ret != 0 )
        return( ret );

    total_ext_len += cur_ext_len;
    buf += cur_ext_len;

    /* The supported_signature_algorithms extension is REQUIRED for
     * certificate authenticated ciphersuites. */
    ret = mbedtls_ssl_write_signature_algorithms_ext( ssl, buf, end, &cur_ext_len );
    if( ret != 0 )
        return( ret );

    total_ext_len += cur_ext_len;
    buf += cur_ext_len;

    /* We need to send the key shares under three conditions:
     * 1 ) A certificate-based ciphersuite is being offered. In this case
     *    supported_groups and supported_signature extensions have been successfully added.
     * 2 ) A PSK-based ciphersuite with ECDHE is offered. In this case the
     *    psk_key_exchange_modes has been added as the last extension.
     * 3 ) Or, in case all ciphers are supported ( which includes #1 and #2 from above )
     */

    ret = ssl_write_key_shares_ext( ssl, buf, end, &cur_ext_len );
    if( ret != 0 )
        return( ret );

    total_ext_len += cur_ext_len;
    buf += cur_ext_len;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    {
        size_t bytes_written;
        /* We need to save the pointer to the pre-shared key extension
         * because it has to be updated later. */
        ret = mbedtls_ssl_write_pre_shared_key_ext( ssl, buf, end,
                                                    &bytes_written,
                                                    &cur_ext_len,
                                                    SSL_WRITE_PSK_EXT_PARTIAL );
        if( ret != 0 )
            return( ret );

        total_ext_len += cur_ext_len;
        buf += bytes_written;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %d",
                                total_ext_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", extension_start, total_ext_len );

    /* Write extension length */
    *extension_start++ = (unsigned char)( ( total_ext_len >> 8 ) & 0xFF );
    *extension_start++ = (unsigned char)( ( total_ext_len ) & 0xFF );

    *len_without_binders = buf - start;
    *len_with_binders = ( extension_start + total_ext_len ) - start;
    return( 0 );
}

static int ssl_parse_supported_version_ext( mbedtls_ssl_context* ssl,
                                            const unsigned char* buf,
                                            size_t len )
{
    ((void) ssl);

    if( len != 2 ||
        buf[0] != MBEDTLS_SSL_MAJOR_VERSION_3 ||
        buf[1] != MBEDTLS_SSL_MINOR_VERSION_4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected version" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
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


#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext( mbedtls_ssl_context *ssl,
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
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
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

static int ssl_parse_server_psk_identity_ext( mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t len )
{
    int ret = 0;
    size_t selected_identity;

    if( mbedtls_ssl_get_psk( ssl, NULL, NULL ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no pre-shared key" ) );
        return( MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    if( len != (size_t)2 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad psk_identity extension in server hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    selected_identity = ( buf[0] << 8 ) | buf[1];

    if( selected_identity > 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unknown identity" ) );

        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                                    MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                    MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY ) ) != 0 )
        {
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY );
    }

/*	buf += 2; */
    ssl->handshake->extensions_present |= PRE_SHARED_KEY_EXTENSION;
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
int ssl_parse_encrypted_extensions_early_data_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   size_t len )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
    {
        /* The server must not send the EarlyDataIndication if the
         * client hasn't indicated the use of 0-RTT. */
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    if( len != 0 )
    {
        /* The message must be empty. */
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
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
#endif /* MBEDTLS_ZERO_RTT */

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
/*

  ssl_parse_key_shares_ext() verifies whether the information in the extension
  is correct and stores the provided key shares.

*/

/* The ssl_parse_key_shares_ext() function is used
 *  by the client to parse a KeyShare extension in
 *  a ServerHello message.
 *
 *  The server only provides a single KeyShareEntry.
 */
static int ssl_parse_key_shares_ext( mbedtls_ssl_context *ssl,
                                     const unsigned char *buf,
                                     size_t len ) {

    int ret = 0;
    unsigned char *end = (unsigned char*)buf + len;
    unsigned char *start = (unsigned char*)buf;
    int named_group;
    int i;
    const mbedtls_ecp_curve_info *curve_info;
    int match_found = 0;
    mbedtls_ecp_group_id gid;

    /* Is there a key share available at the server config? */
    /* if( ssl->conf->keyshare_ctx == NULL )
       {
       MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no key share context" ) );

       if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
       return( ret );

       return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
       }
    */

    /* read named group */
    named_group = ( buf[0] << 8 ) | buf[1];

    /* We need to find out which key share the server had selected from
     * those sent out.
     */

    for( i=0;
         ssl->handshake->key_shares_curve_list[i] != MBEDTLS_ECP_DP_NONE;
         i++ ) {

        gid = ssl->handshake->key_shares_curve_list[i];

        curve_info = mbedtls_ecp_curve_info_from_grp_id( gid );

        /* If we find a match then we need to read the key share
         * provided by the server and store it alongside the
         * respective key share structure.
         */
        if( curve_info->tls_id == named_group )
        {
            match_found = 1;

            break;
        }
    }

    if( match_found == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching curve for ECDHE" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /* We store the server-selected key share at a given place
     * in our array of ECDH parameters.
     */
    ssl->handshake->ecdh_ctx_selected = i;

    if( ( ret = mbedtls_ecdh_read_tls_13_params( &ssl->handshake->ecdh_ctx[i],
                                          ( const unsigned char ** )&start, end ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ecdh_read_tls_13_params" ), ret );
        return( ret );
    }

    if( check_ecdh_params( ssl ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "check_ecdh_params() failed!" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    ssl->handshake->extensions_present |= KEY_SHARE_EXTENSION;
    return( ret );
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */


#if defined(MBEDTLS_SSL_ALPN)
static int ssl_parse_alpn_ext( mbedtls_ssl_context *ssl,
                               const unsigned char *buf, size_t len )
{
    size_t list_len, name_len;
    const char **p;

    /* If we didn't send it, the server shouldn't send it */
    if( ssl->conf->alpn_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );

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
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );

    list_len = ( buf[0] << 8 ) | buf[1];
    if( list_len != len - 2 )
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );

    name_len = buf[2];
    if( name_len != list_len - 1 )
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );

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

    return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
}
#endif /* MBEDTLS_SSL_ALPN */

/*
 *
 * STATE HANDLING: CertificateRequest
 *
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
static int ssl_certificate_request_process( mbedtls_ssl_context* ssl );

/* Coordination:
 * Deals with the ambiguity of not knowing if a CertificateRequest
 * will be sent. Returns a negative code on failure, or
 * - SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST
 * - SSL_CERTIFICATE_REQUEST_SKIP
 * indicating if a Certificate Request is expected or not.
 */
#define SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST 0
#define SSL_CERTIFICATE_REQUEST_SKIP    1
static int ssl_certificate_request_coordinate( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_certificate_request_fetch( mbedtls_ssl_context* ssl,
                                          unsigned char** buf,
                                          size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_certificate_request_parse( mbedtls_ssl_context* ssl,
                                          unsigned char const* buf,
                                          size_t buflen );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
static int ssl_certificate_request_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

/* Main entry point; orchestrates the other functions */
static int ssl_certificate_request_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate request" ) );

    /* Coordination step
     * - Fetch record
     * - Make sure it's either a CertificateRequest or a ServerHelloDone
     */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_certificate_request_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    if( ret == SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST )
    {
        unsigned char *buf;
        size_t buflen;

#if defined(MBEDTLS_SSL_USE_MPS)

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                              MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                                              &buf, &buflen ) );

        mbedtls_ssl_add_hs_msg_to_checksum(
            ssl, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST, buf, buflen );

        /* Process the message contents */
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_parse( ssl, buf, buflen ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_fetch( ssl, &buf, &buflen ) );
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_parse( ssl, buf, buflen ) );
#endif /* MBEDTLS_SSL_USE_MPS */
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
    MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_postprocess( ssl ) );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "got %s certificate request",
                                ssl->client_auth ? "a" : "no" ) );

cleanup:

    /* In the MPS one would close the read-port here to
     * ensure there's no overlap of reading and writing. */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate request" ) );
    return( ret );
}

#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_certificate_request_coordinate( mbedtls_ssl_context* ssl )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= skip parse certificate request" ) );
        return( SSL_CERTIFICATE_REQUEST_SKIP );
    }

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps.l4 ) );
    if( ret != MBEDTLS_MPS_MSG_HS )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps.l4, &msg ) );

    if( msg.type == MBEDTLS_SSL_HS_CERTIFICATE_REQUEST )
        return( SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST );

    return( SSL_CERTIFICATE_REQUEST_SKIP );

cleanup:
    return( ret);
}

#else /* MBEDTLS_SSL_USE_MPS */

static int ssl_certificate_request_coordinate( mbedtls_ssl_context* ssl )
{
    int ret;

    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
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
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] == MBEDTLS_SSL_HS_CERTIFICATE_REQUEST )
    {
        return( SSL_CERTIFICATE_REQUEST_EXPECT_REQUEST );
    }

    return( SSL_CERTIFICATE_REQUEST_SKIP );
}

static int ssl_certificate_request_fetch( mbedtls_ssl_context* ssl,
                                          unsigned char **buf,
                                          size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE          ||
        ssl->in_msg[0]  != MBEDTLS_SSL_HS_CERTIFICATE_REQUEST )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

    return( 0 );
}
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_certificate_request_parse( mbedtls_ssl_context* ssl,
                                          const unsigned char* buf,
                                          size_t buflen )
{

    int ret;
    const unsigned char* p;
    unsigned char* ext;
    size_t ext_len = 0;
    int context_len = 0;

    /* TODO: Add bounds checks! Only then remove the next line. */
    ((void) buflen);

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
    context_len = p[0];

    /* skip context_len */
    p++;

    /* Fixed length fields are:
     *  - 1 for length of context
     *  - 2 for length of extensions
     * -----
     *    3 bytes
     */

    if( buflen < (size_t)( 3 + context_len ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

    /* store context ( if necessary ) */
    if( context_len > 0 )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Certificate Request Context", p, context_len );

        ssl->handshake->certificate_request_context = mbedtls_calloc( context_len, 1 );
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
    ext_len = ( p[0] << 8 ) | ( p[1] );

    /* At least one extension needs to be present, namely signature_algorithms ext. */
    if( ext_len < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

    /* skip total extension length */
    p += 2;

    ext = (unsigned char*) p; /* jump to extensions */
    while( ext_len )
    {
        unsigned int ext_id = ( ( ext[0] << 8 ) | ( ext[1] ) );
        unsigned int ext_size = ( ( ext[2] << 8 ) | ( ext[3] ) );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
        }

        switch ( ext_id )
        {

            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found signature_algorithms extension" ) );

                if( ( ret = mbedtls_ssl_parse_signature_algorithms_ext( ssl, ext + 4, (size_t)ext_size ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_parse_signature_algorithms_ext" ) );
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR, ret );
                    return( ret );
                }
                break;

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown extension found: %d ( ignoring )",
                                            ext_id ) );
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
        }
    }

    ssl->client_auth = 1;
    return( 0 );
}
#endif /* ( MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ) */


static int ssl_certificate_request_postprocess( mbedtls_ssl_context* ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CERTIFICATE );
    return( 0 );
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
static int ssl_encrypted_extensions_process( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_encrypted_extensions_fetch( mbedtls_ssl_context* ssl,
                                           unsigned char** buf,
                                           size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_encrypted_extensions_parse( mbedtls_ssl_context* ssl,
                                           unsigned char* buf,
                                           size_t buflen );
static int ssl_encrypted_extensions_postprocess( mbedtls_ssl_context* ssl );

static int ssl_encrypted_extensions_process( mbedtls_ssl_context* ssl )
{
    int ret;
    unsigned char *buf;
    size_t buflen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse encrypted extensions" ) );

#if defined(MBEDTLS_SSL_USE_MPS)

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                             MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION,
                                             &buf, &buflen ) );

    mbedtls_ssl_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION, buf, buflen );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_parse( ssl, buf, buflen ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */
    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_fetch( ssl, &buf, &buflen ) );
    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_parse( ssl, buf, buflen ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse encrypted extensions" ) );
    return( ret );

}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_encrypted_extensions_fetch( mbedtls_ssl_context* ssl,
                                           unsigned char **buf,
                                           size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad encrypted extensions" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    if( ssl->in_msg[0] != MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad encrypted extensions" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS );
        ret = MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS;
        goto cleanup;
    }

    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

cleanup:

    return( ret );
}


#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_encrypted_extensions_parse( mbedtls_ssl_context* ssl,
                                           unsigned char* buf,
                                           size_t buflen )
{
    int ret=0;
    size_t ext_len;
    unsigned char *ext;

    /* TODO: Add bounds checks! Only then remove the next line. */
    ((void) buflen );

    ext_len = ( ( buf[0] << 8 ) | ( buf[1] ) );

    buf += 2; /* skip extension length */
    ext = buf;

    /* Checking for an extension length that is too short */
    if( ext_len > 0UL && ext_len < 4UL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Extension length too short - bad encrypted extensions message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /* Checking for an extension length that is not aligned with the rest of the message */
    if( buflen != 2 + ext_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Extension length misaligned - bad encrypted extensions message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "encrypted extensions, total extension length: %d", ext_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "encrypted extensions extensions", ext, ext_len );

    while( ext_len )
    {
        unsigned int ext_id = ( ( ext[0] << 8 )
                                | ( ext[1] ) );
        unsigned int ext_size = ( ( ext[2] << 8 )
                                  | ( ext[3] ) );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad encrypted extensions message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS );
        }

        /* TBD: The client MUST check EncryptedExtensions for the
         * presence of any forbidden extensions and if any are found MUST abort
         * the handshake with an "illegal_parameter" alert.
         */

        switch ( ext_id )
        {

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
            case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found max_fragment_length extension" ) );

                if( ( ret = ssl_parse_max_fragment_length_ext( ssl,
                                                               ext + 4, ext_size ) ) != 0 )
                {
                    return( ret );
                }

                break;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */


#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found alpn extension" ) );

                if( ( ret = ssl_parse_alpn_ext( ssl, ext + 4, (size_t)ext_size ) ) != 0 )
                {
                    return( ret );
                }

                break;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
            case MBEDTLS_TLS_EXT_SERVERNAME:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found server_name extension" ) );

                /* The server_name extension is an empty extension */

                break;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_ZERO_RTT)
            case MBEDTLS_TLS_EXT_EARLY_DATA:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found early data extension"));

                ret = ssl_parse_encrypted_extensions_early_data_ext(
                    ssl, ext + 4, (size_t) ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_parse_early_data_ext", ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_ZERO_RTT */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown extension found: %d ( ignoring )", ext_id ) );
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad encrypted extensions message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_ENCRYPTED_EXTENSIONS );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse encrypted extension" ) );

    return( ret );
}

static int ssl_encrypted_extensions_postprocess( mbedtls_ssl_context* ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );
    return( 0 );
}


/*
 *
 * STATE HANDLING: ServerHello
 *
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
static int ssl_server_hello_process( mbedtls_ssl_context* ssl );

/* Fetch and preprocess
 * Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO_COORDINATE_HELLO or
 * - SSL_SERVER_HELLO_COORDINATE_HRR
 * to indicate which message is expected and to be parsed next. */
#define SSL_SERVER_HELLO_COORDINATE_HELLO  0
#define SSL_SERVER_HELLO_COORDINATE_HRR 1

#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_server_hello_coordinate( mbedtls_ssl_context* ssl,
                                        mbedtls_mps_handshake_in *msg,
                                        unsigned char **buf,
                                        size_t *buflen );
#else
static int ssl_server_hello_coordinate( mbedtls_ssl_context* ssl,
                                        unsigned char **buf,
                                        size_t *buflen );
#endif

/* Parse ServerHello */
static int ssl_server_hello_parse( mbedtls_ssl_context* ssl,
                                   const unsigned char* buf,
                                   size_t buflen );

static int ssl_server_hello_postprocess( mbedtls_ssl_context* ssl );

static int ssl_hrr_parse( mbedtls_ssl_context* ssl,
                          const unsigned char* buf,
                          size_t buflen );

static int ssl_hrr_postprocess( mbedtls_ssl_context* ssl,
                                const unsigned char* buf,
                                size_t buflen );

/*
 * Implementation
 */

static int ssl_server_hello_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;
#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_mps_handshake_in msg;
#endif
    unsigned char *buf;
    size_t buflen;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse server hello" ) );

    /* Coordination step
     * - Fetch record
     * - Make sure it's either a ServerHello or a HRR.
     * - Switch processing routine in case of HRR
     */

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_server_hello_coordinate( ssl, &msg,
                                                 &buf, &buflen ) );
#else /* MBEDTLS_SSL_USE_MPS */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_server_hello_coordinate( ssl,
                                                 &buf, &buflen ) );
#endif /* MBEDTLS_SSL_USE_MPS */

    /* Parsing step
     * We know what message to expect by now and call
     * the respective parsing function.
     */

    if( ret == SSL_SERVER_HELLO_COORDINATE_HELLO )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_server_hello_parse( ssl, buf, buflen ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                            buf, buflen );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit_ext( msg.handle ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps.l4  ) );
#endif /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_server_hello_postprocess( ssl ) );
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK( ssl_hrr_parse( ssl, buf, buflen ) );

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit_ext( msg.handle ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps.l4  ) );
#endif /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_hrr_postprocess( ssl, buf, buflen ) );
    }


cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse server hello" ) );
    return( ret );
}

static int ssl_server_hello_is_hrr( unsigned const char *buf )
{
    const char magic_hrr_string[32] =
        { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
          0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
          0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
          0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33 ,0x9C };

    /* Check whether this message is a HelloRetryRequest ( HRR ) message.
     *
     * ServerHello and HRR are only distinguished by Random set to the
     * special value of the SHA-256 of "HelloRetryRequest".
     *
     * struct {
     * 	  ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2 ^ 16 - 1>;
     * } ServerHello;
     *
     */

    if( memcmp( buf + 2, magic_hrr_string,
                sizeof( magic_hrr_string ) ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}


#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_server_hello_coordinate( mbedtls_ssl_context* ssl,
                                        mbedtls_mps_handshake_in *msg,
                                        unsigned char **buf,
                                        size_t *buflen )
{
    int ret = 0;
    unsigned char *peak;

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps.l4 ) );

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
    if( ret == MBEDTLS_MPS_MSG_CCS )
    {
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps.l4 ) );
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

    if( ret != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps.l4,
                                                      msg ) );

    if( msg->type != MBEDTLS_SSL_HS_SERVER_HELLO )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    ret = mbedtls_mps_reader_get_ext( msg->handle,
                                  msg->length,
                                  &peak,
                                  NULL );

    if( ret == MBEDTLS_ERR_MPS_READER_OUT_OF_DATA )
    {
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_pause( &ssl->mps.l4 ) );
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    }
    else
    {
        if( ssl_server_hello_is_hrr( peak ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
            ret = SSL_SERVER_HELLO_COORDINATE_HRR;
        }
        else
        {
            ret = SSL_SERVER_HELLO_COORDINATE_HELLO;
        }

        *buf = peak;
        *buflen = msg->length;
    }

cleanup:

    return( ret );
}
#else /* MBEDTLS_SSL_USE_MPS */
static int ssl_server_hello_coordinate( mbedtls_ssl_context* ssl,
                                        unsigned char **buf,
                                        size_t *buflen )
{
    int ret;

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_read_record( ssl, 0 ) );

    /* TBD: If we do an HRR, keep track of the number
     * of ClientHello's we sent, and fail if it
     * exceeds the configured threshold. */

    if( ( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ) ||
        ( ssl->in_msg[0] != MBEDTLS_SSL_HS_SERVER_HELLO ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected message" ) );

        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    *buf = ssl->in_msg;
    *buflen = ssl->in_hslen;

    if( ssl_server_hello_is_hrr( ssl->in_msg + 4 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
        ret = SSL_SERVER_HELLO_COORDINATE_HRR;
    }
    else
    {
        ret = SSL_SERVER_HELLO_COORDINATE_HELLO;
    }

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_server_hello_session_id_check( mbedtls_ssl_context* ssl,
                                              const unsigned char** buf,
                                              const unsigned char* end )
{
    size_t buflen = (size_t)( end - *buf );
    size_t recv_id_len;

    if( buflen == 0 )
        return( 1 );

    recv_id_len = **buf;
    *buf   += 1; /* skip session id length */
    buflen -= 1;

    /* legacy_session_id_echo */
    if( ssl->session_negotiate->id_len != recv_id_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Mismatch of session id length" ) );
        return( 1 );
    }

    if( buflen < recv_id_len )
        return( 1 );

    if( memcmp( ssl->session_negotiate->id, *buf,
                ssl->session_negotiate->id_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unexpected legacy_session_id_echo" ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Expected Session ID",
                               ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Received Session ID", *buf,
                               ssl->session_negotiate->id_len );
        return( 1 );
    }

    *buf   += recv_id_len;
    buflen -= recv_id_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Session ID",
                           ssl->session_negotiate->id,
                           ssl->session_negotiate->id_len );
    return( 0 );
}

static int ssl_server_hello_parse( mbedtls_ssl_context* ssl,
                                   const unsigned char* buf,
                                   size_t buflen )
{

    int ret; /* return value */
    int i; /* scratch value */
    const unsigned char* msg_end = buf + buflen; /* pointer to the end of the buffer for length checks */

    size_t ext_len; /* stores length of all extensions */
    unsigned int ext_id; /* id of an extension */
    const unsigned char* ext; /* pointer to an individual extension */
    unsigned int ext_size; /* size of an individual extension */

    const mbedtls_ssl_ciphersuite_t* suite_info; /* pointer to ciphersuite */

#if defined(MBEDTLS_SSL_USE_MPS)
    size_t hs_hdr_add = 4;
#else
    size_t hs_hdr_add = 4;
#endif /* MBEDTLS_SSL_USE_MPS */

    /* Check for minimal length */
    /* struct {
     *    ProtocolVersion legacy_version = 0x0303;
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
    if( buflen < 38 + hs_hdr_add )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message - min size not reached" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "server hello", buf, buflen );

#if !defined(MBEDTLS_SSL_USE_MPS)
    /* skip header */
    buf += mbedtls_ssl_hs_hdr_len( ssl );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, version", buf + 0, 2 );
    mbedtls_ssl_read_version( &ssl->major_ver, &ssl->minor_ver,
                              ssl->conf->transport, buf + 0 );

    /* The version field in the ServerHello must contain 0x303 */
    if( buf[0] != 0x03 || buf[1] != 0x03 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                              MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
    }

    /* skip version */
    buf += 2;

    /* Internally we use the correct 1.3 version */
    ssl->major_ver = 0x03;
    ssl->minor_ver = 0x04;

    /* store server-provided random values */
    memcpy( ssl->handshake->randbytes + 32, buf, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes", buf + 2, 32 );

    /* skip random bytes */
    buf += 32;

    if( ssl_server_hello_session_id_check( ssl, &buf, msg_end ) != 0 )
    {
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /* read server-selected ciphersuite, which follows random bytes */
    i = ( buf[0] << 8 ) | buf[1];

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
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                              MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    mbedtls_ssl_optimize_checksum( ssl, ssl->handshake->ciphersuite_info );

    ssl->session_negotiate->ciphersuite = i;

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: ( %04x ) - %s", i, suite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    i = 0;
    while ( 1 )
    {
        if( ssl->conf->ciphersuite_list[ssl->minor_ver][i] == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
            return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        if( ssl->conf->ciphersuite_list[ssl->minor_ver][i++] ==
            ssl->session_negotiate->ciphersuite )
        {
            break;
        }
    }

    /* Ensure that compression method is set to zero */
    if( buf[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /* skip compression */
    buf++;

    /* Are we reading beyond the message buffer? */
    if( ( buf + 2 ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    ext_len = ( ( buf[0] << 8 ) | ( buf[1] ) );
    buf += 2; /* skip extension length */

    /* Are we reading beyond the message buffer? */
    if( ( buf + ext_len ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    ext = buf;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, total extension length: %d", ext_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello extensions", ext, ext_len );

    while ( ext_len )
    {
        ext_id = ( ( ext[0] << 8 ) | ( ext[1] ) );
        ext_size = ( ( ext[2] << 8 ) | ( ext[3] ) );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                  MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
            return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        switch ( ext_id )
        {
            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported_versions extension" ) );

                ret = ssl_parse_supported_version_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                    return( ret );
                break;

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension" ) );
                if( ( ret = ssl_parse_server_psk_identity_ext( ssl, ext + 4, (size_t)ext_size ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_server_psk_identity_ext" ), ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_KEY_SHARES:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key_shares extension" ) );

                if( ( ret = ssl_parse_key_shares_ext( ssl, ext + 4, (size_t)ext_size ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_parse_key_shares_ext", ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown extension found: %d ( ignoring )", ext_id ) );
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    return( 0 );
}


static int ssl_server_hello_postprocess( mbedtls_ssl_context* ssl )
{
    int ret;
    mbedtls_ssl_key_set traffic_keys;
    /* We need to set the key exchange algorithm based on the
     * following rules:
     *
     *   1 ) IF PRE_SHARED_KEY extension was received
     *      THEN set MBEDTLS_KEY_EXCHANGE_PSK
     *   2 ) IF PRE_SHARED_KEY extension && KEY_SHARE was received
     *      THEN set MBEDTLS_KEY_EXCHANGE_ECDHE_PSK
     *   3 ) IF KEY_SHARES extension was received && SIG_ALG extension received
     *      THEN set MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA
     *   ELSE unknown key exchange mechanism.
     */

    if( ssl->handshake->extensions_present & PRE_SHARED_KEY_EXTENSION )
    {
        if( ssl->handshake->extensions_present & KEY_SHARE_EXTENSION )
            ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_ECDHE_PSK;
        else
            ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_PSK;
    }
    else if( ssl->handshake->extensions_present & KEY_SHARE_EXTENSION )
        ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA;
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unknown key exchange." ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /* Generate handshake keying material */
    ret = mbedtls_ssl_handshake_key_derivation( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake_key_derivation", ret );
        return( ret );
    }

    ret = mbedtls_ssl_tls13_populate_transform(
                              ssl->transform_handshake,
                              ssl->conf->endpoint,
                              ssl->session_negotiate->ciphersuite,
                              &traffic_keys,
                              ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_USE_MPS)
    /* We're not yet using MPS for all outgoing encrypted handshake messages,
     * so we cannot yet remove the old transform generation code in case
     * MBEDTLS_SSL_USE_MPS is set. */
    {
        mbedtls_ssl_transform *transform_handshake =
            mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
        if( transform_handshake == NULL )
            return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

        ret = mbedtls_ssl_tls13_populate_transform(
                              transform_handshake,
                              ssl->conf->endpoint,
                              ssl->session_negotiate->ciphersuite,
                              &traffic_keys,
                              ssl );

        /* Register transform with MPS. */
        ret = mbedtls_mps_add_key_material( &ssl->mps.l4,
                                            transform_handshake,
                                            &ssl->epoch_handshake );
        if( ret != 0 )
            return( ret );
    }
#endif /* MBEDTLS_SSL_USE_MPS */

    /* Switch to new keys for inbound traffic. */
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to handshake keys for inbound traffic" ) );
    ssl->session_in = ssl->session_negotiate;

#if defined(MBEDTLS_SSL_USE_MPS)
    ret = mbedtls_mps_set_incoming_keys( &ssl->mps.l4,
                                         ssl->epoch_handshake );
    if( ret != 0 )
        return( ret );
#else
    mbedtls_ssl_set_inbound_transform( ssl, ssl->transform_handshake );
#endif /* MBEDTLS_SSL_USE_MPS */

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );

    return( 0 );
}


static int ssl_hrr_parse( mbedtls_ssl_context* ssl,
                          const unsigned char* buf, size_t buflen )
{
    int ret; /* return value */
    int i; /* scratch value */
    int found = 0;
    const unsigned char* msg_end = buf + buflen; /* pointer to the end of the buffer for length checks */

    size_t ext_len; /* stores length of all extensions */
    unsigned int ext_id; /* id of an extension */
    const unsigned char* ext; /* pointer to an individual extension */
    unsigned int ext_size; /* size of an individual extension */

    const mbedtls_ssl_ciphersuite_t* suite_info; /* pointer to ciphersuite */

#if defined(MBEDTLS_ECDH_C)
    /* Variables for parsing the key_share */
    const mbedtls_ecp_group_id* grp_id;
    const mbedtls_ecp_curve_info* info, * curve = NULL;
    int tls_id;
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_SSL_COOKIE_C)
    size_t cookie_len;
    unsigned char *cookie;
#endif /* MBEDTLS_SSL_COOKIE_C */

#if defined(MBEDTLS_SSL_USE_MPS)
    size_t hs_hdr_add = 0;
#else
    size_t hs_hdr_add = 4;
#endif /* MBEDTLS_SSL_USE_MPS */

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
    if( buflen < 38 + hs_hdr_add )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message - min size not reached" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
    }

    MBEDTLS_SSL_DEBUG_BUF( 5, "hello retry request", buf, buflen );

#if !defined(MBEDTLS_SSL_USE_MPS)
    /* skip header */
    buf += mbedtls_ssl_hs_hdr_len( ssl );
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_BUF( 3, "hello retry request, version", buf + 0, 2 );
    mbedtls_ssl_read_version( &ssl->major_ver, &ssl->minor_ver,
                              ssl->conf->transport, buf + 0 );

    /* The version field must contain 0x303 */
    if( buf[0] != 0x03 || buf[1] != 0x03 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                              MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
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

    if( ssl_server_hello_session_id_check( ssl, &buf, msg_end ) != 0 )
    {
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
    }

    /* read server-selected ciphersuite, which follows random bytes */
    i = ( buf[0] << 8 ) | buf[1];

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
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                              MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    mbedtls_ssl_optimize_checksum( ssl, ssl->handshake->ciphersuite_info );

    ssl->session_negotiate->ciphersuite = i;

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                              MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "hello retry request, chosen ciphersuite: ( %04x ) - %s", i, suite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    i = 0;
    while ( 1 )
    {
        if( ssl->conf->ciphersuite_list[ssl->minor_ver][i] == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                  MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
            return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        }

        if( ssl->conf->ciphersuite_list[ssl->minor_ver][i++] ==
            ssl->session_negotiate->ciphersuite )
        {
            break;
        }
    }

    /* Ensure that compression method is set to zero */
    if( buf[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
    }

    /* skip compression */
    buf++;

    /* Are we reading beyond the message buffer? */
    if( ( buf + 2 ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
    }

    ext_len = ( ( buf[0] << 8 ) | ( buf[1] ) );
    buf += 2; /* skip extension length */

    /* Are we reading beyond the message buffer? */
    if( ( buf + ext_len ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                              MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
    }

    ext = buf;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "hello retry request, total extension length: %d", ext_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "extensions", ext, ext_len );

    while ( ext_len )
    {
        ext_id = ( ( ext[0] << 8 ) | ( ext[1] ) );
        ext_size = ( ( ext[2] << 8 ) | ( ext[3] ) );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad hello retry request message" ) );
            SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                  MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
            return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        }

        switch ( ext_id )
        {
#if defined(MBEDTLS_SSL_COOKIE_C)
            case MBEDTLS_TLS_EXT_COOKIE:

                /* Retrieve length field of cookie */
                if( ext_size >= 2 )
                {
                    cookie = (unsigned char *) ( ext + 4 );
                    cookie_len = ( cookie[0] << 8 ) | cookie[1];
                    cookie += 2;
                }
                else
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad HRR message - cookie length mismatch" ) );
                    return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
                }

                if( ( cookie_len + 2 ) != ext_size )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad HRR message - cookie length mismatch" ) );
                    return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
                }

                MBEDTLS_SSL_DEBUG_BUF( 3, "cookie extension", cookie, cookie_len );

                mbedtls_free( ssl->handshake->verify_cookie );

                ssl->handshake->verify_cookie = mbedtls_calloc( 1, cookie_len );
                if( ssl->handshake->verify_cookie == NULL )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc failed ( %d bytes )", cookie_len ) );
                    return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
                }

                memcpy( ssl->handshake->verify_cookie, cookie, cookie_len );
                ssl->handshake->verify_cookie_len = (unsigned char) cookie_len;
                break;
#endif /* MBEDTLS_SSL_COOKIE_C */


            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported_versions extension" ) );

                ret = ssl_parse_supported_version_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                    return( ret );
                break;

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_KEY_SHARES:

                MBEDTLS_SSL_DEBUG_BUF( 3, "key_share extension", ext + 4, ext_size );

                /* Read selected_group */
                tls_id = ( ( ext[4] << 8 ) | ( ext[5] ) );
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "selected_group ( %d )", tls_id ) );

                info = mbedtls_ecp_curve_info_from_tls_id( tls_id );

                if( info != NULL )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 3, ( "selected_group by name ( %s )", info->name ) );
                }
                /*
                 * Upon receipt of this extension in a HelloRetryRequest, the client
                 * MUST first verify that the selected_group field corresponds to a
                 * group which was provided in the "supported_groups" extension in the
                 * original ClientHello.
                 *
                 * The supported_group was based on the info in ssl->conf->curve_list.
                 */

                for ( grp_id = ssl->conf->curve_list; *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++ ) {
                    /* In the initial ClientHello we transmitted the key shares based on
                     * key_shares_curve_list.
                     */
                    info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );

                    if( info == NULL ) return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

                    if( info->tls_id == tls_id )
                    {
                        /* We found a match */
                        found = 1;
                        break;
                    }
                }

                /* If the server provided a key share that was not sent in the ClientHello
                 * then the client MUST abort the handshake with an "illegal_parameter" alert.
                 */
                if( found == 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad HRR ( server provided key share that was not sent in ClientHello )" ) );
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                          MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
                    return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
                }

                /*
                 * Client MUST verify that the selected_group
                 * field does not correspond to a group which was provided in the
                 * "key_share" extension in the original ClientHello.
                 */
                found = 0;
                for ( grp_id = ssl->handshake->key_shares_curve_list;
                      *grp_id != MBEDTLS_ECP_DP_NONE; grp_id++ )
                {
                    info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );

                    if( info == NULL ) return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

                    if( info->tls_id == tls_id )
                    {
                        /* We found a match */
                        found = 1;
                        break;
                    }
                }

                /* If the server sent an HRR message with a key share already
                 * provided in the ClientHello then the client MUST abort the
                 * handshake with an "illegal_parameter" alert.
                 */
                if( found == 1 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad HRR ( server sent HRR with a key share already provided in ClientHello )" ) );
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                          MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
                    return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
                }

                /* Modify key_shares_curve_list for next ClientHello
                 * based on info provided by server. For the second
                 * ClientHello we only send the key share expected
                 * by the server.
                 */
                curve = mbedtls_ecp_curve_info_from_tls_id( tls_id );

                if( curve == NULL ) return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

                ssl->handshake->key_shares_curve_list[0] = curve->grp_id;
                ssl->handshake->key_shares_curve_list[1] = MBEDTLS_ECP_DP_NONE;

                break;
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
            return( MBEDTLS_ERR_SSL_BAD_HS_HELLO_RETRY_REQUEST );
        }

    }

    return( 0 );
}

static int ssl_hrr_postprocess( mbedtls_ssl_context* ssl,
                                const unsigned char* orig_buf,
                                size_t orig_msg_len )
{
    int ret = 0;

    ssl->handshake->hello_retry_requests_received++;

    MBEDTLS_SSL_DEBUG_MSG( 4, ( "Compress transcript hash for stateless HRR" ) );
    ret = mbedtls_ssl_hash_transcript( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hash_transcript", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        orig_buf, orig_msg_len );
#else /* MBEDTLS_SSL_USE_MPS */
    /* Add transcript for HRR */
    ssl->handshake->update_checksum( ssl, orig_buf, orig_msg_len );
#endif /* MBEDTLS_SSL_USE_MPS */

    return( 0 );
}

/*
 * TLS and DTLS 1.3 State Maschine -- client side
 */
int mbedtls_ssl_handshake_client_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Handshake completed but ssl->handshake is NULL.\n" ) );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "client state: %d", ssl->state ) );

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        return( ret );

    switch ( ssl->state )
    {
        case MBEDTLS_SSL_HELLO_REQUEST:
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );

#if defined(MBEDTLS_ECP_C)
            /* We need to initialize the handshake->key_shares_curve_list. */
            if( ssl->handshake->key_shares_curve_list == NULL )
            {
                /* We need to allocate one additional key share for the delimiter. */
                ssl->handshake->key_shares_curve_list =
                    mbedtls_calloc( 1, sizeof( mbedtls_ecp_group_id* ) * ( MBEDTLS_SSL_MAX_KEY_SHARES+1 ) );
                if( ssl->conf->key_shares_curve_list == NULL )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
                }
                memcpy( ssl->handshake->key_shares_curve_list,
                        ssl->conf->key_shares_curve_list,
                        sizeof( mbedtls_ecp_group_id ) * MBEDTLS_SSL_MAX_KEY_SHARES );

                /* We need to put a delimiter to the end of the key shares curve list */
                ssl->handshake->key_shares_curve_list[MBEDTLS_SSL_MAX_KEY_SHARES] = MBEDTLS_ECP_DP_NONE;
            }
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
            ssl->session_negotiate->endpoint = ssl->conf->endpoint;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
            break;

            /* ----- WRITE CLIENT HELLO ----*/

        case MBEDTLS_SSL_CLIENT_HELLO:

            ret = ssl_client_hello_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_client_hello", ret );
                break;
            }

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO );
#else
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_EARLY_APP_DATA );
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

#if defined(MBEDTLS_SSL_USE_MPS)
            ret = mbedtls_mps_flush( &ssl->mps.l4 );
            if( ret != 0 )
                break;
#endif /* MBEDTLS_SSL_USE_MPS */

            break;

            /* ----- WRITE CHANGE CIPHER SPEC ----*/

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO:

            ret = mbedtls_ssl_write_change_cipher_spec_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_change_cipher_spec_process", ret );
                break;
            }

            break;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

            /* ----- WRITE EARLY DATA ----*/

        case MBEDTLS_SSL_EARLY_APP_DATA:

            ret = ssl_write_early_data_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_early_data_process", ret );
                break;
            }

            break;

            /* ----- READ SERVER HELLO ----*/

        case MBEDTLS_SSL_SERVER_HELLO:
            /* In this state the client is expecting a ServerHello
             * message but the server could also return a HelloRetryRequest.
             *
             * Reset extensions we have seen so far.
             */
            ssl->handshake->extensions_present = NO_EXTENSION;
            ret = ssl_server_hello_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_server_hello_process", ret );
                break;
            }

            if( ssl->handshake->hello_retry_requests_received > 0 )
            {
                /* If we received the HRR msg then we send another ClientHello */
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
                /* If not offering early data, the client sends a dummy
                 * change_cipher_spec record immediately before its
                 * second flight. This may either be before its second
                 * ClientHello or before its encrypted handshake flight.
                 */
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO );
#else
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_CLIENT_HELLO );
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */
            }
            else
            {
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
            }
            break;

            /* ----- WRITE CHANGE_CIPHER_SPEC ----*/

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO:

            ret = mbedtls_ssl_write_change_cipher_spec_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_change_cipher_spec_process", ret );
                break;
            }

            break;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

            /* ----- WRITE 2nd CLIENT HELLO ----*/
        case MBEDTLS_SSL_SECOND_CLIENT_HELLO:
            ret = ssl_client_hello_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_client_hello", ret );
                break;
            }
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_SERVER_HELLO );

#if defined(MBEDTLS_SSL_USE_MPS)
            ret = mbedtls_mps_flush( &ssl->mps.l4 );
            if( ret != 0 )
                break;
#endif /* MBEDTLS_SSL_USE_MPS */

            break;

            /* ----- READ 2nd SERVER HELLO ----*/

        case MBEDTLS_SSL_SECOND_SERVER_HELLO:
            /* In this state the client is expecting a ServerHello
             * message and not the HRR anymore.
             */
            /* reset extensions we have seen so far */
            ssl->handshake->extensions_present = NO_EXTENSION;
            ret = ssl_server_hello_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_parse_server_hello", ret );
                break;
            }

            /* if we received a second HRR we abort */
            if( ssl->handshake->hello_retry_requests_received == 2 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Too many HelloRetryRequests received from server; I give up." ) );
                mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
                return ( MBEDTLS_ERR_SSL_BAD_HS_TOO_MANY_HRR );
            }
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
            break;

            /* ----- READ ENCRYPTED EXTENSIONS ----*/

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:

            ret = ssl_encrypted_extensions_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_encrypted_extensions_process", ret );
                break;
            }

            break;

            /* ----- READ CERTIFICATE REQUEST ----*/

        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_certificate_request_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_certificate_request_process", ret );
                break;
            }

            break;

            /* ----- READ SERVER CERTIFICATE ----*/

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = mbedtls_ssl_read_certificate_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_certificate_process", ret );
                break;
            }
            break;

            /* ----- READ CERTIFICATE VERIFY ----*/

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = mbedtls_ssl_read_certificate_verify_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_certificate_verify_process", ret );
                break;
            }

            break;

            /* ----- READ FINISHED ----*/

        case MBEDTLS_SSL_SERVER_FINISHED:

            ret = mbedtls_ssl_finished_in_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_finished_in_process", ret );
                break;
            }

            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_END_OF_EARLY_DATA );
            break;

            /* ----- WRITE END-OF-EARLY-DATA ----*/

        case MBEDTLS_SSL_END_OF_EARLY_DATA:

            ret = ssl_write_end_of_early_data_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_end_of_early_data_process", ret );
                break;
            }

            break;

            /* ----- WRITE CHANGE CIPHER SPEC ----*/

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED:

            ret = mbedtls_ssl_write_change_cipher_spec_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_change_cipher_spec_process", ret );
                break;
            }

            break;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */


            /* ----- WRITE CERTIFICATE ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:

            ret = mbedtls_ssl_write_certificate_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_certificate_process", ret );
                break;
            }
            break;

            /* ----- WRITE CLIENT CERTIFICATE VERIFY ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
            ret = mbedtls_ssl_certificate_verify_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_certificate_verify_process", ret );
                break;
            }
            break;

            /* ----- WRITE CLIENT FINISHED ----*/

        case MBEDTLS_SSL_CLIENT_FINISHED:
            ret = mbedtls_ssl_finished_out_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_finished_out_process", ret );
                break;
            }
            break;

        case MBEDTLS_SSL_FLUSH_BUFFERS:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake: done" ) );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for inbound traffic" ) );
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for outbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
            ret = mbedtls_mps_set_incoming_keys( &ssl->mps.l4,
                                                 ssl->epoch_application );
            if( ret != 0 )
                return( ret );

            ret = mbedtls_mps_set_outgoing_keys( &ssl->mps.l4,
                                                 ssl->epoch_application );
            if( ret != 0 )
                return( ret );
#else
            mbedtls_ssl_set_inbound_transform ( ssl, ssl->transform_application );
            mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_application );
#endif /* MBEDTLS_SSL_USE_MPS */

            mbedtls_ssl_handshake_wrapup( ssl );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
            break;

    case MBEDTLS_SSL_CLIENT_NEW_SESSION_TICKET:

            ret = mbedtls_ssl_new_session_ticket_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_new_session_ticket_process", ret );
                break;
            }

            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
            ret = MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
