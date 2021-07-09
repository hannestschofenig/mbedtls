/*
*  TLSv1.3 server-side functions
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

#if defined(MBEDTLS_SSL_SRV_C)

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "ssl_tls13_keys.h"

#include <string.h>

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif /* MBEDTLS_ECP_C */

#include "mbedtls/hkdf.h"

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
#include "mbedtls/ssl_ticket.h"
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif /* MBEDTLS_HAVE_TIME */


#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
static int ssl_write_sni_server_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf,
    size_t buflen,
    size_t *olen )
{
    unsigned char *p = buf;
    *olen = 0;

    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SERVERNAME ) == 0 )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding server_name extension" ) );

    if( buflen < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Write extension header */
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SERVERNAME >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SERVERNAME ) & 0xFF );

    /* Write total extension length */
    *p++ = 0;
    *p++ = 0;

    *olen = 4;

    return( 0 );
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */


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
static int ssl_write_key_shares_ext(
    mbedtls_ssl_context *ssl,
    unsigned char* buf,
    unsigned char* end,
    size_t* olen )
{
    unsigned char *p = buf + 4;
    unsigned char *header = buf; /* Pointer where the header has to go. */
    size_t len;
    int ret;

    const mbedtls_ecp_curve_info *info = NULL;
    /*	const mbedtls_ecp_group_id *grp_id; */

    *olen = 0;

    /* TBD: Can we say something about the smallest number of bytes needed for the ecdhe parameters */
    if( end < p || ( end - p ) < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    if( ssl->conf->curve_list == NULL )
    {
        /* This should never happen since we previously checked the
         * server-supported curves against the client-provided curves.
         * We should have returned a HelloRetryRequest instead.
         */
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "server key share extension: empty curve list" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding key share extension" ) );

    /* Fetching the agreed curve. */
    info = mbedtls_ecp_curve_info_from_grp_id( ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].grp.id );

    if( info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "server key share extension: fetching agreed curve failed" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDHE curve: %s", info->name ) );

    if( ( ret = mbedtls_ecp_group_load( &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].grp, info->grp_id ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecp_group_load", ret );
        return( ret );
    }

    if( ( ret = mbedtls_ecdh_make_tls_13_params( &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected], &len,
                                        p, end-buf,
                                        ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_make_tls_13_params", ret );
        return( ret );
    }

    p += len;

    MBEDTLS_SSL_DEBUG_ECP( 3, "ECDHE: Q ", &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].Q );

    /* Write extension header */
    *header++ = (unsigned char)( ( MBEDTLS_TLS_EXT_KEY_SHARES >> 8 ) & 0xFF );
    *header++ = (unsigned char)( ( MBEDTLS_TLS_EXT_KEY_SHARES ) & 0xFF );

    /* Write total extension length */
    *header++ = (unsigned char)( ( ( len ) >> 8 ) & 0xFF );
    *header++ = (unsigned char)( ( ( len ) ) & 0xFF );

    *olen = len + 4; /* 4 bytes for fixed header + length of key share */

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECDSA_C */


#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )

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
#endif /* MBEDTLS_ECP_C */
            return( -1 );

    MBEDTLS_SSL_DEBUG_ECP( 3, "ECDH: Qp", &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].Qp );

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C || ( MBEDTLS_ECDSA_C */

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )


/*
  mbedtls_ssl_parse_supported_groups_ext( ) processes the received
  supported groups extension and copies the client provided
  groups into ssl->handshake->curves.

  Possible response values are:
  - MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_GROUPS
  - MBEDTLS_ERR_SSL_ALLOC_FAILED
*/
int mbedtls_ssl_parse_supported_groups_ext(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, size_t len ) {

    size_t list_size, our_size;
    const unsigned char *p;
    const mbedtls_ecp_curve_info *curve_info, **curves;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Received supported groups", buf, len );

    list_size = ( ( buf[0] << 8 ) | ( buf[1] ) );
    if( list_size + 2 != len ||
        list_size % 2 != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad supported groups extension" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_GROUPS );
    }

    /* Should never happen unless client duplicates the extension */
    /*	if( ssl->handshake->curves != NULL )
	{
	MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad supported groups extension" ) );
	return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_GROUPS );
	}
    */
    /* Don't allow our peer to make us allocate too much memory,
     * and leave room for a final 0 */
    our_size = list_size / 2 + 1;
    if( our_size > MBEDTLS_ECP_DP_MAX )
        our_size = MBEDTLS_ECP_DP_MAX;

    if( ( curves = mbedtls_calloc( our_size, sizeof( *curves ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_calloc failed" ) );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    ssl->handshake->curves = curves;

    p = buf + 2;
    while ( list_size > 0 && our_size > 1 )
    {
        curve_info = mbedtls_ecp_curve_info_from_tls_id( ( p[0] << 8 ) | p[1] );

        /*
          mbedtls_ecp_curve_info_from_tls_id( ) uses the mbedtls_ecp_curve_info
          data structure ( defined in ecp.c ), which only includes the list of
          curves implemented. Hence, we only add curves that are also supported
          and implemented by the server.
        */

        if( curve_info != NULL )
        {
            *curves++ = curve_info;
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "supported curve: %s", curve_info->name ) );

            our_size--;
        }

        list_size -= 2;
        p += 2;
    }

    return( 0 );

}
#endif /* MBEDTLS_ECDH_C || ( MBEDTLS_ECDSA_C */

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
/*
 *  ssl_parse_key_shares_ext() verifies whether the information in the extension
 *  is correct and stores the provided key shares. Whether this is an acceptable
 *  key share depends on the selected ciphersuite.
 *
 *  Possible return values are:
 *  - 0: Successful processing of the client provided key share extension.
 *  - MBEDTLS_ERR_SSL_BAD_HS_WRONG_KEY_SHARE: The key share provided by the client
 *    does not match a group supported by the server. A HelloRetryRequest will
 *    be needed.
 *  - Another negative return value for fatal errors.
*/

static int ssl_parse_key_shares_ext(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    size_t len )
{
    int ret = 0, final_ret = 0, extensions_available = 1;
    unsigned char *end = (unsigned char*)buf + len;
    unsigned char *start = (unsigned char*)buf;
    unsigned char *old;

    size_t n;
    unsigned int ks_entry_size;

    int match_found = 0;

    const mbedtls_ecp_group_id *gid;

    /* Pick the first KeyShareEntry  */
    n = ( buf[0] << 8 ) | buf[1];

    if( n + 2 > len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad key share extension in client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }
    start += 2;

    /* We try to find a suitable key share entry and copy it to the
     * handshake context. Later, we have to find out whether we can do
     * something with the provided key share or whether we have to
     * dismiss it and send a HelloRetryRequest message. */

    /*
     * Ephemeral ECDH parameters:
     *
     * struct {
     *    NamedGroup group;
     *    opaque key_exchange<1..2^16-1>;
     * } KeyShareEntry;
     */

    /* Jump over extension length field to the first KeyShareEntry by advancing buf+2 */
    old = start;
    while( extensions_available )
    {
        ret = mbedtls_ecdh_read_tls_13_params(
            &ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected],
            (const unsigned char **) &start, end );

        if( ret != 0 )
        {
            /* For some reason we didn't recognize the key share. We jump
             * to the next one
             */

            MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ecdh_read_tls_13_params failed " ), ret );
            final_ret = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_SHARE;
            goto skip_parsing_key_share_entry;
        }

        /* Does the provided key share match any of our supported groups */
        for ( gid = ssl->conf->curve_list; *gid != MBEDTLS_ECP_DP_NONE; gid++ )
        {
            /* Currently we only support a single key share */
            /* Hence, we do not need a loop */
            if( ssl->handshake->ecdh_ctx[ssl->handshake->ecdh_ctx_selected].grp.id == *gid )
            {
                match_found = 1;

                ret = check_ecdh_params( ssl );

                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "check_ecdh_params: %d" ), ret );
                    final_ret = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;
                    goto skip_parsing_key_share_entry;
                }

                break;
            }
        }

        if( match_found == 0 )
        {
            /* A HelloRetryRequest is needed */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching curve for ECDHE" ) );
            final_ret = MBEDTLS_ERR_SSL_HRR_REQUIRED;
        }
        else
        {
            final_ret = 0;
            goto finish_key_share_parsing;
        }
    skip_parsing_key_share_entry:

        /* we jump to the next key share entry, if there is one */
        ks_entry_size = ( ( old[2] << 8 ) | ( old[3] ) );
        /* skip named group id + length field + key share entry length */
        start = old + ( ks_entry_size + 4 );
        old = start;
        if( start >= end )
        {
            /* we reached the end */
            final_ret = MBEDTLS_ERR_SSL_BAD_HS_WRONG_KEY_SHARE;
            extensions_available = 0;
        }
    }

finish_key_share_parsing:

    if( final_ret == 0 )
    {
        /* we found a key share we like */
        return ( 0 );
    }
    else {
        ( (void ) buf );
        return ( final_ret );
    }
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
int mbedtls_ssl_parse_new_session_ticket_server(
    mbedtls_ssl_context *ssl,
    unsigned char *buf,
    size_t len )
{
    int ret;
    unsigned char *ticket_buffer;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse new session ticket" ) );

    if( ssl->conf->f_ticket_parse == NULL ||
        ssl->conf->f_ticket_write == NULL )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket length: %d", len ) );

    if( len == 0 ) return( 0 );

    /* We create a copy of the encrypted ticket since decrypting
     * it into the same buffer will wipe-out the original content.
     * We do, however, need the original buffer for computing the
     * psk binder value.
     */
    ticket_buffer = mbedtls_calloc( len,1 );

    if( ticket_buffer == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    memcpy( ticket_buffer, buf, len );

    if( ( ret = ssl->conf->f_ticket_parse( ssl->conf->p_ticket, ssl->session_negotiate,
                                         ticket_buffer, len ) ) != 0 )
    {
        mbedtls_free( ticket_buffer );
        if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket is not authentic" ) );
        else if( ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED )
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket is expired" ) );
        else
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_ticket_parse", ret );

        return( ret );
    }

    /* We delete the temporary buffer */
    mbedtls_free( ticket_buffer );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse new session ticket" ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_parse_client_psk_identity_ext(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf,
    size_t len )
{
    int ret = 0;
    unsigned int item_array_length, item_length, sum, length_so_far;
    unsigned char server_computed_binder[MBEDTLS_MD_MAX_SIZE];
    const unsigned char *psk = NULL;
    unsigned char const * const start = buf;
    size_t psk_len = 0;
    unsigned char const *end_of_psk_identities;

    unsigned char transcript[MBEDTLS_MD_MAX_SIZE];
    size_t transcript_len;

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
    uint32_t obfuscated_ticket_age;
#if defined(MBEDTLS_HAVE_TIME)
    time_t now;
    int64_t diff;
#endif /* MBEDTLS_HAVE_TIME */
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

    /* Read length of array of identities */
    item_array_length = ( buf[0] << 8 ) | buf[1];
    length_so_far = item_array_length + 2;
    if( length_so_far > len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad psk_identity extension in client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }
    end_of_psk_identities = buf + length_so_far;
    buf += 2;
    sum = 2;
    while( sum < item_array_length + 2 )
    {
        /* Read to psk identity length */
        item_length = ( buf[0] << 8 ) | buf[1];
        sum = sum + 2 + item_length;

        if( sum > len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "psk_identity length mismatch" ) );

            if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        /*
         * Extract pre-shared key identity provided by the client
         */
        /* jump to identity value itself */
        buf += 2;

        MBEDTLS_SSL_DEBUG_BUF( 3, "received psk identity", buf, item_length );

        if( ssl->conf->f_psk != NULL )
        {
            if( ssl->conf->f_psk( ssl->conf->p_psk, ssl, buf, item_length ) != 0 )
                ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
        }
        else
        {
            /* Identity is not a big secret since clients send it in the clear,
             * but treat it carefully anyway, just in case */
            if( item_length != ssl->conf->psk_identity_len ||
                mbedtls_ssl_safer_memcmp( ssl->conf->psk_identity, buf, item_length ) != 0 )
            {
                ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
            }
            else
            {
                /* skip obfuscated ticket age */
                /* TBD: Process obfuscated ticket age ( zero for externally configured PSKs?! ) */
                buf = buf + item_length + 4; /* 4 for obfuscated ticket age */;

                mbedtls_ssl_set_hs_psk( ssl, ssl->conf->psk, ssl->conf->psk_len );
                goto psk_parsing_successful;

            }
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
            /* Check the ticket cache if previous lookup was unsuccessful */
            if( ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY )
            {
                /* copy ticket since it acts as the psk_identity */
                if( ssl->session_negotiate->ticket != NULL )
                {
                    mbedtls_free( ssl->session_negotiate->ticket );
                }
                ssl->session_negotiate->ticket = mbedtls_calloc( 1, item_length );
                if( ssl->session_negotiate->ticket == NULL )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc failed ( %d bytes )", item_length ) );
                    return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
                }
                memcpy( ssl->session_negotiate->ticket, buf, item_length );
                ssl->session_negotiate->ticket_len = item_length;

                ret = mbedtls_ssl_parse_new_session_ticket_server( ssl,
                                             ssl->session_negotiate->ticket,
                                             item_length );
                if( ret == 0 )
                {
                    /* found a match in the ticket cache; everything is OK */
                    ssl->handshake->resume = 1;

                    /* We put the resumption key into the handshake->psk.
                     *
                     * Note: The key in the ticket is already the final PSK,
                     *       i.e., the HKDF-Expand-Label( resumption_master_secret,
                     *                                    "resumption",
                     *                                    ticket_nonce,
                     *                                    Hash.length )
                     *       function has already been applied.
                     */
                    mbedtls_ssl_set_hs_psk( ssl, ssl->session_negotiate->key,
                                            ssl->session_negotiate->resumption_key_len );
                    MBEDTLS_SSL_DEBUG_BUF( 4, "Ticket-resumed PSK:", ssl->session_negotiate->key,
                                           ssl->session_negotiate->resumption_key_len );

                    /* obfuscated ticket age follows the identity field, which is
                     * item_length long, containing the ticket */
                    memcpy( &obfuscated_ticket_age, buf+item_length, 4 );

                    MBEDTLS_SSL_DEBUG_MSG( 4, ( "ticket: obfuscated_ticket_age: %u",
                                                obfuscated_ticket_age ) );
                    /*
                     * A server MUST validate that the ticket age for the selected PSK identity
                     * is within a small tolerance of the time since the ticket was issued.
                     */

#if defined(MBEDTLS_HAVE_TIME)
                    now = time( NULL );

                    /* Check #1:
                     *   Is the time when the ticket was issued later than now?
                     */

                    if( now < ssl->session_negotiate->start )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 3,
                               ( "Ticket expired: now=%d, ticket.start=%d",
                                 now, ssl->session_negotiate->start ) );
                        ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                    }

                    /* Check #2:
                     *   Is the ticket expired already?
                     */

                    if( now - ssl->session_negotiate->start > ssl->session_negotiate->ticket_lifetime )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 3,
                               ( "Ticket expired ( now - ticket.start=%d, "\
                                 "ticket.ticket_lifetime=%d",
                                 now - ssl->session_negotiate->start,
                                 ssl->session_negotiate->ticket_lifetime ) );

                        ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                    }

                    /* Check #3:
                     *   Is the ticket age for the selected PSK identity
                     *   (computed by subtracting ticket_age_add from
                     *   PskIdentity.obfuscated_ticket_age modulo 2^32 )
                     *   within a small tolerance of the time since the
                     *   ticket was issued?
                     */

                    diff = ( now - ssl->session_negotiate->start ) -
                        ( obfuscated_ticket_age - ssl->session_negotiate->ticket_age_add );

                    if( diff > MBEDTLS_SSL_TICKET_AGE_TOLERANCE )
                    {
                        MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "Ticket age outside tolerance window ( diff=%d )",
                              diff ) );
                        ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                    }

#if defined(MBEDTLS_ZERO_RTT)
                    if( ssl->conf->early_data_enabled == MBEDTLS_SSL_EARLY_DATA_ENABLED )
                    {
                        if( diff <= MBEDTLS_SSL_EARLY_DATA_MAX_DELAY )
                        {
                            ssl->session_negotiate->process_early_data =
                                MBEDTLS_SSL_EARLY_DATA_ENABLED;
                        }
                        else
                        {
                            MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "0-RTT is disabled ( diff=%d exceeds "\
                              "MBEDTLS_SSL_EARLY_DATA_MAX_DELAY )", diff ) );
                            ssl->session_negotiate->process_early_data =
                                MBEDTLS_SSL_EARLY_DATA_DISABLED;
                            ret = MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED;
                        }
                    }
#endif /* MBEDTLS_ZERO_RTT */
#endif /* MBEDTLS_HAVE_TIME */

                    /* TBD: check ALPN, ciphersuite and SNI as well */

                    /*
                     * If the check failed, the server SHOULD proceed with
                     * the handshake but reject 0-RTT, and SHOULD NOT take any
                     * other action that assumes that this ClientHello is fresh.
                     */

                    /* Disable 0-RTT */
                    if( ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED )
                    {
#if defined(MBEDTLS_ZERO_RTT)
                        if( ssl->conf->early_data_enabled ==
                            MBEDTLS_SSL_EARLY_DATA_ENABLED )
                        {
                            ssl->session_negotiate->process_early_data =
                                MBEDTLS_SSL_EARLY_DATA_DISABLED;
                        }
#else
                        ( ( void )buf );
#endif /* MBEDTLS_ZERO_RTT */
                    }
                }
            }
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
        }
        /* skip the processed identity field and obfuscated ticket age field */
        buf += item_length;
        buf += 4;
        sum = sum + 4;
    }

    if( ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Session ticket expired." ) );
        return( ret );
    }

    if( ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Unknown PSK identity", buf, item_length );
        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                   MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                   MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY ) ) != 0 )
        {
            return( ret );
        }

        return( MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY );
    }

    if( length_so_far != sum )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad psk_identity extension in client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

psk_parsing_successful:

    /* Update the handshake transcript with the CH content up to
     * but excluding the PSK binder list. */
    ssl->handshake->update_checksum( ssl, start,
                                     (size_t)( end_of_psk_identities - start ) );

    buf = end_of_psk_identities;

    /* Get current state of handshake transcript. */
    ret = mbedtls_ssl_get_handshake_transcript( ssl,
                                                ssl->handshake->ciphersuite_info->mac,
                                                transcript, sizeof( transcript ),
                                                &transcript_len );
    if( ret != 0 )
        return( ret );

    /* read length of psk binder array */
    item_array_length = ( buf[0] << 8 ) | buf[1];
    length_so_far += item_array_length;
    buf += 2;

    sum = 0;
    while( sum < item_array_length )
    {
        /* Read to psk binder length */
        item_length = buf[0];
        sum = sum + 1 + item_length;
        buf += 1;

        if( sum > item_array_length )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "psk binder length mismatch" ) );

            if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        psk = ssl->handshake->psk;
        psk_len = ssl->handshake->psk_len;

        ret = mbedtls_ssl_tls1_3_create_psk_binder( ssl,
                 psk, psk_len,
                 ssl->handshake->ciphersuite_info->mac,
                 !( ssl->handshake->resume == 1 ) /* external PSK */,
                 transcript, server_computed_binder );

        /* We do not check for multiple binders */
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "PSK binder calculation failed." ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder ( computed ): ",
                               server_computed_binder, item_length );
        MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder ( received ): ",
                               buf, item_length );

        if( mbedtls_ssl_safer_memcmp( server_computed_binder, buf,
                                      item_length ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1,
                ( "Received psk binder does not match computed psk binder." ) );

            if( ( ret = mbedtls_ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        buf += item_length;

        ret = 0;
        goto done;
    }

    /* No valid PSK binder value found */
    /* TODO: Shouldn't we just fall back to a full handshake in this case? */
    ret = MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO;

done:

    /* Update the handshake transcript with the binder list. */
    ssl->handshake->update_checksum( ssl,
                                     end_of_psk_identities,
                                     (size_t)( buf - end_of_psk_identities ) );

    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED*/

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/*
 * struct {
 *   select ( Handshake.msg_type ) {
 *      case client_hello:
 *          PskIdentity identities<6..2^16-1>;
 *
 *      case server_hello:
 *          uint16 selected_identity;
 *   }
 * } PreSharedKeyExtension;
 */

static int ssl_write_server_pre_shared_key_ext( mbedtls_ssl_context *ssl,
                                               unsigned char* buf,
                                               unsigned char* end,
                                               size_t* olen )
{
    unsigned char *p = (unsigned char*)buf;
    size_t selected_identity;

    *olen = 0;

    if( ssl->handshake->psk == NULL )
    {
        /* We shouldn't have called this extension writer unless we've
         * chosen to use a PSK. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding pre_shared_key extension" ) );

    if( end < p || ( end - p ) < 6 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Extension Type */
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_PRE_SHARED_KEY >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_PRE_SHARED_KEY ) & 0xFF );

    /* Extension Length */
    *p++ = (unsigned char)( ( 2 >> 8 ) & 0xFF );
    *p++ = (unsigned char)( 2 & 0xFF );

    /* NOTE: This will need to be adjusted once we support multiple PSKs
     *       being offered by the client. */
    selected_identity = 0;

    /* Write selected_identity */
    *p++ = (unsigned char)( ( selected_identity >> 8 ) & 0xFF );
    *p++ = (unsigned char)( selected_identity & 0xFF );

    *olen = 6;

    MBEDTLS_SSL_DEBUG_MSG( 4, ( "sent selected_identity: %d", selected_identity ) );

    return( 0 );
}
#endif	/* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED  */


#if defined(MBEDTLS_SSL_COOKIE_C)
int mbedtls_ssl_set_client_transport_id( mbedtls_ssl_context *ssl,
                                        const unsigned char *info,
                                        size_t ilen )
{
    if( ssl->conf->endpoint != MBEDTLS_SSL_IS_SERVER )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    mbedtls_free( ssl->cli_id );

    if( ( ssl->cli_id = mbedtls_calloc( 1, ilen ) ) == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    memcpy( ssl->cli_id, info, ilen );
    ssl->cli_id_len = ilen;

    return( 0 );
}
#endif /* MBEDTLS_SSL_COOKIE_C */

#if defined(MBEDTLS_SSL_COOKIE_C)
void mbedtls_ssl_conf_cookies( mbedtls_ssl_config *conf,
                              mbedtls_ssl_cookie_write_t *f_cookie_write,
                              mbedtls_ssl_cookie_check_t *f_cookie_check,
                              void *p_cookie,
                              unsigned int rr_config )
{
    conf->f_cookie_write = f_cookie_write;
    conf->f_cookie_check = f_cookie_check;
    conf->p_cookie = p_cookie;
    conf->rr_config = rr_config;
}
#endif /* MBEDTLS_SSL_COOKIE_C */

#if defined(MBEDTLS_SSL_COOKIE_C)
static int ssl_parse_cookie_ext( mbedtls_ssl_context *ssl,
                                 const unsigned char *buf,
                                 size_t len )
{
    int ret = 0;
    size_t cookie_len;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "parse cookie extension" ) );

    if( ssl->conf->f_cookie_check != NULL )
    {
        if( len >= 2 )
        {
            cookie_len = ( buf[0] << 8 ) | buf[1];
            buf += 2;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message - cookie length mismatch" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( cookie_len + 2 != len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message - cookie length mismatch" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        MBEDTLS_SSL_DEBUG_BUF( 3, "Received cookie", buf, cookie_len );

        if( ssl->conf->f_cookie_check( ssl->conf->p_cookie,
                      buf, cookie_len, ssl->cli_id, ssl->cli_id_len ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification failed" ) );
            ssl->handshake->verify_cookie_len = 1;
            ret = MBEDTLS_ERR_SSL_HRR_REQUIRED;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification passed" ) );
            ssl->handshake->verify_cookie_len = 0;
        }
    }
    else {
        /* TBD: Check under what cases this is appropriate */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification skipped" ) );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_COOKIE_C */



#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
static int ssl_parse_servername_ext( mbedtls_ssl_context *ssl,
                                    const unsigned char *buf,
                                    size_t len )
{
    int ret;
    size_t servername_list_size, hostname_len;
    const unsigned char *p;


    if( ssl->conf->p_sni == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "No SNI callback configured. Skip SNI parsing." ) );
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Parse ServerName extension" ) );

    servername_list_size = ( ( buf[0] << 8 ) | ( buf[1] ) );
    if( servername_list_size + 2 != len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    p = buf + 2;
    while ( servername_list_size > 0 )
    {
        hostname_len = ( ( p[1] << 8 ) | p[2] );
        if( hostname_len + 3 > servername_list_size )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( p[0] == MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME )
        {
            ret = ssl->conf->f_sni( ssl->conf->p_sni,
                                   ssl, p + 3, hostname_len );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_sni_wrapper", ret );
                mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                               MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME );
                return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
            }
            return( 0 );
        }

        servername_list_size -= hostname_len + 3;
        p += hostname_len + 3;
    }

    if( servername_list_size != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    return( 0 );
}
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */


#if defined(MBEDTLS_ZERO_RTT)
/*
  static int ssl_parse_early_data_ext( mbedtls_ssl_context *ssl,
  const unsigned char *buf,
  size_t len )
  {
  ( ( void* )ssl );
  ( ( void* )buf );
  return( 0 );
  }
*/
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static int ssl_parse_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             size_t len )
{
    if( len != 1 || buf[0] >= MBEDTLS_SSL_MAX_FRAG_LEN_INVALID )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->session_negotiate->mfl_code = buf[0];
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Maximum fragment length = %d", buf[0] ) );

    return( 0 );
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/*
 * ssl_parse_key_exchange_modes_ext( ) structure:
 *
 * enum { psk_ke( 0 ), psk_dhe_ke( 1 ), ( 255 ) } PskKeyExchangeMode;
 *
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 */

static int ssl_parse_key_exchange_modes_ext( mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             size_t len )
{
    size_t psk_mode_list_len;
    unsigned psk_key_exchange_modes = 0;

    /* Read PSK mode list length (1 Byte) */
    psk_mode_list_len = *buf++;
    len--;

    /* There's no content after the PSK mode list, to its length
     * must match the total length of the extension. */
    if( psk_mode_list_len != len )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    /* Currently, there are only two PSK modes, so even without looking
     * at the content, something's wrong if the list has more than 2 items. */
    if( psk_mode_list_len > 2 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    while( psk_mode_list_len-- != 0 )
    {
        switch( *buf )
        {
        case MBEDTLS_SSL_TLS13_PSK_MODE_PURE:
            psk_key_exchange_modes |= MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_KE;
            break;
        case MBEDTLS_SSL_TLS13_PSK_MODE_ECDHE:
            psk_key_exchange_modes |= MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_DHE_KE;
            break;
        default:
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }
    }

    ssl->session_negotiate->key_exchange_modes = psk_key_exchange_modes;
    return ( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */



/*
 * ssl_write_supported_version_ext( ):
 * ( as sent by server )
 *
 * case server_hello:
 *          ProtocolVersion selected_version;
 */

static int ssl_write_supported_version_ext( mbedtls_ssl_context *ssl,
                                            unsigned char* buf,
                                            unsigned char* end,
                                            size_t* olen )
{
    unsigned char *p = buf;
    *olen = 0;

    /* With only a single supported version we do not need the ssl structure. */
    ( (void ) ssl );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding supported version extension" ) );

    if( end < p || (size_t)( end - p ) < 6 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS ) & 0xFF );

    /* length */
    *p++ = 0x00;
    *p++ = 2;

    /* For TLS 1.3 and for DTLS 1.3 we use 0x0304 */
    *p++ = 0x03;
    *p++ = 0x04;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "version [%d:%d]", *( p-2 ), *( p-1 ) ) );

    *olen = 6;

    return( 0 );
}


static int ssl_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                            const unsigned char *buf, size_t len )
{
    size_t list_len;
    int major_ver, minor_ver;

    if( len < 3 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_parse_supported_versions_ext: Incorrect length" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_VERSIONS_EXT );
    }

    while ( len > 0 )
    {
        list_len = buf[0];

        /* length has to be at least 2 bytes long */
        if( list_len < 2 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_parse_supported_versions_ext: Incorrect length" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_VERSIONS_EXT );
        }

        /* skip length field */
        buf++;

        mbedtls_ssl_read_version( &major_ver, &minor_ver, ssl->conf->transport, buf );

        /* In this implementation we only support TLS 1.3 and DTLS 1.3. */
        if( major_ver == MBEDTLS_SSL_MAJOR_VERSION_3 &&
            minor_ver == MBEDTLS_SSL_MINOR_VERSION_4 )
        {
            /* we found a supported version */
            goto found_version;
        }
        else
        {
            /* if no match found, check next entry */
            buf += 2;
            len -= 3;
        }
    }

    /* If we got here then we have no version in common */
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS. Supported is [%d:%d]",
                              ssl->conf->min_major_ver, ssl->conf->min_minor_ver ) );

    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                          MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

found_version:

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Negotiated version. Supported is [%d:%d]",
                              major_ver, minor_ver ) );

    /* version in common */
    ssl->major_ver = major_ver;
    ssl->minor_ver = minor_ver;
    ssl->handshake->max_major_ver = ssl->major_ver;
    ssl->handshake->max_minor_ver = ssl->minor_ver;

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
    /* Store minor version for later use with ticket serialization. */
    ssl->session_negotiate->minor_ver = ssl->minor_ver;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

    return( 0 );
}

#if defined(MBEDTLS_SSL_ALPN)
static int ssl_parse_alpn_ext( mbedtls_ssl_context *ssl,
                              const unsigned char *buf, size_t len )
{
    size_t list_len, cur_len, ours_len;
    const unsigned char *theirs, *start, *end;
    const char **ours;

    /* If ALPN not configured, just ignore the extension */
    if( ssl->conf->alpn_list == NULL )
        return( 0 );

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     */

    /* Min length is 2 ( list_len ) + 1 ( name_len ) + 1 ( name ) */
    if( len < 4 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    list_len = ( buf[0] << 8 ) | buf[1];
    if( list_len != len - 2 )
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

    /*
     * Use our order of preference
     */
    start = buf + 2;
    end = buf + len;
    for ( ours = ssl->conf->alpn_list; *ours != NULL; ours++ )
    {
        ours_len = strlen( *ours );
        for ( theirs = start; theirs != end; theirs += cur_len )
        {
            /* If the list is well formed, we should get equality first */
            if( theirs > end )
                return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

            cur_len = *theirs++;

            /* Empty strings MUST NOT be included */
            if( cur_len == 0 )
                return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );

            if( cur_len == ours_len &&
                memcmp( theirs, *ours, cur_len ) == 0 )
            {
                ssl->alpn_chosen = *ours;
                return( 0 );
            }
        }
    }

    /* If we get there, no match was found */
    mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                   MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL );
    return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
}
#endif /* MBEDTLS_SSL_ALPN */

/*
 *
 * STATE HANDLING: NewSessionTicket message
 *
 */
#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

/* Main state-handling entry point; orchestrates the other functions. */
static int ssl_write_new_session_ticket_process( mbedtls_ssl_context* ssl );

#define SSL_NEW_SESSION_TICKET_SKIP  0
#define SSL_NEW_SESSION_TICKET_WRITE 1

static int ssl_write_new_session_ticket_coordinate( mbedtls_ssl_context* ssl );

static int ssl_write_new_session_ticket_write( mbedtls_ssl_context* ssl,
                                               unsigned char* buf,
                                               size_t buflen,
                                               size_t* olen );

/* Update the state after handling the incoming end of early data message. */
static int ssl_write_new_session_ticket_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */
static int ssl_write_new_session_ticket_process( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_write_new_session_ticket_coordinate( ssl ) );

    if( ret == SSL_NEW_SESSION_TICKET_WRITE )
    {
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_handshake_out msg;
        unsigned char *buf;
        mbedtls_mps_size_t buf_len, msg_len;

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

        msg.type   = MBEDTLS_SSL_HS_NEW_SESSION_TICKET;
        msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                           &msg, NULL, NULL ) );

        /* Request write-buffer */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle,
                                                      MBEDTLS_MPS_SIZE_MAX,
                                                      &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_write_new_session_ticket_write(
                                  ssl, buf, buf_len, &msg_len ) );

        /* Commit message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                         buf_len - msg_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

        MBEDTLS_SSL_PROC_CHK(
            ssl_write_new_session_ticket_postprocess( ssl ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */

        ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
        ssl->out_msg[0] = MBEDTLS_SSL_HS_NEW_SESSION_TICKET;
        MBEDTLS_SSL_PROC_CHK( ssl_write_new_session_ticket_write( ssl,
                                        ssl->out_msg,
                                        MBEDTLS_SSL_MAX_CONTENT_LEN,
                                        &ssl->out_msglen ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

        MBEDTLS_SSL_PROC_CHK(
            ssl_write_new_session_ticket_postprocess( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK(
            ssl_write_new_session_ticket_postprocess( ssl ) );
    }

cleanup:

    return( ret );
}

static int ssl_write_new_session_ticket_coordinate( mbedtls_ssl_context* ssl )
{
    /* Check whether the use of session tickets is enabled */
    if( ssl->conf->session_tickets == 0 )
    {
        return( SSL_NEW_SESSION_TICKET_SKIP );
    }

    return( SSL_NEW_SESSION_TICKET_WRITE );
}


static int ssl_write_new_session_ticket_postprocess( mbedtls_ssl_context* ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
    return( 0 );
}

/* This function creates a NewSessionTicket message in the following format:
 *
 * struct {
 *    uint32 ticket_lifetime;
 *    uint32 ticket_age_add;
 *    opaque ticket_nonce<0..255>;
 *    opaque ticket<1..2^16-1>;
 *    Extension extensions<0..2^16-2>;
 * } NewSessionTicket;
 *
 * The ticket inside the NewSessionTicket message is an encrypted container
 * carrying the necessary information so that the server is later able to
 * re-start the communication.
 *
 * The following fields are placed inside the ticket by the
 * f_ticket_write() function:
 *
 *  - creation time (start)
 *  - flags (flags)
 *  - lifetime (ticket_lifetime)
 *  - age add (ticket_age_add)
 *  - key (key)
 *  - key length (key_len)
 *  - ciphersuite (ciphersuite)
 *  - certificate of the peer (peer_cert)
 *
 */
static int ssl_write_new_session_ticket_write( mbedtls_ssl_context* ssl,
                                               unsigned char* buf,
                                               size_t buflen,
                                               size_t* olen )
{
    int ret;
    size_t tlen;
    size_t ext_len = 0;
    unsigned char *p;
    unsigned char *end = buf + buflen;
    mbedtls_ssl_ciphersuite_t *suite_info;
    int hash_length;
    unsigned char *ticket_lifetime_ptr;

#if defined(MBEDTLS_SSL_USE_MPS)
    size_t const total_length = 12 + MBEDTLS_SSL_TICKET_NONCE_LENGTH;
    p = buf;
#else
    size_t const total_length = 16 + MBEDTLS_SSL_TICKET_NONCE_LENGTH;
    p = buf + 4;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write NewSessionTicket msg" ) );

    /* Do we have space for the fixed length part of the ticket */
    if( buflen < total_length )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer for ticket too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    suite_info = (mbedtls_ssl_ciphersuite_t *) ssl->handshake->ciphersuite_info;

    hash_length = mbedtls_hash_size_for_ciphersuite( suite_info );

    if( hash_length == -1 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* In this code the psk key length equals the length of the hash */
    ssl->session->resumption_key_len = hash_length;
    ssl->session->ciphersuite = ssl->handshake->ciphersuite_info->id;

    /* Ticket Lifetime
     * (write it later)
     */
    ticket_lifetime_ptr = p;
    p+=4;

    /* Ticket Age Add */
    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                  (unsigned char*) &ssl->session->ticket_age_add,
                                  sizeof( ssl->session->ticket_age_add ) ) != 0 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Failed to generate ticket" ) );
        return( ret );
    }

    *(p++) = ( ssl->session->ticket_age_add >> 24 ) & 0xFF;
    *(p++) = ( ssl->session->ticket_age_add >> 16 ) & 0xFF;
    *(p++) = ( ssl->session->ticket_age_add >>  8 ) & 0xFF;
    *(p++) = ( ssl->session->ticket_age_add >>  0 ) & 0xFF;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->ticket_age_add: %u", ssl->session->ticket_age_add ) );

    /* Ticket Nonce */
    *(p++) = MBEDTLS_SSL_TICKET_NONCE_LENGTH;

    ret = ssl->conf->f_rng( ssl->conf->p_rng, p,
                            MBEDTLS_SSL_TICKET_NONCE_LENGTH );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 3, "ticket_nonce:",
                           p, MBEDTLS_SSL_TICKET_NONCE_LENGTH );

    MBEDTLS_SSL_DEBUG_BUF( 3, "resumption_master_secret",
                           ssl->session->app_secrets.resumption_master_secret,
                           hash_length );

    /* Computer resumption key
     *
     *  HKDF-Expand-Label( resumption_master_secret,
     *                    "resumption", ticket_nonce, Hash.length )
     */
    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( suite_info->mac,
               ssl->session->app_secrets.resumption_master_secret,
               hash_length,
               MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( resumption ),
               (const unsigned char *) p,
               MBEDTLS_SSL_TICKET_NONCE_LENGTH,
               ssl->session->key,
               hash_length );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 2, "Creating the ticket-resumed PSK failed", ret );
        return ( ret );
    }

    p += MBEDTLS_SSL_TICKET_NONCE_LENGTH;

    ssl->session->resumption_key_len = hash_length;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Ticket-resumed PSK",
                           ssl->session->key, hash_length );

    /* Ticket */
    ret = ssl->conf->f_ticket_write( ssl->conf->p_ticket,
                                     ssl->session,
                                     p + 2, end,
                                     &tlen,
                                     &ssl->session->ticket_lifetime);
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_ticket_write", ret );
        return( ret );
    }

    /* Ticket lifetime */
    *(ticket_lifetime_ptr++) = ( ssl->session->ticket_lifetime >> 24 ) & 0xFF;
    *(ticket_lifetime_ptr++) = ( ssl->session->ticket_lifetime >> 16 ) & 0xFF;
    *(ticket_lifetime_ptr++) = ( ssl->session->ticket_lifetime >>  8 ) & 0xFF;
    *(ticket_lifetime_ptr++) = ( ssl->session->ticket_lifetime >>  0 ) & 0xFF;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "ticket->ticket_lifetime: %d",
                               ssl->session->ticket_lifetime ) );

    /* Ticket Length */
    p[0] = (unsigned char)( ( tlen >> 8 ) & 0xFF );
    p[1] = (unsigned char)( ( tlen >> 0 ) & 0xFF );

    p += 2 + tlen;

    /* Ticket Extensions
     *
     * Note: We currently don't have any extensions.
     * Set length to zero.
     */
    *(p++) = ( ext_len >> 8 ) & 0xFF;
    *(p++) = ( ext_len >> 0 ) & 0xFF;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "NewSessionTicket (extension_length): %d", ext_len ) );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "NewSessionTicket (ticket length): %d", tlen ) );

    *olen = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 4, "ticket", buf, *olen );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write new session ticket" ) );

    return( ret );
}
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

/*
 *
 * STATE HANDLING: Parse End-of-Early Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_read_end_of_early_data_process( mbedtls_ssl_context* ssl );

#define SSL_END_OF_EARLY_DATA_SKIP   0
#define SSL_END_OF_EARLY_DATA_EXPECT 1

static int ssl_read_end_of_early_data_coordinate( mbedtls_ssl_context* ssl );

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_end_of_early_data_fetch( mbedtls_ssl_context* ssl );
#endif /* MBEDTLS_ZERO_RTT */

/* Update the state after handling the incoming end of early data message. */
static int ssl_read_end_of_early_data_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int ssl_read_end_of_early_data_process( mbedtls_ssl_context* ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse end_of_early_data" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_read_end_of_early_data_coordinate( ssl ) );
    if( ret == SSL_END_OF_EARLY_DATA_EXPECT )
    {
#if defined(MBEDTLS_ZERO_RTT)

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( ssl_end_of_early_data_fetch( ssl ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps.l4 ) );

        mbedtls_ssl_add_hs_hdr_to_checksum(
            ssl, MBEDTLS_SSL_HS_END_OF_EARLY_DATA, 0 );

#else /* MBEDTLS_SSL_USE_MPS */
        MBEDTLS_SSL_PROC_CHK( ssl_end_of_early_data_fetch( ssl ) );
#endif /* MBEDTLS_SSL_USE_MPS */

#else /* MBEDTLS_ZERO_RTT */

        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#endif /* MBEDTLS_ZERO_RTT */

    }

    /* Postprocessing step: Update state machine */
    MBEDTLS_SSL_PROC_CHK( ssl_read_end_of_early_data_postprocess( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse end_of_early_data" ) );
    return( ret );

}

#if defined(MBEDTLS_ZERO_RTT)

#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_end_of_early_data_fetch( mbedtls_ssl_context *ssl )
{
    int ret;
    mbedtls_mps_handshake_in msg;

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps.l4 ) );

    if( ret != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_handshake( &ssl->mps.l4,
                                                      &msg ) );

    if( msg.type != MBEDTLS_SSL_HS_END_OF_EARLY_DATA ||
        msg.length != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, (
             "Bad EndOfEarlyData message: Type %u (expect %u), "
             "Length %u (expect %u)",
             (unsigned) msg.type, MBEDTLS_SSL_HS_END_OF_EARLY_DATA,
             (unsigned) msg.length, 0 ) );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

cleanup:

    return( ret );
}
#else /* MBEDTLS_SSL_USE_MPS */
static int ssl_end_of_early_data_fetch( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE        ||
        ssl->in_msg[0]  != MBEDTLS_SSL_HS_END_OF_EARLY_DATA ||
        ssl->in_hslen   != 4 )
    {
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */

#endif /* MBEDTLS_ZERO_RTT */

#if !defined(MBEDTLS_ZERO_RTT)
static int ssl_read_end_of_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    ((void) ssl);
    return( SSL_END_OF_EARLY_DATA_SKIP );
}
#else /* MBEDTLS_ZERO_RTT */
static int ssl_read_end_of_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_END_OF_EARLY_DATA_SKIP );

    return( SSL_END_OF_EARLY_DATA_EXPECT );
}
#endif /* MBEDTLS_ZERO_RTT */

static int ssl_read_end_of_early_data_postprocess( mbedtls_ssl_context* ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
    return ( 0 );
}

/*
 *
 * STATE HANDLING: Parse Early Data
 *
 */

 /*
  * Overview
  */

  /* Main state-handling entry point; orchestrates the other functions. */
int ssl_read_early_data_process( mbedtls_ssl_context* ssl );

#define SSL_EARLY_DATA_SKIP   0
#define SSL_EARLY_DATA_EXPECT 1

#if defined(MBEDTLS_ZERO_RTT)
#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_early_data_fetch( mbedtls_ssl_context* ssl,
                                 mbedtls_mps_reader **reader );
#else
static int ssl_early_data_fetch( mbedtls_ssl_context* ssl,
                                 unsigned char** buf,
                                 size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */
#endif /* MBEDTLS_ZERO_RTT */

static int ssl_read_early_data_coordinate( mbedtls_ssl_context* ssl );

#if defined(MBEDTLS_ZERO_RTT)
/* Parse early data send by the peer. */
static int ssl_read_early_data_parse( mbedtls_ssl_context* ssl,
    unsigned char const* buf,
    size_t buflen );
#endif /* MBEDTLS_ZERO_RTT */

/* Update the state after handling the incoming early data message. */
static int ssl_read_early_data_postprocess( mbedtls_ssl_context* ssl );

/*
 * Implementation
 */

int ssl_read_early_data_process( mbedtls_ssl_context* ssl )
{
    int ret;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse early data" ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_read_early_data_coordinate( ssl ) );

    if( ret == SSL_EARLY_DATA_EXPECT )
    {
#if defined(MBEDTLS_ZERO_RTT)
        unsigned char *buf;
        size_t buflen;
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_reader *rd;
#endif /* MBEDTLS_SSL_USE_MPS */

#if defined(MBEDTLS_SSL_USE_MPS)
        MBEDTLS_SSL_PROC_CHK( ssl_early_data_fetch( ssl, &rd ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_get( rd,
                                                  MBEDTLS_MPS_SIZE_MAX,
                                                  &buf,
                                                  &buflen ) );
        MBEDTLS_SSL_PROC_CHK( ssl_read_early_data_parse( ssl, buf, buflen ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_reader_commit( rd ) );
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_consume( &ssl->mps.l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */

        MBEDTLS_SSL_PROC_CHK( ssl_early_data_fetch( ssl, &buf, &buflen ) );
        MBEDTLS_SSL_PROC_CHK( ssl_read_early_data_parse( ssl, buf, buflen ) );

#endif /* MBEDTLS_SSL_USE_MPS */

        /* No state machine update at this point -- we might receive
         * multiple 0-RTT messages. */

#else /* MBEDTLS_ZERO_RTT */

        /* Should never happen */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

#endif /* MBEDTLS_ZERO_RTT */
    }
    else
    {
        MBEDTLS_SSL_PROC_CHK( ssl_read_early_data_postprocess( ssl ) );
    }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse early data" ) );
    return( ret );
}

#if defined(MBEDTLS_ZERO_RTT)
#if defined(MBEDTLS_SSL_USE_MPS)
static int ssl_early_data_fetch( mbedtls_ssl_context *ssl,
                                 mbedtls_mps_reader **rd )
{
    int ret;
    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps.l4 ) );

    if( ret != MBEDTLS_MPS_MSG_APP )
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_read_application( &ssl->mps.l4, rd ) );

cleanup:

    return( ret );
}
#else /* MBEDTLS_SSL_USE_MPS */
static int ssl_early_data_fetch( mbedtls_ssl_context *ssl,
                                 unsigned char **buf,
                                 size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
    {
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                              MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    *buf    = ssl->in_msg;
    *buflen = ssl->in_hslen;

cleanup:

    return( ret );
}
#endif /* MBEDTLS_SSL_USE_MPS */
#endif /* MBEDTLS_ZERO_RTT */

#if !defined(MBEDTLS_ZERO_RTT)
static int ssl_read_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    ((void) ssl);
    return( SSL_EARLY_DATA_SKIP );
}
#else /* MBEDTLS_ZERO_RTT */
static int ssl_read_early_data_coordinate( mbedtls_ssl_context* ssl )
{
    int ret;

    if( ssl->handshake->early_data != MBEDTLS_SSL_EARLY_DATA_ON )
        return( SSL_EARLY_DATA_SKIP );

    /* Activate early data transform */
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to 0-RTT keys for inbound traffic" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_set_incoming_keys( &ssl->mps.l4,
                                                   ssl->epoch_earlydata ) );

    MBEDTLS_SSL_PROC_CHK_NEG( mbedtls_mps_read( &ssl->mps.l4 ) );
    if( ret != MBEDTLS_MPS_MSG_APP )
        return( SSL_EARLY_DATA_SKIP );

    return( SSL_EARLY_DATA_EXPECT );

cleanup:

    return( ret );

#else /* MBEDTLS_SSL_USE_MPS */

    mbedtls_ssl_set_inbound_transform( ssl, ssl->transform_earlydata );

    /* Fetching step */
    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    ssl->keep_current_message = 1;

    /* Check for EndOfEarlyData */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
        return( SSL_EARLY_DATA_SKIP );

    return( SSL_EARLY_DATA_EXPECT );

#endif /* MBEDTLS_SSL_USE_MPS */
}

static int ssl_read_early_data_parse( mbedtls_ssl_context* ssl,
                                      unsigned char const* buf,
                                      size_t buflen )
{
    /* Check whether we have enough buffer space. */
    if( buflen <= ssl->conf->max_early_data )
    {
        /* TODO: We need to check that we're not receiving more 0-RTT
         * than what the ticket allows. */

        /* copy data to staging area */
        memcpy( ssl->early_data_server_buf, buf, buflen );
        /* execute callback to process application data */
        ssl->conf->early_data_callback( ssl, ssl->early_data_server_buf,
                                        buflen );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Buffer too small (recv %d bytes, buffer %d bytes)",
                                    buflen, ssl->conf->max_early_data ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT */

static int ssl_read_early_data_postprocess( mbedtls_ssl_context* ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_END_OF_EARLY_DATA );
    return ( 0 );
}


/*
 *
 * STATE HANDLING: ClientHello
 *
 * There are three possible classes of outcomes when parsing the CH:
 *
 * 1) The CH was well-formed and matched the server's configuration.
 *
 *    In this case, the server progresses to sending its ServerHello.
 *
 * 2) The CH was well-formed but didn't match the server's configuration.
 *
 *    For example, the client might not have offered a key share which
 *    the server supports, or the server might require a cookie.
 *
 *    In this case, the server sends a HelloRetryRequest.
 *
 * 3) The CH was ill-formed
 *
 *    In this case, we abort the handshake.
 *
 */

/*
 * Overview
 */

/* Main entry point from the state machine; orchestrates the otherfunctions. */
static int ssl_client_hello_process( mbedtls_ssl_context* ssl );

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_client_hello_fetch( mbedtls_ssl_context* ssl,
                                   unsigned char** buf,
                                   size_t* buflen );
#endif /* MBEDTLS_SSL_USE_MPS */

static int ssl_client_hello_parse( mbedtls_ssl_context* ssl,
                                   unsigned char* buf,
                                   size_t buflen );

/* Update the handshake state machine */
/* TODO: At the moment, this doesn't update the state machine - why? */
static int ssl_client_hello_postprocess( mbedtls_ssl_context* ssl,
                                         int hrr_required );

/*
 * Implementation
 */

#define SSL_CLIENT_HELLO_OK           0
#define SSL_CLIENT_HELLO_HRR_REQUIRED 1

static int ssl_client_hello_process( mbedtls_ssl_context* ssl )
{

    int ret = 0;
    int hrr_required = SSL_CLIENT_HELLO_OK;
    unsigned char* buf = NULL;
    size_t buflen = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse client hello" ) );

#if defined(MBEDTLS_SSL_USE_MPS)

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_fetch_full_hs_msg( ssl,
                                            MBEDTLS_SSL_HS_CLIENT_HELLO,
                                            &buf, &buflen ) );

    mbedtls_ssl_add_hs_hdr_to_checksum( ssl,
                  MBEDTLS_SSL_HS_CLIENT_HELLO, buflen );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_client_hello_parse( ssl, buf, buflen ) );
    hrr_required = ret;

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_mps_hs_consume_full_hs_msg( ssl ) );

#else /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_client_hello_fetch( ssl, &buf, &buflen ) );
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_client_hello_parse( ssl, buf, buflen ) );
    hrr_required = ret;

#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "postprocess" ) );
    MBEDTLS_SSL_PROC_CHK( ssl_client_hello_postprocess( ssl, hrr_required ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );
    return( ret );
}

#if !defined(MBEDTLS_SSL_USE_MPS)
static int ssl_client_hello_fetch( mbedtls_ssl_context* ssl,
                                   unsigned char** dst,
                                   size_t* dstlen )
{
    int ret;
    unsigned char* buf;
    size_t msg_len;

    if( ( ret = mbedtls_ssl_fetch_input( ssl, 5 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    buf = ssl->in_hdr;

    MBEDTLS_SSL_DEBUG_BUF( 4, "record header", buf,
             mbedtls_ssl_hdr_len( ssl ) );

    /*
     * TLS Client Hello
     *
     * Record layer:
     *     0  .   0   message type
     *     1  .   2   protocol version
     *     3  .   11  DTLS: epoch + record sequence number
     *     3  .   4   message length
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, message type: %d", buf[0] ) );

    if( buf[0] != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        if( buf[0] == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
        {
            msg_len = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];

            if( msg_len != 1 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad CCS message" ) );
                return( MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
            }

            MBEDTLS_SSL_DEBUG_MSG( 3, ( "CCS, message len.: %d", msg_len ) );

            if( ( ret = mbedtls_ssl_fetch_input( ssl,
                            mbedtls_ssl_hdr_len( ssl ) + msg_len ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
                return( MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
            }

            if( ssl->in_msg[0] == 1 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "Change Cipher Spec message received and ignoring it." ) );
                ssl->in_left = 0;
                return ( MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
            }
            else
            {
                if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                                          MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                          MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE ) ) != 0 )
                {
                    return( ret );
                }
                return ( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
            }
        }
        else
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Spurious message ( maybe alert message )" ) );

            return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, message len.: %d",
                              ( ssl->in_len[0] << 8 ) | ssl->in_len[1] ) );

    msg_len = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];

    if( msg_len > MBEDTLS_SSL_MAX_CONTENT_LEN )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    if( ( ret = mbedtls_ssl_fetch_input( ssl,
                      mbedtls_ssl_hdr_len( ssl ) + msg_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->in_left = 0;
    buf = ssl->in_msg;

    MBEDTLS_SSL_DEBUG_BUF( 4, "record contents", buf, msg_len );

    /*
     * Handshake layer:
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   DTLS only: message seqence number
     *     6  .   8   DTLS only: fragment offset
     *     9  .  11   DTLS only: fragment length
     */
    if( msg_len < mbedtls_ssl_hs_hdr_len( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello v3, handshake type: %d", buf[0] ) );

    if( buf[0] != MBEDTLS_SSL_HS_CLIENT_HELLO )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello v3, handshake len.: %d",
                              ( buf[1] << 16 ) | ( buf[2] << 8 ) | buf[3] ) );

    /* We don't support fragmentation of ClientHello ( yet? ) */
    if( buf[1] != 0 ||
        msg_len != mbedtls_ssl_hs_hdr_len( ssl ) + ( ( buf[2] << 8 ) | buf[3] ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    *dst = ssl->in_msg;
    *dstlen = msg_len;
    return( 0 );
}

#endif /* MBEDTLS_SSL_USE_MPS */

static void ssl_debug_print_client_hello_exts( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Supported Extensions:" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- KEY_SHARE_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_KEY_SHARE ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- PSK_KEY_EXCHANGE_MODES_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- PRE_SHARED_KEY_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SIGNATURE_ALGORITHM_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SIGNATURE_ALGORITHM ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SUPPORTED_GROUPS_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_GROUPS ) >0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SUPPORTED_VERSION_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_VERSION ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#if defined ( MBEDTLS_SSL_SERVER_NAME_INDICATION )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SERVERNAME_EXTENSION    ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SERVERNAME ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#if defined ( MBEDTLS_SSL_ALPN )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- ALPN_EXTENSION   ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_ALPN ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_ALPN */
#if defined ( MBEDTLS_SSL_MAX_FRAGMENT_LENGTH )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- MAX_FRAGMENT_LENGTH_EXTENSION  ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_MAX_FRAGMENT_LENGTH ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */
#if defined ( MBEDTLS_SSL_COOKIE_C )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- COOKIE_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_COOKIE ) >0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_COOKIE_C */
#if defined(MBEDTLS_ZERO_RTT)
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- EARLY_DATA_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_EARLY_DATA ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_ZERO_RTT*/
}

static int ssl_client_hello_has_psk_extensions( mbedtls_ssl_context *ssl )
{
    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY ) &&
        ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) )
    {
        return( 1 );
    }

    return( 0 );
}

static int ssl_client_hello_has_cert_extensions( mbedtls_ssl_context *ssl )
{
    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_GROUPS )    &&
        ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SIGNATURE_ALGORITHM ) &&
        ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_KEY_SHARE ) )
    {
        return( 1 );
    }

    return( 0 );
}

static int ssl_client_hello_allows_psk_mode( mbedtls_ssl_context *ssl,
                                             unsigned psk_mode )
{
    if( ( ssl->session_negotiate->key_exchange_modes & psk_mode ) != 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int ssl_client_hello_allows_pure_psk( mbedtls_ssl_context *ssl )
{
    return( ssl_client_hello_allows_psk_mode( ssl,
                           MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_KE ) );
}

static int ssl_client_hello_allows_psk_ecdhe( mbedtls_ssl_context *ssl )
{
    return( ssl_client_hello_allows_psk_mode( ssl,
                           MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_DHE_KE ) );
}

static int ssl_check_psk_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !ssl_client_hello_has_psk_extensions( ssl ) )
        return( 0 );

    /* Test whether pure PSK is offered by client and supported by us. */
    if( mbedtls_ssl_conf_tls13_pure_psk_enabled( ssl ) &&
        ssl_client_hello_allows_pure_psk( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using a PSK key exchange" ) );
        ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_PSK;
        return( 1 );
    }

    /* Test whether PSK-ECDHE is offered by client and supported by us. */
    if( mbedtls_ssl_conf_tls13_psk_ecdhe_enabled( ssl ) &&
        ssl_client_hello_allows_psk_ecdhe( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Using a ECDHE-PSK key exchange" ) );
        ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_ECDHE_PSK;
        return( 1 );
    }

    /* Can't use PSK */
    return( 0 );
}

static int ssl_check_certificate_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !mbedtls_ssl_conf_tls13_pure_ecdhe_enabled( ssl ) )
        return( 0 );

    if( !ssl_client_hello_has_cert_extensions( ssl ) )
        return( 0 );

    ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA;
    return( 1 );
}

#if defined(MBEDTLS_ZERO_RTT)
static int ssl_check_use_0rtt_handshake( mbedtls_ssl_context *ssl )
{
    /* Check if the user has enabled 0-RTT in the config */
    if( !mbedtls_ssl_conf_tls13_0rtt_enabled( ssl ) )
        return( 0 );

    /* Check if the client has indicated the use of 0-RTT */
    if( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_EARLY_DATA ) == 0 )
        return( 0 );

    /* If the client has indicated the use of 0-RTT but not sent
     * the PSK extensions, that's not conformant (and there's no
     * way to continue from here). */
    if( !ssl_client_hello_has_psk_extensions( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Client indicated 0-RTT without offering PSK extensions" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /* Accept 0-RTT */
    ssl->handshake->early_data = MBEDTLS_SSL_EARLY_DATA_ON;
    return( 0 );
}
#endif /* MBEDTLS_ZERO_RTT*/

static int ssl_client_hello_parse( mbedtls_ssl_context* ssl,
                                  unsigned char* buf,
                                  size_t buflen )
{
    int ret, final_ret = 0, got_common_suite;
    size_t i, j;
    size_t comp_len, sess_len;
    size_t ciph_len, ext_len, ext_len_psk_ext = 0;
    unsigned char *orig_buf, *end = buf + buflen;
    unsigned char *ciph_offset;
    unsigned char *p = NULL;
    unsigned char *ext = NULL;
    unsigned char *ext_psk_ptr = NULL;

    const int* ciphersuites;
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info;

    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;
    ssl->session_negotiate->key_exchange = MBEDTLS_KEY_EXCHANGE_NONE;

    /* TBD: Refactor */
    orig_buf = buf;

    /*
     * ClientHello layer:
     *     0  .   1   protocol version
     *     2  .  33   random bytes ( starting with 4 bytes of Unix time )
     *    34  .  35   session id length ( 1 byte )
     *    35  . 34+x  session id
     *   35+x . 35+x  DTLS only: cookie length ( 1 byte )
     *   36+x .  ..   DTLS only: cookie
     *    ..  .  ..   ciphersuite list length ( 2 bytes )
     *    ..  .  ..   ciphersuite list
     *    ..  .  ..   compression alg. list length ( 1 byte )
     *    ..  .  ..   compression alg. list
     *    ..  .  ..   extensions length ( 2 bytes, optional )
     *    ..  .  ..   extensions ( optional )
     */

#if !defined(MBEDTLS_SSL_USE_MPS)
    buf    += mbedtls_ssl_hs_hdr_len( ssl );
    buflen -= mbedtls_ssl_hs_hdr_len( ssl );
#endif /* MBEDTLS_SSL_USE_MPS */

    /* TBD: Needs to be updated due to mandatory extensions
     * Minimal length ( with everything empty and extensions ommitted ) is
     * 2 + 32 + 1 + 2 + 1 = 38 bytes. Check that first, so that we can
     * read at least up to session id length without worrying.
     */
    if( buflen < 38 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /*
     * We ignore the version field in the ClientHello.
     * We use the version field in the extension.
     */
    buf += 2; /* skip version */

    /*
     * Save client random
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes", buf, 32 );

    memcpy( &ssl->handshake->randbytes[0], buf, 32 );
    buf += 32; /* skip random bytes */

    /*
     * Parse session ID
     */
    sess_len = buf[0];
    buf++; /* skip session id length */

    if( sess_len > 32 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ssl->session_negotiate->id_len = sess_len;

    /* Note that this field is echoed even if
     * the client's value corresponded to a cached pre-TLS 1.3 session
     * which the server has chosen not to resume. A client which
     * receives a legacy_session_id_echo field that does not match what
     * it sent in the ClientHello MUST abort the handshake with an
     * "illegal_parameter" alert.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, session id length ( %d )", sess_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, session id", buf, sess_len );

    memcpy( &ssl->session_negotiate->id[0], buf, sess_len ); /* write session id */
    buf += sess_len;

    ciph_len = ( buf[0] << 8 ) | ( buf[1] );

    /* Length check */
    if( buf + ciph_len > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /* store pointer to ciphersuite list */
    ciph_offset = buf;

    /* skip cipher length */
    buf += 2;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, ciphersuitelist",
                          buf, ciph_len );

    /* skip ciphersuites for now */
    buf += ciph_len;

    /*
     * For TLS 1.3 we are not using compression.
     */
    comp_len = buf[0];

    if( buf + comp_len > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    buf++; /* skip compression length */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, compression",
                          buf, comp_len );

    /* Determine whether we are indeed using null compression */
    if( ( comp_len != 1 ) && ( buf[1] == 0 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    /* skip compression */
    buf++;

    /*
     * Check the extension length
     */
    if( buf+2 > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    ext_len = ( buf[0] << 8 )	| ( buf[1] );

    if( ( ext_len > 0 && ext_len < 4 ) ||
        buf + 2 + ext_len > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    buf += 2;

    ext = buf;
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", ext, ext_len );

    while( ext_len != 0 )
    {
        unsigned int ext_id, ext_size;

        if( ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        /* The PSK extension must be the last in the ClientHello.
         * Fail if we've found it already but haven't yet reached
         * the end of the extension block. */
        if( ext_psk_ptr != NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        ext_id   = ( ( (size_t) ext[0] << 8 ) | ( (size_t) ext[1] << 0 ) );
        ext_size = ( ( (size_t) ext[2] << 8 ) | ( (size_t) ext[3] << 0 ) );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        switch( ext_id )
        {
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
            case MBEDTLS_TLS_EXT_SERVERNAME:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found ServerName extension" ) );
                ret = ssl_parse_servername_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_parse_servername_ext", ret );
                    return( MBEDTLS_ERR_SSL_BAD_HS_SERVERNAME_EXT );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SERVERNAME;
                break;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_COOKIE_C)
            case MBEDTLS_TLS_EXT_COOKIE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found cookie extension" ) );

                ret = ssl_parse_cookie_ext( ssl, ext + 4, ext_size );

                /* if cookie verification failed then we return a hello retry message */
                if( ret == MBEDTLS_ERR_SSL_HRR_REQUIRED )
                {
                    final_ret = ret;
                }
                else if( ret == 0 ) /* cookie extension present and processed succesfully */
                {
                    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_COOKIE;
                }
                break;
#endif /* MBEDTLS_SSL_COOKIE_C  */

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension" ) );
                /* Delay processing of the PSK identity once we have
                 * found out which algorithms to use. We keep a pointer
                 * to the buffer and the size for later processing.
                 */
                ext_len_psk_ext = ext_size;
                ext_psk_ptr = ext + 4;

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PRE_SHARED_KEY;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED */

#if defined(MBEDTLS_ZERO_RTT)
            case MBEDTLS_TLS_EXT_EARLY_DATA:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found early_data extension" ) );

                /* There is nothing really to process with this extension.

                   ret = ssl_parse_early_data_ext( ssl, ext + 4, ext_size );
                   if( ret != 0 ) {
                   MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_parse_supported_groups_ext", ret );
                   return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_GROUPS );
                   }
                */
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_EARLY_DATA;
                break;
#endif /* MBEDTLS_ZERO_RTT */

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported group extension" ) );

                /* Supported Groups Extension
                 *
                 * When sent by the client, the "supported_groups" extension
                 * indicates the named groups which the client supports,
                 * ordered from most preferred to least preferred.
                 */
                ret = mbedtls_ssl_parse_supported_groups_ext( ssl, ext + 4,
                        ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_parse_supported_groups_ext", ret );
                    return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_GROUPS );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_GROUPS;
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
            case MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found psk key exchange modes extension" ) );

                ret = ssl_parse_key_exchange_modes_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_parse_key_exchange_modes_ext", ret );
                    return( MBEDTLS_ERR_SSL_BAD_HS_PSK_KEY_EXCHANGE_MODES_EXT );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )
            case MBEDTLS_TLS_EXT_KEY_SHARES:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key share extension" ) );

                /*
                 * Key Share Extension
                 *
                 * When sent by the client, the "key_share" extension
                 * contains the endpoint's cryptographic parameters for
                 * ECDHE/DHE key establishment methods.
                 */
                ret = ssl_parse_key_shares_ext( ssl, ext + 4, ext_size );
                if( ret == MBEDTLS_ERR_SSL_BAD_HS_WRONG_KEY_SHARE )
                {
                    /* We need to send a HelloRetryRequest message
                     * but we still have to determine the ciphersuite.
                     * Note: We got the key share - we just didn't like
                     *       the content of it.
                     */
                    final_ret = MBEDTLS_ERR_SSL_HRR_REQUIRED;
                    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
                    break;
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
            case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found max fragment length extension" ) );

                ret = ssl_parse_max_fragment_length_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_max_fragment_length_ext" ), ret );
                    return( MBEDTLS_ERR_SSL_BAD_HS_MAX_FRAGMENT_LENGTH_EXT );
                }
                ssl->handshake->extensions_present |= MAX_FRAGMENT_LENGTH_EXTENSION;
                break;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported versions extension" ) );

                ret = ssl_parse_supported_versions_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_supported_versions_ext" ), ret );
                    return( MBEDTLS_ERR_SSL_BAD_HS_SUPPORTED_VERSIONS_EXT );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_VERSION;
                break;

#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found alpn extension" ) );

                ret = ssl_parse_alpn_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_alpn_ext" ), ret );
                    return( MBEDTLS_ERR_SSL_BAD_HS_ALPN_EXT );
                }
                ssl->handshake->extensions_present |= ALPN_EXTENSION;
                break;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found signature_algorithms extension" ) );

                ret = mbedtls_ssl_parse_signature_algorithms_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_parse_supported_signature_algorithms_server_ext ( %d )", ret ) );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIGNATURE_ALGORITHM;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown extension found: %d ( ignoring )", ext_id ) );
        }

        ext_len -= 4 + ext_size;
        ext     += 4 + ext_size;
    }

    /* Update checksum with either
     * - The entire content of the CH message, if no PSK extension is present
     * - The content up to but excluding the PSK extension, if present.
     */
    {
        unsigned char *ch_without_psk;
        if( ext_psk_ptr == NULL )
            ch_without_psk = ext;
        else
            ch_without_psk = ext_psk_ptr;

        ssl->handshake->update_checksum( ssl,
                                         orig_buf,
                                         ch_without_psk - orig_buf );
    }

    /*
     * Search for a matching ciphersuite
     */
    got_common_suite = 0;
    ciphersuites = ssl->conf->ciphersuite_list[ssl->minor_ver];
    ciphersuite_info = NULL;
#if defined(MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE)
    for ( j = 0, p = ciph_offset + 2; j < ciph_len; j += 2, p += 2 )
    {
        for ( i = 0; ciphersuites[i] != 0; i++ )
#else
    for ( i = 0; ciphersuites[i] != 0; i++ )
    {
        for ( j = 0, p = ciph_offset + 2; j < ciph_len; j += 2, p += 2 )
#endif /* MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE */
        {
            if( p[0] != ( ( ciphersuites[i] >> 8 ) & 0xFF ) ||
                p[1] != ( ( ciphersuites[i] ) & 0xFF ) )
                continue;

            got_common_suite = 1;
            ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( ciphersuites[i] );

            if( ciphersuite_info == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "mbedtls_ssl_ciphersuite_from_id: should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            goto have_ciphersuite;
            /*
              if( ( ret = ssl_ciphersuite_match( ssl, ciphersuites[i],
              &ciphersuite_info ) ) != 0 )
              return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

              if( ciphersuite_info != NULL )
              goto have_ciphersuite;
            */

        }
    }

    if( got_common_suite )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got ciphersuites in common, but none of them usable" ) );
        /*mbedtls_ssl_send_fatal_handshake_failure( ssl ); */
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no ciphersuites in common" ) );
        /*mbedtls_ssl_send_fatal_handshake_failure( ssl ); */
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

    have_ciphersuite:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "selected ciphersuite: %s",
                                ciphersuite_info->name ) );

    ssl->session_negotiate->ciphersuite = ciphersuites[i];
    ssl->handshake->ciphersuite_info = ciphersuite_info;

    /* List all the extensions we have received */
    ssl_debug_print_client_hello_exts( ssl );

    /*
     * Determine the key exchange algorithm to use.
     * There are three types of key exchanges supported in TLS 1.3:
     * - (EC)DH with ECDSA,
     * - (EC)DH with PSK,
     * - plain PSK.
     *
     * The PSK-based key exchanges may additionally be used with 0-RTT.
     *
     * Our built-in order of preference is
     *  1 ) Plain PSK Mode
     *  2 ) (EC)DHE-PSK Mode
     *  3 ) Certificate Mode
     */

    ssl->session_negotiate->key_exchange = 0;

    if( !ssl_check_psk_key_exchange( ssl ) &&
        !ssl_check_certificate_key_exchange( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ClientHello message misses mandatory extensions." ) );
        SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION ,
                              MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
        return( MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO );
    }

#if defined(MBEDTLS_ZERO_RTT)
    ret = ssl_check_use_0rtt_handshake( ssl );
    if( ret != 0 )
        return( ret );
#endif /* MBEDTLS_ZERO_RTT */

    /* If we've settled on a PSK-based exchange, parse PSK identity ext */
    if( mbedtls_ssl_tls13_key_exchange_with_psk( ssl ) )
    {
        ret = mbedtls_ssl_parse_client_psk_identity_ext( ssl,
                                                         ext_psk_ptr,
                                                         ext_len_psk_ext );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, ( "ssl_parse_client_psk_identity" ),
                                   ret );
            return( ret );
        }
    }

#if defined(MBEDTLS_SSL_COOKIE_C)
    /* If we failed to see a cookie extension, and we required it through the
     * configuration settings ( rr_config ), then we need to send a HRR msg.
     * Conceptually, this is similiar to having received a cookie that failed
     * the verification check.
     */
    if( ( ssl->conf->rr_config == MBEDTLS_SSL_FORCE_RR_CHECK_ON ) &&
        !( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_COOKIE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "Cookie extension missing. Need to send a HRR." ) );
        final_ret = MBEDTLS_ERR_SSL_HRR_REQUIRED;
    }
#endif /* MBEDTLS_SSL_COOKIE_C */

    if( final_ret == MBEDTLS_ERR_SSL_HRR_REQUIRED )
    {
        final_ret = SSL_CLIENT_HELLO_HRR_REQUIRED;

        /*
         * Create stateless transcript hash for HRR
         */
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Compress transcript hash for stateless HRR" ) );
        ret = mbedtls_ssl_hash_transcript( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hash_transcript", ret );
            return( ret );
        }
    }

    return( final_ret );
}

static int ssl_client_hello_postprocess( mbedtls_ssl_context* ssl,
                                         int hrr_required )
{
    int ret = 0;
#if defined(MBEDTLS_ZERO_RTT)
    mbedtls_ssl_key_set traffic_keys;
#endif /* MBEDTLS_ZERO_RTT */

    if( ssl->handshake->hello_retry_requests_sent == 0 &&
        ssl->conf->rr_config == MBEDTLS_SSL_FORCE_RR_CHECK_ON )
    {
        hrr_required = SSL_CLIENT_HELLO_HRR_REQUIRED;
    }

    if( hrr_required == SSL_CLIENT_HELLO_HRR_REQUIRED )
    {
        /* Transmit Hello Retry Request */
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HELLO_RETRY_REQUEST );
        return( 0 );
    }

    ret = mbedtls_ssl_tls1_3_key_schedule_stage_early_data( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
             "mbedtls_ssl_tls1_3_key_schedule_stage_early_data", ret );
        return( ret );
    }

#if defined(MBEDTLS_ZERO_RTT)
    if( ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_ON )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Generate 0-RTT keys" ) );

        ret = mbedtls_ssl_tls1_3_generate_early_data_keys(
            ssl, &traffic_keys );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1,
                      "mbedtls_ssl_tls1_3_generate_early_data_keys", ret );
            return( ret );
        }

#if !defined(MBEDTLS_SSL_USE_MPS)
        ret = mbedtls_ssl_tls13_populate_transform(
            ssl->transform_earlydata, ssl->conf->endpoint,
            ssl->session_negotiate->ciphersuite, &traffic_keys, ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
            return( ret );
        }

#else /* MBEDTLS_SSL_USE_MPS */

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
        }
#endif /* MBEDTLS_SSL_USE_MPS */
    }

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );

#endif /* MBEDTLS_ZERO_RTT */

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    return( 0 );

}


#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static void ssl_write_max_fragment_length_ext( mbedtls_ssl_context *ssl,
                                               unsigned char *buf,
                                               size_t *olen )
{
    unsigned char *p = buf;

    *olen = 0;
    if( ( ssl->handshake->extensions_present & MAX_FRAGMENT_LENGTH_EXTENSION )
        == 0 )
    {
        return( 0 );
    }

    if( ssl->session_negotiate->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE )
    {
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, max_fragment_length extension" ) );

    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH ) & 0xFF );

    *p++ = 0x00;
    *p++ = 1;

    *p++ = ssl->session_negotiate->mfl_code;

    *olen = 5;
}
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */



#if defined(MBEDTLS_SSL_ALPN)
static int ssl_write_alpn_ext( mbedtls_ssl_context *ssl,
                                unsigned char *buf, size_t buflen, size_t *olen )
{
    *olen = 0;

    if( ( ssl->handshake->extensions_present & ALPN_EXTENSION ) == 0 ||
        ssl->alpn_chosen == NULL )
    {
        return( 0 );
    }

    if( buflen < 7 + strlen( ssl->alpn_chosen ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, adding alpn extension" ) );
    /*
     * 0 . 1    ext identifier
     * 2 . 3    ext length
     * 4 . 5    protocol list length
     * 6 . 6    protocol name length
     * 7 . 7+n  protocol name
     */
    buf[0] = (unsigned char)( ( MBEDTLS_TLS_EXT_ALPN >> 8 ) & 0xFF );
    buf[1] = (unsigned char)( ( MBEDTLS_TLS_EXT_ALPN ) & 0xFF );

    *olen = 7 + strlen( ssl->alpn_chosen );

    buf[2] = (unsigned char)( ( ( *olen - 4 ) >> 8 ) & 0xFF );
    buf[3] = (unsigned char)( ( *olen - 4 ) & 0xFF );

    buf[4] = (unsigned char)( ( ( *olen - 6 ) >> 8 ) & 0xFF );
    buf[5] = (unsigned char)( ( *olen - 6 ) & 0xFF );

    buf[6] = (unsigned char)( ( *olen - 7 ) & 0xFF );

    memcpy( buf + 7, ssl->alpn_chosen, *olen - 7 );
    return ( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */



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

static int ssl_encrypted_extensions_prepare( mbedtls_ssl_context* ssl );
static int ssl_encrypted_extensions_write( mbedtls_ssl_context* ssl,
                                           unsigned char* buf,
                                           size_t buflen,
                                           size_t* olen );
static int ssl_encrypted_extensions_postprocess( mbedtls_ssl_context* ssl );



static int ssl_encrypted_extensions_process( mbedtls_ssl_context* ssl )
{
    int ret;

#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_mps_handshake_out msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write encrypted extension" ) );

    if( ssl->handshake->state_local.encrypted_extensions_out.preparation_done == 0 )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_prepare( ssl ) );
        ssl->handshake->state_local.encrypted_extensions_out.preparation_done = 1;
    }

#if defined(MBEDTLS_SSL_USE_MPS)
    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

    msg.type   = MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION;
    msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                       &msg, NULL, NULL ) );

    /* Request write-buffer */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_write(
                              ssl, buf, buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION,
                                        buf, msg_len );

    /* Commit message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                             buf_len - msg_len ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_postprocess( ssl ) );

#else  /* MBEDTLS_SSL_USE_MPS */

    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_write( ssl, ssl->out_msg,
                                                          MBEDTLS_SSL_MAX_CONTENT_LEN,
                                                          &ssl->out_msglen ) );

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION;

    MBEDTLS_SSL_DEBUG_BUF( 3, "EncryptedExtensions", ssl->out_msg, ssl->out_msglen );

    /* Update state */
    MBEDTLS_SSL_PROC_CHK( ssl_encrypted_extensions_postprocess( ssl ) );

    /* Dispatch message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

    /* NOTE: For the new messaging layer, the postprocessing step
     *       might come after the dispatching step if the latter
     *       doesn't send the message immediately.
     *       At the moment, we must do the postprocessing
     *       prior to the dispatching because if the latter
     *       returns WANT_WRITE, we want the handshake state
     *       to be updated in order to not enter
     *       this function again on retry. */

#endif /* MBEDTLS_SSL_USE_MPS */

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write encrypted extension" ) );
    return( ret );
}

static int ssl_encrypted_extensions_prepare( mbedtls_ssl_context* ssl )
{
    int ret;
    mbedtls_ssl_key_set traffic_keys;

    /* Compute handshake secret */
    ret = mbedtls_ssl_tls1_3_key_schedule_stage_handshake( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_master_secret", ret );
        return( ret );
    }

    /* Derive handshake key material */
    ret = mbedtls_ssl_tls1_3_generate_handshake_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
                "mbedtls_ssl_tls1_3_generate_handshake_keys", ret );
        return( ret );
    }

#if !defined(MBEDTLS_SSL_USE_MPS)

    /* Setup transform from handshake key material */
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

    mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_handshake );

#else /* MBEDTLS_SSL_USE_MPS */

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

        /* Use new transform for outgoing data. */
        ret = mbedtls_mps_set_outgoing_keys( &ssl->mps.l4,
                                             ssl->epoch_handshake );
        if( ret != 0 )
            return( ret );
    }
#endif /* MBEDTLS_SSL_USE_MPS */

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for outbound data" ) );

#if !defined(MBEDTLS_SSL_USE_MPS)
    memset( ssl->out_ctr, 0, 8 );
#endif /* MBEDTLS_SSL_USE_MPS */

    return( 0 );
}

static int ssl_encrypted_extensions_write( mbedtls_ssl_context* ssl,
                                           unsigned char* buf,
                                           size_t buflen,
                                           size_t* olen )
{
    int ret;
    size_t n, enc_ext_len;
    unsigned char *p, *end, *len;

    /* If all extensions are disabled then olen is 0. */
    *olen = 0;

    end = buf + buflen;
    p = buf;

#if !defined(MBEDTLS_SSL_USE_MPS)
    if( buflen < 4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

    /* Skip HS header */
    p += 4;
#endif /* MBEDTLS_SSL_USE_MPS */

    /*
     * struct {
     *    Extension extensions<0..2 ^ 16 - 1>;
     * } EncryptedExtensions;
     *
     */

    /* Skip extension length; first write extensions, then update length */
    len = p;
    p += 2;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    ret = ssl_write_sni_server_ext( ssl, p, end - p, &n );
    if( ret != 0 )
        return( ret );
    p += n;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_ALPN)
    ret = ssl_write_alpn_ext( ssl, p, end - p, &n );
    if( ret != 0 )
        return( ret );
    p  += n;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    ret = ssl_write_max_fragment_length_ext( ssl, p, end - p, &n );
    if( ret != 0 )
        return( ret );
    p += n;
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_ZERO_RTT)
    ret = mbedtls_ssl_write_early_data_ext( ssl, p, (size_t)( end - p ), &n );
    if( ret != 0 )
        return( ret );
    p += n;
#endif /* MBEDTLS_ZERO_RTT */

    *olen = p - buf;
    enc_ext_len = (size_t)( ( p - len ) - 2 );

    len[0] = (unsigned char)( ( enc_ext_len >> 8 ) & 0xFF );
    len[1] = (unsigned char)( ( enc_ext_len >> 0 ) & 0xFF );

    return( 0 );
}

static int ssl_encrypted_extensions_postprocess( mbedtls_ssl_context* ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );
    return( 0 );
}

/*
 *
 * HelloRetryRequest message
 *
 * Servers send this message in response to a ClientHello message when
 * the server was able to find an acceptable set of algorithms and groups
 * that are mutually supported, but the client's KeyShare did not contain
 * an acceptable offer.
 *
 * We also send this message with DTLS 1.3 to perform a return-routability
 * check (and we include a cookie).
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
static int ssl_write_hello_retry_request_process( mbedtls_ssl_context* ssl );

static int ssl_write_hello_retry_request_coordinate( mbedtls_ssl_context* ssl );
static int ssl_write_hello_retry_request_write( mbedtls_ssl_context* ssl,
                                          unsigned char* buf,
                                          size_t buflen,
                                          size_t* olen );
static int ssl_write_hello_retry_request_postprocess( mbedtls_ssl_context* ssl );

static int ssl_write_hello_retry_request_process( mbedtls_ssl_context *ssl )
{
    int ret;
#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_mps_handshake_out msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_PROC_CHK( ssl_write_hello_retry_request_coordinate( ssl ) );

#if defined(MBEDTLS_SSL_USE_MPS)

    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

    msg.type   = MBEDTLS_SSL_HS_SERVER_HELLO;
    msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                       &msg, NULL, NULL ) );

    /* Request write-buffer */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_write_hello_retry_request_write(
                              ssl, buf, buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, msg_len );

    /* Commit message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                             buf_len - msg_len ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

    MBEDTLS_SSL_PROC_CHK( ssl_write_hello_retry_request_postprocess( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

#else /* MBEDTLS_SSL_USE_MPS */

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_SERVER_HELLO;
    MBEDTLS_SSL_PROC_CHK( ssl_write_hello_retry_request_write( ssl,
                              ssl->out_msg,
                              MBEDTLS_SSL_MAX_CONTENT_LEN,
                              &ssl->out_msglen ) );

    MBEDTLS_SSL_PROC_CHK( ssl_write_hello_retry_request_postprocess( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */

cleanup:

    return( ret );
}


static int ssl_write_hello_retry_request_coordinate( mbedtls_ssl_context *ssl )
{
    if( ssl->handshake->hello_retry_requests_sent > 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Too many HRRs" ) );
        return( MBEDTLS_ERR_SSL_BAD_HS_TOO_MANY_HRR );
    }

    return( 0 );
}

static int ssl_write_hello_retry_request_postprocess( mbedtls_ssl_context *ssl )
{
    ssl->handshake->hello_retry_requests_sent++;

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CCS_AFTER_HRR );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

    return( 0 );
}

static int ssl_write_hello_retry_request_write( mbedtls_ssl_context* ssl,
                                                unsigned char* buf,
                                                size_t buflen,
                                                size_t* olen )
{
    int ret;
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    unsigned char *ext_len_byte;
    size_t ext_length;
    size_t total_ext_len = 0;
    unsigned char *extension_start;
    const char magic_hrr_string[32] =
               { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE,
                 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2,
                 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09,
                 0xE2, 0xC8, 0xA8, 0x33 ,0x9C };

#if defined(MBEDTLS_ECDH_C)
    const mbedtls_ecp_group_id *gid;
    const mbedtls_ecp_curve_info **curve = NULL;
#endif /* MBEDTLS_ECDH_C */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write hello retry request" ) );

#if defined(MBEDTLS_SSL_USE_MPS)
    p = buf;
#else
    p = buf + 4;
#endif /* MBEDTLS_SSL_USE_MPS */

    /*
     * struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random ( with magic value );
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<0..2^16-1>;
     * } ServerHello; --- aka HelloRetryRequest
     */


    /* For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     *
     *  For DTLS 1.3 we use the legacy version number
     *  {254,253}.
     *
     *  In cTLS the version number is elided.
     */
    *p++ = 0x03;
    *p++ = 0x03;
    MBEDTLS_SSL_DEBUG_BUF( 3, "server version", p - 2, 2 );

    /* write magic string (as a replacement for the random value) */
    memcpy( p, &magic_hrr_string[0], 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "Random bytes in HelloRetryRequest", p, 32 );
    p += 32;

    /* write legacy_session_id_echo */
    *p++ = (unsigned char) ssl->session_negotiate->id_len;
    memcpy( p, &ssl->session_negotiate->id[0], ssl->session_negotiate->id_len );
    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", p, ssl->session_negotiate->id_len );
    p += ssl->session_negotiate->id_len;

    /* write ciphersuite (2 bytes) */
    *p++ = (unsigned char)( ssl->session_negotiate->ciphersuite >> 8 );
    *p++ = (unsigned char)( ssl->session_negotiate->ciphersuite );
    MBEDTLS_SSL_DEBUG_BUF( 3, "ciphersuite", p-2, 2 );

    /* write legacy_compression_method (0) */
    *p++ = 0x0;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "legacy compression method: [%d]", *( p-1 ) ) );

    /* write extensions */
    extension_start = p;
    /* Extension starts with a 2 byte length field; we skip it and write it later */
    p += 2;

#if defined(MBEDTLS_SSL_COOKIE_C)

    /* Cookie Extension
     *
     * struct {
     *    opaque cookie<0..2^16-1>;
     * } Cookie;
     *
     */

    /* Write extension header */
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_COOKIE >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_COOKIE >> 0 ) & 0xFF );

    /* Skip writing the extension and the cookie length */
    ext_len_byte = p;
    p = p + 4;

    /* If we get here, f_cookie_check is not null */
    if( ssl->conf->f_cookie_write == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "inconsistent cookie callbacks" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ( ret = ssl->conf->f_cookie_write( ssl->conf->p_cookie,
                                           &p, end,
                                           ssl->cli_id,
                                           ssl->cli_id_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_cookie_write", ret );
        return( ret );
    }

    ext_length = ( p - ( ext_len_byte + 4 ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Cookie", ext_len_byte + 4, ext_length );

    /* Write extension length */
    *ext_len_byte++ = (unsigned char)( ( ( ext_length + 2 ) >> 8 ) & 0xFF );
    *ext_len_byte++ = (unsigned char)( ( ext_length + 2 ) & 0xFF );

    /* Write cookie length */
    *ext_len_byte++ = (unsigned char)( ( ext_length >> 8 ) & 0xFF );
    *ext_len_byte = (unsigned char)( ext_length & 0xFF );

    /* 2 bytes for extension type,
     * 2 bytes for extension length field,
     * 2 bytes for cookie length */
    total_ext_len += ext_length + 6;
#endif /* MBEDTLS_SSL_COOKIE_C */

    /* Add supported_version extension */
    if( ( ret = ssl_write_supported_version_ext( ssl, p, end,
                                                 &ext_length ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_supported_version_ext", ret );
        return( ret );
    }

    total_ext_len += ext_length;
    p += ext_length;

#if defined(MBEDTLS_ECDH_C)
    /* key_share Extension
     *
     *  struct {
     *    select ( Handshake.msg_type ) {
     *      case client_hello:
     *          KeyShareEntry client_shares<0..2^16-1>;
     *
     *      case hello_retry_request:
     *          NamedGroup selected_group;
     *
     *      case server_hello:
     *          KeyShareEntry server_share;
     *    };
     * } KeyShare;
     *
     */

    /* For a pure PSK-based ciphersuite there is no key share to declare.
     * Hence, we focus on ECDHE-EDSA and ECDHE-PSK.
     */
    if( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA ||
        ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK )
    {
        /* Write extension header */
        *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_KEY_SHARES >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( MBEDTLS_TLS_EXT_KEY_SHARES >> 0 ) & 0xFF );

        ext_len_byte = p;

        /* Write length */
        *p++ = 0;
        *p++ = 2;
        ext_length = 2;

        for ( gid = ssl->conf->curve_list; *gid != MBEDTLS_ECP_DP_NONE; gid++ )
        {
            for ( curve = ssl->handshake->curves; *curve != NULL; curve++ )
            {
                if( ( *curve )->grp_id == *gid )
                    goto curve_matching_done;
            }
        }

    curve_matching_done:
        if( curve == NULL || *curve == NULL )
        {
            /* This case should not happen */
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching named group found" ) );
            return( MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN );
        }

        /* Write selected group */
        *p++ = ( *curve )->tls_id >> 8;
        *p++ = ( *curve )->tls_id & 0xFF;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "NamedGroup in HRR: %s", (*curve)->name ) );

        /* 2 bytes for extension_type and 2 bytes for length field */
        total_ext_len += ext_length + 4;

    }
#endif /* MBEDTLS_ECDH_C */

    *extension_start++ = (unsigned char)( ( total_ext_len >> 8 ) & 0xFF );
    *extension_start++ = (unsigned char)( ( total_ext_len >> 0 ) & 0xFF );

    *olen = p - buf;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write hello retry request" ) );
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

/* ServerHello handling sub-routines */
static int ssl_server_hello_prepare( mbedtls_ssl_context* ssl );
static int ssl_server_hello_write( mbedtls_ssl_context* ssl,
                                   unsigned char* buf,
                                   size_t buflen,
                                   size_t* olen );
static int ssl_server_hello_postprocess( mbedtls_ssl_context* ssl );

static int ssl_server_hello_process( mbedtls_ssl_context* ssl ) {

    int ret = 0;

#if defined(MBEDTLS_SSL_USE_MPS)
    mbedtls_mps_handshake_out msg;
    unsigned char *buf;
    mbedtls_mps_size_t buf_len, msg_len;
#endif /* MBEDTLS_SSL_USE_MPS */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write server hello" ) );

    /* Preprocessing */

    /* This might lead to ssl_process_server_hello( ) being called multiple
     * times. The implementation of ssl_process_server_hello_preprocess( )
     * must either be safe to be called multiple times, or we need to add
     * state to omit this call once we're calling ssl_process_server_hello( )
     * multiple times. */
    MBEDTLS_SSL_PROC_CHK( ssl_server_hello_prepare( ssl ) );

#if defined(MBEDTLS_SSL_USE_MPS)
    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

    msg.type   = MBEDTLS_SSL_HS_SERVER_HELLO;
    msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                       &msg, NULL, NULL ) );

    /* Request write-buffer */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                  &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_server_hello_write( ssl, buf, buf_len,
                                                  &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, msg_len );

    /* Commit message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                             buf_len - msg_len ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

    /* Postprocess */
    MBEDTLS_SSL_PROC_CHK( ssl_server_hello_postprocess( ssl ) );

#else  /* MBEDTLS_SSL_USE_MPS */

    /* Writing */

    /* Make sure we can write a new message. */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

    MBEDTLS_SSL_PROC_CHK( ssl_server_hello_write( ssl, ssl->out_msg,
                            MBEDTLS_SSL_MAX_CONTENT_LEN, &ssl->out_msglen ) );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server hello" ) );

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_SERVER_HELLO;

    /* Postprocess */
    MBEDTLS_SSL_PROC_CHK( ssl_server_hello_postprocess( ssl ) );

    /* NOTE: For the new messaging layer, the postprocessing step
     *       might come after the dispatching step if the latter
     *       doesn't send the message immediately.
     *       At the moment, we must do the postprocessing
     *       prior to the dispatching because if the latter
     *       returns WANT_WRITE, we want the handshake state
     *       to be updated in order to not enter
     *       this function again on retry. */

    /* Dispatch */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write server hello" ) );
    return( ret );
}


/* IMPORTANT: This function can currently be called multiple times
 *            in case the call to mbedtls_ssl_flush_output( ) that
 *            follows  it in ssl_process_server_hello( ) fails.
 *
 *            Make sure that the preparations in this function
 *            can safely be repeated multiple times, or add logic
 *            to ssl_process_server_hello( ) to never call it twice.
 */
static int ssl_server_hello_prepare( mbedtls_ssl_context* ssl )
{
    int ret;

    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng, ssl->handshake->randbytes + 32, 32 ) ) != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes", ssl->handshake->randbytes + 32, 32 );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */


    /* Check for session resumption
     * <TBD>
     */

    return( 0 );
}

static int ssl_server_hello_write( mbedtls_ssl_context* ssl,
                                   unsigned char* buf,
                                   size_t buflen,
                                   size_t* olen )
{
    int ret=0;
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
    size_t rand_bytes_len;

    /* Buffer management */
    unsigned char* start = buf;
    unsigned char* end = buf + buflen;

    rand_bytes_len = 32;

    /* Ensure we have enough room for ServerHello
     * up to but excluding the extensions. */
    if( buflen < ( 4+32+2+2+1+ssl->session_negotiate->id_len+1+1 ) ) /* TBD: FIXME */
    {
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );
    }

#if !defined(MBEDTLS_SSL_USE_MPS)
    /*
     *  TLS 1.3
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *
     *  cTLS
     *     0  .   0   handshake type
     *
     * The header is set by ssl_write_record.
     * For DTLS 1.3 the other fields are adjusted.
     */
    buf += 4; /* skip handshake type + length */
    buflen -=4;
#endif /* MBEDTLS_SSL_USE_MPS */

    /* Version */
    *buf++ = (unsigned char)0x3;
    *buf++ = (unsigned char)0x3;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen version: [0x3:0x3]" ) );
    buflen -= 2;

    /* Write random bytes */
    memcpy( buf, ssl->handshake->randbytes + 32, rand_bytes_len );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes", buf, rand_bytes_len );

    buf += rand_bytes_len;
    buflen -= rand_bytes_len;

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    /* Write legacy session id */
    *buf++ = (unsigned char)ssl->session_negotiate->id_len;
    buflen--;
    memcpy( buf, &ssl->session_negotiate->id[0], ssl->session_negotiate->id_len );
    buf += ssl->session_negotiate->id_len;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "session id length ( %d )", ssl->session_negotiate->id_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id, ssl->session_negotiate->id_len );
    buflen -= ssl->session_negotiate->id_len;

    /* write selected ciphersuite ( 2 bytes ) */
    *buf++ = (unsigned char)( ssl->session_negotiate->ciphersuite >> 8 );
    *buf++ = (unsigned char)( ssl->session_negotiate->ciphersuite );
    buflen -= 2;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: %s ( id=%d )", mbedtls_ssl_get_ciphersuite_name( ssl->session_negotiate->ciphersuite ), ssl->session_negotiate->ciphersuite ) );

    /* write legacy_compression_method ( 0 ) */
    *buf++ = 0x0;
    buflen--;

    /* First write extensions, then the total length */
    extension_start = buf;
    total_ext_len = 0;
    buf += 2;

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    /* Only add the pre_shared_key extension if the client provided it in the ClientHello
     * and if the key exchange supports PSK
     */
    if( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY && (
            ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ||
            ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ) )
    {
        ret = ssl_write_server_pre_shared_key_ext( ssl, buf, end,
                                                   &cur_ext_len );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_server_pre_shared_key_ext",
                                   ret );
            return( ret );
        }

        total_ext_len += cur_ext_len;
        buf += cur_ext_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )
    /* Only add the key_share extension if the client provided it in the ClientHello
     * and if the appropriate key exchange mechanism was selected
     */
    if( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_KEY_SHARE && (
            ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ||
            ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA ) )
    {
        if( ( ret = ssl_write_key_shares_ext( ssl, buf, end, &cur_ext_len ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_key_shares_ext", ret );
            return( ret );
        }

        total_ext_len += cur_ext_len;
        buf += cur_ext_len;
    }
#endif /* ( MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

    /* Add supported_version extension */
    if( ( ret = ssl_write_supported_version_ext( ssl, buf, end, &cur_ext_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_supported_version_ext", ret );
        return( ret );
    }

    total_ext_len += cur_ext_len;
    buf += cur_ext_len;

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello extensions", extension_start, total_ext_len );

    /* Write length information */
    *extension_start++ = (unsigned char)( ( total_ext_len >> 8 ) & 0xFF );
    *extension_start++ = (unsigned char)( ( total_ext_len ) & 0xFF );
    buflen -= 2 + total_ext_len;

    *olen = buf - start;

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello", start, *olen );

    return( ret );
}

static int ssl_server_hello_postprocess( mbedtls_ssl_context* ssl )
{
    int ret = 0;
    ( (void ) ssl );

    return( ret );
}

/*
 *
 * STATE HANDLING: CertificateRequest
 *
 */

/* Main entry point; orchestrates the other functions */
static int ssl_certificate_request_process( mbedtls_ssl_context* ssl );

/* Coordination:
 * Check whether a CertificateRequest message should be written.
 * Returns a negative error code on failure, or one of
 * - SSL_CERTIFICATE_REQUEST_EXPECT_WRITE or
 * - SSL_CERTIFICATE_REQUEST_SKIP
 * indicating if the writing of the CertificateRequest
 * should be skipped or not.
 */
#define SSL_CERTIFICATE_REQUEST_SEND 0
#define SSL_CERTIFICATE_REQUEST_SKIP 1
static int ssl_certificate_request_coordinate( mbedtls_ssl_context* ssl );
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
static int ssl_certificate_request_write( mbedtls_ssl_context* ssl,
                                          unsigned char* buf,
                                          size_t buflen,
                                          size_t* olen );
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
static int ssl_certificate_request_postprocess( mbedtls_ssl_context* ssl );


/*
 * Implementation
 */

static int ssl_certificate_request_process( mbedtls_ssl_context* ssl )
{
    int ret = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate request" ) );

    /* Coordination step: Check if we need to send a CertificateRequest */
    MBEDTLS_SSL_PROC_CHK_NEG( ssl_certificate_request_coordinate( ssl ) );

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    if( ret == SSL_CERTIFICATE_REQUEST_SEND )
    {
#if defined(MBEDTLS_SSL_USE_MPS)
        mbedtls_mps_handshake_out msg;
        unsigned char *buf;
        mbedtls_mps_size_t buf_len, msg_len;

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_flush( &ssl->mps.l4 ) );

        msg.type   = MBEDTLS_SSL_HS_CERTIFICATE_REQUEST;
        msg.length = MBEDTLS_MPS_SIZE_UNKNOWN;
        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_write_handshake( &ssl->mps.l4,
                                                           &msg, NULL, NULL ) );

        /* Request write-buffer */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_get_ext( msg.handle, MBEDTLS_MPS_SIZE_MAX,
                                                      &buf, &buf_len ) );

        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_write(
                                  ssl, buf, buf_len, &msg_len ) );

        mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                                            buf, msg_len );

        /* Commit message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_writer_commit_partial_ext( msg.handle,
                                                                 buf_len - msg_len ) );

        MBEDTLS_SSL_PROC_CHK( mbedtls_mps_dispatch( &ssl->mps.l4 ) );

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_postprocess( ssl ) );

#else  /* MBEDTLS_SSL_USE_MPS */

        /* Make sure we can write a new message. */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_flush_output( ssl ) );

        /* Prepare CertificateRequest message in output buffer. */
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_write( ssl, ssl->out_msg,
                                                             MBEDTLS_SSL_MAX_CONTENT_LEN,
                                                             &ssl->out_msglen ) );

        ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
        ssl->out_msg[0] = MBEDTLS_SSL_HS_CERTIFICATE_REQUEST;

        /* Update state */
        MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_postprocess( ssl ) );

        /* Dispatch message */
        MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg( ssl ) );

#endif /* MBEDTLS_SSL_USE_MPS */

    }
    else
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
        if( ret == SSL_CERTIFICATE_REQUEST_SKIP )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate request" ) );

            /* Update state */
            MBEDTLS_SSL_PROC_CHK( ssl_certificate_request_postprocess( ssl ) );
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate request" ) );
    return( ret );
}


static int ssl_certificate_request_coordinate( mbedtls_ssl_context* ssl )
{
    int authmode;

    if( ( ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK ||
          ssl->session_negotiate->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK ) )
        return( SSL_CERTIFICATE_REQUEST_SKIP );

#if !defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    ( ( void )authmode );
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#else

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET )
        authmode = ssl->handshake->sni_authmode;
    else
#endif
        authmode = ssl->conf->authmode;

    if( authmode == MBEDTLS_SSL_VERIFY_NONE )
        return( SSL_CERTIFICATE_REQUEST_SKIP );

    return( SSL_CERTIFICATE_REQUEST_SEND );

#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
}

static int ssl_certificate_request_write( mbedtls_ssl_context* ssl,
                                          unsigned char* buf,
                                          size_t buflen,
                                          size_t* olen )
{
    int ret;
    size_t ext_size;
    unsigned char* p;
    unsigned char* end = buf + buflen;

    p = buf;

#if !defined(MBEDTLS_SSL_USE_MPS)
    /* Skip over handshake header.
     *
     * NOTE:
     * Even for DTLS, we are skipping 4 bytes for the TLS handshake
     * header. The actual DTLS handshake header is inserted in
     * the record writing routine mbedtls_ssl_write_record( ).
     */
    p += 4;
#endif /* MBEDTLS_SSL_USE_MPS */

    if( p + 1 + 2 > end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "buffer too small" ) );
        return ( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    /*
     *
     * struct {
     *   opaque certificate_request_context<0..2^8-1>;
     *   Extension extensions<2..2^16-1>;
     * } CertificateRequest;
     *
     */

    /*
     * Write certificate_request_context
     */

    /*
     * We use a zero length context for the normal handshake
     * messages. For post-authentication handshake messages
     * this request context would be set to a non-zero value.
     */
    *p++ = 0x0;

    /*
     * Write extensions
     */

    /* The extensions must contain the signature_algorithms. */
    /* Currently we don't use any other extension */
    ret = mbedtls_ssl_write_signature_algorithms_ext( ssl, p + 2,
                                                      end, &ext_size );
    if( ret != 0 )
        return( ret );

    /* length field for all extensions */
    *p++ = (unsigned char)( ( ext_size >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ext_size >> 0 ) & 0xFF );
    p += ext_size;

    *olen = p - buf;

    return( ret );
}


static int ssl_certificate_request_postprocess( mbedtls_ssl_context* ssl )
{
    /* next state */
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CERTIFICATE );
    return( 0 );
}

/*
 * TLS and DTLS 1.3 State Maschine -- server side
 */
int mbedtls_ssl_handshake_server_step_tls1_3( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "server state: %d", ssl->state ) );

#if !defined(MBEDTLS_SSL_USE_MPS)
    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        return( ret );
#endif /* !MBEDTLS_SSL_USE_MPS */

    switch( ssl->state )
    {
        /* start state */
        case MBEDTLS_SSL_HELLO_REQUEST:
            ssl->handshake->hello_retry_requests_sent = 0;
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
            ssl->handshake->ccs_sent = 0;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

            break;

            /* ----- READ CLIENT HELLO ----*/

        case MBEDTLS_SSL_CLIENT_HELLO:

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
            ssl->session_negotiate->minor_ver = ssl->minor_ver;
            ssl->session_negotiate->endpoint = ssl->conf->endpoint;
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

            ret = ssl_client_hello_process( ssl );
            if( ret != 0 )
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_client_hello_process", ret );

            break;

            /* ----- WRITE EARLY APP DATA  ----*/
        case MBEDTLS_SSL_EARLY_APP_DATA:

            ret = ssl_read_early_data_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_read_early_data_process", ret );
                return ( ret );
            }

            break;

            /* ----- WRITE HELLO RETRY REQUEST ----*/

        case MBEDTLS_SSL_HELLO_RETRY_REQUEST:

            ret = ssl_write_hello_retry_request_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_hello_retry_request", ret );
                return( ret );
            }

            break;

            /* ----- WRITE CHANGE CIPHER SPEC ----*/

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_SERVER_CCS_AFTER_HRR:

            ret = mbedtls_ssl_write_change_cipher_spec_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_change_cipher_spec_process", ret );
                return( ret );
            }

            break;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

            /* ----- READ 2nd CLIENT HELLO ----*/
        case MBEDTLS_SSL_SECOND_CLIENT_HELLO:

            ret = ssl_client_hello_process( ssl );

            switch( ret )
            {
                case 0:
                    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
                    break;
                case MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION:
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                          MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
                    break;
                case MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN:
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                          MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN );
                    break;
                case MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE:
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                          MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE );
                    break;
                case MBEDTLS_ERR_SSL_BAD_HS_MISSING_EXTENSION_EXT:
                    SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION,
                                          MBEDTLS_ERR_SSL_BAD_HS_MISSING_EXTENSION_EXT );
                    break;
                case MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC:
                    /* Stay in this state */
                    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SECOND_CLIENT_HELLO );
                    ret = 0;
                    break;
                default:
                    return( ret );
            }

            break;
            /* ----- WRITE SERVER HELLO ----*/

        case MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_server_hello_process( ssl );

            if( ret != 0 )
                break;

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
            if( ssl->handshake->ccs_sent > 1 )
            {
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO );
            }
            else
            {
                mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
            }
#else
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

            break;

            /* ----- WRITE CHANGE CIPHER SPEC ----*/

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO:

            ret = mbedtls_ssl_write_change_cipher_spec_process(ssl);

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_change_cipher_spec_process", ret );
                return( ret );
            }

            break;
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

            /* ----- WRITE ENCRYPTED EXTENSIONS ----*/

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_encrypted_extensions_process( ssl );
            break;

            /* ----- WRITE CERTIFICATE REQUEST ----*/

        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_certificate_request_process( ssl );
            break;

            /* ----- WRITE SERVER CERTIFICATE ----*/

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = mbedtls_ssl_write_certificate_process( ssl );
            break;

            /* ----- WRITE SERVER CERTIFICATE VERIFY ----*/

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = mbedtls_ssl_write_certificate_verify_process( ssl );
            break;

            /* ----- WRITE FINISHED ----*/

        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = mbedtls_ssl_finished_out_process( ssl );
            break;

            /* ----- READ CLIENT CERTIFICATE ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = mbedtls_ssl_read_certificate_process( ssl );
            break;

            /* ----- READ CLIENT CERTIFICATE VERIFY ----*/

        case MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
            ret = mbedtls_ssl_read_certificate_verify_process( ssl );
            break;

        case MBEDTLS_SSL_END_OF_EARLY_DATA:
            ret = ssl_read_end_of_early_data_process( ssl );
            break;

            /* ----- READ FINISHED ----*/

        case MBEDTLS_SSL_CLIENT_FINISHED:

            ret = mbedtls_ssl_finished_in_process( ssl );

            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_finished_in_process", ret );
                return( ret );
            }

            /* Compute resumption_master_secret */
            ret = mbedtls_ssl_tls1_3_generate_resumption_master_secret( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1,
                          "mbedtls_ssl_tls1_3_generate_resumption_master_secret ", ret );
                return( ret );
            }

            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake: done" ) );

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for all traffic" ) );

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
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET );

            break;

        case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET:

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)

            ret = ssl_write_new_session_ticket_process( ssl );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_write_new_session_ticket ", ret );
                return( ret );
            }
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
