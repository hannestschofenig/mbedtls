/*
 *  Messaging layer for use with TLS/DTLS 1.3
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

/* This code will be merged into MPS:
 * https://github.com/hanno-arm/mbedtls/tree/mps_implementation/
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)



#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "mbedtls/aes.h"
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/hkdf.h"
#include <string.h>

#if defined(MBEDTLS_X509_CRT_PARSE_C) &&                \
    defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

/*
 * Encryption/decryption functions
 */
static int ssl_encrypt_buf( mbedtls_ssl_context *ssl )
{
    mbedtls_cipher_mode_t mode;
    int auth_done = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> encrypt buf" ) );

    if( ssl->session_out == NULL || ssl->transform_out == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_out->cipher_ctx_enc );

    MBEDTLS_SSL_DEBUG_BUF( 4, "plaintext ( before encryption )",
                           ssl->out_msg, ssl->out_msglen );

    /*
     * Encrypt
     */
#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C) ||  defined(MBEDTLS_CHACHAPOLY_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY )
    {
        int ret;
        size_t enc_msglen, olen;
        unsigned char* enc_msg;
        unsigned char add_data[5];
        size_t add_data_len;
        unsigned char taglen;

        taglen = ssl->handshake->ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* TBD: We need to adjust the additional data calculation for CID use */

            /* Adding the ( fake ) content type to additional data */
            add_data[0] = 23;

            /* Adding the version to additional data */
            add_data[1] = 0xfe;
            add_data[2] = 0xfd;

            /* Adding the length to additional data */
            add_data[3] = ( ( ssl->out_msglen + taglen ) >> 8 ) & 0xFF;
            add_data[4] = ( ssl->out_msglen + taglen ) & 0xFF;

            add_data_len = 5;
        }
        else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        {
            /* Adding the content type to additional data */
            add_data[0] = ssl->out_hdr[0];

            /* Adding the version to additional data */
            add_data[1] = ssl->out_hdr[1];
            add_data[2] = ssl->out_hdr[2];

            /* Adding the length to additional data */
            add_data[3] = ( ( ssl->out_msglen + taglen ) >> 8 ) & 0xFF;
            add_data[4] = ( ssl->out_msglen + taglen ) & 0xFF;

            add_data_len = 5;
        }

        enc_msg = ssl->out_msg;
        enc_msglen = ssl->out_msglen;
        /* We adjust the message length since the authentication tag also consumes space. */
        ssl->out_msglen += taglen;

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "msglen ( %d )", ssl->out_msglen ) );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( before )", ssl->transform_out->iv_enc, ssl->transform_out->ivlen );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( before ):", ssl->transform_out->sequence_number_enc, 12 );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Additional data used", add_data, add_data_len );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Plaintext message:", enc_msg, enc_msglen );

        if( ( ret = mbedtls_cipher_auth_encrypt( &ssl->transform_out->cipher_ctx_enc,
                                                 ssl->transform_out->iv_enc,
                                                 ssl->transform_out->ivlen,
                                                 add_data, add_data_len,
                                                 enc_msg, enc_msglen,
                                                 enc_msg, &olen,
                                                 enc_msg + enc_msglen, taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_cipher_auth_encrypt", ret );
            return( ret );
        }

        if( olen != enc_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        /* ssl->out_msglen += taglen; */
        auth_done++;

        /* The size of the sequence number varies with DTLS 1.2 and DTLS 1.3,
	 * as well as been encrypted and plaintext payloads.
	 *
	 * Cases for the sequence numbers and epochs:
	 * - DTLS 1.2 plaintext: 48 bit seqnr + 16 bit epoch
	 * - DTLS 1.2 ciphertext: 48 bit seqnr + 16 bit epoch
	 * - DTLS 1.3 plaintext: 48 bit seqnr + 16 bit epoch
	 * - DTLS 1.3 ciphertext: 16 bit or 8 bit seqnr + 2 bit epoch
	 *                        ( encrypted seqnr )
	 */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* For DTLS 1.3 and encrypted payloads only */
        if( ( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM ) &&
            ( ssl->transform_out != NULL ) )
        {
            /* TBD: Need to optimize this code section */

            unsigned char mask[16];
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init( &aes_ctx );

            /* For a working sequence number encryption solution we need 16 or more bytes
             * of encrypted payload. We do a sanity check for the message length.
             */
            if( enc_msglen + taglen < 16 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Sequence number encryption failed - msg payload too short." ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            /* Need to adjust to the key size and algorithm */
            mbedtls_aes_setkey_enc( &aes_ctx, ssl->transform_out->traffic_keys.client_sn_key, 128 );

            /*   Mask = AES-ECB( sn_key, Ciphertext[0..15] ) */
            mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, ssl->out_msg, mask );

            /*  The encrypted sequence number is computed by XORing the leading bytes
             *  of the Mask with the sequence number.
             */
            ssl->out_ctr[0] ^= mask[0];
            ssl->out_ctr[1] ^= mask[1];

            mbedtls_aes_free( &aes_ctx );
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS   */

        if( ( ret = mbedtls_increment_sequence_number( &ssl->transform_out->sequence_number_enc[0], ssl->transform_out->iv_enc, ssl->transform_out->ivlen ) ) != 0 )
        {

            MBEDTLS_SSL_DEBUG_RET( 1, "Error in sequence number processing", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( after )", ssl->transform_out->iv_enc, ssl->transform_out->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( after ):", ssl->transform_out->sequence_number_enc, 12 );

        MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( with tag ): ", enc_msg, ssl->out_msglen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Tag", enc_msg + enc_msglen, taglen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( without tag ): ", enc_msg, ssl->out_msglen - taglen );
    } else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C || MBEDTLS_MODE_CHACHAPOLY  */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= encrypt buf" ) );

    return( 0 );
}

static int ssl_decrypt_buf( mbedtls_ssl_context *ssl )
{
    size_t i;
    mbedtls_cipher_mode_t mode;
    int auth_done = 0;


    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> decrypt buf" ) );

    if( ssl->session_in == NULL || ssl->transform_in == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    mode = mbedtls_cipher_get_cipher_mode( &ssl->transform_in->cipher_ctx_dec );

    if( ssl->in_msglen < ssl->transform_in->minlen )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "in_msglen ( %d ) < minlen ( %d )",
                                    ssl->in_msglen, ssl->transform_in->minlen ) );
        return( MBEDTLS_ERR_SSL_INVALID_MAC );
    }


#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C)
    if( mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY )
    {
        int ret;
        size_t dec_msglen, olen;
        unsigned char* dec_msg;
        unsigned char* dec_msg_result;
        unsigned char taglen;
        unsigned char add_data[5];
        size_t add_data_len;

        taglen = ssl->handshake->ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Adding the content type to additional data */
            add_data[0] = 0x17;

            /* Adding the version to additional data */
            add_data[1] = 0xfe;
            add_data[2] = 0xfd;

            /* Adding the length to additional data */
            add_data[3] = ssl->in_hdr[3];
            add_data[4] = ssl->in_hdr[4];

            add_data_len = 5;

            dec_msglen = ssl->in_msglen - taglen;
            dec_msg = ssl->in_msg;
            dec_msg_result = ssl->in_msg; /* We write the result into the input buffer */
            ssl->in_msglen = dec_msglen; /* We adjust the message length since the authentication tag also consumes space. */

            MBEDTLS_SSL_DEBUG_MSG( 4, ( "msglen ( %d )", ssl->in_msglen ) );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( before )", ssl->transform_in->iv_dec, ssl->transform_in->ivlen );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( before ):", ssl->transform_in->sequence_number_dec, 12 );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Additional data used", add_data, add_data_len );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( with tag ):", dec_msg, dec_msglen + taglen );
            MBEDTLS_SSL_DEBUG_BUF( 4, "Tag", dec_msg + dec_msglen, taglen );
            MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( without tag ):", dec_msg, dec_msglen );
        }
        else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        {
            /* Adding the content type to additional data */
            add_data[0] = ssl->in_hdr[0];

            /* Adding the version to additional data */
            add_data[1] = ssl->in_hdr[1];
            add_data[2] = ssl->in_hdr[2];

            /* Adding the length to additional data */
            add_data[3] = ssl->in_hdr[3];
            add_data[4] = ssl->in_hdr[4];

            add_data_len = 5;

            dec_msglen = ssl->in_msglen - taglen;
            dec_msg = ssl->in_msg;
            dec_msg_result = ssl->in_msg; /* We write the result into the input buffer */
            ssl->in_msglen = dec_msglen; /* We adjust the message length since the authentication tag also consumes space. */

            MBEDTLS_SSL_DEBUG_MSG( 4, ( "msglen ( %d )", ssl->in_msglen ) );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( before )", ssl->transform_in->iv_dec, ssl->transform_in->ivlen );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( before ):", ssl->transform_in->sequence_number_dec, 12 );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Additional data used", add_data, add_data_len );

            MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( with tag ):", dec_msg, dec_msglen + taglen );
            MBEDTLS_SSL_DEBUG_BUF( 4, "Tag", dec_msg + dec_msglen, taglen );
            MBEDTLS_SSL_DEBUG_BUF( 4, "Encrypted message ( without tag ):", dec_msg, dec_msglen );
        }

#if defined(MBEDTLS_SSL_PROTO_DTLS)  && defined(MBEDTLS_CID)
        /* For DTLS 1.3 and encrypted payloads we need to decrypt the sequence number */
        if( ( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM ) &&
            ( ssl->transform_out != NULL ) )
        {
            /* TBD: Need to optimize this code section */
            /* Need to find out whether this section is only executed when the CID extension has been agreed. */

            unsigned char mask[16];
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init( &aes_ctx );

            /* For a working sequence number encryption solution we need 16 or more bytes
             * of encrypted payload. We do a sanity check for the message length.
             */
            if( dec_msglen + taglen < 16 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Sequence number encryption failed - msg payload too short." ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }
            /* Need to adjust to the key size and algorithm */
            mbedtls_aes_setkey_enc( &aes_ctx, ssl->transform_out->traffic_keys.server_sn_key, 128 );

            /* Mask = AES-ECB( sn_key, Ciphertext[0..15] ) */
            mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, dec_msg, mask );

            /*  Decrypt the sequence number using XOR with the leading bytes
             *  of the Mask.
             */
            ssl->in_ctr[0] ^= mask[0];
            ssl->in_ctr[1] ^= mask[1];

            mbedtls_aes_free( &aes_ctx );
	}
#endif /* MBEDTLS_SSL_PROTO_DTLS && MBEDTLS_CID */

        /*
         * Decrypt and authenticate
         */
        if( ( ret = mbedtls_cipher_auth_decrypt( &ssl->transform_in->cipher_ctx_dec,
                                                 ssl->transform_in->iv_dec,
                                                 ssl->transform_in->ivlen,
                                                 add_data, add_data_len,
                                                 dec_msg, dec_msglen,
                                                 dec_msg_result, &olen,
                                                 dec_msg + dec_msglen, taglen ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "Error in mbedtls_cipher_auth_decrypt( )", ret );

            if( ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED )
                return( MBEDTLS_ERR_SSL_INVALID_MAC );

            return( ret );
        }
        auth_done++;

        if( ( ret = mbedtls_increment_sequence_number( &ssl->transform_in->sequence_number_dec[0], ssl->transform_in->iv_dec, ssl->transform_in->ivlen ) ) != 0 )
        {

            MBEDTLS_SSL_DEBUG_RET( 1, "Error in sequence number processing", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "Nonce ( after )", ssl->transform_in->iv_dec, ssl->transform_in->ivlen );
        MBEDTLS_SSL_DEBUG_BUF( 4, "Sequence Number ( after ):", ssl->transform_in->sequence_number_dec, 12 );


#if defined(MBEDTLS_SSL_PROTO_DTLS)

        /* Always copy the most recent IV used for incoming data. */
        memcpy( ssl->transform_in->traffic_keys_previous.iv, ssl->transform_in->iv_dec, ssl->transform_in->ivlen );

#endif /* MBEDTLS_SSL_PROTO_DTLS */

        if( olen != dec_msglen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        /* This is now the structure of the resulting decrypted message:
         *    struct {
         *      opaque content[TLSPlaintext.length];
         *      ContentType type;
         *      uint8 zeros[length_of_padding];
         * } TLSInnerPlaintext;
         */
    }
    else
#endif /* MBEDTLS_GCM_C || MBEDTLS_CCM_C || MBEDTLS_MODE_CHACHAPOLY */
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Make extra sure authentication was performed, exactly once */
    if( auth_done != 1 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( ssl->in_msglen == 0 )
    {
        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * ( excessive CPU consumption ).
         */
        if( ssl->nb_zero > 3 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "received four consecutive empty "
                                        "messages, possible DoS attack" ) );
            return( MBEDTLS_ERR_SSL_INVALID_MAC );
        }
    }
    else
        ssl->nb_zero = 0;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        ; /* in_ctr read from peer, not maintained internally */
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        for( i = 8; i > mbedtls_ssl_ep_len( ssl ); i-- )
            if( ++ssl->in_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == mbedtls_ssl_ep_len( ssl ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "incoming message counter would wrap" ) );
            return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= decrypt buf" ) );

    return( 0 );
}

/*
 * Record layer functions
 */

/*
 * Write current record.
 * Uses ssl->out_msgtype, ssl->out_msglen and bytes at ssl->out_msg.
 */
int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl )
{
    int ret, done = 0;
    size_t dummy_length;
    size_t len = ssl->out_msglen;
    size_t protected_record_size;

    ((void) dummy_length); /* TODO: Guard this appropriately. */

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> write record" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
    {
        ; /* Skip special handshake treatment when resending */
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        if( ( ssl->out_msg != NULL ) && ( ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE ) )
        {

            if( ssl->out_msg[0] != MBEDTLS_SSL_HS_HELLO_REQUEST &&
                ssl->handshake == NULL && ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            /*
             * TLS / DTLS 1.3 Handshake Message
             *
             * struct {
             *     HandshakeType msg_type;    // handshake type
             *     uint24 length;             // bytes in message
             *     uint16 message_seq;        // DTLS only
             *     uint24 fragment_offset;    // DTLS only
             *     uint24 fragment_length;    // DTLS-required field
             *     select( HandshakeType ) {
             *         case client_hello:          ClientHello;
             *         case server_hello:          ServerHello;
             *         case end_of_early_data:     EndOfEarlyData;
             *         case encrypted_extensions:  EncryptedExtensions;
             *         case certificate_request:   CertificateRequest;
             *         case certificate:           Certificate;
             *         case certificate_verify:    CertificateVerify;
             *         case finished:              Finished;
             *         case new_session_ticket:    NewSessionTicket;
             *         case key_update:            KeyUpdate;
             *     } body;
             * } Handshake;
             *
             */
            /* Add handshake message length */
            ssl->out_msg[1] = (unsigned char)( ( len - 4 ) >> 16 );
            ssl->out_msg[2] = (unsigned char)( ( len - 4 ) >> 8 );
            ssl->out_msg[3] = (unsigned char)( ( len - 4 ) );

            if( ssl->transform_out != NULL )
            {
                /* We add the ContentType to the end of the payload
                   and fake the one visible from the outside. */
                ssl->out_msg[len] = MBEDTLS_SSL_MSG_HANDSHAKE;
                len += 1;
                ssl->out_msglen += 1;
            }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
            /*
             * DTLS has additional fields in the Handshake layer,
             * between the length field and the actual payload:
             *      uint16 message_seq;
             *      uint24 fragment_offset;
             *      uint24 fragment_length;
             */
            if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            {
                /* Make room for the additional DTLS fields */
                memmove( ssl->out_msg + mbedtls_ssl_hs_hdr_len( ssl ), ssl->out_msg + 4, len - 4 );
                ssl->out_msglen += 8;
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
                /* Advancing also the pointer to the pre_shared_key extension ( if used ) */
                if( ( ssl->handshake != NULL ) && ( ssl->handshake->pre_shared_key_pointer != NULL ) )
                {
                    ssl->handshake->pre_shared_key_pointer += 8;
                }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
                len += 8;

                /* Write message_seq and update it */
                if( ssl->out_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET )
                {
                    /* TBD: Here we just fake the sequence number field.
                     * In the future we need to store the sequence number in the
                     * session state ( instead of the handshake state ).
                     */
                    /* Add Handshake sequence number */
                    ssl->out_msg[4] = ( ssl->handshake->out_msg_seq >> 8 ) & 0xFF;
                    ssl->out_msg[5] = ( ssl->handshake->out_msg_seq ) & 0xFF;
                    ++( ssl->handshake->out_msg_seq );
                }
                else
                {
                    /* Add Handshake sequence number */
                    ssl->out_msg[4] = ( ssl->handshake->out_msg_seq >> 8 ) & 0xFF;
                    ssl->out_msg[5] = ( ssl->handshake->out_msg_seq ) & 0xFF;
                    ++( ssl->handshake->out_msg_seq );
                }

                /* We don't fragment, so frag_offset = 0 and frag_len = len */
                memset( ssl->out_msg + 6, 0x00, 3 );

                /* Copying the length field back into the shifted area */
                memcpy( ssl->out_msg + 9, ssl->out_msg + 1, 3 );
            }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED) && defined(MBEDTLS_SSL_CLI_C)
            /* We need to patch the psk binder by
             * re-running the function to get the correct length information for the extension.
             * But: we only do that when in ClientHello state and when using a PSK mode
             */
            if( ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
                &&
                ( ssl->state == MBEDTLS_SSL_CLIENT_HELLO )
                &&
                ( ssl->handshake->extensions_present & PRE_SHARED_KEY_EXTENSION )
                &&
                ( ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_ALL ||
                  ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_ALL ||
                  ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_KE ||
                  ssl->conf->key_exchange_modes == MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_DHE_KE ) ) {

                mbedtls_ssl_write_pre_shared_key_ext( ssl, ssl->handshake->ptr_to_psk_ext, &ssl->out_msg[len], &dummy_length, 1 );
            }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED && MBEDTLS_SSL_CLI_C */

            /* For post-handshake messages we do not need to update the hash anymore */
            if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
            {
                if( ssl->transform_out != NULL )
                {
                    /* If we append the handshake type to the message then we
                     * don't include it in the handshake hash. */

                    MBEDTLS_SSL_DEBUG_MSG( 5, ( "--- Update Checksum ( mbedtls_ssl_write_record-1 )" ) );

                    ssl->handshake->update_checksum( ssl, ssl->out_msg, len - 1 );
                }
                else
                {
                    MBEDTLS_SSL_DEBUG_MSG( 5, ( "--- Update Checksum ( mbedtls_ssl_write_record )" ) );
                    ssl->handshake->update_checksum( ssl, ssl->out_msg, len );
                }
            }
        }
    }

    /* Save handshake and CCS messages for resending */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake != NULL &&
        ssl->handshake->retransmit_state != MBEDTLS_SSL_RETRANS_SENDING &&
        ( ssl->out_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC ||
          ssl->out_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE ) )
    {
        if( ( ret = ssl_flight_append( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_flight_append", ret );
            return( ret );
        }
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_write != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_write( )" ) );

        ret = mbedtls_ssl_hw_record_write( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_write", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

    if( !done )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        size_t i=0;

        /*
         *
         * --- DTLS 1.3 Record Layer Header ---
         *
         * struct {
         * 		ContentType type;
         * 		ProtocolVersion legacy_record_version;
         * 		uint16 epoch = 0         // DTLS field
         * 		uint48 sequence_number;  // DTLS field
         * 		uint16 length;
         * 		opaque fragment[DTLSPlaintext.length];
         * } DTLSPlaintext;

         * struct {
         * 		opaque content[DTLSPlaintext.length];
         *      ContentType type;
         * 		uint8 zeros[length_of_padding];
         * } DTLSInnerPlaintext;
         *
         * struct {
         * 		opaque unified_hdr[variable];
         * 		opaque encrypted_record[length];
         * } DTLSCiphertext;
         *
         *    0 1 2 3 4 5 6 7
         *    +-+-+-+-+-+-+-+-+
         *    |0|0|1|C|S|L|E E|
         *    +-+-+-+-+-+-+-+-+
         *    | Connection ID |   Legend:
         *    | ( if any,      |
         *    /  length as    /   C   - CID present
         *    |  negotiated )  |   S   - Sequence number length
         *    +-+-+-+-+-+-+-+-+   L   - Length present
         *    |  8 or 16 bit  |   E   - Epoch
         *    |Sequence Number|
         *    +-+-+-+-+-+-+-+-+
         *    | 16 bit Length |
         *    | ( if present )  |
         *    +-+-+-+-+-+-+-+-+
         *
         */

        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {

            if( ssl->transform_out == NULL )
            {
                /* Plaintext DTLS payload */

                /* Set ContentType  */
                ssl->out_hdr[0] = ssl->out_msgtype;

                /* Write version */
                mbedtls_ssl_write_version( ssl->major_ver, ssl->minor_ver,
                                           ssl->conf->transport, ssl->out_hdr + 1 );

                /* Write epoch */
                ssl->out_buf[3] = ( char )( ssl->out_epoch >> 8 ) & 0xFF;
                ssl->out_buf[4] = ( char )( ssl->out_epoch ) & 0xFF;

                /* Write sequence number */
                /* TBD */

                /* Write Length */
                ssl->out_len[0] = (unsigned char)( len >> 8 );
                ssl->out_len[1] = (unsigned char)( len );
            }
            else
            {
                /* Encrypted DTLS payload */

                /* Set flags in unified header */
                ssl->out_hdr[0] = MBEDTLS_SSL_UNIFIED_HDR_PREAMBLE_3;

#if defined(MBEDTLS_CID)
                if( ssl->out_cid_len > 0 )
                {

                    ssl->out_hdr[0] = ssl->out_hdr[0] | MBEDTLS_SSL_UNIFIED_HDR_CID;

                    /* Write the CID of the outgoing datagram */
                    memcpy( &ssl->out_hdr[1], ssl->out_cid, ssl->out_cid_len );
                    i += ssl->out_cid_len;
                }
#endif /* MBEDTLS_CID */

                /* Write epoch */
                switch ( ssl->out_epoch % 4 ) {

                    case 0: /* clear epoch 1 and 2 */
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1 );
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2 );
                        break;

                    case 1: /* Set epoch 1 and clear epoch 2 */
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1;
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2 );
                        break;

                    case 2: /* Clear epoch 1 and set epoch 2 */
                        ssl->out_hdr[0] &= ~( MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1 );
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2;
                        break;

                    case 3: /* Set epoch 1 and 2 */
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1;
                        ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2;
                }

                /* Write 16 bit sequence number */
                ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_SNR;

                /* Change pointer for where to store the sequence number fields */
                ssl->out_ctr = &ssl->out_hdr[1 + i];

                /* Write 16 bit length */
                ssl->out_hdr[0] |= MBEDTLS_SSL_UNIFIED_HDR_LEN;
                ssl->out_hdr[3 + i] = (unsigned char)( len >> 8 );
                ssl->out_hdr[4 + i] = (unsigned char)( len );

                /* Change pointer to length field */
                ssl->out_len = &ssl->out_hdr[3 + i];

                /* Change pointer to message contents */
                ssl->out_msg = &ssl->out_hdr[3 + i + 2];
            }
        }
        else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        {

            /*
             *
             * --- TLS 1.3 Record Layer Header ---
             *
             *	struct {
             *  	ContentType type;
             *		ProtocolVersion record_version = { 3, 1 };
             * 		uint16 length;
             * 		opaque fragment[TLSPlaintext.length];
             * } TLSPlaintext;
             */

            /* Set ContentType  */
            if( ssl->transform_out != NULL )
            {
                /* In case of TLS 1.3 for encrypted payloads we claim that we are
                 * sending application data but in reality we are using
                 * an encrypted handshake message.
                 */
                ssl->out_hdr[0] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
            }
            else
            {
                ssl->out_hdr[0] = ssl->out_msgtype;
            }

            /* TLS 1.3 re-uses the version {3, 4} in the ClientHello, Serverhello,
             * etc. but the record layer uses {3, 3} ( or {3,1} for compatibility reasons,
             * and hence we need to patch it.
             */
            mbedtls_ssl_write_version( 3, 3, ssl->conf->transport, ssl->out_hdr + 1 );

            /* Write Length */
            ssl->out_len[0] = (unsigned char)( len >> 8 );
            ssl->out_len[1] = (unsigned char)( len );
        }

        if( ssl->transform_out != NULL )
        {
            if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_encrypt_buf", ret );
                return( ret );
            }

            len = ssl->out_msglen;
            ssl->out_len[0] = (unsigned char)( len >> 8 );
            ssl->out_len[1] = (unsigned char)( len );
        }

        /* Calculate the number of bytes we have to put on the wire */
        protected_record_size = mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_OUT,
                                                     ssl->transform_out ) + len;

        ssl->out_left += protected_record_size;
        ssl->out_hdr  += protected_record_size;
        mbedtls_ssl_update_out_pointers( ssl, ssl->transform_out );

        if( ssl->transform_out != NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                                        "version = [%d:%d], msglen = %d",
                                        ssl->out_msgtype, ssl->major_ver, ssl->minor_ver,
                                        ( ssl->out_len[0] << 8 ) | ssl->out_len[1] ) );
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                                        "version = [%d:%d], msglen = %d",
                                        ssl->out_hdr[0], ssl->out_hdr[1], ssl->out_hdr[2],
                                        ( ssl->out_len[0] << 8 ) | ssl->out_len[1] ) );
        }
    }

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= write record" ) );

    return( 0 );
}

/*
 * ContentType type;
 * ProtocolVersion version;
 * uint16 epoch;            // DTLS only
 * uint48 sequence_number;  // DTLS only
 * uint16 length;
 */
static int ssl_parse_record_header( mbedtls_ssl_context* ssl )
{
    int ret;
    int major_ver, minor_ver;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    int ptr_to_len;

    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->transform_in != NULL ) {
        /* For DTLS 1.3 we need to process the variable length
         * header incrementally. */

        MBEDTLS_SSL_DEBUG_BUF( 4, "input DTLS 1.3 unified header", ssl->in_hdr, 1 );

    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        MBEDTLS_SSL_DEBUG_BUF( 4, "input record header", ssl->in_hdr, mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN, ssl->transform_in ) );

        ssl->in_msgtype = ssl->in_hdr[0];
        ssl->in_msglen = ( ssl->in_len[0] << 8 ) | ssl->in_len[1];
        mbedtls_ssl_read_version( &major_ver, &minor_ver, ssl->conf->transport, ssl->in_hdr + 1 );

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "input record: msgtype = %d, "
                                    "version = [%d:%d], msglen = %d",
                                    ssl->in_msgtype,
                                    major_ver, minor_ver, ssl->in_msglen ) );

        /* Check record type */
        if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE &&
            ssl->in_msgtype != MBEDTLS_SSL_MSG_ALERT &&
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
            ssl->in_msgtype != MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */
            ssl->in_msgtype != MBEDTLS_SSL_MSG_ACK &&
            ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "unknown record type" ) );

            if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                        MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE ) ) != 0 )
            {
                return( ret );
            }

            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }



#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->transform_in != NULL ) {

        /* For DTLS 1.3 we need to determine how long the header of the
         * received packet actually is. */

        size_t fetch_len = 1;

        /* Check header for correctness. */
        if( ( ssl->in_hdr[0] & ( MBEDTLS_SSL_UNIFIED_HDR_PREAMBLE_1 | MBEDTLS_SSL_UNIFIED_HDR_PREAMBLE_1 | MBEDTLS_SSL_UNIFIED_HDR_PREAMBLE_3 ) ) != 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unified header contains invalid preamble." ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        /* Store message type */
/* ssl->in_msgtype = MBEDTLS_SSL_MSG_TLS_CID; ( in DTLS 1.3 we shouldn't be using this message type ) */
        ssl->in_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;

#if defined(MBEDTLS_CID)
        if( ssl->in_hdr[0] & MBEDTLS_SSL_UNIFIED_HDR_CID )
        {
            /* Datagram contains a CID */
            fetch_len += ssl->in_cid_len;
        }
#endif /* MBEDTLS_CID */

        if( ssl->in_hdr[0] & MBEDTLS_SSL_UNIFIED_HDR_SNR )
        {
            /* Datagram contains a sequence number of 2 bytes length */
            fetch_len += 2;
        }
        else
        {
            /* Datagram contains a sequence number of 1 byte length */
            fetch_len++;
        }

        if( ssl->in_hdr[0] & MBEDTLS_SSL_UNIFIED_HDR_LEN )
        {
            /* Datagram contains a length field */
            ptr_to_len = fetch_len;
            fetch_len += 2;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "no length information in the DTLS 1.3 header" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        /* Read the entire header */
        if( ssl->in_left < fetch_len )
        {
            /* TBD ( Experimental ): Fetch the rest of the header, if
             * we do not have enough data in the input buffer yet.
             */
            if( ( ret = mbedtls_ssl_fetch_input( ssl, fetch_len ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
                return( ret );
            }
        }
        /* Retrieve message length info */
        ssl->in_msglen = ( ssl->in_hdr[ptr_to_len] << 8 ) | ssl->in_hdr[ptr_to_len + 1];

    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        /* Check version */
        if( major_ver != ssl->major_ver )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "major version mismatch" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

        if( minor_ver > ssl->conf->max_minor_ver )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "minor version mismatch" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }
    /* Check epoch with DTLS */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned int rec_epoch = 0;

        if( ssl->transform_in != NULL )
        {
            if( ssl->in_hdr[0] & MBEDTLS_SSL_UNIFIED_HDR_EPOCH_1 )
                rec_epoch += 1;

            if( ssl->in_hdr[0] & MBEDTLS_SSL_UNIFIED_HDR_EPOCH_2 )
                rec_epoch += 2;
        }
        else
        {
            rec_epoch = ( ssl->in_ctr[0] << 8 ) | ssl->in_ctr[1];
        }

        if( rec_epoch != ssl->in_epoch )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "record from another epoch: "
                                        "expected %d, received %d",
                                        ssl->in_epoch, rec_epoch ) );

#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) && defined(MBEDTLS_SSL_SRV_C)
            /*
             * Check for an epoch 0 ClientHello. We can't use in_msg here to
             * access the first byte of record content ( handshake type ), as we
             * have an active transform ( possibly iv_len != 0 ), so use the
             * fact that the record header len is 13 instead.
             */
            if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER &&
                ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER &&
                rec_epoch == 0 &&
                ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
                ssl->in_left > 13 &&
                ssl->in_buf[13] == MBEDTLS_SSL_HS_CLIENT_HELLO )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "possible client reconnect "
                                            "from the same port" ) );
                return( ssl_handle_possible_reconnect( ssl ) );
            }
            else
#endif /* MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE && MBEDTLS_SSL_SRV_C */
            {
                /* TBD: Check return statement for DTLS 1.3 */
                return( MBEDTLS_ERR_SSL_INVALID_RECORD );
            }
        }

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        /* Replay detection only works for the current epoch */
        if( rec_epoch == ssl->in_epoch &&
            mbedtls_ssl_dtls_replay_check( ssl ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "replayed record" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

        /* We store the epoch value received from the other side */
        ssl->rec_epoch = rec_epoch;

    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /* Check length against the size of our buffer */
    if( ssl->in_msglen > MBEDTLS_SSL_IN_BUFFER_LEN
        - (size_t)( ssl->in_msg - ssl->in_buf ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
        return( MBEDTLS_ERR_SSL_INVALID_RECORD );
    }

    /* Check length against bounds of the current transform and version */
    if( ssl->transform_in == NULL )
    {
        if( ssl->in_msglen < 1 ||
            ssl->in_msglen > MBEDTLS_SSL_MAX_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }
    else
    {
#if !defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        /* In compatibility mode we will receive
         * Change Cipher Spec messages, which are
         * ssl->in_msglen = 1 in length. */
        if( ssl->in_msglen < ssl->transform_in->minlen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
#endif /* !MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

        /*
         * TLS encrypted messages can have up to 256 bytes of padding
         */
        if(
#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
            ssl->in_msgtype != MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC &&
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */
            ssl->minor_ver >= MBEDTLS_SSL_MINOR_VERSION_1 &&
            ssl->in_msglen > ssl->transform_in->minlen +
            MBEDTLS_SSL_MAX_CONTENT_LEN + 256 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }
    }

    return( 0 );
}

/*
 * If applicable, decrypt ( and decompress ) record content
 */
static int ssl_prepare_record_content( mbedtls_ssl_context *ssl )
{
    int ret, done = 0;

    MBEDTLS_SSL_DEBUG_BUF( 4, "RECEIVED FROM NETWORK",
                           ssl->in_hdr, mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN, ssl->transform_in ) + ssl->in_msglen );

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_read != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "going for mbedtls_ssl_hw_record_read( )" ) );

        ret = mbedtls_ssl_hw_record_read( ssl );
        if( ret != 0 && ret != MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_read", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }

        if( ret == 0 )
            done = 1;
    }
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */
    if( !done && ssl->transform_in != NULL )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)

        /* If we received an old record ( based on the epoch value )
         * then we need to change the keys. */
        if( ( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM ) &&
            ( ssl->rec_epoch != ssl->in_epoch ) &&
            ( ssl->transform_in->traffic_keys_previous.epoch == ssl->rec_epoch ) )
        {
            ret = mbedtls_set_traffic_key( ssl, &ssl->transform_in->traffic_keys_previous, ssl->transform_in,1 );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_set_traffic_key", ret );
                return( ret );
            }
        }

#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
            return( 0 );
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

        if( ( ret = ssl_decrypt_buf( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "ssl_decrypt_buf", ret );
            return( ret );
        }

        MBEDTLS_SSL_DEBUG_BUF( 4, "input payload after decrypt",
                               ssl->in_msg, ssl->in_msglen );

        if( ssl->in_msglen > MBEDTLS_SSL_MAX_CONTENT_LEN )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( MBEDTLS_ERR_SSL_INVALID_RECORD );
        }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
        /* We re-set the key. */

        if( ( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM ) &&
            ( ssl->rec_epoch != ssl->in_epoch ) &&
            ( ssl->transform_in->traffic_keys_previous.epoch == ssl->rec_epoch ) )
        {
            ret = mbedtls_set_traffic_key( ssl, &ssl->transform_in->traffic_keys, ssl->transform_in,1 );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_set_traffic_key", ret );
                return( ret );
            }
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    }


#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        mbedtls_ssl_dtls_replay_update( ssl );
    }
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

    return( 0 );
}

void ssl_handshake_wrapup_free_hs_transform( mbedtls_ssl_context *ssl );

/*
 * Read a record. ( TLS 1.3 only )
 *
 * Silently ignore non-fatal alert ( and for DTLS, invalid records as well,
 * RFC 6347 4.1.2.7 ) and continue reading until a valid record is found.
 *
 */

int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl )
{
    int ret;
    int fetch_len;

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "=> read record" ) );

    if( ssl->in_hslen != 0 && ssl->in_hslen < ssl->in_msglen )
    {
        /*
         * Get next Handshake message in the current record
         */
        ssl->in_msglen -= ssl->in_hslen;

        memmove( ssl->in_msg, ssl->in_msg + ssl->in_hslen,
                 ssl->in_msglen );

        MBEDTLS_SSL_DEBUG_BUF( 4, "remaining content in record",
                               ssl->in_msg, ssl->in_msglen );

        if( ( ret = mbedtls_ssl_prepare_handshake_record( ssl ) ) != 0 )
            return( ret );

        return( 0 );
    }

    ssl->in_hslen = 0;

    /*
     * Read the record header and parse it
     */
    fetch_len = mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN, ssl->transform_in );

read_record_header:
    if( ( ret = mbedtls_ssl_fetch_input( ssl, fetch_len ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( ret );
    }

    if( ( ret = ssl_parse_record_header( ssl ) ) != 0 )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            ret != MBEDTLS_ERR_SSL_CLIENT_RECONNECT )
        {
            /* Ignore bad record and get next one; drop the whole datagram
             * since current header cannot be trusted to find the next record
             * in current datagram */
            ssl->next_record_offset = 0;
            ssl->in_left = 0;

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record ( header )" ) );
            goto read_record_header;
        }
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        return( ret );
    }

    /*
     * Read message contents
     */
    if( ( ret = mbedtls_ssl_fetch_input( ssl, fetch_len + ssl->in_msglen ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
        return( ret );
    }


    /* Done reading this record, get ready for the next one */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        ssl->next_record_offset = ssl->in_msglen + mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN, ssl->transform_in );
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        ssl->in_left = 0;

    /*
     * optionally decrypt message
     */

    if( ( ret = ssl_prepare_record_content( ssl ) ) != 0 )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            /* Silently discard invalid records */
            if( ret == MBEDTLS_ERR_SSL_INVALID_RECORD ||
                ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            {
                /* Except when waiting for Finished as a bad mac here
                 * probably means something went wrong in the handshake
                 * ( eg wrong psk used, mitm downgrade attempt, etc. ) */
                if( ssl->state == MBEDTLS_SSL_CLIENT_FINISHED ||
                    ssl->state == MBEDTLS_SSL_SERVER_FINISHED )
                {
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
                    if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
                    {
                        mbedtls_ssl_send_alert_message( ssl,
                                                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                        MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
                    }
#endif /* MBEDTLS_SSL_ALL_ALERT_MESSAGES */
                    return( ret );
                }

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
                if( ssl->conf->badmac_limit != 0 &&
                    ++ssl->badmac_seen >= ssl->conf->badmac_limit )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "too many records with bad MAC" ) );
                    return( MBEDTLS_ERR_SSL_INVALID_MAC );
                }
#endif /* MBEDTLS_SSL_DTLS_BADMAC_LIMIT */

                MBEDTLS_SSL_DEBUG_MSG( 1, ( "discarding invalid record ( mac )" ) );
                goto read_record_header;
            }

            return( ret );
        }
        else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
        {
            /* Error out ( and send alert ) on invalid records */
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
            if( ret == MBEDTLS_ERR_SSL_INVALID_MAC )
            {
                mbedtls_ssl_send_alert_message( ssl,
                                                MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC );
            }
#endif /* MBEDTLS_SSL_ALL_ALERT_MESSAGES */
            return( ret );
        }
    }

    /*
     * Handshake message processing for unencrypted handshake messages
     */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        if( ( ret = mbedtls_ssl_prepare_handshake_record( ssl ) ) != 0 )
            return( ret );
    }

    /* In TLS / DTLS 1.3 most of the messages are encrypted and appear to be
     * application data payloads with the true message type hidden inside.
     */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_APPLICATION_DATA || ssl->in_msgtype == MBEDTLS_SSL_MSG_TLS_CID )
    {
        /* The structure of the payload should be as follows:
         *    struct {
         *       opaque content[TLSPlaintext.length];
         *       ContentType type;
         *       uint8 zeros[length_of_padding];
         *    } TLSInnerPlaintext;
         *
         * We will check whether the ContentType is indeed a
         * handshake message.
         *
         * We will walk backwards in the decrypted message
         * to scan over eventually available padding bytes.
         *
         * A similiar structure is used for DTLS 1.3, namely
         *
         *    struct {
         *       opaque content[DTLSPlaintext.length];
         *       ContentType type;
         *       uint8 zeros[length_of_padding];
         *    } DTLSInnerPlaintext;
         *
         */

        /* Set handshake message to an invalid type */
        ssl->in_msgtype = 0;

        for ( int i = ssl->in_msglen; i > 0; i-- )
        {
            switch ( ssl->in_msg[i - 1] )
            {
                case 0:
                    /* This is padding. */
                    break;

                case MBEDTLS_SSL_MSG_HANDSHAKE:
                    /* We received an encrypted handshake message */
                    ssl->in_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
                    /* Skip the ContentType and padding */
                    ssl->in_msglen = i - 1;
                    /* ssl->in_hslen = ( ( ssl->in_msg[1] << 16 ) | ( ssl->in_msg[2] << 8 ) | ( ssl->in_msg[3] ) ) + mbedtls_ssl_hs_hdr_len( ssl ); */

                    if( ( ret = mbedtls_ssl_prepare_handshake_record( ssl ) ) != 0 )	return( ret );

                    break;
                case MBEDTLS_SSL_MSG_APPLICATION_DATA:
                    /* We received application data */
                    ssl->in_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
                    /* Skip the ContentType and padding */
                    ssl->in_msglen = i - 1;
                    break;
                case MBEDTLS_SSL_MSG_ALERT:
                    /* We received an alert */
                    ssl->in_msgtype = MBEDTLS_SSL_MSG_ALERT;
                    /* Skip the ContentType and padding */
                    ssl->in_msglen = i - 1;
                    break;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
                case MBEDTLS_SSL_MSG_ACK:
                    /* We received an ACK */
                    ssl->in_msgtype = MBEDTLS_SSL_MSG_ACK;
                    /* Skip the ContentType and padding */
                    ssl->in_msglen = i - 1;

                    if( ( ret = mbedtls_ssl_parse_ack( ssl ) ) != 0 )
                        return( ret );

                    break;
#endif /* MBEDTLS_SSL_PROTO_DTLS */
                default:
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "unknown message" ) );

                    mbedtls_ssl_send_alert_message( ssl,
                                                    MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                    MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );

                    return( MBEDTLS_ERR_SSL_BAD_HS_UNKNOWN_MSG );
            }

            if( ssl->in_msgtype != 0 )
            {
                /* we found an appropriate type. */
                break;
            }
        }
    }

    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "got an alert message, type: [%d:%d]",
                                    ssl->in_msg[0], ssl->in_msg[1] ) );

        /*
         * Ignore non-fatal alerts, except close_notify and no_renegotiation
         */
        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_FATAL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "is a fatal alert message ( msg %d )",
                                        ssl->in_msg[1] ) );
            return( MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE );
        }

        if( ssl->in_msg[0] == MBEDTLS_SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "is a close notify message" ) );
            return( MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY );
        }

        /* Silently ignore: fetch new message */
        goto read_record_header;
    }

#if defined(MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE)
    /* We ignore incoming ChangeCipherSpec messages */
    if( ssl->in_msgtype == MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Received ChangeCipherSpec message" ) );

        if( ssl->in_msglen != 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad CCS message" ) );
            return( MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
        }

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "CCS, message len.: %d", ssl->in_msglen ) );

        /*
          if( ( ret = mbedtls_ssl_fetch_input( ssl, mbedtls_ssl_hdr_len( ssl ) + ssl->in_msglen ) ) != 0 )
          {
          MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_fetch_input", ret );
          return( MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
          }
        */

        /* Message payload is 1-byte long; check whether it is set to '1' */
        if( ssl->in_msg[0] == 1 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "Ignoring CCS." ) );

            /* Done reading this record, get ready for the next one */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
            if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
            {
                ssl->next_record_offset = mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN ) + ssl->in_msglen;
            }
            else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
            {
                ssl->in_left = 0;
            }

            /* Silently ignore: fetch new message */
            goto read_record_header;
        }
        else
        {
            if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                        MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE ) ) != 0 )
            {
                return( ret );
            }
            return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        }
    }
#endif /* MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE */

    MBEDTLS_SSL_DEBUG_MSG( 5, ( "<= read record" ) );

    return( 0 );
}

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                                MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}



/*
 * Send pending fatal alerts or warnings.
 */
int mbedtls_ssl_handle_pending_alert( mbedtls_ssl_context *ssl )
{
    int ret;

    /* Send alert if requested */
    if( ssl->send_alert != 0 )
    {
        ret = mbedtls_ssl_send_alert_message( ssl,
                                              ssl->send_alert,
                                              ssl->alert_type );
        if( ret != 0 )
            return( ret );
    }

    ssl->send_alert = 0;
    ssl->alert_type = 0;
    return( 0 );
}

int mbedtls_ssl_send_alert_message( mbedtls_ssl_context *ssl,
                                    unsigned char level,
                                    unsigned char message )
{
    int ret;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> send alert message" ) );

    ssl->out_msgtype = MBEDTLS_SSL_MSG_ALERT;
    ssl->out_msg[0] = level;
    ssl->out_msg[1] = message;

    /* TBD: We need to check what alert messages are sent encrypted.
       Particularly for alerts that are send after cleaning the
       handshake will potentially transmitted in cleartext. */
    if( ssl->transform != NULL || ssl->transform_out!=NULL )
    {
        /* If we encrypt then we add the content type and optionally padding. */
        ssl->out_msglen = 3; // 3 includes the content type as well
        /* We use no padding. */
        ssl->out_msg[2] = MBEDTLS_SSL_MSG_ALERT;
    } else
    {
        ssl->out_msglen = 2;
    }

    if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= send alert message" ) );

    return( 0 );
}




int mbedtls_ssl_get_record_expansion( const mbedtls_ssl_context *ssl, int direction )
{
    size_t transform_expansion;
    mbedtls_ssl_transform *transform = ssl->transform_out;


    if( transform == NULL && direction == MBEDTLS_SSL_DIRECTION_IN )
        return( ( int ) mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN, transform ) );

    if( transform == NULL && direction == MBEDTLS_SSL_DIRECTION_OUT )
        return( ( int )mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_OUT, transform ) );

    switch( mbedtls_cipher_get_cipher_mode( &transform->cipher_ctx_enc ) )
    {
        case MBEDTLS_MODE_GCM:
        case MBEDTLS_MODE_CCM:
        case MBEDTLS_MODE_STREAM:
            transform_expansion = transform->minlen;
            break;

        case MBEDTLS_MODE_CBC:
            transform_expansion = transform->maclen
                + mbedtls_cipher_get_block_size( &transform->cipher_ctx_enc );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( direction == MBEDTLS_SSL_DIRECTION_IN )
        return( ( int )( mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_IN, transform ) + transform_expansion ) );
    else
        return( ( int )( mbedtls_ssl_hdr_len( ssl, MBEDTLS_SSL_DIRECTION_OUT, transform ) + transform_expansion ) );
}



/*
 * Receive application data decrypted from the SSL layer
 */
int mbedtls_ssl_read( mbedtls_ssl_context *ssl, unsigned char *buf, size_t len )
{
    int ret, record_read = 0;
    size_t n;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> read" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
            return( ret );

        if( ssl->handshake != NULL &&
            ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING )
        {
            if( ( ret = mbedtls_ssl_resend( ssl ) ) != 0 )
                return( ret );
        }
    }
#endif


    if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        ret = mbedtls_ssl_handshake( ssl );
        if( ret == MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO )
        {
            record_read = 1;
        }
        else if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
            return( ret );
        }
    }

    if( ssl->in_offt == NULL )
    {
        /* Start timer if not already running */
        if( ssl->f_get_timer != NULL &&
            ssl->f_get_timer( ssl->p_timer ) == -1 )
        {
            mbedtls_ssl_set_timer( ssl, ssl->conf->read_timeout );
        }

        if( !record_read )
        {
            if( ( ret = mbedtls_ssl_read_record( ssl ) ) != 0 )
            {
                if( ret == MBEDTLS_ERR_SSL_CONN_EOF )
                    return( 0 );

                if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
                    return( ret );

                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
                return( ret );
            }
        }




        /* Fatal and closure alerts handled by mbedtls_ssl_read_record( ) */
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ignoring non-fatal non-closure alert" ) );
            return( MBEDTLS_ERR_SSL_WANT_READ );
        }

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
        /* Post-Handshake messages, like the NewSessionTicket message, appear after the finished
         * message was sent */
        if( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE )
        {
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "received post-handshake message" ) );

#if defined(MBEDTLS_SSL_CLI_C)
            if( ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) &&
                ( ssl->in_hslen != mbedtls_ssl_hs_hdr_len( ssl ) ) &&
                ( ssl->in_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET ) ) {
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "NewSessionTicket received" ) );

                if( ( ret = mbedtls_ssl_parse_new_session_ticket( ssl ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_parse_new_session_ticket", ret );
                    return( ret );
                }
            }
#endif /* MBEDTLS_SSL_CLI_C */
        } else
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
            if( ssl->in_msgtype == MBEDTLS_SSL_MSG_ACK )
            {
                /* We will not pass the Ack msg to the application. */
                ssl->in_offt = NULL;
                ssl->in_msglen = 0;
                MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= read" ) );
                return( MBEDTLS_ERR_SSL_WANT_READ );
            }
            else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
                if( ssl->in_msgtype != MBEDTLS_SSL_MSG_APPLICATION_DATA )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad application data message" ) );
                    return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
                }


        if( ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) &&
            ( ssl->in_msg[0] == MBEDTLS_SSL_HS_NEW_SESSION_TICKET ) )
        {
            /* We will not pass a NewSessionTicket to the application. */
            ssl->in_offt = NULL;
            ssl->in_msglen = 0;
            n = MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET;
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= read" ) );

            /* For a post-handshake message we may need to return
             * an ACK message
             */
            /* TBD. */
            return( ( int ) n );

        }
        else
        {
            ssl->in_offt = ssl->in_msg;
        }

    }

    n = ( len < ssl->in_msglen )
        ? len : ssl->in_msglen;

    memcpy( buf, ssl->in_offt, n );
    ssl->in_msglen -= n;

    if( ssl->in_msglen == 0 )
        /* all bytes consumed  */
        ssl->in_offt = NULL;
    else
        /* more data available */
        ssl->in_offt += n;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= read" ) );

    return( ( int ) n );
}

/*
 * Send application data to be encrypted by the SSL layer,
 * taking care of max fragment length and buffer size
 */
static int ssl_write_real( mbedtls_ssl_context *ssl,
                           const unsigned char *buf, size_t len )
{
    int ret;
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    size_t max_len = mbedtls_ssl_get_max_frag_len( ssl );


    if( len > max_len )
    {
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "fragment larger than the ( negotiated ) "
                                        "maximum fragment length: %d > %d",
                                        len, max_len ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        }
        else
#endif
            len = max_len;
    }
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

    if( ssl->out_left != 0 )
    {
        if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flush_output", ret );
            return( ret );
        }
    }
    else
    {
        ssl->out_msgtype = MBEDTLS_SSL_MSG_APPLICATION_DATA;
        memcpy( ssl->out_msg, buf, len );

        /* Adding content type at the end of the data*/
        ssl->out_msg[len] = MBEDTLS_SSL_MSG_APPLICATION_DATA;
        ssl->out_msglen = len + 1;
        len++;

        if( ( ret = mbedtls_ssl_write_record( ssl ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_record", ret );
            return( ret );
        }
    }

    return( ( int ) len );
}



/*
 * Write application data ( public-facing wrapper )
 */
int mbedtls_ssl_write( mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len )
{
    int ret;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write" ) );

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );


#if defined(MBEDTLS_ZERO_RTT)
    if( ( ssl->handshake!= NULL ) && ( ssl->handshake->early_data == MBEDTLS_SSL_EARLY_DATA_OFF ) )
#endif/* MBEDTLS_ZERO_RTT */
    {
        if( ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER )
        {
            if( ( ret = mbedtls_ssl_handshake( ssl ) ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_handshake", ret );
                return( ret );
            }
        }
    }

    ret = ssl_write_real( ssl, buf, len );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write" ) );

    return( ret );
}

/*
 * Notify the peer that the connection is being closed
 */
int mbedtls_ssl_close_notify( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ssl == NULL || ssl->conf == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write close notify" ) );

    if( ssl->out_left != 0 )
        return( mbedtls_ssl_flush_output( ssl ) );

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER )
    {
        if( ( ret = mbedtls_ssl_send_alert_message( ssl,
                                                    MBEDTLS_SSL_ALERT_LEVEL_WARNING,
                                                    MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_send_alert_message", ret );
            return( ret );
        }
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write close notify" ) );

    return( 0 );
}


#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS_C */
