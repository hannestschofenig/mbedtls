/*
 *  SSLv3/TLSv1 shared functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_PROTO_QUIC)

#include <stdbool.h>

#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "mbedtls/quic.h"
#include "mbedtls/quic_internal.h"

int mbedtls_quic_input_provide_data(mbedtls_ssl_context* ssl,
    mbedtls_ssl_crypto_level level,
    const uint8_t* data,
    size_t len) {

  int rv = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

  MBEDTLS_SSL_DEBUG_MSG( 2,
      ( "=> mbedtls_quic_input_provide_data: level: %d len: %u", level, len ) );

  quic_input_queue *queue = quic_input_lookup_queue(ssl, level);

  rv = quic_input_provide_data(ssl, queue, data, len);

  MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_quic_input_provide_data", rv);
  return rv;
}

int quic_input_allocate_msg(mbedtls_ssl_context *ssl, quic_input_queue *queue) {
  int rv = 0;
  quic_input_msg *hs_msg = NULL;
  char hs_msg_type = queue->tmp_hdr[0];
  const size_t hs_msg_size = hs_msg_body_size(queue->tmp_hdr) + QUIC_HS_HDR_SIZE;

  /* Allocate QD block for the `quic_input_msg` + hs_msg_len bytes */
  if ((hs_msg = mbedtls_calloc(1, sizeof(quic_input_msg) + hs_msg_size)) == NULL) {
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "quic_input_provide_data: FATAL ERR "
          "failed to allocate %u bytes", sizeof(quic_input_msg) + hs_msg_size));
    rv = MBEDTLS_ERR_SSL_ALLOC_FAILED;
    goto cleanup;
  }

  /* Initialize the handshake message header */
  hs_msg->next       = NULL;
  hs_msg->size       = hs_msg_size;
  hs_msg->num        = queue->msg_count++;
  hs_msg->type       = hs_msg_type;
  hs_msg->level      = queue->level;
  hs_msg->len        = 0;

  hs_msg_append_data(hs_msg, queue->tmp_hdr, QUIC_HS_HDR_SIZE);

  /* Append the new handshake message to the chain */
  if (queue->tail != NULL) {
    queue->tail->next = hs_msg;
  } else {
    queue->head = hs_msg;
  }
  queue->tail = hs_msg;

  MBEDTLS_SSL_DEBUG_QUIC_HS_MSG(3, "quic_input_provide_data: "
      "allocated new message", hs_msg);

  // Release the pointer to the message, since the ownership
  // has been transferred to the queue.
  hs_msg = NULL;

cleanup:
  mbedtls_free(hs_msg);
  queue->tmp_hdr_len = 0;
  return rv;
}

int quic_input_provide_data(mbedtls_ssl_context *ssl, quic_input_queue* queue, const uint8_t* data, size_t datalen) {

  MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> quic_input_provide_data" ) );

  if (data == NULL || datalen == 0) {
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= quic_input_provide_data (null input)" ) );
    return 0;
  }

  /* Start consuming the data, while splitting it into handshake messages. */
  int rv = 0;

  const uint8_t *data_end = data + datalen;
  while (data < data_end) {

    /* ---- CONSUME HANDSHAKE MESSAGE BODY ----
     *
     * The last element in the input queue may contain only
     * a part of the handshake message. In such case, the
     * actual length of the message will not match the length field
     * in the headshake header: `queue->tail->len < queue->tail-size`.
     *
     * If this is the case, this means that the handshake message
     * has been fragmented in the body area, and that the `data`
     * pointer carries the continuation data.
     *
     * Check for the partial message body, and provide the
     * necessary data.
     */
    if (quic_input_last_msg_is_partial(ssl, queue)) {
      data += quic_input_fill_last_msg(ssl, queue, data, data_end);
      continue;
    }

    /* ---- CONSUME HANDSHAKE MESSAGE HEADER -----
     *
     * The header message is first being read from the `data` pointer
     * into the `queue->tmp_hdr`. This way, if the CRYPTO frame payload
     * has been fragmented for some reason, the code is able to continue
     * reading the header bytes.
     */
    if (quic_input_last_msg_hdr_is_partial(ssl, queue)) {
      data += quic_input_fill_last_msg_hdr(ssl, queue, data, data_end);
      continue;
    }

    /* ---- VALIDATE THE HANDSHAKE HEADER ----
     *
     * The header has been fully consumed and stored in the `queue->tmp_hdr`
     * array. Validate the header.
     */
    if ((rv = quic_input_validate_last_hdr(ssl, queue)) != 0) {
      //  The header is not valid. Reset the header state and return early,
      //  ignoring the rest of the data. If the next invocation of
      //  `quic_input_provide_data` will start with a valid message, the
      //  queue will start from parsing the header.
      quic_input_reset_last_msg_hdr(ssl, queue);
      MBEDTLS_SSL_DEBUG_RET(2, "quic_input_provide_data", rv);
      return rv;
    }

    /* ---- ALLOCATE A NEW MESSAAGE IN THE QUEUE ----
     *
     * The header has been fully consumed and stored in the `queue->tmp_hdr`
     * array. Proceed to parsing the header, and allocate the memory.
     */
    if ((rv = quic_input_allocate_msg(ssl, queue)) != 0) {
      MBEDTLS_SSL_DEBUG_RET(2, "quic_input_provide_data", rv);
      return rv;
    }
  } /* while data < data_end */

  return rv;
}

int quic_input_read(
    mbedtls_ssl_context *ssl,
    quic_input_queue    *queue,
    uint8_t             *data,
    size_t               datalen) {

  int rv = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

  MBEDTLS_SSL_DEBUG_MSG( 3,
      ( "=> quic_input_read: data: %p len: %u", data, datalen ) );

  quic_input_msg  *hs_msg = NULL;

  if (data == NULL || datalen == 0) {
    // nowhere to read, not an error.
    rv = 0;
    goto cleanup;
  }

  if ((hs_msg = queue->head) == NULL) {
    // nothing to read, not an error.
    rv = 0;
    goto cleanup;
  }

  MBEDTLS_SSL_DEBUG_QUIC_HS_MSG(3, "quic_input_read", hs_msg);

  if (hs_msg->len < datalen) {
    datalen = hs_msg->len;
  }

  memcpy(data, (uint8_t*)(hs_msg + 1), datalen);

  rv = (int)datalen;

  // Currently, a partial read on the message will purge the
  // message from the queue.
  queue->head = hs_msg->next;

  if (hs_msg->next == NULL) {
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "quic_input_read: empty queue" ) );
    queue->tail = NULL;
  }

cleanup:
  mbedtls_free(hs_msg);

  MBEDTLS_SSL_DEBUG_RET(2, "quic_input_read", rv);
  return rv;
}

int mbedtls_quic_input_read(
    mbedtls_ssl_context *ssl,
    mbedtls_ssl_crypto_level level,
    uint8_t *data,
    size_t datalen) {

  int rv = MBEDTLS_ERR_SSL_INTERNAL_ERROR;

  MBEDTLS_SSL_DEBUG_MSG( 2,
      ( "=> mbedtls_quic_input_read: level %d data: %p len: %u", level, data, datalen ) );

  quic_input_queue *queue = quic_input_lookup_queue(ssl, level);

  // Dispatch the data to the appropriate queuue.
  rv =  quic_input_read(ssl, queue, data, datalen);

  MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_quic_input_read", rv);
  return rv;
}

void mbedtls_quic_input_init(mbedtls_ssl_context *ssl, mbedtls_quic_input *mqueue) {

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_quic_input_init" ) );

  memset(mqueue, 0, sizeof(mbedtls_quic_input));

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_quic_input_init" ) );
}

int mbedtls_quic_input_setup(mbedtls_ssl_context *ssl, mbedtls_quic_input *mqueue) {

  int rv = 0;

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_quic_input_setup" ) );

  mqueue->queues_ = mbedtls_calloc(QUIC_QUEUE_MAX_QUEUES, sizeof(quic_input_queue));
  if (mqueue->queues_ == NULL) {
    rv = MBEDTLS_ERR_SSL_ALLOC_FAILED;
    goto cleanup;
  }

  mqueue->queues_[QUIC_QUEUE_INITIAL].level     = MBEDTLS_SSL_CRYPTO_LEVEL_INITIAL;
  mqueue->queues_[QUIC_QUEUE_HANDSHAKE].level   = MBEDTLS_SSL_CRYPTO_LEVEL_HANDSHAKE;
  mqueue->queues_[QUIC_QUEUE_APPLICATION].level = MBEDTLS_SSL_CRYPTO_LEVEL_APPLICATION;

  MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_quic_input_setup", rv);
cleanup:
  return rv;
}

void quic_input_free(mbedtls_ssl_context *ssl, quic_input_queue *queue) {

  MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> quic_input_free: level: %d", queue->level ) );

  quic_input_msg *hs_msg = queue->head;

  while (hs_msg != NULL) {

    MBEDTLS_SSL_DEBUG_QUIC_HS_MSG(3, "ssl_quic_single_level_queue_free", hs_msg);

    quic_input_msg *p = hs_msg;
    hs_msg = hs_msg->next;
    mbedtls_free(p);
  }

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= quic_input_free: level: %d", queue->level ) );
}

void mbedtls_quic_input_free(mbedtls_ssl_context *ssl, mbedtls_quic_input *mqueue) {

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_quic_input_free" ) );

  quic_input_free(ssl, &mqueue->queues_[MBEDTLS_SSL_CRYPTO_LEVEL_INITIAL]);
  quic_input_free(ssl, &mqueue->queues_[MBEDTLS_SSL_CRYPTO_LEVEL_HANDSHAKE]);
  quic_input_free(ssl, &mqueue->queues_[MBEDTLS_SSL_CRYPTO_LEVEL_APPLICATION]);

  mbedtls_free(mqueue->queues_);

  MBEDTLS_SSL_DEBUG_MSG( 1, ( "<= mbedtls_quic_input_free" ) );
}

int quic_input_peek(
    mbedtls_ssl_context *ssl,
    quic_input_queue* queue,
    uint8_t *otype,
    size_t *osize,
    size_t *olen) {

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> quic_input_peek" ) );

  quic_input_msg     *hs_msg = queue->head;

  if (hs_msg == NULL ) {

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= quic_input_peek: WANT_READ" ) );

    *olen  = 0;
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  *otype = hs_msg->type;
  *osize  = hs_msg->size;
  *olen  = hs_msg->len;

  if (hs_msg->size != hs_msg->len) {
    MBEDTLS_SSL_DEBUG_QUIC_HS_MSG(2, "<= quic_input_peek: WANT_READ", hs_msg);
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  MBEDTLS_SSL_DEBUG_QUIC_HS_MSG(2, "<= quic_input_peek: ", hs_msg);

  return 0;
}

int mbedtls_quic_input_peek(
    mbedtls_ssl_context *ssl,
    mbedtls_ssl_crypto_level level,
    uint8_t *otype,
    size_t *osize,
    size_t *olen) {

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> mbedtls_quic_input_peek" ) );

  quic_input_queue *queue = quic_input_lookup_queue(ssl, level);

  int rv = quic_input_peek(ssl, queue, otype, osize, olen);

  MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= mbedtls_quic_input_peek" ) );

  return rv;
}

void mbedtls_ssl_set_hs_quic_method(mbedtls_ssl_context *ssl, void *p_quic_method, mbedtls_quic_method *quic_method) {
  ssl->p_quic_method = p_quic_method;
  ssl->quic_method = quic_method;
}

bool mbedtls_ssl_is_quic_client(mbedtls_ssl_context* ssl) {
  if (!ssl || !ssl->conf) {
    return false;
  }

  if (ssl->conf->endpoint != MBEDTLS_SSL_IS_CLIENT) {
    return false;
  }

  if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_QUIC) {
    return false;
  }

  if (!ssl->quic_method || !ssl->p_quic_method) {
    return false;
  }

  return true;
}

#endif /* MBEDTLS_SSL_PROTO_QUIC */
