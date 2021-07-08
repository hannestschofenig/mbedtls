#ifndef MBEDTLS_SSL_QIUC_INTERNAL_H
#define MBEDTLS_SSL_QIUC_INTERNAL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif /* MBEDTLS_CONFIG_FILE */

#if defined(MBEDTLS_SSL_PROTO_QUIC)
#include "mbedtls/quic.h"

#include <string.h>
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdbool.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct quic_input_msg      quic_input_msg;
typedef struct quic_input_queue    quic_input_queue;

/**
 * \brief Size of the TLS handshake message header.
 */
#define QUIC_HS_HDR_SIZE 4

/**
 * \brief Labels for different input queues.
 */
typedef enum {
  QUIC_QUEUE_INITIAL,
  QUIC_QUEUE_HANDSHAKE,
  QUIC_QUEUE_APPLICATION,
  QUIC_QUEUE_MAX_QUEUES,
} quic_queue_label;

/**
 * \brief Contiguous block of QUIC handshake message, at a given level.
 *
 * The quic data for the different levels is kept in a singly linked
 * list of "quic_input_msg" structs.
 *
 * Each struct is allocated for the entire handshake message, even
 * in the case when only part of the handshake message is available.
 *
 * The individual handshake messages are chained into a single-linked
 * list, which forms a queue of messages.
 *
 * This representation is trading off memory space for the ease of debugging.
 * Once the implementation is rock solid, this can be replaced with
 * a contiguous arena of data, with the parsing complexity moved to the
 * reading routine. In the mean time, the current representation allows
 * finding logical inconsistencies with ease.
 *
 * Layout of the "quic_input_msg"
 * 0-------8-------16--------------32-----------------------------63
 * | size                          |  on 64bit arch                |
 * +-------------------------------+-------------------------------+
 * | len                           |  on 64bit arch                |
 * +-------------------------------+-------------------------------+
 * | next                          |  on 64bit arch                |
 * +-------------------------------+-------------------------------+
 * | level                         |  num                          |
 * +-------+----+------------------+-------------------------------+
 * | type  |hdr |       handshake                                  |
 * +-------+----+         data              +----------------------+
 * |                      ....              |   compiler padding
 * +-------+-----------------------+-------------------------------+
 *
 *
 * The functions `hs_msg_data_begin` and `hs_msg_data_end` provide
 * pointers to the beginning of the handshake data, and one byte past
 * the end of the data in the message. The function `hs_msg_append_data`
 * is a convenient way to append data to the message. All three functions
 * assert that the message is allocated.
 */
struct quic_input_msg {
  size_t                     size;   /*!< Total size of the handshake data. */
  size_t                     len;    /*!< Available data, including header. */
  quic_input_msg            *next;   /*!< Next msg in the chain. */
  mbedtls_ssl_crypto_level   level;  /*!< Crypto level. */
  int                        num;    /*!< Number of this msg in queue. */
  char                       type;   /*!< Handshake msg type. */
};

/**
 * \brief Incoming queue of handshake messages.
 *
 * This is a sequence of handshake messages in a given encryption level.
 * The messages are added to the tail of the queue and are read from the
 * head of the queue. The queue struct keeps the `level` field for
 * debugging purposes. `msg_count` is incremented with every new message
 * that gets added to the queue (and is being copied to the `num` field
 * in that message. The purpose of the `msg_count` is debugging.
 *
 * The `tmp_hdr` and `tmp_hdr_len` fields store the header of the
 * incoming message. Since the stream of messages can be fragmented
 * on the header boundary, the writing routine `quic_input_provide_data`
 * first writes the temporary header from the data (and uses `tmp_hdr_len`
 * to keep track on whether the header is complete or not).
 * Once the header has been fully consumed, `quic_input_provide_data`
 * appends a new message to the tail of the queue, and resets `tmp_hdr_len`.
 */
struct quic_input_queue {
  size_t                     msg_count;
  mbedtls_ssl_crypto_level   level;
  quic_input_msg            *head;
  quic_input_msg            *tail;
  uint8_t                    tmp_hdr[QUIC_HS_HDR_SIZE];
  size_t                     tmp_hdr_len;
};


/**
 * \brief Provide data to a single queue. Used by `mbedtls_quic_input_provide_data`, and by tests.
 *
 * \param ssl        SSL context.
 * \param input      single-level message queue.
 * \param data       handshake data.
 * \param daltalen   handshake data len.
 */
int quic_input_provide_data(
    mbedtls_ssl_context *ssl, quic_input_queue *input, const uint8_t *data, size_t datalen);

/**
 * \brief Peek in the single queue. Used by `mbedtls_quic_input_peek`, and by tests.
 */
int quic_input_peek(
    mbedtls_ssl_context       *ssl,
    quic_input_queue          *input,
    uint8_t                   *otype,
    size_t                    *osize,
    size_t                    *olen);
/**
 * \brief Get a message from a single queue. Used by `mbedtls_quic_input_read`, and by tests.
 *
 * \return number of bytes written into the data buffer, or a negative error value.
 */
int quic_input_read(
    mbedtls_ssl_context  *ssl,
    quic_input_queue     *input,
    uint8_t              *data,
    size_t                datalen);

/**
 * \brief Deallocate single queue. Used by `mbedtls_quic_input_free`, and by tests.
 */
void quic_input_free(mbedtls_ssl_context *ssl, quic_input_queue *input);


/**
 * \brief Lookup a queue by the input label. Used by mbedtls_quic_*`, and by tests.
 *
 * \return NULL if not found, a pointer to the appropriate queue otherwise.
 */
static inline quic_input_queue* quic_input_lookup_queue(
    mbedtls_ssl_context *ssl,
    mbedtls_ssl_crypto_level level) {

  MBEDTLS_ASSERT(level < QUIC_QUEUE_MAX_QUEUES);

  quic_input_queue *queue = &(ssl->quic_input.queues_[level]);

  MBEDTLS_ASSERT(level == queue->level);

  return queue;
}

#define hs_msg_body_size(p) ((uint32_t)(p[1]) << 16) | ((uint32_t)(p[2]) << 8)  | (uint32_t)(p[3])

static inline uint8_t *hs_msg_data_begin(const quic_input_msg *msg) {
  MBEDTLS_ASSERT(msg != NULL);
  return (uint8_t*)(msg) + sizeof(quic_input_msg);
}

static inline uint8_t *hs_msg_data_end(const quic_input_msg *msg) {
  MBEDTLS_ASSERT(msg != NULL);
  return (uint8_t*)(msg) + sizeof(quic_input_msg) + msg->len;
}

static inline uint8_t *hs_msg_append_data(quic_input_msg *msg,
    const uint8_t* data, size_t len) {
  MBEDTLS_ASSERT(msg != NULL);
  uint8_t *p = (uint8_t*)(msg) + sizeof(quic_input_msg) + msg->len;
  memcpy(p, data, len);
  msg->len += len;
  return p + len;
}

/**
 * \brief Checks if the message type can be accepted.
 */
static inline bool quic_input_hs_type_valid(uint8_t hs_type) {
  switch (hs_type) {
  case MBEDTLS_SSL_HS_CLIENT_HELLO:
  case MBEDTLS_SSL_HS_SERVER_HELLO:
  case MBEDTLS_SSL_HS_NEW_SESSION_TICKET:
  case MBEDTLS_SSL_HS_HELLO_RETRY_REQUEST:
  case MBEDTLS_SSL_HS_ENCRYPTED_EXTENSION:
  case MBEDTLS_SSL_HS_CERTIFICATE:
  case MBEDTLS_SSL_HS_CERTIFICATE_REQUEST:
  case MBEDTLS_SSL_HS_CERTIFICATE_VERIFY:
  case MBEDTLS_SSL_HS_FINISHED:
  case MBEDTLS_SSL_HS_MESSAGE_HASH:
    return true;
  default:
    return false;
  }
}

/**
 * \brief Checks whether more data is required for the last message in the queue.
 */
static inline bool quic_input_last_msg_is_partial(mbedtls_ssl_context *ssl,
    quic_input_queue *queue) {

  quic_input_msg *hs_msg;

  if ((hs_msg = queue->tail) == NULL) {
    return false;
  }

  if (hs_msg->size == hs_msg->len) {
    return false;
  }

  MBEDTLS_ASSERT(hs_msg->size > hs_msg->len);

  return true;
}

/**
 * \brief Attempt to fill the last message in the queue from the data.
 * \return number of bytes consumed from the data.
 */
static inline size_t quic_input_fill_last_msg(mbedtls_ssl_context *ssl,
    quic_input_queue *queue, const uint8_t *data, const uint8_t *data_end) {
  quic_input_msg *hs_msg;

  if ((hs_msg = queue->tail) == NULL) {
    return 0;
  }

  size_t len = hs_msg->size - hs_msg->len;
  size_t available = data_end - data;
  if (len > available) {
    len = available;
  }

  MBEDTLS_SSL_DEBUG_MSG( 3, ( "quic_input_fill_msg_data: "
        "appending %u bytes to the partial message: size: %u len: %u",
        len, hs_msg->size, hs_msg->len) );

  hs_msg_append_data(hs_msg, data, len);

  return len;
}

/**
 * \brief Checks whether more data is required for the last message header.
 */
static inline bool quic_input_last_msg_hdr_is_partial(mbedtls_ssl_context *ssl,
    quic_input_queue *queue) {
  return queue->tmp_hdr_len < QUIC_HS_HDR_SIZE;
}

/**
 * \brief Attempt to fill the last message header from the data.
 * \return number of bytes consumed from the data.
 */
static inline size_t quic_input_fill_last_msg_hdr(mbedtls_ssl_context *ssl,
    quic_input_queue *queue, const uint8_t *data, const uint8_t *data_end) {
  size_t len = 0;

  MBEDTLS_SSL_DEBUG_MSG( 3, ( "quic_input_fill_last_msg_hdr: "
        "parsing new handshake message header: hdr_len %u", queue->tmp_hdr_len));
  while (queue->tmp_hdr_len < QUIC_HS_HDR_SIZE && (data + len) < data_end) {
    queue->tmp_hdr[queue->tmp_hdr_len++] = data[len++];
  }
  return len;
}

/**
 * \brief Checks whether the last message header is valid.
 */
static inline int quic_input_validate_last_hdr(mbedtls_ssl_context *ssl,
    quic_input_queue *queue) {
  MBEDTLS_ASSERT(queue->tmp_hdr_len == QUIC_HS_HDR_SIZE);

  /* Extract the message's type from the temporary message header */
  char hs_msg_type = queue->tmp_hdr[0];

  if (!quic_input_hs_type_valid(hs_msg_type)) {
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "quic_input_validate_last_hdr: FATAL ERR "
          "invalid handshake message type %c", hs_msg_type));
    return MBEDTLS_ERR_SSL_BAD_HS_UNKNOWN_MSG;
  }

  const size_t hs_msg_size = hs_msg_body_size(queue->tmp_hdr) + QUIC_HS_HDR_SIZE;

  if (hs_msg_size > MBEDTLS_SSL_MAX_CONTENT_LEN) {
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "quic_input_validate_last_hdr: FATAL ERR "
          "handshake message size %u exceeds max %u",
          hs_msg_type, MBEDTLS_SSL_MAX_CONTENT_LEN));
    return MBEDTLS_ERR_SSL_INVALID_RECORD;
  }

  return 0;
}

static inline void quic_input_reset_last_msg_hdr(mbedtls_ssl_context *ssl,
    quic_input_queue *queue) {
  queue->tmp_hdr_len = 0;
}

/**
 * \brief Uses the last message header to allocate an element in the queue.
 */
int quic_input_allocate_msg(mbedtls_ssl_context *ssl, quic_input_queue *queue);


#ifdef __cplusplus
} // extern "C"
#endif

#endif /* MBEDTLS_SSL_PROTO_QUIC */


#endif /* MBEDTLS_SSL_QIUC_INTERNAL_H */
