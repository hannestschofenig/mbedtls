
#ifndef MBEDTLS_SSL_QIUC_H
#define MBEDTLS_SSL_QIUC_H

#if defined(MBEDTLS_SSL_PROTO_QUIC)

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_session  mbedtls_ssl_session;
typedef struct mbedtls_quic_input  mbedtls_quic_input;
typedef struct quic_input_msg      quic_input_msg;
typedef struct quic_input_queue    quic_input_queue;

/**
 * \brief Encryption level used by the QUIC callbacks.
 */
typedef enum {
  MBEDTLS_SSL_CRYPTO_LEVEL_INITIAL,
  MBEDTLS_SSL_CRYPTO_LEVEL_HANDSHAKE,
  MBEDTLS_SSL_CRYPTO_LEVEL_APPLICATION,
  MBEDTLS_SSL_CRYPTO_LEVEL_EARLY_DATA,
  MBEDTLS_SSL_CRYPTO_LEVEL_MAX,
} mbedtls_ssl_crypto_level ;

/**
 * \brief Array of incoming queues - the top level structure.
 */
struct mbedtls_quic_input {
  // Array of queues, one for each of Initial, Handshake and Application levels.
  // We can not inline the storage for the queues inside
  // `mbedtls_quic_input`, since `sizeof(quic_input_queue)` is only known in
  // "mbedtls/quic_internal.h"
  quic_input_queue *queues_;
};


/**
 * \brief Send handshake data to mbedtls.
 *
 * This is the top level `provide_data` function. It dispatches
 * the incoming data to the appropriate queue, and invokes
 * `quic_input_provide_data` to do the heavy lifting.
 *
 * \param ssl SSL context.
 * \param level encryption level.
 * \param data handshake data.
 * \param len data length.
 */
int mbedtls_quic_input_provide_data(
    mbedtls_ssl_context      *ssl,
    mbedtls_ssl_crypto_level  level,
    const uint8_t            *data,
    size_t                    len);

/**
 * \brief Init the QUIC input subsystem.
 *
 * \param ssl     SSL context.
 * \param input   QUIC input structure.
 */
void mbedtls_quic_input_init(mbedtls_ssl_context *ssl, mbedtls_quic_input  *input);

/**
 * \brief Setup the QUIC input subsystem.
 *
 * \param ssl     SSL context.
 * \param input   QUIC input structure.
 */
int mbedtls_quic_input_setup(mbedtls_ssl_context *ssl, mbedtls_quic_input  *input);

/**
 * \brief Deallocate the QUIC input subsystem.
 *
 * Deallocates any messages that have not been consumed. In the happy path
 * scenario every handshake message is being fed to the state machine,
 * but in case of an aborted handshake, pending messages have to be cleaned up.
 *
 * \param ssl     SSL context.
 * \param input   QUIC input structure.
 */
void mbedtls_quic_input_free(mbedtls_ssl_context *ssl, mbedtls_quic_input *input);

/**
 * \brief Check whether a message is available for reading.
 *
 * This routine is used to check whether the input subsystem has enough data
 * for the next state.
 *
 * It's second duty is to allow distinguishing between multiple potential messages,
 * e.g. CERTIFICATE_REQUEST, CERTIFICATE or FINISHED, which can all follow the
 * ENCRYPTED_EXTENSIONS.
 *
 * \param ssl        SSL context.
 * \param level      the encryption level.
 * \param otype      type of the next available handshake message (only if a message is avaiable).
 * \param osize      size of the next available handshake message (only if a message is avaiable).
 * \param olen       length of the next available handshake message (only if a message is avaiable).
 *
 * \return 0 if a message is available to be read, MBEDTLS_ERR_SSL_WANT_READ otherwise.
 */
int mbedtls_quic_input_peek(
    mbedtls_ssl_context       *ssl,
    mbedtls_ssl_crypto_level   level,
    uint8_t                   *otype,
    size_t                    *osize,
    size_t                    *olen);

/**
 * \brief Get a message from the appropriate queue, and remove it from the input system.
 *
 * \param ssl        SSL context.
 * \param level      the encryption level.
 * \param data       Buffer to which the data will be copied.
 * \param datalen    Size of the data buffer.
 *
 * \return number of bytes written into the data buffer, or a negative error value.
 */
int mbedtls_quic_input_read(
    mbedtls_ssl_context       *ssl,
    mbedtls_ssl_crypto_level  level,
    uint8_t                  *data,
    size_t                    datalen);

/**
 * \brief Callback to set the encryption secrets for a level.
 *
 * \param param the context parameter provided via `mbedtls_ssl_set_hs_quic_method`.
 * \param level the corresponding crypto level.
 * \param read_secret secret used for the incoming data, NULL if not applicaable.
 * \param write_secret secret used for the outgoing data, NULL if not applicable.
 * \param len length of the secret buffers.
 */
typedef int mbedtls_quic_set_encryption_secrets_t(
    void                     *param,
    mbedtls_ssl_crypto_level  level,
    const uint8_t            *read_secret,
    const uint8_t            *write_secret,
    size_t                    len);

/**
 * \brief Callback to deliver the handshake data to the remote endpoint.
 *
 * \param param the context parameter provided via `mbedtls_ssl_set_hs_quic_method`.
 * \param level the corresponding crypto level.
 * \param data handshake data to be delivered to the remote endpoint.
 * \param len length of the handshake data.
 */
typedef int mbedtls_quic_add_handshake_data_t(
    void                     *param,
    mbedtls_ssl_crypto_level  level,
    const uint8_t            *data,
    size_t                    len);

/**
 * \brief Callback to deliver a TLS alert to the remote endpoint.
 *
 * \param param the context parameter provided via `mbedtls_ssl_set_hs_quic_method`.
 * \param level the corresponding crypto level.
 * \param alert TLS alert code to be delivered.
 */
typedef int mbedtls_quic_send_alert_t(
    void                     *param,
    mbedtls_ssl_crypto_level   level,
    uint8_t                    alert);

/**
 * \brief Callback to notify the MNS on a new TLS session.
 *
 * \param param the context parameter provided via `mbedtls_ssl_set_hs_quic_method`.
 * \param session_ticket TLS session ticket to be transfered to caller.
 */
typedef void mbedtls_quic_process_new_session_t(
    void                     *param,
    mbedtls_ssl_session       *session_ticket);
/**
 * \brief QUIC method callbacks.
 */
typedef struct mbedtls_quic_method {
    mbedtls_quic_set_encryption_secrets_t  *set_encryption_secrets;
    mbedtls_quic_add_handshake_data_t      *add_handshake_data;
    mbedtls_quic_send_alert_t              *send_alert;
    mbedtls_quic_process_new_session_t     *process_new_session;
} mbedtls_quic_method;

/**
 * \brief   Set the QUIC method callbacks.
 *
 * \param ssl            SSL context.
 * \param p_quic_method  parameter (context) shared by BIO callbacks
 * \param quic_method QUIC method callbacks.
 */
void mbedtls_ssl_set_hs_quic_method(mbedtls_ssl_context *ssl,
    void *p_quic_method, mbedtls_quic_method *quic_method);

/**
 * \brief check that the quic_method callbacks can be safely invoked.
 *
 * \param ssl        SSL context.
 */
bool mbedtls_ssl_is_quic_client(mbedtls_ssl_context* ssl);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* MBEDTLS_SSL_PROTO_QUIC */


#endif /* MBEDTLS_SSL_QIUC_H */
