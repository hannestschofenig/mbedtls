#include <oqs/oqs.h>

/*
 * PQC error codes
 */
#define MBEDTLS_ERR_PQC_KEM_SETUP_FAILED                  -0x4E00
/** Destination buffer too small */
#define MBEDTLS_ERR_PQC_BUFFER_TOO_SMALL                  -0x4F00

#define GROUPID_bikel1 0x0238
#define GROUPID_bikel3 0x023b
#define GROUPID_hqc128 0x022c
#define GROUPID_hqc192 0x022d
#define GROUPID_hqc256 0x022e
#define GROUPID_kyber512 0x023a
#define GROUPID_kyber768 0x023c
#define GROUPID_kyber1024 0x023d
#define GROUPID_kyber90s512 0x023e
#define GROUPID_kyber90s768 0x023f
#define GROUPID_kyber90s1024 0x0240
#define GROUPID_ntru_hps2048509 0x0214
#define GROUPID_ntru_hps2048677 0x0215
#define GROUPID_ntru_hps4096821 0x0216
#define GROUPID_ntruprime_ntru_hrss701 0x0217
#define GROUPID_ntruprime_ntrulpr653 0x022f
#define GROUPID_ntruprime_ntrulpr761 0x0230
#define GROUPID_ntruprime_ntrulpr857 0x0231
#define GROUPID_ntruprime_sntrup653 0x0232
#define GROUPID_ntruprime_sntrup761 0x0233
#define GROUPID_ntruprime_sntrup857 0x0234
#define GROUPID_saber_lightsaber 0x0218
#define GROUPID_saber_saber 0x0219
#define GROUPID_saber_firesaber 0x021a
#define GROUPID_frodokem_640_aes 0x0200
#define GROUPID_frodokem_640_shake 0x0201
#define GROUPID_frodokem_976_aes 0x0202
#define GROUPID_frodokem_976_shake 0x0203
#define GROUPID_frodokem_1344_aes 0x0204
#define GROUPID_frodokem_1344_shake 0x0205
#define GROUPID_sidh_p434 0x021b
#define GROUPID_sidh_p503 0x021c
#define GROUPID_sidh_p610 0x021d
#define GROUPID_sidh_p751 0x021e
#define GROUPID_sike_p434 0x021f
#define GROUPID_sike_p503 0x0220
#define GROUPID_sike_p610 0x0221
#define GROUPID_sike_p751 0x0222

/*
 * Lightweight info struct for kem
 */
typedef struct mbedtls_kem_info {
    const uint16_t tls_id;
    const char *name;
} mbedtls_kem_info;

/*
 * Holds libOQS OQS_KEM struct, and additional fields to hold keys
 */
typedef struct mbedtls_oqs_kem_ctx {
    OQS_KEM *kem;
    uint8_t* public_key;
    uint8_t* secret_key;
    uint8_t* ciphertext;
    uint8_t* shared_secret;
} mbedtls_oqs_kem_ctx;


/* TODO NEED TO INTEGRATE LIBOQS ENABLE MACROS TO CONTROL WHAT IS INCLUDED */
/**
 * \brief           Returns supported libOQS KEMs
 *
 * \return          Array of supported mbedtls_kem_info structs
 */
const mbedtls_kem_info *mbedtls_get_kem_list( void );


/* TODO NEED TO INTEGRATE LIBOQS ENABLE MACROS TO CONTROL WHAT IS INCLUDED */
/**
 * \brief           Returns mbedtls_kem_info corresponding to provided
 *                  IANA TLS group id.
 *
 * \return          mbedtls_kem_info if provided id is supported, otherwise
 *                  NULL.
 */
const mbedtls_kem_info *mbedtls_kem_info_from_tls_id( uint16_t tls_id )

/**
 * \brief           This function initialises the provided medtls_oqs_kem_ctx struct.
 *                  This is invoked in ssl_handshake_params_init().
 *
 * \param ctx       mbedtls_oqs_kem_ctx object to initialise.
 */
void mbedtls_oqs_kem_init( mbedtls_oqs_kem_ctx *ctx );

/**
 * \brief           Setups up provided mbedtls_oqs_kem_ctx object with
 *                  provided tls_id.
 *
 * \param ctx       mbedtls_oqs_kem_ctx object to setup.
 *
 * \param tls_id    IANA TLS group id to set the context up with.
 *
 * \note            The key-holding fields of ctx are heap allocated
 *                  according to their corresponding length_* field in
 *                  ctx->kem (ctx->kem->length_public_key informs allocation size of
 *                  ctx->public_key etc.).
 *
 * \return          \c 0 on success.
 * \return          MBEDTLS_ERR_SSL_ALLOC_FAILED if heap allocation fails.
 * \return          MBEDTLS_ERR_PQC_KEM_SETUP_FAILED if kem setup fails.
 */
int mbedtls_oqs_kem_setup( mbedtls_oqs_kem_ctx *ctx, uint16_t tls_id )

/**
 * \brief           This function frees the provided medtls_oqs_kem_ctx struct.
 *                  This is invoked in ssl_handshake_params_free().
 *
 * \param ctx       mbedtls_oqs_kem_ctx object to free.
 */
void mbedtls_oqs_kem_free( mbedtls_oqs_kem_ctx *ctx );
