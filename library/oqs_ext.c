#include "oqs_ext.h"

static const mbedtls_kem_info kem_list[] =
{
    { GROUPID_bikel1, OQS_KEM_alg_bikel1 },
    { GROUPID_bikel3, OQS_KEM_alg_bikel3 },
    { GROUPID_hqc128, OQS_KEM_alg_hqc128 },
    { GROUPID_hqc192, OQS_KEM_alg_hqc192 },
    { GROUPID_hqc256, OQS_KEM_alg_hqc256 },
    { GROUPID_kyber512, OQS_KEM_alg_kyber512 },
    { GROUPID_kyber768, OQS_KEM_alg_kyber768 },
    { GROUPID_kyber1024, OQS_KEM_alg_kyber1024 },
    { GROUPID_kyber90s512, OQS_KEM_alg_kyber90s512 },
    { GROUPID_kyber90s768, OQS_KEM_alg_kyber90s768 },
    { GROUPID_kyber90s1024, OQS_KEM_alg_kyber90s1024 },
    { GROUPID_ntru_hps2048509, OQS_KEM_alg_ntru_hps2048509 },
    { GROUPID_ntru_hps2048677, OQS_KEM_alg_ntru_hps2048677 },
    { GROUPID_ntru_hps4096821, OQS_KEM_alg_ntru_hps4096821 },
    { GROUPID_ntruprime_ntru_hrss701, OQS_KEM_alg_ntruprime_ntru_hrss701 },
    { GROUPID_ntruprime_ntrulpr653, OQS_KEM_alg_ntruprime_ntrulpr653 },
    { GROUPID_ntruprime_ntrulpr761, OQS_KEM_alg_ntruprime_ntrulpr761 },
    { GROUPID_ntruprime_ntrulpr857, OQS_KEM_alg_ntruprime_ntrulpr857 },
    { GROUPID_ntruprime_sntrup653, OQS_KEM_alg_ntruprime_sntrup653 },
    { GROUPID_ntruprime_sntrup761, OQS_KEM_alg_ntruprime_sntrup761 },
    { GROUPID_ntruprime_sntrup857, OQS_KEM_alg_ntruprime_sntrup857 },
    { GROUPID_saber_lightsaber, OQS_KEM_alg_saber_lightsaber },
    { GROUPID_saber_saber, OQS_KEM_alg_saber_saber },
    { GROUPID_saber_firesaber, OQS_KEM_alg_saber_firesaber },
    { GROUPID_frodokem_640_aes, OQS_KEM_alg_frodokem_640_aes },
    { GROUPID_frodokem_640_shake, OQS_KEM_alg_frodokem_640_shake },
    { GROUPID_frodokem_976_aes, OQS_KEM_alg_frodokem_976_aes },
    { GROUPID_frodokem_976_shake, OQS_KEM_alg_frodokem_976_shake },
    { GROUPID_frodokem_1344_aes, OQS_KEM_alg_frodokem_1344_aes },
    { GROUPID_frodokem_1344_shake, OQS_KEM_alg_frodokem_1344_shake },
    { GROUPID_sidh_p434, OQS_KEM_alg_sidh_p434 },
    { GROUPID_sidh_p503, OQS_KEM_alg_sidh_p503 },
    { GROUPID_sidh_p610, OQS_KEM_alg_sidh_p610 },
    { GROUPID_sidh_p751, OQS_KEM_alg_sidh_p751 },
    { GROUPID_sike_p434, OQS_KEM_alg_sike_p434 },
    { GROUPID_sike_p503, OQS_KEM_alg_sike_p503 },
    { GROUPID_sike_p610, OQS_KEM_alg_sike_p610 },
    { GROUPID_sike_p751, OQS_KEM_alg_sike_p751 },
    { 0, 0 },
};

const mbedtls_kem_info *mbedtls_get_kem_list( void )
{
    return( kem_list );
}

const mbedtls_kem_info *mbedtls_kem_info_from_tls_id( uint16_t tls_id )
{
    const mbedtls_kem_info *kem_info;

    for( kem_info = get_kem_list();
         kem_info->tls_id != 0;
         kem_info++ )
    {
        if( kem_info->tls_id == tls_id && OQS_KEM_alg_is_enabled( kem_info->name ))
            return( kem_info );
    }

    return( NULL );
}

static OQS_KEM *setup_kem( uint16_t group_id )
{
    const mbedtls_kem_info *kem_info;

    if ( kem_info = mbedtls_kem_info_from_tls_id( group_id ) != 0 ) {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Given group_id not availiable" ) );
        return( NULL );
    }
    return OQS_new( kem_info->name );
}

void mbedtls_oqs_kem_init( mbedtls_oqs_kem_ctx *ctx )
{
    ctx->kem = NULL;
    ctx->public_key = NULL:
    ctx->secret_key = NULL:
    ctx->ciphertext = NULL:
    ctx->shared_secret = NULL:
}

int mbedtls_oqs_kem_setup( mbedtls_oqs_kem_ctx *ctx, uint16_t tls_id )
{
    if( !( ctx->kem = setup_kem(tls_id) ) )
        return( MBEDTLS_ERR_PQC_KEM_SETUP_FAILED );

    if( ( ctx->public_key = mbedtls_alloc( 1, ctx->kem->length_public_key ) == NULL ) ||
        ( ctx->serect_key = mbedtls_alloc( 1, ctx->kem->length_serect_key ) == NULL ) ||
        ( ctx->ciphertext = mbedtls_alloc( 1, ctx->kem->length_ciphertext ) == NULL ) ||
        ( ctx->shared_secret = mbedtls_alloc( 1, ctx->kem->length_shared_secret ) == NULL ) )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    return( 0 );
}

int mbedtls_copy_byte_string( unsigned char *in,  unsigned char *inlen,
                              unsigned char *out, size_t outlen )
{
    if ( inlen <= outlen )
    {
        memcpy( out, in, inlen );
        return( 0 );
    }
    return ( MBEDTLS_ERR_PQC_BUFFER_TOO_SMALL );
}

void mbedtls_oqs_kem_free( mbedtls_oqs_kem_context *ctx )
{
    if( ctx->kem )
        OQS_KEM_free(ctx->kem);
    if( ctx->public_key )
        mbedtls_free(ctx->public_key);
    if( ctx->secret_key )
        mbedtls_free(ctx->secret_key);
    if( ctx->ciphertext )
        mbedtls_free(ctx->ciphertext);
    if( ctx->shared_secret )
        mbedtls_free(ctx->shared_secret);
}
