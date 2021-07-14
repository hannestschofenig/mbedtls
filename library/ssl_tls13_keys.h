/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
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
 */
#if !defined(MBEDTLS_SSL_TLS1_3_KEYS_H)
#define MBEDTLS_SSL_TLS1_3_KEYS_H

#include "mbedtls/ssl_internal.h"

/* The maximum size of the intermediate key material.
 * The IKM can be a
 * - 0-string of length corresponding to the size of the
 *   underlying hash function, and hence can be bounded
 *   in size by MBEDTLS_MD_MAX_SIZE.
 * - the PSK, which is bounded in size by MBEDTLS_PREMASTER_SIZE
 * - the (EC)DHE, which is bounded in size by MBEDTLS_PREMASTER_SIZE
 */
#define MBEDTLS_SSL_TLS1_3_MAX_IKM_SIZE \
    ( MBEDTLS_PREMASTER_SIZE > MBEDTLS_MD_MAX_SIZE ? \
      MBEDTLS_PREMASTER_SIZE : MBEDTLS_MD_MAX_SIZE )

/* This requires MBEDTLS_SSL_TLS1_3_LABEL( idx, name, string ) to be defined at
 * the point of use. See e.g. the definition of mbedtls_ssl_tls1_3_labels_union
 * below. */
#define MBEDTLS_SSL_TLS1_3_LABEL_LIST                                                 \
    MBEDTLS_SSL_TLS1_3_LABEL( finished    , "finished"                              ) \
    MBEDTLS_SSL_TLS1_3_LABEL( resumption  , "resumption"                            ) \
    MBEDTLS_SSL_TLS1_3_LABEL( traffic_upd , "traffic upd"                           ) \
    MBEDTLS_SSL_TLS1_3_LABEL( exporter    , "exporter"                              ) \
    MBEDTLS_SSL_TLS1_3_LABEL( key         , "key"                                   ) \
    MBEDTLS_SSL_TLS1_3_LABEL( iv          , "iv"                                    ) \
    MBEDTLS_SSL_TLS1_3_LABEL( c_hs_traffic, "c hs traffic"                          ) \
    MBEDTLS_SSL_TLS1_3_LABEL( c_ap_traffic, "c ap traffic"                          ) \
    MBEDTLS_SSL_TLS1_3_LABEL( c_e_traffic , "c e traffic"                           ) \
    MBEDTLS_SSL_TLS1_3_LABEL( s_hs_traffic, "s hs traffic"                          ) \
    MBEDTLS_SSL_TLS1_3_LABEL( s_ap_traffic, "s ap traffic"                          ) \
    MBEDTLS_SSL_TLS1_3_LABEL( s_e_traffic , "s e traffic"                           ) \
    MBEDTLS_SSL_TLS1_3_LABEL( e_exp_master, "e exp master"                          ) \
    MBEDTLS_SSL_TLS1_3_LABEL( res_master  , "res master"                            ) \
    MBEDTLS_SSL_TLS1_3_LABEL( exp_master  , "exp master"                            ) \
    MBEDTLS_SSL_TLS1_3_LABEL( ext_binder  , "ext binder"                            ) \
    MBEDTLS_SSL_TLS1_3_LABEL( res_binder  , "res binder"                            ) \
    MBEDTLS_SSL_TLS1_3_LABEL( derived     , "derived"                               ) \
    MBEDTLS_SSL_TLS1_3_LABEL( client_cv   , "TLS 1.3, client CertificateVerify"     ) \
    MBEDTLS_SSL_TLS1_3_LABEL( server_cv   , "TLS 1.3, server CertificateVerify"     )

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    const unsigned char name    [ sizeof(string) - 1 ];

union mbedtls_ssl_tls1_3_labels_union
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
struct mbedtls_ssl_tls1_3_labels_struct
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
#undef MBEDTLS_SSL_TLS1_3_LABEL

extern const struct mbedtls_ssl_tls1_3_labels_struct mbedtls_ssl_tls1_3_labels;

#define MBEDTLS_SSL_TLS1_3_LBL_LEN( LABEL )  \
    sizeof(mbedtls_ssl_tls1_3_labels.LABEL)

#define MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( LABEL )  \
    mbedtls_ssl_tls1_3_labels.LABEL,              \
    MBEDTLS_SSL_TLS1_3_LBL_LEN( LABEL )

#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN  \
    sizeof( union mbedtls_ssl_tls1_3_labels_union )

/* The maximum length of HKDF contexts used in the TLS 1.3 standard.
 * Since contexts are always hashes of message transcripts, this can
 * be approximated from above by the maximum hash size. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN  \
    MBEDTLS_MD_MAX_SIZE

/* Maximum desired length for expanded key material generated
 * by HKDF-Expand-Label.
 *
 * Warning: If this ever needs to be increased, the implementation
 * ssl_tls1_3_hkdf_encode_label() in ssl_tls13_keys.c needs to be
 * adjusted since it currently assumes that HKDF key expansion
 * is never used with more than 255 Bytes of output. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN 255

/* Macro to express the length of the verify structure length.
 *
 * The structure is computed per TLS 1.3 specification as:
 *   - 64 bytes of octet 32,
 *   - 33 bytes for the context string
 *        (which is either "TLS 1.3, client CertificateVerify"
 *         or "TLS 1.3, server CertificateVerify"),
 *   - 1 byte for the octet 0x0, which servers as a separator,
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
#define MBEDTLS_SSL_VERIFY_STRUCT_MAX_SIZE  ( 64 +                 \
                                              33 +                 \
                                               1 +                 \
                                              MBEDTLS_MD_MAX_SIZE  \
                                            )

/**
 * \brief           The \c HKDF-Expand-Label function from
 *                  the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *                  HKDF-Expand-Label( Secret, Label, Context, Length ) =
 *                       HKDF-Expand( Secret, HkdfLabel, Length )
 * </tt>
 *
 * \param hash_alg  The identifier for the hash algorithm to use.
 * \param secret    The \c Secret argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p slen Bytes.
 * \param slen      The length of \p secret in Bytes.
 * \param label     The \c Label argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p llen Bytes.
 * \param llen      The length of \p label in Bytes.
 * \param ctx       The \c Context argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p clen Bytes.
 * \param clen      The length of \p context in Bytes.
 * \param buf       The destination buffer to hold the expanded secret.
 *                  This must be a writable buffer of length \p blen Bytes.
 * \param blen      The desired size of the expanded secret in Bytes.
 *
 * \returns         \c 0 on success.
 * \return          A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen );

/**
 * \brief           This function is part of the TLS 1.3 key schedule.
 *                  It extracts key and IV for the actual client/server traffic
 *                  from the client/server traffic secrets.
 *
 * From RFC 8446:
 *
 * <tt>
 *   [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
 *   [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)*
 * </tt>
 *
 * \param hash_alg      The identifier for the hash algorithm to be used
 *                      for the HKDF-based expansion of the secret.
 * \param client_secret The client traffic secret.
 *                      This must be a readable buffer of size \p slen Bytes
 * \param server_secret The server traffic secret.
 *                      This must be a readable buffer of size \p slen Bytes
 * \param slen          Length of the secrets \p client_secret and
 *                      \p server_secret in Bytes.
 * \param key_len       The desired length of the key to be extracted in Bytes.
 * \param iv_len        The desired length of the IV to be extracted in Bytes.
 * \param keys          The address of the structure holding the generated
 *                      keys and IVs.
 *
 * \returns             \c 0 on success.
 * \returns             A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys );


#define MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED 0
#define MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED   1

/**
 * \brief The \c Derive-Secret function from the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *   Derive-Secret( Secret, Label, Messages ) =
 *      HKDF-Expand-Label( Secret, Label,
 *                         Hash( Messages ),
 *                         Hash.Length ) )
 * </tt>
 *
 * \param hash_alg   The identifier for the hash function used for the
 *                   applications of HKDF.
 * \param secret     The \c Secret argument to the \c Derive-Secret function.
 *                   This must be a readable buffer of length \p slen Bytes.
 * \param slen       The length of \p secret in Bytes.
 * \param label      The \c Label argument to the \c Derive-Secret function.
 *                   This must be a readable buffer of length \p llen Bytes.
 * \param llen       The length of \p label in Bytes.
 * \param ctx        The hash of the \c Messages argument to the
 *                   \c Derive-Secret function, or the \c Messages argument
 *                   itself, depending on \p context_already_hashed.
 * \param clen       The length of \p hash.
 * \param ctx_hashed This indicates whether the \p ctx contains the hash of
 *                   the \c Messages argument in the application of the
 *                   \c Derive-Secret function
 *                   (value MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED), or whether
 *                   it is the content of \c Messages itself, in which case
 *                   the function takes care of the hashing
 *                   (value MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED).
 * \param dstbuf     The target buffer to write the output of
 *                   \c Derive-Secret to. This must be a writable buffer of
 *                   size \p buflen Bytes.
 * \param buflen     The length of \p dstbuf in Bytes.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t buflen );

/**
 * \brief Derive TLS 1.3 early data key material from early secret.
 *
 *        This is a small wrapper invoking mbedtls_ssl_tls1_3_derive_secret()
 *        with the appropriate labels.
 *
 * \param md_type      The hash algorithm associated with the PSK for which
 *                     early data key material is being derived.
 * \param early_secret The early secret from which the early data key material
 *                     should be derived. This must be a readable buffer whose
 *                     length is the digest size of the hash algorithm
 *                     represented by \p md_size.
 * \param transcript   The transcript of the handshake so far, calculated with
 *                     respect to \p md_type. This must be a readable buffer
 *                     whose length is the digest size of the hash algorithm
 *                     represented by \p md_size.
 * \param derived_early_secrets The address of the structure in which to store
 *                              the early data key material.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_derive_early_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *early_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_early_secrets *derived_early_secrets );

/**
 * \brief Derive TLS 1.3 handshake key material from handshake secret.
 *
 *        This is a small wrapper invoking mbedtls_ssl_tls1_3_derive_secret()
 *        with the appropriate labels.
 *
 * \param md_type           The hash algorithm used in the handshake for which
 *                          key material is being derived.
 * \param handshake_secret  The handshake secret from which the handshake key
 *                          material should be derived. This must be a readable
 *                          buffer whose length is the digest size of the hash
 *                          algorithm represented by \p md_size.
 * \param transcript        The transcript of the handshake so far, calculated
 *                          with respect to \p md_type. This must be a readable
 *                          buffer whose length is the digest size of the hash
 *                          algorithm represented by \p md_size.
 * \param derived_handshake_secrets The address of the structure in which to
 *                                  store the handshake key material.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_derive_handshake_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *handshake_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_handshake_secrets *derived_handshake_secrets );

/**
 * \brief Derive TLS 1.3 application key material from master secret.
 *
 *        This is a small wrapper invoking mbedtls_ssl_tls1_3_derive_secret()
 *        with the appropriate labels.
 *
 * \param md_type           The hash algorithm used in the application for which
 *                          key material is being derived.
 * \param master_secret     The master secret from which the application key
 *                          material should be derived. This must be a readable
 *                          buffer whose length is the digest size of the hash
 *                          algorithm represented by \p md_size.
 * \param transcript        The transcript of the application so far, calculated
 *                          with respect to \p md_type. This must be a readable
 *                          buffer whose length is the digest size of the hash
 *                          algorithm represented by \p md_size.
 * \param derived_application_secrets The address of the structure in which to
 *                                    store the application key material.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_derive_application_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *master_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_application_secrets *derived_application_secrets );

#if defined(MBEDTLS_SSL_NEW_SESSION_TICKET)
/**
 * \brief Derive TLS 1.3 resumption master secret.
 *
 *        This is a small wrapper invoking mbedtls_ssl_tls1_3_derive_secret()
 *        with the appropriate label.
 *
 * \param md_type           The hash algorithm used in the application for which
 *                          key material is being derived.
 * \param application_secret The application secret from which the resumption master
 *                          secret should be derived. This must be a readable
 *                          buffer whose length is the digest size of the hash
 *                          algorithm represented by \p md_size.
 * \param transcript        The transcript of the application so far, calculated
 *                          with respect to \p md_type. This must be a readable
 *                          buffer whose length is the digest size of the hash
 *                          algorithm represented by \p md_size.
 * \param transcript_len    The length of \p transcript in Bytes.
 * \param derived_application_secrets The address of the structure in which to
 *                                    store the resumption master secret.
 *
 * \returns        \c 0 on success.
 * \returns        A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_derive_resumption_master_secret(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_application_secrets *derived_application_secrets );
#endif /* MBEDTLS_SSL_NEW_SESSION_TICKET */

/**
 * \brief Compute the next secret in the TLS 1.3 key schedule
 *
 * The TLS 1.3 key schedule proceeds as follows to compute
 * the three main secrets during the handshake: The early
 * secret for early data, the handshake secret for all
 * other encrypted handshake messages, and the master
 * secret for all application traffic.
 *
 * <tt>
 *                    0
 *                    |
 *                    v
 *     PSK ->  HKDF-Extract = Early Secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *  (EC)DHE -> HKDF-Extract = Handshake Secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *     0 -> HKDF-Extract = Master Secret
 * </tt>
 *
 * Each of the three secrets in turn is the basis for further
 * key derivations, such as the derivation of traffic keys and IVs;
 * see e.g. mbedtls_ssl_tls1_3_make_traffic_keys().
 *
 * This function implements one step in this evolution of secrets:
 *
 * <tt>
 *                old_secret
 *                    |
 *                    v
 *     Derive-Secret( ., "derived", "" )
 *                    |
 *                    v
 *     input -> HKDF-Extract = new_secret
 * </tt>
 *
 * \param hash_alg    The identifier for the hash function used for the
 *                    applications of HKDF.
 * \param secret_old  The address of the buffer holding the old secret
 *                    on function entry. If not \c NULL, this must be a
 *                    readable buffer whose size matches the output size
 *                    of the hash function represented by \p hash_alg.
 *                    If \c NULL, an all \c 0 array will be used instead.
 * \param input       The address of the buffer holding the additional
 *                    input for the key derivation (e.g., the PSK or the
 *                    ephemeral (EC)DH secret). If not \c NULL, this must be
 *                    a readable buffer whose size \p input_len Bytes.
 *                    If \c NULL, an all \c 0 array will be used instead.
 * \param input_len   The length of \p input in Bytes. This must not be
 *                    larger than MBEDTLS_SSL_TLS1_3_MAX_IKM_SIZE.
 * \param secret_new  The address of the buffer holding the new secret
 *                    on function exit. This must be a writable buffer
 *                    whose size matches the output size of the hash
 *                    function represented by \p hash_alg.
 *                    This may be the same as \p secret_old.
 *
 * \returns           \c 0 on success.
 * \returns           A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new );

/*
 * TLS 1.3 key schedule evolutions
 *
 *   Early Data -> Handshake -> Application
 *
 * Small wrappers around mbedtls_ssl_tls1_3_evolve_secret().
 */

/**
 * \brief Begin TLS 1.3 key schedule by calculating early secret
 *        from chosen PSK.
 *
 *        The TLS 1.3 key schedule can be viewed as a simple state machine
 *        with states Initial -> Early -> Handshake -> Application, and
 *        this function represents the Initial -> Early transition.
 *
 *        In the early stage, mbedtls_ssl_tls1_3_generate_early_data_keys()
 *        can be used to derive the 0-RTT traffic keys.
 *
 * \param ssl  The SSL context to operate on.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_key_schedule_stage_early_data(
    mbedtls_ssl_context *ssl );

/**
 * \brief Transition into handshake stage of TLS 1.3 key schedule.
 *
 *        The TLS 1.3 key schedule can be viewed as a simple state machine
 *        with states Initial -> Early -> Handshake -> Application, and
 *        this function represents the Early -> Handshake transition.
 *
 *        In the handshake stage, mbedtls_ssl_tls1_3_generate_handshake_keys()
 *        can be used to derive the handshake traffic keys.
 *
 * \param ssl  The SSL context to operate on. This must be in key schedule
 *             stage \c Early.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_key_schedule_stage_handshake(
    mbedtls_ssl_context *ssl );

/**
 * \brief Transition into application stage of TLS 1.3 key schedule.
 *
 *        The TLS 1.3 key schedule can be viewed as a simple state machine
 *        with states Initial -> Early -> Handshake -> Application, and
 *        this function represents the Handshake -> Application transition.
 *
 *        In the handshake stage, mbedtls_ssl_tls1_3_generate_application_keys()
 *        can be used to derive the handshake traffic keys.
 *
 * \param ssl  The SSL context to operate on. This must be in key schedule
 *             stage \c Handshake.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_key_schedule_stage_application(
    mbedtls_ssl_context *ssl );

/*
 * Convenience functions combining
 *
 *    mbedtls_ssl_tls1_3_key_schedule_stage_xxx()
 *
 * with
 *
 *    mbedtls_ssl_tls1_3_make_traffic_keys()
 *
 * Those functions assume that the key schedule has been moved
 * to the correct stage via
 *
 *    mbedtls_ssl_tls1_3_key_schedule_stage_xxx().
 */

/**
 * \brief Compute traffic keys for 0-RTT.
 *
 * \param ssl  The SSL context to operate on. This must be in key schedule stage
 *             \c Early, see mbedtls_ssl_tls1_3_key_schedule_stage_early_data().
 * \param traffic_keys The address at which to store the 0-RTT traffic key
 *                     keys. This must be writable but may be uninitialized.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_generate_early_data_keys(
    mbedtls_ssl_context *ssl, mbedtls_ssl_key_set *traffic_keys );

/**
 * \brief Compute TLS 1.3 handshake traffic keys.
 *
 * \param ssl  The SSL context to operate on. This must be in
 *             key schedule stage \c Handshake, see
 *             mbedtls_ssl_tls1_3_key_schedule_stage_handshake().
 * \param traffic_keys The address at which to store the handshake traffic key
 *                     keys. This must be writable but may be uninitialized.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_generate_handshake_keys(
    mbedtls_ssl_context* ssl, mbedtls_ssl_key_set *traffic_keys );

/**
 * \brief Compute TLS 1.3 application traffic keys.
 *
 * \param ssl  The SSL context to operate on. This must be in
 *             key schedule stage \c Application, see
 *             mbedtls_ssl_tls1_3_key_schedule_stage_application().
 * \param traffic_keys The address at which to store the application traffic key
 *                     keys. This must be writable but may be uninitialized.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_generate_application_keys(
    mbedtls_ssl_context* ssl, mbedtls_ssl_key_set *traffic_keys );

/**
 * \brief Compute TLS 1.3 resumption master secret.
 *
 * \param ssl  The SSL context to operate on. This must be in
 *             key schedule stage \c Application, see
 *             mbedtls_ssl_tls1_3_key_schedule_stage_application().
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_generate_resumption_master_secret(
    mbedtls_ssl_context* ssl );

/**
 * \brief Calculate content of TLS 1.3 Finished message.
 *
 * \param ssl  The SSL context to operate on. This must be in
 *             key schedule stage \c Handshake, see
 *             mbedtls_ssl_tls1_3_key_schedule_stage_application().
 * \param dst        The address at which to write the Finished content.
 * \param dst_len    The size of \p dst in bytes.
 * \param actual_len The address at which to store the amount of data
 *                   actually written to \p dst upon success.
 * \param from       The endpoint the Finished message originates from:
 *                   - #MBEDTLS_SSL_IS_CLIENT for the Client's Finished message
 *                   - #MBEDTLS_SSL_IS_SERVER for the Server's Finished message
 *
 * \note       Both client and server call this function twice, once to
 *             generate their own Finished message, and once to verify the
 *             peer's Finished message.

 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_calc_finished( mbedtls_ssl_context* ssl,
                                      unsigned char* dst,
                                      size_t dst_len,
                                      size_t *actual_len,
                                      int from );

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
/**
 * \brief Calculate a TLS 1.3 PSK binder
 *
 * \param ssl  The SSL context. This is used for debugging only and may
 *             be \c NULL if MBEDTLS_DEBUG_C is disabled.
 * \param psk         The buffer holding the PSK for which to create a binder.
 * \param psk_len     The size of \p psk in bytes.
 * \param md_type     The hash algorithm associated to the PSK \p psk.
 * \param is_external This indicates whether the PSK \p psk is externally
 *                    provisioned or a resumption PSK:
 *                    - \c 1: Externally provisioned PSK
 *                    - \c 0: Resumption PSK
 * \param transcript  The handshake transcript up to the point where the
 *                    PSK binder calculation happens. This must be readable,
 *                    and its size must be equal to the digest size of
 *                    the hash algorithm represented by \p md_type.
 * \param result      The address at which to store the PSK binder on success.
 *                    This must be writable, and its size must be equal to the
 *                    digest size of  the hash algorithm represented by \p md_type.
 *
 * \returns    \c 0 on success.
 * \returns    A negative error code on failure.
 */
int mbedtls_ssl_tls1_3_create_psk_binder( mbedtls_ssl_context *ssl,
                               unsigned char const *psk, size_t psk_len,
                               const mbedtls_md_type_t md_type,
                               int is_external,
                               unsigned char const *transcript,
                               unsigned char *result );
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */

#endif /* MBEDTLS_SSL_TLS1_3_KEYS_H */
