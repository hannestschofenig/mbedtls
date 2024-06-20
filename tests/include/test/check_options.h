/**
 * Below part is to fix different options
 * should be removed after merged
 **/
#if defined(MBEDTLS_TMP_TEST_CASE_1)
        // issue #238
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #undef MBEDTLS_SSL_PROTO_TLS1_2
        #undef MBEDTLS_DISABLE_NONBLOCK_IO
        #undef MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_2)
        // issue not created
        #undef MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #undef MBEDTLS_DISABLE_NONBLOCK_IO
        #undef MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_3)
        // issue not created
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #undef MBEDTLS_DISABLE_NONBLOCK_IO
        #undef MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_5)
        // issue not created
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #undef MBEDTLS_SSL_PROTO_TLS1_2
        #define MBEDTLS_DISABLE_NONBLOCK_IO
        #undef MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_6)
        // issue #298
        #undef MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #define MBEDTLS_DISABLE_NONBLOCK_IO
        #undef MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_7)
        // issue #297
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #define MBEDTLS_DISABLE_NONBLOCK_IO
        #undef MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_9)
        // issue not created
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #undef MBEDTLS_SSL_PROTO_TLS1_2
        #undef MBEDTLS_DISABLE_NONBLOCK_IO
        #define MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_10)
        // issue not created
        #undef MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #undef MBEDTLS_DISABLE_NONBLOCK_IO
        #define MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_11)
        // issue not created
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #undef MBEDTLS_DISABLE_NONBLOCK_IO
        #define MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_13)
        // issue not created
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #undef MBEDTLS_SSL_PROTO_TLS1_2
        #define MBEDTLS_DISABLE_NONBLOCK_IO
        #define MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_14)
        // issue not created
        #undef MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #define MBEDTLS_DISABLE_NONBLOCK_IO
        #define MBEDTLS_SSL_USE_MPS
#endif

#if defined(MBEDTLS_TMP_TEST_CASE_15)
        // issue not created
        #define MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL
        #define MBEDTLS_SSL_PROTO_TLS1_2
        #define MBEDTLS_DISABLE_NONBLOCK_IO
        #define MBEDTLS_SSL_USE_MPS
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#undef MBEDTLS_SSL_TLS13_COMPATIBILITY_MODE
#endif


/**
 * above part is to fix different options
 * should be removed after merged
 **/