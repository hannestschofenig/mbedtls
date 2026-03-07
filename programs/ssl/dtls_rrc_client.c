/*
 *  DTLS client demo for RRC interop against Californium.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_SSL_CLI_C) ||         \
    !defined(MBEDTLS_TIMING_C) || !defined(MBEDTLS_SSL_PROTO_DTLS) || \
    !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID) ||                        \
    !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID_RRC) ||                    \
    !defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
int main(void)
{
    mbedtls_printf("Required features not enabled.\n");
    mbedtls_exit(0);
}
#else

#include <string.h>

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "6684"

#define READ_TIMEOUT_MS 8000

static int do_request(mbedtls_ssl_context *ssl,
                      const unsigned char *req,
                      size_t req_len,
                      const char *label)
{
    int ret;
    unsigned char buf[2048];
    size_t i;

    mbedtls_printf("  > %s send %u bytes\n", label, (unsigned) req_len);

    do {
        ret = mbedtls_ssl_write(ssl, req, req_len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0) {
        mbedtls_printf("  ! mbedtls_ssl_write failed: -0x%04x\n", (unsigned) -ret);
        return ret;
    }

    do {
        ret = mbedtls_ssl_read(ssl, buf, sizeof(buf));
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret < 0) {
        mbedtls_printf("  ! mbedtls_ssl_read failed: -0x%04x\n", (unsigned) -ret);
        return ret;
    }

    mbedtls_printf("  < %s recv %u bytes: ", label, (unsigned) ret);
    for (i = 0; i < (size_t) ret; i++) {
        mbedtls_printf("%02x", buf[i]);
    }
    mbedtls_printf("\n");

    return 0;
}

int main(void)
{
    int ret = 1;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_timing_delay_context timer;
    unsigned char cid[4] = { 0x01, 0x02, 0x03, 0x04 };

    /* CoAP CON GET /rrc with different MID/token. */
    const unsigned char req1[] = { 0x41, 0x01, 0x10, 0x01, 0x11, 0xb3, 'r', 'r', 'c' };
    const unsigned char req2[] = { 0x41, 0x01, 0x10, 0x02, 0x22, 0xb3, 'r', 'r', 'c' };
    const unsigned char req3[] = { 0x41, 0x01, 0x10, 0x03, 0x33, 0xb3, 'r', 'r', 'c' };
    static const int psk_ciphersuite[] = { MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8, 0 };
    static const unsigned char psk_identity[] = "Client_identity";
    static const unsigned char psk_secret[] = "secretPSK";

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    if (psa_crypto_init() != PSA_SUCCESS) {
        mbedtls_printf("psa_crypto_init failed\n");
        goto exit;
    }

    mbedtls_printf("  . Connecting to udp/%s/%s...\n", SERVER_ADDR, SERVER_PORT);
    if ((ret = mbedtls_net_connect(&server_fd, SERVER_ADDR,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_UDP)) != 0) {
        mbedtls_printf("  ! mbedtls_net_connect failed: %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf("  ! mbedtls_ssl_config_defaults failed: -0x%04x\n", (unsigned) -ret);
        goto exit;
    }

    mbedtls_ssl_conf_read_timeout(&conf, READ_TIMEOUT_MS);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_ciphersuites(&conf, psk_ciphersuite);
    if ((ret = mbedtls_ssl_conf_psk(&conf, psk_secret, sizeof(psk_secret) - 1,
                                    psk_identity, sizeof(psk_identity) - 1)) != 0) {
        mbedtls_printf("  ! mbedtls_ssl_conf_psk failed: -0x%04x\n", (unsigned) -ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_conf_cid(&conf, sizeof(cid),
                                    MBEDTLS_SSL_UNEXPECTED_CID_IGNORE)) != 0) {
        mbedtls_printf("  ! mbedtls_ssl_conf_cid failed: -0x%04x\n", (unsigned) -ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        mbedtls_printf("  ! mbedtls_ssl_setup failed: -0x%04x\n", (unsigned) -ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_cid(&ssl, MBEDTLS_SSL_CID_ENABLED,
                                   cid, sizeof(cid))) != 0) {
        mbedtls_printf("  ! mbedtls_ssl_set_cid failed: -0x%04x\n", (unsigned) -ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    mbedtls_printf("  . Performing DTLS handshake...\n");
    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret != 0) {
        mbedtls_printf("  ! mbedtls_ssl_handshake failed: -0x%04x\n", (unsigned) -ret);
        goto exit;
    }

    if ((ret = do_request(&ssl, req1, sizeof(req1), "req1")) != 0) {
        goto exit;
    }

    mbedtls_printf("  . Waiting 7s to expire NAT mapping...\n");
    mbedtls_net_usleep(7000000);

    if ((ret = do_request(&ssl, req2, sizeof(req2), "req2")) != 0) {
        goto exit;
    }

    if ((ret = do_request(&ssl, req3, sizeof(req3), "req3")) != 0) {
        goto exit;
    }

    ret = 0;

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_psa_crypto_free();
    return ret;
}
#endif
