#ifdef USE_DTLS13

#include <wolfssl/ssl.h>
#include <sock_tls.h>

#include <inttypes.h>

#include <net/sock/udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define SERVER_PORT 11111
#define DEBUG 1
extern const unsigned char server_cert[];
extern const unsigned char server_key[];
extern unsigned int server_cert_len;
extern unsigned int server_key_len;

// xxd -i wolfssl/certs/ecc-keyPub.der
unsigned char server_rpk[] = {
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00, 0x04, 0xbb, 0x33, 0xac, 0x4c, 0x27, 0x50, 0x4a, 0xc6, 0x4a,
  0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f, 0x36, 0xdb, 0x72, 0x2d, 0xce, 0x94,
  0xea, 0x2b, 0xfa, 0xcb, 0x20, 0x09, 0x39, 0x2c, 0x16, 0xe8, 0x61, 0x02,
  0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93, 0x9a, 0x31, 0x5b, 0x97, 0x92, 0x21,
  0x7f, 0xf0, 0xcf, 0x18, 0xda, 0x91, 0x11, 0x02, 0x34, 0x86, 0xe8, 0x20,
  0x58, 0x33, 0x0b, 0x80, 0x34, 0x89, 0xd8
};
unsigned int server_rpk_len = 91;
// xxd -i wolfssl/certs/ecc-key.der
unsigned char server_rpk_priv[] = {
  0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x45, 0xb6, 0x69, 0x02, 0x73,
  0x9c, 0x6c, 0x85, 0xa1, 0x38, 0x5b, 0x72, 0xe8, 0xe8, 0xc7, 0xac, 0xc4,
  0x03, 0x8d, 0x53, 0x35, 0x04, 0xfa, 0x6c, 0x28, 0xdc, 0x34, 0x8d, 0xe1,
  0xa8, 0x09, 0x8c, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xbb, 0x33, 0xac,
  0x4c, 0x27, 0x50, 0x4a, 0xc6, 0x4a, 0xa5, 0x04, 0xc3, 0x3c, 0xde, 0x9f,
  0x36, 0xdb, 0x72, 0x2d, 0xce, 0x94, 0xea, 0x2b, 0xfa, 0xcb, 0x20, 0x09,
  0x39, 0x2c, 0x16, 0xe8, 0x61, 0x02, 0xe9, 0xaf, 0x4d, 0xd3, 0x02, 0x93,
  0x9a, 0x31, 0x5b, 0x97, 0x92, 0x21, 0x7f, 0xf0, 0xcf, 0x18, 0xda, 0x91,
  0x11, 0x02, 0x34, 0x86, 0xe8, 0x20, 0x58, 0x33, 0x0b, 0x80, 0x34, 0x89,
  0xd8
};
unsigned int server_rpk_priv_len = 121;

static sock_tls_t skv;
static sock_tls_t *sk = &skv;

static const char Test_dtls_string[] = "DTLS OK!";

#define APP_DTLS_BUF_SIZE 64

int dtls_server(int argc, char **argv)
{
    do {
        char buf[APP_DTLS_BUF_SIZE];
        int ret;
        sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
        local.port = SERVER_PORT;

        (void)argc;
        (void)argv;

        // if (sock_dtls_create(sk, &local, NULL, 0, wolfDTLSv1_2_server_method()) != 0) {
        if (sock_dtls_create(sk, &local, NULL, 0, wolfDTLSv1_3_server_method()) != 0) {
            LOG_ERROR("ERROR: Unable to create DTLS sock\n");
            return -1;
        }

        // /* Load certificate file for the DTLS server */
        // if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, server_cert,
        //             server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
        // {
        //     LOG_ERROR("Failed to load certificate from memory.\n");
        //     return -1;
        // }

        // /* Load the private key */
        // if (wolfSSL_CTX_use_PrivateKey_buffer(sk->ctx, server_key,
        //             server_key_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
        // {
        //     LOG_ERROR("Failed to load private key from memory.\n");
        //     return -1;
        // }

        // using RPK
        wolfSSL_CTX_set_verify(sk->ctx, WOLFSSL_VERIFY_NONE, 0);

        /* Load RPK for the DTLS server */
        if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, server_rpk,
                    server_rpk_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
        {
            LOG_ERROR("Error loading cert buffer\n");
            return -1;
        }

        /* Load the private key */
        if (wolfSSL_CTX_use_PrivateKey_buffer(sk->ctx, server_rpk_priv,
                    server_rpk_priv_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
        {
            LOG_ERROR("Failed to load private key from memory.\n");
            return -1;
        }

        /* Create the DTLS session */
        ret = sock_dtls_session_create(sk);
        if (ret < 0)
        {
            LOG_ERROR("Failed to create DTLS session (err: %s)\n", strerror(-ret));
            return -1;
        }

        char ctype[] = {WOLFSSL_CERT_TYPE_RPK};
        char stype[] = {WOLFSSL_CERT_TYPE_RPK};
        // char stype[] = {WOLFSSL_CERT_TYPE_X509};
        if (wolfSSL_set_client_cert_type(sk->ssl, ctype, 1) != SSL_SUCCESS)
        {
            LOG_ERROR("Failed to set client cert type.\n");
            return -1;
        }
        if (wolfSSL_set_server_cert_type(sk->ssl, stype, 1) != SSL_SUCCESS)
        {
            LOG_ERROR("Failed to set server cert type.\n");
            return -1;
        }

        LOG_DEBUG("Listening on %d\n", SERVER_PORT);
        while(1) {
            /* Wait until a new client connects */
            ret = wolfSSL_accept(sk->ssl);
            if (ret != SSL_SUCCESS) {
                if (wolfSSL_get_error(sk->ssl, ret) != WOLFSSL_ERROR_WANT_READ) {
                    sock_dtls_session_destroy(sk);
                    if (sock_dtls_session_create(sk) < 0)
                        return -1;
                }
                continue;
            }
            LOG_INFO("DTLS: end handshake ok.\n");

            /* Wait until data is received */
            LOG_DEBUG("Connection accepted\n");
            ret = wolfSSL_read(sk->ssl, buf, APP_DTLS_BUF_SIZE);
            if (ret > 0) {
                buf[ret] = (char)0;
                LOG_DEBUG("Received '%s'\n", buf);
            }

            /* Send reply */
            LOG_DEBUG("Sending 'DTLS OK'...\n");
            wolfSSL_write(sk->ssl, Test_dtls_string, sizeof(Test_dtls_string));

            /* Cleanup/shutdown */
            LOG_DEBUG("Closing connection.\n");
            sock_dtls_session_destroy(sk);
            sock_dtls_close(sk);
            wolfSSL_free(sk->ssl);
            wolfSSL_CTX_free(sk->ctx);
            LOG_INFO("Connection closed ok.\n");
            break;
        }
    } while (1);
    // } while (0);
    return 0;
}

#endif /* USE_DTLS13 */