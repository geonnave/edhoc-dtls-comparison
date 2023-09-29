#ifdef USE_DTLS13

#include <wolfssl/ssl.h>
#include <sock_tls.h>

#include <inttypes.h>

#include <net/sock/udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "dtls_creds.h"

#define SERVER_PORT 11111
#define DEBUG 1

static sock_tls_t skv;
static sock_tls_t *sk = &skv;

#define APP_DTLS_BUF_SIZE 64

#ifdef MODULE_WOLFSSL_STATIC_MEMORY
extern uint8_t wolfssl_general_memory[];
extern size_t wolfssl_general_memory_sz;
extern uint8_t wolfssl_io_memory[];
extern size_t wolfssl_io_memory_sz;
#endif

#ifdef DTLS_MUTUAL_AUTH
static int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    (void)preverify;
    (void)store;
    return 1;
}
#endif

int dtls_server(int argc, char **argv)
{
    do {
        char buf[APP_DTLS_BUF_SIZE];
        int ret;
        sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
        local.port = SERVER_PORT;

        (void)argc;
        (void)argv;

#ifdef MODULE_WOLFSSL_STATIC_MEMORY
        if (sock_dtls_create_static(sk, &local, NULL, 0, wolfDTLSv1_3_server_method_ex,
            wolfssl_general_memory, wolfssl_general_memory_sz, wolfssl_io_memory, wolfssl_io_memory_sz
        ) != 0) {
#else
        if (sock_dtls_create(sk, &local, NULL, 0, wolfDTLSv1_3_server_method()) != 0) {
#endif
            LOG_ERROR("ERROR: Unable to create DTLS sock\n");
            return -1;
        }

#ifdef DTLS_MUTUAL_AUTH
        /* Verify peer, but do not verify CA */
        wolfSSL_CTX_set_verify(sk->ctx, WOLFSSL_VERIFY_PEER, myVerify);
        wolfSSL_CTX_mutual_auth(sk->ctx, 1);
        LOG_DEBUG("DTLS: mutual authentication ON\n");
#else
        /* Disable cert verification */
        wolfSSL_CTX_set_verify(sk->ctx, WOLFSSL_VERIFY_NONE, 0);
        LOG_DEBUG("DTLS: mutual authentication OFF\n");
#endif

        /* Load credential for the DTLS server */
        if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, server_cred,
                    server_cred_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
        {
            LOG_ERROR("Error loading cert buffer\n");
            return -1;
        }

        /* Load the private key */
        if (wolfSSL_CTX_use_PrivateKey_buffer(sk->ctx, server_priv,
                    server_priv_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
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

#if defined(DTLS_RPK)
        char ctype[] = {WOLFSSL_CERT_TYPE_RPK};
        char stype[] = {WOLFSSL_CERT_TYPE_RPK};
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
#endif

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

#ifndef HANDSHAKE_ONLY
            const char Test_dtls_string[] = "DTLS OK!";
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
#endif

            /* Cleanup/shutdown */
            LOG_DEBUG("Closing connection.\n");
            sock_dtls_close(sk);
            sock_dtls_session_destroy(sk);
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