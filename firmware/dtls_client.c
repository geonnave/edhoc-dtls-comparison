#ifdef USE_DTLS13

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <sock_tls.h>
#include <net/sock.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gnrc/netif.h"
#include "log.h"

extern void MEASURE_START(void);
extern void MEASURE_STOP(void);

#define SERVER_PORT 11111
#define APP_DTLS_BUF_SIZE 64

extern const unsigned char server_cert[];
extern const unsigned long server_cert_len;

// xxd -i wolfssl/certs/ecc-client-keyPub.der
unsigned char client_rpk[] = {
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00, 0x04, 0x55, 0xbf, 0xf4, 0x0f, 0x44, 0x50, 0x9a, 0x3d, 0xce,
  0x9b, 0xb7, 0xf0, 0xc5, 0x4d, 0xf5, 0x70, 0x7b, 0xd4, 0xec, 0x24, 0x8e,
  0x19, 0x80, 0xec, 0x5a, 0x4c, 0xa2, 0x24, 0x03, 0x62, 0x2c, 0x9b, 0xda,
  0xef, 0xa2, 0x35, 0x12, 0x43, 0x84, 0x76, 0x16, 0xc6, 0x56, 0x95, 0x06,
  0xcc, 0x01, 0xa9, 0xbd, 0xf6, 0x75, 0x1a, 0x42, 0xf7, 0xbd, 0xa9, 0xb2,
  0x36, 0x22, 0x5f, 0xc7, 0x5d, 0x7f, 0xb4
};
unsigned int client_rpk_len = 91;
// xxd -i wolfssl/certs/ecc-client-key.der
unsigned char client_rpk_priv[] = {
  0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xf8, 0xcf, 0x92, 0x6b, 0xbd,
  0x1e, 0x28, 0xf1, 0xa8, 0xab, 0xa1, 0x23, 0x4f, 0x32, 0x74, 0x18, 0x88,
  0x50, 0xad, 0x7e, 0xc7, 0xec, 0x92, 0xf8, 0x8f, 0x97, 0x4d, 0xaf, 0x56,
  0x89, 0x65, 0xc7, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x55, 0xbf, 0xf4,
  0x0f, 0x44, 0x50, 0x9a, 0x3d, 0xce, 0x9b, 0xb7, 0xf0, 0xc5, 0x4d, 0xf5,
  0x70, 0x7b, 0xd4, 0xec, 0x24, 0x8e, 0x19, 0x80, 0xec, 0x5a, 0x4c, 0xa2,
  0x24, 0x03, 0x62, 0x2c, 0x9b, 0xda, 0xef, 0xa2, 0x35, 0x12, 0x43, 0x84,
  0x76, 0x16, 0xc6, 0x56, 0x95, 0x06, 0xcc, 0x01, 0xa9, 0xbd, 0xf6, 0x75,
  0x1a, 0x42, 0xf7, 0xbd, 0xa9, 0xb2, 0x36, 0x22, 0x5f, 0xc7, 0x5d, 0x7f,
  0xb4
};
unsigned int client_rpk_priv_len = 121;

static sock_tls_t skv;
static sock_tls_t *sk = &skv;

static void usage(const char *cmd_name)
{
    LOG_ERROR("Usage: %s <server-address>\n", cmd_name);
}

int dtls_client(int argc, char **argv)
{
    int ret = 0;
    char buf[APP_DTLS_BUF_SIZE] = "Hello from DTLS client!";
    char *iface;
    char *addr_str;
    int connect_timeout = 0;
    const int max_connect_timeouts = 5;

    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    addr_str = argv[1];
    sock_udp_ep_t local = SOCK_IPV6_EP_ANY;
    sock_udp_ep_t remote = SOCK_IPV6_EP_ANY;

    /* Parsing <address> */
    iface = ipv6_addr_split_iface(addr_str);
    if (!iface) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote.netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
    }
    else {
        gnrc_netif_t *netif = gnrc_netif_get_by_pid(atoi(iface));
        if (netif == NULL) {
            LOG_ERROR("ERROR: interface not valid\n");
            usage(argv[0]);
            return -1;
        }
        remote.netif = (uint16_t)netif->pid;
    }
    if (ipv6_addr_from_str((ipv6_addr_t *)remote.addr.ipv6, addr_str) == NULL) {
        LOG_ERROR("ERROR: unable to parse destination address\n");
        usage(argv[0]);
        return -1;
    }
    remote.port = SERVER_PORT;

    MEASURE_START();

    // if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_2_client_method()) != 0) {
    if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_3_client_method()) != 0) {
        LOG_ERROR("ERROR: Unable to create DTLS sock\n");
        return -1;
    }

//     /* Disable certificate validation from the client side */
//     wolfSSL_CTX_set_verify(sk->ctx, SSL_VERIFY_NONE, 0);

//     /* Load certificate file for the DTLS client */
//     if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, server_cert,
//                 server_cert_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
//     {
//         LOG_ERROR("Error loading cert buffer\n");
//         return -1;
//     }

    /* Disable certificate validation from the client side */
    wolfSSL_CTX_set_verify(sk->ctx, WOLFSSL_VERIFY_NONE, 0);
    // wolfSSL_CTX_set_verify(sk->ctx, WOLFSSL_VERIFY_PEER, NULL);

    /* Load RPK for the DTLS client */
    if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, client_rpk,
                client_rpk_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG_ERROR("Error loading cert buffer\n");
        return -1;
    }

    /* Load the private key */
    if (wolfSSL_CTX_use_PrivateKey_buffer(sk->ctx, client_rpk_priv,
                client_rpk_priv_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG_ERROR("Failed to load private key from memory.\n");
        return -1;
    }

    if (sock_dtls_session_create(sk) < 0) // calls wolfSSL_new(sk->ctx)
        return -1;
    wolfSSL_dtls_set_timeout_init(sk->ssl, 5);

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

    LOG_DEBUG("connecting to server...\n");
    /* attempt to connect until the connection is successful */
    do {
        ret = wolfSSL_connect(sk->ssl);
        if ((ret != SSL_SUCCESS)) {
            if(wolfSSL_get_error(sk->ssl, ret) == SOCKET_ERROR_E) {
                LOG(LOG_WARNING, "Socket error: reconnecting...\n");
                sock_dtls_session_destroy(sk);
                connect_timeout = 0;
                if (sock_dtls_session_create(sk) < 0)
                    return -1;
            }
            if ((wolfSSL_get_error(sk->ssl, ret) == WOLFSSL_ERROR_WANT_READ) &&
                    (connect_timeout++ >= max_connect_timeouts)) {
                LOG(LOG_WARNING, "Server not responding: reconnecting...\n");
                sock_dtls_session_destroy(sk);
                connect_timeout = 0;
                if (sock_dtls_session_create(sk) < 0)
                    return -1;
            }
        }
    } while(ret != SSL_SUCCESS);

    MEASURE_STOP();

    /* set remote endpoint */
    sock_dtls_set_endpoint(sk, &remote);

    /* send the hello message */
    wolfSSL_write(sk->ssl, buf, strlen(buf));

    /* wait for a reply, indefinitely */
    do {
        ret = wolfSSL_read(sk->ssl, buf, APP_DTLS_BUF_SIZE - 1);
        LOG_DEBUG("wolfSSL_read returned %d\n", ret);
    } while (ret <= 0);
    buf[ret] = (char)0;
    LOG_DEBUG("Received: '%s'\n", buf);

    /* Clean up and exit. */
    LOG_DEBUG("Closing connection.\n");
    sock_dtls_session_destroy(sk);
    sock_dtls_close(sk);
    wolfSSL_free(sk->ssl);
    wolfSSL_CTX_free(sk->ctx);
    LOG_INFO("Connection closed ok.\n");
    return 0;
}

#endif /* USE_DTLS13 */
