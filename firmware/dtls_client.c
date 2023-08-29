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

#include "dtls_creds.h"

extern void MEASURE_START(void);
extern void MEASURE_STOP(void);

#define SERVER_PORT 11111
#define APP_DTLS_BUF_SIZE 64

static sock_tls_t skv;
static sock_tls_t *sk = &skv;

#ifdef MODULE_WOLFSSL_STATIC_MEMORY
extern uint8_t wolfssl_general_memory[];
extern size_t wolfssl_general_memory_sz;
extern uint8_t wolfssl_io_memory[];
extern size_t wolfssl_io_memory_sz;
#endif

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

#ifdef MODULE_WOLFSSL_STATIC_MEMORY
    if (sock_dtls_create_static(sk, &local, &remote, 0, wolfDTLSv1_3_client_method_ex,
        wolfssl_general_memory, wolfssl_general_memory_sz, wolfssl_io_memory, wolfssl_io_memory_sz
    ) != 0) {
#else
    if (sock_dtls_create(sk, &local, &remote, 0, wolfDTLSv1_3_client_method()) != 0) {
#endif
        LOG_ERROR("ERROR: Unable to create DTLS sock\n");
        return -1;
    }

    /* Disable certificate validation */
    wolfSSL_CTX_set_verify(sk->ctx, WOLFSSL_VERIFY_NONE, 0);

    /* Load Credential for the DTLS client */
    if (wolfSSL_CTX_use_certificate_buffer(sk->ctx, client_cred,
                client_cred_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG_ERROR("Error loading cert buffer\n");
        return -1;
    }

    /* Load the private key */
    if (wolfSSL_CTX_use_PrivateKey_buffer(sk->ctx, client_priv,
                client_priv_len, SSL_FILETYPE_ASN1 ) != SSL_SUCCESS)
    {
        LOG_ERROR("Failed to load private key from memory.\n");
        return -1;
    }

    if (sock_dtls_session_create(sk) < 0) // calls wolfSSL_new(sk->ctx)
        return -1;
    wolfSSL_dtls_set_timeout_init(sk->ssl, 5);

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
    sock_dtls_close(sk);
    sock_dtls_session_destroy(sk);
    wolfSSL_free(sk->ssl);
    wolfSSL_CTX_free(sk->ctx);
    LOG_INFO("Connection closed ok.\n");
    return 0;
}

#endif /* USE_DTLS13 */
