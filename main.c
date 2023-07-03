#include <stdio.h>
#include "shell.h"
#include "log.h"
#include "od.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#if defined(USE_EDHOC)
extern int edhoc_initiator(int argc, char **argv);
extern int edhoc_responder(int argc, char **argv);
static const shell_command_t shell_commands[] = {
    { "edhoci", "Start a EDHOC initiator", edhoc_initiator },
    { "edhocr", "Start and stop a EDHOC responder", edhoc_responder },
    { NULL, NULL, NULL }
};
#ifdef RUST_PSA
extern void mbedtls_memory_buffer_alloc_init(uint8_t *buf, size_t len);
#endif
#elif defined(USE_DTLS13)
extern int dtls_client(int argc, char **argv);
extern int dtls_server(int argc, char **argv);
static const shell_command_t shell_commands[] = {
    { "dtlsc", "Start a DTLS client", dtls_client },
    { "dtlss", "Start and stop a DTLS server", dtls_server },
    { NULL, NULL, NULL }
};
#endif

int main(void)
 {
    puts("EDHOC to TLS1.3 Comparison!");

    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    LOG(LOG_INFO, "RIOT wolfSSL DTLS testing implementation\n");

#if defined(USE_EDHOC)
    puts("Selected protocol: EDHOC");
    // edhoc will run on sock_udp
#ifdef RUST_PSA
    // Memory buffer for mbedtls
    uint8_t buffer[4096 * 2] = {0};
    mbedtls_memory_buffer_alloc_init(buffer, 4096 * 2);
#endif
#elif defined(USE_DTLS13)
    puts("Selected protocol: DTLS 1.3");
    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    // dtls13 will run on sock_dtls (wolfssl's wrapper for sock_udp)
#endif

    /* start shell */
    LOG(LOG_INFO, "All up, running the shell now\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
