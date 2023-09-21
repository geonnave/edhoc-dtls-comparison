#include <stdio.h>
#include "msg.h"
#include "shell.h"
#include "log.h"
#include "od.h"
#include "periph/gpio.h"
#include "ztimer.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];
gpio_t pin_otii = GPIO_PIN(0, 31);

#if defined(USE_EDHOC)
#include "edhoc_rs.h"
extern int edhoc_initiator(int argc, char **argv);
extern int edhoc_responder(int argc, char **argv);
#ifndef EVALUATION_MODE
static const shell_command_t shell_commands[] = {
    { "edhoci", "Start a EDHOC initiator", edhoc_initiator },
    { "edhocr", "Start and stop a EDHOC responder", edhoc_responder },
    { NULL, NULL, NULL }
};
#endif
#ifdef RUST_PSA
extern void mbedtls_memory_buffer_alloc_init(uint8_t *buf, size_t len);
#endif
#elif defined(USE_DTLS13)
#include "wolfssl/ssl.h"
extern int dtls_client(int argc, char **argv);
extern int dtls_server(int argc, char **argv);

#ifdef MODULE_WOLFSSL_STATIC_MEMORY
#define WOLFSSL_GENERAL_MEMORY_MAX (100*1024)
#define WOLFSSL_IO_MEMORY_MAX (80*1024)
uint8_t wolfssl_general_memory[WOLFSSL_GENERAL_MEMORY_MAX];
size_t wolfssl_general_memory_sz = WOLFSSL_GENERAL_MEMORY_MAX;
uint8_t wolfssl_io_memory[WOLFSSL_IO_MEMORY_MAX];
size_t wolfssl_io_memory_sz = WOLFSSL_IO_MEMORY_MAX;
#endif

#ifndef EVALUATION_MODE
static const shell_command_t shell_commands[] = {
    { "dtlsc", "Start a DTLS client", dtls_client },
    { "dtlss", "Start and stop a DTLS server", dtls_server },
    { NULL, NULL, NULL }
};
#endif
#endif

void MEASURE_START(void)
{
#if defined(USE_EDHOC)
    LOG_INFO("EDHOC: begin handshake.\n");
#elif defined(USE_DTLS13)
    LOG_INFO("DTLS: begin handshake.\n");
#endif
    gpio_set(pin_otii);
}

void MEASURE_STOP(void)
{
    gpio_clear(pin_otii);
#if defined(USE_EDHOC)
    LOG_INFO("EDHOC: end handshake ok.\n");
#elif defined(USE_DTLS13)
    LOG_INFO("DTLS: end handshake ok.\n");
#endif
}

static void run_evaluation(size_t times)
{
    LOG_INFO("Triggering handshake for %u times! (in 10 seconds...) \n", times);
    ztimer_sleep(ZTIMER_MSEC, 10000);
    for (size_t i = 0; i < times; i++) {
        LOG_INFO("Handshake %u\n", i);
#if defined(USE_EDHOC)
        edhoc_initiator(0, NULL);
#elif defined(USE_DTLS13)
        int argc = 2;
        char *argv[] = {"dtlsc", "fe80::5c0d:cee5:5196:8be8"};
        dtls_client(argc, argv);
#endif
        ztimer_sleep(ZTIMER_MSEC, 3000);
    }
}

int main(void)
 {
    LOG_INFO("EDHOC to TLS1.3 Comparison!\n");

    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    // initialize pin for OTII device, which is used for measuring
    // energy consumption and handshake duration
    gpio_init(pin_otii, GPIO_OUT);

#if defined(USE_EDHOC)
    LOG_INFO("Selected protocol: EDHOC\n");
    edhoc_rs_crypto_init();
#ifdef RUST_PSA
    // Memory buffer for mbedtls
    uint8_t buffer[4096 * 2] = {0};
    mbedtls_memory_buffer_alloc_init(buffer, 4096 * 2);
#endif
#elif defined(USE_DTLS13)
    LOG_INFO("Selected protocol: DTLS 1.3\n");
    int ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        LOG_ERROR("wolfSSL_Init failed: %d\n", ret);
        return -1;
    }
    wolfSSL_Debugging_ON();
#endif

#ifdef EVALUATION_MODE
    run_evaluation(EVALUATION_TIMES);
#else
    /* start shell */
    LOG_INFO("All up, running the shell now\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
#endif

    return 0;
}
