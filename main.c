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
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/wc_port.h>
extern int dtls_client(int argc, char **argv);
extern int dtls_server(int argc, char **argv);
static const shell_command_t shell_commands[] = {
    { "dtlsc", "Start a DTLS client", dtls_client },
    { "dtlss", "Start and stop a DTLS server", dtls_server },
    { NULL, NULL, NULL }
};
#elif defined(CC310_ONLY)
#include "sns_silib.h"
#include "crys_rnd.h"
#include "crys_ecpki_kg.h"
#include "crys_ecpki_types.h"
#include "crys_ecpki_domain.h"
CRYS_RND_State_t     wc_rndCtx;
CRYS_RND_WorkBuff_t  wc_rndWorkBuff;
SaSiRndGenerateVectWorkFunc_t wc_rndGenVectFunc = CRYS_RND_GenerateVector;
static const shell_command_t shell_commands[] = {
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

    printf("will wolfCrypt_Init......\n");
    int ret;
    if ((ret = wolfCrypt_Init()) != 0) {
        printf("wolfCrypt_Init failed %d\n", ret);
        return -1;
    }

    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    puts("WolfSSL initialized\n");
#elif defined(CC310_ONLY)
    puts("Just testing the CC310 crypto accelerator");
    int ret = SaSi_LibInit();
    if (ret != SASI_SUCCESS) {
        printf("SaSi_LibInit failed %d\n", ret);
        return -1;
    }
    ret = CRYS_RndInit(&wc_rndCtx, &wc_rndWorkBuff);
    if (ret != CRYS_OK) {
        printf("CRYS_RndInit failed %d\n", ret);
        return -1;
    }

    const CRYS_ECPKI_Domain_t           * p_domain = CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
    CRYS_ECPKI_UserPrivKey_t        p_private_key_user = { 0 };
    CRYS_ECPKI_UserPublKey_t        p_public_key_user = { 0 };
    CRYS_ECPKI_KG_TempData_t        temp_data;
    CRYS_ECPKI_KG_FipsContext_t     temp_fips_buffer;

    CRYSError_t crys_error = CRYS_ECPKI_GenKeyPair(&wc_rndCtx,
                                       wc_rndGenVectFunc,
                                       p_domain,
                                       &p_private_key_user,
                                       &p_public_key_user,
                                       &temp_data,
                                       &temp_fips_buffer );
    if (crys_error != CRYS_OK) {
        printf("CRYS_ECPKI_GenKeyPair failed %ld\n", crys_error);
        return -1;
    }
#endif

    /* start shell */
    LOG(LOG_INFO, "All up, running the shell now\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
