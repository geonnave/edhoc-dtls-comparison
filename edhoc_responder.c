#ifdef USE_EDHOC

#include <stdio.h>

#include "net/gcoap.h"

#include "edhoc_rs.h"
#include "edhoc_creds.h"



int edhoc_responder(int argc, char **argv) {
    (void)argc;
    (void)argv;
    puts("Begin test: edhoc handshake.");
    EdhocResponderC responder = responder_new(R, 32*2, G_I, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);
    (void)responder;

    // EdhocMessageBuffer message_1 = buffer;
    // responder_process_message_1(&responder, &message_1);

    // EdhocMessageBuffer message_2;
    // uint8_t c_r_sent;
    // responder_prepare_message_2(&responder, &message_2, &c_r_sent);

    // EdhocMessageBuffer message_3 = buffer;
    // uint8_t prk_out_responder[SHA256_DIGEST_LEN];
    // responder_process_message_3(&responder, &message_3, &prk_out_responder);

    // printf("\nprk_out_responder: \n");
    // od_hex_dump(prk_out_responder, SHA256_DIGEST_LEN, OD_WIDTH_DEFAULT);

    puts("End test: edhoc handshake.");
    return 0;
}

#endif /* USE_EDHOC */
