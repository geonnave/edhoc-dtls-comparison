#include <stdio.h>
#include "edhoc_rs.h"
#include "edhoc_creds.h"

int edhoc_responder(int argc, char **argv) {
    (void)argc;
    (void)argv;
    puts("Begin test: edhoc handshake.");
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
