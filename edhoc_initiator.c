#include <stdio.h>
#include "edhoc_rs.h"
#include "od.h"
#include "edhoc_creds.h"

int edhoc_initiator(int argc, char **argv) {
    (void)argc;
    (void)argv;
    puts("Begin test: edhoc handshake.");
    EdhocInitiatorC initiator = initiator_new(I, 32*2, G_R, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);

    EdhocMessageBuffer message_1;
    initiator_prepare_message_1(&initiator, &message_1);
    od_hex_dump(message_1.content, message_1.len, OD_WIDTH_DEFAULT);

    // EdhocMessageBuffer message_2;
    // // message_2 = send_udp(message_1)
    // uint8_t c_r_received;
    // initiator_process_message_2(&initiator, &message_2, &c_r_received);

    // EdhocMessageBuffer message_3;
    // uint8_t prk_out_initiator[SHA256_DIGEST_LEN];
    // initiator_prepare_message_3(&initiator, &message_3, &prk_out_initiator);
    // // send_udp(message_3)

    // printf("\nprk_out_initiator: \n");
    // od_hex_dump(prk_out_initiator, SHA256_DIGEST_LEN, OD_WIDTH_DEFAULT);

    puts("End test: edhoc handshake.");

    return 0;
}
