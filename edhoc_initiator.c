#ifdef USE_EDHOC

#include <stdio.h>
#include <od.h>
#include "edhoc_rs.h"

#include "net/gcoap.h"
#include "net/sock/util.h"

#include "edhoc_creds.h"

static char *addr_str = "[fe80::b834:d60b:796f:8de0%6]:5683";

// typedef struct client_state {
//     bool has_new_response;
//     coap_pkt_t response_pdu;
// } client_state_t;

// client_state_t client_state = {
//     .has_new_response = false,
//     .response_pdu = {0},
// };

static void _resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t* pdu,
                          const sock_udp_ep_t *remote)
{
    printf("Received response: %u\n", pdu->hdr->code);
    printf("Received response: %.*s\n", (int)pdu->payload_len, (char *)pdu->payload);

    // client_state.has_new_response = true;
    // memcpy(&client_state.response_pdu, pdu, sizeof(coap_pkt_t));
}

static ssize_t _send_coap_message(uint8_t *buf, size_t len, char *addr_str)
{
    size_t bytes_sent;
    sock_udp_ep_t remote;

    if (sock_udp_name2ep(&remote, addr_str) != 0) {
        printf("gcoap: sock udp name2ep failed\n");
        return 0;
    }

    if (remote.port == 0) {
        remote.port = CONFIG_GCOAP_PORT;
    }

    bytes_sent = gcoap_req_send(buf, len, &remote, _resp_handler, NULL);
    return bytes_sent;
}

int send_edhoc_coap_request(uint8_t *payload, size_t paylen, uint8_t value_to_prepend) {
    coap_pkt_t pdu;
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    size_t len;

    // gcoap_req_init(&pdu, buf, CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET, "/.well-known/core");
    gcoap_req_init(&pdu, buf, CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_POST, "/.well-known/edhoc");
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);
    coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
    if (pdu.payload_len >= paylen + 1) {
        *(pdu.payload) = value_to_prepend;
        memcpy(pdu.payload + sizeof(uint8_t), payload, paylen + 1);
        len += paylen + 1;
    }

    printf("Sending request to %s\n", addr_str);
    od_hex_dump(buf, len, OD_WIDTH_DEFAULT);
    ssize_t ret = _send_coap_message(buf, len, addr_str);
    if (ret <= 0) {
        printf("gcoap: msg send failed: %d\n", ret);
        return 1;
    }

    return 0;
}

int edhoc_initiator(int argc, char **argv) {
    (void)argc;
    (void)argv;
    puts("Begin test: edhoc handshake.");
    EdhocInitiatorC initiator = initiator_new(I, 32*2, G_R, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);

    EdhocMessageBuffer message_1;
    initiator_prepare_message_1(&initiator, &message_1);
    od_hex_dump(message_1.content, message_1.len, OD_WIDTH_DEFAULT);

    send_edhoc_coap_request(message_1.content, message_1.len, 0xF5); // prepend CBOR true to message_1

    // EdhocMessageBuffer message_2;
    // // message_2 = send_coap(message_1)
    // uint8_t c_r_received;
    // initiator_process_message_2(&initiator, &message_2, &c_r_received);



    // EdhocMessageBuffer message_3;
    // uint8_t prk_out_initiator[SHA256_DIGEST_LEN];
    // initiator_prepare_message_3(&initiator, &message_3, &prk_out_initiator);
    // // send_coap(message_3)

    // printf("\nprk_out_initiator: \n");
    // od_hex_dump(prk_out_initiator, SHA256_DIGEST_LEN, OD_WIDTH_DEFAULT);

    puts("End test: edhoc handshake.");

    return 0;
}

#endif /* USE_EDHOC */
