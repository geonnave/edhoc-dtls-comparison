#ifdef USE_EDHOC

#include <stdio.h>
#include "od.h"
#include "log.h"
#include "net/gcoap.h"
#include "net/sock/util.h"

#include "edhoc_rs.h"
#include "edhoc_creds.h"

static char *addr_str = "[fe80::b834:d60b:796f:8de0%6]:5683";

EdhocInitiatorC initiator = {0};

static void coap_response_handler_for_edhoc(const gcoap_request_memo_t *memo, coap_pkt_t* pdu, const sock_udp_ep_t *remote);

static ssize_t _send_coap_message(uint8_t *buf, size_t len, char *addr_str)
{
    size_t bytes_sent;
    sock_udp_ep_t remote = { .port = CONFIG_GCOAP_PORT };

    if (sock_udp_name2ep(&remote, addr_str) != 0) {
        LOG_ERROR("COAP: sock udp name2ep failed\n");
        return 0;
    }

    bytes_sent = gcoap_req_send(buf, len, &remote, coap_response_handler_for_edhoc, NULL);
    return bytes_sent;
}

int send_edhoc_coap_request(uint8_t *payload, size_t paylen, uint8_t value_to_prepend) {
    coap_pkt_t pdu;
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    size_t len;

    // gcoap_req_init(&pdu, buf, CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET, "/.well-known/core");
    // gcoap_req_init(&pdu, buf, CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_POST, "/.well-known/edhoc");
    gcoap_req_init(&pdu, buf, CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_POST, "/foo");
    coap_hdr_set_type(pdu.hdr, COAP_TYPE_CON);
    coap_opt_add_format(&pdu, COAP_FORMAT_TEXT);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
    if (pdu.payload_len >= paylen + 1) {
        *(pdu.payload) = value_to_prepend;
        memcpy(pdu.payload + sizeof(uint8_t), payload, paylen + 1);
        len += paylen + 1;
    }

    LOG_DEBUG("Sending request of len %u to %s\n", len, addr_str);
    // od_hex_dump(buf, len, OD_WIDTH_DEFAULT);
    ssize_t ret = _send_coap_message(buf, len, addr_str);
    if (ret <= 0) {
        LOG_ERROR("COAP: msg send failed: %d\n", ret);
        return 1;
    }

    return 0;
}

static void coap_response_handler_for_edhoc(const gcoap_request_memo_t *memo, coap_pkt_t* pdu, const sock_udp_ep_t *remote)
{
    LOG_DEBUG("COAP: Received response: %u\n", pdu->hdr->code);
    LOG_DEBUG("COAP: Received response: %.*s\n", (int)pdu->payload_len, (char *)pdu->payload);

    if (pdu->hdr->code != COAP_CODE_CHANGED) {
        LOG_ERROR("COAP: Received unexpected response with code: %u\n", pdu->hdr->code);
        return;
    }

    if (initiator.state._0 == WaitMessage2) {
        LOG_DEBUG("EDHOC: will process message_2\n");
        // construct and process the received message_2
        EdhocMessageBuffer message_2 = { .len = pdu->payload_len };
        memcpy(message_2.content, pdu->payload, pdu->payload_len);
        uint8_t c_r_received;
        initiator_process_message_2(&initiator, &message_2, &c_r_received);
        LOG_DEBUG("EDHOC: processed message_2 (c_r_received: %u):\n", c_r_received);
        // od_hex_dump(message_2.content, message_2.len, OD_WIDTH_DEFAULT);

        // construct and send message_3
        EdhocMessageBuffer message_3;
        uint8_t prk_out_initiator[SHA256_DIGEST_LEN];
        initiator_prepare_message_3(&initiator, &message_3, &prk_out_initiator);
        LOG_DEBUG("EDHOC: prepared message_3:\n");
        // od_hex_dump(message_3.content, message_3.len, OD_WIDTH_DEFAULT);
        LOG_DEBUG("EDHOC: prk_out_initiator: \n");
        // od_hex_dump(prk_out_initiator, SHA256_DIGEST_LEN, OD_WIDTH_DEFAULT);

        int ret = send_edhoc_coap_request(message_3.content, message_3.len, c_r_received); // prepend c_r_received to message_3
        if (ret != 0) {
            LOG_ERROR("EDHOC: message_3 send failed\n");
            return;
        }
        LOG_DEBUG("EDHOC: message_3 sent ok.\n");
    } else if (initiator.state._0 == Completed) {
        LOG_DEBUG("EDHOC: Received message_3 response\n");
        LOG_INFO("EDHOC: end handshake ok.\n");
    } else {
        LOG_ERROR("EDHOC: Received unexpected response\n");
    }
}

int edhoc_initiator(int argc, char **argv) {
    (void)argc;
    (void)argv;

    LOG_DEBUG("EDHOC: loading initiator.\n");
    initiator = initiator_new(I, 32*2, G_R, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);

    LOG_INFO("EDHOC: begin handshake.\n");
    EdhocMessageBuffer message_1;
    initiator_prepare_message_1(&initiator, &message_1);
    LOG_DEBUG("EDHOC: prepared message_1:\n");
    // od_hex_dump(message_1.content, message_1.len, OD_WIDTH_DEFAULT);

    send_edhoc_coap_request(message_1.content, message_1.len, 0xF5); // prepend CBOR true to message_1

    // the rest of the logic is in the response handler

    return 0;
}

#endif /* USE_EDHOC */
