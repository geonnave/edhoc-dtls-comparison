#ifdef USE_EDHOC

#include <stdio.h>
#include "od.h"
#include "log.h"
#include "net/gcoap.h"

#include "edhoc_rs.h"
#include "edhoc_creds.h"

extern void MEASURE_START(void);
extern void MEASURE_STOP(void);

static ssize_t coap_edhoc_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);

/* CoAP resources. Must be sorted by path (ASCII order). */
static const coap_resource_t _resources[] = {
    { "/.well-known/edhoc", COAP_POST, coap_edhoc_handler, NULL },
};

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    GCOAP_SOCKET_TYPE_UNDEF,
    NULL,
    NULL,
    NULL
};

EdhocResponderC responder = {0};

static ssize_t coap_edhoc_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx)
{
    (void)ctx;
    LOG_DEBUG("COAP: received new message\n");

    if (responder.state._0 == Start && pdu->payload[0] == 0xF5) {
        MEASURE_START();

        LOG_DEBUG("EDHOC: will process message_1\n");
        EdhocMessageBuffer message_1 = { .len = pdu->payload_len - 1 };
        memcpy(message_1.content, pdu->payload + sizeof(uint8_t), pdu->payload_len - 1); // skip first byte
        uint8_t ret = responder_process_message_1(&responder, &message_1);
        if (ret != 0) {
            LOG_DEBUG("EDHOC: error processing message 1: %d\n", ret);
            return -1;
        }

        EdhocMessageBuffer message_2;
        uint8_t c_r_sent;
        responder_prepare_message_2(&responder, &message_2, &c_r_sent);
        LOG_DEBUG("EDHOC: prepared message_2:\n");
        // od_hex_dump(message_2.content, message_2.len, OD_WIDTH_DEFAULT);

        gcoap_resp_init(pdu, buf, len, COAP_CODE_CHANGED);
        coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
        size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
        memcpy(pdu->payload, message_2.content, message_2.len);

        LOG_DEBUG("COAP: responding with message_2\n");
        return resp_len + message_2.len;
    } else {
        // potentially message_3
        LOG_DEBUG("EDHOC: will process message_3\n");
        uint8_t _c_r_received = pdu->payload[0]; // not used
        uint8_t prk_out_responder[SHA256_DIGEST_LEN];
        EdhocMessageBuffer message_3 = { .len = pdu->payload_len - 1 };
        memcpy(message_3.content, pdu->payload + sizeof(uint8_t), pdu->payload_len - 1); // skip first byte
        uint8_t ret = responder_process_message_3(&responder, &message_3, &prk_out_responder);
        if (ret != 0) {
            LOG_DEBUG("EDHOC: error processing message 3: %d\n", ret);
            return -1;
        }
        LOG_DEBUG("\nprk_out_responder: \n");
        // od_hex_dump(prk_out_responder, SHA256_DIGEST_LEN, OD_WIDTH_DEFAULT);

        ret = gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
        if (ret <= 0) {
            LOG_DEBUG("COAP: error sending response: %d\n", ret);
            return -1;
        }

        MEASURE_STOP();

        // reset responder, to be ready for a possible next session
        responder = responder_new(R, 32*2, G_I, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);

        return ret;
    }

    LOG_DEBUG("COAP: responding BAD_REQUEST\n");
    return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
}

int edhoc_responder(int argc, char **argv) {
    (void)argc;
    (void)argv;

    LOG_DEBUG("COAP: initialize server.\n");
    gcoap_register_listener(&_listener);

    LOG_DEBUG("EDHOC: initialize responder.\n");
    responder = responder_new(R, 32*2, G_I, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);

    return 0;
}

#endif /* USE_EDHOC */
