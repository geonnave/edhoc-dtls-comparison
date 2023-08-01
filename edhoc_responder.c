#ifdef USE_EDHOC

#include <stdio.h>
#include "od.h"
#include "net/gcoap.h"

#include "edhoc_rs.h"
#include "edhoc_creds.h"

static ssize_t coap_edhoc_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);
static ssize_t _riot_board_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx);

/* CoAP resources. Must be sorted by path (ASCII order). */
static const coap_resource_t _resources[] = {
    // { "/.well-known/edhoc", COAP_METHOD_POST, coap_edhoc_handler, NULL },
    { "/foo", COAP_POST, coap_edhoc_handler, NULL },
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
};

static const char *_link_params[] = {
    ";ct=0;rt=\"count\";obs",
    NULL
};

/* Adds link format params to resource list */
static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context) {
    ssize_t res = gcoap_encode_link(resource, buf, maxlen, context);
    if (res > 0) {
        if (_link_params[context->link_pos]
                && (strlen(_link_params[context->link_pos]) < (maxlen - res))) {
            if (buf) {
                memcpy(buf+res, _link_params[context->link_pos],
                       strlen(_link_params[context->link_pos]));
            }
            return res + strlen(_link_params[context->link_pos]);
        }
    }

    return res;
}

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    GCOAP_SOCKET_TYPE_UNDEF,
    _encode_link,
    NULL,
    NULL
};

EdhocResponderC responder = {0};

static ssize_t coap_edhoc_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx)
{
    (void)ctx;
    printf("COAP: received new message\n");
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    if (responder.state._0 == Start && pdu->payload[0] == 0xF5) {
        printf("EDHOC: will process message_1\n");
        EdhocMessageBuffer message_1 = { .len = pdu->payload_len - 1 };
        memcpy(message_1.content, pdu->payload + sizeof(uint8_t), pdu->payload_len - 1); // skip first byte
        uint8_t ret = responder_process_message_1(&responder, &message_1);
        if (ret != 0) {
            printf("EDHOC: error processing message 1: %d\n", ret);
            return -1;
        }

        EdhocMessageBuffer message_2;
        uint8_t c_r_sent;
        responder_prepare_message_2(&responder, &message_2, &c_r_sent);
        printf("EDHOC: prepared message_2:\n");
        od_hex_dump(message_2.content, message_2.len, OD_WIDTH_DEFAULT);

        gcoap_resp_init(pdu, buf, len, COAP_CODE_CHANGED);
        coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
        size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
        memcpy(pdu->payload, message_2.content, message_2.len);

        printf("COAP: responding with message_2\n");
        return resp_len + message_2.len;
    } else {
        // potentially message_3
        printf("EDHOC: will process message_3\n");
        uint8_t _c_r_received = pdu->payload[0]; // not used
        uint8_t prk_out_responder[SHA256_DIGEST_LEN];
        EdhocMessageBuffer message_3 = { .len = pdu->payload_len - 1 };
        memcpy(message_3.content, pdu->payload + sizeof(uint8_t), pdu->payload_len - 1); // skip first byte
        uint8_t ret = responder_process_message_3(&responder, &message_3, &prk_out_responder);
        if (ret != 0) {
            printf("EDHOC: error processing message 3: %d\n", ret);
            return -1;
        }
        printf("\nprk_out_responder: \n");
        od_hex_dump(prk_out_responder, SHA256_DIGEST_LEN, OD_WIDTH_DEFAULT);

        return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
    }

    printf("COAP: responding BAD_REQUEST\n");
    return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
}

static ssize_t _riot_board_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, coap_request_ctx_t *ctx)
{
    (void)ctx;
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the RIOT board name in the response buffer */
    if (pdu->payload_len >= strlen(RIOT_BOARD)) {
        memcpy(pdu->payload, RIOT_BOARD, strlen(RIOT_BOARD));
        return resp_len + strlen(RIOT_BOARD);
    }
    else {
        puts("gcoap_cli: msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
}

int edhoc_responder(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("COAP: initialize server.\n");
    gcoap_register_listener(&_listener);

    printf("EDHOC: initialize responder.\n");
    responder = responder_new(R, 32*2, G_I, 32*2, ID_CRED_I, 4*2, CRED_I, 107*2, ID_CRED_R, 4*2, CRED_R, 84*2);
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

    return 0;
}

// void server_init(void)
// {
//     printf("COAP: initialize server.\n");
//     gcoap_register_listener(&_listener);
// }

#endif /* USE_EDHOC */
