#include <stdio.h>
#include "od.h"

int main(void)
 {
    puts("EDHOC to TLS1.3 Comparison!");

#if defined(USE_EDHOC)
    puts("Selected protocol: EDHOC");
    // edhoc will run on sock_udp
#elif defined(USE_DTLS13)
    puts("Selected protocol: DTLS 1.3");
    // dtls13 will run on sock_dtls (wolfssl's wrapper for sock_udp)
#endif

    return 0;
}
