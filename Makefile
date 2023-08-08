# name of your application
APPLICATION = edhoc-dtls-1_3-comparison
BOARD ?= nrf52840dk
RIOTBASE ?= $(CURDIR)/../../RIOT-FORK
DEVELHELP ?= 1

ifeq (eval, $(MODE))
TIMES ?= 3
CFLAGS += -DEVALUATION_MODE -DEVALUATION_TIMES=$(TIMES)
endif

ifeq (dtls, $(SEC))
CFLAGS += -DUSE_DTLS13 # flag for the application code
CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL
# A larger stack size is required if using ECC or RSA
# CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(4*THREAD_STACKSIZE_DEFAULT\)
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384 -DTHREAD_STACKSIZE_MAIN=16384

INCLUDES += -I$(CURDIR)/../../edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/include
ARCHIVES += $(CURDIR)/../../edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a

USEPKG += wolfssl
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_ecc
USEMODULE += wolfssl
USEMODULE += wolfcrypt_cryptocell
# USEMODULE += wolfssl_debug
USEMODULE += wolfssl_rpk
USEMODULE += wolfssl_dtls
USEMODULE += wolfssl_tls13
USEMODULE += wolfssl_dtls13
else
CFLAGS += -DUSE_EDHOC # flag for the application code
INCLUDES += -I$(CURDIR)/../../edhoc-rs-FORK/target/include
ARCHIVES += $(CURDIR)/../../edhoc-rs-FORK/target/thumbv7em-none-eabihf/release/libedhoc_rs.a
# This is actually only needed in the RUST_CRYPTOCELL310 configuration
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384
CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=2

USEMODULE += gcoap
endif

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += sock_udp

# Modules used for the evauluation
FEATURES_OPTIONAL += periph_gpio
USEMODULE += periph_gpio_irq
USEMODULE += ztimer
USEMODULE += ztimer_msec

# optional and debug modules
CFLAGS += -Wno-error=unused-variable -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=pedantic -DLOG_LEVEL=LOG_INFO
USEMODULE += od
USEMODULE += fmt
USEMODULE += shell
USEMODULE += netutils
USEMODULE += random
USEMODULE += shell_cmds_default
USEMODULE += ps
USEMODULE += gnrc_icmpv6_echo

include $(RIOTBASE)/Makefile.include
