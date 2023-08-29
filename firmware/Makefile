RIOTBASE ?= $(CURDIR)/../../../dev/RIOT-FORK
EDHOC_RS_DIR ?= $(CURDIR)/../../../dev/edhoc-rs-FORK
BOARD ?= nrf52840dk
DEVELHELP ?= 1

SEC ?= edhoc
MODE ?= shell

APPLICATION = edhoc-dtls-1_3-comparison-$(SEC)-$(MODE)

ifeq (eval, $(MODE))
TIMES ?= 3
CFLAGS += -DEVALUATION_MODE -DEVALUATION_TIMES=$(TIMES)
endif

# cryptocell310's RNG requires a large stack size
CFLAGS += -DTHREAD_STACKSIZE_MAIN=16384 -DGCOAP_STACK_SIZE=8192+512

ifeq (dtls, $(SEC))
 # flags for the application code
CFLAGS += -DUSE_DTLS13
CFLAGS += -DDTLS_RPK # or -DDTLS_CERT

CFLAGS += -DDTLS_WOLFSSL
INCLUDES += -I$(EDHOC_RS_DIR)/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/include
ARCHIVES += $(EDHOC_RS_DIR)/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a

USEPKG += wolfssl
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_ecc
USEMODULE += wolfcrypt_cryptocell
USEMODULE += wolfssl
USEMODULE += wolfssl_static_memory
USEMODULE += wolfssl_rpk
USEMODULE += wolfssl_dtls
USEMODULE += wolfssl_tls13
USEMODULE += wolfssl_dtls13
else
CFLAGS += -DUSE_EDHOC # flag for the application code
CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=2
INCLUDES += -I$(EDHOC_RS_DIR)/target/include
ARCHIVES += $(EDHOC_RS_DIR)/target/thumbv7em-none-eabihf/release/libedhoc_rs.a

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
USEMODULE += ztimer
USEMODULE += ztimer_msec

USEMODULE += shell

# debug configurations
CFLAGS += -DLOG_LEVEL=LOG_INFO
# USEMODULE += wolfssl_debug

CFLAGS += -Wno-error=unused-variable -Wno-error=unused-function -Wno-error=unused-parameter -Wno-error=pedantic
USEMODULE += shell_cmds_default
USEMODULE += ps
# USEMODULE += od
# USEMODULE += fmt
# USEMODULE += netutils
# USEMODULE += random
# USEMODULE += gnrc_icmpv6_echo

include $(RIOTBASE)/Makefile.include
