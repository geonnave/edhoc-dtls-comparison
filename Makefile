# name of your application
APPLICATION = edhoc-dtls-1_3-comparison

# If no BOARD is found in the environment, use this default:
BOARD ?= nrf52840dk

ifeq (dtls, $(PROTOCOL))
CFLAGS += -DUSE_DTLS13 # flag for the application code

CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL -Wno-unused-parameter -Wno-unused-variable -DLOG_LEVEL=LOG_DEBUG
# A larger stack size is required if using ECC or RSA
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(4*THREAD_STACKSIZE_DEFAULT\)

USEPKG += wolfssl
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_ecc
USEMODULE += wolfssl
# USEMODULE += wolfssl_debug
USEMODULE += wolfssl_dtls
USEMODULE += wolfssl_tls13
USEMODULE += wolfssl_dtls13
else
CFLAGS += -DUSE_EDHOC # flag for the application code

INCLUDES += -I$(CURDIR)/../../edhoc-rs-FORK/include
ARCHIVES += $(CURDIR)/../../edhoc-rs-FORK/target/thumbv7em-none-eabihf/release/libedhoc_rs.a

# This is actually only needed in the RUST_CRYPTOCELL310 configuration
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384
endif

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += sock_udp

USEMODULE += od
USEMODULE += shell
USEMODULE += shell_cmds_default

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../RIOT

DEVELHELP ?= 1

include $(RIOTBASE)/Makefile.include
