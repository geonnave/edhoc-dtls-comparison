# name of your application
APPLICATION = edhoc-dtls-1_3-comparison
BOARD ?= nrf52840dk
RIOTBASE ?= $(CURDIR)/../../RIOT-FORK
DEVELHELP ?= 1
QUIET ?= 1

SEC ?= cc310_only

ifeq (dtls, $(SEC))
CFLAGS += -DUSE_DTLS13 # flag for the application code

CFLAGS += -DDTLS_DEFAULT_PORT=$(DTLS_PORT) -DDTLS_WOLFSSL -Wno-unused-parameter -Wno-unused-variable -DLOG_LEVEL=LOG_DEBUG
# A larger stack size is required if using ECC or RSA
# CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(4*THREAD_STACKSIZE_DEFAULT\)
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384 -DTHREAD_STACKSIZE_MAIN=16384
# CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=32768 -DISR_STACKSIZE=32768 -DTHREAD_STACKSIZE_MAIN=32768

INCLUDES += -I/home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/include
# ARCHIVES += /home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310_0.9.13.a
ARCHIVES += /home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a

USEPKG += wolfssl
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_ecc
USEMODULE += wolfcrypt_cryptocell
USEMODULE += wolfssl
# USEMODULE += wolfssl_debug
USEMODULE += wolfssl_dtls
USEMODULE += wolfssl_tls13
USEMODULE += wolfssl_dtls13
else ifeq (cc310_only, $(SEC))
CFLAGS += -DCC310_ONLY # flag for the application code

CFLAGS += -Wno-unused-parameter -Wno-unused-variable -DLOG_LEVEL=LOG_DEBUG
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384 -DTHREAD_STACKSIZE_MAIN=16384

INCLUDES += -I/home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/include
ARCHIVES += /home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a
# ARCHIVES += /home/gfedrech/Developer/inria/dev/edhoc-rs-FORK/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310_0.9.13.a

else
CFLAGS += -DUSE_EDHOC # flag for the application code

INCLUDES += -I$(CURDIR)/../../edhoc-rs-FORK/target/include
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

include $(RIOTBASE)/Makefile.include
