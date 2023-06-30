# name of your application
APPLICATION = c-wrapper-riot

# If no BOARD is found in the environment, use this default:
BOARD ?= nrf52840dk

ifeq (dtls, $(PROTOCOL))
  CFLAGS += -DUSE_DTLS13
else
  CFLAGS += -DUSE_EDHOC
endif

INCLUDES += -I$(CURDIR)/../../edhoc-rs-FORK/include
ARCHIVES += $(CURDIR)/../../edhoc-rs-FORK/target/thumbv7em-none-eabihf/release/libedhoc_rs.a

# This is actually only needed in the RUST_CRYPTOCELL310 configuration
CFLAGS += -DTHREAD_STACKSIZE_DEFAULT=16384 -DISR_STACKSIZE=16384

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += sock_udp

USEMODULE += od

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../../RIOT

DEVELHELP ?= 1

include $(RIOTBASE)/Makefile.include
