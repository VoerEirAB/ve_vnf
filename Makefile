ifeq ($(RTE_SDK),)
    RTE_SDK=/opt/dpdk
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = ve_vnf.a
LIBABIVER := 1

# binary name
APP = ve_vnf

# all source are stored in SRCS-y
SRCS-y := main.c

CFLAGS += -O3
#CFLAGS += $(WERROR_FLAGS)
CFLAGS:=$(filter-out -Werror=unused-variable,$(CFLAGS))

SRCS-y += icmp_arp.c
SRCS-y += cmd_parser.c
SRCS-y += ip.c

SYMLINK-y-include := ip.h utils.h parser.h icmp.h

include $(RTE_SDK)/mk/rte.extapp.mk
