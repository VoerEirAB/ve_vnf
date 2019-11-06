ifeq ($(RTE_SDK),)
    RTE_SDK=/opt/dpdk
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

DIRS-y += receiver
DIRS-y += reflector

include $(RTE_SDK)/mk/rte.extapp.mk