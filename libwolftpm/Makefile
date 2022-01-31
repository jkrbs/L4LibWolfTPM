PKGDIR  ?= .
L4DIR   ?= ../../l4re/src/l4
O =../../l4re/obj/l4/arm64

#DEFINES += -DDEBUG_WOLFTPM=1 -DWOLFTPM_DEBUG_VERBOSE=1

CFLAGS += -I/home/beleg/l4-wolftpm/include
CXXFLAGS += -I/home/beleg/l4-wolftpm/include

TARGET          = libwolftpm.a libwolftpm.p.a 
SRC_C         	= tpm2_packet.c tpm2_param_enc.c tpm2.c tpm2_tis.c
SRC_CC			= tpm_io.cc tpm2_wrap.cc tpm_test_keys.cc
include $(L4DIR)/mk/lib.mk
