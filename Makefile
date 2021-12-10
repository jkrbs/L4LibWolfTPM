PKGDIR  ?= .
L4DIR   ?= ../l4re/src/l4

O=../l4re/obj/l4/arm64

TARGET          = wolftpm
SRC_C         	= tpm2_packet.c tpm2_param_enc.c tpm2.c tpm2_tis.c 
SRC_CC			= tpm_io.cc tpm2_wrap.cc extend.cc
include $(L4DIR)/mk/prog.mk
