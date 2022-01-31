PKGDIR ?= .
#PKGNAME = wolftpm_measure_seal
L4DIR ?= ../../../l4re/src/l4
O = ../../../l4re/obj/l4/arm64

DEFINES += -DUSE_GETTIME
CXXFLAGS += -I/home/beleg/l4-wolftpm/include

TARGET = libwolftpm_measure_quote
SRC_CC = main.cc

REQUIRES_LIBS = libwolftpm
DEPENDS_LIBS = $(REQUIRES_LIBS)

include $(L4DIR)/mk/prog.mk
