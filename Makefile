################################################################################
# Main Makefile for 3881 linux
# History
# Author     Date          Version
# hisilion   2020-3-29     V1.0
################################################################################
KDIR ?= /home/paul/output/cinnado_d1_t31l/build/linux-a4417fd29af2f77a2b303bccb969b49c105fedc0
CROSS_COMPILE ?= mipsel-linux-

CURDIR := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)
SYSDIR ?= $(CURDIR)
PRJ_ROOT=$(CURDIR)
COMPLIE_ROOT := $(CURDIR)
WIFI_DRIVER_DIR=$(PRJ_ROOT)/driver

export PRJ_ROOT
export SYSDIR
export WIFI_DRIVER_DIR
export COMPLIE_ROOT

MAKE = make

TAGETS_BUILD :=
TAGETS_CLEAN :=

.PHONY: all linux_driver tools sample clean_prepare clean linux_driver_clean

all: linux_driver

clean:clean_prepare linux_driver_clean sample_clean tools_clean

clean_prepare:
	$(RM) -rf $(SYSDIR)/build/build_tmp
	$(RM) -rf $(SYSDIR)/output

linux_driver:
	make ARCH=mips -C ${WIFI_DRIVER_DIR} WIFI_DRIVER_DIR=${WIFI_DRIVER_DIR} CROSS_COMPILE=${CROSS_COMPILE} HISILICON_PLATFORM=$(HISILICON_PLATFORM) KDIR=${KDIR}

clean:
	make ARCH=mips -C ${WIFI_DRIVER_DIR} WIFI_DRIVER_DIR=${WIFI_DRIVER_DIR} CROSS_COMPILE=${CROSS_COMPILE} HISILICON_PLATFORM=$(HISILICON_PLATFORM) KDIR=${KDIR} clean

sample:
	$(MAKE) -C app/demo_linux HISILICON_PLATFORM=$(HISILICON_PLATFORM) all

tools:
	$(MAKE) -C components/linux HISILICON_PLATFORM=$(HISILICON_PLATFORM) tools

sample_clean:
	$(MAKE) -C app/demo_linux HISILICON_PLATFORM=$(HISILICON_PLATFORM) clean

linux_driver_clean:
	$(MAKE) -C ${WIFI_DRIVER_DIR} WIFI_DRIVER_DIR=${WIFI_DRIVER_DIR} CROSS_COMPILE=${CROSS_COMPILE} HISILICON_PLATFORM=$(HISILICON_PLATFORM) KDIR=${KDIR} clean

tools_clean:
	$(MAKE) -C components/linux HISILICON_PLATFORM=$(HISILICON_PLATFORM) clean
