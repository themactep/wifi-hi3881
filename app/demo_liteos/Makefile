#!/bin/bash

LITEOSTOPDIR ?= ../..
include $(COMPLIE_ROOT)/build/config/config.mk

SAMPLE_OUT = $(COMPLIE_ROOT)/output/bin
OBJ_DIR = .

ifeq ($(CFG_MFG_FW), y)
TARGET = mfg_sample
else
TARGET = sample
endif

include $(LITEOSTOPDIR)/config.mk
RM = -rm -rf

SAMPLE_INCLUDE := -I $(COMPLIE_ROOT)/include \
                  -I $(COMPLIE_ROOT)/components/liteos/iperf2/include \
                  -I $(COMPLIE_ROOT)/components/liteos/at/src \
                  -I $(COMPLIE_ROOT)/components/liteos/wpa_supplicant \
                  -I $(COMPLIE_ROOT)/components/liteos/wpa_supplicant/src \
                  -I $(COMPLIE_ROOT)/components/liteos/wpa_supplicant/src/utils

OUT := $(COMPLIE_ROOT)/out/

ifneq ($(HISILICON_PLATFORM),)
LITEOS_CFLAGS += -DHISI_WIFI_PLATFORM_$(HISILICON_PLATFORM)
ifneq ($(findstring $(HISILICON_PLATFORM),HI3559 HI3556 HI3516EV300 HI3516EV100),)
$(warning  HISILICON_PLATFORM=$(HISILICON_PLATFORM))
else
$(warning  HISILICON_PLATFORM=$(HISILICON_PLATFORM), not support platform)
endif
else
$(warning  HISILICON_PLATFORM is empty)
endif
#wifi driver feature need move to right position
LITEOS_CFLAGS +=-D_PRE_WLAN_FEATURE_HIPRIV
ifeq ($(UART), y)
LITEOS_CFLAGS += -D_TYPE_UART_MSG
else
LITEOS_CFLAGS += -D_TYPE_PMC_PWR_WAKEUP
endif

LITEOS_CFGLAS += -DCONFIG_NO_CONFIG_WRITE

LITEOS_LIBDEP += -lltoswpa -lwpa -lhi3881 -lat -liperf2
ifeq ($(CFG_SIGMA), y)
LITEOS_LIBDEP += -lwifitest
LITEOS_CFLAGS += -D_CONFIG_SIGMA_TEST
endif
LITEOS_LDFLAGS += -L$(ROOTOUT)/lib
DEMO_CFLAGS := -Werror -Wall -fsigned-char -freg-struct-return -fno-strict-aliasing -Wtrampolines -Wdate-time -Wformat=2 -Wshadow -Wfloat-equal -fvisibility=hidden -fno-common -fstack-protector-strong
DEMO_CFLAGS += $(SAMPLE_INCLUDE)
#添加后liteos代码编译不过
#DEMO_CFLAGS += -Wextra
#规范建议：在Debug版本中实施，Release版本不实施
#DEMO_CFLAGS += -ftrapv
LITEOS_LIBDEPS := --start-group $(LITEOS_LIBDEP) --end-group

SRCS = $(wildcard *.c)
#ifneq ($(OUT)/lib/libipcm.a, $(wildcard $(OUT)/lib/libipcm.a))
#	@echo "$(OUT)"
#	@cp -rf $(LITEOS_CPU_TYPE)/*.a $(OUT)/lib
#endif

OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))

all: prepare $(TARGET)

#建立目标目录
prepare:
	mkdir -p $(SAMPLE_OUT);

clean:
	@$(RM) *.o  $(TARGET) *.bin *.map *.asm

$(TARGET): $(OBJS)
	@echo "generate $@"
	@$(LD) $(LITEOS_LDFLAGS) --gc-sections -Map=$(SAMPLE_OUT)/$(TARGET).map -o $(SAMPLE_OUT)/$(TARGET) $(OBJS) $(LITEOS_LIBDEPS) $(LITEOS_TABLES_LDFLAGS)
	$(OBJCOPY) -O binary $(SAMPLE_OUT)/$(TARGET) $(SAMPLE_OUT)/$(TARGET).bin
	$(OBJDUMP) -d $(SAMPLE_OUT)/$(TARGET) >$(SAMPLE_OUT)/$(TARGET).asm

$(OBJS): $(OBJ_DIR)/%.o : %.c
	@echo "Compiling $<"
	@$(CC) $(DEMO_CFLAGS) $(LITEOS_CFLAGS) -c $< -o $@


.PHONY: all clean
