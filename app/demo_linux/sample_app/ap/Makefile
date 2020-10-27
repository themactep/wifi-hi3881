#===============================================================================
# export variable
#===============================================================================
ifeq ($(CFG_HI_EXPORT_FLAG),)
SDK_DIR := $(shell cd $(CURDIR)/../.. && /bin/pwd)

include $(SDK_DIR)/base.mak
endif

#CURDIR ?= $(shell pwd)
#CC := $(CROSS_COMPILE)gcc
#===============================================================================
# local variable
#===============================================================================
SAMPLE_IMAGES := sample_ap

CFLAGS = -Werror -funsigned-char -freg-struct-return -fno-strict-aliasing -Wtrampolines -Wdate-time -Wformat=2 -Wshadow -Wall -fpic -fpie -fno-common -Wfloat-equal -Wextra -fvisibility=hidden -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2 -O2 -pipe
#规范建议：在Debug版本中实施，Release版本不实施
#CFLAGS += -ftrapv

# 配置平台
ifneq ($(HISILICON_PLATFORM),)
CFLAGS += -DHISI_WIFI_PLATFORM_$(HISILICON_PLATFORM)
ifneq ($(findstring $(HISILICON_PLATFORM),HI3559 HI3556 HI3516EV300 HI3516EV100),)
$(warning  HISILICON_PLATFORM=$(HISILICON_PLATFORM))
else
$(warning  HISILICON_PLATFORM=$(HISILICON_PLATFORM), not support platform)
endif
else
$(warning  HISILICON_PLATFORM is empty)
endif

CFLAGS += -I$(CURDIR)/../../securec
CFLAGS += -I$(CURDIR)/../common
CFLAGS += -I$(CURDIR)/../../interface/include
CFLAGS += -D_GNU_SOURCE
#CFLAGS += -I/opt/hisi-linux/x86-arm/arm-himix100-linux/target/usr/include

LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie -Wl,-Bsymbolic -rdynamic -Wl,--no-undefined

LIBPATH := -L$(CURDIR)/../../interface/lib
LIBPATH += -L$(CURDIR)/../../securec
#LIBPATH += -L/opt/hisi-linux/x86-arm/arm-himix100-linux/target/usr/lib

AP_OBJ := sample_ap.o ../common/sample_common.o

DEPEND_LIBS := -lpthread -lwlanap -lhi_securec

#include $(SAMPLE_DIR)/hi_sample_rules.mak

.PHONY: all clean
all:$(SAMPLE_IMAGES)

sample_ap: $(AP_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBPATH) $(DEPEND_LIBS)

%.o: %.c
#	$(CC) $(BUILD_CFLGAS) -c $< -o $@ -I$(INCLUDE_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-@rm -f $(SAMPLE_IMAGES)
	-@rm -f $(AP_OBJ)
