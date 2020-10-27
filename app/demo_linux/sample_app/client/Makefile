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
SAMPLE_IMAGES := sample_cli

CFLAGS = -Werror -funsigned-char -freg-struct-return -fno-strict-aliasing -Wtrampolines -Wdate-time -Wformat=2 -Wshadow -Wall -fpic -fpie -fno-common -Wfloat-equal -Wextra -fvisibility=hidden -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2 -O2 -pipe
#规范建议：在Debug版本中实施，Release版本不实施
#CFLAGS += -ftrapv

CFLAGS += -I$(CURDIR)/../../securec
CFLAGS += -I$(CURDIR)/../../interface/include
CFLAGS += -D_GNU_SOURCE

LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie -Wl,-Bsymbolic -rdynamic -Wl,--no-undefined

LIBPATH := -L$(CURDIR)/../../interface/lib
LIBPATH += -L$(CURDIR)/../../securec

STA_OBJ := sample_cli.o \

DEPEND_LIBS := -lpthread -lwlansta -lhi_securec

#include $(SAMPLE_DIR)/hi_sample_rules.mak
.PHONY: all clean
all:$(SAMPLE_IMAGES)

sample_cli: $(STA_OBJ)
	$(CC) -o $@ $^ $(LIBPATH) $(DEPEND_LIBS) $(LDFLAGS)

%.o: %.c
#	$(CC) $(BUILD_CFLGAS) -c $< -o $@ -I$(INCLUDE_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-@rm -f $(SAMPLE_IMAGES)
	-@rm -f $(STA_OBJ)
