# A simple Makefile for lib(libxxx.a)
# By Late Lee(http://www.latelee.org)

include $(COMPLIE_ROOT)/build/config/config.mk
include $(LITEOSTOPDIR)/config.mk
WIFI_DRIVER_DIR := $(COMPLIE_ROOT)/driver
include $(WIFI_DRIVER_DIR)/env_config.mk

INCLUDE_PATH += -I ./src
INCLUDE_PATH += -I $(COMPLIE_ROOT)/include \
                -I $(COMPLIE_ROOT)/include/interface/rom \
                -I $(COMPLIE_ROOT)/include/interface \
                -I $(COMPLIE_ROOT)/include/wifi \
                -I $(COMPLIE_ROOT)/driver/oam \
                -I $(COMPLIE_ROOT)/driver/oal \
                -I $(COMPLIE_ROOT)/driver/include \
                -I $(COMPLIE_ROOT)/components/liteos/iperf2/include \
                -I $(COMPLIE_ROOT)/components/liteos/Wi-FiTestSuite-9.2.0/inc

CFLAGS += $(LITEOS_CFLAGS) $(HI1131_WIFI_CFLAGS) $(INCLUDE_PATH)
CXXFLAGS += $(INCLUDE_PATH)

CFLAGS += -Werror

ifeq ($(CFG_SIGMA), y)
AT_FLAGS += -DCONFIG_SIGMA_TEST
endif
ifeq ($(CFG_MFG_FW), y)
AT_FLAGS += -DCONFIG_MFG_TEST
endif

BUILD  = $(ROOTOUT)/obj/at
TARGET_LIB_DIR=$(ROOTOUT)/lib
LIB = $(TARGET_LIB_DIR)/libat.a

#编译源文件目录
SRC_DIRS := ./src

SRCS := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
OBJS = $(patsubst %.c,$(BUILD)/%.o,$(SRCS))

ASFLAG += -Werror -Wall -Wextra -Wdate-time -Wtrampolines -Wfloat-equal -Wshadow -Wformat=2 -funsigned-char -freg-struct-return -fno-strict-aliasing -fno-common -fvisibility=hidden -fno-common -fstack-protector-strong
ifeq ($(CFG_KERNEL_SMP), y)
#添加-Wextra后，liteos引入了linux头文件，编译不过
AT_FLAGS += -Wdate-time -Wtrampolines -Wfloat-equal -Wshadow -Wformat=2 -funsigned-char -freg-struct-return -fno-strict-aliasing -fno-common -fvisibility=hidden -fno-common -fstack-protector-strong
AT_FLAGS += -D_PRE_LOSCFG_KERNEL_SMP
else
AT_FLAGS += -Wextra -Wdate-time -Wtrampolines -Wfloat-equal -Wshadow -Wformat=2 -funsigned-char -freg-struct-return -fno-strict-aliasing -fno-common -fvisibility=hidden -fno-common -fstack-protector-strong
endif
#该选项添加后liteos代码编译不过
#AT_FLAGS += -Wall
#规范建议：在Debug版本中实施，Release版本不实施
#AT_FLAGS += -ftrapv
AT_FLAGS += -DCONFIG_IPERF_SUPPORT -DCONFIG_WPS_SUPPORT

all: prepare  $(LIB)

#建立目标目录
prepare:
	mkdir -p $(BUILD);\
	for dir in $(SRC_DIRS);\
	do if [ -d $$dir ]; \
	then \
	mkdir -p  $(BUILD)/$$dir;\
	fi;\
	done
	$(Q)mkdir -p $(TARGET_LIB_DIR)

$(OBJS): $(BUILD)/%.o : %.c prepare
	@echo Compile  $<;
	@$(CC) $(CFLAGS) $(AT_FLAGS) $(MOD_INCLUDE) -c $< -o $@ ; \

$(LIB): $(OBJS)
	@$(Q)$(AR) $(ARFLAGS) $@ $(sort $(OBJS))

clean:
	$(Q)$(RM) -rf $(OBJS) $(LIB) $(BUILD) *.bak *~

.PHONY: all clean clean_target_lib prepare
