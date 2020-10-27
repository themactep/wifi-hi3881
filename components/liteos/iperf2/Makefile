# A simple Makefile for lib(libxxx.a)
# By Late Lee(http://www.latelee.org)
include $(LITEOSTOPDIR)/config.mk

INCLUDE_PATH += -I  include
INCLUDE_PATH += -I $(COMPLIE_ROOT)/include

CFLAGS += $(LITEOS_CFLAGS) $(INCLUDE_PATH)
CXXFLAGS += $(INCLUDE_PATH)
ifeq ($(LOSCFG_DEBUG_CLOSE_PRINT), y)
CFLAGS += -DIPERF_CLOSE_PRINT
endif

CFLAGS += -Werror -Wall -Wextra -fsigned-char -freg-struct-return -fno-strict-aliasing -Wtrampolines -Wdate-time -Wformat=2 -Wshadow -Wfloat-equal -fvisibility=hidden -fno-common -fstack-protector-strong
#规范建议：在Debug版本中实施，Release版本不实施
#CFLAGS += -ftrapv

BUILD  = $(ROOTOUT)/obj/iperf2
TARGET_LIB_DIR=$(ROOTOUT)/lib
LIB = $(TARGET_LIB_DIR)/libiperf2.a

#编译源文件目录
SRC_DIRS := ./src

SRCS := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
OBJS = $(patsubst %.c,$(BUILD)/%.o,$(SRCS))

all:  prepare $(LIB)

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

$(OBJS): $(BUILD)/%.o : %.c
	$(Q)echo Compile  $<;
	@$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(OBJS)
	$(Q)echo Compile  $<;
	@$(AR) $(ARFLAGS) $@ $(sort $(OBJS))

clean:
	@$(RM) $(LIB)  $(BUILD) *.bak *~

.PHONY: all clean
