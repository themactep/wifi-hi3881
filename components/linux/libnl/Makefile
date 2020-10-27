################################################################################
ARCH		     ?= arm
CROSS_COMPILE        ?= arm-hisiv300-linux-
PREFIX               ?=
LOCAL_PREFIX         ?= $(shell pwd)/../_install
################################################################################
BUILD_DIR            := $(OUT_DIR)/tools/libnl
HOST                 := arm-linux
CC                   := $(CROSS_COMPILE)gcc
SRC                  := libnl-3.5.0
UTILS                := libnl-3.so.200.26.0 libnl-genl-3.so.200.26.0
TARGETS		     := $(addprefix $(PREFIX)/$(LIBS_DIR)/,$(UTILS))
################################################################################

all: $(TARGETS)

$(PREFIX)/$(LIBS_DIR)/$(UTILS): $(LOCAL_PREFIX)/$(UTILS)
	test -d $(PREFIX)/$(LIBS_DIR) || mkdir -p $(PREFIX)/$(LIBS_DIR)
	cp -rv $(LOCAL_PREFIX)/$(LIBS_DIR)/libnl-3.so.200.26.0  $(PREFIX)/$(LIBS_DIR)
	cp -rv $(LOCAL_PREFIX)/$(LIBS_DIR)/libnl-genl-3.so.200.26.0  $(PREFIX)/$(LIBS_DIR)

$(LOCAL_PREFIX)/$(UTILS): $(BUILD_DIR)/$(SRC)
	cd $(BUILD_DIR)/$(SRC) && \
		./configure --host=$(HOST) --prefix=$(LOCAL_PREFIX) CC=$(CC) && \
		make && \
		make install && \
	cd -
	cp -rv $(BUILD_DIR)/$(SRC)/include/linux-private/linux $(LOCAL_PREFIX)/include/

$(BUILD_DIR)/$(SRC):
	test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	tar -zxf $(SRC).tar.gz -C $(BUILD_DIR)

clean:
	-rm -rf $(BUILD_DIR) $(LOCAL_PREFIX)/$(LIBS_DIR)/$(UTILS)

################################################################################
.PHONY: clean
################################################################################
