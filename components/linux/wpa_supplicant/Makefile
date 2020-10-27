################################################################################
ARCH              ?= arm
CROSS_COMPILE     ?= arm-hisiv600-linux-
PREFIX            ?=
LOCAL_PREFIX      ?= $(shell pwd)/../_install
################################################################################
BUILD_DIR         := $(OUT_DIR)/tools/wpa_supplicant
HOST              := $(patsubst %-,%,$(CROSS_COMPILE))
SRC               := wpa_supplicant-2.9
UTILS             := wpa_cli wpa_supplicant
UTILS_DIR         := $(BUILD_DIR)/$(SRC)/wpa_supplicant
TARGETS           := $(addprefix $(PREFIX)/$(TOOLS_DIR)/,wpa_supplicant)
################################################################################
export PKG_CONFIG_PATH=$(LOCAL_PREFIX)/lib/pkgconfig

all: $(TARGETS)

$(PREFIX)/$(TOOLS_DIR)/wpa_supplicant: $(UTILS_DIR)/config_finish
	make -C $(UTILS_DIR) CC=$(HOST)-gcc && \
	$(CROSS_COMPILE)strip $(UTILS_DIR)/wpa_supplicant && \
	test -d $(PREFIX)/$(TOOLS_DIR) || mkdir -p $(PREFIX)/$(TOOLS_DIR) && \
	cp -fv $(addprefix $(UTILS_DIR)/,$(UTILS)) $(PREFIX)/$(TOOLS_DIR)/

$(UTILS_DIR)/config_finish: $(BUILD_DIR)/$(SRC)
	@cp -fv $(UTILS_DIR)/defconfig $(UTILS_DIR)/.config
	@(echo "CONFIG_DRIVER_NL80211=y"; \
		echo "CONFIG_LIBNL32=y"; \
		echo "CONFIG_TLS=internal"; \
		echo "CONFIG_INTERNAL_LIBTOMMATH=y"; \
		echo "CFLAGS += -I$(LOCAL_PREFIX)/include"; \
		echo "LIBS += -L$(LOCAL_PREFIX)/lib"; \
		echo "LIBS_p += -L$(LOCAL_PREFIX)/lib") >> $(UTILS_DIR)/.config
	touch $@

$(BUILD_DIR)/$(SRC):
	test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	tar -xzf $(SRC).tar.gz -C $(BUILD_DIR)

clean:
	-rm -rf $(BUILD_DIR)

################################################################################
.PHONY: clean
################################################################################
