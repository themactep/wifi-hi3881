################################################################################
ARCH			 ?= arm
CROSS_COMPILE            ?= arm-hisiv300-linux-
PREFIX                   ?=
LOCAL_PREFIX             ?= $(shell pwd)/../_install
################################################################################
BUILD_DIR                := $(OUT_DIR)/tools/hostapd
HOST                     := $(patsubst %-,%,$(CROSS_COMPILE))
SRC                      := hostapd-2.9
UTILS                    := hostapd
UTILS_DIR                := $(BUILD_DIR)/$(SRC)/hostapd
TARGETS		         := $(addprefix $(PREFIX)/$(TOOLS_DIR)/,$(UTILS))
################################################################################
export PKG_CONFIG_PATH=$(LOCAL_PREFIX)/lib/pkgconfig

all: $(TARGETS)

$(PREFIX)/$(TOOLS_DIR)/$(UTILS): $(UTILS_DIR)/config_finish
	make -C $(UTILS_DIR) CC=$(HOST)-gcc && \
	$(CROSS_COMPILE)strip $(UTILS_DIR)/$(UTILS) && \
	test -d $(PREFIX)/$(TOOLS_DIR) || mkdir -p $(PREFIX)/$(TOOLS_DIR) && \
	cp -fv $(UTILS_DIR)/$(UTILS) $(PREFIX)/$(TOOLS_DIR)/

$(UTILS_DIR)/config_finish: $(BUILD_DIR)/$(SRC)
	@(echo -e "\n# The follow config add by Makefile"; \
		echo "CONFIG_DRIVER_NL80211=y"; \
		echo "CONFIG_LIBNL32=y"; \
		echo "CONFIG_IEEE80211N=y"; \
		echo "CONFIG_TLS=internal"; \
		echo "CONFIG_INTERNAL_LIBTOMMATH=y"; \
		echo "CFLAGS += -I$(LOCAL_PREFIX)/include"; \
		echo "LIBS += -L$(LOCAL_PREFIX)/lib") >> $(UTILS_DIR)/.config
	touch $@

$(BUILD_DIR)/$(SRC):
	test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	tar -xzf $(SRC).tar.gz -C $(BUILD_DIR)

clean:
	-rm -rf $(BUILD_DIR)

################################################################################
.PHONY: clean
################################################################################
