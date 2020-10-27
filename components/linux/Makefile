################################################################################
#Compile tools and kernel configure
ARCH		:= mips
CROSS_COMPILE	:= mips-linux-uclibc-gnu-
PREFIX		:= $(shell pwd)/out
OUT_DIR		:= $(shell pwd)/build_tmp
################################################################################
NL_LIB        = libnl
TOOLS         = hostapd wpa_supplicant
LOCAL_PREFIX  = $(OUT_DIR)/tools/_install
BUILD_TOOLS   = $(patsubst %,%.tmp,${TOOLS})
LIBS_DIR      = lib
TOOLS_DIR     = tools
################################################################################
MKFLAGS       = ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) \
		PREFIX=$(PREFIX) \
		OUT_DIR=$(OUT_DIR) \
		LOCAL_PREFIX=$(LOCAL_PREFIX) \
		TOOLS_DIR=$(TOOLS_DIR)	\
		LIBS_DIR=$(LIBS_DIR)

################################################################################
tools: echo.temp $(NL_LIB) $(BUILD_TOOLS)

echo.temp:
	@echo "Build wifi tool suit"
	@test -d $(OUT_DIR)/tools || mkdir -p $(OUT_DIR)/tools

$(NL_LIB):echo.temp
	@echo -e "\033[31m""Build libnl ...""\033[00m"
	make -C $(NL_LIB) $(MKFLAGS)

%.tmp:$(NL_LIB)
	@echo -e "\033[31m""Build $(patsubst %.tmp,%,$@) ...""\033[00m"
	make -C $(patsubst %.tmp,%,$@) $(MKFLAGS)

clean:
	for i in $(TOOLS); do ( \
		make -C $$i $(MKFLAGS) clean; \
	) done
	make -C libnl $(MKFLAGS) clean;
	-rm -rf $(LOCAL_PREFIX)
	-rm -rf $(OUT_DIR)
	-rm -rf $(PREFIX)
################################################################################

.PHONY: clean  tools
