#===============================================================================
# export variable
#===============================================================================
ifeq ($(CFG_HI_EXPORT_FLAG),)
SAMPLE_DIR := $(shell cd $(CURDIR)/.. && /bin/pwd)

include $(SAMPLE_DIR)/base.mak
endif

#===============================================================================
# local variable
#===============================================================================
#CFLAGS += $(CFG_HI_CFLAGS)
#CFLAGS += -I$(SDK_DIR)/source/common/include
CFLAGS = -Werror -funsigned-char -freg-struct-return -fno-strict-aliasing -Wtrampolines -Wdate-time -Wformat=2 -Wshadow -Wall -fpic -fpie -fno-common -Wfloat-equal -Wextra -fvisibility=hidden -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2 -O2 -pipe
#规范建议：在Debug版本中实施，Release版本不实施
#CFLAGS += -ftrapv

CFLAGS += -I$(CURDIR)/src/util
CFLAGS += -I$(CURDIR)/include
CFLAGS += -I$(SAMPLE_DIR)/securec
CFLAGS += -I$(SAMPLE_DIR)/sample_app/ap
CFLAGS += -D_GNU_SOURCE
CFLAGS += -DDEBUG

ifeq ($(CFG_HI_WIFI_DEVICE_HI3881),y)
CFLAGS += -DWIFI_DEVICE_HI3881
endif

LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie -Wl,-Bsymbolic -rdynamic -Wl,--no-undefined
LIBPATH := -L$(CURDIR)/../securec
DEPEND_LIBS := -lpthread -lhi_securec

target :=
ifeq ($(CFG_HI_WIFI_MODE_STA),y)
src_sta := $(CURDIR)/src/sta/hi_wlan_sta.c
src_sta += $(CURDIR)/src/sta/wlan_sm.c
src_sta += $(CURDIR)/src/sta/wlan_hal.c
src_sta += $(CURDIR)/src/util/wlan_util.c
ifeq ($(CFG_HI_WIFI_MODE_P2P),y)
src_sta += $(CURDIR)/src/sta/hi_wlan_p2p.c
endif

objs_sta = $(src_sta:.c=.o)

LIB_WIFI_STA  := libwlansta

target += $(LIB_WIFI_STA).a $(LIB_WIFI_STA).so
endif

ifeq ($(CFG_HI_WIFI_MODE_AP),y)
src_ap := $(CURDIR)/src/ap/hi_wlan_ap.c
src_ap += $(CURDIR)/src/util/wlan_util.c

objs_ap = $(src_ap:.c=.o)

LIB_WIFI_AP   := libwlanap

target += $(LIB_WIFI_AP).a $(LIB_WIFI_AP).so
endif

#===============================================================================
# rules
#===============================================================================
.PHONY: all clean distclean install uninstall

all:$(target)
	mkdir -p $(CURDIR)/lib
	$(AT)mv -f  *.a   $(CURDIR)/lib
	$(AT)mv -f  *.so   $(CURDIR)/lib

ifeq ($(CFG_HI_WIFI_MODE_STA),y)
$(LIB_WIFI_STA).a: $(objs_sta)
	$(AT)$(AR) -rc -o $@ $^

$(LIB_WIFI_STA).so: $(objs_sta)
	$(AT)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBPATH) $(DEPEND_LIBS)
endif

ifeq ($(CFG_HI_WIFI_MODE_AP),y)
$(LIB_WIFI_AP).a: $(objs_ap)
	$(AT)$(AR) -rc -o $@ $^

$(LIB_WIFI_AP).so: $(objs_ap)
	$(AT)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBPATH) $(DEPEND_LIBS)
endif

%.o: %.c
	$(AT)$(CC) $(CFLAGS) -fPIC -c $< -o $@

install: all
ifeq ($(CFG_HI_WIFI_MODE_STA),y)
	$(AT)cp -rvf ./lib/$(LIB_WIFI_STA).so $(SHARED_LIB_DIR)/
	$(AT)cp -rvf ./lib/$(LIB_WIFI_STA).a $(STATIC_LIB_DIR)/
	$(AT)cp -rvf ./include/hi_wlan.h $(INCLUDE_DIR)/
endif
ifeq ($(CFG_HI_WIFI_MODE_AP),y)
	$(AT)cp -rvf ./lib/$(LIB_WIFI_AP).so $(SHARED_LIB_DIR)/
	$(AT)cp -rvf ./lib/$(LIB_WIFI_AP).a $(STATIC_LIB_DIR)/
	$(AT)cp -rvf ./include/hi_wlan.h $(INCLUDE_DIR)/
endif

uninstall:
ifeq ($(CFG_HI_WIFI_MODE_STA),y)
	$(AT)rm -rvf $(SHARED_LIB_DIR)/$(notdir $(LIB_WIFI_STA).so)
	$(AT)rm -rvf $(STATIC_LIB_DIR)/$(notdir $(LIB_WIFI_STA).a)
	$(AT)rm -rvf $(INCLUDE_DIR)/$(notdir hi_wlan.h)
endif
ifeq ($(CFG_HI_WIFI_MODE_AP),y)
	$(AT)rm -rvf $(SHARED_LIB_DIR)/$(notdir $(LIB_WIFI_AP).so)
	$(AT)rm -rvf $(STATIC_LIB_DIR)/$(notdir $(LIB_WIFI_AP).a)
	$(AT)rm -rvf $(INCLUDE_DIR)/$(notdir hi_wlan.h)
endif

clean:
	$(AT)rm -rf $(CURDIR)/src/sta/*.o
	$(AT)rm -rf $(CURDIR)/src/ap/*.o
	$(AT)rm -rf $(CURDIR)/src/util/*.o
	$(AT)rm -rf $(CURDIR)/lib

distclean: clean
