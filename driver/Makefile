
KDIR ?= /home/shell/linux-4.9.y
CROSS_COMPILE ?= mips-linux-uclibc-gnu-

##################path of compile file :start###############
#####wifi#####
OAL_PATH := oal/
OAM_PATH := oam/
FRW_PATH := frw/
MAC_PATH := mac/common/
HMAC_PATH := mac/hmac/
HCC_PATH := hcc/
WAL_PATH := wal/
SEC_PATH := libsec/
##################path of compile file :end###############

$(warning WIFI_DRIVER_DIR=$(WIFI_DRIVER_DIR))
include $(WIFI_DRIVER_DIR)/env_config.mk

HI1131_HOST_CFLAGS += -std=gnu99 -Wno-declaration-after-statement -fsigned-char -freg-struct-return -Wtrampolines -Wfloat-equal -fvisibility=hidden
#HI1131_HOST_CFLAGS += -std=gnu99 -Werror -Wno-declaration-after-statement -fsigned-char -freg-struct-return -Wtrampolines -Wdate-time -Wfloat-equal -fvisibility=hidden
HI1131_HOST_CFLAGS += -D_FORTIFY_SOURCE=2 -pipe
HI1131_HOST_CFLAGS += -Os
#该选项导致linux内核接口编译报错
#HI1131_HOST_CFLAGS += -Wshadow
#该选项导致linux内核接口编译报错
#HI1131_HOST_CFLAGS += -Wextra
#该选项导致linux内核接口编译报错
#HI1131_HOST_CFLAGS += -Wformat=2
#规范建议：在Debug版本中实施，Release版本不实施
#CFLAGS += -ftrapv

HI1131_HOST_CFLAGS += $(HI1131_WIFI_CFLAGS)

$(warning  HI1131_HOST_CFLAGS=$(HI1131_HOST_CFLAGS))

####################################### platform module start #########################################
oal-objs := oal_netbuf.o oal_util.o oal_net.o

oal-objs += oal_cfg80211.o oal_sdio_host.o oal_kernel_file.o exception_rst.o  plat_board_common_sdio.o plat_firmware.o plat_pm.o plat_pm_wlan.o plat_sdio.o oal_chr.o

oal-objs := $(addprefix $(OAL_PATH),$(oal-objs))
oal-flash-objs := oal_main.o
oal-flash-objs := $(addprefix $(OAL_PATH),$(oal-flash-objs))

oam-objs := oam_main.o
oam-objs := $(addprefix $(OAM_PATH),$(oam-objs))

plat-objs += $(oal-objs)
plat-flash-objs += $(oam-objs)
plat-flash-objs += $(oal-flash-objs)

#####platform rom modules #####
oam-rom-objs := oam_log.o
oam-rom-objs := $(addprefix $(OAM_PATH),$(oam-rom-objs))
frw-rom-objs += frw_event.o frw_event_sched.o frw_main.o frw_task.o frw_timer.o
frw-rom-objs := $(addprefix $(FRW_PATH),$(frw-rom-objs))
oal-rom-objs += oal_mem.o
oal-rom-objs := $(addprefix $(OAL_PATH),$(oal-rom-objs))

plat-rom-objs += $(frw-rom-objs)
plat-rom-objs += $(oal-rom-objs)
plat-rom-objs += $(oam-rom-objs)
####################################### platform module end #########################################
####################################### securec lib start  #########################################
sec-objs += memcpy_s.o memmove_s.o memset_s.o strcat_s.o strcpy_s.o strncat_s.o strncpy_s.o strtok_s.o \
            snprintf_s.o vsnprintf_s.o secureprintoutput_a.o
sec-objs := $(addprefix $(SEC_PATH),$(sec-objs))
plat-flash-objs += $(sec-objs)

####################################### securec lib end #########################################
####################################### wifi module start #########################################
hmac-objs := hmac_11i.o hmac_blockack.o hmac_chan_mgmt.o hmac_config.o hmac_crypto_tkip.o \
             hmac_device.o hmac_encap_frame.o hmac_encap_frame_ap.o hmac_encap_frame_sta.o hmac_frag.o hmac_fsm.o hmac_main.o \
             hmac_mgmt_ap.o hmac_mgmt_bss_comm.o hmac_mgmt_classifier.o hmac_mgmt_sta.o hmac_protection.o hmac_user.o \
             hmac_rx_data.o hmac_tx_data.o hmac_rx_filter.o hmac_scan.o hmac_sme_sta.o hmac_tx_amsdu.o hmac_vap.o \
             hmac_event.o
ifeq ($(CFG_RF_110X_CALI_DPD), y)
hmac-objs += hmac_cali_dpd.o
endif
ifeq ($(CFG_EDCA_OPT_AP), y)
hmac-objs += hmac_edca_opt.o
endif
ifeq ($(CFG_P2P), y)
hmac-objs += hmac_p2p.o
endif
ifeq ($(CFG_TCP_OPT), y)
hmac-objs += hmac_tcp_opt.o
endif
ifeq ($(CFG_TX_CLASSIFY_LAN_TO_WLAN), y)
hmac-objs += hmac_traffic_classify.o
endif
ifeq ($(CFG_WOW), y)
hmac-objs += hmac_wow.o
endif
ifeq ($(CFG_UAPSD), y)
hmac-objs += hmac_uapsd.o
endif
ifeq ($(CFG_ANY), y)
hmac-objs += hmac_any.o
endif
ifeq ($(CFG_WAPI), y)
hmac-objs += hmac_wapi.o hmac_wapi_wpi.o hmac_wapi_sms4.o
endif
hmac-objs := $(addprefix $(HMAC_PATH),$(hmac-objs))

wal-objs  := wal_customize.o wal_cfg80211.o wal_11d.o wal_hipriv.o wal_event_msg.o hi_wifi_driver_api.o wal_linux_flowctl.o wal_ioctl.o wal_event.o wal_scan.o \
             wal_main.o wal_regdb.o wal_net.o
ifeq ($(LOSCFG_DAQ), y)
wal-objs  += wal_maintenance.o
endif
ifeq ($(CFG_LITEOS), y)
wal-objs  += wal_wpa_ioctl.o
wal-objs  += wal_cfg80211_apt.o
endif
wal-objs  := $(addprefix $(WAL_PATH),$(wal-objs))

mac-objs  := mac_data.o mac_device.o mac_frame.o mac_ie.o mac_user.o mac_vap.o mac_mib.o mac_pm_driver.o
mac-objs  := $(addprefix $(MAC_PATH),$(mac-objs))

hcc-objs  := hcc_comm.o hcc_task.o hcc_host.o hcc_hmac.o hmac_hcc_adapt.o
hcc-objs  := $(addprefix $(HCC_PATH),$(hcc-objs))

wifi-objs += $(mac-objs)
wifi-flash-objs += $(hmac-objs)
wifi-flash-objs += $(wal-objs)
wifi-flash-objs += $(hcc-objs)

mac-rom-objs  := mac_resource.o mac_regdomain.o
mac-rom-objs  := $(addprefix $(MAC_PATH),$(mac-rom-objs))

####################################### wifi module end #########################################
COBJS = $(wifi-objs) $(plat-objs) $(plat-rom-objs) $(mac-rom-objs)
OBJS = $(patsubst %.o,$(BUILD)/%.o,$(COBJS))
SRC_DIRS = $(sort $(dir $(COBJS)))

FLASH_COBJS = $(plat-flash-objs) $(wifi-flash-objs)
FLASH_OBJS = $(patsubst %.o,$(BUILD)/%.o,$(FLASH_COBJS))
SRC_DIRS_FLASH = $(sort $(dir $(FLASH_COBJS)))

EXTRA_CFLAGS += $(HI1131_HOST_CFLAGS)
CROSS_COMPILE := $(CROSS_COMPILE)
KDIR := $(KDIR)
ARCH := arm

PWD := $(shell pwd)
USER_MODULE_NAME := hi3881
MODULE_NAME := $(USER_MODULE_NAME)
$(MODULE_NAME)-y += $(COBJS) $(FLASH_COBJS)
obj-m = $(MODULE_NAME).o

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules
	$(CROSS_COMPILE)strip --strip-unneeded $(USER_MODULE_NAME).ko
#	$(warning "===============WIFI_DRIVER_DIR=$(WIFI_DRIVER_DIR)==================")

clean:
	rm -rf $(COBJS) $(MODULE_NAME).o $(MODULE_NAME).ko
	rm -rf ./*.ko
	rm -rf ./*.o
	rm -rf ./hcc/*.o
	rm -rf ./mac/hmac/*.o
	rm -rf ./oal/*.o
	rm -rf ./oal/*.o.d
	rm -rf ./oam/*.o
	rm -rf ./wal/*.o
	rm -rf ./.*.o
	rm -rf ./*.mod.*
	rm -rf ./.*.cmd
	rm -rf Module.symvers modules.order
	rm -rf .tmp_versions
	rm -rf ./frw/.*.cmd
	rm -rf ./hcc/.*.cmd
	rm -rf ./mac/common/.*.cmd
	rm -rf ./mac/common/*.o.d
	rm -rf ./mac/hmac/.*.cmd
	rm -rf ./oal/.*.cmd
	rm -rf ./oam/.*.cmd
	rm -rf ./wal/.*.cmd
	rm -rf ./pm/.*.cmd
	rm -rf ./libsec/.*.cmd
	rm -rf ./libsec/*.o

.PHONY: all clean prepare


