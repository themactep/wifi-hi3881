include $(LITEOSTOPDIR)/config.mk

CDEFINES += -DINCLUDE_UNUSED -DWLAN_HEADERS -DWIRELESS_EXT=0 \
            -DBT_SETUP=0 -DREGCODE_REMAPPING=0 -DSOFTAP_MODE \
            -DSOFTMAC_FILE_USED  -DWPA_SUPPLICANT -DHOSTAPD
CDEFINES += -DCONFIG_NO_CONFIG_WRITE -DCONFIG_WPA -DCONFIG_SHA256 \
            -DOS_NO_C_LIB_DEFINES -DOPENSSL_DISABLE_OLD_DES_SUPPORT \
            -DTHIRTY_TWO_BIT -DOPENSSL_NO_SOCK -DCONFIG_IEEE80211N \
            -DNEED_AP_MLME -DCONFIG_INTERNAL_LIBTOMMATH -DLTM_FAST -DCONFIG_NO_RADIUS \
            -DCONFIG_NO_ACCOUNTING -DCONFIG_NO_VLAN -DHOSTAPD \
            -DCONFIG_NO_CONFIG_BLOBS -DCONFIG_CTRL_IFACE -DIEEE8021X_EAPOL -DCONFIG_TI_COMPILER \
            -DCONFIG_CRYPTO_INTERNAL -DCONFIG_LITEOS_WPA -DLOS_WPA_EVENT_CALLBAK
#LiteOS wpa code crop
CDEFINES += -DHISI_CODE_CROP -DLOS_CONFIG_NO_VLAN -DLOS_CONFIG_MESH_TRIM -DLOS_CONFIG_HOSTAPD_QOS           \
            -DHISI_WPA_MINI -DLOS_CONFIG_HOSTAPD_SECURITY -DLOS_CONFIG_HISI_DRIVER_NOT_SUPPORT              \
            -DLOS_CONFIG_HOSTAPD_EAP_CIPHERS -DHISI_WPA_KEY_MGMT_CROP -DLOS_CONFIG_HOSTAPD_TKIP_MIC         \
            -DLOS_CONFIG_HOSTAPD_RRM -DHISI_EAP_TRIM -DCONFIG_NO_HOSTAPD_LOGGER -DLOS_CONFIG_80211_IES_CROP \
            -DLOS_CONFIG_NO_PMKSA -DCONFIG_PRINT_NOUSE -DLOS_INLINE_FUNC_CROP -DCONFIG_SAE_NO_FFC           \
            -DCONFIG_SAE_NO_PW_ID -DCONFIG_SAE_ONE_ECC_CURVE -DCONFIG_SAE_CROP -DCONFIG_WPS_SUPPORT         \
            -DCONFIG_WPS -DEAP_WSC
#LiteOS wpa code crop
CDEFINES += -DLOS_CONFIG_HOSTAPD_PMKSA -DLOS_HOSTAPD_HT_CONFIG_CROP \
	    -DLOS_HOSTAPD_CONFIG_CROP -DLOS_CONFIG_ACL_CROP\

#scan size crop
#CDEFINES += -DHISI_SCAN_SIZE_CROP

#LiteOs wpa code patch
CDEFINES += -DLOS_WPA_PATCH

#LiteOs wpa debug print into uart
#ifneq ($(LOSCFG_CONFIG_DEBUG), y)
#CDEFINES += -DCONFIG_NO_WPA_MSG
#endif

CDEFINES += -DCONFIG_NO_RANDOM_POOL
CDEFINES += -DCONFIG_NO_STDOUT_DEBUG
ifeq ($(LOSCFG_CONFIG_WPS), y)
CDEFINES += -DCONFIG_WPS -DEAP_WSC
endif

ifeq ($(LOSCFG_CONFIG_P2P), y)
CDEFINES += -DCONFIG_P2P -DCONFIG_GAS -DCONFIG_OFFCHANNEL -DLOS_CONFIG_P2P
CDEFINES += -DCONFIG_WPS -DEAP_WSC -DEAP_SERVER -DEAP_SERVER_IDENTITY -DEAP_SERVER_WSC  \
            -DCONFIG_WPS_AP -DCONFIG_AP -DLOS_CONFIG_HOSTAPD_MGMT -DLOS_CONFIG_P2P_AUTO_CONNECT
endif
CDEFINES += -DCONFIG_IEEE80211W
#CDEFINES += -Werror

CURDIR := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)
WPA_SUPPLICANT_DIR := $(CURDIR)

INCLUDE_PATH = -I src/utils -Isrc

DEVICE_TYPE = hisilicon

ifeq ($(DEVICE_TYPE), hisilicon)
INCLUDE_PATH += -I $(CURDIR)/src/drivers \
                -I $(CURDIR)/wpa_supplicant \
				-I $(CURDIR)/wpa_supplicant/ltos_src \
				-I $(CURDIR)/../../../driver/oal \
				-I $(CURDIR)/../../../driver/libsec \
				-I $(CURDIR)/../../../include \
				-I $(CURDIR)/../../../driver/include \
				-I $(CURDIR)
CDEFINES += -DCONFIG_DRIVER_HISILICON

ifeq ($(LOSCFG_CONFIG_REKEY_OFFLOAD), y)
CDEFINES += -D_PRE_WLAN_FEATURE_REKEY_OFFLOAD
endif

endif

ifeq ($(LOSCFG_CONFIG_MESH), y)
CONFIG_SAE=y
CONFIG_AP=y
CONFIG_TLS = internal
CONFIG_CRYPTO=internal
CDEFINES += -DCONFIG_MESH -DLOS_CONFIG_MESH_GTK -DLOS_CONFIG_MESH -DLOS_CONFIG_HOSTAPD_MGMT

ifdef CONFIG_OPENSSL_INTERNAL_AES_WRAP
# Seems to be needed at least with BoringSSL
NEED_INTERNAL_AES_WRAP=y
CDEFINES += -DCONFIG_OPENSSL_INTERNAL_AES_WRAP
endif

ifdef NEED_DH_GROUPS_ALL
CDEFINES += -DALL_DH_GROUPS
endif

endif

ifeq ($(CONFIG_SAE), y)
CDEFINES  += -DCONFIG_SAE  -DCONFIG_ECC -DCONFIG_IEEE80211W
endif

CMNFLAGS:=-Wall -Wpointer-arith -Wundef $(INCLUDE_PATH) $(CDEFINES)
LITEOS_CFLAGS += $(CMNFLAGS) -Wstrict-prototypes
CXXFLAGS := $(CMNFLAGS) -Woverloaded-virtual -fno-rtti -fno-exceptions -fpermissive

ifeq ($(LOSCFG_KASAN), y)
ifeq ($(LOSCFG_KASAN_LITEOS_NET_WPA), y)
LITEOS_CFLAGS += -fsanitize=kernel-address -fasan-shadow-offset=1835008 --param asan-stack=1 -fsanitize=bounds-strict -DLOSCFG_DEBUG_KASAN
endif
endif

ARFLAGS = cr -D
#LIBOUT = $(TARGET_BUILD_ROOT_DIR)/liteos/wpa_supplicant
LIBOUT = $(ROOTOUT)/obj/wpa_supplicant
LIB_WPA = $(ROOTOUT)/lib/libwpa.a
LIB_LTOS_WPA = $(ROOTOUT)/lib/libltoswpa.a
WPA_SRC = src
WPA_SUPP_SRC = wpa_supplicant
WPA_LTOS_SRC = ltos_src
RM = -rm -rf

WPA_SRCS =  $(WPA_SUPP_SRC)/bss.c \
            $(WPA_SUPP_SRC)/config.c \
            $(WPA_SUPP_SRC)/config_none.c \
            $(WPA_SUPP_SRC)/ctrl_iface.c \
            $(WPA_SUPP_SRC)/ctrl_iface_rtos.c \
            $(WPA_SUPP_SRC)/wpa_cli_rtos.c \
            $(WPA_SUPP_SRC)/eap_register.c \
            $(WPA_SUPP_SRC)/events.c \
            $(WPA_SUPP_SRC)/main_rtos.c\
            $(WPA_SUPP_SRC)/scan.c \
            $(WPA_SUPP_SRC)/wpa_supplicant.c \
            $(WPA_SUPP_SRC)/wpas_glue.c \
            $(WPA_SUPP_SRC)/ap.c  \
            $(WPA_SUPP_SRC)/wifi_api.c


WPA_SRCS += hostapd/main_rtos.c \
            hostapd/eap_register.c \
            hostapd/ctrl_iface_rtos.c


WPA_SRCS += $(WPA_SRC)/common/ieee802_11_common.c \
            $(WPA_SRC)/common/wpa_common.c \
            $(WPA_SRC)/common/hw_features_common.c

WPA_SRCS += $(WPA_SRC)/crypto/aes-cbc.c \
	    $(WPA_SRC)/crypto/aes-internal-dec.c \
	$(WPA_SRC)/crypto/aes-internal-enc.c \
	$(WPA_SRC)/crypto/aes-internal.c \
	$(WPA_SRC)/crypto/aes-unwrap.c \
	$(WPA_SRC)/crypto/aes-wrap.c \
	$(WPA_SRC)/crypto/aes-omac1.c \
	$(WPA_SRC)/crypto/crypto_internal-modexp.c \
	$(WPA_SRC)/crypto/dh_group5.c \
	$(WPA_SRC)/crypto/dh_groups.c \
	$(WPA_SRC)/crypto/md5-internal.c \
	$(WPA_SRC)/crypto/md5.c \
	$(WPA_SRC)/crypto/random.c \
	$(WPA_SRC)/crypto/rc4.c \
        $(WPA_SRC)/crypto/sha1-internal.c \
	$(WPA_SRC)/crypto/sha1-pbkdf2.c \
	$(WPA_SRC)/crypto/sha1-prf.c \
	$(WPA_SRC)/crypto/sha1.c \
	$(WPA_SRC)/crypto/sha256-internal.c \
	$(WPA_SRC)/crypto/sha256-prf.c \
	$(WPA_SRC)/crypto/sha256.c \
	$(WPA_SRC)/crypto/tls_internal.c \


WPA_SRCS += $(WPA_SRC)/drivers/drivers.c \
            $(WPA_SRC)/drivers/driver_common.c

WPA_SRCS += $(WPA_SRC)/eapol_supp/eapol_supp_sm.c \
            $(WPA_SRC)/eap_peer/eap.c \
            $(WPA_SRC)/eap_common/eap_common.c \
            $(WPA_SRC)/eap_peer/eap_methods.c \
            $(WPA_SRC)/eapol_auth/eapol_auth_sm.c \
            $(WPA_SRC)/eap_server/eap_server.c \
            $(WPA_SRC)/eap_server/eap_server_identity.c \
            $(WPA_SRC)/eap_server/eap_server_methods.c

WPA_SRCS += $(WPA_SRC)/l2_packet/l2_packet_rtos.c

WPA_SRCS +=$(WPA_SRC)/rsn_supp/wpa.c \
                $(WPA_SRC)/rsn_supp/wpa_ie.c

WPA_SRCS += $(WPA_SRC)/utils/base64.c \
            $(WPA_SRC)/utils/common.c \
            $(WPA_SRC)/utils/ip_addr.c \
            $(WPA_SRC)/utils/uuid.c \
            $(WPA_SRC)/utils/wpa_debug.c \
            $(WPA_SRC)/utils/wpabuf.c \
            $(WPA_SRC)/utils/os_rtos.c


WPA_SRCS += $(WPA_SRC)/tls/bignum.c

ifeq ($(findstring -DCONFIG_P2P, $(CDEFINES)), -DCONFIG_P2P)
WPA_SRCS += $(WPA_SUPP_SRC)/p2p_supplicant.c  \
            $(WPA_SUPP_SRC)/p2p_supplicant_sd.c   \
            $(WPA_SRC)/p2p/p2p.c              \
            $(WPA_SRC)/p2p/p2p_utils.c        \
            $(WPA_SRC)/p2p/p2p_parse.c        \
            $(WPA_SRC)/p2p/p2p_build.c        \
            $(WPA_SRC)/p2p/p2p_go_neg.c       \
            $(WPA_SRC)/p2p/p2p_sd.c           \
            $(WPA_SRC)/p2p/p2p_pd.c           \
            $(WPA_SRC)/p2p/p2p_invitation.c   \
            $(WPA_SRC)/p2p/p2p_dev_disc.c     \
            $(WPA_SRC)/p2p/p2p_group.c        \
            $(WPA_SRC)/ap/p2p_hostapd.c       \
            $(WPA_SRC)/utils/bitfield.c       \
            $(WPA_SRC)/common/gas.c       \
            $(WPA_SUPP_SRC)/gas_query.c       \
            $(WPA_SUPP_SRC)/offchannel.c
endif

ifeq ($(findstring -DCONFIG_WPS, $(CDEFINES)), -DCONFIG_WPS)
WPA_SRCS += $(WPA_SRC)/wps/wps.c \
            $(WPA_SRC)/wps/wps_common.c \
            $(WPA_SRC)/wps/wps_attr_parse.c \
            $(WPA_SRC)/wps/wps_attr_build.c \
            $(WPA_SRC)/wps/wps_attr_process.c \
            $(WPA_SRC)/wps/wps_dev_attr.c \
            $(WPA_SRC)/wps/wps_enrollee.c \
            $(WPA_SUPP_SRC)/notify.c \
            $(WPA_SUPP_SRC)/wps_supplicant.c \
            $(WPA_SRC)/eap_common/eap_wsc_common.c
ifeq ($(findstring -DEAP_SERVER_WSC, $(CDEFINES)), -DEAP_SERVER_WSC)
WPA_SRCS += $(WPA_SRC)/eap_server/eap_server_wsc.c \
            $(WPA_SRC)/ap/wps_hostapd.c \
            $(WPA_SRC)/wps/wps_registrar.c

endif
ifeq ($(findstring -DEAP_WSC, $(CDEFINES)), -DEAP_WSC)
WPA_SRCS += $(WPA_SRC)/eap_peer/eap_wsc.c
endif

endif


ifeq ($(CONFIG_WPA_TEST), y)
WPA_SRCS += $(WPA_SRC)/common/common_module_tests.c
WPA_SRCS += $(WPA_SRC)/utils/utils_module_tests.c
WPA_SRCS += $(WPA_SRC)/crypto/crypto_module_tests.c
WPA_SRCS += $(WPA_SUPP_SRC)/wpas_module_tests.c
endif


ifeq ($(LOSCFG_CONFIG_MESH), y)
WPA_SRCS += $(WPA_SUPP_SRC)/mesh.c
WPA_SRCS += $(WPA_SUPP_SRC)/mesh_mpm.c
WPA_SRCS += $(WPA_SUPP_SRC)/mesh_rsn.c
WPA_SRCS += $(WPA_SRC)/common/sae.c
WPA_SRCS += $(WPA_SRC)/common/dragonfly.c
WPA_SRCS += $(WPA_SRC)/crypto/crypto_internal.c
WPA_SRCS += $(WPA_SRC)/crypto/tls_none.c
WPA_SRCS += $(WPA_SRC)/crypto/aes-siv.c
WPA_SRCS += $(WPA_SRC)/crypto/aes-ctr.c
WPA_SRCS += $(WPA_SRC)/crypto/des-internal.c

ifeq ($(CONFIG_AP), n)

WPA_SRCS += $(WPA_SRC)/eapol_auth/eapol_auth_sm.c

endif

endif


WPA_SRCS += $(WPA_SRC)/ap/hostapd.c \
            $(WPA_SRC)/ap/bss_load.c \
            $(WPA_SRC)/ap/wpa_auth_glue.c \
            $(WPA_SRC)/ap/utils.c \
            $(WPA_SRC)/ap/ap_config.c \
            $(WPA_SRC)/ap/sta_info.c \
            $(WPA_SRC)/ap/tkip_countermeasures.c \
            $(WPA_SRC)/ap/ap_mlme.c \
            $(WPA_SRC)/ap/drv_callbacks.c \
            $(WPA_SRC)/ap/ap_drv_ops.c \
            $(WPA_SRC)/ap/ieee802_11_ht.c \
            $(WPA_SRC)/ap/ieee802_11.c \
            $(WPA_SRC)/ap/hw_features.c \
            $(WPA_SRC)/ap/wpa_auth.c \
            $(WPA_SRC)/ap/wpa_auth_ie.c \
            $(WPA_SRC)/ap/ieee802_1x.c \
            $(WPA_SRC)/ap/eap_user_db.c \
            $(WPA_SRC)/ap/beacon.c


ifeq ($(DEVICE_TYPE), hisilicon)
WPA_SRCS += $(WPA_SRC)/drivers/driver_hisi.c \
            $(WPA_SRC)/drivers/driver_hisi_ioctl.c

endif

include current_module.rules
#include $(HDB_SCRIPT_PATH)/mk_prim_xml_step1_wpa.mk

LIB_WPA_COBJ = $(patsubst %.c,$(LIBOUT)/%.o,$(WPA_SRCS))

WPA_CFLAGS = $(LITEOS_CFLAGS) -Os -Werror -fsigned-char -freg-struct-return -fno-strict-aliasing -Wtrampolines -Wdate-time -Wshadow -fstack-protector-strong
#该选项添加后wpa代码编译不过
#WPA_CFLAGS += -Wextra
#该选项添加后wpa代码编译不过
#WPA_CFLAGS += -Wformat=2
#规范建议：在Debug版本中实施，Release版本不实施
#WPA_CFLAGS += -ftrapv

ifeq ($(CFG_KERNEL_SMP), y)
WPA_CFLAGS += -D_PRE_LOSCFG_KERNEL_SMP
endif

all: $(LIBOUT) $(LIB_WPA) $(LIB_LTOS_WPA)
#all: do_prim_xml_step1 $(LIBOUT) $(LIB_WPA) $(LIB_LTOS_WPA)

$(LIB_WPA_COBJ): $(LIBOUT)/%.o : %.c
	@echo "Compile $<"
	@$(CC) $(WPA_CFLAGS) -c $< -o $@
	#@python $(HDB_SCRIPT_PATH)/cc_prim.py "_PYTHON_ARG_" "CC" $(CC) "_PYTHON_ARG_" "CFLAGS" $(WPA_CFLAGS) "_PYTHON_ARG_" "SRC_FILE_NAME" $< "_PYTHON_ARG_" "DST_FILE_NAME" $@ "_PYTHON_ARG_" "CURRENT_DIR" $(WPA_SUPPLICANT_DIR)

$(LIB_WPA): $(LIB_WPA_COBJ) $(LIB_LTOS_WPA)
	@$(AR) $(ARFLAGS) $@ $(sort $(LIB_WPA_COBJ))
$(LIBOUT):
	mkdir -p $(LIBOUT)/$(WPA_SRC)/ap   $(LIBOUT)/$(WPA_SRC)/utils  $(LIBOUT)/$(WPA_SRC)/rsn_supp  $(LIBOUT)/$(WPA_SRC)/l2_packet
	mkdir -p $(LIBOUT)/$(WPA_SUPP_SRC) $(LIBOUT)/$(WPA_SRC)/crypto $(LIBOUT)/$(WPA_SRC)/drivers $(LIBOUT)/$(WPA_SRC)/common  $(LIBOUT)/$(WPA_SRC)/wps  $(LIBOUT)/$(WPA_SRC)/tls
	mkdir -p $(LIBOUT)/hostapd $(LIBOUT)/$(WPA_SRC)/eap_common  $(LIBOUT)/$(WPA_SRC)/eap_server  $(LIBOUT)/$(WPA_SRC)/eap_peer  $(LIBOUT)/$(WPA_SRC)/eapol_supp
	mkdir -p $(LIBOUT)/$(WPA_SRC)/eapol_auth
	mkdir -p $(LIBOUT)/$(WPA_SRC)/p2p
	mkdir -p $(LIBOUT)/$(WPA_LTOS_SRC)
	cp -rf $(WPA_LTOS_SRC)/libltoswpa.a $(LIB_LTOS_WPA)

clean:
	@$(RM) $(LIBOUT) *.bak *~

release:$(LIBOUT) $(LIB_WPA)
	mkdir -p $(COMPLIE_ROOT)/release/$(LITEOS_PLATFORM)/$(DEVICE_TYPE)/lib
	mkdir -p $(COMPLIE_ROOT)/release/$(LITEOS_PLATFORM)/$(DEVICE_TYPE)/include
	cp -f $(LIB_WPA) $(COMPLIE_ROOT)/release/$(LITEOS_PLATFORM)/$(DEVICE_TYPE)/lib
	cp -f $(COMPLIE_ROOT)/tools/wpa_supplicant/wpa_supplicant/wpa_supplicant.h $(COMPLIE_ROOT)/release/$(LITEOS_PLATFORM)/$(DEVICE_TYPE)/include
	cp -f $(COMPLIE_ROOT)/tools/wpa_supplicant/hostapd/hostapd_if.h $(COMPLIE_ROOT)/release/$(LITEOS_PLATFORM)/$(DEVICE_TYPE)/include

release_clean:
	@$(RM) $(LIBOUT) *.bak *~
	@$(RM) $(LIBOUT)/..
	@$(RM) $(COMPLIE_ROOT)/release/$(LITEOS_PLATFORM)/wpa_supplicant

.PHONY: all clean release release_clean
