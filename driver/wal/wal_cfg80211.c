/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Linux cfg80211 interface.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "hmac_ext_if.h"
#include "wal_cfg80211.h"
#include "wal_scan.h"
#include "wal_main.h"
#include "wal_regdb.h"
#include "wal_ioctl.h"
#include "wal_hipriv.h"
#include "wal_net.h"
#include "wal_customize.h"
#include "mac_ie.h"
#include "wal_event_msg.h"
#include "wal_cfg80211_apt.h"
#include "plat_pm_wlan.h"
#include "hi_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#define WIFI_G_RATES           (g_wifi_rates + 0)
#define WIFI_G_RATES_SIZE      12

/* �豸֧�ֵ����� */
static oal_ieee80211_rate g_wifi_rates[] = {
    ratetab_ent(10,  0x1,   0),
    ratetab_ent(20,  0x2,   0),
    ratetab_ent(55,  0x4,   0),
    ratetab_ent(110, 0x8,   0),
    ratetab_ent(60,  0x10,  0),
    ratetab_ent(90,  0x20,  0),
    ratetab_ent(120, 0x40,  0),
    ratetab_ent(180, 0x80,  0),
    ratetab_ent(240, 0x100, 0),
    ratetab_ent(360, 0x200, 0),
    ratetab_ent(480, 0x400, 0),
    ratetab_ent(540, 0x800, 0),
};

/* 2.4G Ƶ�� */
oal_ieee80211_channel g_wifi_2ghz_channels[] = {
    chan2g(1, 2412, 0),
    chan2g(2, 2417, 0),
    chan2g(3, 2422, 0),
    chan2g(4, 2427, 0),
    chan2g(5, 2432, 0),
    chan2g(6, 2437, 0),
    chan2g(7, 2442, 0),
    chan2g(8, 2447, 0),
    chan2g(9, 2452, 0),
    chan2g(10, 2457, 0),
    chan2g(11, 2462, 0),
    chan2g(12, 2467, 0),
    chan2g(13, 2472, 0),
    chan2g(14, 2484, 0),
};

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/* �豸֧�ֵļ����׼� */
static const hi_u32 g_wifi_cipher_suites[] = {
    WLAN_CIPHER_SUITE_WEP40,
    WLAN_CIPHER_SUITE_WEP104,
    WLAN_CIPHER_SUITE_TKIP,
    WLAN_CIPHER_SUITE_CCMP,
    WLAN_CIPHER_SUITE_AES_CMAC,
    WLAN_CIPHER_SUITE_SMS4,
};
#endif

/* 2.4G Ƶ����Ϣ */
static oal_ieee80211_supported_band g_wifi_band_2ghz = {
    .channels   = g_wifi_2ghz_channels,
    .n_channels = sizeof(g_wifi_2ghz_channels)/sizeof(oal_ieee80211_channel),
    .bitrates   = WIFI_G_RATES,
    .n_bitrates = WIFI_G_RATES_SIZE,
    .ht_cap = {
        .ht_supported = HI_TRUE,
        .cap = IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_20 | IEEE80211_HT_CAP_SGI_40,
    },
};

#ifdef _PRE_WLAN_FEATURE_P2P
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_workqueue_s *g_del_virtual_inf_workqueue = HI_NULL;

static oal_ieee80211_iface_limit g_sta_p2p_limits[] = {
    {
    .max = 2,
    .types = bit(NL80211_IFTYPE_STATION),
    },
    /* 1131���һ��AP���ͽӿ� */
    {
    .max = 1,
    .types = bit(NL80211_IFTYPE_AP),
    },
    {
    .max = 2,
    .types = bit(NL80211_IFTYPE_P2P_GO) | BIT(NL80211_IFTYPE_P2P_CLIENT),
    },
    {
    .max = 1,
    .types = bit(NL80211_IFTYPE_P2P_DEVICE),
    },
#ifdef _PRE_WLAN_FEATURE_MESH
    {
    .max = 1,
    .types = bit(NL80211_IFTYPE_MESH_POINT),
    },
#endif
};

static oal_ieee80211_iface_combination
g_sta_p2p_iface_combinations[] = {
    {
    .num_different_channels = 2,
    .max_interfaces = 3,
    .limits = g_sta_p2p_limits,
    .n_limits = hi_array_size(g_sta_p2p_limits),
    },
};

/* There isn't a lot of sense in it, but you can transmit anything you like */
static const struct ieee80211_txrx_stypes
g_wal_cfg80211_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
    [NL80211_IFTYPE_ADHOC] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ACTION >> 4)
    },
    [NL80211_IFTYPE_STATION] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ACTION >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4)
    },
    [NL80211_IFTYPE_AP] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4) |
        bit(IEEE80211_STYPE_DISASSOC >> 4) |
        bit(IEEE80211_STYPE_AUTH >> 4) |
        bit(IEEE80211_STYPE_DEAUTH >> 4) |
        bit(IEEE80211_STYPE_ACTION >> 4)
    },
    [NL80211_IFTYPE_AP_VLAN] = {
        /* copy AP */
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4) |
        bit(IEEE80211_STYPE_DISASSOC >> 4) |
        bit(IEEE80211_STYPE_AUTH >> 4) |
        bit(IEEE80211_STYPE_DEAUTH >> 4) |
        bit(IEEE80211_STYPE_ACTION >> 4)
    },
    [NL80211_IFTYPE_P2P_CLIENT] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ACTION >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4)
    },
    [NL80211_IFTYPE_P2P_GO] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4) |
        bit(IEEE80211_STYPE_DISASSOC >> 4) |
        bit(IEEE80211_STYPE_AUTH >> 4) |
        bit(IEEE80211_STYPE_DEAUTH >> 4) |
        bit(IEEE80211_STYPE_ACTION >> 4)
    },
#if defined(_PRE_WLAN_FEATURE_P2P)
    [NL80211_IFTYPE_P2P_DEVICE] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ACTION >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4)
    },
#endif /* WL_CFG80211_P2P_DEV_IF */
#ifdef _PRE_WLAN_FEATURE_MESH
    [NL80211_IFTYPE_MESH_POINT] = {
        .tx = 0xffff,
        .rx = bit(IEEE80211_STYPE_ASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_REASSOC_REQ >> 4) |
        bit(IEEE80211_STYPE_PROBE_REQ >> 4) |
        bit(IEEE80211_STYPE_DISASSOC >> 4) |
        bit(IEEE80211_STYPE_AUTH >> 4) |
        bit(IEEE80211_STYPE_DEAUTH >> 4) |
        bit(IEEE80211_STYPE_ACTION >> 4)
    },
#endif
};
#endif
#endif

hi_u8               g_cookie_array_bitmap = 0;   /* ÿ��bit ��ʾcookie array ���Ƿ�ʹ�ã�1 - ��ʹ�ã�0 - δʹ�� */
cookie_arry_stru        g_cookie_array[WAL_COOKIE_ARRAY_SIZE];

/* insmod ����vap mode */
int g_mode = WAL_WIFI_MODE_STA_AP; /* wifi Ĭ��STA_AP ����ģʽ */
module_param(g_mode, int, 0644);
/* insmod ����vap bandwith */
int g_bw = WAL_WIFI_BW_LEGACY_20M;
module_param(g_bw, int, 0644);
/* insmod ����vap protocol */
int g_proto = WAL_PHY_MODE_11N;
module_param(g_proto, int, 0644);

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
oal_ieee80211_channel* wal_get_g_wifi_2ghz_channels(hi_void)
{
    return g_wifi_2ghz_channels;
}

#ifdef _PRE_WLAN_FEATURE_P2P
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 �� �� ��  : wal_is_p2p_group_exist
 ��������  : ����Ƿ����P2P group
 �������  : mac_device_stru *pst_mac_device
 �������  : ��
 �� �� ֵ  : static hi_u32 HI_TRUE    ����P2P group
                           HI_FALSE   ������P2P group
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��9��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_is_p2p_group_exist(mac_device_stru *mac_dev)
{
    if (hmac_p2p_check_vap_num(mac_dev, WLAN_P2P_GO_MODE) != HI_SUCCESS ||
        hmac_p2p_check_vap_num(mac_dev, WLAN_P2P_CL_MODE) != HI_SUCCESS) {
        return HI_TRUE;
    } else {
        return HI_FALSE;
    }
}
#endif
/*****************************************************************************
 �� �� ��  : wal_del_p2p_group
 ��������  : ɾ��P2P group
 �������  : mac_device_stru *pst_mac_device
 �������  : ��
 �� �� ֵ  : static hi_void
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��9��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_del_p2p_group(const mac_device_stru *mac_dev)
{
    mac_vap_stru        *mac_vap  = HI_NULL;
    hmac_vap_stru       *hmac_vap = HI_NULL;
    oal_net_device_stru *netdev   = HI_NULL;

    for (hi_u8 vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_P2P, "{wal_del_p2p_group::mac vap Err!vapId=%d}", mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        hmac_vap = hmac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(hmac_vap == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_P2P, "{wal_del_p2p_group::get hmac vap resource fail! vap id is %d}",
                mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        netdev = hmac_vap->net_device;
        if (oal_unlikely(netdev == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_P2P, "{wal_del_p2p_group::netdev Err!vap id=%d}", mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        if (is_p2p_go(mac_vap) || is_p2p_cl(mac_vap)) {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
            mac_cfg_del_vap_param_stru del_vap_param;

            /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ�� */
            memset_s(&del_vap_param, sizeof(del_vap_param), 0, sizeof(del_vap_param));

            del_vap_param.net_dev = netdev;
            del_vap_param.vap_mode = mac_vap->vap_mode;
            del_vap_param.p2p_mode = mac_get_p2p_mode(mac_vap);
#endif
            oam_warning_log2(mac_vap->vap_id, OAM_SF_P2P, "{wal_del_p2p_group:: vap mode[%d], p2p mode[%d]}\r\n",
                mac_vap->vap_mode, mac_get_p2p_mode(mac_vap));
            /* ɾ���Ѿ����ڵ�P2P group */
            wal_force_scan_complete(netdev);
            wal_stop_vap(netdev);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
            if (wal_cfg80211_del_vap(&del_vap_param) == HI_SUCCESS) {
                wal_cfg80211_unregister_netdev(netdev);
            }
#else
            if (wal_deinit_wlan_vap(netdev) == HI_SUCCESS) {
                /* ȥע��netdev */
                oal_net_unregister_netdev(netdev);
                oal_net_free_netdev(netdev);
            }
#endif
        }
    }

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 �� �� ��  : wal_set_p2p_status
 ��������  :����p2p Ϊ��Ӧ״̬
 �������  : oal_net_device_stru *net_dev, wlan_p2p_status_enum_uint32 en_status
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   :
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_set_p2p_status(oal_net_device_stru *netdev, wlan_p2p_status_enum_uint32 status)
{
    hi_u32             ret;
    wal_msg_write_stru write_msg;

    /* ��д��Ϣͷ */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_P2P_STATUS, sizeof(wlan_p2p_status_enum_uint32));
    /* ��д��Ϣ�� */
    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value),
                 &status, sizeof(wlan_p2p_status_enum_uint32)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_set_p2p_status::mem safe function err!}");
        return HI_FAIL;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(wlan_p2p_status_enum_uint32),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_set_p2p_status::return err code [%d]!}\r\n", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}
#endif

hi_u32 wal_cfg80211_add_virtual_intf_p2p_proc(mac_device_stru *mac_device)
{
    /* ���net_device ǰ���жϵ�ǰ�Ƿ�����ɾ��net_device ״̬��
        �������ɾ��net_device����ȴ�ɾ����ɣ������ */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    if (hmac_dev->p2p_intf_status & bit(P2P_STATUS_IF_DELETING)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf:Released lock ,wait till IF_DEL is complete}");
        hi_s32 l_timeout = hi_wait_event_timeout(hmac_dev->netif_change_event,
            ((hmac_dev->p2p_intf_status & bit(P2P_STATUS_IF_DELETING)) == HI_FALSE),
            WAL_MAX_WAIT_TIME / HI_MILLISECOND_PER_TICK);
        if (l_timeout > 0) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::IF DEL is Success!}\r\n");
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::timeount < 0, return -EAGAIN!}\r\n");
            return HI_FAIL;
        }
    }

    /* ���wifi �����У�P2P group �Ƿ��Ѿ����������P2P group �Ѿ�������
        �򽫸�P2P group ɾ�����������´���P2P group */
    if (wal_is_p2p_group_exist(mac_device) == HI_TRUE) {
        oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::found exist p2p group, delet it first!}");
        if (wal_del_p2p_group(mac_device) != HI_SUCCESS) {
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_remain_on_channel
 ��������  : ������ָ���ŵ�
 �������  : [1]wiphy
             [2]wdev
             [3]chan
             [4]duration
             [5]pull_cookie
 �������  : ��
 �� �� ֵ  : static hi_s32
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_remain_on_channel(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    oal_ieee80211_channel *chan, hi_u32 duration, hi_u64 *pull_cookie)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_remain_on_channel(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    oal_ieee80211_channel *chan, hi_u32 duration, hi_u64 *pull_cookie)
#endif
{
    /* 1.1 ��μ�� */
    if ((wiphy == HI_NULL) || (wdev == HI_NULL) || (chan == HI_NULL) || (pull_cookie == HI_NULL)) {
        oam_error_log0(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::wiphy or wdev or chan or pull_cookie is null}");
        goto fail;
    }

    oal_net_device_stru *netdev = wdev->netdev;
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::pst_netdev ptr is null!}\r\n");
        goto fail;
    }

    mac_device_stru *mac_device     = (mac_device_stru *)mac_res_get_dev();
    hi_u16           us_center_freq = chan->center_freq;
    hi_s32           l_channel      = (hi_s32)oal_ieee80211_frequency_to_channel((hi_s32)us_center_freq);

    mac_remain_on_channel_param_stru remain_on_channel = {0};

    /* 2.1 ��Ϣ����׼�� */
    remain_on_channel.uc_listen_channel = (hi_u8)l_channel;
    remain_on_channel.listen_duration = duration;
    remain_on_channel.st_listen_channel = *chan;
    remain_on_channel.listen_channel_type = WLAN_BAND_WIDTH_20M;

    if (chan->band == IEEE80211_BAND_2GHZ) {
        remain_on_channel.band = WLAN_BAND_2G;
    } else {
        oam_warning_log1(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::wrong band type[%d]!}\r\n", chan->band);
        goto fail;
    }
    /* DTS2015120401781��cookie+1ֵ��ǰ����֤������ɨ���cookieֵһ�±�������ɨ��cookieֵŪ�������
     * cookieֵ�ϲ������Ҫ�ж��Ƿ�����εķ��͵��µ�callbacks_pending
     */
    *pull_cookie = ++mac_device->p2p_info.ull_last_roc_id;
    if (*pull_cookie == 0) {
        *pull_cookie = ++mac_device->p2p_info.ull_last_roc_id;
    }

    /* ����cookie ֵ���·���HMAC ��DMAC */
    remain_on_channel.ull_cookie = mac_device->p2p_info.ull_last_roc_id;

    /* ���¼������� */
    hi_u32 ret = wal_cfg80211_start_req(netdev, &remain_on_channel,
        sizeof(mac_remain_on_channel_param_stru), WLAN_CFGID_CFG80211_REMAIN_ON_CHANNEL, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::wal_send_cfg_event return err code:[%d]}", ret);
        goto fail;
    }

    /* �ϱ���ͣ��ָ���ŵ��ɹ� */
#if (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
    cfg80211_ready_on_channel(wdev, ull_cookie, chan, duration, en_gfp);
#endif
    ret = cfg80211_remain_on_channel(netdev, chan->center_freq, duration);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_P2P, "{wal_cfg80211_remain_on_channel::cfg80211_remain_on_channel fail[%u]}\r\n", ret);
        goto fail;
    }

    oam_warning_log4(0, OAM_SF_P2P,
        "{wal_cfg80211_remain_on_channel::SUCC! l_channel=%d, ul_duration=%d, cookie 0x%x, band= %d!}\r\n",
        l_channel, duration, *pull_cookie, remain_on_channel.band);

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_cancel_remain_on_channel
 ��������  : ֹͣ������ָ���ŵ�
 �������  : [1]wiphy
             [2]wdev
             [3]ull_cookie
 �������  : ��
 �� �� ֵ  : static hi_s32
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_cancel_remain_on_channel(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev, hi_u64 ull_cookie)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_cancel_remain_on_channel(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev, hi_u64 ull_cookie)
#endif
{
    oal_net_device_stru             *netdev                  = HI_NULL;
    mac_remain_on_channel_param_stru cancel_remain_on_channel = {0};
    hi_u32                           ret;

    hi_unref_param(wiphy);
    hi_unref_param(ull_cookie);
    netdev = wdev->netdev;

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &cancel_remain_on_channel,
        sizeof(mac_remain_on_channel_param_stru), WLAN_CFGID_CFG80211_CANCEL_REMAIN_ON_CHANNEL, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_P2P,
            "{wal_cfg80211_cancel_remain_on_channel::wal_send_cfg_event return err code:[%d]!}", ret);
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}
#endif /* #ifdef _PRE_WLAN_FEATURE_P2P */

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 �� �� ��  : wal_cfg80211_register_netdev
 ��������  : �ں�ע��ָ�����͵�net_device,������Ҫ��mutex lock��Ӧ��
 �������  : mac_device_stru *pst_hmac_device
             oal_net_device_stru *pst_net_dev
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_register_netdev(oal_net_device_stru *netdev)
{
    /* �ں�ע��net_device, ֻ����0 */
    return (hi_u32)oal_net_register_netdev(netdev);
}

/*****************************************************************************
 �� �� ��  : wal_find_wmm_uapsd
 ��������  : �����ں��·���beacon_info�е�wmm ie��wmm uapsd�Ƿ�ʹ��
 �������  : hi_u8 *puc_frame_body, hi_s32 l_len

 �������  : ��
 �� �� ֵ  : uapsdʹ�ܣ�����HI_TRUE�����򣬷���HI_FALSE
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��8��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_find_wmm_uapsd(hi_u8 *puc_frame_body, hi_s32 l_len)
{
    hi_s32    l_index = 0;
    hi_u8     auc_oui[MAC_OUI_LEN];

    auc_oui[0] = (hi_u8)MAC_WLAN_OUI_MICRO0;
    auc_oui[1] = (hi_u8)MAC_WLAN_OUI_MICRO1;
    auc_oui[2] = (hi_u8)MAC_WLAN_OUI_MICRO2; /* 2: �����3λ */
    /* �ж� WMM UAPSD �Ƿ�ʹ�� */
    while (l_index < l_len) {
        if ((puc_frame_body[l_index] == MAC_EID_WMM)
            && (0 == memcmp(puc_frame_body + l_index + 2, auc_oui, MAC_OUI_LEN)) /* 2��ƫ��λ */
            && (puc_frame_body[l_index + 2 + MAC_OUI_LEN] == MAC_OUITYPE_WMM) /* 2��ƫ��λ */
            && (puc_frame_body[l_index + MAC_WMM_QOS_INFO_POS] & BIT7)) {
            return HI_TRUE;
        } else {
            l_index += (MAC_IE_HDR_LEN + puc_frame_body[l_index + 1]);
        }
    }

    return HI_FALSE;
}

hi_u32 wal_cfg80211_open_wmm(oal_net_device_stru *netdev, hi_u16 us_len, hi_u8 *puc_param)
{
    mac_vap_stru             *mac_vap = HI_NULL;
    wal_msg_write_stru        write_msg;
    hi_u32                    ret;
    mac_vap = oal_net_dev_priv(netdev);
    if (oal_unlikely(mac_vap == HI_NULL || puc_param == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_open_wmm::pst_mac_vap/puc_param is null ptr!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �������vap������ */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG,
            "{wal_cfg80211_open_wmm::this is config vap! can't get info.}");
        return HI_FAIL;
    }

    /* ��д�¼�ͷ */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_WMM_SWITCH, sizeof(hi_u8));
    /* ��д��Ϣ�� */
    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value), puc_param, sizeof(hi_u8)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_open_wmm::mem safe function err!}");
        return HI_FAIL;
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_open_wmm:return err code %d!}\r\n", ret);
        return HI_FAIL;
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : wal_parse_wmm_ie
 ��������  : �����ں˴��ݹ���beacon��Ϣ�е�Wmm��ϢԪ��
 �������  : oal_beacon_parameters *pst_beacon_info

 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��7��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_parse_wmm_ie(oal_net_device_stru *netdev, mac_vap_stru *mac_vap, oal_beacon_parameters *beacon_info)
{
    hi_u8               *puc_wmm_ie = HI_NULL;
    hi_u16               us_len = sizeof(hi_u8);
    hi_u8                wmm = HI_TRUE;
    hi_u32               ret = HI_SUCCESS;

    hi_u8                uapsd;
    wal_msg_write_stru   write_msg;

    /*  ����wmm_ie  */
    puc_wmm_ie = mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WMM,
                                    beacon_info->tail, beacon_info->tail_len);
    if (puc_wmm_ie == HI_NULL) {
    /* wmm ieδ�ҵ�����˵��wmm �� */
        wmm = HI_FALSE;
    } else { /*  �ҵ�wmm ie��˳���ж���uapsd�Ƿ�ʹ�� */
        /* DTS2015080707662:�ж�WMM��ϢԪ�غ�ƫ��8�ֽ� ��bit7λ�Ƿ�Ϊ1,1��ʾuapsdʹ�� */
        if (HI_FALSE == wal_find_wmm_uapsd(beacon_info->tail, beacon_info->tail_len)) {
            /* ��ӦUAPSD �� */
            uapsd = HI_FALSE;
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{wal_parse_wmm_ie::uapsd is disabled!!}");
        }

        /* ��д msg ��Ϣͷ */
        wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_UAPSD_EN, sizeof(hi_u32));
        /* ��д msg ��Ϣ�� */
        uapsd = HI_FALSE;

        if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value), &uapsd, sizeof(hi_u32)) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "{wal_parse_wmm_ie::mem safe function err!}");
            return HI_FAIL;
        }

        /* ������Ϣ */
        ret = (hi_u32)wal_send_cfg_event(netdev,
                                         WAL_MSG_TYPE_WRITE,
                                         WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                                         (hi_u8 *)&write_msg,
                                         HI_FALSE,
                                         HI_NULL);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            ret = HI_FAIL;
            oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{wal_parse_wmm_ie::uapsd switch set failed[%d].}", ret);
        }
    }

    /*  wmm ����/�ر� ���  */
    ret = wal_cfg80211_open_wmm(netdev, us_len, &wmm);
    if (ret != HI_SUCCESS) {
        ret = HI_FAIL;
        oam_warning_log0(0, OAM_SF_TX, "{wal_parse_wmm_ie::can not open wmm!}\r\n");
    }

    return ret;
}

/*****************************************************************************
 ��������  : ���ѱ�����Ϣ���ȡptk,gtk����Կ
 �������  : [1]wiphy
             [2]netdev
             [3]p_cfg80211_get_key_info
             [4]cookie
             [5]callback
 �������  : hi_u32
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
*****************************************************************************/
static hi_s32 wal_cfg80211_get_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index,
    bool pairwise, const hi_u8 *puc_mac_addr, hi_void *cookie,
    hi_void (*callback)(hi_void *cookie, oal_key_params_stru*))
{
    wal_msg_write_stru    write_msg;
    mac_getkey_param_stru payload  = {0};
    hi_u8                 mac_addr[WLAN_MAC_ADDR_LEN];
    wal_msg_stru         *rsp_msg = HI_NULL;

    /* 1.1 ��μ�� */
    if ((wiphy == HI_NULL) || (netdev == HI_NULL) || (cookie == HI_NULL) || (callback == HI_NULL)) {
        oam_error_log4(0, OAM_SF_ANY, "{wal_cfg80211_get_key::Param ERR,wiphy,netdev,cookie,callback %d, %d, %d, %d}",
            wiphy, netdev, cookie, callback);
        goto fail;
    }

    /* 2.1 ��Ϣ����׼�� */
    payload.netdev    = netdev;
    payload.key_index = key_index;

    if (puc_mac_addr != HI_NULL) {
        /* ����ʹ���ں��·���macָ�룬���ܱ��ͷţ���Ҫ������������ʹ�� */
        if (memcpy_s(mac_addr, WLAN_MAC_ADDR_LEN, puc_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::mem safe function err!}");
            goto fail;
        }
        payload.puc_mac_addr = mac_addr;
    } else {
        payload.puc_mac_addr = HI_NULL;
    }

    payload.pairwise = pairwise;
    payload.cookie   = cookie;
    payload.callback = callback;

    oam_info_log2(0, OAM_SF_ANY, "{wal_cfg80211_get_key::key_idx:%d,en_pairwise:%d}",
        key_index, payload.pairwise);
    if (puc_mac_addr != HI_NULL) {
        oam_info_log3(0, OAM_SF_ANY, "{wal_cfg80211_get_key::MAC ADDR: XX:XX:XX:%02X:%02X:%02X!}\r\n",
            puc_mac_addr[3], puc_mac_addr[4], puc_mac_addr[5]); /* mac addr 0:1:2:3:4:5 */
    } else {
        oam_info_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::MAC ADDR IS null!}\r\n");
    }
    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    /* 3.1 ��д msg ��Ϣͷ */
    write_msg.wid = WLAN_CFGID_GET_KEY;
    write_msg.us_len = sizeof(mac_getkey_param_stru);

    /* 3.2 ��д msg ��Ϣ�� */
    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value), &payload, sizeof(mac_getkey_param_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::mem safe function err!}");
        goto fail;
    }

    /* ������Ϣ��ʹ���˾ֲ�����ָ�룬�����Ҫ�����͸ú�������Ϊͬ��������hmac����ʱ��ʹ��Ұָ�� */
    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_getkey_param_stru), (hi_u8 *)&write_msg, HI_TRUE, &rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_get_key::return err code [%u]!}", ret);
        goto fail;
    }

    if (wal_check_and_release_msg_resp(rsp_msg) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_key::wal_check_and_release_msg_resp fail.}");
        goto fail;
    }

    return HI_SUCCESS;
fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 ��������  : ʹ���õ���Կ��Ч.PMF ����ʹ�ã����ù�����Կ
 �������  : [1]wiphy
             [2]netdev
             [3]key_index
 �������  : hi_u32
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
*****************************************************************************/
hi_s32 wal_cfg80211_set_default_mgmt_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index)
{
    /* ���ù�����Կ */
    return -HI_FAIL;
}

/*****************************************************************************
 ��������  : ����wiphy�豸�� ������RTS ������ֵ����Ƭ������ֵ
 �������  : oal_wiphy_stru *pst_wiphy
             hi_u32 ul_changed
 �� �� ֵ  : static hi_s32
 �޸���ʷ      :
  1.��    ��   : 2013��10��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_s32 wal_cfg80211_set_wiphy_params(oal_wiphy_stru *wiphy, hi_u32 changed)
{
    /* ͨ��HOSTAPD ����RTS ���ޣ���Ƭ���� ���ýӿ�wal_ioctl_set_frag�� wal_ioctl_set_rts */
    oam_warning_log0(0, OAM_SF_CFG,
        "{wal_cfg80211_set_wiphy_params::should not call this fun. call wal_ioctl_set_frag/wal_ioctl_set_rts!}\r\n");
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �޸�bss������Ϣ
 �������  : oal_wiphy_stru        *pst_wiphy
             oal_net_device_stru   *pst_netdev
             oal_bss_parameters    *pst_bss_params
 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_s32 wal_cfg80211_change_bss(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    oal_bss_parameters *bss_params)
{
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ӡ�ϲ��·��ĵ���ɨ��������Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��6��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void wal_cfg80211_print_sched_scan_req_info(oal_cfg80211_sched_scan_request_stru  *request)
{
    hi_char    ac_tmp_buff[200]; /* 200 bufferԪ�ظ��� */
    hi_s32     l_loop = 0;

    /* ��ӡ�������� */
/* HI1131C modify begin */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    oam_warning_log3(0, OAM_SF_SCAN,
        "wal_cfg80211_print_sched_scan_req_info::channels[%d],flags[%d],rssi_thold[%d]",
        request->n_channels, request->flags, request->min_rssi_thold);
#else
oam_warning_log3(0, OAM_SF_SCAN,
    "wal_cfg80211_print_sched_scan_req_info::channels[%d],flags[%d],rssi_thold[%d]",
    request->n_channels, request->flags, request->rssi_thold);
#endif
#endif
/* HI1131C modify end */
    /* ��ӡssid���ϵ���Ϣ */
    for (l_loop = 0; l_loop < request->n_match_sets; l_loop++) {
        if (memset_s(ac_tmp_buff, sizeof(ac_tmp_buff), 0, sizeof(ac_tmp_buff)) != EOK) {
            continue;
        }
        if (snprintf_s(ac_tmp_buff, sizeof(ac_tmp_buff), sizeof(ac_tmp_buff) - 1,
            "mactch_sets[%d] info, ssid_len[%d], ssid: %s.\n",
            l_loop, request->match_sets[l_loop].ssid.ssid_len, request->match_sets[l_loop].ssid.ssid) == -1) {
            oam_error_log0(0, OAM_SF_CFG, "wal_cfg80211_print_sched_scan_req_info:: l_loop snprintf_s fail.");
            continue;
        }
    }

    for (l_loop = 0; l_loop < request->n_ssids; l_loop++) {
        if (memset_s(ac_tmp_buff, sizeof(ac_tmp_buff), 0, sizeof(ac_tmp_buff)) != EOK) {
            continue;
        }
        if (snprintf_s(ac_tmp_buff, sizeof(ac_tmp_buff), sizeof(ac_tmp_buff) - 1,
            "ssids[%d] info, ssid_len[%d], ssid: %s.\n", l_loop, request->ssids[l_loop].ssid_len,
            request->ssids[l_loop].ssid) == -1) {
            oam_error_log0(0, OAM_SF_CFG, "wal_cfg80211_print_sched_scan_req_info:: snprintf_s fail.");
            continue;
        }
    }

    return;
}

/*****************************************************************************
 ��������  : ����ɨ������
 �������  : oal_wiphy_stru                         *pst_wiphy
             oal_net_device_stru                    *pst_netdev
             oal_cfg80211_sched_scan_request_stru   *pst_request
 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_s32 wal_cfg80211_sched_scan_start(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    oal_cfg80211_sched_scan_request_stru *request)
{
    oal_cfg80211_ssid_stru *ssid_tmp = HI_NULL;
    mac_pno_scan_stru       pno_scan_info;

    /* �����Ϸ��Լ�� */
    if ((wiphy == HI_NULL) || (netdev == HI_NULL) || (request == HI_NULL)) {
        oam_error_log3(0, OAM_SF_CFG,
            "{wal_cfg80211_sched_scan_start::input param pointer is null,pst_wiphy[%p],pst_netdev[%p],pst_request[%p]}",
            wiphy, netdev, request);
        goto fail;
    }

    /* ͨ��net_device �ҵ���Ӧ��mac_device_stru �ṹ */
    mac_vap_stru     *mac_vap   = oal_net_dev_priv(netdev);
    hmac_device_stru *hmac_dev  = hmac_get_device_stru();
    hmac_scan_stru   *scan_mgmt = &(hmac_dev->scan_mgmt);

    /* �����ǰ�豸����ɨ��״̬������������ɨ�� */
    if (scan_mgmt->request != HI_NULL) {
        oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_sched_scan_start:: device is busy, don't start sched scan!}");
        goto fail;
    }

    /* ����ں��·�����Ҫƥ���ssid���ϵĸ����Ƿ�Ϸ� */
    if (request->n_match_sets <= 0) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN, "{wal_cfg80211_sched_scan_start::match_sets = %d!}",
                         request->n_match_sets);
        goto fail;
    }

    /* ��ʼ��pnoɨ��Ľṹ����Ϣ
       ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&pno_scan_info, sizeof(mac_pno_scan_stru), 0, sizeof(mac_pno_scan_stru));

    /* ���ں��·���ƥ���ssid���ϸ��Ƶ����� */
    for (hi_s32 l_loop = 0; l_loop < request->n_match_sets; l_loop++) {
        ssid_tmp = (oal_cfg80211_ssid_stru *)&(request->match_sets[l_loop].ssid);
        if (memcpy_s(pno_scan_info.ac_match_ssid_set[l_loop], WLAN_SSID_MAX_LEN,
                     ssid_tmp->ssid, ssid_tmp->ssid_len) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_sched_scan_start::mem safe function err!}");
            continue;
        }
        pno_scan_info.ac_match_ssid_set[l_loop][ssid_tmp->ssid_len] = '\0';
        pno_scan_info.l_ssid_count++;
    }

    /* ����������ֵ */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    pno_scan_info.l_rssi_thold = request->min_rssi_thold;
#else
    pno_scan_info.l_rssi_thold = request->rssi_thold;
#endif
#endif

    pno_scan_info.pno_scan_interval = PNO_SCHED_SCAN_INTERVAL;        /* �����Լ�����Ϊ30s */
    pno_scan_info.pno_scan_repeat   = MAX_PNO_REPEAT_TIMES;

    /* ���浱ǰ��PNO����ɨ������ָ�� */
    scan_mgmt->sched_scan_req     = request;
    scan_mgmt->sched_scan_complete = HI_FALSE;

    /* ά���ӡ�ϲ��·��ĵ���ɨ�����������Ϣ */
    wal_cfg80211_print_sched_scan_req_info(request);

    /* �·�pnoɨ������hmac */
    hi_u32 ret = wal_cfg80211_start_sched_scan(netdev, &pno_scan_info);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_SCAN, "{wal_cfg80211_sched_scan_start::wal_cfg80211_start_sched_scan err[%d]}", ret);
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}


/*****************************************************************************
 �� �� ��  : wal_cfg80211_add_station
 ��������  : �����û�
 �������  : oal_wiphy_stru *pst_wiphy
             oal_net_device *pst_dev
             hi_u8 *puc_mac         �û�mac ��ַ
             oal_station_parameters_stru *pst_sta_parms �û�����
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
static hi_s32 wal_cfg80211_add_station(oal_wiphy_stru *wiphy, oal_net_device_stru *dev,
    const hi_u8 *puc_mac, oal_station_parameters_stru *pst_sta_parms)
#else
static hi_s32 wal_cfg80211_add_station(oal_wiphy_stru *wiphy, oal_net_device_stru *dev,
    hi_u8 *puc_mac, oal_station_parameters_stru *pst_sta_parms)
#endif
{
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_change_station
 ��������  : ɾ���û�
 �������  : oal_wiphy_stru *pst_wiphy
             oal_net_device *pst_dev
             hi_u8 *puc_mac         �û�mac ��ַ
             oal_station_parameters_stru *pst_sta_parms �û�����
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
static hi_s32 wal_cfg80211_change_station(oal_wiphy_stru *wiphy, oal_net_device_stru *dev, const hi_u8 *puc_mac,
    oal_station_parameters_stru *sta_parms)
#else
static hi_s32 wal_cfg80211_change_station(oal_wiphy_stru *wiphy, oal_net_device_stru *dev, hi_u8 *puc_mac,
    oal_station_parameters_stru *sta_parms)
#endif
{
    return HI_SUCCESS;
}

#define QUERY_STATION_INFO_TIME  (5 * HZ)
/*****************************************************************************
 �� �� ��  : wal_cfg80211_fill_station_info
 ��������  : station_info�ṹ��ֵ
 �������  : oal_station_info_stru  *pst_sta_info,
             oal_station_info_stru *pst_stats
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void wal_cfg80211_fill_station_info(oal_station_info_stru  *sta_info, oal_station_info_stru  *stats)
{
    sta_info->filled |= STATION_INFO_SIGNAL;

    sta_info->signal = stats->signal;

    sta_info->filled |= STATION_INFO_RX_PACKETS;
    sta_info->filled |= STATION_INFO_TX_PACKETS;

    sta_info->rx_packets = stats->rx_packets;
    sta_info->tx_packets = stats->tx_packets;

    sta_info->filled   |= STATION_INFO_RX_BYTES;
    sta_info->filled   |= STATION_INFO_TX_BYTES;
    sta_info->rx_bytes  = stats->rx_bytes;
    sta_info->tx_bytes  = stats->tx_bytes;

    sta_info->filled |= STATION_INFO_TX_RETRIES;
    sta_info->filled |= STATION_INFO_TX_FAILED;
    sta_info->filled |= STATION_INFO_RX_DROP_MISC;

    sta_info->tx_retries       = stats->tx_retries;
    sta_info->tx_failed        = stats->tx_failed;
    sta_info->rx_dropped_misc  = stats->rx_dropped_misc;

    sta_info->filled |= STATION_INFO_TX_BITRATE ;
    sta_info->txrate.legacy = (hi_u16)(stats->txrate.legacy * 10); /* �ں��е�λΪ100kbps */
    sta_info->txrate.flags  = stats->txrate.flags;
    sta_info->txrate.mcs    = stats->txrate.mcs;
    sta_info->txrate.nss    = stats->txrate.nss;

    oam_info_log4(0, OAM_SF_CFG, "{wal_cfg80211_fill_station_info::legacy[%d],mcs[%d],flags[%d],nss[%d].}",
                  sta_info->txrate.legacy / 10, sta_info->txrate.mcs, /* 10: ��λת�� */
                  sta_info->txrate.flags, sta_info->txrate.nss);
}

/*****************************************************************************
 ��������  : update rssi once a second
 �޸���ʷ      :
  1.��    ��   : 2015��8��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 wal_cfg80211_get_station_filter(mac_vap_stru *mac_vap, hi_u8 *mac_addr)
{
    hmac_user_stru *hmac_user = HI_NULL;
    hi_u32      current_time = hi_get_milli_seconds();
    hi_u32      runtime;

    hmac_user = mac_vap_get_hmac_user_by_addr(mac_vap, mac_addr, WLAN_MAC_ADDR_LEN);
    if (hmac_user == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{wal_cfg80211_get_station_filter::user %d is null.}");
        return HI_FALSE;
    }

    if (current_time >= hmac_user->rssi_last_timestamp) {
        runtime = current_time - hmac_user->rssi_last_timestamp;
    } else {
        runtime = (hi_u32)(HI_U32_MAX - (hmac_user->rssi_last_timestamp - current_time) / HI_MILLISECOND_PER_TICK) *
                           HI_MILLISECOND_PER_TICK;
    }

    if (runtime < WAL_GET_STATION_THRESHOLD) {
        return HI_FALSE;
    }

    hmac_user->rssi_last_timestamp = current_time;
    return HI_TRUE;
}

hi_u32 wal_cfg80211_send_query_station_event(oal_net_device_stru *netdev, mac_vap_stru *mac_vap,
    dmac_query_request_event *query_request, oal_station_info_stru *sta_info)
{
    wal_msg_write_stru write_msg;
    write_msg.wid = WLAN_CFGID_QUERY_STATION_STATS;
    write_msg.us_len = sizeof(dmac_query_request_event);

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY,
            "{wal_cfg80211_send_query_station_event::hmac_vap_get_vap_stru fail.vap_id[%u]}", mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* 3.2 ��д msg ��Ϣ�� */
    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value),
        query_request, sizeof(dmac_query_request_event)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_station::mem safe function err!}");
        return HI_FAIL;
    }

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(dmac_query_request_event), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_get_station::wal_send_cfg_event Err=%d}", ret);
        return ret;
    }

    /* info, boolean argument to function */
    hi_s32 i_leftime = hi_wait_event_timeout(hmac_vap->query_wait_q, (hmac_vap->query_wait_q_flag == HI_TRUE),
        QUERY_STATION_INFO_TIME);
    if (i_leftime == 0) {
        /* ��ʱ��û���ϱ�ɨ����� */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_get_station::query info wait for %ld ms timeout!}",
                         ((QUERY_STATION_INFO_TIME * 1000) / HZ)); /* 1000: ʱ��ת��Ϊms */
        return HI_FAIL;
    } else if (i_leftime < 0) {
        /* ��ʱ���ڲ����� */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_get_station::query info wait for %ld ms error!}",
                         ((QUERY_STATION_INFO_TIME * 1000) / HZ));  /* 1000: ʱ��ת��Ϊms */
        return HI_FAIL;
    } else {
        /* ��������  */
        wal_cfg80211_fill_station_info(sta_info, &hmac_vap->station_info);
        oam_info_log1(0, OAM_SF_CFG, "{wal_cfg80211_get_station::rssi %d.}", hmac_vap->station_info.signal);
        return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : ��ȡstation��Ϣ
 �������  : [1]wiphy,
             [2]dev,
             [3]puc_mac,
             [4]sta_info
 �� �� ֵ  : static hi_s32

*****************************************************************************/
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
hi_s32 wal_cfg80211_get_station(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    const hi_u8 *mac_addr, oal_station_info_stru *sta_info)
#else
hi_s32 wal_cfg80211_get_station(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    hi_u8 *mac_addr, oal_station_info_stru *sta_info)
#endif
{
    dmac_query_request_event query_request;

    if ((wiphy == HI_NULL) || (netdev == HI_NULL) || (mac_addr == HI_NULL) || (sta_info == HI_NULL)) {
        oam_error_log4(0, OAM_SF_ANY, "{wal_cfg80211_get_station::wiphy[0x%p],dev[0x%p],mac[0x%p],sta_info[0x%p]}",
                       wiphy, netdev, mac_addr, sta_info);
        goto fail;
    }

    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_station::oal_net_dev_priv, return null!}");
        goto fail;
    }

    query_request.query_event = OAL_QUERY_STATION_INFO_EVENT;
    if (memcpy_s(query_request.auc_query_sta_addr, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_get_station::mem safe function err!}");
        goto fail;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_get_station:vap_get_vap_stru Err.vap_id=%u}", mac_vap->vap_id);
        goto fail;
    }

    /* �̶�ʱ����������һ��RSSI */
    if (wal_cfg80211_get_station_filter(hmac_vap->base_vap, (hi_u8 *)mac_addr) == HI_FALSE) {
        wal_cfg80211_fill_station_info(sta_info, &hmac_vap->station_info);
        return HI_SUCCESS;
    }

    hmac_vap->query_wait_q_flag = HI_FALSE;

    /********************************************************************************
        ���¼���wal�㴦�� �����ڵ͹�����Ҫ�����⴦���������²����¼���ֱ����ʱ��
        �͹��Ļ��ڽ���beacon֡��ʱ�������ϱ���Ϣ��
    ********************************************************************************/
    if (wal_cfg80211_send_query_station_event(netdev, mac_vap, &query_request, sta_info) != HI_SUCCESS) {
        goto fail;
    }
    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_dump_station
 ��������  : ɾ���û�
 �������  : oal_wiphy_stru *pst_wiphy
             oal_net_device *pst_dev
             hi_u8 *puc_mac         �û�mac ��ַ
             oal_station_parameters_stru *pst_sta_parms �û�����
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_s32 wal_cfg80211_dump_station(oal_wiphy_stru *wiphy, oal_net_device_stru *dev, hi_s32 int_index,
    hi_u8 *mac_addr, oal_station_info_stru *sta_info)
{
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_mgmt_tx_cancel_wait
 ��������  : ȡ�����͹���֡�ȴ�
 �������  : [1]wiphy
             [2]wdev
             [3]ull_cookie
 �������  : ��
 �� �� ֵ  : static hi_s32
*****************************************************************************/
static hi_s32 wal_cfg80211_mgmt_tx_cancel_wait(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev, hi_u64 ull_cookie)
{
    return -HI_FAIL;
}

hi_u32 wal_cfg80211_get_vap_p2p_mode(nl80211_iftype_uint8 type, wlan_p2p_mode_enum_uint8 *p2p_mode,
    wlan_vap_mode_enum_uint8 *vap_mode)
{
    switch (type) {
        case NL80211_IFTYPE_P2P_DEVICE:    /* P2P DEVICE��ǰ��ͷ��أ���Ӧ���ߵ����� */
            oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf:: p2p0 need create before this!}");
            return HI_FAIL;
        case NL80211_IFTYPE_P2P_CLIENT:
            *vap_mode = WLAN_VAP_MODE_BSS_STA;
            *p2p_mode = WLAN_P2P_CL_MODE;
            break;
        case NL80211_IFTYPE_STATION:
            *vap_mode = WLAN_VAP_MODE_BSS_STA;
            *p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
        case NL80211_IFTYPE_P2P_GO:
            *vap_mode = WLAN_VAP_MODE_BSS_AP;
            *p2p_mode = WLAN_P2P_GO_MODE;
            break;
        case NL80211_IFTYPE_AP:
            *vap_mode = WLAN_VAP_MODE_BSS_AP;
            *p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
#ifdef _PRE_WLAN_FEATURE_MESH
        case NL80211_IFTYPE_MESH_POINT:
            *vap_mode = WLAN_VAP_MODE_MESH;
            *p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
#endif
        default:
            oam_error_log1(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::Unsupported interface type[%d]!}", type);
            return HI_FAIL;
    }

    return HI_SUCCESS;
}

hi_u32 wal_cfg80211_add_virtual_intf_get_netdev(const hi_char *puc_name, oal_net_device_stru **netdev)
{
    hi_char auc_name[OAL_IF_NAME_SIZE] = {0};

    oal_net_device_stru *netdev_cfg = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev_cfg == HI_NULL) {
        oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_cfg_net_dev null!}");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev_cfg);
#endif
    if (memcpy_s(auc_name, OAL_IF_NAME_SIZE, puc_name, strlen(puc_name)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::mem safe function err!}");
        return HI_CONTINUE;
    }

#if defined(_PRE_WLAN_FEATURE_FLOWCTL)
    /* �˺�����һ����δ���˽�г��ȣ��˴����漰Ϊ0 */
    *netdev = oal_net_alloc_netdev_mqs(auc_name);
#elif defined(_PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL)
    /* �˺�����һ����δ���˽�г��ȣ��˴����漰Ϊ0 */
    *netdev = oal_net_alloc_netdev_mqs(auc_name);
#else
    /* �˺�����һ����δ���˽�г��ȣ��˴����漰Ϊ0 */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    *netdev = oal_net_alloc_netdev(auc_name, OAL_IF_NAME_SIZE);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    *netdev = oal_net_alloc_netdev(0, auc_name, oal_ether_setup);
#endif
#endif
    if (oal_unlikely((*netdev) == HI_NULL)) {
        oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_net_dev null ptr error!}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

hi_u32 wal_cfg80211_add_virtual_intf_set_wireless_dev(oal_wireless_dev *wdev, mac_device_stru *mac_device,
    oal_net_device_stru *netdev, nl80211_iftype_uint8 type)
{
    /* ��netdevice���и�ֵ */
    /* ���´�����net_device ��ʼ����Ӧ���� */
#if (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
    netdev->wireless_handlers = wal_get_g_iw_handler_def();
#endif
    netdev->netdev_ops = wal_get_net_dev_ops();

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC) && (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
    netdev->ethtool_ops = &g_wal_ethtool_ops;
#endif

#if (LINUX_VERSION_CODE >= kernel_version(4, 11, 9))
    /* destructor change to priv_destructor */
    netdev->priv_destructor              = oal_net_free_netdev;
    netdev->needs_free_netdev            = false;
#else
    oal_netdevice_destructor(netdev)     = oal_net_free_netdev;
#endif
    oal_netdevice_ifalias(netdev)        = HI_NULL;
    oal_netdevice_watchdog_timeo(netdev) = 5; /* �̶�����Ϊ 5 */
    oal_netdevice_wdev(netdev)           = wdev;
    oal_netdevice_qdisc(netdev, HI_NULL);

    wdev->iftype = type;
    wdev->wiphy  = mac_device->wiphy;
    wdev->netdev = netdev;    /* ��wdev �е�net_device ��ֵ */
    oal_netdevice_flags(netdev) &= ~OAL_IFF_RUNNING;    /* ��net device��flag��Ϊdown */

    if (wal_cfg80211_register_netdev(netdev) != HI_SUCCESS) {
        /* ע�᲻�ɹ����ͷ���Դ */
        oal_mem_free(wdev);
        oal_net_free_netdev(netdev);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

oal_wireless_dev *wal_cfg80211_add_virtual_intf_send_event(oal_net_device_stru *netdev,
    oal_wireless_dev *wdev, wlan_p2p_mode_enum_uint8 p2p_mode, wlan_vap_mode_enum_uint8 vap_mode)
{
    wal_msg_write_stru   write_msg;
    wal_msg_stru        *rsp_msg    = HI_NULL;
    oal_net_device_stru *netdev_cfg = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev_cfg == HI_NULL) {
        oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::pst_cfg_net_dev null!}");
        goto ERR_STEP;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev_cfg);
#endif
    /* ��д��Ϣ */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ADD_VAP, sizeof(mac_cfg_add_vap_param_stru));

    mac_cfg_add_vap_param_stru *add_vap_param = (mac_cfg_add_vap_param_stru *)(write_msg.auc_value);
    add_vap_param->net_dev  = netdev;
    add_vap_param->vap_mode = vap_mode;
#ifdef _PRE_WLAN_FEATURE_P2P
    add_vap_param->p2p_mode = p2p_mode;
#endif

    /* ������Ϣ */
    hi_u32 ret = wal_send_cfg_event(netdev_cfg, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_add_vap_param_stru), (hi_u8 *)&write_msg, HI_TRUE, &rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::wal_send_cfg_event return err code=%u}", ret);
        goto ERR_STEP;
    }

    /* ��ȡ���صĴ����� */
    if (wal_check_and_release_msg_resp(rsp_msg) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::check_and_release_msg_resp fail:err_code}");
        goto ERR_STEP;
    }

    /* ����netdevice��MAC��ַ��MAC��ַ��HMAC�㱻��ʼ����MIB�� */
    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::oal_net_dev_priv(pst_net_dev) is null ptr.}");
        goto ERR_STEP;
    }

    if (memcpy_s((hi_u8 *)oal_netdevice_mac_addr(netdev), WLAN_MAC_ADDR_LEN,
        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::mem safe function err!}");
        oal_mem_free(wdev);
        goto ERR_STEP;
    }

    /* ����VAP UP */
    wal_netdev_open(netdev);

    oam_warning_log1(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf:succ.vap_id[%d]}", mac_vap->vap_id);

    return wdev;

/* �쳣���� */
ERR_STEP: // ����ʧ��֮�󣬽����ڴ��ͷŵȲ������������⣬lint_t e801�澯����
    wal_cfg80211_unregister_netdev(netdev);
    /* ��ȥע�ᣬ���ͷ� */
    oal_mem_free(wdev);
    return ERR_PTR(-EAGAIN);
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_add_virtual_intf
 ��������  : ���ָ�����͵�net_device
 �������  : [1]wiphy
             [2]puc_name
             [3]type
             [4]pul_flags
             [5]params
 �������  : ��
 �� �� ֵ  : static oal_wireless_dev
*****************************************************************************/
#if (LINUX_VERSION_CODE >= kernel_version(4, 12, 0))
static oal_wireless_dev *wal_cfg80211_add_virtual_intf(oal_wiphy_stru *wiphy, const hi_char *puc_name,
    nl80211_iftype_uint8 name_assign_type, enum_nl80211_iftype type, oal_vif_params_stru *params)
#elif (LINUX_VERSION_CODE < kernel_version(3, 18, 0))
static oal_wireless_dev *wal_cfg80211_add_virtual_intf(oal_wiphy_stru *wiphy, const hi_char *puc_name,
    enum_nl80211_iftype type, hi_u32 *pul_flags, oal_vif_params_stru *params)
#else
static oal_wireless_dev *wal_cfg80211_add_virtual_intf(oal_wiphy_stru *wiphy, const hi_char *puc_name,
    nl80211_iftype_uint8 name_assign_type, enum_nl80211_iftype type, hi_u32 *pul_flags, oal_vif_params_stru *params)
#endif
{
    oal_wireless_dev    *wdev = HI_NULL;
    wlan_p2p_mode_enum_uint8  p2p_mode;
    wlan_vap_mode_enum_uint8  vap_mode;

#if (LINUX_VERSION_CODE < kernel_version(4, 12, 0))
    hi_unref_param(pul_flags);
#endif

    /* 1.1 ��μ�� */
    if ((wiphy == HI_NULL) || (puc_name == HI_NULL) || (params == HI_NULL)) {
        oam_error_log3(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf:: ptr is null,wiphy %p,name %p,params %p!}",
            (uintptr_t)wiphy, (uintptr_t)puc_name, (uintptr_t)params);
        return ERR_PTR(-EINVAL);
    }

    /* ��μ�����쳣��ֵ��������OALͳһ�ӿ� */
    mac_wiphy_priv_stru *wiphy_priv = oal_wiphy_priv(wiphy);
    mac_device_stru     *mac_device = wiphy_priv->mac_device;

    oam_warning_log1(0, OAM_SF_CFG, "{wal_cfg80211_add_virtual_intf::en_type[%d]!}", type);

    /* ���������net device�Ѿ����ڣ�ֱ�ӷ��� */
    oal_net_device_stru *netdev = oal_get_netdev_by_name(puc_name);
    if (netdev != HI_NULL) {
        /* ����oal_dev_get_by_name�󣬱������oal_dev_putʹnet_dev�����ü�����һ */
        oal_dev_put(netdev);
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::the net_device is already exist!}");
        wdev = netdev->ieee80211_ptr;
        return wdev;
    }

    if (wal_cfg80211_get_vap_p2p_mode(type, &p2p_mode, &vap_mode) != HI_SUCCESS) {
        return ERR_PTR(-EINVAL);
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    if (wal_cfg80211_add_virtual_intf_p2p_proc(mac_device) != HI_SUCCESS) {
        return ERR_PTR(-EAGAIN);
    }
#endif

    hi_u32 ret = wal_cfg80211_add_virtual_intf_get_netdev(puc_name, &netdev);
    if (ret == HI_FAIL) {
        return ERR_PTR(-ENOMEM);
    } else if (ret == HI_CONTINUE) {
        return HI_NULL;
    }

    wdev = (oal_wireless_dev *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(oal_wireless_dev));
    if (oal_unlikely(wdev == HI_NULL)) {
        oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_virtual_intf::alloc mem, pst_wdev is null ptr}");
        /* �쳣�����ͷ��ڴ� */
        oal_net_free_netdev(netdev);
        return ERR_PTR(-ENOMEM);
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(wdev, sizeof(oal_wireless_dev), 0, sizeof(oal_wireless_dev));

    if (wal_cfg80211_add_virtual_intf_set_wireless_dev(wdev, mac_device, netdev, type) != HI_SUCCESS) {
        return ERR_PTR(-EBUSY);
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    return wal_cfg80211_add_virtual_intf_send_event(netdev, wdev, p2p_mode, vap_mode);
}

hi_u32 wal_cfg80211_del_p2p_proc(wal_msg_write_stru *write_msg, oal_net_device_stru *netdev, mac_vap_stru *mac_vap)
{
#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8 p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(netdev->ieee80211_ptr->iftype);
    if (p2p_mode == WLAN_P2P_BUTT) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::get p2p mode err}");
        return HI_ERR_CODE_PTR_NULL;
    }

    ((mac_cfg_del_vap_param_stru *)write_msg->auc_value)->p2p_mode = mac_get_p2p_mode(mac_vap);

    hi_u32 ret = wal_set_p2p_status(netdev, P2P_STATUS_IF_DELETING);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::wal_set_p2p_status return %u}.", ret);
        return ret;
    }
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_del_virtual_intf
 ��������  : ɾ����ӦVAP
 �������  : oal_wiphy_stru            *pst_wiphy
             oal_wireless_dev     *pst_wdev
             hi_s32                  l_ifindex
 �������  : ��
 �� �� ֵ  : hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_s32 wal_cfg80211_del_virtual_intf(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev)
{
    wal_msg_stru       *rsp_msg = HI_NULL;
    wal_msg_write_stru  write_msg;

    if (oal_unlikely((wiphy == HI_NULL) || (wdev == HI_NULL))) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::pst_wiphy or pst_wdev null ptr error %p, %p}",
            (uintptr_t)wiphy, (uintptr_t)wdev);
        return -HI_ERR_CODE_PTR_NULL;
    }

    oal_net_device_stru *netdev  = wdev->netdev;
    mac_vap_stru        *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::mac_vap is null by netdev, mode[%d]}",
            netdev->ieee80211_ptr->iftype);
        return -HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::get_vap_stru fail.vap_id[%u]}", mac_vap->vap_id);
        return -HI_ERR_CODE_PTR_NULL;
    }

    oal_net_tx_stop_all_queues();
    wal_netdev_stop(netdev);

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    /* ��ʼ��ɾ��vap ���� */
    ((mac_cfg_del_vap_param_stru *)write_msg.auc_value)->net_dev = netdev;

    hi_u32 ret = wal_cfg80211_del_p2p_proc(&write_msg, netdev, mac_vap);
    if (ret != HI_SUCCESS) {
        return -HI_FAIL;
    }

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_DEL_VAP, sizeof(mac_cfg_del_vap_param_stru));

    /* ����linux work ɾ��net_device */
#ifdef _PRE_WLAN_FEATURE_P2P
    hmac_vap->del_net_device = netdev;
#endif

#if defined (_PRE_WLAN_FEATURE_P2P) && (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
    hi_workqueue_add_work(g_del_virtual_inf_workqueue, &(hmac_vap->del_virtual_inf_worker));
#endif

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_del_vap_param_stru), (hi_u8 *)&write_msg, HI_TRUE, &rsp_msg);

    if (wal_check_and_release_msg_resp(rsp_msg) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::wal_check_and_release_msg_resp fail}");
    }

    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_del_virtual_intf::return err code %d}", ret);
        return -HI_FAIL;
    }

    return HI_SUCCESS;
}

/* P2P ����ȱʧ��CFG80211�ӿ� */
hi_void wal_cfg80211_mgmt_frame_register(struct wiphy *wiphy, struct wireless_dev *wdev, hi_u16 frame_type, bool reg)
{
    return;
}

hi_s32 wal_cfg80211_set_bitrate_mask(struct wiphy *wiphy, oal_net_device_stru *netdev, const hi_u8 *peer,
    const struct cfg80211_bitrate_mask *mask)
{
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_p2p_device
 ��������  : ����P2P_DEV
 �������  : oal_wiphy_stru       *pst_wiphy
             oal_wireless_dev   *pst_wdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��11��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_s32 wal_cfg80211_start_p2p_device(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev)
{
    return -HI_FAIL;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_stop_p2p_device
 ��������  : ֹͣP2P_DEV
 �������  : oal_wiphy_stru       *pst_wiphy
             oal_wireless_dev   *pst_wdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��11��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void wal_cfg80211_stop_p2p_device(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev)
{
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_set_power_mgmt
 ��������  : ���ص͹���
 �������  : oal_wiphy_stru       *pst_wiphy
             oal_wireless_dev   *pst_wdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��07��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_s32 wal_cfg80211_set_power_mgmt(oal_wiphy_stru  *wiphy, oal_net_device_stru *netdev,
    bool enabled, hi_s32 timeout)
{
    wal_msg_write_stru           write_msg;
    mac_cfg_ps_open_stru        *sta_pm_open = HI_NULL;
    hi_u32                       ret;
    mac_vap_stru                *mac_vap = HI_NULL;

    /* host�͹���û�п�,��ʱ����device�ĵ͹��� */
    if (!hmac_get_wlan_pm_switch()) {
        return HI_SUCCESS;
    }

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_STA_PM_ON, sizeof(mac_cfg_ps_open_stru));
    mac_vap    = oal_net_dev_priv(netdev);
    if (oal_unlikely(mac_vap == NULL)) {
        oam_warning_log0(0, OAM_SF_PWR, "{wal_cfg80211_set_power_mgmt::get mac vap failed.}");
        return HI_SUCCESS;
    }

    /* P2P dev���·� */
    if (is_p2p_dev(mac_vap)) {
        oam_warning_log0(0, OAM_SF_PWR, "wal_cfg80211_set_power_mgmt:vap is p2p dev return");
        return HI_SUCCESS;
    }

    oam_warning_log3(0, OAM_SF_PWR, "{wal_cfg80211_set_power_mgmt::vap mode[%d]p2p mode[%d]set pm:[%d]}",
                     mac_vap->vap_mode, mac_vap->p2p_mode, enabled);

    sta_pm_open = (mac_cfg_ps_open_stru *)(write_msg.auc_value);
    /* MAC_STA_PM_SWITCH_ON / MAC_STA_PM_SWITCH_OFF */
    sta_pm_open->pm_enable      = enabled;
    sta_pm_open->pm_ctrl_type   = MAC_STA_PM_CTRL_TYPE_HOST;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ps_open_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_set_power_mgmt::fail to send pm cfg msg, error[%u]}", ret);
        return -HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_sched_scan
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_start_sched_scan(oal_net_device_stru *netdev, mac_pno_scan_stru *pno_scan_info)
{
    mac_pno_scan_stru      *pno_scan_params = HI_NULL;
    hi_u32                  ret;

    /* ����pno����ɨ��������˴�����hmac���ͷ� */
    pno_scan_params = (mac_pno_scan_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(mac_pno_scan_stru));
    if (pno_scan_params == HI_NULL) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_sched_scan::alloc pno scan param memory failed!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (memcpy_s(pno_scan_params, sizeof(mac_pno_scan_stru),
        pno_scan_info, sizeof(mac_pno_scan_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_sched_scan::mem safe function err!}");
        oal_mem_free(pno_scan_params);
        return HI_FAIL;
    }

    ret = (hi_u32)wal_cfg80211_start_req(netdev, &pno_scan_params, sizeof(mac_pno_scan_stru),
                                         WLAN_CFGID_CFG80211_START_SCHED_SCAN, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oal_mem_free(pno_scan_params);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_sched_scan_stop
 ��������  : ����ɨ��ر�
 �������  : oal_wiphy_stru                       *pst_wiphy
             oal_net_device_stru                  *pst_netdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/

#if (LINUX_VERSION_CODE >= kernel_version(4, 12, 0))
static hi_s32 wal_cfg80211_sched_scan_stop(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u64 reqid)
#else
static hi_s32 wal_cfg80211_sched_scan_stop(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev)
#endif
{
    hmac_device_stru               *hmac_dev = HI_NULL;
    mac_device_stru                *mac_device = HI_NULL;
    hmac_scan_stru                 *scan_mgmt = HI_NULL;
    wal_msg_write_stru              write_msg;
    hi_u32                          pedding_data = 0;       /* ������ݣ���ʹ�ã�ֻ��Ϊ�˸��ýӿ� */
    hi_u32                          ret;

    /* �����Ϸ��Լ�� */
    if ((wiphy == HI_NULL) || (netdev == HI_NULL)) {
        oam_error_log2(0, OAM_SF_CFG,
                       "{wal_cfg80211_sched_scan_stop::input param pointer is null, pst_wiphy[%p], pst_netdev[%p]!}",
                       (uintptr_t)wiphy, (uintptr_t)netdev);
        goto fail;
    }

    /* ͨ��net_device �ҵ���Ӧ��mac_device_stru �ṹ */
    hmac_dev = (hmac_device_stru *)hmac_get_device_stru();
    scan_mgmt = &(hmac_dev->scan_mgmt);

    oam_warning_log2(0, OAM_SF_SCAN, "{wal_cfg80211_sched_scan_stop::sched scan req[%p],sched scan complete[%d]}",
        (uintptr_t)scan_mgmt->sched_scan_req, scan_mgmt->sched_scan_complete);

    if ((scan_mgmt->sched_scan_req != HI_NULL) && (scan_mgmt->sched_scan_complete != HI_TRUE)) {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        /* �������ɨ������δִ�У����ϱ�����ɨ���� */
        if (scan_mgmt->request == HI_NULL) {
            mac_device = mac_res_get_dev();
            oal_cfg80211_sched_scan_result(mac_device->wiphy);
        }
#endif
        scan_mgmt->sched_scan_req     = HI_NULL;
        scan_mgmt->sched_scan_complete = HI_TRUE;

        /* ���¼�֪ͨdevice��ֹͣPNO����ɨ�� */
        wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CFG80211_STOP_SCHED_SCAN, sizeof(pedding_data));
        if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value),
            (hi_s8 *)&pedding_data, sizeof(pedding_data)) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_sched_scan_stop::mem safe function err!}");
            goto fail;
        }

        ret = wal_send_cfg_event(netdev,
                                 WAL_MSG_TYPE_WRITE,
                                 WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(pedding_data),
                                 (hi_u8 *)&write_msg,
                                 HI_FALSE,
                                 HI_NULL);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY,
                "{wal_cfg80211_sched_scan_stop::fail to stop pno sched scan, error[%u]}", ret);
            goto fail;
        }
    }

    return HI_SUCCESS;
fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_stop_ap
 ��������  : ֹͣAP
 �������  : oal_wiphy_stru        *pst_wiphy
             oal_net_device_stru *pst_netdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_s32 wal_cfg80211_stop_ap(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev)
{
    wal_msg_write_stru write_msg;

    hi_unref_param(wiphy);

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    /* �����Ϸ��Լ�� */
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::pst_netdev is null!}");
        goto fail;
    }
#endif
    /* ��ȡvap id */
    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::can't get mac vap from netdevice priv data!}");
        goto fail;
    }

    /* �ж��Ƿ�Ϊ��apģʽ */
    if ((mac_vap->vap_mode != WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        && (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)
#endif
    ) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_stop_ap::vap is not in ap mode!}");
        goto fail;
    }

    /* ���netdev����running״̬������Ҫdown */
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::vap is already down!}\r\n");
        return HI_SUCCESS;
    }

    /*****************************************************************************
        ������Ϣ��ͣ��ap
    *****************************************************************************/
    /* ��д��Ϣ */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_DOWN_VAP, sizeof(mac_cfg_start_vap_param_stru));

#ifdef _PRE_WLAN_FEATURE_P2P
    oal_wireless_dev    *wdev     = netdev->ieee80211_ptr;
    wlan_p2p_mode_enum_uint8  p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(wdev->iftype);
    if (WLAN_P2P_BUTT == p2p_mode) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::wal_wireless_iftype_to_mac_p2p_mode return BUFF}\r\n");
        goto fail;
    }
    oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_stop_ap::en_p2p_mode=%u}\r\n", p2p_mode);

    ((mac_cfg_start_vap_param_stru *)write_msg.auc_value)->p2p_mode = p2p_mode;
#endif

    ((mac_cfg_start_vap_param_stru *)write_msg.auc_value)->net_dev = netdev;

    /* ������Ϣ */
    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_start_vap_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_stop_ap::failed to stop ap, error[%u]}", ret);
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

hi_void wal_cfg80211_set_iftype(const mac_cfg_add_vap_param_stru *add_vap_param, oal_wireless_dev *wdev)
{
    if (add_vap_param->vap_mode == WLAN_VAP_MODE_BSS_AP) {
        wdev->iftype = NL80211_IFTYPE_AP;
    } else if (add_vap_param->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        wdev->iftype = NL80211_IFTYPE_STATION;
#ifdef _PRE_WLAN_FEATURE_MESH
    } else if (add_vap_param->vap_mode == WLAN_VAP_MODE_MESH) {
        wdev->iftype = NL80211_IFTYPE_MESH_POINT;
#endif
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    if (add_vap_param->p2p_mode == WLAN_P2P_DEV_MODE) {
        wdev->iftype = NL80211_IFTYPE_P2P_DEVICE;
    } else if (add_vap_param->p2p_mode == WLAN_P2P_CL_MODE) {
        wdev->iftype = NL80211_IFTYPE_P2P_CLIENT;
    } else if (add_vap_param->p2p_mode == WLAN_P2P_GO_MODE) {
        wdev->iftype = NL80211_IFTYPE_P2P_GO;
    }
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_add_vap
 ��������  : CFG80211 �ӿ���������豸
 �������  : mac_cfg_add_vap_param_stru *pst_add_vap_param
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��1��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_add_vap(const mac_cfg_add_vap_param_stru *add_vap_param)
{
    /* DTS2015022603795 : P2P change interfaceʱ����Ҫ���³�ʼ����ע��netdev.
     * nl80211 netlink pre diot �л��ȡrntl_lock�������� ע��net_device ���ȡrntl_lock����������������� */
    wal_msg_write_stru     write_msg;
    wal_msg_stru          *rsp_msg    = HI_NULL;
    oal_net_device_stru   *netdev     = add_vap_param->net_dev;
    oal_wireless_dev      *wdev       = netdev->ieee80211_ptr;
    oal_net_device_stru   *netdev_cfg = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);

    if (netdev_cfg == HI_NULL) {
        oal_mem_free(wdev);
        oal_net_free_netdev(netdev);
        oam_warning_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_vap::pst_cfg_net_dev is null!}");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev_cfg);
#endif
    wal_cfg80211_set_iftype(add_vap_param, wdev);

    oal_netdevice_flags(netdev) &= ~OAL_IFF_RUNNING;   /* ��net device��flag��Ϊdown */

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    /* ��д��Ϣ */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ADD_VAP, sizeof(mac_cfg_add_vap_param_stru));
    ((mac_cfg_add_vap_param_stru *)write_msg.auc_value)->net_dev      = netdev;
    ((mac_cfg_add_vap_param_stru *)write_msg.auc_value)->vap_mode     = add_vap_param->vap_mode;
    ((mac_cfg_add_vap_param_stru *)write_msg.auc_value)->cfg_vap_indx = WLAN_CFG_VAP_ID;
#ifdef _PRE_WLAN_FEATURE_P2P
    ((mac_cfg_add_vap_param_stru *)write_msg.auc_value)->p2p_mode     = add_vap_param->p2p_mode;
#endif

    /* ������Ϣ */
    hi_u32 ret = wal_send_cfg_event(netdev_cfg, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_add_vap_param_stru), (hi_u8 *)&write_msg, HI_TRUE, &rsp_msg);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oal_mem_free(wdev);
        oal_net_free_netdev(netdev);
        oam_warning_log1(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_vap::return err code [%u]}", ret);
        return ret;
    }

    /* ��ȡ���صĴ����� */
    ret = wal_check_and_release_msg_resp(rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_cfg80211_add_vap::hmac add vap Err=%u}", ret);
        /* �쳣�����ͷ��ڴ� */
        oal_mem_free(wdev);
        oal_net_free_netdev(netdev);
        return ret;
    }

    wal_set_mac_to_mib(add_vap_param->net_dev);    /* by lixu tmp */

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_del_vap
 ��������  : CFG80211 �ӿ�ɾ�������豸
 �������  : mac_cfg_del_vap_param_stru *pst_del_vap_param
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��1��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_del_vap(const mac_cfg_del_vap_param_stru *del_vap_param)
{
    hi_u32                       ret;
    wal_msg_write_stru           write_msg;
    wal_msg_stru                *rsp_msg = HI_NULL;
    oal_net_device_stru         *netdev = HI_NULL;

    if (oal_unlikely(del_vap_param == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::pst_del_vap_param null ptr !}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    netdev = del_vap_param->net_dev;
    /* �豸��up״̬������ɾ����������down */
    if (oal_unlikely(0 != (OAL_IFF_RUNNING & oal_netdevice_flags(netdev)))) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::device is busy, please down it first %d!}\r\n",
            oal_netdevice_flags(netdev));
        return HI_ERR_CODE_CONFIG_BUSY;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    /* ��ʼ��ɾ��vap ���� */
    ((mac_cfg_del_vap_param_stru *)write_msg.auc_value)->net_dev = netdev;
#ifdef _PRE_WLAN_FEATURE_P2P
    ((mac_cfg_del_vap_param_stru *)write_msg.auc_value)->p2p_mode = del_vap_param->p2p_mode;
#endif
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_DEL_VAP, sizeof(mac_cfg_del_vap_param_stru));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_del_vap_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_TRUE,
                             &rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::return err code [%u]!}\r\n", ret);
        return ret;
    }

    if (HI_SUCCESS != wal_check_and_release_msg_resp(rsp_msg)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_vap::wal_check_and_release_msg_resp fail!}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_connect
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_start_connect(oal_net_device_stru *netdev,
    const mac_cfg80211_connect_param_stru *mac_cfg80211_connect_param)
{
    return wal_cfg80211_start_req(netdev,
                                  mac_cfg80211_connect_param,
                                  sizeof(mac_cfg80211_connect_param_stru),
                                  WLAN_CFGID_CFG80211_START_CONNECT,
                                  HI_TRUE);
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_disconnect
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_start_disconnect(oal_net_device_stru *netdev, const mac_cfg_kick_user_param_stru *disconnect_param)
{
    /* ע�� ������Ϣδ���������ֱ�ӷ��أ�����WPA_SUPPLICANT�����·���Ϣ����������ȵ�����ʱ���쳣���ѣ�
       ���º����·�����Ϣ����Ϊ����ʧ�ܣ�Ŀǰ��ȥ�����¼��޸�Ϊ�ȴ���Ϣ������������ϱ���
       ���һ�������HI_FALSE��ΪHI_TRUE */
    return wal_cfg80211_start_req(netdev, disconnect_param, sizeof(mac_cfg_kick_user_param_stru),
                                  WLAN_CFGID_KICK_USER, HI_TRUE);
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_unregister_netdev
 ��������  : �ں�ȥע��ָ�����͵�net_device,������Ҫ��mutex lock��Ӧ��
 �������  : mac_device_stru *pst_hmac_device
             oal_net_device_stru *pst_net_dev
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_cfg80211_unregister_netdev(oal_net_device_stru *netdev)
{
    /* ȥע��netdev */
    oal_net_unregister_netdev(netdev);
    oal_net_free_netdev(netdev);
}

#if (LINUX_VERSION_CODE >= kernel_version(4,1,0))
static hi_void wal_cfg80211_abort_scan(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev)
{
    oal_net_device_stru *netdev = HI_NULL;

    /* 1.1 ��μ�� */
    if ((wiphy == HI_NULL) || (wdev == HI_NULL)) {
        oam_error_log2(0, OAM_SF_CFG, "{wal_cfg80211_abort_scan::wiphy or wdev is null, %p, %p!}",
                       wiphy, wdev);
        return;
    }
    netdev = wdev->netdev;
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_abort_scan::netdev is null!}\r\n");
        return;
    }
    oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_abort_scan::enter!}\r\n");
    wal_force_scan_complete(netdev);
    return;
}
#endif
#endif /* #if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) */

/*****************************************************************************
 �� �� ��  : wal_parse_rsn_ie
 ��������  : ����beacon֡�е� RSN ��ϢԪ��
 �������  : [1]puc_ie
             [2]beacon_param
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 wal_parse_rsn_ie(const hi_u8 *puc_ie, mac_beacon_param_stru *beacon_param)
{
    /*************************************************************************/
    /*                  RSN Element Format                                   */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length | Version | Group Cipher Suite | Pairwise Cipher */
    /* --------------------------------------------------------------------- */
    /* |     1     |    1   |    2    |         4          |       2         */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Suite Count| Pairwise Cipher Suite List | AKM Suite Count | AKM Suite List */
    /* ---------------------------------------------------------------------  */
    /*            |         4*m                |     2           |   4*n      */
    /* ---------------------------------------------------------------------  */
    /* ---------------------------------------------------------------------  */
    /* |RSN Capabilities|PMKID Count|PMKID List|Group Management Cipher Suite */
    /* ---------------------------------------------------------------------  */
    /* |        2       |    2      |   16 *s  |               4           |  */
    /* ---------------------------------------------------------------------  */
    /*                                                                        */
    /**************************************************************************/
    hi_u8 auc_oui[MAC_OUI_LEN] = {MAC_WLAN_OUI_RSN0, MAC_WLAN_OUI_RSN1, MAC_WLAN_OUI_RSN2};
    hi_u8 index = 2; /* 2: ���� RSN IE �� IE ���� */

    /* ������С��2��ȡ�����ֵ�����쳣 */
    if (puc_ie[1] < MAC_MIN_RSN_LEN) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_parse_rsn_ie::invalid RSN IE len[%d]!}\r\n", puc_ie[1]);
        return HI_FAIL;
    }

    /* ��ȡRSN �汾�� */
    if (hi_makeu16(puc_ie[index], puc_ie[index + 1]) != MAC_RSN_IE_VERSION) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN version illegal!}\r\n");
        return HI_FAIL;
    }

    index += 2;  /* 2: ���� RSN �汾�ų��� */

    /* ��ȡ�鲥��Կ�׼� */
    if (memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN) != 0) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN group OUI illegal!}\r\n");
        return HI_FAIL;
    }
    beacon_param->group_crypto = puc_ie[index + MAC_OUI_LEN];

    index += 4; /* 4: �����鲥��Կ�׼����� */

    /* ��ȡ�ɶ���Կ�׼� */
    hi_u16 us_pcip_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    if (us_pcip_num > MAC_PAIRWISE_CIPHER_SUITES_NUM) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_parse_rsn_ie::pairwise chiper num illegal!}\r\n", us_pcip_num);
        return HI_FAIL;
    }

    /* �������׼���ʼ��Ϊ0xff */ /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(beacon_param->auc_pairwise_crypto_wpa2, MAC_PAIRWISE_CIPHER_SUITES_NUM, 0xff,
        MAC_PAIRWISE_CIPHER_SUITES_NUM);

    index += 2; /* 2: ��ȡ�����׼� */
    for (hi_u16 us_temp = 0; us_temp < us_pcip_num; us_temp++) {
        if (0 != memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN)) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN paerwise OUI illegal!}\r\n");
            return HI_FAIL;
        }
        beacon_param->auc_pairwise_crypto_wpa2[us_temp] = puc_ie[index + MAC_OUI_LEN];

        index += 4; /* 4: �׼����� */
    }

    /* ��ȡ��֤�׼����� */
    hi_u16 us_auth_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    us_auth_num = oal_min(us_auth_num, WLAN_AUTHENTICATION_SUITES);
    index += 2; /* 2: ��ȡ��֤���� */

    /* ����֤�׼���ʼ��Ϊ0xff */ /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(beacon_param->auc_auth_type, us_auth_num, 0xff, us_auth_num);

    /* ��ȡ��֤���� */
    for (hi_u16 auth_temp = 0; auth_temp < us_auth_num; auth_temp++) {
        if (0 != memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN)) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_parse_rsn_ie::RSN auth OUI illegal!}\r\n");
            return HI_FAIL;
        }
        beacon_param->auc_auth_type[auth_temp] = puc_ie[index + MAC_OUI_LEN];
        index += 4; /* 4: ���ͳ��� */
    }

    /* ��ȡRSN ������Ϣ */
    beacon_param->us_rsn_capability = hi_makeu16(puc_ie[index], puc_ie[index + 1]);

    /* ���ü���ģʽ */
    beacon_param->crypto_mode |= WLAN_WPA2_BIT;

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_parse_wpa_ie
 ��������  : ����beacon֡�е� WPA ��ϢԪ��
 �������  : [1]puc_ie
             [2]beacon_param
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 wal_parse_wpa_ie(const hi_u8 *puc_ie, mac_beacon_param_stru *beacon_param)
{
    hi_u8  auc_oui[MAC_OUI_LEN] = {MAC_WLAN_OUI_MICRO0, MAC_WLAN_OUI_MICRO1, MAC_WLAN_OUI_MICRO2};

    /**************************************************************************/
    /*                  WPA Element Format                                    */
    /* ---------------------------------------------------------------------  */
    /* |Element ID | Length |    WPA OUI    |  Version |  Group Cipher Suite  */
    /* ---------------------------------------------------------------------  */
    /* |     1     |   1    |        4      |     2    |         4            */
    /* ---------------------------------------------------------------------  */
    /* ---------------------------------------------------------------------  */
    /* Pairwise Cipher |  Pairwise Cipher   |                 |               */
    /* Suite Count     |    Suite List      | AKM Suite Count |AKM Suite List */
    /* ---------------------------------------------------------------------  */
    /*        2        |          4*m       |         2       |     4*n       */
    /* ---------------------------------------------------------------------  */
    /*                                                                        */
    /**************************************************************************/
    hi_u8 index = 2 + 4; /* 2 4: ���� WPA IE(1 �ֽ�) ��IE ����(1 �ֽ�) ��WPA OUI(4 �ֽ�) */

    hi_u16 us_ver = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    /* �Ա�WPA �汾��Ϣ */
    if (us_ver != MAC_WPA_IE_VERSION) {
        oam_error_log0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA version illegal!}\r\n");
        return HI_FAIL;
    }

    index += 2; /* 2: ���� �汾�� ���� */

    hi_u8 *puc_pcip_policy = beacon_param->auc_pairwise_crypto_wpa;
    hi_u8 *puc_auth_policy = beacon_param->auc_auth_type;

    /* ��ȡ�鲥��Կ�׼� */
    if (memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN) != 0) {
        oam_error_log0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA group OUI illegal!}\r\n");
        return HI_FAIL;
    }
    beacon_param->group_crypto = puc_ie[index + MAC_OUI_LEN];

    index += 4; /* 4: �����鲥��Կ�׼����� */

    /* ��ȡ�ɶ���Կ�׼� */
    hi_u16 us_pcip_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    if (us_pcip_num > MAC_PAIRWISE_CIPHER_SUITES_NUM) {
        oam_error_log1(0, OAM_SF_WPA, "{wal_parse_wpa_ie::pairwise chiper num illegal %d!}\r\n", us_pcip_num);
        return HI_FAIL;
    }

    /* �������׼���ʼ��Ϊ0xff */ /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ�� */
    memset_s(beacon_param->auc_pairwise_crypto_wpa, MAC_PAIRWISE_CIPHER_SUITES_NUM, 0xff,
        MAC_PAIRWISE_CIPHER_SUITES_NUM);

    index += 2; /* 2: ��ȡ�׼� */
    for (hi_u16 us_temp = 0; us_temp < us_pcip_num; us_temp++) {
        if (memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN) != 0) {
            oam_error_log0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA pairwise OUI illegal!}\r\n");
            return HI_FAIL;
        }
        puc_pcip_policy[us_temp] = puc_ie[index + MAC_OUI_LEN];
        index += 4; /* 4: �׼����� */
    }

    /* ��ȡ��֤�׼����� */
    hi_u16 us_auth_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    us_auth_num = oal_min(us_auth_num, MAC_AUTHENTICATION_SUITE_NUM);
    index += 2; /* 2 ��ȡ��֤���� */

    /* ����֤�׼���ʼ��Ϊ0xff */
    if (memset_s(puc_auth_policy, us_auth_num, 0xff, us_auth_num) != EOK) {
        return HI_FAIL;
    }
    /* ��ȡ��֤���� */
    for (hi_u16 auth_temp = 0; auth_temp < us_auth_num; auth_temp++) {
        if (memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN) != 0) {
            oam_error_log0(0, OAM_SF_WPA, "{wal_parse_wpa_ie::WPA auth OUI illegal!}\r\n");
            return HI_FAIL;
        }
        puc_auth_policy[auth_temp] = puc_ie[index + MAC_OUI_LEN];
        index += 4; /* 4: ���ͳ��� */
    }

    /* ���ü���ģʽ */
    beacon_param->crypto_mode |= WLAN_WPA_BIT;

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_parse_wpa_wpa2_ie
 ��������  : �����ں˴��ݹ�����beacon��Ϣ�е�WPA/WPA2 ��ϢԪ��
 �������  : oal_beacon_parameters *pst_beacon_info
             mac_beacon_param_stru *pst_beacon_param
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��12��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_parse_wpa_wpa2_ie(const oal_beacon_parameters *beacon_info, mac_beacon_param_stru *beacon_param)
{
    const hi_u8         *puc_rsn_ie = HI_NULL;
    hi_u8               *puc_wpa_ie = HI_NULL;
    hi_u32               ret;
    oal_ieee80211_mgmt  *mgmt   = HI_NULL;
    hi_u16               us_capability_info;

    /* �ж��Ƿ���� */
    mgmt = (oal_ieee80211_mgmt *)beacon_info->head;
    us_capability_info = mgmt->u.beacon.capab_info;
    beacon_param->privacy = HI_FALSE;
    if (WLAN_WITP_CAPABILITY_PRIVACY & us_capability_info) {
        beacon_param->privacy = HI_TRUE;

        /* ���� RSN ��ϢԪ�� */
        puc_rsn_ie = mac_find_ie(MAC_EID_RSN, beacon_info->tail, beacon_info->tail_len);
        if (puc_rsn_ie != HI_NULL) {
            /* ����RSN ��ϢԪ�ؽ�������֤���� */
            ret = wal_parse_rsn_ie(puc_rsn_ie, beacon_param);
            if (ret != HI_SUCCESS) {
                oam_warning_log0(0, OAM_SF_WPA, "{wal_parse_wpa_wpa2_ie::Failed to parse RSN ie!}\r\n");
                return HI_FAIL;
            }
        }

        /* ���� WPA ��ϢԪ�أ�����������֤���� */
        puc_wpa_ie = mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_OUITYPE_WPA,
                                        beacon_info->tail, (hi_s32)beacon_info->tail_len);
        if (puc_wpa_ie != HI_NULL) {
            ret = wal_parse_wpa_ie(puc_wpa_ie, beacon_param);
            if (ret != HI_SUCCESS) {
                oam_warning_log0(0, OAM_SF_WPA, "{wal_parse_wpa_wpa2_ie::Failed to parse WPA ie!}\r\n");
                return HI_FAIL;
            }
        }
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  : �����ں˴��ݹ���beacon��Ϣ�е�mesh configuration��ϢԪ��
 �������  : oal_beacon_parameters *pst_beacon_info
 �� �� ֵ  : hi_u32
 �޸���ʷ      :
  1.��    ��   : 2019��3��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_parse_mesh_conf_ie(const oal_beacon_parameters *beacon_info, mac_beacon_param_stru *beacon_param)
{
    const hi_u8 *puc_mesh_conf_ie = HI_NULL;
    hi_u8 index = 0;

    /* ���� mesh conf��ϢԪ�� */
    puc_mesh_conf_ie = mac_find_ie(MAC_EID_MESH_CONF, beacon_info->tail, beacon_info->tail_len);
    if (puc_mesh_conf_ie != HI_NULL) {
        /* ����Mesh Conf��ϢԪ�ؽ�����mesh������ */
        /* ������С��2��ȡ�����ֵ�����쳣 */
        if (puc_mesh_conf_ie[1] < MAC_MIN_MESH_CONF_LEN) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_parse_mesh_conf_ie::invalid mesh conf IE len[%d]!}\r\n",
                puc_mesh_conf_ie[1]);
            return HI_FAIL;
        }

        index += 6; /* 6: ���� Mesh conf IE �� IE ���� ,ѡ·�㷨���������� */
        beacon_param->mesh_auth_protocol = puc_mesh_conf_ie[index++];
        beacon_param->mesh_formation_info = puc_mesh_conf_ie[index++];
        beacon_param->mesh_capability = puc_mesh_conf_ie[index];
        oam_warning_log3(0, OAM_SF_ANY,
            "{wal_parse_mesh_conf_ie::auth_protocol = %d, formation_info = %d, capability = %d!}",
            beacon_param->mesh_auth_protocol, beacon_param->mesh_formation_info, beacon_param->mesh_capability);
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_parse_mesh_conf_ie::mesh vap can't find mesh conf ie!}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 �� �� ��  : wal_check_support_basic_rate_6M
 ��������  : �ж�ָ�����ʼ�����չ���ʼ����Ƿ����6M������Ϊ��������
 �������  : [1]puc_supported_rates_ie
             [2]supported_rates_num
             [3]puc_extended_supported_rates_ie
             [4]extended_supported_rates_num
 �������  : ��
 �� �� ֵ  : static hi_bool : HI_TRUE    ֧��
                              HI_FALSE   ��֧��
*****************************************************************************/
static hi_bool wal_check_support_basic_rate_6m(const hi_u8 *puc_supported_rates_ie, hi_u8 supported_rates_num,
    const hi_u8 *puc_extended_supported_rates_ie, hi_u8 extended_supported_rates_num)
{
    hi_u8     loop;
    hi_bool support = HI_FALSE;
    for (loop = 0; loop < supported_rates_num; loop++) {
        if (puc_supported_rates_ie == HI_NULL) {
            break;
        }
        if (puc_supported_rates_ie[2 + loop] == 0x8c) { /* 2��ƫ��λ */
            support = HI_TRUE;
        }
    }

    for (loop = 0; loop < extended_supported_rates_num; loop++) {
        if (puc_extended_supported_rates_ie == HI_NULL) {
            break;
        }
        if (puc_extended_supported_rates_ie[2 + loop] == 0x8c) { /* 2��ƫ��λ */
            support = HI_TRUE;
        }
    }

    return support;
}

/*****************************************************************************
 �� �� ��  : wal_parse_protocol_mode
 ��������  : ����Э��ģʽ
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��6��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_parse_protocol_mode(wlan_channel_band_enum_uint8 band, const oal_beacon_parameters *beacon_info,
    const hi_u8 *puc_ht_ie, const hi_u8 *puc_vht_ie, wlan_protocol_enum_uint8 *pen_protocol)
{
    hi_u8   *puc_supported_rates_ie             = HI_NULL;
    hi_u8   *puc_extended_supported_rates_ie    = HI_NULL;
    hi_u8    supported_rates_num             = 0;
    hi_u8    extended_supported_rates_num    = 0;
    hi_u16   us_offset;

    if (puc_vht_ie != HI_NULL) {
        /* ����AP Ϊ11ac ģʽ */
        *pen_protocol = WLAN_VHT_MODE;
        return HI_SUCCESS;
    }
    if (puc_ht_ie != HI_NULL) {
        /* ����AP Ϊ11n ģʽ */
        *pen_protocol = WLAN_HT_MODE;
        return HI_SUCCESS;
    }

    if (WLAN_BAND_2G == band) {
        us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
        if (beacon_info->head_len > us_offset) {
            puc_supported_rates_ie = mac_find_ie(MAC_EID_RATES,
                beacon_info->head + 24 + us_offset, beacon_info->head_len - us_offset); /* mac header����24 */
            if (puc_supported_rates_ie != HI_NULL) {
                supported_rates_num = puc_supported_rates_ie[1];
            }
        }
        puc_extended_supported_rates_ie = mac_find_ie(MAC_EID_XRATES, beacon_info->tail, beacon_info->tail_len);
        if (puc_extended_supported_rates_ie != HI_NULL) {
            extended_supported_rates_num = puc_extended_supported_rates_ie[1];
        }

        if (supported_rates_num + extended_supported_rates_num == 4) { /* �ж���IE�����Ƿ�Ϊ4��ѡ��ģʽ */
            *pen_protocol = WLAN_LEGACY_11B_MODE;
            return HI_SUCCESS;
        }
        if (supported_rates_num + extended_supported_rates_num == 8) { /* �ж���IE�����Ƿ�Ϊ8��ѡ��ģʽ */
            *pen_protocol = WLAN_LEGACY_11G_MODE;
            return HI_SUCCESS;
        }
        if (supported_rates_num + extended_supported_rates_num == 12) { /* �ж���IE�����Ƿ�Ϊ12��ѡ��ģʽ */
            /* ���ݻ�����������Ϊ 11gmix1 ���� 11gmix2 */
            /* ����������ʼ�֧�� 6M , ���ж�Ϊ 11gmix2 */
            *pen_protocol = WLAN_MIXED_ONE_11G_MODE;
            if (wal_check_support_basic_rate_6m(puc_supported_rates_ie, supported_rates_num,
                                                puc_extended_supported_rates_ie,
                                                extended_supported_rates_num) == HI_TRUE) {
                *pen_protocol = WLAN_MIXED_TWO_11G_MODE;
            }
            return HI_SUCCESS;
        }
    }

    /* �����������Ϊ���ò����� */
    *pen_protocol = WLAN_PROTOCOL_BUTT;

    return HI_FAIL;
}

/*****************************************************************************
 �� �� ��  : wal_parse_ht_vht_ie
 ��������  : �����ں˴��ݹ�����beacon��Ϣ�е�ht_vht ��ϢԪ��
 �������  : oal_beacon_parameters *pst_beacon_info
             mac_beacon_param_stru *pst_beacon_param
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��4��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_parse_ht_vht_ie(const mac_vap_stru *mac_vap, const oal_beacon_parameters  *beacon_info,
    mac_beacon_param_stru  *beacon_param)
{
    hi_u8 *puc_ht_ie  = mac_find_ie(MAC_EID_HT_CAP, beacon_info->tail, beacon_info->tail_len);
    hi_u8 *puc_vht_ie = mac_find_ie(MAC_EID_VHT_CAP, beacon_info->tail, beacon_info->tail_len);

    /* ����Э��ģʽ */
    hi_u32 ret = wal_parse_protocol_mode(mac_vap->channel.band, beacon_info, puc_ht_ie,
        puc_vht_ie, &beacon_param->protocol);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_parse_ht_vht_ie::return err code!}\r\n", ret);
        return ret;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    /* ���ƻ�ʵ��P2P GO 2.4G��Ĭ��֧��11ac Э��ģʽ */
    if (is_p2p_go(mac_vap) && (WLAN_BAND_2G == mac_vap->channel.band)) {
        beacon_param->protocol = ((HI_TRUE == mac_vap->cap_flag.ac2g) ? WLAN_VHT_MODE : WLAN_HT_MODE);
    }
#endif /* _PRE_WLAN_FEATURE_P2P */

    /* ����short gi���� */
    if (puc_ht_ie == HI_NULL) {
        return HI_SUCCESS;
    }

    /* ʹ��ht cap ie���������2���ֽ� */
    if (puc_ht_ie[1] < sizeof(mac_frame_ht_cap_stru)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_parse_ht_vht_ie::invalid htcap ie len %d}\n", puc_ht_ie[1]);
        return HI_SUCCESS;
    }

    mac_frame_ht_cap_stru *ht_cap = (mac_frame_ht_cap_stru *)(puc_ht_ie + MAC_IE_HDR_LEN);

    beacon_param->shortgi_20 = (hi_u8)ht_cap->short_gi_20mhz;
    beacon_param->shortgi_40 = 0;

    if ((mac_vap->channel.en_bandwidth > WLAN_BAND_WIDTH_20M)
        && (mac_vap->channel.en_bandwidth != WLAN_BAND_WIDTH_BUTT)) {
        beacon_param->shortgi_40 = (hi_u8)ht_cap->short_gi_40mhz;
    }

    beacon_param->smps_mode = (hi_u8)ht_cap->sm_power_save;

    if (puc_vht_ie == HI_NULL) {
        return HI_SUCCESS;
    }

    /* ʹ��vht cap ie���������4���ֽ� */
    if (puc_vht_ie[1] < sizeof(mac_vht_cap_info_stru)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_parse_ht_vht_ie::invalid ht cap ie len[%d]!}\r\n",
            puc_vht_ie[1]);
        return HI_SUCCESS;
    }

    mac_vht_cap_info_stru *vht_cap = (mac_vht_cap_info_stru *)(puc_vht_ie + MAC_IE_HDR_LEN);

    beacon_param->shortgi_80 = 0;

    if ((mac_vap->channel.en_bandwidth > WLAN_BAND_WIDTH_40MINUS)
        && (mac_vap->channel.en_bandwidth != WLAN_BAND_WIDTH_BUTT)) {
        beacon_param->shortgi_80 = vht_cap->short_gi_80mhz;
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_QUICK_START
hi_u32 g_l_scan_enable = HI_FALSE;
hi_u32 hisi_quick_set_scan_enable(hi_s32 l_enable_flag)
{
    return g_l_scan_enable = l_enable_flag;
}
hi_u32 hisi_quick_get_scan_enable(hi_void)
{
    return g_l_scan_enable;
}
#endif

/*****************************************************************************
 �� �� ��  : wal_cfg80211_scan
 ��������  : �ں˵�������ɨ��Ľӿں���
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_scan(oal_wiphy_stru *wiphy, oal_cfg80211_scan_request_stru *request)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_scan(oal_wiphy_stru *wiphy, oal_cfg80211_scan_request_stru *request)
#endif
{
    hmac_device_stru           *hmac_dev = HI_NULL;
    mac_vap_stru               *mac_vap = HI_NULL;
    hmac_scan_stru             *scan_mgmt = HI_NULL;
    oal_net_device_stru        *netdev = HI_NULL;

    if ((wiphy == HI_NULL) || (request == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_scan::parameter is wrong, return fail!}");
        goto fail;
    }

    oam_info_log2(0, OAM_SF_SCAN, "{wal_cfg80211_scan::request to scan, channel:%d, ssid:%d}",
                  request->n_channels, request->n_ssids);

    netdev = (request->wdev == HI_NULL ? HI_NULL : request->wdev->netdev);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_scan::acquire netdev fail, return fail!}");
        goto fail;
    }

    /* ͨ��net_device �ҵ���Ӧ��mac_vap_stru �ṹ */
    mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_scan::cann't acquire mac_vap from netdev, return fail!}");
        goto fail;
    }

#ifdef _PRE_WLAN_FEATURE_WAPI
    if (is_p2p_scan_req(request) && (HI_TRUE == hmac_user_is_wapi_connected())) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_cfg80211_scan::cann't execute p2p scan under wapi mode, return!}");
        goto fail;
    }
#endif/* #ifdef _PRE_WLAN_FEATURE_WAPI */

    hmac_dev = hmac_get_device_stru();
    scan_mgmt = &(hmac_dev->scan_mgmt);

    /* ���ɨ��δ��ɣ���ֱ�ӷ��� */
    if (scan_mgmt->complete == HI_FALSE) {
        oam_warning_log0(0, OAM_SF_SCAN,
            "{wal_cfg80211_scan::the last scan is still running, refuse this scan request.}");
        goto fail;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    /* �����ǰ����ɨ�������У�����ͣ����ɨ�� */
    if (scan_mgmt->sched_scan_req != HI_NULL) {
#if (LINUX_VERSION_CODE >= kernel_version(4, 12, 0))
        wal_cfg80211_sched_scan_stop(wiphy, netdev, 0);
#else
        wal_cfg80211_sched_scan_stop(wiphy, netdev);
#endif
    }
#endif

    /* ���浱ǰ�·���ɨ�����󵽱��� */
    scan_mgmt->request = request;

    /* ����ɨ�� */
    if (HI_SUCCESS != wal_start_scan_req(netdev, scan_mgmt)) {
        scan_mgmt->request = HI_NULL;
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_set_wep_key
 ��������  : ����wep������Ϣ
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��11��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  1.��    ��   : 2014��01��24��
    ��    ��   : Hisilicon
    �޸�����   : �޸ĺ����� ���ں˿���wep ������Ϣ������

*****************************************************************************/
static hi_u32 wal_set_wep_key(mac_cfg80211_connect_param_stru *connect_param,
    const oal_cfg80211_connect_params_stru *sme)
{
    connect_param->puc_wep_key            = sme->key;
    connect_param->wep_key_len         = sme->key_len;
    connect_param->wep_key_index       = sme->key_idx;
    connect_param->crypto.cipher_group = (hi_u8)sme->crypto.cipher_group;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ʹ��PMF STAUT�·�n_akm_suites==0��RSN�������
 �������  : mac_cfg80211_connect_param_stru   *pst_connect_param
             oal_cfg80211_connect_params_stru    *pst_sme
 �� �� ֵ  : static hi_u32
*****************************************************************************/
static hi_u32 wal_set_crypto_pmf(mac_cfg80211_connect_param_stru *connect,
    const oal_cfg80211_connect_params_stru *sme, const hi_u8 *puc_ie)
{
    /* ����WPA/WPA2 ������Ϣ */
    connect->crypto.control_port = (hi_u8)sme->crypto.control_port;
    connect->crypto.wpa_versions = (hi_u8)sme->crypto.wpa_versions;

    /* ��ȡgroup cipher type */
    connect->crypto.cipher_group = puc_ie[MAC_IE_HDR_LEN + MAC_RSN_VERSION_LEN + MAC_OUI_LEN];

    /* ��ȡpairwise cipher cout */
    hi_u32 offset = MAC_IE_HDR_LEN + MAC_RSN_VERSION_LEN + MAC_OUI_LEN + MAC_OUITYPE_WPA;
    connect->crypto.n_ciphers_pairwise = puc_ie[offset];
    connect->crypto.n_ciphers_pairwise += (hi_u8)(puc_ie[offset + 1] << 8); /* ����8λ */
    if (connect->crypto.n_ciphers_pairwise > OAL_NL80211_MAX_NR_CIPHER_SUITES) {
        oam_warning_log1(0, 0, "{wal_set_crypto_pmf:invalid ciphers len:%d!}", connect->crypto.n_ciphers_pairwise);
        return HI_FAIL;
    }
    /* ��ȡpairwise cipher type */
    offset += MAC_RSN_CIPHER_COUNT_LEN;
    if (connect->crypto.n_ciphers_pairwise) {
        for (hi_u8 loop2 = 0; loop2 < connect->crypto.n_ciphers_pairwise; loop2++) {
            connect->crypto.ciphers_pairwise[loop2] = (hi_u8)puc_ie[offset + MAC_OUI_LEN];
            offset += (MAC_OUITYPE_WPA + MAC_OUI_LEN);
        }
    }

    /* ��ȡAKM cout */
    connect->crypto.n_akm_suites = puc_ie[offset];
    connect->crypto.n_akm_suites += (hi_u8)(puc_ie[offset + 1] << 8); /* ����8λ */
    if (connect->crypto.n_akm_suites > OAL_NL80211_MAX_NR_AKM_SUITES) {
        oam_warning_log1(0, 0, "{wal_set_crypto_pmf:invalid akm len:%d!}", connect->crypto.n_akm_suites);
        return HI_FAIL;
    }
    /* ��ȡAKM type */
    offset += MAC_RSN_CIPHER_COUNT_LEN;
    if (connect->crypto.n_akm_suites) {
        for (hi_u8 loop3 = 0; loop3 < connect->crypto.n_akm_suites; loop3++) {
            connect->crypto.akm_suites[loop3] = (hi_u8)puc_ie[offset + MAC_OUI_LEN];
            offset += (MAC_OUITYPE_WPA + MAC_OUI_LEN);
        }
    }

    return HI_SUCCESS;
}


/*****************************************************************************
 ��������  : ����STA connect ������Ϣ
 �������  : mac_cfg80211_connect_param_stru   *pst_connect_param
             oal_cfg80211_connect_params_stru    *pst_sme
 �� �� ֵ  : static hi_u32
*****************************************************************************/
hi_u32 wal_set_crypto_info(mac_cfg80211_connect_param_stru *connect_param, const oal_cfg80211_connect_params_stru *sme)
{
    hi_u8 *puc_ie = mac_find_ie(MAC_EID_RSN, (hi_u8 *)sme->ie, sme->ie_len);

    if ((sme->key_len != 0) && (sme->crypto.n_akm_suites == 0)) {
        /* ����wep������Ϣ */
        return wal_set_wep_key(connect_param, sme);
    } else if (sme->crypto.n_akm_suites != 0) {
        if ((sme->crypto.n_akm_suites > OAL_NL80211_MAX_NR_AKM_SUITES) ||
            (sme->crypto.n_ciphers_pairwise > OAL_NL80211_MAX_NR_CIPHER_SUITES)) {
            oam_warning_log0(0, OAM_SF_CFG, "{wal_set_crypto_info:invalid suites len!}");
            return HI_FAIL;
        }
        /* ����WPA/WPA2 ������Ϣ */
        connect_param->crypto.wpa_versions       = (hi_u8)sme->crypto.wpa_versions;
        connect_param->crypto.cipher_group       = (hi_u8)sme->crypto.cipher_group;
        connect_param->crypto.n_ciphers_pairwise = (hi_u8)sme->crypto.n_ciphers_pairwise;
        connect_param->crypto.n_akm_suites       = (hi_u8)sme->crypto.n_akm_suites;
        connect_param->crypto.control_port       = (hi_u8)sme->crypto.control_port;

        for (hi_u8 loop = 0; loop < connect_param->crypto.n_ciphers_pairwise; loop++) {
            connect_param->crypto.ciphers_pairwise[loop] = (hi_u8)sme->crypto.ciphers_pairwise[loop];
        }

        for (hi_u8 loop1 = 0; loop1 < connect_param->crypto.n_akm_suites; loop1++) {
            connect_param->crypto.akm_suites[loop1] = (hi_u8)sme->crypto.akm_suites[loop1];
        }

        return HI_SUCCESS;
    } else if (puc_ie != HI_NULL) {
        /* ����ʹ��PMF STAUT�·�n_akm_suites==0��RSN������� */
        return wal_set_crypto_pmf(connect_param, sme, puc_ie);
    } else if (mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WPS, (hi_u8 *)sme->ie,
        (hi_s32)(sme->ie_len))) {
        /* DTS2015022604379 ���ʹ����WPS���򷵻سɹ� */
        oam_warning_log0(0, OAM_SF_CFG, "{wal_set_crypto_info:connect use wps method!}");

        return HI_SUCCESS;
    }

    return HI_FAIL;
}

#ifdef _PRE_WLAN_FEATURE_P2P
/*****************************************************************************
 ��������  : �ж��Ƿ�ΪP2P DEVICE .�����P2P device�������������
 �������  : oal_net_device_stru *pst_net_device
 �� �� ֵ  : hi_u8 HI_TRUE:P2P DEVICE �豸��
                                 HI_FALSE:��P2P DEVICE �豸
 �޸���ʷ      :
  1.��    ��   : 2019��5��20��
    ��    ��   : Hisilicon
    �޸�����   : ͨ��iftypeʶ��p2p dev
*****************************************************************************/
static hi_u8 wal_is_p2p_device(const oal_net_device_stru *netdev)
{
    oal_wireless_dev *wdev = HI_NULL;

    /* ��ȡmac device */
    wdev        = netdev->ieee80211_ptr;
    return (wdev->iftype == NL80211_IFTYPE_P2P_DEVICE);
}
#endif

hi_u32 wal_cfg80211_start_connect_or_req(oal_net_device_stru *netdev,
    const mac_cfg80211_connect_param_stru *mac_cfg80211_connect_param)
{
    hi_u32 ret;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    ret = wal_cfg80211_start_connect(netdev, mac_cfg80211_connect_param);
#else
    ret = wal_cfg80211_start_req(netdev, mac_cfg80211_connect_param, sizeof(mac_cfg80211_connect_param_stru),
                                 WLAN_CFGID_CFG80211_START_CONNECT, HI_TRUE);
#endif
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_start_connect_or_req::wal_cfg80211_start_connect fail %u}", ret);
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_connect
 ��������  : �����ں��·��Ĺ������sta��������
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2013��10��24��
    ��    ��   : Hisilicon
    �޸�����   : ���Ӽ�����֤��صĴ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_connect(oal_wiphy_stru *wiphy, oal_net_device_stru *net_device,
    oal_cfg80211_connect_params_stru *sme)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_connect(oal_wiphy_stru *wiphy, oal_net_device_stru *net_device,
    oal_cfg80211_connect_params_stru *sme)
#endif
{
    mac_cfg80211_connect_param_stru mac_cfg80211_connect_param = {0};

    if ((wiphy == HI_NULL) || (net_device == HI_NULL) || (sme == HI_NULL)) {
        oam_error_log3(0, OAM_SF_ANY, "{wal_cfg80211_connect::connect failed,wiphy=%p,netdev=%p,sme=%p}",
            (uintptr_t)wiphy, (uintptr_t)net_device, (uintptr_t)sme);
        goto fail;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    /* begin:DTS2015040702497 ��ֹ����p2p device�豸�������� */
    if (wal_is_p2p_device(net_device)) {
        oam_warning_log0(0, OAM_SF_ANY, "wal_cfg80211_connect:connect stop, p2p device should not connect.");
        goto fail;
    }
    /* end:DTS2015040702497 ��ֹ����p2p device�豸�������� */
#endif

    /* iw�ӿ��·��Ĺ��������п������ŵ���Ϣ����ʱ����ʿ�ָ�룬���Ҵ˴���ȡ�ŵ��ţ������������У���û���õ� */
    /* �����ں��·��� ssid */
    mac_cfg80211_connect_param.puc_ssid = (hi_u8 *)sme->ssid;
    mac_cfg80211_connect_param.ssid_len = (hi_u8)sme->ssid_len;

    /* �����ں��·��� bssid */
    mac_cfg80211_connect_param.puc_bssid = (hi_u8 *)sme->bssid;

    /* �����ں��·��İ�ȫ��ز��� */
    /* ������֤���� */
    mac_cfg80211_connect_param.auth_type = sme->auth_type;

    /* ���ü������� */
    mac_cfg80211_connect_param.privacy = sme->privacy;

    /* ��ȡ�ں��·���pmf��ʹ�ܵĽ�� */
    mac_cfg80211_connect_param.mfp = sme->mfp;

    oam_warning_log4(0, OAM_SF_ANY, "{wal_cfg80211_connect::start new conn,ssid_len=%d,auth_type=%d,privacy=%d,mfp=%d}",
        sme->ssid_len, sme->auth_type, sme->privacy, sme->mfp);

    /* ���ü��ܲ��� */
#ifdef _PRE_WLAN_FEATURE_WAPI
    if (sme->crypto.wpa_versions == WITP_WAPI_VERSION) {
        oam_warning_log0(0, OAM_SF_ANY, "wal_cfg80211_connect::crypt ver is wapi!");
        mac_cfg80211_connect_param.wapi = HI_TRUE;
    } else {
        mac_cfg80211_connect_param.wapi = HI_FALSE;
    }
#endif

    if (sme->privacy) {
        hi_u32 ret = wal_set_crypto_info(&mac_cfg80211_connect_param, sme);
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_connect::connect failed, wal_set_wep_key fail:%d!}\r\n", ret);
            goto fail;
        }
    }

    /* ���ù���P2P/WPS ie */
    mac_cfg80211_connect_param.puc_ie = (hi_u8 *)sme->ie;
    mac_cfg80211_connect_param.ie_len = (hi_u32)(sme->ie_len);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) && \
    ((_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) || (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION))
    wlan_pm_set_timeout(WLAN_SLEEP_LONG_CHECK_CNT);
#endif

    if (wal_cfg80211_start_connect_or_req(net_device, &mac_cfg80211_connect_param) != HI_SUCCESS) {
        goto fail;
    }
    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_disconnect
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_disconnect(oal_wiphy_stru *wiphy, oal_net_device_stru *net_device, hi_u16 us_reason_code)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_disconnect(oal_wiphy_stru *wiphy, oal_net_device_stru *net_device, hi_u16 us_reason_code)
#endif
{
    mac_cfg_kick_user_param_stru    mac_cfg_kick_user_param;
    hi_u32                          ret;
    mac_user_stru                   *mac_user = HI_NULL;
    mac_vap_stru                    *mac_vap = HI_NULL;
    hi_unref_param(wiphy);

    if (net_device == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY,
            "{wal_cfg80211_disconnect::input netdev pointer is null!}\r\n");
        goto fail;
    }

    /* �����ں��·���connect���� */
    if (memset_s(&mac_cfg_kick_user_param, sizeof(mac_cfg_kick_user_param_stru), 0,
        sizeof(mac_cfg_kick_user_param_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::mem safe function err!}");
        goto fail;
    }

    /* �����ں��·���ȥ����ԭ��  */
    mac_cfg_kick_user_param.us_reason_code = us_reason_code;

    /* ��д��sta������ap mac ��ַ */
    mac_vap = oal_net_dev_priv(net_device);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::get mac vap ptr is null!}\r\n");
        goto fail;
    }

    mac_user = mac_user_get_user_stru(mac_vap->assoc_vap_id);
    if (mac_user == HI_NULL) {
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_cfg80211_disconnect::mac_user_get_user_stru pst_mac_user is null, user idx[%d]!}\r\n",
            mac_vap->assoc_vap_id);
        goto fail;
    }

    if (memcpy_s(mac_cfg_kick_user_param.auc_mac_addr, WLAN_MAC_ADDR_LEN,
                 mac_user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_disconnect::mem safe function err!}");
        goto fail;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    ret = wal_cfg80211_start_disconnect(net_device, &mac_cfg_kick_user_param);
#else
    ret = wal_cfg80211_start_req(net_device, &mac_cfg_kick_user_param, sizeof(mac_cfg_kick_user_param_stru),
        WLAN_CFGID_KICK_USER, HI_TRUE);
#endif
    if (ret != HI_SUCCESS) {
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_add_key
 ��������  : ����ptk,gtk����Կ�������
 �������  : [1]wiphy
             [2]netdev
             [3]p_cfg80211_add_key_info
             [4]mac_addr
             [5]params
 �������  : hi_u32
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_add_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    cfg80211_add_key_info_stru *cfg80211_add_key_info, const hi_u8 *puc_mac_addr, oal_key_params_stru *params)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_add_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index,
    bool pairwise, const hi_u8 *puc_mac_addr, oal_key_params_stru *params)
#endif
{
    mac_addkey_param_stru payload_params;
    hi_u32                ret;

    hi_unref_param(wiphy);
    /* 1.1 ��μ�� */
    if ((netdev == HI_NULL) || (params == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_cfg80211_add_key::Param Check ERROR,pst_netdev, pst_params %p, %p, %p!}",
                       (uintptr_t)netdev, (uintptr_t)params);
        goto fail;
    }

    /* 1.2 key���ȼ�飬��ֹ����Խ�� */
    if ((params->key_len > OAL_WPA_KEY_LEN) || (params->seq_len > OAL_WPA_SEQ_LEN)) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_cfg80211_add_key::Param Check ERROR! key_len[%x]  seq_len[%x]!}",
                       (hi_s32)params->key_len, (hi_s32)params->seq_len);
        goto fail;
    }

    /* 2.1 ��Ϣ����׼�� */
    if (memset_s(&payload_params, sizeof(payload_params), 0, sizeof(payload_params)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_key::mem safe function err!}");
        goto fail;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    payload_params.key_index = cfg80211_add_key_info->key_index;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    payload_params.key_index = key_index;
#endif

    if (puc_mac_addr != HI_NULL) {
        /* ����ʹ���ں��·���macָ�룬���ܱ��ͷţ���Ҫ������������ʹ�� */
        if (memcpy_s(payload_params.auc_mac_addr, WLAN_MAC_ADDR_LEN, puc_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_key::mem safe function err!}");
            goto fail;
        }
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    payload_params.pairwise  = cfg80211_add_key_info->pairwise;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    payload_params.pairwise  = pairwise;
#endif

    /* 2.2 ��ȡ�����Կֵ */
    payload_params.key.key_len = params->key_len;
    payload_params.key.seq_len = params->seq_len;
    payload_params.key.cipher  = params->cipher;
    if (memcpy_s(payload_params.key.auc_key, OAL_WPA_KEY_LEN, params->key, (hi_u32)params->key_len) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_key::mem safe function err!}");
        goto fail;
    }

    if (params->seq != HI_NULL && params->seq_len != 0) {
        if (memcpy_s(payload_params.key.auc_seq, OAL_WPA_SEQ_LEN, params->seq, (hi_u32)params->seq_len) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_add_key::mem safe function err!}");
            goto fail;
        }
    }
    oam_info_log3(0, OAM_SF_ANY, "{wal_cfg80211_add_key::key_len:%d, seq_len:%d, cipher:0x%08x!}",
                  params->key_len, params->seq_len, params->cipher);

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &payload_params, sizeof(mac_addkey_param_stru), WLAN_CFGID_ADD_KEY, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_add_key::return err code [%u]!}", ret);
        goto fail;
    }
    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_remove_key
 ��������  : ��ptk,gtk����Կ�������ɾ��
 �������  : [1]wiphy
             [2]netdev
             [3]key_index
             [4]pairwise
             [5]puc_mac_addr
 �������  : hi_u32
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_remove_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index,
    hi_bool pairwise, const hi_u8 *mac_addr)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_remove_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index,
    bool pairwise, const hi_u8 *mac_addr)
#endif
{
    mac_removekey_param_stru         payload_params  = {0};
    hi_u32                           ret;

    hi_unref_param(wiphy);
    /* 1.1 ��μ�� */
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::pst_netdev is null!}");
        goto fail;
    }
    if (oal_net_dev_priv(netdev) == HI_NULL) {
        oam_info_log0(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::ml_priv is null!}");
        goto fail;
    }

    /* 2.1 ��Ϣ����׼�� */
    payload_params.key_index = key_index;

    if (mac_addr != HI_NULL) {
        /* ����ʹ���ں��·���macָ�룬���ܱ��ͷţ���Ҫ������������ʹ�� */
        if (memcpy_s(payload_params.auc_mac_addr, OAL_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::mem safe function err!}");
            goto fail;
        }
    }
    payload_params.pairwise  = pairwise;

    oam_info_log2(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::index:%d, pairwise:%d!}", key_index,
        payload_params.pairwise);

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &payload_params,
        sizeof(mac_removekey_param_stru), WLAN_CFGID_REMOVE_KEY, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_remove_key::return err code [%u]!}", ret);
        goto fail;
    }
    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_set_default_key
 ��������  : ʹ���õ���Կ��Ч
 �������  : [1]wiphy
             [2]netdev
             [3]key_index
             [4]unicast
             [5]multicast
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 �޸�����  : �ϲ���������֡Ĭ����Կ�����ù���֡Ĭ����Կ����
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_set_default_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    hi_u8 key_index, hi_bool unicast, hi_bool multicast)
#else
hi_s32 wal_cfg80211_set_default_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    hi_u8 key_index, bool unicast, bool multicast)
#endif
{
    mac_setdefaultkey_param_stru  payload_params  = {0};
    hi_u32                        ret;

    hi_unref_param(wiphy);
    /* 1.1 ��μ�� */
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY,
                       "{wal_cfg80211_set_default_key::pst_netdev ptr is null!}\r\n");
        goto fail;
    }

    /* 2.1 ��Ϣ����׼�� */
    payload_params.key_index = key_index;
    payload_params.unicast   = unicast;
    payload_params.multicast = multicast;

    oam_info_log3(0, OAM_SF_ANY, "{wal_cfg80211_set_default_key::key_index:%d, unicast:%d, multicast:%d!}\r\n",
                  key_index, payload_params.unicast, payload_params.multicast);

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &payload_params,
        sizeof(mac_setdefaultkey_param_stru), WLAN_CFGID_DEFAULT_KEY, HI_FALSE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_set_default_key::return err code [%u]!}", ret);
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_set_ssid
 ��������  : ����ap
 �������  : oal_net_device_stru   *pst_netdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_cfg80211_set_ssid(oal_net_device_stru *netdev, const hi_u8 *puc_ssid_ie, hi_u8 ssid_len)
{
    mac_cfg_ssid_param_stru      ssid_param = {0};
    hi_u32                       ret;

    /* 2.1 ��Ϣ����׼�� */
    ssid_param.ssid_len = ssid_len;
    if (memcpy_s(ssid_param.ac_ssid, WLAN_SSID_MAX_LEN, (hi_s8 *)puc_ssid_ie, ssid_len) != EOK) {
        oam_error_log0(0, 0, "{wal_cfg80211_set_ssid::mem safe function err!}");
        return HI_FAIL;
    }

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &ssid_param, sizeof(mac_cfg_ssid_param_stru), WLAN_CFGID_SSID, HI_FALSE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_set_ssid::return err code [%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  :����meshid
 �������  : oal_net_device_stru   *pst_netdev
                            hi_u8 *puc_ssid_ie
                            hi_u8 uc_ssid_len
 �� �� ֵ  : static hi_s32
 �޸���ʷ      :
  1.��    ��   : 2019��3��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_cfg80211_set_meshid(oal_net_device_stru *netdev, const hi_u8 *puc_meshid_ie, hi_u8 meshid_len)
{
    mac_cfg_ssid_param_stru      ssid_param = {0};
    hi_u32                       ret;

    /* 2.1 ��Ϣ����׼�� */
    ssid_param.ssid_len = meshid_len;
    if (memcpy_s(ssid_param.ac_ssid, WLAN_SSID_MAX_LEN, (hi_s8 *)puc_meshid_ie, meshid_len) != EOK) {
        oam_error_log0(0, 0, "{wal_cfg80211_set_meshid::mem safe function err!}");
        return HI_FAIL;
    }

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &ssid_param, sizeof(mac_cfg_ssid_param_stru), WLAN_CFGID_MESHID, HI_FALSE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_set_meshid::return err code [%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

hi_u32 wal_cfg80211_configuration_beacon(const mac_vap_stru *mac_vap, const oal_beacon_data_stru *beacon_info,
    mac_beacon_param_stru *beacon_param)
{
    oal_beacon_parameters beacon_info_tmp = {0};
    hi_u32                       ret;

    /*****************************************************************************
        1.��ȫ����ie��Ϣ��
    *****************************************************************************/
    hi_u16 beacon_head_len = (hi_u16)beacon_info->head_len;
    hi_u16 beacon_tail_len = (hi_u16)beacon_info->tail_len;
    hi_u32 beacon_len = (hi_u32)beacon_head_len + (hi_u32)beacon_tail_len;
    hi_u8  *puc_beacon_info_tmp = (hi_u8 *)(oal_memalloc(beacon_len));
    if (puc_beacon_info_tmp == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::memalloc failed.}");
        return HI_ERR_CODE_PTR_NULL;
    } else {
        /* ����beacon���� ��11bģʽ�£�beacon_tail_lenΪ0�� */
        if (beacon_tail_len != 0) {
            ret = (hi_u32)memcpy_s(puc_beacon_info_tmp, beacon_head_len, beacon_info->head, beacon_head_len);
            ret |= (hi_u32)memcpy_s(puc_beacon_info_tmp + beacon_head_len, beacon_tail_len,
                beacon_info->tail, beacon_tail_len);
        } else {
            ret = (hi_u32)memcpy_s(puc_beacon_info_tmp, beacon_head_len, beacon_info->head, beacon_head_len);
        }
        if (ret != EOK) {
            oam_error_log0(0, 0, "{wal_cfg80211_fill_beacon_param::mem safe function err!}");
            oal_free(puc_beacon_info_tmp);
            return HI_FAIL;
        }
    }

    beacon_info_tmp.head     = puc_beacon_info_tmp;
    beacon_info_tmp.head_len = (hi_u32)beacon_head_len;
    beacon_info_tmp.tail     = puc_beacon_info_tmp + (hi_u32)beacon_head_len;
    beacon_info_tmp.tail_len = (hi_u32)beacon_tail_len;

    /* ��ȡ WPA/WPA2 ��ϢԪ�� */
    ret = wal_parse_wpa_wpa2_ie(&beacon_info_tmp, beacon_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::failed to parse WPA/WPA2 ie!}");
        oal_free(puc_beacon_info_tmp);
        return ret;
    }

    ret = wal_parse_ht_vht_ie(mac_vap, &beacon_info_tmp, beacon_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::failed to parse HT/VHT ie!}");
        oal_free(puc_beacon_info_tmp);
        return ret;
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    /* ��ȡmesh conf��ϢԪ�� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        ret = wal_parse_mesh_conf_ie(&beacon_info_tmp, beacon_param);
        if (ret != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::Mesh VAP fail parse ie!}");
            oal_free(puc_beacon_info_tmp);
            return ret;
        }
    }
#endif
    /* �ͷ���ʱ������ڴ� */
    oal_free(puc_beacon_info_tmp);

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_fill_beacon_param
 ��������  : ��Ҫ�·����޸ĵ�beacon֡�������뵽��νṹ����
 �������  : mac_vap_stru                *pst_mac_vap,
             struct cfg80211_beacon_data *pst_beacon_info,
             mac_beacon_param_stru       *pst_beacon_param
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_cfg80211_fill_beacon_param(mac_vap_stru *mac_vap, oal_beacon_data_stru *beacon_info,
    mac_beacon_param_stru *beacon_param)
{
    if (mac_vap == HI_NULL || beacon_info == HI_NULL || beacon_param == HI_NULL) {
        oam_error_log3(0, OAM_SF_ANY,
            "{wal_cfg80211_fill_beacon_param::param is NULL. pst_mac_vap=%p, pst_beacon_info=%p, pst_beacon_param=%p",
            (uintptr_t)mac_vap, (uintptr_t)beacon_info, (uintptr_t)beacon_param);
        return HI_ERR_CODE_PTR_NULL;
    }
    if (beacon_info->tail == HI_NULL || beacon_info->head == HI_NULL) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_ANY,
                       "{wal_cfg80211_fill_beacon_param::beacon frame error tail = %p, head = %p!}",
                       (uintptr_t)beacon_info->tail, (uintptr_t)beacon_info->head);
        return HI_ERR_CODE_PTR_NULL;
    }

    hi_u32 ret = wal_cfg80211_configuration_beacon(mac_vap, beacon_info, beacon_param);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    oam_warning_log3(mac_vap->vap_id, OAM_SF_ANY,
        "{wal_cfg80211_fill_beacon_param::crypto_mode=%d, group_crypt=%d, en_protocol=%d!}", beacon_param->crypto_mode,
        beacon_param->group_crypto, beacon_param->protocol);

    oam_warning_log2(mac_vap->vap_id, OAM_SF_ANY,
        "{wal_cfg80211_fill_beacon_param::auth_type[0]=%d, auth_type[1]=%d}", beacon_param->auc_auth_type[0],
        beacon_param->auc_auth_type[1]);

#ifdef _PRE_WLAN_FEATURE_MESH
    /* ��ӡ����ʹ�� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{wal_cfg80211_fill_beacon_param::mesh formation info = %d, mesh capability = %d}",
            beacon_param->mesh_formation_info, beacon_param->mesh_capability);
    }
#endif

    /* ���ձ�14�ŵ��������жϣ�ֻ��11bģʽ�²�������14����11bģʽ ��Ϊ11b */
    if ((mac_vap->channel.chan_number == 14) && (beacon_param->protocol != WLAN_LEGACY_11B_MODE)) { /* 14�������ŵ��� */
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY,
                       "{wal_cfg80211_fill_beacon_param::ch 14 should in 11b, but is %d!}", beacon_param->protocol);
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::change protocol to 11b!}");
        beacon_param->protocol = WLAN_LEGACY_11B_MODE;
    }

    for (hi_u32 loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::wpa pariwise[%d] = %d!}",
                         loop, beacon_param->auc_pairwise_crypto_wpa[loop]);
    }

    for (hi_u32 loop1 = 0; loop1 < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop1++) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param::wpa2 pariwise[%d] = %d!}",
                         loop1, beacon_param->auc_pairwise_crypto_wpa2[loop1]);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_change_beacon
 ��������  : �޸�ap beacon֡���ò���
 �������  : oal_wiphy_stru          *pst_wiphy
             oal_net_device_stru     *pst_netdev
             struct cfg80211_beacon_data *info
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_change_beacon(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, oal_beacon_data_stru *beacon_info)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_change_beacon(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, oal_beacon_data_stru *beacon_info)
#endif
{
    mac_beacon_param_stru        beacon_param;  /* beacon info struct */
    mac_vap_stru                *mac_vap = HI_NULL;
    hi_u32                       ret;

    hi_unref_param(wiphy);

    /* �����Ϸ��Լ�� */
    if ((netdev == HI_NULL) || (beacon_info == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY,
            "{wal_cfg80211_change_beacon::pst_netdev = %p, pst_beacon_info = %p!}",
            (uintptr_t)netdev, (uintptr_t)beacon_info);
        goto fail;
    }

    /* ��ȡvap id */
    mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::pst_mac_vap = %p}", (uintptr_t)mac_vap);
        goto fail;
    }

    /* ��ʼ��beacon interval ��DTIM_PERIOD ���� */
    if (memset_s(&beacon_param, sizeof(mac_beacon_param_stru), 0, sizeof(mac_beacon_param_stru)) != EOK) {
        oam_error_log0(0, 0, "{wal_cfg80211_change_beacon::mem safe function err!}");
        goto fail;
    }
    ret = wal_cfg80211_fill_beacon_param(mac_vap, beacon_info, &beacon_param);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY,
            "{wal_cfg80211_change_beacon::failed to fill beacon param, error[%d]}", ret);
        goto fail;
    }

    /* ���ò������� */
    beacon_param.operation_type = MAC_SET_BEACON;

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &beacon_param,
        sizeof(mac_beacon_param_stru), WLAN_CFGID_CFG80211_CONFIG_BEACON, HI_FALSE);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_cfg80211_change_beacon::Failed to start addset beacon, error[%d]!}", ret);
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_convert_width_to_value
 ��������  : ���ں��·��Ĵ���ö��ת������ʵ�Ĵ�����ֵ
 �������  : [1]l_channel_width
 �������  : ��
 �� �� ֵ  : static hi_s32
*****************************************************************************/
static hi_u32 wal_cfg80211_convert_width_to_value(hi_s32 l_channel_width)
{
    hi_u32 l_channel_width_value = 0;

    switch (l_channel_width) {
        case 0: /* 0 �ں˴��� */
        case 1: /* 1 �ں˴��� */
            l_channel_width_value = 20; /* 20 ��ʵ�Ĵ���ֵ */
            break;
        case 2: /* 2 �ں˴��� */
            l_channel_width_value = 40; /* 40 ��ʵ�Ĵ���ֵ */
            break;
        case 3: /* 3 �ں˴��� */
        case 4: /* 4 �ں˴��� */
            l_channel_width_value = 80; /* 80 ��ʵ�Ĵ���ֵ */
            break;
        case 5: /* 5 �ں˴��� */
            l_channel_width_value = 160; /* 160 ��ʵ�Ĵ���ֵ */
            break;
        default:
            break;
    }

    return l_channel_width_value;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_set_channel_info
 ��������  : �����ŵ�
 �������  : oal_wiphy_stru           *pst_wiphy
             oal_net_device_stru      *pst_netdev
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_cfg80211_set_channel_info(oal_net_device_stru *netdev)
{
    mac_cfg_channel_param_stru        channel_param = {0};
    wlan_channel_bandwidth_enum_uint8 bandwidth;

    oal_ieee80211_channel *channel = netdev->ieee80211_ptr->preset_chandef.chan;
    hi_s32 l_bandwidth    = netdev->ieee80211_ptr->preset_chandef.width;
    hi_s32 l_center_freq1 = netdev->ieee80211_ptr->preset_chandef.center_freq1;
    hi_s32 l_channel      = channel->hw_value;

    /* �ж��ŵ��ڲ��ڹ������� */
    hi_u32 ret = mac_is_channel_num_valid(channel->band, (hi_u8)l_channel);
    if (ret != HI_SUCCESS) {
        oam_warning_log3(0, OAM_SF_ANY,
            "{wal_cfg80211_set_channel::channel Err.band=%d,ch=%d,ErrCode=%u}", channel->band, l_channel, ret);
        return ret;
    }

    /* �����ں˴���ֵ��WITP ����ֵת�� */
    hi_s32 l_channel_center_freq = oal_ieee80211_frequency_to_channel(l_center_freq1);
    hi_u32 l_bandwidth_value     = wal_cfg80211_convert_width_to_value(l_bandwidth);
    if (l_bandwidth_value == 0) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_set_channel::channelWidth Err,l_bandwidth=%d", l_bandwidth);
        return HI_FAIL;
    }

    if (l_bandwidth_value == 80) { /* 80���������ֵ */
        bandwidth = mac_get_bandwith_from_center_freq_seg0((hi_u8)l_channel, (hi_u8)l_channel_center_freq);
    } else if (l_bandwidth_value == 40) { /* 40���������ֵ */
        switch (l_channel_center_freq - l_channel) {
            case -2: /* -2: �ں˴��� */
                bandwidth = WLAN_BAND_WIDTH_40MINUS;
                break;
            case 2: /* 2: �ں˴��� */
                bandwidth = WLAN_BAND_WIDTH_40PLUS;
                break;
            default:
                bandwidth = WLAN_BAND_WIDTH_20M;
                break;
        }
    } else {
        bandwidth = WLAN_BAND_WIDTH_20M;
    }

    /* 2.1 ��Ϣ����׼�� */
    channel_param.channel      = (hi_u8)channel->hw_value;
    channel_param.band         = channel->band;
    channel_param.en_bandwidth = bandwidth;

    oam_warning_log3(0, OAM_SF_ANY, "{wal_cfg80211_set_channel::channel=%d,band=%d,bandwidth=%d}",
        channel_param.channel, channel_param.band, channel_param.en_bandwidth);

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &channel_param,
        sizeof(mac_cfg_channel_param_stru), WLAN_CFGID_CFG80211_SET_CHANNEL, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_set_channel_info::return err code [%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_u32 wal_wifi_set_bw(oal_net_device_stru *netdev, wal_wifi_bw_enum_int bw)
{
    hi_char ac_bw[WAL_BW_STR_MAX_LEN] = {0};
    if ((bw > WAL_WIFI_BW_HIEX_5M) || (bw < WAL_WIFI_BW_LEGACY_20M)) {
        oam_error_log0(0, 0, "hi_wifi_set_bandwidth invalid bw.");
        return HI_FAIL;
    }

    strcpy_s(ac_bw, WAL_BW_STR_MAX_LEN, "20");
    if (bw == WAL_WIFI_BW_HIEX_5M) {
        strcpy_s(ac_bw, WAL_BW_STR_MAX_LEN, "5");
    } else if (bw == WAL_WIFI_BW_HIEX_10M) {
        strcpy_s(ac_bw, WAL_BW_STR_MAX_LEN, "10");
    }

    if (wal_hipriv_set_bw(netdev, (hi_char *)ac_bw) != HI_SUCCESS) {
        oam_error_log0(0, 0, "wal_hipriv_set_bw failed.");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_ap
 ��������  : ����AP,����AP ������
 �������  : oal_wiphy_stru              *pst_wiphy
             oal_net_device_stru         *pst_netdev
             struct cfg80211_ap_settings *settings
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_start_ap(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, oal_ap_settings_stru *ap_settings)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_start_ap(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, oal_ap_settings_stru *ap_settings)
#endif
{
    mac_beacon_param_stru       beacon_param = {0};  /* beacon info struct */

    hi_unref_param(wiphy);

    /* �����Ϸ��Լ�� */
    if ((netdev == HI_NULL) || (ap_settings == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_cfg80211_start_ap:: %p, %p!}", (uintptr_t)netdev, (uintptr_t)ap_settings);
        goto fail;
    }

    /* ��ȡvap id */
    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_cfg80211_start_ap::pst_mac_vap = %p}", (uintptr_t)mac_vap);
        goto fail;
    }

    /*****************************************************************************
        1.�����ŵ�
    *****************************************************************************/
    if (wal_cfg80211_set_channel_info(netdev) != HI_SUCCESS) {
        goto fail;
    }

    /*****************************************************************************
        2.����ssid����Ϣ
    *****************************************************************************/
    if ((ap_settings->ssid_len > 32) || (ap_settings->ssid_len == 0)) { /* 32: �����Ͻ� */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap: len[%d].}", ap_settings->ssid_len);
        goto fail;
    }

    if (wal_cfg80211_set_ssid(netdev, ap_settings->ssid, (hi_u8)ap_settings->ssid_len) != HI_SUCCESS) {
        goto fail;
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    /*****************************************************************************
        2.Mesh����meshid����Ϣ,��ssidһ��
    *****************************************************************************/
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        if (wal_cfg80211_set_meshid(netdev, ap_settings->ssid, (hi_u8)ap_settings->ssid_len) != HI_SUCCESS) {
            goto fail;
        }
    }
#endif

    /*****************************************************************************
        3.����beaconʱ������tim period�Լ���ȫ������Ϣ��
    *****************************************************************************/
    /* ��ʼ��beacon interval ��DTIM_PERIOD ���� */
    beacon_param.l_interval    = ap_settings->beacon_interval;
    beacon_param.l_dtim_period = ap_settings->dtim_period;
    beacon_param.hidden_ssid = (ap_settings->hidden_ssid == 1);

    oam_warning_log3(0, OAM_SF_ANY, "{wal_cfg80211_fill_beacon_param:beacon_interval=%d,dtim_period=%d,hidden_ssid=%d}",
        ap_settings->beacon_interval, ap_settings->dtim_period, ap_settings->hidden_ssid);

    if (wal_cfg80211_fill_beacon_param(mac_vap, &(ap_settings->beacon), &beacon_param) != HI_SUCCESS) {
        goto fail;
    }

    /* ���ò������� */
    beacon_param.operation_type = MAC_ADD_BEACON;

    /* ���¼������� */
    if (wal_cfg80211_start_req(netdev, &beacon_param, sizeof(mac_beacon_param_stru),
        WLAN_CFGID_CFG80211_CONFIG_BEACON, HI_FALSE) != HI_SUCCESS) {
        goto fail;
    }

    /*****************************************************************************
        4.����ap
    *****************************************************************************/
    hi_u32 ret = wal_start_vap(netdev);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to start ap, error[%u]}", ret);
        goto fail;
    }
    /* ����net_device��flags��־ */
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) != 0) {
        oal_netdevice_flags(netdev) &= (~OAL_IFF_RUNNING);
    }
    if (wal_wifi_set_bw(netdev, g_bw) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_start_ap::failed to set bw}");
        goto fail;
    }
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
        oal_netdevice_flags(netdev) |= OAL_IFF_RUNNING;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_change_virtual_intf
 ��������  : ת��AP��STA ״̬
 �������  : [1]wiphy
             [2]net_dev
             [3]type        ��һ��״̬
             [4]pul_flags
             [5]params
 �������  : ��
 �� �� ֵ  : static hi_s32
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(4, 12, 0))
hi_s32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru *wiphy, oal_net_device_stru *net_dev,
    enum_nl80211_iftype type, oal_vif_params_stru *params)
#else
hi_s32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru *wiphy, oal_net_device_stru *net_dev,
    enum_nl80211_iftype type, hi_u32 *pul_flags, oal_vif_params_stru *params)
#endif
{
    wlan_p2p_mode_enum_uint8    p2p_mode;
    wlan_vap_mode_enum_uint8    vap_mode;
#ifdef _PRE_WLAN_FEATURE_P2P
    mac_cfg_del_vap_param_stru  del_vap_param;
    mac_cfg_add_vap_param_stru  add_vap_param;
    mac_vap_stru               *mac_vap = HI_NULL;
#endif
    hi_unref_param(wiphy);

    /* 1.1 ��μ�� */
    if (net_dev == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::pst_dev is null!}\r\n");
        return -HI_ERR_CODE_PTR_NULL;
    }

    if (params == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG,
            "{wal_cfg80211_change_virtual_intf::pst_params ptr is null!}\r\n");
        return -HI_ERR_CODE_PTR_NULL;
    }

    /* ���VAP ��ǰģʽ��Ŀ��ģʽ�Ƿ���ͬ�������ͬ��ֱ�ӷ��� */
    if (net_dev->ieee80211_ptr->iftype == type) {
        oam_warning_log1(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::same iftype[%d],do not need change !}\r\n",
            type);
        return HI_SUCCESS;
    }

    oam_warning_log2(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::[%d][%d]}\r\n",
                     (net_dev->ieee80211_ptr->iftype), type);

    switch (type) {
        case NL80211_IFTYPE_MONITOR:
        case NL80211_IFTYPE_WDS:
        case NL80211_IFTYPE_ADHOC:
            oam_error_log1(0, OAM_SF_CFG,
                "{wal_cfg80211_change_virtual_intf::currently we do not support this type[%d]}\r\n", type);
            return -HI_ERR_WIFI_WAL_INVALID_PARAMETER;
#ifdef _PRE_WLAN_FEATURE_MESH
        case NL80211_IFTYPE_MESH_POINT:
            vap_mode = WLAN_VAP_MODE_MESH;
            p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
#endif
        case NL80211_IFTYPE_STATION:
            if (net_dev->ieee80211_ptr->iftype == NL80211_IFTYPE_AP) {
                /* ����ɨ��,�Է���20/40Mɨ������йر�AP */
                wal_force_scan_complete(net_dev);

                /* AP�ر��л���STAģʽ,ɾ�����vap */
                /* DTS2015121600902 ���vap״̬��netdevice״̬��һ�£��޷�ɾ��vap�����⣬VAPɾ�����ϱ��ɹ� */
                if (HI_SUCCESS != wal_stop_vap(net_dev)) {
                    oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::wal_stop_vap enter a error.}");
                }
                if (HI_SUCCESS != wal_deinit_wlan_vap(net_dev)) {
                    oam_warning_log0(0, OAM_SF_CFG,
                        "{wal_cfg80211_change_virtual_intf::wal_deinit_wlan_vap enter a error.}");
                }

                net_dev->ieee80211_ptr->iftype = type;

                return HI_SUCCESS;
            }
            {
                net_dev->ieee80211_ptr->iftype = type; /* P2P BUG P2P_DEVICE ��ǰ����������Ҫͨ��wpa_supplicant ���� */
                oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::change to station}\r\n");
            }
            return HI_SUCCESS;
        case NL80211_IFTYPE_P2P_CLIENT:
            vap_mode = WLAN_VAP_MODE_BSS_STA;
            p2p_mode = WLAN_P2P_CL_MODE;
            break;
        case NL80211_IFTYPE_AP:
        case NL80211_IFTYPE_AP_VLAN:
            vap_mode = WLAN_VAP_MODE_BSS_AP;
            p2p_mode = WLAN_LEGACY_VAP_MODE;
            break;
        case NL80211_IFTYPE_P2P_GO:
            vap_mode = WLAN_VAP_MODE_BSS_AP;
            p2p_mode = WLAN_P2P_GO_MODE;
            break;
        default:
            oam_error_log1(0, OAM_SF_CFG,
                "{wal_cfg80211_change_virtual_intf::currently we do not support this type[%d]}\r\n", type);
            return -HI_ERR_CODE_PTR_NULL;
    }

    if ((type == NL80211_IFTYPE_AP) || (type == NL80211_IFTYPE_MESH_POINT)) {
        net_dev->ieee80211_ptr->iftype = type;
        if (wal_setup_vap(net_dev) != HI_SUCCESS) {
            return -HI_FAIL;
        }
        return HI_SUCCESS;
    }
#ifdef _PRE_WLAN_FEATURE_P2P
    /* �豸ΪP2P �豸����Ҫ����change virtual interface */
    mac_vap = oal_net_dev_priv(net_dev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG,
            "{wal_cfg80211_change_virtual_intf::can't get mac vap from netdevice priv data.}\r\n");
        return -HI_ERR_CODE_PTR_NULL;
    }

    if (is_legacy_vap(mac_vap)) {
        net_dev->ieee80211_ptr->iftype = type;
        return HI_SUCCESS;
    }

    if (0 == (strcmp("p2p0", (const hi_char *)net_dev->name))) {
        /* ����쳣�����,wpa_supplicant�·�p2p0�豸�л���p2p go/cliģʽ����fastboot������ */
        oam_warning_log0(0, OAM_SF_CFG,
            "{wal_cfg80211_change_virtual_intf::p2p0 netdevice can not change to P2P CLI/GO.}\r\n");
        return -HI_FAIL;
    }

    /* �����ǰģʽ��Ŀ��ģʽ��ͬ������Ҫ:
       1. ֹͣ VAP
       2. ɾ�� VAP
       3. ���´�����ӦģʽVAP
       4. ����VAP
    */
    /* ֹͣVAP */
    wal_netdev_stop(net_dev);
    if (memset_s(&del_vap_param, sizeof(del_vap_param), 0, sizeof(del_vap_param)) != EOK) {
        return -HI_FAIL;
    }
    /* ɾ��VAP */
    del_vap_param.net_dev = net_dev;
    /* �豸p2p ģʽ��Ҫ��net_device �л�ȡ */
    del_vap_param.p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(net_dev->ieee80211_ptr->iftype);
    if (wal_cfg80211_del_vap(&del_vap_param)) {
        return -HI_FAIL;
    }

    if (memset_s(&add_vap_param, sizeof(add_vap_param), 0, sizeof(add_vap_param)) != EOK) {
        return -HI_FAIL;
    }
    /* ���´�����ӦģʽVAP */
    add_vap_param.net_dev = net_dev;
    add_vap_param.vap_mode = vap_mode;
    add_vap_param.p2p_mode = p2p_mode;
    if (wal_cfg80211_add_vap(&add_vap_param) != HI_SUCCESS) {
        return -HI_FAIL;
    }
    /* ����VAP */
    wal_netdev_open(net_dev);

    net_dev->ieee80211_ptr->iftype = type;
#endif
    return HI_SUCCESS;
}
#else
hi_u32 wal_cfg80211_intf_mode_check(oal_net_device_stru *netdev, nl80211_iftype_uint8 type)
{
    switch (type) {
        case NL80211_IFTYPE_MONITOR:
        case NL80211_IFTYPE_WDS:
        case NL80211_IFTYPE_ADHOC:
            oam_error_log1(0, OAM_SF_CFG,
                "{wal_cfg80211_change_virtual_intf::currently we do not support this type[%d]}\r\n", type);
            return HI_ERR_WIFI_WAL_INVALID_PARAMETER;
        case NL80211_IFTYPE_STATION:
            if (netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_AP) {
                /* ����ɨ��,�Է���20/40Mɨ������йر�AP */
                wal_force_scan_complete(netdev);

                /* AP�ر��л���STAģʽ,ɾ�����vap */
                /* DTS2015121600902 ���vap״̬��netdevice״̬��һ�£��޷�ɾ��vap�����⣬VAPɾ�����ϱ��ɹ� */
                if (wal_stop_vap(netdev) != HI_SUCCESS) {
                    oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::wal_stop_vap enter a error.}");
                }
                if (wal_deinit_wlan_vap(netdev) != HI_SUCCESS) {
                    oam_warning_log0(0, OAM_SF_CFG,
                        "{wal_cfg80211_change_virtual_intf::wal_deinit_wlan_vap enter a error.}");
                }

                netdev->ieee80211_ptr->iftype = type;

                return HI_SUCCESS;
            }
            netdev->ieee80211_ptr->iftype = type; /* P2P BUG P2P_DEVICE ��ǰ����������Ҫͨ��wpa_supplicant ���� */
            oam_warning_log0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::change to station}\r\n");
            return HI_SUCCESS;
#ifdef _PRE_WLAN_FEATURE_MESH
        case NL80211_IFTYPE_MESH_POINT:
#endif
        case NL80211_IFTYPE_P2P_CLIENT:
        case NL80211_IFTYPE_AP:
        case NL80211_IFTYPE_AP_VLAN:
        case NL80211_IFTYPE_P2P_GO:
            break;
        default:
            oam_error_log1(0, OAM_SF_CFG,
                "{wal_cfg80211_change_virtual_intf::currently we do not support this type[%d]}\r\n", type);
            return HI_ERR_CODE_PTR_NULL;
    }

    return HI_CONTINUE;
}

hi_u32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    nl80211_iftype_uint8 type, hi_u32 *pul_flags, oal_vif_params_stru *params)
{
    mac_vap_stru               *mac_vap = HI_NULL;
    hi_u32                      ret;
    hi_unref_param(wiphy);

    /* 1.1 ��μ�� */
    if (netdev == HI_NULL || params == HI_NULL) {
        oam_error_log2(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::params null! netdev=%p, params=%p",
                       (uintptr_t)netdev, (uintptr_t)params);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���VAP ��ǰģʽ��Ŀ��ģʽ�Ƿ���ͬ�������ͬ��ֱ�ӷ��� */
    if (netdev->ieee80211_ptr->iftype == type) {
        oam_warning_log1(0, OAM_SF_CFG, "wal_cfg80211_change_virtual_intf::same iftype[%d],do not need change!", type);
        return HI_SUCCESS;
    }

    oam_warning_log2(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::[%d][%d]}\r\n",
                     (netdev->ieee80211_ptr->iftype), type);
    *pul_flags = 0;

    ret = wal_cfg80211_intf_mode_check(netdev, type);
    if (ret != HI_CONTINUE) {
        return ret;
    }

    if ((type == NL80211_IFTYPE_AP) || (type == NL80211_IFTYPE_MESH_POINT)) {
        netdev->ieee80211_ptr->iftype = type;
        return wal_setup_vap(netdev);
    }

    /* �豸ΪP2P �豸����Ҫ����change virtual interface */
    mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_change_virtual_intf::oal_net_dev_priv fail!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (is_legacy_vap(mac_vap)) {
        netdev->ieee80211_ptr->iftype = type;
        return HI_SUCCESS;
    }

    if (0 == (strcmp("p2p0", (const hi_char *)netdev->name))) {
        /* ����쳣�����,wpa_supplicant�·�p2p0�豸�л���p2p go/cliģʽ����fastboot������ */
        oam_warning_log0(0, OAM_SF_CFG,
            "{wal_cfg80211_change_virtual_intf::p2p0 netdevice can not change to P2P CLI/GO.}\r\n");
        return HI_FAIL;
    }

    /* �����ǰģʽ��Ŀ��ģʽ��ͬ������Ҫ:
       1. ֹͣ VAP
       2. ɾ�� VAP
       3. ���´�����ӦģʽVAP
       4. ����VAP
    */
    /* ֹͣVAP */
    wal_netdev_stop(netdev);
    if (wal_deinit_wlan_vap(netdev) != HI_SUCCESS) {
        return HI_FAIL;
    }

    netdev->ieee80211_ptr->iftype = type;
    if (wal_init_wlan_vap(netdev) != HI_SUCCESS) {
        return HI_FAIL;
    }
    /* ����VAP */
    wal_netdev_open(netdev);

    return HI_SUCCESS;
}
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_del_send_event(oal_net_device_stru *netdev, const hi_u8 *mac_addr, mac_vap_stru *mac_vap)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
hi_u32 wal_cfg80211_del_send_event(oal_net_device_stru *netdev,
                                   oal_station_del_parameters_stru *params, mac_vap_stru *mac_vap)
#else
hi_u32 wal_cfg80211_del_send_event(oal_net_device_stru *netdev,
                                   hi_u8 *mac_addr, mac_vap_stru *mac_vap)
#endif
#endif
{
    mac_cfg_kick_user_param_stru kick_user_param;
    hi_s32                       user_count_ok   = 0;
    hi_s32                       user_count_fail = 0;
    hi_u32                       ret;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    const hi_u8 *mac_addr = params->mac;
    kick_user_param.us_reason_code = params->reason_code;
#else
    kick_user_param.us_reason_code = MAC_INACTIVITY;
#endif
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    kick_user_param.us_reason_code = MAC_INACTIVITY;
#endif
    hi_unref_param(mac_vap);

#ifdef _PRE_WLAN_FEATURE_MESH
    kick_user_param.us_reason_code = (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) ?
        MAC_WPA_KICK_MESH_USER : kick_user_param.us_reason_code;
#endif

    if (memcpy_s(kick_user_param.auc_mac_addr, OAL_MAC_ADDR_LEN, mac_addr, OAL_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_send_event::mem safe function err!}");
        return HI_FAIL;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    ret = wal_cfg80211_start_disconnect(netdev, &kick_user_param);
#else
    ret = wal_cfg80211_start_req(netdev, &kick_user_param, sizeof(mac_cfg_kick_user_param_stru),
        WLAN_CFGID_KICK_USER, HI_TRUE);
#endif
    if (ret != HI_SUCCESS) {
        /* ����ɾ����ʱ������û��Ѿ�ɾ������ʱ�ٽ����û����ң��᷵�ش������ERROR��ӡ���޸�Ϊwarning */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_send_event::kick_user Err=%d}", ret);
        user_count_fail++;
    } else {
        user_count_ok++;
    }

    if (user_count_fail > 0) {
        oam_info_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_send_event::%d user deleteErr}", user_count_fail);
        return HI_ERR_CODE_PTR_NULL;
    }

    oam_info_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_send_event::%d user delete OK}", user_count_ok);

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_del_station
 ��������  : ɾ���û�
 �������  : oal_wiphy_stru *pst_wiphy
             oal_net_device *pst_dev
             hi_u8 *puc_mac         �û�mac ��ַ�����mac = NULL,ɾ�������û�
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_del_station(const oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, const hi_u8 *mac_addr)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_del_station(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    oal_station_del_parameters_stru *params)
#else
    u8 *mac)
#endif
#endif
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_u8 bcast_mac_addr[OAL_MAC_ADDR_LEN];
#endif
    hi_u8 user_idx;

    hi_unref_param(wiphy);
    if (netdev == HI_NULL) {
        goto fail;
    }

    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_station::can't get mac vap from netdevice priv data!}\r\n");
        goto fail;
    }

    /* �ж��Ƿ���APģʽ */
    if ((mac_vap->vap_mode != WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        && (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)
#endif
    ) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::vap_mode=%d Err}", mac_vap->vap_mode);
        goto fail;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (mac_addr == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_del_station::Mac addr is null!}");
        goto fail;
    } else {
        oam_info_log3(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::delete user:XX:XX:XX:%02X:%02X:%02X}",
            mac_addr[3], mac_addr[4], mac_addr[5]); /* 3, 4, 5: �����±� */
    }
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    if (params->mac == HI_NULL) {
        /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
        memset_s(bcast_mac_addr, OAL_MAC_ADDR_LEN, 0xff, OAL_MAC_ADDR_LEN);

        params->mac = bcast_mac_addr;
        oam_info_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::deleting all user!}\r\n");
    } else {
        oam_info_log3(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::delete user:XX:XX:XX:%02X:%02X:%02X}",
            params->mac[3], params->mac[4], params->mac[5]); /* 3, 4, 5: �����±� */
    }
#else
    if (mac == HI_NULL) {
        /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
        memset_s(bcast_mac_addr, OAL_MAC_ADDR_LEN, 0xff, OAL_MAC_ADDR_LEN);

        mac = bcast_mac_addr;
        oam_info_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::deleting all user!}\r\n");
    } else {
        oam_info_log3(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_del_station::delete user:XX:XX:XX:%02X:%02X:%02X}",
            mac[3], mac[4], mac[5]); /* 3, 4, 5: �����±� */
    }

#endif
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_u32 ret = mac_vap_find_user_by_macaddr(mac_vap, (hi_u8 *)mac_addr, OAL_MAC_ADDR_LEN, &user_idx);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    hi_u32 ret = mac_vap_find_user_by_macaddr(mac_vap, (hi_u8 *)params->mac, OAL_MAC_ADDR_LEN, &user_idx);
#else
    hi_u32 ret = mac_vap_find_user_by_macaddr(mac_vap, (hi_u8 *)mac, OAL_MAC_ADDR_LEN, &user_idx);
#endif
#endif
    if (ret != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_UM, "{wal_cfg80211_del_station::user has been deleted}\r\n");
        goto fail;
    }

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    ret = wal_cfg80211_del_send_event(netdev, mac_addr, mac_vap);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    ret = wal_cfg80211_del_send_event(netdev, params, mac_vap);
#else
    ret = wal_cfg80211_del_send_event(netdev, mac, mac_vap);
#endif
#endif
    if (ret != HI_SUCCESS) {
        goto fail;
    }

    return HI_SUCCESS;

fail:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return HI_FAIL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return -HI_FAIL;
#endif
}

/*****************************************************************************
 �� �� ��  : wal_check_cookie_timeout
 ��������  : ɾ��cookie �б��г�ʱ��cookie
 �������  : cookie_arry_stru *pst_cookie_array
             hi_u32 ul_current_time
 �������  : ��
 �� �� ֵ  : hi_void
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��1��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_check_cookie_timeout(cookie_arry_stru  *cookie_array, hi_u8 *puc_cookie_bitmap)
{
    hi_u8               loops = 0;
    cookie_arry_stru   *tmp_cookie = HI_NULL;

    oam_warning_log0(0, OAM_SF_CFG, "{wal_check_cookie_timeout::time_out!}\r\n");
    for (loops = 0; loops < WAL_COOKIE_ARRAY_SIZE; loops++) {
        tmp_cookie = &cookie_array[loops];
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        if (hi_get_tick() > tmp_cookie->record_time + WAL_MGMT_TX_TIMEOUT_MSEC / HI_MILLISECOND_PER_TICK) {
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        if (oal_time_is_before(tmp_cookie->record_time + OAL_MSECS_TO_JIFFIES(WAL_MGMT_TX_TIMEOUT_MSEC))) {
#endif

            /* cookie array �б����cookie ֵ��ʱ */
            /* ���cookie array �г�ʱ��cookie */
            tmp_cookie->record_time = 0;
            tmp_cookie->ull_cookie     = 0;
            /* ���ռ�õ�cookie bitmapλ */
            oal_bit_clear_bit_one_byte(puc_cookie_bitmap, loops);
        }
    }
}

/*****************************************************************************
 �� �� ��  : wal_del_cookie_from_array
 ��������  : ɾ��ָ��idx ��cookie
 �������  : [1]cookie_array
             [2]puc_cookie_bitmap
             [3]cookie_idx
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 wal_del_cookie_from_array(cookie_arry_stru *cookie_array, hi_u8 *puc_cookie_bitmap, hi_u8 cookie_idx)
{
    cookie_arry_stru   *tmp_cookie = HI_NULL;

    /* �����Ӧcookie bitmap λ */
    oal_bit_clear_bit_one_byte(puc_cookie_bitmap, cookie_idx);

    /* ���cookie array �г�ʱ��cookie */
    tmp_cookie = &cookie_array[cookie_idx];
    tmp_cookie->ull_cookie     = 0;
    tmp_cookie->record_time = 0;
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_add_cookie_to_array
 ��������  : ���cookie ��cookie array ��
 �������  : [1]cookie_array
             [2]puc_cookie_bitmap
             [3]puc_cookie_idx
             [4]pull_cookie
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 wal_add_cookie_to_array(cookie_arry_stru *cookie_array, hi_u8 *puc_cookie_bitmap,
    const hi_u64 *pull_cookie, hi_u8 *puc_cookie_idx)
{
    hi_u8           idx;
    cookie_arry_stru   *tmp_cookie = HI_NULL;

    if (*puc_cookie_bitmap == 0xFF) {
        /* cookie array �������ش��� */
        oam_warning_log0(0, OAM_SF_CFG, "{wal_add_cookie_to_array::array full!}\r\n");
        return HI_FAIL;
    }

    /* ��cookie ��ӵ�array �� */
    idx = oal_bit_get_num_one_byte(*puc_cookie_bitmap);
    oal_bit_set_bit_one_byte(puc_cookie_bitmap, idx);

    tmp_cookie = &cookie_array[idx];
    tmp_cookie->ull_cookie      = *pull_cookie;
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    tmp_cookie->record_time  = hi_get_tick();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    tmp_cookie->record_time  = OAL_TIME_JIFFY;
#endif

    *puc_cookie_idx = idx;
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_check_cookie_from_array
 ��������  : ��cookie array �в�����Ӧcookie index
 �������  : [1]puc_cookie_bitmap
             [2]cookie_idx
 �������  : ��
 �� �� ֵ  : status hi_u32
*****************************************************************************/
static hi_u32 wal_check_cookie_from_array(const hi_u8 *puc_cookie_bitmap, hi_u8 cookie_idx)
{
    /* ��cookie bitmap�в�����Ӧ��cookie index�����λͼΪ0����ʾ�Ѿ���del */
    if (*puc_cookie_bitmap & (bit(cookie_idx))) {
        return HI_SUCCESS;
    }
    /* �Ҳ����򷵻�FAIL */
    return HI_FAIL;
}

/*****************************************************************************
 �� �� ��  : wal_mgmt_do_tx
 ��������  : WAL �㷢�ʹ�wpa_supplicant  ���յ��Ĺ���֡
 �������  : oal_net_device_stru    *pst_netdev        ���͹���֡�豸
             mac_mgmt_frame_stru    *pst_mgmt_tx_param ���͹���֡����
 �������  : ��
 �� �� ֵ  : static hi_u32 HI_SUCCESS ���ͳɹ�
                                   HI_FAIL ����ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��8��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_mgmt_do_tx(oal_net_device_stru *netdev, const mac_mgmt_frame_stru *mgmt_tx_param)
{
    mac_vap_stru                    *mac_vap = HI_NULL;
    hmac_vap_stru                   *hmac_vap = HI_NULL;
    oal_mgmt_tx_stru                *mgmt_tx = HI_NULL;
    hi_u32                           wal_ret;
    hi_s32                           i_leftime;

    mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_mgmt_do_tx::can't get mac vap from netdevice priv data.}\r\n");
        return HI_FAIL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{wal_mgmt_do_tx::pst_hmac_vap ptr is null!}\r\n");
        return HI_FAIL;
    }

    mgmt_tx = &(hmac_vap->mgmt_tx);
    mgmt_tx->mgmt_tx_complete = HI_FALSE;
    mgmt_tx->mgmt_tx_status  = HI_FALSE;

    /* ���¼������� */
    wal_ret = wal_cfg80211_start_req(netdev, mgmt_tx_param,
        sizeof(mac_mgmt_frame_stru), WLAN_CFGID_CFG80211_MGMT_TX, HI_FALSE);
    if (wal_ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY,
            "{wal_mgmt_do_tx::wal_send_cfg_event return err code:[%d]!}", wal_ret);
        return wal_ret;
    }

    i_leftime = hi_wait_event_timeout(mgmt_tx->wait_queue, HI_TRUE == mgmt_tx->mgmt_tx_complete,
        WAL_MGMT_TX_TIMEOUT_MSEC / HI_MILLISECOND_PER_TICK); // ʹ�÷�wifiĿ¼����꺯��,�󱨸澯,lin_t e26�澯����
    if (i_leftime == 0) {
        /* ��ʱ����ʱ */
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mgmt_do_tx::mgmt tx timeout!}\r\n");
        return HI_FAIL;
    } else if (i_leftime < 0) {
        /* ��ʱ���ڲ����� */
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mgmt_do_tx::mgmt tx timer error!}\r\n");
        return HI_FAIL;
    } else {
        /* ��������  */
        oam_info_log0(0, OAM_SF_ANY, "{wal_mgmt_do_tx::mgmt tx commpleted!}\r\n");
        /* DTS2015122906020. �������ͽ��������ط������״̬ */
        return (hi_u32)((mgmt_tx->mgmt_tx_status == HI_FALSE) ? HI_FAIL : HI_SUCCESS);
    }
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
static hi_u32 wal_cfg80211_mgmt_tx_parameter_check(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    struct cfg80211_mgmt_tx_params *pst_params, hi_u64 *pull_cookie)
#else
static hi_u32 wal_cfg80211_mgmt_tx_parameter_check(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    oal_ieee80211_channel *chan, const hi_u8 *puc_buf, hi_u64 *pull_cookie)
#endif
{
    oal_net_device_stru         *netdev;
    hi_unref_param(wiphy);

#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    if (pst_params == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::pst_params is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    oal_ieee80211_channel       *chan = pst_params->chan;
    const hi_u8                 *puc_buf  = pst_params->buf;
#endif
    if ((wdev == HI_NULL) || (chan == HI_NULL) || (pull_cookie == HI_NULL) || (puc_buf == HI_NULL)) {
        oam_error_log3(0, OAM_SF_CFG,
            "{wal_cfg80211_mgmt_tx_parameter_check::wdev or chan or cookie or buf ptr is null, error %p, %p, %p!}\r\n",
            (uintptr_t)wdev, (uintptr_t)chan, (uintptr_t)pull_cookie);
        return HI_ERR_CODE_PTR_NULL;
    }

    netdev = wdev->netdev;
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::pst_netdev ptr is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::can't get mac vap fail!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::pst_hmac_vap ptr is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_mgmt_tx
 ��������  : ���͹���֡
*****************************************************************************/
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
hi_s32 wal_cfg80211_mgmt_tx(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev, oal_cfg80211_mgmt_tx_params_stru *params,
    hi_u64 *pull_cookie)
#else
hi_s32 wal_cfg80211_mgmt_tx(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev, oal_ieee80211_channel *chan, bool offchan,
    hi_u32 wait, const hi_u8 *puc_buf, size_t len, bool no_cck, bool dont_wait_for_ack, hi_u64 *pull_cookie)
#endif
{
    mac_device_stru                 *mac_dev = (mac_device_stru *)mac_res_get_dev();
    mac_mgmt_frame_stru              mgmt_tx = {0};
    hi_u8                            cookie_idx;
    hi_u32                           ret;

#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    if (wal_cfg80211_mgmt_tx_parameter_check(wiphy, wdev, params, pull_cookie) != HI_SUCCESS) {
        return -HI_ERR_CODE_PTR_NULL;
    }

    const hi_u8 *puc_buf  = params->buf;
    hi_u32 len   = params->len;
    oal_ieee80211_channel *chan = params->chan;
#else
    hi_unref_param(offchan);
    hi_unref_param(wait);
    hi_unref_param(no_cck);
    hi_unref_param(dont_wait_for_ack);
    if (wal_cfg80211_mgmt_tx_parameter_check(wiphy, wdev, chan, puc_buf, pull_cookie) != HI_SUCCESS) {
        return -HI_ERR_CODE_PTR_NULL;
    }
#endif
    mac_vap_stru *mac_vap = oal_net_dev_priv(wdev->netdev);

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);

    mac_p2p_info_stru *p2p_info = &mac_dev->p2p_info;
    *pull_cookie = p2p_info->ull_send_action_id++;   /* cookieֵ�ϲ������Ҫ�ж��Ƿ�����εķ��͵��µ�callback */
    if (*pull_cookie == 0) {
        *pull_cookie = p2p_info->ull_send_action_id++;
    }
    const oal_ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)puc_buf;
    if (oal_ieee80211_is_probe_resp(mgmt->frame_control)) {
        *pull_cookie = 0; /* set cookie default value */
        /* host should not send PROE RESPONSE,
           device will send immediately when receive probe request packet */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        cfg80211_mgmt_tx_status(wdev, puc_buf, len, HI_TRUE);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_cfg80211_mgmt_tx_status(wdev, *pull_cookie, puc_buf, len, HI_TRUE, GFP_KERNEL);
#endif
        return HI_SUCCESS;
    }

    /* 2.1 ��Ϣ����׼�� */
    mgmt_tx.channel = oal_ieee80211_frequency_to_channel(chan->center_freq);
    if (wal_add_cookie_to_array(g_cookie_array, &g_cookie_array_bitmap, pull_cookie, &cookie_idx) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::Failed to add cookies!}");
        return -HI_FAIL;
    }
    mgmt_tx.mgmt_frame_id = cookie_idx;
    mgmt_tx.us_len        = (hi_u16)len;
    mgmt_tx.puc_frame     = puc_buf;

    hmac_vap->mgmt_tx.mgmt_tx_complete = HI_FALSE;
    hmac_vap->mgmt_tx.mgmt_tx_status   = HI_FALSE;

    hi_u32 start_time_stamp = OAL_TIME_JIFFY;

    /* ����ʧ�ܣ������ش� */
    do {
        ret = wal_mgmt_do_tx(wdev->netdev, &mgmt_tx);
    }while ((ret != HI_SUCCESS) && (oal_time_before(OAL_TIME_JIFFY,
        start_time_stamp + OAL_MSECS_TO_JIFFIES(2 * WAL_MGMT_TX_TIMEOUT_MSEC)))); /* 2 times */

    if (ret != HI_SUCCESS) {
        /* ����ʧ�ܣ�����ʱ֡��bitmap */
        wal_check_cookie_timeout(g_cookie_array, &g_cookie_array_bitmap);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        cfg80211_mgmt_tx_status(wdev, puc_buf, len, HI_FALSE);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_cfg80211_mgmt_tx_status(wdev, *pull_cookie, puc_buf, len, HI_FALSE, GFP_KERNEL);
#endif
    } else {
        /* ��������  */
        *pull_cookie = g_cookie_array[hmac_vap->mgmt_tx.mgmt_frame_id].ull_cookie;
        wal_del_cookie_from_array(g_cookie_array, &g_cookie_array_bitmap, hmac_vap->mgmt_tx.mgmt_frame_id);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        cfg80211_mgmt_tx_status(wdev, puc_buf, len, HI_FALSE);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_cfg80211_mgmt_tx_status(wdev, *pull_cookie, puc_buf, len, HI_FALSE, GFP_KERNEL);
#endif
    }

    return HI_SUCCESS;
}

#else
static hi_u32 wal_cfg80211_mgmt_tx_parameter_check(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    oal_ieee80211_channel *chan, const hi_u8 *puc_buf, hi_u64 *pull_cookie)
{
    oal_net_device_stru *netdev;
    hi_unref_param(wiphy);
    if ((wdev == HI_NULL) || (chan == HI_NULL) || (pull_cookie == HI_NULL) || (puc_buf == HI_NULL)) {
        oam_error_log3(0, OAM_SF_CFG,
            "{wal_cfg80211_mgmt_tx_parameter_check::wdev or chan or cookie or buf ptr is null, error %p, %p, %p!}\r\n",
            (uintptr_t)wdev, (uintptr_t)chan, (uintptr_t)pull_cookie);
        return HI_ERR_CODE_PTR_NULL;
    }

    netdev = wdev->netdev;
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::pst_netdev ptr is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::can't get mac vap fail!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{wal_cfg80211_mgmt_tx_parameter_check::pst_hmac_vap ptr is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_mgmt_tx
 ��������  : ���͹���֡
*****************************************************************************/
hi_u32 wal_cfg80211_mgmt_tx(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev, oal_ieee80211_channel *chan,
    const hi_u8 *puc_buf, hi_u32 len, hi_u64 *pull_cookie)
{
    mac_device_stru                 *mac_dev = (mac_device_stru *)mac_res_get_dev();
    mac_mgmt_frame_stru              mgmt_tx = {0};
    hi_u8                            cookie_idx;
    hi_u32                           ret;

    if (wal_cfg80211_mgmt_tx_parameter_check(wiphy, wdev, chan, puc_buf, pull_cookie) != HI_SUCCESS) {
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_stru *mac_vap = oal_net_dev_priv(wdev->netdev);
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_p2p_info_stru *p2p_info = &mac_dev->p2p_info;
    *pull_cookie = p2p_info->ull_send_action_id++;   /* cookieֵ�ϲ������Ҫ�ж��Ƿ�����εķ��͵��µ�callback */
    if (*pull_cookie == 0) {
        *pull_cookie = p2p_info->ull_send_action_id++;
    }
    const oal_ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)puc_buf;
    if (oal_ieee80211_is_probe_resp(mgmt->frame_control)) {
        *pull_cookie = 0; /* set cookie default value */
        /* host should not send PROE RESPONSE,
           device will send immediately when receive probe request packet */
        cfg80211_mgmt_tx_status(wdev, puc_buf, len, HI_TRUE);
        return HI_SUCCESS;
    }

    /* 2.1 ��Ϣ����׼�� */
    mgmt_tx.channel = oal_ieee80211_frequency_to_channel(chan->center_freq);
    if (wal_add_cookie_to_array(g_cookie_array, &g_cookie_array_bitmap, pull_cookie, &cookie_idx) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx::Failed to add cookies!}\r\n");
        return HI_FAIL;
    }
    mgmt_tx.mgmt_frame_id = cookie_idx;
    mgmt_tx.us_len        = (hi_u16)len;
    mgmt_tx.puc_frame     = puc_buf;

    hmac_vap->mgmt_tx.mgmt_tx_complete = HI_FALSE;
    hmac_vap->mgmt_tx.mgmt_tx_status = HI_FALSE;

    hi_u32 start_time_stamp = hi_get_tick();

    hi_u32 end_time_stamp = start_time_stamp + 2 * WAL_MGMT_TX_TIMEOUT_MSEC / HI_MILLISECOND_PER_TICK; /* 2: ����ϵ�� */
    /* ����ʧ�ܣ������ش� */
    do {
        ret = wal_mgmt_do_tx(wdev->netdev, &mgmt_tx);
    }while ((ret != HI_SUCCESS) && (hi_get_tick() < end_time_stamp));

    if (ret != HI_SUCCESS) {
        /* ����ʧ�ܣ�����ʱ֡��bitmap */
        wal_check_cookie_timeout(g_cookie_array, &g_cookie_array_bitmap);
    } else {
        /* ��������  */
        *pull_cookie = g_cookie_array[hmac_vap->mgmt_tx.mgmt_frame_id].ull_cookie;
        wal_del_cookie_from_array(g_cookie_array, &g_cookie_array_bitmap, hmac_vap->mgmt_tx.mgmt_frame_id);
    }
    cfg80211_mgmt_tx_status(wdev, puc_buf, len, ((ret != HI_SUCCESS) ? HI_FALSE : HI_TRUE));

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 �� �� ��  : wal_cfg80211_mgmt_tx_status
 ��������  : HMAC��mgmt tx status��WAL, ����wait queue
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_cfg80211_mgmt_tx_status(frw_event_mem_stru * event_mem)
{
    frw_event_stru                  *event = HI_NULL;
    dmac_crx_mgmt_tx_status_stru    *mgmt_tx_status_param = HI_NULL;
    hmac_vap_stru                   *hmac_vap = HI_NULL;
    oal_mgmt_tx_stru                *mgmt_tx = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_mgmt_tx_status::event_mem is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;
    hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::pst_hmac_vap null.vap_id[%d]}",
            event->event_hdr.vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    mgmt_tx_status_param   = (dmac_crx_mgmt_tx_status_stru *)(event->auc_event_data);
    mgmt_tx = &(hmac_vap->mgmt_tx);
    mgmt_tx->mgmt_tx_complete = HI_TRUE;
    mgmt_tx->mgmt_tx_status   = mgmt_tx_status_param->tx_status;
    mgmt_tx->mgmt_frame_id    = mgmt_tx_status_param->mgmt_frame_id;

    /* �Ҳ�����Ӧ��cookieֵ��˵���Ѿ���ʱ����������Ҫ�ٻ��� */
    if (HI_SUCCESS == wal_check_cookie_from_array(&g_cookie_array_bitmap, mgmt_tx->mgmt_frame_id)) {
         /* �ñ������Ż�ʱ��֤HI_WAIT_QUEUE_WAKE_UP�����ִ�� */
        oal_smp_mb();
        hi_wait_queue_wake_up_interrupt(&mgmt_tx->wait_queue);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_req
 ��������  : ��wal���¼�
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��1��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_start_req(oal_net_device_stru *netdev, const hi_void *ps_param, hi_u16 us_len,
    wlan_cfgid_enum_uint16 wid, hi_u8 need_rsp)
{
    wal_msg_write_stru              write_msg;
    wal_msg_stru                   *rsp_msg = HI_NULL;
    hi_u32                          ret;

    if (ps_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_req::param is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д msg ��Ϣͷ */
    write_msg.wid = wid;
    write_msg.us_len = us_len;

    /* ��д msg ��Ϣ�� */
    if (us_len > WAL_MSG_WRITE_MAX_LEN) {
        oam_error_log2(0, OAM_SF_SCAN, "{wal_cfg80211_start_req::us_len %d > WAL_MSG_WRITE_MAX_LEN %d err!}\r\n",
            us_len, WAL_MSG_WRITE_MAX_LEN);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value), ps_param, us_len) != EOK) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_req::mem safe function err!}");
        return HI_FAIL;
    }
    /***************************************************************************
           ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             need_rsp,
                             need_rsp ? &rsp_msg : HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_SCAN,
            "{wal_cfg80211_start_req::wal_send_cfg_event return err code %u!}\r\n", ret);
        return ret;
    }
    if (need_rsp && (rsp_msg != HI_NULL)) {
        /* ��ȡ���صĴ����� */
        ret = wal_check_and_release_msg_resp(rsp_msg);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_SCAN,
                "{wal_cfg80211_start_req::wal_send_cfg_event return err code:[%u]}", ret);
            return ret;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_start_scan
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

  2.��    ��   : 2014��1��4��
    ��    ��   : Hisilicon
    �޸�����   : �ع�

*****************************************************************************/
hi_u32 wal_cfg80211_start_scan(oal_net_device_stru *netdev, const mac_cfg80211_scan_param_stru *scan_param)
{
    mac_cfg80211_scan_param_stru    *mac_cfg80211_scan_param = HI_NULL;
    hi_u32                           ret;

    if (scan_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_scan::scan failed, null ptr, pst_scan_param = null.}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �˴�����hmac���ͷ� */
    mac_cfg80211_scan_param =
        (mac_cfg80211_scan_param_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(mac_cfg80211_scan_param_stru));
    if (mac_cfg80211_scan_param == NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_scan::scan failed, alloc scan param memory failed!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (memcpy_s(mac_cfg80211_scan_param, sizeof(mac_cfg80211_scan_param_stru),
        scan_param, sizeof(mac_cfg80211_scan_param_stru)) != EOK) {
        oal_mem_free(mac_cfg80211_scan_param);
        oam_error_log0(0, OAM_SF_SCAN, "{wal_cfg80211_start_scan::mem safe function err!}");
        return HI_FAIL;
    }

    /* 1.������ָ���ָ��, 2.sizeofָ��  */
    ret = wal_cfg80211_start_req(netdev, &mac_cfg80211_scan_param, sizeof(uintptr_t),
                                 WLAN_CFGID_CFG80211_START_SCAN, HI_FALSE);
    if (ret != HI_SUCCESS) {
        /* �·�ɨ��ʧ�ܣ��ͷ� */
        oal_mem_free(mac_cfg80211_scan_param);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_cfg80211_reset_bands
 ��������  : ���³�ʼ��wifi wiphy��bands
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��12��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_cfg80211_reset_bands(hi_void)
{
    hi_s32 i;

    /* ÿ�θ��¹�����,flags���ᱻ�޸�,���ϴ��޸ĵ�ֵ���ᱻ���,�൱��ÿ���޸ĵĹ����붼����Ч��
       ��˸��¹�����Ҫ���flag��־ */
    for (i = 0; i < g_wifi_band_2ghz.n_channels; i++) {
        g_wifi_band_2ghz.channels[i].flags = 0;
    }
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/* ��ͬ����ϵͳ����ָ��ṹ�巽ʽ��ͬ */
static oal_cfg80211_ops_stru g_wal_cfg80211_ops =
{
    .scan                     = wal_cfg80211_scan,
    .connect                  = wal_cfg80211_connect,
    .disconnect               = wal_cfg80211_disconnect,
    .add_key                  = wal_cfg80211_add_key,
    .get_key                  = wal_cfg80211_get_key,
    .del_key                  = wal_cfg80211_remove_key,
    .set_default_key          = wal_cfg80211_set_default_key,
    .set_default_mgmt_key     = wal_cfg80211_set_default_mgmt_key,
    .set_wiphy_params         = wal_cfg80211_set_wiphy_params,
/* Hi1131 �޸�AP ���ýӿ� */
    .change_beacon            = wal_cfg80211_change_beacon,
    .start_ap                 = wal_cfg80211_start_ap,
    .stop_ap                  = wal_cfg80211_stop_ap,
    .change_bss               = wal_cfg80211_change_bss,
    .sched_scan_start         = wal_cfg80211_sched_scan_start,
    .sched_scan_stop          = wal_cfg80211_sched_scan_stop,
    .change_virtual_intf      = wal_cfg80211_change_virtual_intf,
    .add_station              = wal_cfg80211_add_station,
    .del_station              = wal_cfg80211_del_station,
    .change_station           = wal_cfg80211_change_station,
    .get_station              = wal_cfg80211_get_station,
    .dump_station             = wal_cfg80211_dump_station,
#ifdef _PRE_WLAN_FEATURE_P2P
    .remain_on_channel        = wal_cfg80211_remain_on_channel,
    .cancel_remain_on_channel = wal_cfg80211_cancel_remain_on_channel,
#endif
    .mgmt_tx                  = wal_cfg80211_mgmt_tx,
    .mgmt_frame_register      = wal_cfg80211_mgmt_frame_register,
    .set_bitrate_mask         = wal_cfg80211_set_bitrate_mask,
    .add_virtual_intf         = wal_cfg80211_add_virtual_intf,
    .del_virtual_intf         = wal_cfg80211_del_virtual_intf,
    .mgmt_tx_cancel_wait      = wal_cfg80211_mgmt_tx_cancel_wait,
    .start_p2p_device         = wal_cfg80211_start_p2p_device,
    .stop_p2p_device          = wal_cfg80211_stop_p2p_device,
    .set_power_mgmt           = wal_cfg80211_set_power_mgmt,
#if (LINUX_VERSION_CODE >= kernel_version(4,1,0))
    .abort_scan               = wal_cfg80211_abort_scan,
#endif /* (LINUX_VERSION_CODE >= kernel_version(4,1,0)) */
};
#endif /* #if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) */

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
int wal_get_vap_mode(hi_void)
{
    return g_mode;
}

int wal_get_bw_type(hi_void)
{
    return g_bw;
}

int wal_get_protocol_type(hi_void)
{
    return g_proto;
}

hi_u32 wal_init_drv_netdev(hi_void)
{
    hi_u32 err_code = HI_FAIL;
    hi_u16 mode = wal_get_vap_mode();
    hi_u16 bw = wal_get_bw_type();
    hi_u16 protocol = wal_get_protocol_type();
    if (mode >= WAL_WIFI_MODE_BUTT || bw >= WAL_WIFI_BW_BUTT || protocol >= WAL_PHY_MODE_BUTT) {
        oam_error_log3(0, 0, "wal_init_drv_netdev:: invalid mode[%d] or bw[%d] or protocol[%d]", mode, bw, protocol);
        return HI_FAIL;
    }

    oam_warning_log3(0, 0, "wal_init_drv_netdev:: mode[%d] bw[%d] protocol[%d]", mode, bw, protocol);

    if (mode == WAL_WIFI_MODE_STA) {
        err_code = wal_init_drv_wlan_netdev(NL80211_IFTYPE_STATION, protocol, bw);
    } else if (mode == WAL_WIFI_MODE_AP) {
        err_code = wal_init_drv_wlan_netdev(NL80211_IFTYPE_AP, WAL_PHY_MODE_11N, bw);
    } else if (mode == WAL_WIFI_MODE_STA_AP) {
        err_code = wal_init_drv_wlan_netdev(NL80211_IFTYPE_STATION, protocol, bw);
        err_code |= wal_init_drv_wlan_netdev(NL80211_IFTYPE_AP, WAL_PHY_MODE_11N, bw);
    }
    if (err_code != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "wal_init_wlan_netdev wlan0 failed.l_return:%d\n", err_code);
        return err_code;
    }
    return err_code;
}
#endif /* #if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) */

/*****************************************************************************
 ��������  : wal_linux_cfg80211���س�ʼ��
 �޸���ʷ      :
  1.��    ��   : 2013��8��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_cfg80211_init(hi_void)
{
    /* ��device��ֱ�ӻ�ȡdev���г�ʼ�� */
    mac_device_stru *mac_dev = mac_res_get_dev();
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    mac_dev->wiphy = oal_wiphy_new(sizeof(mac_wiphy_priv_stru));
#else
    hi_s32            err_code;
    mac_dev->wiphy = oal_wiphy_new(&g_wal_cfg80211_ops, sizeof(mac_wiphy_priv_stru));
#endif
    if (mac_dev->wiphy == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_init::oal_wiphy_new failed!}");
        return HI_FAIL;
    }

    /* ��ʼ��wiphy �ṹ������ */
    oal_wiphy_stru *wiphy = mac_dev->wiphy;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#ifdef _PRE_WLAN_FEATURE_P2P
    wiphy->iface_combinations   = g_sta_p2p_iface_combinations;
    wiphy->n_iface_combinations = hi_array_size(g_sta_p2p_iface_combinations);
    wiphy->mgmt_stypes          = g_wal_cfg80211_default_mgmt_stypes;
    wiphy->max_remain_on_channel_duration = 5000; /* 5000: ����ʱ���� */
    /* ʹ���������� */
    wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;
    wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME;
    /* 1131ע��֧��pno����ɨ�����������Ϣ */
    wiphy->max_sched_scan_ssids  = MAX_PNO_SSID_COUNT;
    wiphy->max_match_sets        = MAX_PNO_SSID_COUNT;
    wiphy->max_sched_scan_ie_len = WAL_MAX_SCAN_IE_LEN;
    wiphy->flags |= WIPHY_FLAG_SUPPORTS_SCHED_SCAN;
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    wiphy->interface_modes = bit(NL80211_IFTYPE_STATION) | bit(NL80211_IFTYPE_AP) | bit(NL80211_IFTYPE_P2P_CLIENT) |
                             bit(NL80211_IFTYPE_P2P_GO) | bit(NL80211_IFTYPE_P2P_DEVICE);
#else
    wiphy->interface_modes = bit(NL80211_IFTYPE_STATION) | bit(NL80211_IFTYPE_AP);
#endif

#ifdef _PRE_WLAN_FEATURE_MESH
    wiphy->interface_modes |= bit(NL80211_IFTYPE_MESH_POINT);
#endif
    wiphy->max_scan_ssids  = WLAN_SCAN_REQ_MAX_BSS;
    wiphy->max_scan_ie_len = WAL_MAX_SCAN_IE_LEN;
    wiphy->cipher_suites   = g_wifi_cipher_suites;
    wiphy->n_cipher_suites = sizeof(g_wifi_cipher_suites) / sizeof(hi_u32);

    /* ��ʹ�ܽ��� */
    wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;
    /* linux 3.14 �汾�����������������޸� */
#if (LINUX_VERSION_CODE >= kernel_version(3, 14, 0))
    wiphy->regulatory_flags |= REGULATORY_CUSTOM_REG;
#endif
    wiphy->signal_type       = CFG80211_SIGNAL_TYPE_MBM;
#endif
    wiphy->bands[IEEE80211_BAND_2GHZ] = &g_wifi_band_2ghz;        /* ֧�ֵ�Ƶ����Ϣ 2.4G */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_wiphy_apply_custom_regulatory(wiphy, wal_get_cfg_regdb());
    err_code = oal_wiphy_register(wiphy);
    if (err_code != 0) {
        oal_wiphy_free(mac_dev->wiphy);
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_init::oal_wiphy_register failed!}\r\n");
        return (hi_u32)err_code;
    }
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_wiphy_apply_custom_regulatory();
    oal_wiphy_register(wiphy);
#endif

    /* P2P add_virtual_intf ����wiphy ��������wiphy priv ָ�뱣��wifi ����mac_devie_stru �ṹָ�� */
    mac_wiphy_priv_stru *wiphy_priv = (mac_wiphy_priv_stru *)(oal_wiphy_priv(wiphy));
    wiphy_priv->mac_device = mac_dev;

    /* linux �����£���ʼ��ʱע������ڵ� */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    err_code = wal_init_drv_netdev();
    if (err_code != HI_SUCCESS) {
        oal_wiphy_free(mac_dev->wiphy);
        oam_error_log1(0, OAM_SF_ANY, "wal_init_wlan_netdev wlan0 failed.l_return:%d\n", err_code);
        return err_code;
    }
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ж��wihpy
 �޸���ʷ      :
  1.��    ��   : 2013��9��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void wal_cfg80211_exit(hi_void)
{
    mac_device_stru    *mac_dev = HI_NULL;

    /* ��device��ֱ�ӻ�ȡdev����ȥ��ʼ�� */
    mac_dev = mac_res_get_dev();
    /* ע��ע�� wiphy device */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_wiphy_unregister(mac_dev->wiphy);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_wiphy_unregister();
#endif
    /* ж��wiphy device */
    oal_wiphy_free(mac_dev->wiphy);
    return;
}

#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
/*****************************************************************************
 �� �� ��  : wal_cfg80211_set_rekey_info
 ��������  : �ϲ��·���rekey info���׸�wal�㴦��
 �������  : oal_net_device_stru      *pst_net_dev,
             mac_rekey_offload_stru   *pst_rekey_offload
 �������  : ��
 �� �� ֵ  : HI_SUCCESS������������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��8��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_cfg80211_set_rekey_info(oal_net_device_stru *netdev, mac_rekey_offload_stru *rekey_offload)
{
    mac_rekey_offload_stru         rekey_params;
    hi_u32                         ret;

    /* 1 �����Ϸ��Լ�� */
    if ((netdev == HI_NULL) || (rekey_offload == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_cfg80211_set_rekey_info::pst_net_dev = %p, pst_rekey_offload = %p!}",
                       (uintptr_t)netdev, (uintptr_t)rekey_offload);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* 2 ��Ϣ����׼�� */
    if (memcpy_s(&rekey_params, sizeof(mac_rekey_offload_stru),
        rekey_offload, sizeof(mac_rekey_offload_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_cfg80211_set_rekey_info::mem safe function err!}");
        return HI_FAIL;
    }

    /* ���¼������� */
    ret = wal_cfg80211_start_req(netdev, &rekey_params,
        sizeof(mac_rekey_offload_stru), WLAN_CFGID_SET_REKEY, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY,
            "{wal_cfg80211_set_rekey_info::wal_send_cfg_event return err code:[%d]!}", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}
#endif /* _PRE_WLAN_FEATURE_REKEY_OFFLOAD */

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

