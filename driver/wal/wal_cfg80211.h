/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_cfg80211.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_CFG80211_H__
#define __WAL_CFG80211_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "wal_main.h"
#include "hmac_ext_if.h"
#include "wal_ioctl.h"
#include "wal_hipriv.h"
#include "wal_scan.h"
#include "oal_net.h"
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifndef HAVE_PCLINT_CHECK
#include "hi_wifi_driver_wpa_if.h"
#endif
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
#include "hmac_p2p.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define     WAL_MAX_SCAN_TIME_PER_CHANNEL  400
#define     WAL_MAX_SCAN_TIME_PER_SCAN_REQ (5 * 1000)      /* wpa_s�·�ɨ�����󣬳�ʱʱ��Ϊ5s����λΪms */

/* channel index and frequence */
#define WAL_MIN_CHANNEL_2G      1
#define WAL_MAX_CHANNEL_2G      14

#define WAL_MIN_FREQ_2G         (2412 + 5*(WAL_MIN_CHANNEL_2G - 1))
#define WAL_MAX_FREQ_2G         2484

/* wiphy �ṹ���ʼ������ */
#define WAL_MAX_SCAN_IE_LEN                 1000
/* 802.11n HT �������� */
#define IEEE80211_HT_CAP_LDPC_CODING        0x0001
#define IEEE80211_HT_CAP_SUP_WIDTH_20_40    0x0002
#define IEEE80211_HT_CAP_SM_PS              0x000C
#define IEEE80211_HT_CAP_SM_PS_SHIFT        2
#define IEEE80211_HT_CAP_GRN_FLD            0x0010
#define IEEE80211_HT_CAP_SGI_20             0x0020
#define IEEE80211_HT_CAP_SGI_40             0x0040
#define IEEE80211_HT_CAP_TX_STBC            0x0080
#define IEEE80211_HT_CAP_RX_STBC            0x0300
#define IEEE80211_HT_CAP_DELAY_BA           0x0400
#define IEEE80211_HT_CAP_MAX_AMSDU          0x0800
#define IEEE80211_HT_CAP_DSSSCCK40          0x1000
#define IEEE80211_HT_CAP_RESERVED           0x2000
#define IEEE80211_HT_CAP_40MHZ_INTOLERANT   0x4000
#define IEEE80211_HT_CAP_LSIG_TXOP_PROT     0x8000

/* 802.11ac VHT Capabilities */
#define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895              0x00000000
#define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_7991              0x00000001
#define IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_11454             0x00000002
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ            0x00000004
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160_80PLUS80MHZ   0x00000008
#define IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK              0x0000000C
#define IEEE80211_VHT_CAP_RXLDPC                            0x00000010
#define IEEE80211_VHT_CAP_SHORT_GI_80                       0x00000020
#define IEEE80211_VHT_CAP_SHORT_GI_160                      0x00000040
#define IEEE80211_VHT_CAP_TXSTBC                            0x00000080
#define IEEE80211_VHT_CAP_RXSTBC_1                          0x00000100
#define IEEE80211_VHT_CAP_RXSTBC_2                          0x00000200
#define IEEE80211_VHT_CAP_RXSTBC_3                          0x00000300
#define IEEE80211_VHT_CAP_RXSTBC_4                          0x00000400
#define IEEE80211_VHT_CAP_RXSTBC_MASK                       0x00000700
#define IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE             0x00000800
#define IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE             0x00001000
#define IEEE80211_VHT_CAP_BEAMFORMER_ANTENNAS_MAX           0x00006000
#define IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MAX           0x00030000
#define IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE             0x00080000
#define IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE             0x00100000
#define IEEE80211_VHT_CAP_VHT_TXOP_PS                       0x00200000
#define IEEE80211_VHT_CAP_HTC_VHT                           0x00400000
#define IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT  23
#define IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK   (7 << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT)
#define IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_UNSOL_MFB 0x08000000
#define IEEE80211_VHT_CAP_VHT_LINK_ADAPTATION_VHT_MRQ_MFB   0x0c000000
#define IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN                0x10000000
#define IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN                0x20000000

/* management */
#define IEEE80211_STYPE_ASSOC_REQ       0x0000
#define IEEE80211_STYPE_ASSOC_RESP      0x0010
#define IEEE80211_STYPE_REASSOC_REQ     0x0020
#define IEEE80211_STYPE_REASSOC_RESP    0x0030
#define IEEE80211_STYPE_PROBE_REQ       0x0040
#define IEEE80211_STYPE_PROBE_RESP      0x0050
#define IEEE80211_STYPE_BEACON          0x0080
#define IEEE80211_STYPE_ATIM            0x0090
#define IEEE80211_STYPE_DISASSOC        0x00A0
#define IEEE80211_STYPE_AUTH            0x00B0
#define IEEE80211_STYPE_DEAUTH          0x00C0
#define IEEE80211_STYPE_ACTION          0x00D0

#define WAL_COOKIE_ARRAY_SIZE           8       /* ����8bit ��map ��Ϊ����cookie ������״̬ */
#define WAL_MGMT_TX_TIMEOUT_MSEC        100     /* WAL ���͹���֡��ʱʱ�� */
#define WAL_MGMT_TX_RETRY_CNT           8       /* WAL ���͹���֡����ش����� */

#define IEEE80211_FCTL_FTYPE            0x000c
#define IEEE80211_FCTL_STYPE            0x00f0
#define IEEE80211_FTYPE_MGMT            0x0000

#define WAL_GET_STATION_THRESHOLD       1000 /* �̶�ʱ��������һ�����¼���DMAC RSSI */

typedef struct cookie_arry {
    hi_u64  ull_cookie;
    hi_u32  record_time;
    hi_u32  reserved;
} cookie_arry_stru;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) || (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define ratetab_ent(_rate, _rateid, _flags)     \
    {                                                               \
        .bitrate        = (_rate),                                  \
        .hw_value       = (_rateid),                                \
        .flags          = (_flags),                                 \
    }

#define chan2g(_channel, _freq, _flags)  \
    {                       \
        .band                   = IEEE80211_BAND_2GHZ,          \
        .center_freq            = (_freq),                      \
        .hw_value               = (_channel),                   \
        .flags                  = (_flags),                     \
        .max_antenna_gain       = 0,                            \
        .max_power              = 30,                           \
    }

#define chan5g(_channel, _flags) \
    {                                              \
        .band                   = IEEE80211_BAND_5GHZ,          \
        .center_freq            = 5000 + (5 * (_channel)),      \
        .hw_value               = (_channel),                   \
        .flags                  = (_flags),                     \
        .max_antenna_gain       = 0,                            \
        .max_power              = 30,                           \
    }

#define chan4_9g(_channel, _flags) \
    {                                              \
        .band                   = IEEE80211_BAND_5GHZ,          \
        .center_freq            = 4000 + (5 * (_channel)),      \
        .hw_value               = (_channel),                   \
        .flags                  = (_flags),                     \
        .max_antenna_gain       = 0,                            \
        .max_power              = 30,                           \
    }
#else
error "WRONG OS VERSION"
#endif

#define WAL_MIN_RTS_THRESHOLD 256
#define WAL_MAX_RTS_THRESHOLD 0xFFFF

#define WAL_MAX_FRAG_THRESHOLD 7536
#define WAL_MIN_FRAG_THRESHOLD 256

#define WAL_MAX_WAIT_TIME 3000
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    WAL_WIFI_MODE_STA = 0,
    WAL_WIFI_MODE_AP = 1,
    WAL_WIFI_MODE_STA_AP = 2,
    /* ��������չ */
    WAL_WIFI_MODE_BUTT
} wal_wifi_mode_enum;
typedef int wal_wifi_mode_enum_int;

typedef enum {
    WAL_WIFI_BW_LEGACY_20M = 0,
    WAL_WIFI_BW_HIEX_10M = 1,
    WAL_WIFI_BW_HIEX_5M = 2,
    WAL_WIFI_BW_BUTT
} wal_wifi_bw_enum;
typedef int wal_wifi_bw_enum_int;

/*****************************************************************************
  5 ��������
*****************************************************************************/
/*****************************************************************************
 ��������  : �ж��Ƿ�Ϊprobe_resp ֡
*****************************************************************************/
static inline hi_u32 oal_ieee80211_is_probe_resp(hi_u16 fc)
{
    return (fc & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE)) ==
        (IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_RESP);
}

hi_void  wal_cfg80211_exit(hi_void);
hi_u32 wal_cfg80211_init(hi_void);
hi_u32 wal_cfg80211_mgmt_tx_status(frw_event_mem_stru *event_mem);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_void wal_cfg80211_unregister_netdev(oal_net_device_stru *netdev);
#endif
hi_void wal_cfg80211_reset_bands(hi_void);

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_add_vap(const mac_cfg_add_vap_param_stru *add_vap_param);
hi_u32 wal_cfg80211_set_default_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index,
    hi_bool unicast, hi_bool multicast);
hi_u32 wal_cfg80211_add_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    cfg80211_add_key_info_stru *cfg80211_add_key_info, const hi_u8 *mac_addr,  oal_key_params_stru *params);
hi_u32 wal_cfg80211_remove_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u8 key_index,
    hi_bool pairwise, const hi_u8 *mac_addr);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_mgmt_tx(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    struct cfg80211_mgmt_tx_params *pst_params, hi_u64 *pull_cookie);
#else
hi_u32 wal_cfg80211_mgmt_tx(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev,
    oal_ieee80211_channel *pst_chan, const hi_u8 *puc_buf, hi_u32 ul_len, hi_u64 *pull_cookie);
#endif
hi_u32 wal_cfg80211_change_virtual_intf(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, nl80211_iftype_uint8 type,
    hi_u32 *pul_flags, oal_vif_params_stru *params);
hi_u32  wal_cfg80211_scan(oal_wiphy_stru *wiphy, oal_cfg80211_scan_request_stru *request);
hi_u32 wal_cfg80211_del_station(const oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, const hi_u8 *mac_addr);
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_stop_ap(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev);
hi_s32 wal_cfg80211_del_virtual_intf(oal_wiphy_stru *wiphy, oal_wireless_dev *wdev);
hi_s32 wal_cfg80211_set_default_key(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    hi_u8 key_index, bool unicast, bool multicast);
#endif
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_cfg80211_connect(oal_wiphy_stru *wiphy, oal_net_device_stru *net_device,
    oal_cfg80211_connect_params_stru *sme);
hi_u32  wal_cfg80211_disconnect(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u16 us_reason_code);
hi_u32 wal_cfg80211_change_beacon(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    oal_beacon_data_stru *beacon_info);
hi_u32 wal_cfg80211_start_ap(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, oal_ap_settings_stru *ap_settings);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_cfg80211_connect(oal_wiphy_stru *wiphy, oal_net_device_stru *net_device,
    oal_cfg80211_connect_params_stru *sme);
hi_s32  wal_cfg80211_disconnect(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, hi_u16 us_reason_code);
hi_s32 wal_cfg80211_change_beacon(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev,
    oal_beacon_data_stru *beacon_info);
hi_s32 wal_cfg80211_start_ap(oal_wiphy_stru *wiphy, oal_net_device_stru *netdev, oal_ap_settings_stru *ap_settings);
#endif /* _PRE_OS_VERSION_LINUX == _PRE_OS_VERSION */
hi_u32  wal_cfg80211_start_scan(oal_net_device_stru *netdev, const mac_cfg80211_scan_param_stru *scan_param);
hi_u32  wal_cfg80211_start_sched_scan(oal_net_device_stru *netdev, mac_pno_scan_stru *pno_scan_info);
hi_u32 wal_cfg80211_start_req(oal_net_device_stru *netdev, const hi_void *ps_param, hi_u16 us_len,
    wlan_cfgid_enum_uint16 wid, hi_u8 need_rsp);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_u32  wal_cfg80211_start_connect(oal_net_device_stru *netdev,
    const mac_cfg80211_connect_param_stru *mac_cfg80211_connect_param);
hi_u32  wal_cfg80211_start_disconnect(oal_net_device_stru *netdev,
    const mac_cfg_kick_user_param_stru *disconnect_param);
int wal_get_vap_mode(hi_void);
int wal_get_bw_type(hi_void);
int wal_get_protocol_type(hi_void);
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_u32 wal_set_p2p_status(oal_net_device_stru *netdev, wlan_p2p_status_enum_uint32 status);
#endif
hi_u32 wal_del_p2p_group(const mac_device_stru *mac_dev);
hi_u32 wal_cfg80211_remain_on_channel(const oal_wiphy_stru *wiphy, const oal_wireless_dev *wdev,
    const struct ieee80211_channel *chan, hi_u32 duration, hi_u64 *pull_cookie);
hi_u32 wal_cfg80211_cancel_remain_on_channel(oal_wiphy_stru *wiphy, const oal_wireless_dev *wdev, hi_u64 ull_cookie);
#endif
#ifdef _PRE_WLAN_FEATURE_QUICK_START
hi_u32 hisi_quick_get_scan_enable(hi_void);
#endif
oal_ieee80211_channel *wal_get_g_wifi_2ghz_channels(hi_void);
hi_u32 wal_wifi_set_bw(oal_net_device_stru *netdev, wal_wifi_bw_enum_int bw);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wal_cfg80211.h */
