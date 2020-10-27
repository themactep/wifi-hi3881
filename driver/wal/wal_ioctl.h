/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_ioctl.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_IOCTL_H__
#define __WAL_IOCTL_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_ext_if.h"
#include "wal_main.h"
#include "wal_event_msg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/* IOCTL˽����������궨�� */
#define WAL_IOCTL_PRIV_SETPARAM          (OAL_SIOCIWFIRSTPRIV + 0)
#define WAL_IOCTL_PRIV_GETPARAM          (OAL_SIOCIWFIRSTPRIV + 1)
#define WAL_IOCTL_PRIV_SET_WMM_PARAM     (OAL_SIOCIWFIRSTPRIV + 3)
#define WAL_IOCTL_PRIV_GET_WMM_PARAM     (OAL_SIOCIWFIRSTPRIV + 5)
#define WAL_IOCTL_PRIV_SET_COUNTRY       (OAL_SIOCIWFIRSTPRIV + 8)
#define WAL_IOCTL_PRIV_GET_COUNTRY       (OAL_SIOCIWFIRSTPRIV + 9)
#define WAL_IOCTL_PRIV_GET_MODE     (OAL_SIOCIWFIRSTPRIV + 17)      /* ��ȡģʽ */
#define WAL_IOCTL_PRIV_SET_MODE     (OAL_SIOCIWFIRSTPRIV + 18)      /* ����ģʽ ����Э��,Ƶ��,���� */
#define WAL_IOCTL_PRIV_AP_GET_STA_LIST               (OAL_SIOCIWFIRSTPRIV + 21)
#define WAL_IOCTL_PRIV_AP_MAC_FLTR                     (OAL_SIOCIWFIRSTPRIV + 22)
/* netd��������������ΪGET��ʽ�·���get��ʽ������������set��ż�� */
#define WAL_IOCTL_PRIV_SET_AP_CFG                    (OAL_SIOCIWFIRSTPRIV + 23)
#define WAL_IOCTL_PRIV_AP_STA_DISASSOC                 (OAL_SIOCIWFIRSTPRIV + 24)
#endif
#define WAL_IOCTL_PRIV_SUBCMD_MAX_LEN          20

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
extern oal_ethtool_ops_stru g_wal_ethtool_ops;
#endif

/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
/* Э��ģʽ���ַ���ӳ�� */
typedef struct {
    hi_char                            *pc_name;        /* ģʽ���ַ��� */
    wlan_protocol_enum_uint8            mode;        /* Э��ģʽ */
    wlan_channel_band_enum_uint8        band;        /* Ƶ�� */
    wlan_channel_bandwidth_enum_uint8   en_bandwidth;   /* ���� */
    hi_u8                               auc_resv[1];
} wal_ioctl_mode_map_stru;

typedef struct wal_android_wifi_priv_cmd {
    hi_s32    l_total_len;
    hi_s32    l_used_len;
    hi_u8   *puc_buf;
} wal_android_wifi_priv_cmd_stru;

/* CFG VAP h2d */
typedef struct {
    oal_net_device_stru        *net_dev;
} mac_cfg_vap_h2d_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32 wal_alloc_cfg_event(oal_net_device_stru *netdev, frw_event_mem_stru **event_mem,
                           hi_void *resp_addr, wal_msg_stru **cfg_msg, hi_u16 us_len);
hi_u32 wal_send_cfg_event(oal_net_device_stru *netdev, wal_msg_type_enum_uint8 msg_type,
                          hi_u16 us_len, const hi_u8 *puc_param, hi_u8 need_rsp, wal_msg_stru **rsp_msg);

hi_u32 wal_start_vap(oal_net_device_stru *netdev);
hi_u32 wal_stop_vap(oal_net_device_stru *netdev);
hi_u32 wal_init_wlan_vap(oal_net_device_stru *netdev);
hi_u32 wal_deinit_wlan_vap(oal_net_device_stru *netdev);
hi_u32 wal_setup_vap(oal_net_device_stru *netdev);
hi_u32 wal_host_dev_init(const oal_net_device_stru *netdev);
#ifdef _PRE_WLAN_FEATURE_P2P
wlan_p2p_mode_enum_uint8 wal_wireless_iftype_to_mac_p2p_mode(nl80211_iftype_uint8 iftype);
#endif
hi_u32 wal_cfg_vap_h2d_event(oal_net_device_stru *netdev);
hi_u32 wal_recover_ini_main_gloabal(hi_void);
hi_u32 wal_host_dev_exit(const oal_net_device_stru *netdev);

hi_u32 wal_ioctl_set_freq(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_ioctl_set_mode(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_ioctl_set_essid(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_ioctl_set_txpower(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_get_cmd_one_arg(const hi_char *pc_cmd, hi_char *pc_arg, hi_u32 pc_arg_len, hi_u32 *pul_cmd_offset);
hi_u32 wal_set_mac_to_mib(oal_net_device_stru *netdev);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_u32 wal_android_priv_cmd(oal_net_device_stru *netdev, oal_ifreq_stru *ifr, hi_s32 cmd);
#endif
#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
hi_u32 wal_cfg80211_set_rekey_info(oal_net_device_stru *netdev, mac_rekey_offload_stru *rekey_offload);
#endif
hi_u32 wal_macaddr_check(const hi_u8 *mac_addr);
#ifdef _PRE_WLAN_FEATURE_P2P
hi_u32 wal_ioctl_set_p2p_noa(oal_net_device_stru *netdev, const mac_cfg_p2p_noa_param_stru *p2p_noa_param);
hi_u32 wal_ioctl_set_p2p_ops(oal_net_device_stru *netdev, const mac_cfg_p2p_ops_param_stru *p2p_ops_param);
hi_u32 wal_ioctl_set_wps_p2p_ie(oal_net_device_stru *netdev, const hi_u8 *puc_buf, hi_u32 len,
                                en_app_ie_type_uint8 type);
#endif
#if (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
oal_iw_handler_def_stru *wal_get_g_iw_handler_def(hi_void);
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wal_ioctl.h */

