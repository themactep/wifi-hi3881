/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_wpa_ioctl.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */
#ifndef __WAL_WPA_IOCTL_H__
#define __WAL_WPA_IOCTL_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifndef HAVE_PCLINT_CHECK
#include "hi_wifi_driver_wpa_if.h"
#endif
#endif
#include "oam_ext_if.h"
#include "wal_main.h"
#include "oal_net.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* Driver supports AP mode */
#define HISI_DRIVER_FLAGS_AP                         0x00000040
/* Driver supports concurrent P2P operations */
#define HISI_DRIVER_FLAGS_P2P_CONCURRENT             0x00000200
/*
 * Driver uses the initial interface as a
 * dedicated management interface, i.e., it cannot
 * be used for P2P group operations or non-P2P purposes.
 */
#define HISI_DRIVER_FLAGS_P2P_DEDICATED_INTERFACE    0x00000400
/* P2P capable (P2P GO or P2P Client) */
#define HISI_DRIVER_FLAGS_P2P_CAPABLE                0x00000800
/* Driver supports a dedicated interface for P2P Device */
#define HISI_DRIVER_FLAGS_DEDICATED_P2P_DEVICE       0x20000000

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    HISI_CHAN_DISABLED      = 1<<0,
    HISI_CHAN_PASSIVE_SCAN  = 1<<1,
    HISI_CHAN_NO_IBSS       = 1<<2,
    HISI_CHAN_RADAR         = 1<<3,
    HISI_CHAN_NO_HT40PLUS   = 1<<4,
    HISI_CHAN_NO_HT40MINUS  = 1<<5,
    HISI_CHAN_NO_OFDM       = 1<<6,
    HISI_CHAN_NO_80MHZ      = 1<<7,
    HISI_CHAN_NO_160MHZ     = 1<<8,
}hisi_channel_flags_enum;
typedef hi_u8 hisi_channel_flags_enum_uint8;
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
typedef hi_s32 (*hwal_ioctl_handler)(hi_char *puc_ifname, hi_void *p_buf);

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 hwal_ioctl_set_power(hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_del_virtual_intf(hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_ip_notify(const hi_char *puc_ifname, const hi_void *buf);
hi_s32 hwal_ioctl_set_max_sta(hi_char *puc_ifname, hi_void *max_sta_num);
hi_s32 hwal_ioctl_stop_ap(hi_char *puc_ifname, hi_void *buf);
#endif
hi_s32 hwal_ioctl_set_pm_switch(const hi_char *puc_ifname, const hi_void *buf);
hi_s32 hwal_ioctl_set_key(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_new_key(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_del_key(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_ap(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_change_beacon(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_send_mlme(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_send_eapol(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_mode(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_receive_eapol(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_enable_eapol(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_disable_eapol(const hi_char *puc_ifname, const hi_void *buf);
hi_s32 hwal_ioctl_get_addr(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_get_hw_feature(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hisi_hwal_wpa_ioctl(hi_char *pc_ifname, hisi_ioctl_command_stru *cmd);
hi_s32 hwal_ioctl_scan(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_disconnect(const hi_char *puc_ifname, const hi_void *buf);
hi_s32 hwal_ioctl_assoc(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_netdev(const hi_char *puc_ifname, const hi_void *buf);
hi_u8 hwal_is_valid_ie_attr(const hi_u8 *puc_ie, hi_u32 ie_len);
hi_s32 hwal_ioctl_sta_remove(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_send_action(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_delay_report(const hi_char *puc_ifname, hi_void *buf);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_s32 hwal_ioctl_set_mesh_user(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_enable_auto_peer(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_mesh_gtk(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_accept_peer(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_accept_sta(const hi_char *puc_ifname, hi_void *buf);
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
hi_s32 hwal_ioctl_add_if(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_remove_if(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_probe_req_report(const hi_char *puc_ifname, const hi_void *buf);
hi_s32 hwal_ioctl_remain_on_channel(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_cancel_remain_on_channel(const hi_char *puc_ifname, const hi_void *buf);
hi_s32 hwal_ioctl_set_ap_wps_p2p_ie(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_p2p_noa(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_set_p2p_powersave(const hi_char *puc_ifname, hi_void *buf);
hi_s32 hwal_ioctl_get_p2p_addr(const hi_char *puc_ifname, hi_void *buf);
#endif
hi_s32 hwal_ioctl_get_drv_flags(const hi_char *puc_ifname, hi_void *buf);

#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
hi_s32 hwal_ioctl_set_rekey_info(const hi_char *puc_ifname, hi_void *buf);
#endif
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of wal_wpa_ioctl.h */

