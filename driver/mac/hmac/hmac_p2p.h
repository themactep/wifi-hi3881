/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_p2p.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_P2P_H__
#define __HMAC_P2P_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "hmac_fsm.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/* p2p ״̬�� */
typedef enum {
    P2P_STATUS_DISCOVERY_ON = 0,
    P2P_STATUS_SEARCH_ENABLED,
    P2P_STATUS_IF_ADD,
    P2P_STATUS_IF_DEL,
    P2P_STATUS_IF_DELETING,
    P2P_STATUS_IF_CHANGING,
    P2P_STATUS_IF_CHANGED,
    P2P_STATUS_LISTEN_EXPIRED,
    P2P_STATUS_ACTION_TX_COMPLETED,
    P2P_STATUS_ACTION_TX_NOACK,
    P2P_STATUS_SCANNING,
    P2P_STATUS_GO_NEG_PHASE,
    P2P_STATUS_DISC_IN_PROGRESS
} wlan_p2p_status_enum;
typedef hi_u32 wlan_p2p_status_enum_uint32;

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
/* �ϱ�������ʱ���ݽṹ */
typedef struct {
    oal_ieee80211_channel_stru st_listen_channel;
    oal_wireless_dev *wdev;
    hi_u64 ull_cookie;
} hmac_p2p_listen_expired_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32 hmac_p2p_encap_action(hi_u8 *puc_data, const mac_action_data_stru *action_data);
hi_u32 hmac_p2p_check_vap_num(const mac_device_stru *mac_dev, wlan_p2p_mode_enum_uint8 p2p_mode);
hi_u32 hmac_p2p_send_listen_expired_to_host(const hmac_vap_stru *hmac_vap);
hi_u32 hmac_p2p_send_listen_expired_to_device(const hmac_vap_stru *hmac_vap);
hi_u32 hmac_p2p_add_gc_vap(mac_device_stru *mac_dev, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_del_gc_vap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_check_can_enter_state(const mac_vap_stru *mac_vap, hmac_fsm_input_type_enum_uint8 input_req);
hi_u32 hmac_p2p_get_home_channel(const mac_vap_stru *mac_vap, hi_u32 *pul_home_channel,
                                 wlan_channel_bandwidth_enum_uint8 *pen_home_channel_bandwidth);
hi_void hmac_p2p_disable_pm(const hmac_vap_stru *hmac_vap);
hi_u32 hmac_p2p_is_go_neg_req_frame(const hi_u8* puc_data);
hi_u32 hmac_p2p_get_status(hi_u32 p2p_status, wlan_p2p_status_enum_uint32 status);
hi_u32 hmac_p2p_set_status(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_void hmac_p2p_clr_status(hi_u32 *pul_p2p_status, wlan_p2p_status_enum_uint32 status);
hi_u32 hmac_p2p_remain_on_channel(const hmac_vap_stru *hmac_vap,
                                  mac_remain_on_channel_param_stru *remain_on_channel);
hi_u32 hmac_p2p_listen_timeout(mac_vap_stru *mac_vap);
hi_u32 hmac_p2p_send_action(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_set_ps_ops(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_set_ps_noa(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_find_listen_channel(mac_vap_stru *mac_vap, hi_u16 us_len, hi_u8 *puc_param);
hi_void hmac_p2p_del_ie(hi_u8 *puc_ie, hi_u32 *ie_len);
hi_u32 hmac_p2p_set_wps_p2p_ie(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_config_remain_on_channel(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_cancel_remain_on_channel(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_u32 hmac_p2p_sta_not_up_rx_mgmt(const hmac_vap_stru *hmac_vap, const dmac_wlan_crx_event_stru *crx_event);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_P2P_H__ */
