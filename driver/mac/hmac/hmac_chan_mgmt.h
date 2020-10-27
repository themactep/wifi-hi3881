/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_chan_mgmt.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_CHAN_MGMT_H__
#define __HMAC_CHAN_MGMT_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "hmac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    MAC_CHNL_AV_CHK_NOT_REQ = 0,        /* ����Ҫ�����ŵ�ɨ�� */
    MAC_CHNL_AV_CHK_IN_PROG = 1,        /* ���ڽ����ŵ�ɨ�� */
    MAC_CHNL_AV_CHK_COMPLETE = 2,       /* �ŵ�ɨ������� */

    MAC_CHNL_AV_CHK_BUTT,
} mac_chnl_av_chk_enum;
typedef hi_u8 mac_chnl_av_chk_enum_uint8;

/*****************************************************************************
  4 STRUCT����
*****************************************************************************/
typedef struct {
    hi_u16 us_freq;         /* �ŵ�Ƶ�� */
    hi_u8 idx;           /* �ŵ������� */
    hi_u8 auc_resv;
} hmac_dfs_channel_info_stru;

typedef struct {
    hi_u16 us_freq;         /* ����Ƶ�ʣ���λMHz */
    hi_u8 number;        /* �ŵ��� */
    hi_u8 idx;           /* �ŵ�����(�����) */
} mac_freq_channel_map_stru;

/*****************************************************************************
  5 ��������
*****************************************************************************/
hi_void hmac_chan_disable_machw_tx(const mac_vap_stru *mac_vap);
hi_void hmac_chan_multi_select_channel_mac(mac_vap_stru *mac_vap, hi_u8 channel,
                                           wlan_channel_bandwidth_enum_uint8 bandwidth);
mac_chnl_av_chk_enum_uint8 hmac_chan_do_channel_availability_check(mac_device_stru *mac_dev,
                                                                   mac_vap_stru *mac_vap,
                                                                   hi_u8 first_time);
hi_u32 hmac_start_bss_in_available_channel(hmac_vap_stru *hmac_vap);

hi_u32 hmac_chan_restart_network_after_switch(const mac_vap_stru *mac_vap);
hi_void hmac_chan_multi_switch_to_new_channel(const mac_vap_stru *mac_vap, hi_u8 channel,
                                              wlan_channel_bandwidth_enum_uint8 bandwidth);
hi_void hmac_dfs_set_channel(mac_vap_stru *mac_vap, hi_u8 channel);

hi_u32 hmac_ie_proc_ch_switch_ie(mac_vap_stru *mac_vap, const hi_u8 *puc_payload,
                                 mac_eid_enum_uint8 eid_type);
hi_u32 hmac_chan_switch_to_new_chan_complete(frw_event_mem_stru *event_mem);
hi_void hmac_chan_sync(mac_vap_stru *mac_vap,
                       hi_u8 channel, wlan_channel_bandwidth_enum_uint8 bandwidth,
                       hi_u8 switch_immediately);
hi_u32 hmac_dbac_status_notify(frw_event_mem_stru *event_mem);
hi_u32 hmac_chan_start_bss(hmac_vap_stru *hmac_vap);
hi_void hmac_channel_switch_report_event(const hmac_vap_stru *hmac_vap, hi_s32 l_freq);
mac_freq_channel_map_stru get_ast_freq_map_2g_elem(hi_u32 index);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* end of hmac_chan_mgmt.h */
