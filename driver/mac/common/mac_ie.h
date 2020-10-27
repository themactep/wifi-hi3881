/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_ie.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_IE_H__
#define __MAC_IE_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_frame.h"
#include "wlan_mib.h"
#include "wlan_types.h"
#include "mac_user.h"
#include "mac_vap.h"

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
/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 inline��������
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
/*****************************************************************************
 ��������  : �ж�֡�����Ƿ�Ϊ(��)��������/��Ӧ
 �������  : uc_mgmt_frm_type: ֡����
 �� �� ֵ  : ��HI_TRUE/��HI_FALSE
 �޸���ʷ      :
  1.��    ��   : 2014��7��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u32 mac_check_is_assoc_frame(hi_u8 mgmt_frm_type)
{
    if ((mgmt_frm_type == WLAN_FC0_SUBTYPE_ASSOC_RSP) ||
        (mgmt_frm_type == WLAN_FC0_SUBTYPE_REASSOC_REQ) ||
        (mgmt_frm_type == WLAN_FC0_SUBTYPE_REASSOC_RSP) ||
        (mgmt_frm_type == WLAN_FC0_SUBTYPE_ASSOC_REQ)) {
        return HI_TRUE;
    }
    return HI_FALSE;
}
#endif

/*****************************************************************************
  11 ��������
*****************************************************************************/
mac_sec_ch_off_enum_uint8 mac_get_sco_from_bandwidth(wlan_channel_bandwidth_enum_uint8 bandwidth);

wlan_channel_bandwidth_enum_uint8 mac_get_bandwith_from_center_freq_seg0(hi_u8 channel, hi_u8 chan_center_freq);

hi_void mac_ie_get_vht_rx_mcs_map(mac_rx_max_mcs_map_stru *mac_rx_mcs_sta,
                                  mac_rx_max_mcs_map_stru *mac_rx_mcs_ap);

wlan_mib_mimo_power_save_enum_uint8 mac_ie_proc_sm_power_save_field(hi_u8 smps);
hi_u8 mac_ie_proc_ht_green_field(const mac_user_stru *mac_user_sta, mac_vap_stru *mac_vap,
                                 hi_u8 ht_green_field, hi_bool prev_asoc_ht);
hi_u8 mac_ie_proc_ht_supported_channel_width(const mac_user_stru *mac_user_sta, mac_vap_stru *mac_vap,
                                             hi_u8 supported_channel_width, hi_bool prev_asoc_ht);
hi_u8 mac_ie_proc_lsig_txop_protection_support(const mac_user_stru *mac_user_sta, mac_vap_stru *mac_vap,
                                               hi_u8 lsig_txop_protection_support, hi_bool prev_asoc_ht);
hi_u8 mac_ie_get_chan_num(hi_u8 *puc_frame_body, hi_u16 us_frame_len, hi_u16 us_offset, hi_u8 curr_chan);
hi_u32 mac_set_second_channel_offset_ie(wlan_channel_bandwidth_enum_uint8 bw, hi_u8 *pauc_buffer,
                                        hi_u8  *puc_output_len);
hi_u8 mac_ie_check_p2p_action(const hi_u8 *puc_payload);
hi_u32  mac_config_set_mib(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_void mac_ie_proc_ht_sta(const mac_vap_stru *mac_vap,  const hi_u8 *puc_payload, const hi_u16 *pus_index,
                           mac_user_stru *mac_user_ap, hi_u16 *pus_ht_cap_info, hi_u16 *pus_amsdu_max);
hi_u32 mac_proc_ht_opern_ie(mac_vap_stru *mac_vap, const hi_u8 *puc_payload, mac_user_stru *mac_user);
hi_void  mac_ie_txbf_set_ht_hdl(mac_user_ht_hdl_stru *ht_hdl, hi_u32 info_elem);
wlan_channel_bandwidth_enum_uint8 mac_get_bandwidth_from_sco(mac_sec_ch_off_enum_uint8 sec_chan_offset);


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __MAC_IE_H__ */
