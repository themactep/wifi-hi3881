/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_encap_frame_ap.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_ENCAP_FRAME_AP_H__
#define __HMAC_ENCAP_FRAME_AP_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_vap.h"
#include "hmac_user.h"
#include "hmac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
typedef enum {
    /* ���ܷ�ʽΪopen */
    HMAC_AP_AUTH_SEQ1_OPEN_ANY = 0,
    /* ���ܷ�ʽΪwep,�����ش�֡ */
    HMAC_AP_AUTH_SEQ1_WEP_NOT_RESEND,
    /* ���ܷ�ʽΪwep,������ش�֡ */
    HMAC_AP_AUTH_SEQ1_WEP_RESEND,
    /* ���ܷ�ʽΪopen */
    HMAC_AP_AUTH_SEQ3_OPEN_ANY,
    /* ���ܷ�ʽΪWEP,assoc״̬Ϊauth comlete */
    HMAC_AP_AUTH_SEQ3_WEP_COMPLETE,
    /* ���ܷ�ʽΪWEP,assoc״̬Ϊassoc */
    HMAC_AP_AUTH_SEQ3_WEP_ASSOC,
    /* ʲôҲ���� */
    HMAC_AP_AUTH_DUMMY,

    HMAC_AP_AUTH_BUTT
} hmac_ap_auth_process_code_enum;
typedef hi_u8 hmac_ap_auth_process_code_enum_uint8;

/*****************************************************************************
  3 STRUCT����
*****************************************************************************/
typedef struct tag_hmac_auth_rsp_param_stru {
    /* �յ�auth request�Ƿ�Ϊ�ش�֡ */
    hi_u8 auth_resend;
    /* ��¼�Ƿ�Ϊwep */
    hi_u8 is_wep_allowed;
    /* ��¼��֤������ */
    hi_u16 us_auth_type;
    /* ��¼��������ǰ��user�Ĺ���״̬ */
    mac_user_asoc_state_enum_uint8 user_asoc_state;
    hi_u8 resv[3]; /* 3 �����ֽ� */
} hmac_auth_rsp_param_stru;

typedef hmac_ap_auth_process_code_enum_uint8(*hmac_auth_rsp_fun) (const hmac_auth_rsp_param_stru *pst_auth_rsp_param,
                                                                  hi_u8 *puc_code,
                                                                  mac_user_asoc_state_enum_uint8 *pst_usr_ass_stat);

typedef struct tag_hmac_auth_rsp_handle_stru {
    hmac_auth_rsp_param_stru auth_rsp_param;
    hmac_auth_rsp_fun auth_rsp_fun;
} hmac_auth_rsp_handle_stru;

typedef struct hmac_asoc_rsp_ap_info_stru {
    hi_u8 *puc_sta_addr;
    hi_u8 *puc_asoc_rsp;

    hi_u16 status_code;
    hi_u8 assoc_id;
    hi_u8 rsv0;

    hi_u16 us_type;
    hi_u16 us_resv1;
} hmac_asoc_rsp_ap_info_stru;

typedef struct {
    hi_u8 *mac_addr;
    hi_u8  addr_len;
    hi_u8  resv[3]; /* 3 byte�����ֶ� */
} hmac_mac_addr_stru;

/*****************************************************************************
  4 ��������
*****************************************************************************/
hi_u16 hmac_encap_auth_rsp(mac_vap_stru *mac_vap, oal_netbuf_stru *auth_rsp,
                           const oal_netbuf_stru *auth_req, hi_u8 *puc_chtxt, hi_u16 chtxt_len);

hi_u32 hmac_mgmt_encap_asoc_rsp_ap(mac_vap_stru *mac_ap,
                                   hmac_asoc_rsp_ap_info_stru *asoc_rsp_ap_info);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_u32 hmac_encap_mesh_peering_open_frame(mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                          const mac_action_data_stru *action_data);
hi_u32 hmac_encap_mesh_peering_confirm_frame(mac_vap_stru *mac_vap,
                                             hi_u8 *puc_data, const mac_action_data_stru *action_data);
hi_u32 hmac_encap_mesh_peering_close_frame(const mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                           const mac_action_data_stru *action_data);
hi_u32 hmac_encap_mesh_group_key_inform_frame(const mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                              const mac_action_data_stru *action_data);
hi_u32 hmac_encap_mesh_group_key_ack_frame(const mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                           const mac_action_data_stru *action_data);

#endif
#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_ENCAP_FRAME_AP_H__ */
