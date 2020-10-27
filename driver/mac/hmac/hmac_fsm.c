/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Global static state machine two-dimensional function table.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hmac_fsm.h"
#include "hmac_scan.h"
#include "hmac_mgmt_sta.h"
#include "hmac_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �ı�״̬��״̬
 �������  : pst_hmac_vap: HMAC VAP
             en_vap_state: Ҫ�л�����״̬
 �޸���ʷ      :
  1.��    ��   : 2013��6��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_fsm_change_state(hmac_vap_stru *hmac_vap, mac_vap_state_enum_uint8 vap_state)
{
    mac_cfg_mode_param_stru cfg_mode;
    mac_vap_state_enum_uint8 old_state;
    hi_u32 ret;
    old_state = hmac_vap->base_vap->vap_state;

    /* ��vap״̬�ı���Ϣ�ϱ� */
    mac_vap_state_change(hmac_vap->base_vap, vap_state);

    ret = hmac_config_vap_state_syn(hmac_vap->base_vap, sizeof(vap_state), (hi_u8 *)(&vap_state));
    if (ret != HI_SUCCESS) {
        oam_error_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_fsm_change_state::hmac_syn_vap_state failed[%d], old_state=%d, new_state=%d.}",
                       ret, old_state, vap_state);
    }
#ifdef _PRE_WLAN_FEATURE_STA_PM
    /*
     * sta startδ����, HMAC_SWITCH_STA_PSM_PERIOD��Ͷ����Ʊ
     * sta start�����ɹ�, HMAC_SWITCH_STA_PSM_PERIOD�������ܶ�ʱ��
     */
    if ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        ((vap_state == MAC_VAP_STATE_STA_FAKE_UP) || (vap_state == MAC_VAP_STATE_UP))) {
        if (hmac_vap->ps_sw_timer.is_registerd == HI_TRUE) {
            frw_timer_immediate_destroy_timer(&(hmac_vap->ps_sw_timer));
        }
        frw_timer_create_timer(&(hmac_vap->ps_sw_timer), hmac_set_psm_timeout, HMAC_SWITCH_STA_PSM_PERIOD,
                               (hi_void *)hmac_vap, HI_FALSE);
    }
#endif

    /* ����֡���˼Ĵ��� */
    hmac_set_rx_filter_value(hmac_vap->base_vap);

    if ((vap_state == MAC_VAP_STATE_STA_FAKE_UP) &&
        (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA)) {
        cfg_mode.protocol = hmac_vap->preset_para.protocol;
        cfg_mode.band = hmac_vap->preset_para.band;
        cfg_mode.en_bandwidth = hmac_vap->preset_para.en_bandwidth;

        hmac_config_sta_update_rates(hmac_vap->base_vap, &cfg_mode);
    }
}

/*****************************************************************************
 ��������  : ����STA״̬������ɨ������
 �������  : pst_hmac_vap: hmac vap
             pst_scan_params: ɨ���������
 �޸���ʷ      :
  1.��    ��   : 2019��6��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_fsm_handle_scan_req(const mac_vap_stru *mac_vap, mac_scan_req_stru *scan_params)
{
    hmac_vap_stru *hmac_vap = HI_NULL;

    /* ����ڵ��ô����пգ��������ʹ�õ�ָ���п� */
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_fsm_handle_scan_req::mac vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_fsm_handle_scan_req::hmac_vap is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->vap_state == MAC_VAP_STATE_PAUSE) {
        /* �л�vap��״̬ΪUP״̬ */
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_UP);
    }

    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_INIT:
        case MAC_VAP_STATE_STA_FAKE_UP:
        case MAC_VAP_STATE_STA_SCAN_COMP:
        case MAC_VAP_STATE_STA_JOIN_COMP:
        case MAC_VAP_STATE_STA_AUTH_COMP:
        case MAC_VAP_STATE_UP:
        case MAC_VAP_STATE_STA_LISTEN:
            return hmac_scan_proc_scan_req_event(hmac_vap, scan_params);

        default:
            return hmac_scan_proc_scan_req_event_exception(hmac_vap);
    }
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
