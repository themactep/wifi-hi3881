/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: P2P related feature processing
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_util.h"
#include "hmac_ext_if.h"
#include "hmac_device.h"
#include "hmac_vap.h"
#include "hmac_rx_filter.h"
#include "hmac_fsm.h"
#include "hmac_mgmt_bss_comm.h"
#include "mac_frame.h"
#include "hmac_p2p.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ��̬��������
*****************************************************************************/
/*****************************************************************************
  3 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  4 ����ʵ��
*****************************************************************************/
typedef struct mac_vap_state_priority {
    hi_u8 priority;
} mac_vap_state_priority_stru;

typedef struct hmac_input_req_priority {
    hi_u8 priority;
} hmac_input_req_priority_stru;

mac_vap_state_priority_stru g_mac_vap_state_priority_table[MAC_VAP_STATE_BUTT] = {
    {0},    /* MAC_VAP_STATE_INIT */
    {2},    /* MAC_VAP_STATE_UP, VAP UP */
    {0},    /* MAC_VAP_STATE_PAUSE, pause , for ap &sta */
    {0},    /* MAC_VAP_STATE_AP_PAUSE, ap����״̬ */
    {0},    /* MAC_VAP_STATE_STA_FAKE_UP, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_WAIT_SCAN, sta����״̬ */
    {0},    /* MAC_VAP_STATE_STA_SCAN_COMP, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_JOIN_COMP, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_AUTH_COMP, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_WAIT_ASOC, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_OBSS_SCAN, sta����״̬ */
    {10},    /* MAC_VAP_STATE_STA_BG_SCAN, sta����״̬ */
    {0},    /* MAC_VAP_STATE_STA_LISTEN, p2p0 ����, sta����״̬ */
};

hmac_input_req_priority_stru g_mac_fsm_input_type_priority_table[HMAC_FSM_INPUT_TYPE_BUTT] = {
    {0},    /* HMAC_FSM_INPUT_RX_MGMT */
    {0},    /* HMAC_FSM_INPUT_RX_DATA */
    {0},    /* HMAC_FSM_INPUT_TX_DATA */
    {0},    /* HMAC_FSM_INPUT_TIMER0_OUT */
    {0},    /* HMAC_FSM_INPUT_MISC */
    {0},    /* HMAC_FSM_INPUT_START_REQ */
    {5},    /* HMAC_FSM_INPUT_SCAN_REQ */
    {5},    /* HMAC_FSM_INPUT_JOIN_REQ */
    {5},    /* HMAC_FSM_INPUT_AUTH_REQ */
    {5},    /* HMAC_FSM_INPUT_ASOC_REQ */
    {5},    /* HMAC_FSM_INPUT_LISTEN_REQ, P2P ���� */
    {0}     /* HMAC_FSM_INPUT_LISTEN_TIMEOUT, P2P ������ʱ */
};

/*****************************************************************************
 �� �� ��  : hmac_p2p_check_can_enter_state
 ��������  : ����ⲿ�����¼��Ƿ�����ִ��
 �������  : [1]mac_vap
             [2]input_req
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_check_can_enter_state(const mac_vap_stru *mac_vap, hmac_fsm_input_type_enum_uint8 input_req)
{
    mac_device_stru         *mac_dev = HI_NULL;
    mac_vap_stru            *other_vap = HI_NULL;
    hi_u8                    vap_num;
    hi_u8                    vap_idx;

    /*  �������vap ״̬���ж������¼����ȼ��Ƿ��vap ״̬���ȼ���
     *  ��������¼����ȼ��ߣ������ִ�������¼�
     */
    mac_dev = mac_res_get_dev();
    vap_num = mac_dev->vap_num;

    for (vap_idx = 0; vap_idx < vap_num; vap_idx++) {
        other_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (other_vap == HI_NULL) {
            oam_warning_log1(0, OAM_SF_CFG,
                             "{hmac_p2p_check_can_enter_state::hmac_vap_get_vap_stru fail.vap_idx = %u}",
                mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        if (other_vap->vap_id == mac_vap->vap_id) {
            /* �����⵽���Լ���������������VAP ״̬ */
            continue;
        }
        if (g_mac_vap_state_priority_table[other_vap->vap_state].priority >
            g_mac_fsm_input_type_priority_table[input_req].priority) {
            return HI_ERR_CODE_CONFIG_BUSY;
        }
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_get_home_channel
 ��������  : �����Ѿ�UP ��vap ���ŵ�
 �������  : [1]mac_vap
             [2]pul_home_channel
             [3]pen_home_channel_type
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_get_home_channel(const mac_vap_stru *mac_vap, hi_u32 *pul_home_channel,
                                 wlan_channel_bandwidth_enum_uint8 *pen_home_channel_bandwidth)
{
    mac_device_stru                    *mac_dev = HI_NULL;
    hi_u8                               vap_idx;
    hi_u32                              home_channel = 0;
    hi_u32                              last_home_channel = 0;
    wlan_channel_bandwidth_enum_uint8   home_channel_bandwidth = WLAN_BAND_WIDTH_20M;
    wlan_channel_bandwidth_enum_uint8   last_home_channel_bandwidth = WLAN_BAND_WIDTH_20M;

    if (mac_vap == HI_NULL) {
        oam_warning_log0(0, OAM_SF_CFG, "{hmac_p2p_get_home_channel::mac_vap is NULL.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ʼ�� */
    mac_dev = mac_res_get_dev();
    *pul_home_channel = 0;
    *pen_home_channel_bandwidth = WLAN_BAND_WIDTH_20M;

    /* ��ȡhome �ŵ� */
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            oam_warning_log1(0, OAM_SF_CFG,
                             "{hmac_p2p_get_home_channel::hmac_vap_get_vap_stru fail.vap_idx = %u}", vap_idx);
            continue;
        }

        if (mac_vap->vap_state == MAC_VAP_STATE_UP) {
            home_channel = mac_vap->channel.chan_number;
            home_channel_bandwidth = mac_vap->channel.en_bandwidth;
            if (last_home_channel == 0) {
                last_home_channel = home_channel;
                last_home_channel_bandwidth = home_channel_bandwidth;
            } else if (last_home_channel != home_channel ||
                last_home_channel_bandwidth != home_channel_bandwidth) {
                /* Ŀǰ�ݲ�֧�ֲ�ͬ�ŵ���listen */
                oam_warning_log4(mac_vap->vap_id, OAM_SF_CFG,
                    "{hmac_p2p_get_home_channel::home_channel[%d], last_home_channel[%d],home bw[%d], last bw[%d].}",
                    home_channel, last_home_channel,
                    home_channel_bandwidth, last_home_channel_bandwidth);
                return HI_FAIL;
            }
        }
    }

    *pul_home_channel = home_channel;
    *pen_home_channel_bandwidth = home_channel_bandwidth;

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_check_vap_num
 ��������  : ���vapʱ���P2P vap��num�Ƿ����Ҫ��
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��11��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_p2p_check_vap_num(const mac_device_stru *mac_dev, wlan_p2p_mode_enum_uint8 p2p_mode)
{
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u8 vap_idx;

    /* ʣ����Դ�Ƿ��㹻����һ��P2P_DEV */
    if (mac_dev->sta_num > WLAN_STA_NUM_PER_DEVICE) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{hmac_p2p_check_vap_num::can't create p2p vap, because sta num [%d] is more than 2.}",
            mac_dev->sta_num);
        return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
    }

    if (mac_dev->p2p_info.p2p_goclient_num >= WLAN_MAX_SERVICE_P2P_GOCLIENT_NUM) {
        oam_warning_log0(0, OAM_SF_CFG,
            "{hmac_p2p_check_vap_num::can't create p2p vap, because at least 1 GO/GC exist.}");
        return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
    }

    if (p2p_mode == WLAN_P2P_CL_MODE) {
        /* ��ǰҪ��������GC������֧�ִ��� */
        return HI_ERR_SUCCESS;
    }

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap != HI_NULL && (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP
#ifdef _PRE_WLAN_FEATURE_MESH
            || mac_vap->vap_mode == WLAN_VAP_MODE_MESH
#endif
            )) {
            /* ����AP���� */
            oam_warning_log0(0, OAM_SF_CFG, "{hmac_p2p_check_vap_num::can't create GO, because ap is exist.}");
            return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
        }
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����P2P CL MAC��ַ��HAL��
 �޸���ʷ      :
   1.��    ��   : 2019��9��6��
    ��    ��   : Hisilicon
     �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_p2p_set_gc_mac_addr(mac_device_stru *mac_dev, const hmac_vap_stru *hmac_vap,
                                const mac_cfg_add_vap_param_stru *param)
{
    mac_cfg_staion_id_param_stru station_id_param;
    hi_u32                       ret;
    hi_u8                        vap_id;

    vap_id = mac_dev->p2p_info.p2p0_vap_idx;

    /* ����mac��ַ */
    if (memcpy_s(station_id_param.auc_station_id, WLAN_MAC_ADDR_LEN,
        param->net_dev->dev_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        /* �˴�����������Ҫ��Ӧmac_device_set_vap_id�������˲��� */
        mac_device_set_vap_id(mac_dev, hmac_vap->base_vap, param, vap_id, HI_FALSE);

        /* �쳣�����ͷ��ڴ� */
        oal_mem_free(hmac_vap->base_vap->mib_info);

        mac_vap_free_vap_res(vap_id);
        oam_error_log0(0, OAM_SF_CFG, "{hmac_p2p_set_gc_mac_addr::mem safe function err!}");
        return HI_FAIL;
    }
    station_id_param.p2p_mode = param->p2p_mode;

    ret = hmac_config_set_mac_addr(hmac_vap->base_vap, sizeof(mac_cfg_staion_id_param_stru),
                                   (hi_u8 *)(&station_id_param));
    if (ret != HI_SUCCESS) {
        /* �˴�����������Ҫ��Ӧmac_device_set_vap_id�������˲��� */
        mac_device_set_vap_id(mac_dev, hmac_vap->base_vap, param, vap_id, HI_FALSE);

        /* �쳣�����ͷ��ڴ� */
        oal_mem_free(hmac_vap->base_vap->mib_info);

        mac_vap_free_vap_res(vap_id);
        oam_error_log1(0, OAM_SF_CFG, "{hmac_p2p_set_gc_mac_addr::hmac_config_set_mac_addr failed[%d].}", ret);
        return ret;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_add_gc_vap
 ��������  : ����P2P CL ҵ��VAP
 �������  : vap   : ָ������vap
             us_len    : ��������
             puc_param : ����
 �������  : ��
 �� �� ֵ  : HI_SUCCESS ������������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
   1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
     �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_p2p_add_gc_vap(mac_device_stru *mac_dev, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru                 *hmac_vap = HI_NULL;
    hi_u32                         ret;
    hi_u8                          vap_id;
    wlan_p2p_mode_enum_uint8       p2p_mode;
    mac_cfg_add_vap_param_stru    *param = HI_NULL;

    /* VAP�����ж� */
    param = (mac_cfg_add_vap_param_stru *)puc_param;
    p2p_mode = param->p2p_mode;
    ret = hmac_p2p_check_vap_num(mac_dev, p2p_mode);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_p2p_add_gc_vap::check_vap_num failed[%d].}", ret);
        return ret;
    }

    /* P2P CL ��P2P0 ����һ��VAP �ṹ������P2P CL ʱ����Ҫ����VAP ��Դ����Ҫ����p2p0 ��vap �ṹ */
    vap_id = mac_dev->p2p_info.p2p0_vap_idx;
    hmac_vap = hmac_vap_get_vap_stru(vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_p2p_add_gc_vap::hmac_vap_get_vap_stru failed.vap_id:[%d].}", vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    param->vap_id = vap_id;
    hmac_vap->net_device = param->net_dev;

    /* �����뵽��mac_vap�ռ�ҵ�net_device privָ����ȥ */
    oal_net_dev_priv(param->net_dev) = hmac_vap->base_vap;
    param->muti_user_id = hmac_vap->base_vap->multi_user_idx;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(hmac_vap->base_vap, WLAN_CFGID_ADD_VAP, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        /* �쳣�����ͷ��ڴ� */
        oam_error_log1(0, OAM_SF_CFG, "{hmac_p2p_add_gc_vap::hmac_config_alloc_event failed[%d].}", ret);
        return ret;
    }

    if (param->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        /* ��ʼ��uc_assoc_vap_idΪ���ֵ����apδ���� */
        mac_vap_set_assoc_id(hmac_vap->base_vap, 0xff);
    }
    mac_vap_set_p2p_mode(hmac_vap->base_vap, param->p2p_mode);
    mac_inc_p2p_num(hmac_vap->base_vap);

    /* ����֡���� */
    hmac_set_rx_filter_value(hmac_vap->base_vap);

    ret = hmac_p2p_set_gc_mac_addr(mac_dev, hmac_vap, param);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_p2p_add_gc_vap::hmac_p2p_set_gc_mac_addr failed [%d].}", ret);
        return ret;
    }

    oam_info_log3(0, OAM_SF_P2P, "{hmac_p2p_add_gc_vap::func out.vap_mode[%d], p2p_mode[%d}, vap_id[%d]",
                  param->vap_mode, param->p2p_mode, param->vap_id);
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_del_gc_vap
 ��������  : ɾ��p2p cl vap
 �������  : vap   : ָ��vap��ָ��
             us_len    : ��������
             puc_param : ����
 �������  : ��
 �� �� ֵ  : HI_SUCCESS ������������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_p2p_del_gc_vap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru                 *hmac_vap = HI_NULL;
    hi_u32                         ret;
    mac_device_stru               *mac_dev = HI_NULL;
    hi_u8                          vap_id;
    mac_cfg_del_vap_param_stru    *del_vap_param = HI_NULL;

    hi_unref_param(mac_vap);

    if (oal_unlikely((mac_vap == HI_NULL) || (puc_param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_del_vap::param null, vap=%p puc_param=%p.}",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    del_vap_param = (mac_cfg_del_vap_param_stru *)puc_param;
    mac_dev = mac_res_get_dev();
    /* �����ɾ��P2P CL ������Ҫ�ͷ�VAP ��Դ */
    vap_id = mac_dev->p2p_info.p2p0_vap_idx;
    hmac_vap = hmac_vap_get_vap_stru(vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_del_vap::hmac_vap_get_vap_stru fail.vap_id[%d]}", vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }
    /* p2p���������У���ʼ��Ϊclģʽ���л���GOģʽʱ��Ҫͣ��vap����ΪNULL */
    oal_net_dev_priv(hmac_vap->net_device) = HI_NULL;
    hmac_vap->net_device = hmac_vap->p2p0_net_device;
    mac_dec_p2p_num(hmac_vap->base_vap);
    mac_vap_set_p2p_mode(hmac_vap->base_vap, WLAN_P2P_DEV_MODE);
    if (memcpy_s(hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_p2p0_dot11_station_id,
        WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_p2p_del_gc_vap:: auc_p2p0_dot11StationID memcpy_s fail.");
        return HI_FAIL;
    }

    if (hmac_vap->puc_asoc_req_ie_buff != HI_NULL) {
        oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
        hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
    }

    /***************************************************************************
                          ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DEL_VAP, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_p2p_del_gc_vap::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    oam_info_log2(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_del_gc_vap::func out.vap_mode[%d], p2p_mode[%d]}",
        del_vap_param->vap_mode, del_vap_param->p2p_mode);
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_send_listen_expired_to_host
 ��������  : ������ʱ����,֪ͨWAL ������ʱ
 �������  : mac_device_stru *mac_device
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��11��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_p2p_send_listen_expired_to_host(const hmac_vap_stru *hmac_vap)
{
    mac_device_stru                 *mac_dev = HI_NULL;
    oal_wireless_dev                *wdev = HI_NULL;
    mac_p2p_info_stru               *p2p_info = HI_NULL;
    hmac_p2p_listen_expired_stru     p2p_listen_expired = {0};

    mac_dev = mac_res_get_dev();
    p2p_info = &mac_dev->p2p_info;

    /* ��д�ϱ�������ʱ, �ϱ��������豸Ӧ�ò���p2p0 */
    if (hmac_vap->p2p0_net_device != HI_NULL &&
        hmac_vap->p2p0_net_device->ieee80211_ptr != HI_NULL) {
        wdev = hmac_vap->p2p0_net_device->ieee80211_ptr;
    } else {
        wdev = hmac_vap->net_device->ieee80211_ptr;
    }
    p2p_listen_expired.st_listen_channel = p2p_info->st_listen_channel;
    p2p_listen_expired.wdev = wdev;

    return hmac_send_event_to_host(hmac_vap->base_vap, (const hi_u8*)(&p2p_listen_expired),
        sizeof(hmac_p2p_listen_expired_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_LISTEN_EXPIRED);
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_send_listen_expired_to_device
 ��������  : ������ʱ����֪ͨDMAC ����home �ŵ�
 �������  : [1]hmac_vap
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_send_listen_expired_to_device(const hmac_vap_stru *hmac_vap)
{
    mac_device_stru                 *mac_dev = HI_NULL;
    mac_vap_stru                    *mac_vap = HI_NULL;
    mac_p2p_info_stru               *p2p_info = HI_NULL;
    hi_u32                           ret;
    hmac_device_stru                *hmac_dev = HI_NULL;

    mac_dev = mac_res_get_dev();
    /***************************************************************************
     ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    p2p_info = &mac_dev->p2p_info;
    mac_vap = hmac_vap->base_vap;
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CFG80211_CANCEL_REMAIN_ON_CHANNEL,
                                 sizeof(mac_p2p_info_stru), (hi_u8 *)p2p_info);

    /* ǿ��stop listen */
    hmac_dev = hmac_get_device_stru();
    hmac_dev->scan_mgmt.is_scanning = HI_FALSE;

    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P,
            "{hmac_p2p_send_listen_expired_to_device::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_disable_pm
 ��������  : ֹͣp2p noa,p2p oppps
 �������  : [1]hmac_vap
 �������  : ��
 �� �� ֵ  : ��
*****************************************************************************/
hi_void hmac_p2p_disable_pm(const hmac_vap_stru *hmac_vap)
{
    mac_vap_stru                   *mac_vap = HI_NULL;
    mac_cfg_p2p_ops_param_stru      p2p_ops;
    mac_cfg_p2p_noa_param_stru      p2p_noa;
    hi_u32                          ret;

    mac_vap = hmac_vap->base_vap;

    if (memset_s(&p2p_noa, sizeof(p2p_noa), 0, sizeof(p2p_noa)) != EOK) {
        return;
    }
    ret = hmac_p2p_set_ps_noa(mac_vap, sizeof(mac_cfg_p2p_noa_param_stru), (hi_u8 *)&p2p_noa);
    if (ret != HI_SUCCESS) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_P2P,
            "{hmac_p2p_disable_pm::hmac_p2p_set_ps_noa disable p2p NoA fail.}");
    }
    if (memset_s(&p2p_ops, sizeof(p2p_ops), 0, sizeof(p2p_ops)) != EOK) {
        return;
    }
    ret = hmac_p2p_set_ps_ops(mac_vap, sizeof(mac_cfg_p2p_ops_param_stru), (hi_u8 *)&p2p_ops);
    if (ret != HI_SUCCESS) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_P2P,
            "{hmac_p2p_disable_pm::hmac_p2p_set_ps_ops disable p2p OppPS fail.}");
    }
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_is_go_neg_req_frame
 ��������  : �Ƿ���P2P GO negotiation request action֡
 �������  : [1]puc_data
 �������  : ��
 �� �� ֵ  : HI_TRUE ��P2P GO negotiation request action֡
*****************************************************************************/
hi_u32 hmac_p2p_is_go_neg_req_frame(const hi_u8* puc_data)
{
    if ((puc_data[MAC_ACTION_OFFSET_CATEGORY + MAC_80211_FRAME_LEN] == MAC_ACTION_CATEGORY_PUBLIC) &&
        (puc_data[P2P_PUB_ACT_OUI_OFF1 + MAC_80211_FRAME_LEN] == WFA_OUI_BYTE1) &&
        (puc_data[P2P_PUB_ACT_OUI_OFF2 + MAC_80211_FRAME_LEN] == WFA_OUI_BYTE2) &&
        (puc_data[P2P_PUB_ACT_OUI_OFF3 + MAC_80211_FRAME_LEN] == WFA_OUI_BYTE3) &&
        (puc_data[P2P_PUB_ACT_OUI_TYPE_OFF + MAC_80211_FRAME_LEN] == WFA_P2P_V1_0) &&
        (puc_data[P2P_PUB_ACT_OUI_SUBTYPE_OFF + MAC_80211_FRAME_LEN] == P2P_PAF_GON_REQ)) {
        return HI_TRUE;
    } else {
        return HI_FALSE;
    }
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_get_status
 ��������  : �ж�p2p �Ƿ�Ϊ��״̬
 �������  : hi_u32 ul_p2p_status
             wlan_p2p_status_enum_uint32 en_status
 �������  : ��
 �� �� ֵ  : hi_u8
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��5��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_p2p_get_status(hi_u32 p2p_status, wlan_p2p_status_enum_uint32 status)
{
    if (p2p_status & bit(status)) {
        return HI_TRUE;
    } else {
        return HI_FALSE;
    }
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_set_status
 ��������  : ����p2p Ϊ��Ӧ״̬
 �������  : hi_u32 ul_p2p_status
             wlan_p2p_status_enum_uint32 en_status
 �������  : ��
 �� �� ֵ  : hi_u8
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��5��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_p2p_set_status(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    wlan_p2p_status_enum_uint32          *status = HI_NULL;
    hmac_device_stru                     *hmac_dev = HI_NULL;

    hi_unref_param(us_len);
    hi_unref_param(mac_vap);
    hmac_dev = hmac_get_device_stru();
    status = (wlan_p2p_status_enum_uint32 *)puc_param;

    hmac_dev->p2p_intf_status |= ((hi_u32)bit(*status));

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_p2p_clr_status
 ��������  : ���p2p ��Ӧ״̬
 �������  : hi_u32 ul_p2p_status
             wlan_p2p_status_enum_uint32 en_status
 �������  : ��
 �� �� ֵ  : hi_u8
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��5��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void hmac_p2p_clr_status(hi_u32 *pul_p2p_status, wlan_p2p_status_enum_uint32 status)
{
    *pul_p2p_status &= ~((hi_u32)bit(status));
}

/*****************************************************************************
 ��������  : ��װp2p action֡
 �������  : mac_vap: MAC VAP
             pst_mgmt_buf: buffer��ʼ��ַ
             pst_peer_param: �ϲ�������Ϣ
             us_len: ����
 �� �� ֵ  : ��װ���֡�ܳ���

 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_p2p_encap_action(hi_u8 *puc_data, const mac_action_data_stru *action_data)
{
    hi_u8 *puc_frame_origin = HI_NULL;
    hi_u32 us_frame_len;

    /* ������ʼ��ַ�����ڼ��㳤�� */
    puc_frame_origin = puc_data;

    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���� Frame Control field */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_ACTION);

    /* ���� DA address1: Զ�˽ڵ�MAC��ַ */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_dst, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_p2p_encap_action::memcpy_s fail.}");
        return 0;
    }
    /* ���� SA address2: dot11MACAddress */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_src, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_p2p_encap_action::memcpy_s fail.}");
        return 0;
    }
    /* ���� DA address3::BSSID */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_p2p_encap_action::memcpy_s fail.}");
        return 0;
    }
    puc_data += MAC_80211_FRAME_LEN;

    /* ���payload��Ϣ */
    if (action_data->data_len > 0) {
        if (memcpy_s(puc_data, action_data->data_len,
                     action_data->puc_data, action_data->data_len) != EOK) {
            oam_error_log0(0, 0, "{hmac_p2p_encap_action::memcpy_s fail.}");
            return 0;
        }
        puc_data += action_data->data_len;
    }
    us_frame_len = (hi_u32)(puc_data - puc_frame_origin);

    return us_frame_len;
}

/*****************************************************************************
 ��������  : 1102 ����WPS/P2P ��ϢԪ��
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_set_wps_p2p_ie(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    oal_app_ie_stru *wps_p2p_ie = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u32 ret;

    hi_unref_param(us_len);
    wps_p2p_ie = (oal_app_ie_stru *)puc_param;

    /* ����WPS/P2P ��Ϣ */
    ret = hmac_config_set_app_ie_to_vap(mac_vap, wps_p2p_ie, wps_p2p_ie->app_ie_type);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_p2p_set_wps_p2p_ie::hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���beacon ��Ϣ���Ƿ���WPS ��ϢԪ�� */
    if (wps_p2p_ie->app_ie_type == OAL_APP_BEACON_IE) {
        if (wps_p2p_ie->ie_len != 0 &&
            mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WPS,
                wps_p2p_ie->auc_ie, (hi_s32)(wps_p2p_ie->ie_len)) != HI_NULL) {
            /* ����WPS ����ʹ�� */
            hmac_vap->wps_active = HI_TRUE;
            oam_info_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_p2p_set_wps_p2p_ie::set wps enable.}");
        } else {
            hmac_vap->wps_active = HI_FALSE;
        }
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����P2P attribute��ϢԪ��
 �������  : [1]eid
             [2]puc_ies
             [3]l_len
 �� �� ֵ  : hi_u8 *
*****************************************************************************/
static hi_u8 *hmac_p2p_find_attribute(hi_u8 eid, hi_u8 *puc_ies, hi_s32 l_len)
{
    hi_s32 ie_len = 0;

    /* ����P2P IE���������ֱ������һ�� */
    while (l_len > MAC_P2P_ATTRIBUTE_HDR_LEN && puc_ies[0] != eid) {
        ie_len = (hi_s32)((puc_ies[2] << 8) + puc_ies[1]); /* 2:�±꣬8:����8λ��1:�±� */
        l_len -= ie_len + MAC_P2P_ATTRIBUTE_HDR_LEN;
        puc_ies += ie_len + MAC_P2P_ATTRIBUTE_HDR_LEN;
    }
    /* ���ҵ�P2P IE��ʣ�೤�Ȳ�ƥ��ֱ�ӷ��ؿ�ָ�� */
    ie_len = (hi_s32)((puc_ies[2] << 8) + puc_ies[1]); /* 1:�±꣬2:�±꣬8:����λ�ƶ�8λ */
    if ((l_len < MAC_P2P_ATTRIBUTE_HDR_LEN) || (l_len < (MAC_P2P_ATTRIBUTE_HDR_LEN + ie_len))) {
        return HI_NULL;
    }

    return puc_ies;
}

/*****************************************************************************
 ��������  : ����wpa_supplicant �·���IE �е�P2P IE�е�listen channel
 �������  : hi_u8 *puc_param   wpa_supplicant �·���ie
             hi_u16 us_len      wpa_supplicant �·���ie ����
 �޸���ʷ      :
  1.��    ��   : 2015��9��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_p2p_find_listen_channel(mac_vap_stru *mac_vap, hi_u16 us_len, hi_u8 *puc_param)
{
    hi_u8 *puc_p2p_ie = HI_NULL;
    hi_u8 *puc_listen_channel_ie = HI_NULL;

    /* ����P2P IE��Ϣ */
    puc_p2p_ie = mac_find_vendor_ie(MAC_WLAN_OUI_WFA, MAC_WLAN_OUI_TYPE_WFA_P2P, puc_param, (hi_s32) us_len);
    if (puc_p2p_ie == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_p2p_find_listen_channel::p2p ie is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����У�� */
    if (puc_p2p_ie[1] < MAC_P2P_MIN_IE_LEN) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_p2p_find_listen_channel::invalid p2p ie len[%d].}", puc_p2p_ie[1]);
        return HI_FAIL;
    }

    /* ����P2P Listen channel��Ϣ */
    puc_listen_channel_ie = hmac_p2p_find_attribute(MAC_P2P_ATTRIBUTE_LISTEN_CHAN,
                                                    puc_p2p_ie + 6, (puc_p2p_ie[1] - 4)); /* 1:�±꣬4:��4��6:��6 */
    if (puc_listen_channel_ie == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_p2p_find_listen_channel::p2p listen channel ie is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* listen channel����У�飬��� 1:�±꣬2:�±꣬8:����λ��8λ */
    if ((hi_s32)((puc_listen_channel_ie[2] << 8) + puc_listen_channel_ie[1]) != MAC_P2P_LISTEN_CHN_ATTR_LEN) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_p2p_find_listen_channel::invalid p2p listen channel ie len[%d].}",
                         /* 1:�±꣬2:�±꣬8:����λ��8λ */
                         (hi_s32) ((puc_listen_channel_ie[2] << 8) + puc_listen_channel_ie[1]));
        return HI_FAIL;
    }

    /* ��ȡP2P Listen channel��Ϣ */
    mac_vap->p2p_listen_channel = puc_listen_channel_ie[7]; /* 7:�±� */
    oam_info_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_p2p_find_listen_channel::END CHANNEL[%d].}",
                  mac_vap->p2p_listen_channel);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ɾ��wpa_supplicant �·���IE �е�P2P IE
 �������  : hi_u8 *puc_ie       wpa_supplicant �·���ie
             hi_u32 *ie_len  wpa_supplicant �·���ie ����
 �޸���ʷ      :
  1.��    ��   : 2015��8��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_p2p_del_ie(hi_u8 *puc_ie, hi_u32 *ie_len)
{
    hi_u8 *puc_p2p_ie = HI_NULL;
    hi_u32 p2p_ie_len;
    hi_u8 *puc_ie_end = HI_NULL;
    hi_u8 *puc_p2p_ie_end = HI_NULL;

    if ((puc_ie == HI_NULL) || (ie_len == HI_NULL) || (*ie_len == 0)) {
        return;
    }

    puc_p2p_ie = mac_find_vendor_ie(MAC_WLAN_OUI_WFA, MAC_WLAN_OUI_TYPE_WFA_P2P, puc_ie, (hi_s32) (*ie_len));
    if ((puc_p2p_ie == HI_NULL) || (puc_p2p_ie[1] < MAC_P2P_MIN_IE_LEN)) {
        return;
    }

    p2p_ie_len = puc_p2p_ie[1] + MAC_IE_HDR_LEN;

    /* ��p2p ie ��������ݿ�����p2p ie ����λ�� */
    puc_ie_end = (puc_ie + *ie_len);
    puc_p2p_ie_end = (puc_p2p_ie + p2p_ie_len);

    if (puc_ie_end >= puc_p2p_ie_end) {
        if (memmove_s(puc_p2p_ie, (hi_u32)(puc_ie_end - puc_p2p_ie_end),
            puc_p2p_ie_end, (hi_u32)(puc_ie_end - puc_p2p_ie_end)) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "{hmac_p2p_del_ie::memmove_s failed.}");
            return;
        }
        *ie_len -= p2p_ie_len;
    }
    return;
}

/****************************************************************************
 ��������  : HMAC����p2p����״̬�¼���wal
 �޸���ʷ      :
  1.��    ��   : 2019��8��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_p2p_tx_status_event(const mac_vap_stru *mac_vap, const hi_u8 *puc_buf, hi_u32 len, hi_u8 ack)
{
    mac_p2p_tx_status_stru       p2p_tx_status = {0};
    hi_u32                       ret;

    p2p_tx_status.puc_buf = malloc(len);
    if (p2p_tx_status.puc_buf == HI_NULL) {
        oam_unrom_e_log1(0, OAM_SF_P2P, "{hmac_p2p_action_tx_status_event::p2p_tx_status->puc_buf malloc error %p.}",
            (uintptr_t)p2p_tx_status.puc_buf);
        return HI_FALSE;
    }
    if (memcpy_s(p2p_tx_status.puc_buf, len, puc_buf, len) != EOK) {
        oam_unrom_e_log0(0, OAM_SF_P2P, "{hmac_p2p_action_tx_status_event::mem safe function err!}");
        free(p2p_tx_status.puc_buf);
        return HI_FALSE;
    }
    p2p_tx_status.len = len;
    p2p_tx_status.ack = ack;

    ret = hmac_send_event_to_host(mac_vap, (const hi_u8*)(&p2p_tx_status),
        sizeof(mac_p2p_tx_status_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_P2P_TX_STATUS);
    if (ret != HI_SUCCESS) {
        oam_unrom_w_log1(mac_vap->vap_id, OAM_SF_P2P,
            "{hmac_p2p_action_tx_status_event::frw_event_dispatch_event fail [%d].}", ret);
        free(p2p_tx_status.puc_buf);
    }
    return ret;
}

static inline hi_u32 hmac_p2p_send_action_error(const mac_action_data_stru *action_data, oal_netbuf_stru *puc_data)
{
    /* �ͷ��ϲ������puc_data�ռ� */
    if (action_data->data_len > 0) {
        oal_free(action_data->puc_data);
    }
    if (puc_data != HI_NULL) {
        oal_netbuf_free(puc_data);
    }
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : P2P ����Action ֡
 �޸���ʷ      :
  1.��    ��   : 2019��4��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_p2p_send_action(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(us_len);
    if (hmac_vap_get_vap_stru(mac_vap->vap_id) == HI_NULL) {
        oam_warning_log0(0, OAM_SF_P2P, "{hmac_p2p_send_action::hmac_vap null.}");
        return hmac_p2p_send_action_error((mac_action_data_stru *)puc_param, HI_NULL);
    }

    mac_action_data_stru *action_data = (mac_action_data_stru *)puc_param;
    hi_u8                 action_code = mac_get_action_code(action_data->puc_data); /* ��ȡAction category��code */
    oal_netbuf_stru      *puc_data    = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4); /* align 4 */
    if (puc_data == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_send_action::[MESH]puc_data null.}");
        return hmac_p2p_send_action_error(action_data, HI_NULL);
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(oal_netbuf_cb(puc_data), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    if (memset_s((hi_u8 *)oal_netbuf_header(puc_data), MAC_80211_FRAME_LEN, 0, MAC_80211_FRAME_LEN) != EOK) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_send_action::[MESH]memset_s ERR.}");
        return hmac_p2p_send_action_error(action_data, puc_data);
    }

    if (action_code != MAC_PUB_VENDOR_SPECIFIC) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_send_action::P2P:self-protected Err:%d}", action_code);
        return hmac_p2p_send_action_error(action_data, puc_data);
    }

    hi_u32 action_len = hmac_p2p_encap_action((hi_u8 *)(oal_netbuf_header(puc_data)), action_data);
    if (action_len == 0) { /* ��֡ʧ�� */
        return hmac_p2p_send_action_error(action_data, puc_data);
    }

    oal_netbuf_put(puc_data, action_len);

    /* Ϊ��д����������׼������ */
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(puc_data);
    tx_ctl->us_mpdu_len         = action_len;    /* dmac������Ҫ��mpdu���� */
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header        = (mac_ieee80211_frame_stru *)oal_netbuf_header(puc_data);
    tx_ctl->mac_head_type       = 1;

    /* ���¼���dmac����֡���� */
    hi_u32 ret = hmac_tx_mgmt_send_event(mac_vap, puc_data, action_len);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_send_action::P2P:hmac_tx_mgmt_send_event Err%d}", ret);

        ret = hmac_p2p_tx_status_event(mac_vap, (hi_u8 *)(oal_netbuf_header(puc_data)), action_len, HI_FALSE);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_send_action:hmac_p2p_action_tx_status_event=%d}", ret);

        return hmac_p2p_send_action_error(action_data, puc_data);
    }

    if (hmac_p2p_tx_status_event(mac_vap, (hi_u8*)(oal_netbuf_header(puc_data)), action_len, HI_TRUE) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_send_action:hmac_p2p_action_tx_status_event ERR}");
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_netbuf_free(puc_data);
#endif
    /* �ͷ��ϲ������puc_data�ռ� */
    if (action_data->data_len > 0) {
        oal_free(action_data->puc_data);
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����P2P OPS ����
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_set_ps_ops(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_P2P_PS_OPS, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_p2p_set_ps_ops::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����P2P NOA ����
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_set_ps_noa(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    mac_cfg_p2p_noa_param_stru *p2p_noa = HI_NULL;

    p2p_noa = (mac_cfg_p2p_noa_param_stru *)puc_param;

    /* ms to us */
    p2p_noa->start_time *= 1000; /* 1000:ʱ�� */
    p2p_noa->duration *= 1000; /* 1000:ʱ�� */
    p2p_noa->interval *= 1000; /* 1000:ʱ�� */
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_P2P_PS_NOA, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_p2p_set_ps_noa::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : P2P ������ʱ������
 �������  : *p_arg
 �޸���ʷ      :
  1.��    ��   : 2015��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_p2p_listen_comp_cb(hi_void *arg)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_device_stru *mac_dev = HI_NULL;
    hmac_scan_record_stru *scan_record = HI_NULL;

    scan_record = (hmac_scan_record_stru *)arg;

    /* �ж�listen���ʱ��״̬ */
    if (scan_record->scan_rsp_status != MAC_SCAN_SUCCESS) {
        oam_warning_log1(0, OAM_SF_P2P, "{hmac_p2p_listen_comp_cb::listen failed, listen rsp status: %d.}",
                         scan_record->scan_rsp_status);
    }

    hmac_vap = hmac_vap_get_vap_stru(scan_record->vap_id);
    if ((hmac_vap == HI_NULL) || (hmac_vap->base_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_P2P, "{hmac_p2p_listen_comp_cb::hmac_vap is null:vap_id %d.}",
                       scan_record->vap_id);
        return;
    }

    mac_dev = mac_res_get_dev();
    /* DTS2015100902074�����wifi �������ϱ������������⡣
       �˴��ϱ�ull_cookie����1����Ϊ����remain_on_channel�·�ʱ�̱���+1 */
    if (scan_record->ull_cookie == mac_dev->p2p_info.ull_last_roc_id) {
        if (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_STA_LISTEN) {
            hmac_p2p_listen_timeout(hmac_vap->base_vap);
        }
    } else {
        oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_P2P,
            "{hmac_p2p_listen_comp_cb::ignore listen complete.scan_report_cookie[%x]," \
            "current_listen_cookie[%x], ull_last_roc_id[%x].}",
            scan_record->ull_cookie,
            mac_dev->scan_params.ull_cookie, mac_dev->p2p_info.ull_last_roc_id);
    }

    return;
}


/*****************************************************************************
 ��������  : ׼��p2p��������Ķ�Ӧ����
 �������  : mac_scan_req_stru *scan_params,        ɨ�����
             hi_s8 *puc_param,                       p2p��������
 �޸���ʷ      :
  1.��    ��   : 2015��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_p2p_prepare_listen_req_param(mac_scan_req_stru *scan_params, hi_s8 *puc_param)
{
    mac_remain_on_channel_param_stru *remain_on_channel = HI_NULL;
    mac_channel_stru *channel_tmp = HI_NULL;

    remain_on_channel = (mac_remain_on_channel_param_stru *)puc_param;

    if (memset_s(scan_params, sizeof(mac_scan_req_stru), 0, sizeof(mac_scan_req_stru)) != EOK) {
        return;
    }

    /* ���ü����ŵ���Ϣ��ɨ������� */
    scan_params->ast_channel_list[0].band = remain_on_channel->band;
    scan_params->ast_channel_list[0].en_bandwidth = remain_on_channel->listen_channel_type;
    scan_params->ast_channel_list[0].chan_number = remain_on_channel->uc_listen_channel;
    scan_params->ast_channel_list[0].idx = 0;
    channel_tmp = &(scan_params->ast_channel_list[0]);
    if (mac_get_channel_idx_from_num(channel_tmp->band, channel_tmp->chan_number,
                                     &(channel_tmp->idx)) != HI_SUCCESS) {
        oam_warning_log2(0, OAM_SF_P2P,
            "{hmac_p2p_prepare_listen_req_param::mac_get_channel_idx_from_num fail.band[%u] channel[%u]}",
            channel_tmp->band, channel_tmp->chan_number);
    }

    /* ���������������� */
    scan_params->max_scan_cnt_per_channel = 1;
    scan_params->channel_nums = 1;
    scan_params->scan_func = MAC_SCAN_FUNC_P2P_LISTEN;
    scan_params->us_scan_time = (hi_u16) remain_on_channel->listen_duration;
    scan_params->fn_cb = hmac_p2p_listen_comp_cb;
    scan_params->ull_cookie = remain_on_channel->ull_cookie;

    return;
}

/*****************************************************************************
 ��������  : ����device ��ָ���ŵ������������ü�����ʱ��ʱ��
             ����Ǵ�up ״̬����listen ���򷵻�up
             ����Ǵ�scan complete ״̬���룬�򷵻�scan complete
 �������  : [1]hmac_vap_sta
             [2]remain_on_channel
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_remain_on_channel(const hmac_vap_stru *hmac_vap,
                                  mac_remain_on_channel_param_stru *remain_on_channel)
{
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    mac_scan_req_stru scan_params;

    mac_vap = mac_vap_get_vap_stru(hmac_vap->base_vap->vap_id);
    if (mac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_P2P, "{hmac_p2p_remain_on_channel::mac_vap_get_vap_stru fail.vap_id[%u]!}",
                       hmac_vap->base_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_dev = mac_res_get_dev();
    /* DTS2015022500760 ����P2P ������ʱ��ʱ��,
       P2P����Listen״̬���޷��·������������Listen״̬�²������³����������޷��������豸���� */
    if (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_STA_LISTEN) {
        if (hmac_p2p_send_listen_expired_to_host(hmac_vap) != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_P2P, "hmac_p2p_send_listen_expired_to_host return NON SUCCESS. ");
        }

        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P,
            "{hmac_p2p_remain_on_channel::listen nested, send remain on channel expired to host!curr_state[%d]\r\n}",
            hmac_vap->base_vap->vap_state);
    }

    /* �޸�P2P_DEVICE ״̬Ϊ����״̬, DTS2015060904250 P2P����״̬�뱳��ɨ��ʱDMAC��pause״̬��ͻ��
     * P2P_LISTEN״̬��ͬ����DMACȥ��DMAC����ʹ��P2P_LISTEN״̬
     */
    mac_vap_state_change(hmac_vap->base_vap, MAC_VAP_STATE_STA_LISTEN);
    hmac_set_rx_filter_value(hmac_vap->base_vap);

    oam_info_log4(mac_vap->vap_id, OAM_SF_P2P,
        "{hmac_p2p_remain_on_channel::get in listen state!last_state %d, channel %d, duration %d, curr_state %d}\r\n",
        mac_dev->p2p_info.last_vap_state,
        remain_on_channel->uc_listen_channel,
        remain_on_channel->listen_duration, hmac_vap->base_vap->vap_state);

    /* ׼���������� */
    hmac_p2p_prepare_listen_req_param(&scan_params, (hi_s8 *)remain_on_channel);

    /* ����ɨ����ڣ�׼�����м������������ܼ�������ִ�гɹ���ʧ�ܣ������ؼ����ɹ� */
    return hmac_fsm_handle_scan_req(hmac_vap->base_vap, &scan_params);
}

/*****************************************************************************
 ��������  : P2P_DEVICE ������ʱ
 �������  : hmac_vap_stru *hmac_vap_sta
             hi_void *p_param
 �޸���ʷ      :
  1.��    ��   : 2014��11��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_p2p_listen_timeout(mac_vap_stru *mac_vap)
{
    mac_device_stru *mac_dev = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_P2P, "{hmac_p2p_listen_timeout::hmac_vap_get_vap_stru fail.vap_id[%u]!}",
                       mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_dev = mac_res_get_dev();
    oam_info_log2(hmac_vap->base_vap->vap_id, OAM_SF_P2P,
                  "{hmac_p2p_listen_timeout::current mac_vap channel is [%d] state[%d]}",
                  mac_vap->channel.chan_number, hmac_vap->base_vap->vap_state);

    oam_info_log2(hmac_vap->base_vap->vap_id, OAM_SF_P2P,
                  "{hmac_p2p_listen_timeout::next mac_vap channel is [%d] state[%d]}",
                  mac_vap->channel.chan_number, mac_dev->p2p_info.last_vap_state);

    /* ����P2P0 ��P2P_CL ����vap �ṹ�壬������ʱ�����ؼ���ǰ�����״̬ */
    /* DTS2015060904250 p2p listenͬ��vap״̬�뱳��ɨ���ͻ����ͬ����dmac */
    mac_vap_state_change(mac_vap, mac_dev->p2p_info.last_vap_state);
    hmac_set_rx_filter_value(mac_vap);

    /* 3.1 ���¼���WAL ���ϱ��������� */
    if (hmac_p2p_send_listen_expired_to_host(hmac_vap) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_P2P, "hmac_p2p_send_listen_expired_to_host return NON SUCCESS. ");
    }

    /* 3.2 ���¼���DMAC �����ؼ����ŵ� */
    if (hmac_p2p_send_listen_expired_to_device(hmac_vap) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_P2P, "hmac_p2p_send_listen_expired_to_device return NON SUCCESS. ");
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : P2P_DEVICE �ڼ���״̬���յ�����֡����HS2.0��ѯ���̵�ACTION�ϱ�(ԭ������Ϊhmac_p2p_listen_rx_mgmt)
 �������  : [1]hmac_vap_sta,
             [2]crx_event
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_sta_not_up_rx_mgmt(const hmac_vap_stru *hmac_vap, const dmac_wlan_crx_event_stru *crx_event)
{
    mac_vap_stru *mac_vap = HI_NULL;
    hmac_rx_ctl_stru *rx_info = HI_NULL;
    hi_u8 *puc_mac_hdr = HI_NULL;
    hi_u8 mgmt_frm_type;

    mac_vap = hmac_vap->base_vap;
    rx_info = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)crx_event->netbuf);
    puc_mac_hdr = (hi_u8 *)(rx_info->pul_mac_hdr_start_addr);
    if (puc_mac_hdr == HI_NULL) {
        oam_error_log3(rx_info->mac_vap_id, OAM_SF_RX,
            "{hmac_p2p_sta_not_up_rx_mgmt::puc_mac_hdr null, vap_id %d,us_frame_len %d, uc_mac_header_len %d}",
            rx_info->vap_id, rx_info->us_frame_len, rx_info->mac_header_len);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* STA��NOT UP״̬�½��յ����ֹ���֡���� */
    mgmt_frm_type = mac_get_frame_sub_type(puc_mac_hdr);
    switch (mgmt_frm_type) {
        /* �жϽ��յ��Ĺ���֡���� */
        case WLAN_FC0_SUBTYPE_PROBE_REQ:
            /* �ж�ΪP2P�豸,���ϱ�probe req֡��wpa_supplicant */
            if (!is_legacy_vap(mac_vap)) {
                hmac_rx_mgmt_send_to_host(hmac_vap, (oal_netbuf_stru *)crx_event->netbuf);
            }
            break;
        case WLAN_FC0_SUBTYPE_ACTION:
            /* �����Action ֡����ֱ���ϱ�wpa_supplicant */
            hmac_rx_mgmt_send_to_host(hmac_vap, (oal_netbuf_stru *)crx_event->netbuf);
            break;
        default:
            break;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ������ָ���ŵ�
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_config_remain_on_channel(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(us_len);

    /* 1.1 �ж���� */
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_P2P,
            "{hmac_p2p_config_remain_on_channel::mac_vap=%p,puc_param=%p}", (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* add by l00456108 */
#ifdef _PRE_WLAN_FEATURE_WAPI
    if (HI_TRUE == hmac_user_is_wapi_connected()) {
        oam_warning_log0(0, OAM_SF_P2P, "{stop p2p remaining under wapi!}");
        return HI_ERR_CODE_CONFIG_UNSUPPORT;
    }
#endif

    /* 1.2 ����Ƿ��ܽ������״̬ */
    mac_remain_on_channel_param_stru *remain_on_channel = (mac_remain_on_channel_param_stru *)puc_param;
    mac_device_stru                  *mac_dev = mac_res_get_dev();
    hi_u32                            ret = hmac_p2p_check_can_enter_state(mac_vap, HMAC_FSM_INPUT_LISTEN_REQ);
    if (ret != HI_SUCCESS) {
        /* ���ܽ������״̬�������豸æ */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_config_remain_on_channel::device busy ret=%d}", ret);
        return HI_ERR_CODE_CONFIG_BUSY;
    }

    /* 1.3 ��ȡhome �ŵ����ŵ����͡�����������ŵ�Ϊ0����ʾû���豸����up ״̬����������Ҫ�������ŵ� */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_P2P,
                       "{hmac_p2p_config_remain_on_channel::hmac_vap_get_vap_stru null.vap_id = %d}", mac_vap->vap_id);
        return HI_FAIL;
    }

    /* �����ں��·��ļ����ŵ���Ϣ�����ڼ�����ʱ��ȡ������ʱ���� */
    mac_dev->p2p_info.st_listen_channel = remain_on_channel->st_listen_channel;

    /* ����p2p0�� p2p cl ����һ��VAP �ṹ�����ڽ������ʱ����Ҫ����֮ǰ��״̬�����ڼ�������ʱ���� */
    if (mac_vap->vap_state != MAC_VAP_STATE_STA_LISTEN) {
        mac_dev->p2p_info.last_vap_state = mac_vap->vap_state;
    }
    remain_on_channel->last_vap_state = mac_dev->p2p_info.last_vap_state;

    oam_info_log3(mac_vap->vap_id, OAM_SF_P2P,
                  "{hmac_p2p_config_remain_on_channel::listen_channel=%d, current_channel=%d, last_state=%d}\r\n",
                  remain_on_channel->uc_listen_channel, mac_vap->channel.chan_number, mac_dev->p2p_info.last_vap_state);

    /* 3.1 �޸�VAP ״̬Ϊ���� */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_P2P, "{hmac_p2p_config_remain_on_channel fail!hmac_vap is null}\r\n");
        return HI_FAIL;
    }

    /* ״̬������:  hmac_p2p_config_remain_on_channel */
    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_STA_FAKE_UP:
        case MAC_VAP_STATE_STA_SCAN_COMP:
        case MAC_VAP_STATE_STA_LISTEN:
        case MAC_VAP_STATE_UP:
            return hmac_p2p_remain_on_channel(hmac_vap, remain_on_channel);
        default :
            return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : ֹͣ������ָ���ŵ�
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_p2p_cancel_remain_on_channel(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;

    hi_unref_param(us_len);
    hi_unref_param(puc_param);

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P,
                         "hmac_p2p_cancel_remain_on_channel::hmac_vap_get_vap_stru fail.vap_id = %u",
                         mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->vap_state == MAC_VAP_STATE_STA_LISTEN) {
        hmac_p2p_listen_timeout(mac_vap);
    } else {
        if (hmac_p2p_send_listen_expired_to_host(hmac_vap) != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_P2P, "hmac_p2p_send_listen_expired_to_host return NON SUCCESS. ");
        }
    }
    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
