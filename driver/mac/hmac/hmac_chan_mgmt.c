/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hmac_chan_mgmt.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_regdomain.h"
#include "mac_device.h"
#include "hmac_mgmt_sta.h"
#include "hmac_sme_sta.h"
#include "hmac_fsm.h"
#include "hmac_chan_mgmt.h"
#include "hcc_hmac_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/* 2.4GƵ�� �ŵ�������Ƶ��ӳ�� */
const mac_freq_channel_map_stru g_ast_freq_map_2g[MAC_CHANNEL_FREQ_2_BUTT] = {
    {2412, 1, 0},
    {2417, 2, 1},
    {2422, 3, 2},
    {2427, 4, 3},
    {2432, 5, 4},
    {2437, 6, 5},
    {2442, 7, 6},
    {2447, 8, 7},
    {2452, 9, 8},
    {2457, 10, 9},
    {2462, 11, 10},
    {2467, 12, 11},
    {2472, 13, 12},
    {2484, 14, 13},
};

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
mac_freq_channel_map_stru get_ast_freq_map_2g_elem(hi_u32 index)
{
    return g_ast_freq_map_2g[index];
}

/*****************************************************************************
 ��������  : ����VAP�ŵ�������׼���л������ŵ�����
 �������  : pst_mac_vap : MAC VAP�ṹ��ָ��
             uc_channel  : ���ŵ���(׼���л�����20MHz���ŵ���)
             en_bandwidth: �´���ģʽ
 �޸���ʷ      :
  1.��    ��   : 2014��2��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_chan_initiate_switch_to_new_channel(mac_vap_stru *mac_vap, hi_u8 channel,
                                                        wlan_channel_bandwidth_enum_uint8 bandwidth)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u32 ret;
    dmac_set_ch_switch_info_stru *ch_switch_info = HI_NULL;

    /* AP׼���л��ŵ� */
    mac_vap->ch_switch_info.ch_switch_status = WLAN_CH_SWITCH_STATUS_1;
    mac_vap->ch_switch_info.announced_channel = channel;
    mac_vap->ch_switch_info.announced_bandwidth = bandwidth;

    /* ��Beacon֡�����Channel Switch Announcement IE */
    mac_vap->ch_switch_info.csa_present_in_bcn = HI_TRUE;

    oam_info_log2(mac_vap->vap_id, OAM_SF_2040,
                  "{hmac_chan_initiate_switch_to_new_channel::uc_announced_channel=%d,en_announced_bandwidth=%d}",
                  channel, bandwidth);

    /* �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(dmac_set_ch_switch_info_stru));
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_SCAN,
                       "{hmac_chan_initiate_switch_to_new_channel::event_mem null.}");
        return;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_SWITCH_TO_NEW_CHAN,
                       sizeof(dmac_set_ch_switch_info_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       mac_vap->vap_id);

    /* ��д�¼�payload */
    ch_switch_info = (dmac_set_ch_switch_info_stru *)event->auc_event_data;
    ch_switch_info->ch_switch_status = WLAN_CH_SWITCH_STATUS_1;
    ch_switch_info->announced_channel = channel;
    ch_switch_info->announced_bandwidth = bandwidth;
    ch_switch_info->ch_switch_cnt = mac_vap->ch_switch_info.ch_switch_cnt;
    ch_switch_info->csa_present_in_bcn = HI_TRUE;

    /* �ַ��¼� */
    ret = hcc_hmac_tx_control_event(event_mem, sizeof(dmac_set_ch_switch_info_stru));
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_SCAN,
                       "{hmac_chan_initiate_switch_to_new_channel::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);
        return;
    }

    /* �ͷ��¼� */
    frw_event_free(event_mem);
}

/*****************************************************************************
 ��������  : ����device������ap������VAP�ŵ�������׼���л������ŵ�����
 �������  : pst_mac_vap : MAC VAP�ṹ��ָ��
             uc_channel  : ���ŵ���(׼���л�����20MHz���ŵ���)
             en_bandwidth: �´���ģʽ
 �޸���ʷ      :
  1.��    ��   : 2014��4��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_chan_multi_switch_to_new_channel(const mac_vap_stru *mac_vap, hi_u8 channel,
                                              wlan_channel_bandwidth_enum_uint8 bandwidth)
{
    hi_u8 vap_idx;
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru *ap = HI_NULL;

    if (mac_vap != HI_NULL) {
        oam_info_log2(mac_vap->vap_id, OAM_SF_2040,
                      "{hmac_chan_multi_switch_to_new_channel::uc_channel=%d,en_bandwidth=%d}", channel, bandwidth);
    }

    mac_dev = mac_res_get_dev();
    if (mac_dev->vap_num == 0) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_SCAN, "{hmac_chan_multi_switch_to_new_channel::none vap.}");
        return;
    }

    /* ����device������ap������ap�ŵ�������׼���л������ŵ����� */
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        ap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (ap == HI_NULL) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_SCAN, "{hmac_chan_multi_switch_to_new_channel::pst_ap null.}",
                           mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        /* ֻ����AP����ŵ��л���Ϣ */
        if (ap->vap_mode != WLAN_VAP_MODE_BSS_AP) {
            continue;
        }

        hmac_chan_initiate_switch_to_new_channel(ap, channel, bandwidth);
    }
}

hi_void hmac_chan_sync_init(const mac_vap_stru *mac_vap, dmac_set_chan_stru *set_chan)
{
    if (memset_s(set_chan, sizeof(dmac_set_chan_stru), 0, sizeof(dmac_set_chan_stru)) != EOK) {
        return;
    }
    if (memcpy_s(&set_chan->channel, sizeof(mac_channel_stru), &mac_vap->channel,
                 sizeof(mac_channel_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_chan_sync_init::hmac_chan_sync_init memcpy_s fail.");
        return;
    }
    if (memcpy_s(&set_chan->ch_switch_info, sizeof(mac_ch_switch_info_stru), &mac_vap->ch_switch_info,
                 sizeof(mac_ch_switch_info_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_chan_sync_init::hmac_chan_sync_init memcpy_s fail.");
        return;
    }
}

/*****************************************************************************
 ��������  : HMACģ�����¼���DMACģ�飬����SW/MAC/PHY/RF�е��ŵ��ʹ���
             ʹVAP���������ŵ���
 �޸���ʷ      :
  1.��    ��   : 2014��2��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_chan_do_sync(mac_vap_stru *mac_vap, dmac_set_chan_stru *set_chan)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u32 ret;
    hi_u8 idx;

    if (mac_vap == HI_NULL || set_chan == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_chan_do_sync::pst_mac_vap[%p] or pst_set_chan[%p] null!}",
            (uintptr_t)mac_vap, (uintptr_t)set_chan);
        return;
    }

    /* ����VAP�µ���20MHz�ŵ��š�����ģʽ���ŵ����� */
    ret = mac_get_channel_idx_from_num(mac_vap->channel.band, set_chan->channel.chan_number, &idx);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY,
                         "{hmac_chan_sync::mac_get_channel_idx_from_num failed[%d].}", ret);
        return;
    }

    mac_vap->channel.chan_number = set_chan->channel.chan_number;
    mac_vap->channel.en_bandwidth = set_chan->channel.en_bandwidth;
    mac_vap->channel.idx = idx;

    /* �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(dmac_set_chan_stru));
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_SCAN, "{hmac_chan_sync::event_mem null.}");
        return;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WALN_CTX_EVENT_SUB_TYPR_SELECT_CHAN,
                       sizeof(dmac_set_chan_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       mac_vap->vap_id);
    /* event->auc_event_data, �ɱ����� */
    if (memcpy_s(frw_get_event_payload(event_mem), sizeof(dmac_set_chan_stru), (hi_u8 *)set_chan,
                 sizeof(dmac_set_chan_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_chan_do_sync::pst_set_chan memcpy_s fail.");
        frw_event_free(event_mem);
        return;
    }

    /* �ַ��¼� */
    ret = hcc_hmac_tx_control_event(event_mem, sizeof(dmac_set_chan_stru));
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_chan_sync::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);
        return;
    }

    /* �ͷ��¼� */
    frw_event_free(event_mem);
}

/*****************************************************************************
 ��������  : HMAC���ŵ�/������Ϣͬ����DMAC
 �������  : pst_mac_vap : MAC VAP�ṹ��ָ��
             uc_channel  : ��Ҫ�����õ��ŵ���
             en_bandwidth: ��Ҫ�����õĴ���ģʽ
             en_switch_immediately: DMAC���յ�ͬ���¼�֮���Ƿ������л�
 �޸���ʷ      :
  1.��    ��   : 2014��2��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_chan_sync(mac_vap_stru *mac_vap,
                       hi_u8 channel, wlan_channel_bandwidth_enum_uint8 bandwidth,
                       hi_u8 switch_immediately)
{
    dmac_set_chan_stru set_chan;

    hmac_chan_sync_init(mac_vap, &set_chan);
    set_chan.channel.chan_number = channel;
    set_chan.channel.en_bandwidth = bandwidth;
    set_chan.switch_immediately = switch_immediately;
    hmac_chan_do_sync(mac_vap, &set_chan);
}

/*****************************************************************************
 ��������  : ����device������VAP������SW/MAC/PHY/RF�е��ŵ��ʹ���ʹVAP���������ŵ���
 �������  : pst_mac_vap : MAC VAP�ṹ��ָ��
             uc_channel  : ��Ҫ�����õ��ŵ���
             en_bandwidth: ��Ҫ�����õĴ���ģʽ
 �޸���ʷ      :
  1.��    ��   : 2014��4��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_chan_multi_select_channel_mac(mac_vap_stru *mac_vap, hi_u8 channel,
                                           wlan_channel_bandwidth_enum_uint8 bandwidth)
{
    hi_u8 vap_idx;
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru *mac_vap_value = HI_NULL;

    oam_warning_log2(mac_vap->vap_id, OAM_SF_2040,
                     "{hmac_chan_multi_select_channel_mac::uc_channel=%d,en_bandwidth=%d}", channel, bandwidth);

    mac_dev = mac_res_get_dev();
    if (mac_dev->vap_num == 0) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_2040, "{hmac_chan_multi_select_channel_mac::none vap.}");
        return;
    }

    if (mac_is_dbac_running(mac_dev)) {
        hmac_chan_sync(mac_vap, channel, bandwidth, HI_TRUE);
        return;
    }

    /* ����device������vap�� */
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap_value = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap_value == HI_NULL) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_SCAN,
                           "{hmac_chan_multi_select_channel_mac::mac_vap_value null,vap_id=%d.}",
                           mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        hmac_chan_sync(mac_vap_value, channel, bandwidth, HI_TRUE);
    }
}

/*****************************************************************************
 ��������  : ����Ӳ���Ƿ���(����֡��ACK��RTS)
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
             uc_sub_type: �¼�������
 �޸���ʷ      :
  1.��    ��   : 2014��7��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_chan_ctrl_machw_tx(const mac_vap_stru *mac_vap, hi_u8 sub_type)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u32 ret;

    /* �����¼��ڴ� */
    event_mem = frw_event_alloc(0);
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_SCAN, "{hmac_chan_ctrl_machw_tx::event_mem null.}");
        return;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       sub_type,
                       0,
                       FRW_EVENT_PIPELINE_STAGE_1,
                       mac_vap->vap_id);

    /* �ַ��¼� */
    ret = hcc_hmac_tx_control_event(event_mem, 0);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_chan_ctrl_machw_tx::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);
        return;
    }

    /* �ͷ��¼� */
    frw_event_free(event_mem);
}

/*****************************************************************************
 ��������  : ��ֹӲ������(����֡��ACK��RTS)
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
 �޸���ʷ      :
  1.��    ��   : 2014��3��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_chan_disable_machw_tx(const mac_vap_stru *mac_vap)
{
    hmac_chan_ctrl_machw_tx(mac_vap, DMAC_WALN_CTX_EVENT_SUB_TYPR_DISABLE_TX);
}

/*****************************************************************************
 ��������  : ��ָ��(����)�ŵ�������BSS
 �������  : pst_hmac_vap: HMAC VAPָ��
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2014��10��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_start_bss_in_available_channel(hmac_vap_stru *hmac_vap)
{
    hi_u32 ret;

    /* ����hmac_config_start_vap_event������BSS */
    ret = hmac_config_start_vap_event(hmac_vap->base_vap, HI_TRUE);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_INIT);
        oam_warning_log1(0, OAM_SF_SCAN,
                         "{hmac_start_bss_in_available_channel::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    /* ����bssid */
    mac_vap_set_bssid(hmac_vap->base_vap,
                      hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id,
                      WLAN_MAC_ADDR_LEN);

    /* �����Ż�����ͬƵ���µ�������һ�� */
    if (hmac_vap->base_vap->channel.band == WLAN_BAND_2G) {
        mac_mib_set_short_preamble_option_implemented(hmac_vap->base_vap, WLAN_LEGACY_11B_MIB_SHORT_PREAMBLE);
        mac_mib_set_spectrum_management_required(hmac_vap->base_vap, HI_FALSE);
    } else {
        mac_mib_set_short_preamble_option_implemented(hmac_vap->base_vap, WLAN_LEGACY_11B_MIB_LONG_PREAMBLE);
        mac_mib_set_spectrum_management_required(hmac_vap->base_vap, HI_TRUE);
    }

    /* ����AP��״̬��Ϊ UP */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_UP);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ѡһ���ŵ�(��)��������BSS
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2014��6��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_chan_start_bss(hmac_vap_stru *hmac_vap)
{
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hi_u8 channel = 0;
    wlan_channel_bandwidth_enum_uint8 bandwidth = WLAN_BAND_WIDTH_BUTT;
    hi_u32 ret;

    /* ����bssid */
    mac_vap_set_bssid(mac_vap, mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN);

    /* ��ʼ��AP���ʼ� */
    mac_vap_init_rates(mac_vap);

    /* ��ȡmac deviceָ�� */
    mac_dev = mac_res_get_dev();
    /* ��ѡһ���ŵ�(��) */
    ret = mac_is_channel_num_valid(mac_vap->channel.band, channel);
    if (ret != HI_SUCCESS) {
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_INIT);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_chan_start_bss::mac_is_channel_num_valid failed[%d].}", ret);
        return ret;
    }

    oam_info_log2(mac_vap->vap_id, OAM_SF_SCAN,
                  "{hmac_chan_start_bss::AP: Starting network in Channel: %d, bandwidth: %d.}",
                  channel, bandwidth);

    /* ���´���ģʽ */
    mac_vap->channel.en_bandwidth = bandwidth;

    /* �����ŵ��� */
#ifdef _PRE_WLAN_FEATURE_DBAC
    /* ͬʱ���Ķ��VAP���ŵ�����ʱ��Ҫǿ�������¼ */
    /* ��������DBAC������ԭʼ���̽��� */
    if (!mac_dev->dbac_enabled) {
        mac_dev->max_channel = 0;
    }
#else
    mac_dev->max_channel = 0;
#endif

    ret = hmac_config_set_freq(mac_vap, sizeof(hi_u32), &channel);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_chan_start_bss::hmac_config_set_freq failed[%d].}", ret);
        return ret;
    }

    /* ���ô���ģʽ��ֱ�����¼���DMAC���üĴ��� */
    ret = hmac_set_mode_event(mac_vap);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_chan_start_bss::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }
    /* ����ֱ������BSS */
    return hmac_start_bss_in_available_channel(hmac_vap);
}

/*****************************************************************************
 ��������  : �л��ŵ�������BSS
 �޸���ʷ      :
  1.��    ��   : 2014��11��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_chan_restart_network_after_switch(const mac_vap_stru *mac_vap)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u32 ret;

    /* �����¼��ڴ� */
    event_mem = frw_event_alloc(0);
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_SCAN,
                       "{hmac_chan_restart_network_after_switch::event_mem null.}");

        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPR_RESTART_NETWORK,
                       0,
                       FRW_EVENT_PIPELINE_STAGE_1,
                       mac_vap->vap_id);

    /* �ַ��¼� */
    ret = hcc_hmac_tx_control_event(event_mem, 0);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_SCAN,
                       "{hmac_chan_restart_network_after_switch::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);

        return ret;
    }
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����ŵ�/�����л�����¼�
 �������  :
 �޸���ʷ      :
  1.��    ��   : 2014��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_chan_switch_to_new_chan_complete(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    dmac_set_chan_stru *set_chan = HI_NULL;
    hi_u32 ret;
    hi_u8 idx;
    hi_s32 l_freq = 0;
    hi_unref_param(l_freq);

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_2040, "{hmac_switch_to_new_chan_complete::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event = (frw_event_stru *)event_mem->puc_data;
    set_chan = (dmac_set_chan_stru *)event->auc_event_data;
    hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_2040,
                       "{hmac_switch_to_new_chan_complete::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap = hmac_vap->base_vap;
    ret = mac_get_channel_idx_from_num(mac_vap->channel.band, set_chan->channel.chan_number, &idx);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_2040,
                         "{hmac_switch_to_new_chan_complete::mac_get_channel_idx_from_num failed[%d].}", ret);
        return HI_FAIL;
    }

    mac_vap->channel.chan_number = set_chan->channel.chan_number;
    mac_vap->channel.en_bandwidth = set_chan->channel.en_bandwidth;
    mac_vap->channel.idx = idx;

    mac_vap->ch_switch_info.waiting_to_shift_channel =
        set_chan->ch_switch_info.waiting_to_shift_channel;

    mac_vap->ch_switch_info.ch_switch_status = set_chan->ch_switch_info.ch_switch_status;
    mac_vap->ch_switch_info.bw_switch_status = set_chan->ch_switch_info.bw_switch_status;

    l_freq = oal_ieee80211_channel_to_frequency(mac_vap->channel.chan_number, mac_vap->channel.band);
    hi_unref_param(l_freq);

#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    /* ���ŵ��л���Ϣ�ϱ���wpa_supplicant */
    hmac_channel_switch_report_event(hmac_vap, l_freq);
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����dbac status event
 �������  :
 �޸���ʷ      :
  1.��    ��   : 2014��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_dbac_status_notify(frw_event_mem_stru *event_mem)
{
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    frw_event_stru  *event = HI_NULL;
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru    *mac_vap = HI_NULL;
    hi_u8           vap_index = 0;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_DBAC, "{hmac_dbac_status_notify::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event = (frw_event_stru *)event_mem->puc_data;
    mac_dev = mac_res_get_dev();
    mac_dev->dbac_running = event->auc_event_data[0];
    mac_dev->dbac_same_ch = event->auc_event_data[1];
    oam_warning_log2(0, OAM_SF_DBAC, "{hmac_dbac_status_notify::sync dbac status, running[%d], same ch[%d].}",
                     mac_dev->dbac_running, mac_dev->dbac_same_ch);
    /* ����device������STA��KEEPALIVE */
    for (; vap_index < mac_dev->vap_num; vap_index++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_index]);
        if ((mac_vap != HI_NULL) && (is_sta(mac_vap))) {
            /* ����ʱ�ر� keepalive,�ر�ʱ���� */
            mac_vap->cap_flag.keepalive = (mac_dev->dbac_running == HI_TRUE) ? HI_FALSE : HI_TRUE;
        }
    }
#else
    hi_unref_param(event_mem);
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����(Extended) Channel Switch Announcement IE
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
             puc_payload: ָ��(Extended) Channel Switch Announcement IE��ָ��
             en_eid_type: Element ID
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��1��20��
    ��    ��   : Hisilicon
    �޸�����   : ����HMAC
*****************************************************************************/
hi_u32 hmac_ie_proc_ch_switch_ie(mac_vap_stru *mac_vap, const hi_u8 *puc_payload, mac_eid_enum_uint8 eid_type)
{
    if (oal_unlikely((mac_vap == HI_NULL) || (puc_payload == HI_NULL))) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_ie_proc_ch_switch_ie::param null.}");

        return HI_ERR_CODE_PTR_NULL;
    }

    /*************************************************************************/
    /*                    Channel Switch Announcement element                */
    /* --------------------------------------------------------------------- */
    /* |Element ID|Length |Channel switch Mode|New Channel| Ch switch count| */
    /* --------------------------------------------------------------------- */
    /* |1         |1      |1                  |1          |1               | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*                Extended Channel Switch Announcement element           */
    /* --------------------------------------------------------------------- */
    /* |Elem ID|Length|Ch Switch Mode|New Reg Class|New Ch| Ch switch count| */
    /* --------------------------------------------------------------------- */
    /* |1      |1     |1             |1            |1     |1               | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* Extended Channel Switch Announcement element */
    hi_u8 ch_sw_mode = puc_payload[MAC_IE_HDR_LEN];
    hi_u8 new_chan   = puc_payload[MAC_IE_HDR_LEN + 1];
    hi_u8 sw_cnt     = puc_payload[MAC_IE_HDR_LEN + 2]; /* 2:ƫ��2 */

    if (eid_type == MAC_EID_CHANSWITCHANN) {
        if (puc_payload[1] < MAC_CHANSWITCHANN_IE_LEN) {
            oam_warning_log1(0, 0, "{hmac_ie_proc_ch_switch_ie::invalid chan switch ann ie len[%d]}", puc_payload[1]);
            return HI_FAIL;
        }
    } else if (eid_type == MAC_EID_EXTCHANSWITCHANN) {
        if (puc_payload[1] < MAC_EXT_CHANSWITCHANN_IE_LEN) {
            oam_warning_log1(0, 0, "{hmac_ie_proc_ch_switch_ie::invalid ExtChan switch ann ie len=%d}", puc_payload[1]);
            return HI_FAIL;
        }

        /* Skip New Operating Class = puc_payload[MAC_IE_HDR_LEN + 1] */
        new_chan = puc_payload[MAC_IE_HDR_LEN + 2]; /* 2:ƫ��2 */
        sw_cnt   = puc_payload[MAC_IE_HDR_LEN + 3]; /* 3:ƫ��3 */
    } else {
        return HI_FAIL;
    }

    /* ��鵱ǰ�������Ƿ�֧�ָ��ŵ��������֧�֣���ֱ�ӷ��� */
    hi_u32 check = mac_is_channel_num_valid(mac_vap->channel.band, new_chan);
    if (check != HI_SUCCESS) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{hmac_ie_proc_ch_switch_ie::mac_is_channel_num_valid failed[%d], uc_new_chan=%d.}", check, new_chan);
        return check;
    }

    /* ���STA�Ѿ�׼�������ŵ��л��������κ����飬ֱ�ӷ��� */
    if (mac_vap->ch_switch_info.waiting_to_shift_channel == HI_TRUE) {
        if (sw_cnt < mac_vap->ch_switch_info.ch_swt_cnt) {
            return HI_SUCCESS;
        }
    } else if (ch_sw_mode == 1) { /* STA���ŵ��л����ǰӦ��ֹͣ���� */
        hmac_chan_disable_machw_tx(mac_vap);
    } /* ����else */

    mac_vap->ch_switch_info.new_channel    = new_chan;
    mac_vap->ch_switch_info.new_ch_swt_cnt = sw_cnt;
    mac_vap->ch_switch_info.ch_swt_cnt     = sw_cnt;
    mac_vap->ch_switch_info.waiting_to_shift_channel = (hi_u8)HI_TRUE;

    /* ���"�ŵ��л�����"����0���������л��ŵ� */
    if (mac_vap->ch_switch_info.new_ch_swt_cnt == 0) {
        mac_vap->ch_switch_info.channel_swt_cnt_zero =  (hi_u8)HI_TRUE;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hmac_chan_sync(mac_vap, mac_vap->channel.chan_number, mac_vap->channel.en_bandwidth, HI_FALSE);
#endif

    return HI_SUCCESS;
}

#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
/*****************************************************************************
 ��������  : ��CSA�л��ŵ��Ľ���ϱ���WPA
*****************************************************************************/
hi_void hmac_channel_switch_report_event(const hmac_vap_stru *hmac_vap, hi_s32 l_freq)
{
    hmac_send_event_to_host(hmac_vap->base_vap, (const hi_u8*)(&l_freq),
        sizeof(hi_s32), HMAC_HOST_CTX_EVENT_SUB_TYPE_CHANNEL_SWITCH);
    return;
}
#endif

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
