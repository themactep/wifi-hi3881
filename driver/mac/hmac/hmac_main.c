/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HMAC module initialization and uninstallation.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hmac_main.h"
#include "hmac_event.h"
#include "hmac_hcc_adapt.h"
#include "hmac_tx_data.h"
#include "hmac_rx_data.h"
#include "hmac_11i.h"
#include "hmac_mgmt_classifier.h"
#include "hmac_scan.h"
#include "hmac_blockack.h"
#include "frw_main.h"
#include "hmac_chan_mgmt.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
hmac_rxdata_thread_stru     g_st_rxdata_thread;
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
static hi_void hmac_event_fsm_rx_adapt_subtable_register(hi_void)
{
    frw_event_sub_rx_adapt_table_init(g_ast_hmac_wlan_drx_event_sub_table,
                                      sizeof(g_ast_hmac_wlan_drx_event_sub_table) /
                                      sizeof(frw_event_sub_table_item_stru),
                                      hmac_hcc_rx_convert_netbuf_to_event_default);

    frw_event_sub_rx_adapt_table_init(g_ast_hmac_wlan_crx_event_sub_table,
                                      sizeof(g_ast_hmac_wlan_crx_event_sub_table) /
                                      sizeof(frw_event_sub_table_item_stru),
                                      hmac_hcc_rx_convert_netbuf_to_event_default);

    frw_event_sub_rx_adapt_table_init(g_ast_hmac_wlan_ctx_event_sub_table,
                                      sizeof(g_ast_hmac_wlan_ctx_event_sub_table) /
                                      sizeof(frw_event_sub_table_item_stru),
                                      hmac_hcc_rx_convert_netbuf_to_event_default);

    frw_event_sub_rx_adapt_table_init(g_ast_hmac_wlan_misc_event_sub_table,
                                      sizeof(g_ast_hmac_wlan_misc_event_sub_table) /
                                      sizeof(frw_event_sub_table_item_stru),
                                      hmac_hcc_rx_convert_netbuf_to_event_default);

    g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_RX_STA].p_rx_adapt_func =
        hmac_rx_process_data_sta_rx_adapt;
    g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_RX_AP].p_rx_adapt_func  =
        hmac_rx_process_data_sta_rx_adapt;

    /* ע��HMACģ��WLAN_CRX�¼��ӱ� */
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_INIT].p_rx_adapt_func = hmac_rx_convert_netbuf_to_netbuf_default;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_RX].p_rx_adapt_func = hmac_rx_process_mgmt_event_rx_adapt;
#ifdef _PRE_WLAN_FEATURE_FLOWCTL
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_FLOWCTL_BACKP].p_rx_adapt_func = hmac_alg_flowctl_backp_rx_adapt;
#endif

    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_SCAN_RESULT].p_rx_adapt_func =
        hmac_rx_convert_netbuf_to_netbuf_default;
#ifdef _PRE_WLAN_FEATURE_WOW
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_DEV_SYNC_HOST].p_rx_adapt_func =
        hmac_rx_convert_netbuf_to_netbuf_default;
#endif
#ifdef _PRE_WLAN_FEATURE_PROMIS
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_EVENT_PROMIS].p_rx_adapt_func =
        hmac_rx_process_mgmt_event_rx_adapt;
#endif
}

static hi_void hmac_event_fsm_action_subtable_register(hi_void)
{
    /* ���¼����ͺ͵��ú���������ע�ᵽ�¼�����ģ�� */
    /* ע��WLAN_DTX�¼��ӱ� */
    g_ast_hmac_wlan_dtx_event_sub_table[DMAC_TX_WLAN_DTX].func = hmac_tx_wlan_to_wlan_ap;

    /* APģʽ��ע��HMACģ��WLAN_DRX�¼��ӱ� */
    g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_RX_AP].func = hmac_rx_process_data_ap;

    /* STAģʽ��ע��HMACģ��WLAN_DRX�¼��ӱ� */
    g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_RX_STA].func = hmac_rx_process_data_sta;

    /* AP ��STA ������ע��HMACģ��WLAN_DRX�¼��ӱ� */
    g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_TKIP_MIC_FAILE].func =
        hmac_rx_tkip_mic_failure_process;

    /* ע��HMACģ��WLAN_CRX�¼��ӱ� */
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_INIT].func = hmac_init_event_process;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_RX].func = hmac_rx_process_mgmt_event;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_DELBA].func = hmac_mgmt_rx_delba_event;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_SCAN_RESULT].func = hmac_scan_proc_scanned_bss;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_SCAN_COMP].func = hmac_scan_proc_scan_comp_event;
#ifdef _PRE_WLAN_FEATURE_FLOWCTL
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_FLOWCTL_BACKP].func = hmac_flowctl_backp_event;
#endif
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_DISASSOC].func = hmac_mgmt_send_disasoc_deauth_event;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_DEAUTH].func = hmac_mgmt_send_disasoc_deauth_event;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_CH_SWITCH_COMPLETE].func =
        hmac_chan_switch_to_new_chan_complete;
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_DBAC].func = hmac_dbac_status_notify;
#ifdef _PRE_WLAN_FEATURE_WOW
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_DEV_SYNC_HOST].func = hmac_wow_proc_dev_sync_host_event;
#endif
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_CSI_REPORT].func = hmac_csi_data_report_event;
#ifdef _PRE_WLAN_FEATURE_PROMIS
    g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_EVENT_PROMIS].func = hmac_rx_process_mgmt_promis;
#endif

    g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_CREATE_BA].func      = hmac_create_ba_event;
    g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_DEL_BA].func         = hmac_del_ba_event;
    g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_SYN_CFG].func        = hmac_event_config_syn;
#ifdef _PRE_WLAN_FEATURE_WOW
    g_ast_hmac_wlan_misc_event_sub_table[DMAC_MISC_SUB_TYPE_DEV_READY_FOR_HOST_SLP].func =
        hmac_wow_proc_dev_ready_slp_event;
#endif
    g_ast_hmac_wlan_misc_event_sub_table[DMAC_MISC_SUB_TYPE_DISASOC].func               = hmac_proc_disasoc_misc_event;

#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
    g_ast_hmac_host_drx_event_sub_table[HMAC_TX_HOST_DRX].func = hmac_tx_event_process;
    frw_event_table_register(FRW_EVENT_TYPE_HOST_DRX, FRW_EVENT_PIPELINE_STAGE_0, g_ast_hmac_host_drx_event_sub_table);
#endif

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_ALG_INFO_SYN].func           = hmac_syn_info_event;
    g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_VOICE_AGGR].func             = hmac_voice_aggr_event;
    g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_PROTECTION_INFO_SYN].func    = hmac_protection_info_sync_event;
#endif

    g_ast_wal_host_crx_table[WAL_HOST_CRX_SUBTYPE_CFG].func = wal_config_process_pkt;
}
#endif

/*****************************************************************************
 ��������  : hmacģ���¼����䴦������ע�ắ��
 �޸���ʷ      :
  1.��    ��   : 2014��10��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_event_fsm_register(hi_void)
{
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    /* ע�������¼���rx_adapt�ӱ� */
    hmac_event_fsm_rx_adapt_subtable_register();

    /* ע�������¼���ִ�к����ӱ� */
    hmac_event_fsm_action_subtable_register();
#endif
    hmac_event_fsm_table_register();
}

/*****************************************************************************
 ��������  : HMACģ���ʼ������ڣ�����HMACģ���ڲ��������Եĳ�ʼ����
 �� �� ֵ  : ��ʼ������ֵ���ɹ���ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_main_init(hi_void)
{
    hi_u32 return_code;
    frw_init_enum_uint8 init_state = frw_get_init_state();
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* offloadģʽ�� dmac��״̬�޷�����host�࣬��stateΪfrw succ */
    if ((init_state == FRW_INIT_STATE_BUTT) || (init_state < FRW_INIT_STATE_FRW_SUCC)
#else
    if ((init_state == FRW_INIT_STATE_BUTT) || (init_state < FRW_INIT_STATE_DMAC_CONFIG_VAP_SUCC)
#endif
    ) {
        oam_error_log1(0, 0, "hmac_main_init:en_init_state is error %d.", init_state);
        return HI_FAIL;
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    return_code = mac_res_init();
    if (return_code != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "hmac_main_init: mac_res_init return err code %d.", return_code);
        return HI_FAIL;
    }
#endif

    /* �����ʼ��״̬��������VAP�ɹ�ǰ��״̬�������˴�ΪHMAC��һ�γ�ʼ�������ؼ��ػ�������ʼ�� */
    if (init_state < FRW_INIT_STATE_HMAC_CONFIG_VAP_SUCC) {
        /* �¼�ע�� */
        hmac_event_fsm_register();
        return_code = hmac_device_init();
        if (return_code != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_main_init::hmac_device_init failed[%d].}", return_code);
            hmac_device_exit(); /* ͳһ�ͷ�hmac device��Դ */
            return return_code;
        }
        frw_set_init_state(FRW_INIT_STATE_HMAC_CONFIG_VAP_SUCC);
        /* �����ɹ��������ӡ */
    } else {
        oam_error_log1(0, OAM_SF_ANY, "{hmac_main_init::init state error[%d].}", init_state);
    }
#ifndef _PRE_LINUX_BUILTIN
#ifdef _PRE_WLAN_FEATURE_WOW
    hmac_wow_init();
#endif
#endif
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_init_netbuf_stru();
#endif

    printk("hmac_main_init SUCCESSULLY\r\n");
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : HMACģ��ж��
 �޸���ʷ      :
  1.��    ��   : 2012��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_main_exit(hi_void)
{
    hi_u32 return_code;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    if (frw_get_init_state() != FRW_INIT_STATE_HAL_SUCC) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_main_exit::frw state error.}");
        return;
    }
#else
    if (frw_get_init_state() != FRW_INIT_STATE_HMAC_CONFIG_VAP_SUCC) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_main_exit:: frw state error.}");
        return;
    }
#endif
    return_code = hmac_device_exit();
    if (oal_unlikely(return_code != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_main_exit::hmac_device_exit failed[%d].}", return_code);
        return ;
    }
    mac_res_exit();
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    frw_set_init_state(FRW_INIT_STATE_FRW_SUCC);
#else
    frw_set_init_state(FRW_INIT_STATE_DMAC_CONFIG_VAP_SUCC);
#endif
}

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
hi_u8 hmac_get_rxthread_enable()
{
    return g_st_rxdata_thread.rxthread_enable;
}

hi_void hmac_rxdata_netbuf_enqueue(oal_netbuf_stru  *netbuf)
{
#define NETBUG_LISET_LEN_MAX 1000
    if (oal_netbuf_list_len(&g_st_rxdata_thread.rxdata_netbuf_head) > NETBUG_LISET_LEN_MAX) {
        oal_netbuf_free(netbuf);
        g_st_rxdata_thread.pkt_loss_cnt++;
        return;
    }
    oal_netbuf_list_tail(&g_st_rxdata_thread.rxdata_netbuf_head, netbuf);
    return;
}

/*****************************************************************************
 ��������  : dmac �׸�hmac�ĳ�ʼ���ظ��¼�
 �������  : event_mem: �¼��ṹ��
*****************************************************************************/
hi_u32 hmac_init_event_process(frw_event_mem_stru *event_mem)
{
    frw_event_stru        *pst_event = HI_NULL;             /* �¼��ṹ�� */
    mac_data_rate_stru    *pst_data_rate = HI_NULL;
    hi_u8                 *pst_data_mac_addr = HI_NULL;
    dmac_tx_event_stru    *pst_ctx_event = HI_NULL;
    mac_device_stru       *pst_mac_device = HI_NULL;
    hi_unref_param(pst_data_mac_addr);

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_init_event_process::event_mem null.}");
        return HI_FALSE;
    }

    pst_event = (frw_event_stru *)event_mem->puc_data;

    pst_ctx_event = (dmac_tx_event_stru *)pst_event->auc_event_data;
    pst_data_rate = (mac_data_rate_stru *)(oal_netbuf_data((oal_netbuf_stru *)(pst_ctx_event->netbuf)));

    pst_data_mac_addr = (hi_u8*)(oal_netbuf_data((oal_netbuf_stru *)(pst_ctx_event->netbuf))) +
        sizeof(mac_data_rate_stru) * MAC_DATARATES_PHY_80211G_NUM;
    oal_io_print("get rates from device\n");
    /* ͬ��mac֧�ֵ����ʼ���Ϣ */
    pst_mac_device = mac_res_get_dev();
    if (pst_mac_device == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_init_event_process::pst_mac_device null.}");
        oal_netbuf_free((oal_netbuf_stru *)pst_ctx_event->netbuf);
        return HI_FALSE;
    }
    if (memcpy_s((hi_u8 *)(pst_mac_device->mac_rates_11g), sizeof(mac_data_rate_stru) * MAC_DATARATES_PHY_80211G_NUM,
        (hi_u8 *)pst_data_rate, sizeof(mac_data_rate_stru) * MAC_DATARATES_PHY_80211G_NUM) != EOK) {
        oam_error_log0(0, 0, "{hmac_init_event_process::mem safe func err!}");
        return HI_FALSE;
    }

    /* �ͷŵ�02ͬ����Ϣ���õ�netbuf��Ϣ */
    oal_netbuf_free((oal_netbuf_stru *)pst_ctx_event->netbuf);

    return HI_SUCCESS;
}

hi_void hmac_rxdata_sched()
{
    oal_up(&g_st_rxdata_thread.rxdata_sema);
    return;
}
#endif


#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
