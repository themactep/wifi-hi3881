/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL module initialization and uninstallation.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "plat_firmware.h"
#include "plat_pm_wlan.h"
#include "oam_ext_if.h"
#include "frw_main.h"
#include "frw_timer.h"
#include "hmac_ext_if.h"
#include "wal_ioctl.h"
#include "wal_hipriv.h"
#include "wal_cfg80211.h"
#include "wal_linux_flowctl.h"
#include "wal_net.h"
#ifdef _PRE_WLAN_FEATURE_CSI
#include "wal_event.h"
#endif
#include "wal_event_msg.h"
#include "wal_customize.h"
#include "hcc_hmac_if.h"
#include "plat_firmware.h"
#include "wal_main.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/* HOST CTX�ֱ� */
const frw_event_sub_table_item_stru g_ast_wal_host_ctx_table[HMAC_HOST_CTX_EVENT_SUB_TYPE_BUTT] = {
    {wal_scan_comp_proc_sta, HI_NULL, HI_NULL},                  /* HMAC_HOST_CTX_EVENT_SUB_TYPE_SCAN_COMP_STA */
    {wal_asoc_comp_proc_sta, HI_NULL, HI_NULL},                  /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ASOC_COMP_STA */
    {wal_disasoc_comp_proc_sta, HI_NULL, HI_NULL},               /* HMAC_HOST_CTX_EVENT_SUB_TYPE_DISASOC_COMP_STA */
    {wal_connect_new_sta_proc_ap, HI_NULL, HI_NULL},             /* HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_CONNECT_AP */
    {wal_disconnect_sta_proc_ap, HI_NULL, HI_NULL},              /* HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_DISCONNECT_AP */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    {wal_mic_failure_proc, HI_NULL, HI_NULL},                    /* HMAC_HOST_CTX_EVENT_SUB_TYPE_MIC_FAILURE */
#endif
    {wal_send_mgmt_to_host, HI_NULL, HI_NULL},                   /* HMAC_HOST_CTX_EVENT_SUB_TYPE_RX_MGMT */
#ifdef _PRE_WLAN_FEATURE_P2P
    {wal_p2p_listen_timeout, HI_NULL, HI_NULL},                  /* HMAC_HOST_CTX_EVENT_SUB_TYPE_LISTEN_EXPIRED */
#endif
    {wal_report_sta_assoc_info, HI_NULL, HI_NULL},               /* HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_CONN_RESULT */
#ifdef _PRE_WLAN_FEATURE_FLOWCTL
    {wal_flowctl_backp_event_handler, HI_NULL, HI_NULL},         /* HMAC_HOST_CTX_EVENT_SUB_TYPE_FLOWCTL_BACKP */
#endif
    {wal_cfg80211_mgmt_tx_status, HI_NULL, HI_NULL},             /* HMAC_HOST_CTX_EVENT_SUB_TYPE_MGMT_TX_STATUS */
#ifdef _PRE_WLAN_FEATURE_ANY
    {wal_any_process_rx_data, HI_NULL, HI_NULL},                 /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_RX_DATA */
    {wal_any_process_tx_complete, HI_NULL, HI_NULL},             /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_TX_STATUS */
    {wal_any_process_scan_result, HI_NULL, HI_NULL},             /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_SCAN_RESULT */
    {wal_any_process_peer_info, HI_NULL, HI_NULL},               /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_PEER_INFO */
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
    {wal_mesh_close_peer_inform, HI_NULL, HI_NULL},              /* HMAC_HOST_CTX_EVENT_SUB_TYPE_PEER_CLOSE_MESH */
    {wal_mesh_new_peer_candidate, HI_NULL, HI_NULL},             /* HMAC_HOST_CTX_EVENT_SUB_TYPE_NEW_PEER_CANDIDATE */
    {wal_mesh_inform_tx_data_info, HI_NULL, HI_NULL},            /* HMAC_HOST_CTX_EVENT_SUB_TYPE_TX_DATA_INFO */
    {wal_mesh_report_mesh_user_info, HI_NULL, HI_NULL},          /* HMAC_HOST_CTX_EVENT_SUB_TYPE_MESH_USER_INFO */
#endif
#ifdef _PRE_WLAN_FEATURE_CSI
    {wal_csi_data_report, HI_NULL, HI_NULL},                     /* HMAC_HOST_CTX_EVENT_SUB_TYPE_CSI_REPORT */
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    {wal_p2p_action_tx_status, HI_NULL, HI_NULL},                /* HMAC_HOST_CTX_EVENT_SUB_TYPE_P2P_TX_STATUS */
#endif

#ifdef FEATURE_DAQ
    {wal_data_acq_status, HI_NULL, HI_NULL},                      /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ACQ_STATUS */
    {wal_data_acq_result, HI_NULL, HI_NULL},                      /* HMAC_HOST_CTX_EVENT_SUB_TYPE_ACQ_RESULT */
#endif
#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    {wal_channel_switch_report, HI_NULL, HI_NULL},                /* HMAC_HOST_CTX_EVENT_SUB_TYPE_CHANNEL_SWITCH */
#endif
    {wal_get_efuse_mac_from_dev, HI_NULL, HI_NULL},               /* HMAC_HOST_CTX_EVENT_GET_MAC_FROM_EFUSE */
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
    {wal_get_dbg_cal_data_from_dev, HI_NULL, HI_NULL},            /* HMAC_HOST_CTX_EVENT_GET_DBG_CAL_DATA */
#endif
    {wal_report_tx_params, HI_NULL, HI_NULL},                     /* HMAC_HOST_CTX_EVENT_REPORT_TX_PARAMS */
};

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
EVENT_CB_S                 g_backup_event;
#endif
hi_u32                     g_wlan_reusme_wifi_mode = 0;               /* 0:������wifi��1:����AP��2: ���� STA */
hi_u8                       g_wifi_exit_stop_flag = HI_FALSE;
#define WAL_HAL_INTERRUPT_COUNT   4
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : wal_event_fsm_init
 ��������  : ע���¼�������
 �������  : ��
 �������  : ��
 �� �� ֵ  : HI_SUCCESS
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void  wal_event_fsm_init(hi_void)
{
    frw_event_table_register(FRW_EVENT_TYPE_HOST_CTX, FRW_EVENT_PIPELINE_STAGE_0, g_ast_wal_host_ctx_table);
}

/*****************************************************************************
 ��������  : WALģ���ʼ������ڣ�����WALģ���ڲ��������Եĳ�ʼ����
 �� �� ֵ  : ��ʼ������ֵ���ɹ���ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_main_init(hi_void)
{
    hi_u32               ret;
    frw_init_enum_uint8  init_state;

    wal_msg_queue_init();

    init_state = frw_get_init_state();
    /* WALģ���ʼ����ʼʱ��˵��HMAC�϶��Ѿ���ʼ���ɹ� */
    if ((init_state == FRW_INIT_STATE_BUTT) || (init_state < FRW_INIT_STATE_HMAC_CONFIG_VAP_SUCC)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_main_init::invalid state value [%d]!}", init_state);
        return HI_FAIL;
    }

    wal_event_fsm_init();
#ifndef _PRE_LINUX_BUILTIN
    wal_init_dev_addr();
#endif
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
    /* ����proc */
    ret = wal_hipriv_create_proc(HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_main_init_etc::wal_hipriv_create_proc_etc fail[%d]!}\r\n", ret);
        return -OAL_EFAIL;
    }
#endif
#ifndef _PRE_LINUX_BUILTIN
    ret = wal_customize_set_config();
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_main_init::customize init failed [%d]!}", ret);
        return HI_FAIL;
    }
#endif
    ret = wal_cfg80211_init();
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_main_init::wal_cfg80211_init fail[%d]!}", ret);
        return HI_FAIL;
    }
    /* ��host�����WAL��ʼ���ɹ�����Ϊȫ����ʼ���ɹ� */
    frw_set_init_state(FRW_INIT_STATE_ALL_SUCC);

    printk("wal_main_init SUCCESSFULLY\r\n");
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ж��ǰɾ������vap
*****************************************************************************/
hi_void wal_destroy_all_vap(hi_void)
{
    hi_u32   netdev_index;
    oal_net_device_stru *netdev = HI_NULL;

    /* ɾ��ҵ��vap֮ǰ����frw���¼� */
    frw_event_process_all_event();

    /* ɾ��ҵ��vap */
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev = oal_get_past_net_device_by_index(netdev_index);
        if (netdev != HI_NULL) {
            if (strncmp(netdev->name, WLAN_CFG_VAP_NAME, strlen(WLAN_CFG_VAP_NAME)) == 0) {
                continue;
            }
            oal_net_device_close(netdev);
            wal_hipriv_del_vap(netdev);
        }
    }
}

/*****************************************************************************
 �� �� ��  : wal_main_exit
 ��������  : WALģ��ж��
 �������  : ��
 �������  : ��
 �� �� ֵ  : ģ��ж�ط���ֵ���ɹ���ʧ��ԭ��
 ���ú���  : ��
 ��������  : ��

 �޸���ʷ      :
  1.��    ��   : 2012��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void  wal_main_exit(hi_void)
{
    if (frw_get_init_state() != FRW_INIT_STATE_ALL_SUCC) {
        oam_info_log0(0, 0, "{wal_main_exit::frw state wrong.\n");
        return;
    }
    /* down�����е�vap */
    wal_destroy_all_vap();
    wal_cfg80211_exit();
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
    /* ɾ��proc */
    wal_hipriv_remove_proc();
#endif
    /* ж�سɹ�ʱ������ʼ��״̬��ΪHMAC��ʼ���ɹ� */
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    frw_set_init_state(FRW_INIT_STATE_HAL_SUCC);
#else
    frw_set_init_state(FRW_INIT_STATE_HMAC_CONFIG_VAP_SUCC);
#endif
}

/*****************************************************************************
 �� �� ��  : hisi_wifi_resume_process
 ��������  : �ָ�wifi����
*****************************************************************************/
hi_void hisi_wifi_resume_process(hi_void)
{
    oam_info_log1(0, 0, "{hisi_wifi_resume_process::wifi_init, wifi_mode = %u}\n", g_wlan_reusme_wifi_mode);

    /* g_ul_wlan_reusme_wifi_mode��0:������wifi��1:����AP��2: ���� STA */
    if (g_wlan_reusme_wifi_mode == 1) {
        oam_info_log0(0, 0, "{hisi_wifi_resume_process::cmd_wifi_init_module:: end!}\n");
        msleep(3000); /* 3000: ˯��ʱ�� */
    } else if (g_wlan_reusme_wifi_mode == 2) { /* 2: ����STA */
        oam_warning_log0(0, 0, "hisi_wifi_resume_process:: wait development");
    } else {
        /* nothing */
    }
}

/*****************************************************************************
 ��������  : Host���� ���س�ʼ��
 �޸���ʷ      :
  1.��    ��   : 2019��06��04��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hi_wifi_host_init(hi_void)
{
    hi_u32  ret;
    g_wifi_exit_stop_flag = HI_FALSE;
#ifndef _PRE_LINUX_BUILTIN
    ret = hcc_hmac_init();
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, 0, "hi_wifi_host_init: hcc_hmac_init return error code: %d", ret);
        return ret;
    }

    if (plat_firmware_init() != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "plat_firmware_init error\n");
        goto hcc_hmac_init_fail;
    }

    if (wlan_pm_open() != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "wlan_pm_open error\n");
        goto hcc_hmac_init_fail;
    }
#endif
    ret = hmac_main_init();
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, 0, "hi_wifi_host_init: hmac_main_init return error code: %d", ret);
        goto hcc_hmac_init_fail;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#ifndef _PRE_LINUX_BUILTIN
        /* ����wifi_cfg������������ͬ����wal_customize */
        ret = firmware_sync_cfg_paras_to_wal_customize();
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, 0, "hi_wifi_host_init: wal_main_init return error code: %d", ret);
            goto wal_main_init_fail;
        }
#endif
#endif
    ret = wal_main_init();
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, 0, "hi_wifi_host_init: wal_main_init return error code: %d", ret);
        goto wal_main_init_fail;
    }

    printk("hi_wifi_host_init SUCCESSFULLY\r\n");
    return HI_SUCCESS;

wal_main_init_fail:
    hmac_main_exit();
hcc_hmac_init_fail:
    wlan_pm_exit();
    return HI_FAIL;
}

hi_u32 hi_wifi_host_download_fw(hi_void)
{
    hi_u32  ret;

    ret = hcc_hmac_init();
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, 0, "hi_wifi_host_download_fw::hcc_hmac_init return error code: %d", ret);
        goto hmac_main_init_fail;
    }

    if (plat_firmware_init() != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "hi_wifi_host_download_fw::plat_firmware_init error\n");
        goto plat_firmware_fail;
    }

    if (wlan_pm_open() != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "hi_wifi_host_download_fw::wlan_pm_open error\n");
        goto hcc_hmac_init_fail;
    }
    printk("hi_wifi_host_download_fw SUCCESSFULLY\r\n");
    return HI_SUCCESS;

hcc_hmac_init_fail:
    wlan_pm_exit();
plat_firmware_fail:
    plat_firmware_clear();
hmac_main_init_fail:
    hcc_hmac_exit();
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : Host���� ж��
 �޸���ʷ      :
  1.��    ��   : 2019��06��04��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hi_wifi_host_exit(hi_void)
{
    g_wifi_exit_stop_flag = HI_TRUE;
    wal_main_exit();
    hmac_main_exit();
#ifndef _PRE_LINUX_BUILTIN
    plat_firmware_clear();
#endif
    printk("wifi host exit successfully\r\n");
    return;
}

/*****************************************************************************
 ��������  : ƽ̨��ʼ�����������
 �������  : vap_num : ���֧�ֵ�ͬʱ������vap����
             user_num: ���֧�ֽ�����û�����,��vapʱ����
 �޸���ʷ      :
  1.��    ��   : 2014��11��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hi_wifi_plat_init(const hi_u8 vap_num, const hi_u8 user_num)
{
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    hi_bool offload_mode = HI_TRUE;      /* DMAC OFFLOAD: IPC���� */
#else
    hi_bool offload_mode = HI_FALSE;     /* DMAC HOST��һ: IOT���� */
#endif
    hi_u32 wifi_task_size = (hi_u32)FRW_TASK_SIZE;

    oam_info_log2(0, OAM_SF_ANY, "hi_wifi_plat_init vap_num[%d], user_num[%d]", vap_num, user_num);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    if (oam_main_init() != HI_SUCCESS) {
        oam_error_log0(0, 0, "plat_init: oam_main_init return error code.");
        goto oam_main_init_fail;
    }
#endif
#ifndef _PRE_LINUX_BUILTIN
    if (wal_customize_init() != HI_SUCCESS) {
        oam_error_log0(0, 0, "plat_init: wal_customize_init return error code.");
        goto wal_customize_init_fail;
    }
#endif
    if (oal_main_init(vap_num, user_num) != HI_SUCCESS) {
        oam_error_log0(0, 0, "plat_init: oal_main_init return error code.");
        goto oal_main_init_fail;
    }

    if (frw_main_init(offload_mode, wifi_task_size) != HI_SUCCESS) {
        oam_error_log0(0, 0, "plat_init: frw_main_init return error code.");
        goto frw_main_init_fail;
    }

    printk("hi_wifi_plat_init SUCCESSFULLY\r\n");
    return HI_SUCCESS;

frw_main_init_fail:
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    oam_main_exit();
oam_main_init_fail:
#endif
    oal_main_exit();
oal_main_init_fail:
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    wal_customize_exit();
#endif
#ifndef _PRE_LINUX_BUILTIN
wal_customize_init_fail:
#endif
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ƽ̨ж�غ��������
 �޸���ʷ      :
  1.��    ��   : 2014��11��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hi_wifi_plat_exit(hi_void)
{
    oam_main_exit();
    if (frw_get_init_state() != FRW_INIT_STATE_FRW_SUCC) {
        oam_error_log0(0, 0, "{hi_wifi_plat_exit:: frw init state error.}");
        return;
    }
    frw_main_exit();
    oal_main_exit();
#ifndef _PRE_LINUX_BUILTIN
    wal_customize_exit();
#endif
}

hi_u8 hi_wifi_get_host_exit_flag(hi_void)
{
    return g_wifi_exit_stop_flag;
}
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

