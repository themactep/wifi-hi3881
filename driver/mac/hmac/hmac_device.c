/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Hmac device corresponds to the source file of the operation function implementation.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oam_ext_if.h"
#include "oal_ext_if.h"
#include "wal_main.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "mac_regdomain.h"
#include "mac_vap.h"
#include "hmac_device.h"
#include "hmac_vap.h"
#include "hmac_rx_filter.h"
#include "hmac_chan_mgmt.h"
#include "hmac_rx_filter.h"
#include "hmac_config.h"
#include "hmac_device.h"
#include "hmac_scan.h"
#include "hmac_rx_data.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
hmac_device_stru g_hmac_device;

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ��ȡ��ӦHMAC DEVICEȫ�ֱ���
*****************************************************************************/
hmac_device_stru *hmac_get_device_stru(hi_void)
{
    return &g_hmac_device;
}

/*****************************************************************************
 ��������  : ȥ��ʼ��hmac device�������
 �޸���ʷ      :
  1.��    ��   : 2015��1��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_device_exit(hi_void)
{
    mac_device_stru             *mac_dev = HI_NULL;
    hmac_device_stru            *hmac_dev = HI_NULL;
    hi_u32                       return_code;
    hmac_vap_stru               *hmac_vap = HI_NULL;
    mac_cfg_down_vap_param_stru  down_vap = {0};
    hi_u8                        vap_idx = 0;

    hmac_dev = hmac_get_device_stru();
    /* ɨ��ģ��ȥ��ʼ�� */
    hmac_scan_exit(hmac_dev);
#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    hmac_pkt_mem_opt_exit(hmac_dev);
#endif

    /* ��������vap��ʼ����HMAC������������VAPж��Ҳ��HMAC�� */
    hmac_vap = hmac_vap_get_vap_stru(WLAN_CFG_VAP_ID);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_device_exit::pst_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    return_code = hmac_config_del_vap(hmac_vap->base_vap, sizeof(mac_cfg_down_vap_param_stru), (hi_u8 *)&down_vap);
    if (return_code != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_device_exit::hmac_config_del_vap failed[%d].}", return_code);
        return return_code;
    }
    mac_dev = mac_res_get_dev();
    while (mac_dev->auc_vap_id[0] != 0) {
        hmac_vap = hmac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (hmac_vap == HI_NULL) {
            oam_error_log0(0, OAM_SF_ANY, "{hmac_device_exit::hmac_vap null.}");
            return HI_ERR_CODE_PTR_NULL;
        }
        return_code  = hmac_vap_destroy(hmac_vap);
        if (return_code != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_device_exit::hmac_vap_destroy failed[%d].}", return_code);
            return return_code;
        }
    }
    /* ж���û���Դ */
    hmac_user_res_exit();
    /* ж��VAP��Դ */
    hmac_vap_res_exit();

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_cfg_vap_init
 ��������  : ����VAP��ʼ��
 �������  : uc_dev_id: �豸id
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_cfg_vap_init(const mac_device_stru *mac_dev)
{
    hi_u32           ret;
    hmac_vap_stru   *hmac_vap = HI_NULL;
    hi_u8            vap_idx;

    /* ��ʼ�������У�ֻ��ʼ������vap������vap��Ҫͨ��������� ����vap id����Ϊ0 �����쳣 */
    vap_idx = mac_vap_alloc_vap_res();
    if (oal_unlikely(vap_idx != WLAN_CFG_VAP_ID)) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_cfg_vap_init::alloc_vap_res fail. id=[%d].}", vap_idx);
        return HI_FAIL;
    }

    hmac_vap = hmac_vap_get_vap_stru(WLAN_CFG_VAP_ID);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{hmac_cfg_vap_init::pst_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_cfg_add_vap_param_stru  param = {0};       /* ��������VAP�����ṹ�� */
    param.vap_mode = WLAN_VAP_MODE_CONFIG;
    ret = hmac_vap_init(hmac_vap, WLAN_CFG_VAP_ID, &param);
    if (ret != HI_SUCCESS) {
        oam_error_log1(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{hmac_cfg_vap_init::hmac_vap_init failed[%d].}", ret);
        return ret;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* ��ʱdmacδ�ϵ磬֡�����޷��·� */
#else
    /* ����֡���˼Ĵ��� */
    hmac_set_rx_filter_value(hmac_vap->base_vap);
#endif

    ret = hmac_vap_creat_netdev(hmac_vap, WLAN_CFG_VAP_NAME, (hi_s8 *) (mac_dev->auc_hw_addr), WLAN_MAC_ADDR_LEN);
    if (ret != HI_SUCCESS) {
        oam_error_log1(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{hmac_cfg_vap_init::hmac_vap_creat_netdev failed[%d].}",
                       ret);
        return ret;
    }
#ifndef _PRE_LINUX_BUILTIN
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    ret = hmac_cfg_vap_send_event(mac_dev);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_cfg_vap_send_event::hmac_config_send_event fail[%d].", ret);
        return ret;
    }
#endif
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼ��hmac device�������
 �޸���ʷ      :
  1.��    ��   : 2015��1��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_device_init(hi_void)
{
    mac_device_stru     *mac_dev = HI_NULL;
    hmac_device_stru    *hmac_dev = HI_NULL;
    hi_u32           ret;

    mac_dev = mac_res_get_dev();
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    mac_device_init(mac_dev);
#endif
    hmac_dev = hmac_get_device_stru();
    /* �ṹ���ʼ�� */
    if (memset_s(hmac_dev, sizeof(hmac_device_stru), 0, sizeof(hmac_device_stru)) != EOK) {
        return HI_FAIL;
    }
    /* ɨ��ģ���ʼ�� */
    hmac_scan_init(hmac_dev);
    /* ��ʼ��P2P �ȴ����� */
    hi_wait_queue_init_head(&(hmac_dev->netif_change_event));

#ifndef _PRE_WLAN_FEATURE_AMPDU_VAP
    /* ��ʼ��device�µ�rx tx BA�Ự��Ŀ */
    hmac_dev->rx_ba_session_num = 0;
    hmac_dev->tx_ba_session_num = 0;
#endif
    /* hmac mac vap��Դ��ʼ�� */
    ret = hmac_vap_res_init();
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_device_init::hmac_init_vap_res failed.}");
        return HI_FAIL;
    }
    /* hmac mac user ��Դ��ʼ�� */
    ret = hmac_user_res_init();
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_device_init::hmac_user_res_init failed.}");
        return HI_FAIL;
    }
    /* ����vap��ʼ�� */
    ret = hmac_cfg_vap_init(mac_dev);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log1(0, OAM_SF_ANY, "{hmac_device_init::cfg_vap_init failed[%d].}", ret);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
/* ��������  : ���µ�������host device_stru�ĳ�ʼ������ */
hi_u32 hmac_config_host_dev_init(mac_vap_stru *mac_vap, hi_u16 len, const hi_u8 *param)
{
#ifdef _PRE_WLAN_FEATURE_20_40_80_COEXIST
    mac_device_stru     *mac_device;
    hi_u32              ul_loop = 0;
#endif
#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    hmac_device_stru    *hmac_device;
#endif
    hi_unref_param(param);
    hi_unref_param(len);

    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_device_init:: pst_mac_device NULL pointer!}");
        return HI_FALSE;
    }

#ifdef _PRE_WLAN_FEATURE_20_40_80_COEXIST
    mac_device = mac_res_get_dev();
    if (mac_device == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_device_init:: pst_mac_device NULL pointer!}");
        return HI_FALSE;
    }

    for (ul_loop = 0; ul_loop < MAC_MAX_SUPP_CHANNEL; ul_loop++) {
        mac_device->st_ap_channel_list[ul_loop].us_num_networks = 0;
        mac_device->st_ap_channel_list[ul_loop].en_ch_type      = MAC_CH_TYPE_NONE;
    }
#endif

#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    hmac_device = hmac_get_device_stru();
    if (oal_unlikely(hmac_device == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_config_host_dev_init::pst_hmac_device null!}");
        return HI_FALSE;
    }
    hmac_pkt_mem_opt_init(hmac_device);
#endif

    /* �������µ�ʱ����Ҫ��ʼ����hmac_device_stru�µ���Ϣ */
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �µ�������host device_stru��ȥ��ʼ������
*****************************************************************************/
hi_u32 hmac_config_host_dev_exit(mac_vap_stru *pst_mac_vap, hi_u16 len, const hi_u8 *param)
{
#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    hmac_device_stru *hmac_device = hmac_get_device_stru();
    if (oal_unlikely(hmac_device == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_config_host_dev_exit::pst_hmac_device null!}");
        return HI_FALSE;
    }

    hmac_pkt_mem_opt_exit(hmac_device);
#endif

    hi_unref_param(pst_mac_vap);
    hi_unref_param(len);
    hi_unref_param(param);
    return HI_SUCCESS;
}
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

