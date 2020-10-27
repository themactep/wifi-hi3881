/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: The source file of the operation function corresponding to board, chip, and device.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include "oam_ext_if.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "mac_regdomain.h"
#include "mac_vap.h"
#ifdef _PRE_WLAN_ALG_ENABLE
#include "alg_dbac.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  ����ʵ��
*****************************************************************************/
/* mac device ȫ�ֱ��� */
WIFI_ROM_BSS mac_device_stru g_mac_dev;
WIFI_ROM_RODATA hi_u8 const g_mac_bcast_addr[WLAN_MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/*****************************************************************************
 ��������  : ��ȡmac devȫ�ֱ���
*****************************************************************************/
WIFI_ROM_TEXT mac_device_stru *mac_res_get_dev(hi_void)
{
    return &g_mac_dev;
}

WIFI_ROM_TEXT const hi_u8 *mac_get_mac_bcast_addr(hi_void)
{
    return g_mac_bcast_addr;
}

/*****************************************************************************
 ��������  : ��ʼ��device�������
 �޸���ʷ      :
  1.��    ��   : 2013��8��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_device_init(mac_device_stru *mac_dev)
{
    mac_dev->max_bandwidth = WLAN_BAND_WIDTH_20M;
    mac_dev->max_band      = WLAN_BAND_2G;
    mac_dev->max_channel   = 0;
    mac_dev->beacon_interval = WLAN_BEACON_INTVAL_DEFAULT;
    mac_dev->device_state = HI_TRUE;
    mac_dev->reset_switch = HI_FALSE;
    /* Ĭ�Ϲر�wmm,wmm��ʱ��������Ϊ0 */
    mac_dev->wmm = HI_TRUE;
    /* 1131h device�������λ2G 20M 11N */
    mac_dev->protocol_cap  = WLAN_PROTOCOL_CAP_HT;
    mac_dev->bandwidth_cap = WLAN_BW_CAP_20M;
    mac_dev->band_cap      = WLAN_BAND_CAP_2G;
    mac_dev->ldpc_coding  = HI_FALSE;
    mac_dev->tx_stbc      = HI_FALSE;
    mac_dev->rx_stbc      = 1;
    /* ��ʼ��vap numͳ����Ϣ */
    mac_dev->vap_num = 0;
    mac_dev->sta_num = 0;
#ifdef _PRE_WLAN_FEATURE_P2P_ROM
    mac_dev->p2p_info.p2p_device_num   = 0;
    mac_dev->p2p_info.p2p_goclient_num = 0;
#endif
    mac_init_regdomain();
    mac_init_channel_list();
    /* ��ʼ����λ״̬ */
    mac_dev->reset_in_progress = HI_FALSE;
    /* Ĭ�Ϲر�DBAC���� */
#ifdef _PRE_WLAN_FEATURE_DBAC
    mac_dev->dbac_enabled = HI_TRUE;
#endif
    mac_dev->in_suspend       = HI_FALSE;
    mac_dev->arpoffload_switch   = HI_FALSE;
    mac_dev->wapi = HI_FALSE;
}

/*****************************************************************************
 ��������  : Ѱ�Ҵ���UP״̬��VAP
 �������  : mac_device: device
 �������  : ppst_mac_vap  : vap
 �޸���ʷ      :
  1.��    ��   : 2014��11��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_device_find_up_vap(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap)
{
    hi_u8       vap_idx;
    mac_vap_stru   *mac_vap_value = HI_NULL;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap_value = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap_value == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_SCAN, "vap is null! vap id is %d", mac_dev->auc_vap_id[vap_idx]);
            *mac_vap = HI_NULL;
            return;
        }

        if (mac_vap_value->vap_state == MAC_VAP_STATE_UP || mac_vap_value->vap_state == MAC_VAP_STATE_PAUSE ||
            (mac_vap_value->vap_state == MAC_VAP_STATE_STA_LISTEN && mac_vap_value->user_nums > 0)) {
            *mac_vap = mac_vap_value;
            return;
        }
    }
    *mac_vap = HI_NULL;
}

/*****************************************************************************
 ��������  : �Ƿ�����������UP״̬��VAP
 �޸���ʷ      :
  1.��    ��   : 2019��6��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_device_has_other_up_vap(const mac_device_stru *mac_dev, const mac_vap_stru *mac_vap_ref)
{
    hi_u8       vap_idx;
    mac_vap_stru   *mac_vap = HI_NULL;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_SCAN, "vap is null! vap id is %d", mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        if ((mac_vap != mac_vap_ref) &&
            ((mac_vap->vap_state == MAC_VAP_STATE_UP) || (mac_vap->vap_state == MAC_VAP_STATE_PAUSE) ||
             ((mac_vap->vap_state == MAC_VAP_STATE_STA_LISTEN) && (mac_vap->user_nums > 0)))) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : Ѱ��2������UP״̬������VAP
 �������  : mac_device: device
 �������  : ppst_mac_vap  : vap
 �޸���ʷ      :
  1.��    ��   : 2014��11��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_device_find_2up_vap(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap1,
                                             mac_vap_stru **mac_vap2)
{
    mac_vap_stru                  *mac_vap = HI_NULL;
    hi_u8                          vap_idx;
    hi_u8                          up_vap_num = 0;
    mac_vap_stru                  *mac_vap_past[2] = {0}; /* vap numΪ2 */

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            oam_error_log1(0, OAM_SF_ANY, "vap is null, vap id is %d", mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        if ((mac_vap->vap_state == MAC_VAP_STATE_UP) || (mac_vap->vap_state == MAC_VAP_STATE_PAUSE) ||
            ((mac_vap->vap_state == MAC_VAP_STATE_STA_LISTEN) && (mac_vap->user_nums > 0)) ||
            (mac_vap->support_any == HI_TRUE)) {
            mac_vap_past[up_vap_num] = mac_vap;
            up_vap_num++;
            if (up_vap_num >= 2) { /* vap num����2���������� */
                break;
            }
        }
    }

    if (up_vap_num < 2) { /* vap numС��2Ϊ�쳣���� */
        return HI_FAIL;
    }
    *mac_vap1 = mac_vap_past[0];
    *mac_vap2 = mac_vap_past[1];
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����up��vap����
 �޸���ʷ      :
  1.��    ��   : 2014��11��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_device_calc_up_vap_num(const mac_device_stru *mac_dev)
{
    mac_vap_stru               *mac_vap = HI_NULL;
    hi_u8                       vap_idx;
    hi_u8                       up_ap_num = 0;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            oam_error_log1(0, OAM_SF_ANY, "vap is null, vap id is %d", mac_dev->auc_vap_id[vap_idx]);
            continue;
        }
        if ((mac_vap->vap_state == MAC_VAP_STATE_UP) || (mac_vap->vap_state == MAC_VAP_STATE_PAUSE) ||
            (mac_vap->support_any == HI_TRUE)) { /* ����֧��������any���͹��� */
            up_ap_num++;
        }
    }
    return up_ap_num;
}

/*****************************************************************************
 ��������  : Ѱ�Ҵ���UP״̬��STA
 �޸���ʷ      :
  1.��    ��   : 2015��6��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_device_find_up_vap_with_mode(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap,
    wlan_vap_mode_enum_uint8 vap_mode)
{
    hi_u8           vap_idx;
    mac_vap_stru   *mac_vap_value = HI_NULL;

    if (vap_mode != WLAN_VAP_MODE_MESH && vap_mode != WLAN_VAP_MODE_BSS_STA) {
        oam_error_log0(0, 0, "{mac_device_find_up_vap_with_mode::error vap mode.}");
        return HI_FAIL;
    }

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap_value = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap_value == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_SCAN, "vap is null! vap id is %d", mac_dev->auc_vap_id[vap_idx]);

            *mac_vap = HI_NULL;

            return HI_ERR_CODE_PTR_NULL;
        }

        if ((mac_vap_value->vap_state == MAC_VAP_STATE_UP || mac_vap_value->vap_state == MAC_VAP_STATE_PAUSE) &&
            (mac_vap_value->vap_mode == vap_mode)) {
            *mac_vap = mac_vap_value;
            return HI_SUCCESS;
        }
    }
    *mac_vap = HI_NULL;
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : Ѱ�Ҵ���UP״̬�� P2P_GO
 �������  : mac_device: device
 �������  : ppst_mac_vap  : vap
 �޸���ʷ      :
  1.��    ��   : 2014��11��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_device_find_up_p2p_go(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap)
{
    hi_u8       vap_idx;
    mac_vap_stru   *mac_vap_value = HI_NULL;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap_value = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap_value == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_SCAN, "vap is null! vap id is %d", mac_dev->auc_vap_id[vap_idx]);
            continue;
        }
        if ((mac_vap_value->vap_state == MAC_VAP_STATE_UP || mac_vap_value->vap_state == MAC_VAP_STATE_PAUSE) &&
            (mac_vap_value->p2p_mode == WLAN_P2P_GO_MODE)) {
            *mac_vap = mac_vap_value;

            return HI_SUCCESS;
        }
    }
    *mac_vap = HI_NULL;
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : �ж�p2p�豸�Ƿ����
 �������  : mac_device: device
 �޸���ʷ      :
  1.��    ��   : 2015��4��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_device_is_p2p_connected(const mac_device_stru *mac_dev)
{
    hi_u8       vap_idx;
    mac_vap_stru   *mac_vap = HI_NULL;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_P2P, "vap is null! vap id is %d", mac_dev->auc_vap_id[vap_idx]);
            return HI_ERR_CODE_PTR_NULL;
        }
        if ((is_p2p_go(mac_vap) || is_p2p_cl(mac_vap)) &&
           (mac_vap->user_nums > 0)) {
            return HI_SUCCESS;
        }
    }
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ����device��������ɾ��һ��vap������ά��vap����
*****************************************************************************/
hi_void mac_device_set_vap_id(mac_device_stru *mac_dev, mac_vap_stru *mac_vap,
                              const mac_cfg_add_vap_param_stru *param, hi_u8 vap_idx, hi_u8 is_add_vap)
{
    if (is_add_vap == HI_FALSE) {
        /* ɾ��VAP */
        mac_dev->auc_vap_id[mac_dev->vap_num--] = 0;
        if (param->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            if (param->p2p_mode == WLAN_LEGACY_VAP_MODE) {
                mac_dev->sta_num--;
                mac_vap->assoc_vap_id = 0xff;
#ifdef _PRE_WLAN_FEATURE_P2P
            } else if (param->p2p_mode == WLAN_P2P_CL_MODE || param->p2p_mode == WLAN_P2P_DEV_MODE) {
                mac_dec_p2p_num(mac_vap);
#endif
            }
#ifdef _PRE_WLAN_FEATURE_P2P
        } else if (param->vap_mode == WLAN_VAP_MODE_BSS_AP && param->p2p_mode == WLAN_P2P_GO_MODE) {
            mac_dec_p2p_num(mac_vap);
#endif
        }
    } else {
        /* ���VAP */
        mac_dev->auc_vap_id[mac_dev->vap_num++] = vap_idx;
        mac_vap->p2p_mode = param->p2p_mode;
        /* ��P2P VAP */
        if (param->p2p_mode == WLAN_LEGACY_VAP_MODE) {
            if (param->vap_mode == WLAN_VAP_MODE_BSS_STA) {
                mac_dev->sta_num++;
                mac_vap->assoc_vap_id = 0xff;
            }
#ifdef _PRE_WLAN_FEATURE_P2P
        } else {
            mac_inc_p2p_num(mac_vap);
#endif
        }
    }
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
