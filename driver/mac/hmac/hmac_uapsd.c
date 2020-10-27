/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: UAPSD hmac layer processing.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_vap.h"
#include "mac_frame.h"
#include "hmac_mgmt_ap.h"
#include "hmac_encap_frame_ap.h"
#include "hmac_rx_data.h"
#include "hmac_uapsd.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ����UAPSDʹ��
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_uapsden(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    mac_device_stru *mac_dev = HI_NULL;

    /* wmm */
    mac_dev = mac_res_get_dev();
    if (mac_dev->wmm == HI_FALSE) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_set_uapsden::wmm is off, not support uapsd mode}");
        return HI_FAIL;
    }

    /* mesh */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_PWR, "{hmac_config_set_uapsden::vap mode mesh,not support uapsd!}");
        return HI_FAIL;
    }

    /* խ�� */
    if ((mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_5M) ||
        (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_10M)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_PWR,
                         "{hmac_config_set_uapsden::narrow band[%dM] mode,not support uapsd!}",
                         mac_vap->channel.en_bandwidth);
        return HI_FAIL;
    }

    /* ����mibֵ */
    mac_vap_set_uapsd_en(mac_vap, *puc_param);
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_UAPSD_EN, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_uapsden::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

hi_void hmac_uapsd_set_info(const hi_u8 *puc_mac_hdr, const hmac_user_stru *hmac_user, hi_u8 uapsd_flag, hi_u32 idx,
    mac_user_uapsd_status_stru *uapsd_status)
{
    /* ����max SP���� */
    hi_u8 max_sp = (puc_mac_hdr[idx + HMAC_UAPSD_WME_LEN] >> 5) & 0x3; /* ����5λ */
    switch (max_sp) {
        case 1: /* 1 case ��־ */
            uapsd_status->max_sp_len = 2; /* ��ֵΪ2 */
            break;
        case 2: /* 2 case ��־ */
            uapsd_status->max_sp_len = 4; /* ��ֵΪ4 */
            break;
        case 3: /* 3 case ��־ */
            uapsd_status->max_sp_len = 6; /* ��ֵΪ6 */
            break;
        default:
            uapsd_status->max_sp_len = HMAC_UAPSD_SEND_ALL;
            break;
    }
    /* Send uapsd_flag & uapsd_status syn to dmac */
    mac_vap_stru *mac_vap = mac_vap_get_vap_stru(hmac_user->base_user->vap_id);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_uapsd_update_user_para::vap %d null}", hmac_user->base_user->vap_id);
        return;
    }
    hi_u16 us_len = sizeof(hi_u8);
    hi_u16 us_len_total = sizeof(hi_u8) + sizeof(hi_u8) + sizeof(mac_user_uapsd_status_stru);
    hi_u8 *puc_param = (hi_u8 *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, us_len_total);
    if (oal_unlikely(puc_param == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_uapsd_update_user_para::puc_param null.}");
        return;
    }
    // uc_user_index
    puc_param[0] = (hi_u8)hmac_user->base_user->us_assoc_id;
    // uc_uapsd_flag
    puc_param[us_len] = uapsd_flag;
    us_len++;
    // st_uapsd_status
    if (memcpy_s(puc_param + us_len, sizeof(mac_user_uapsd_status_stru), uapsd_status,
                 sizeof(mac_user_uapsd_status_stru)) != EOK) {
        oal_mem_free(puc_param);
        oam_error_log0(0, OAM_SF_CFG, "hmac_uapsd_update_user_para:: st_uapsd_status memcpy_s fail.");
        return;
    }
    us_len += sizeof(mac_user_uapsd_status_stru);

    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_UAPSD_UPDATE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_uapsd_update_user_para:hmac_config_send_event er%u}", ret);
    }
    oal_mem_free(puc_param);
}

/*****************************************************************************
 ��������  : uapsd������������е�WMM IE
 �޸���ʷ      :
  1.��    ��   : 2013��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_uapsd_update_user_para(const hi_u8 *puc_mac_hdr, hi_u8 sub_type, hi_u32 msg_len,
                                    const hmac_user_stru *hmac_user)
{
    hi_u8 found_wmm = HI_FALSE;
    hi_u8 en = HI_FALSE;
    hi_u8 uapsd_flag = 0;
    mac_user_uapsd_status_stru uapsd_status = {0};

    hi_u32 idx = MAC_CAP_INFO_LEN + MAC_LIS_INTERVAL_IE_LEN;
    if (WLAN_FC0_SUBTYPE_REASSOC_REQ == sub_type) {
        idx += WLAN_MAC_ADDR_LEN;
    }
    while (idx < msg_len) {
        if (HI_TRUE != mac_is_wmm_ie((puc_mac_hdr + idx))) {
            idx += (MAC_IE_HDR_LEN + puc_mac_hdr[(idx + 1)]);
            continue;
        }
        found_wmm = HI_TRUE;
        break;
    }
    /* ������WMM IE,ֱ�ӷ��� */
    if (found_wmm == HI_FALSE) {
        oam_warning_log1(hmac_user->base_user->vap_id, OAM_SF_PWR, "Could not find WMM IE in assoc req,user_id[%d]\n",
                         hmac_user->base_user->us_assoc_id);
        return;
    }

    uapsd_status.qos_info = puc_mac_hdr[idx + HMAC_UAPSD_WME_LEN];

    /* 8ΪWMM IE���� */
    if (BIT0 == (puc_mac_hdr[idx + HMAC_UAPSD_WME_LEN] & BIT0)) {
        uapsd_status.ac_trigger_ena[WLAN_WME_AC_VO] = 1;
        uapsd_status.ac_delievy_ena[WLAN_WME_AC_VO] = 1;
        en = HI_TRUE;
    }

    if (BIT1 == (puc_mac_hdr[idx + HMAC_UAPSD_WME_LEN] & BIT1)) {
        uapsd_status.ac_trigger_ena[WLAN_WME_AC_VI] = 1;
        uapsd_status.ac_delievy_ena[WLAN_WME_AC_VI] = 1;
        en = HI_TRUE;
    }

    if (BIT2 == (puc_mac_hdr[idx + HMAC_UAPSD_WME_LEN] & BIT2)) {
        uapsd_status.ac_trigger_ena[WLAN_WME_AC_BK] = 1;
        uapsd_status.ac_delievy_ena[WLAN_WME_AC_BK] = 1;
        en = HI_TRUE;
    }

    if (BIT3 == (puc_mac_hdr[idx + HMAC_UAPSD_WME_LEN] & BIT3)) {
        uapsd_status.ac_trigger_ena[WLAN_WME_AC_BE] = 1;
        uapsd_status.ac_delievy_ena[WLAN_WME_AC_BE] = 1;
        en = HI_TRUE;
    }

    if (en == HI_TRUE) {
        uapsd_flag |= MAC_USR_UAPSD_EN;
    }

    hmac_uapsd_set_info(puc_mac_hdr, hmac_user, uapsd_flag, idx, &uapsd_status);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

