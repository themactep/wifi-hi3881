/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: mac_vap.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include "oal_mem.h"
#include "wlan_types.h"
#include "mac_vap.h"
#include "mac_device.h"
#include "mac_regdomain.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
/*****************************************************************************
 ��������  : ����Mesh IDֵ
 �������  : [1]mac_vap mac vap�ṹ��
             [2]len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_mib_set_meshid(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    mac_cfg_ssid_param_stru *param = HI_NULL;
    hi_u8 *puc_mib_meshid = HI_NULL;
    hi_u8 meshid_len;

    hi_unref_param(len);

    param = (mac_cfg_ssid_param_stru *)puc_param;
    meshid_len = param->ssid_len; /* ���Ȳ������ַ�����β'\0' */
    /* uc_len ���Ȳ������ַ�����β'\0' */
    if (meshid_len > WLAN_SSID_MAX_LEN - 1) {
        meshid_len = WLAN_SSID_MAX_LEN - 1;
    }
    puc_mib_meshid = mac_vap->mib_info->wlan_mib_mesh_sta_cfg.auc_dot11_mesh_id;
    if (memcpy_s(puc_mib_meshid, WLAN_SSID_MAX_LEN, param->ac_ssid, meshid_len) != EOK) {
        return HI_FAIL;
    }
    puc_mib_meshid[meshid_len] = '\0';
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡMesh IDֵ
 �������  : [1]mac_vap mac vap�ṹ��
             [2]puc_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_mib_get_meshid(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param)
{
    mac_cfg_ssid_param_stru *param = HI_NULL;
    hi_u8                    meshid_len;
    hi_u8                   *puc_mib_meshid = HI_NULL;

    puc_mib_meshid = mac_vap->mib_info->wlan_mib_mesh_sta_cfg.auc_dot11_mesh_id;
    meshid_len  = (hi_u8)strlen((hi_char *)puc_mib_meshid);

    param = (mac_cfg_ssid_param_stru *)puc_param;

    param->ssid_len = meshid_len;
    if (memcpy_s(param->ac_ssid, WLAN_SSID_MAX_LEN, puc_mib_meshid, meshid_len) != EOK) {
        return HI_FAIL;
    }

    *puc_len = sizeof(mac_cfg_ssid_param_stru);

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ��ȡʵ�ֵ�pairwise cipher suites����
 �������  : pst_mac_vap: ָ��vap
 �������  : puc_num    : ʵ�ֵ�pairwise cipher suites����
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_mib_get_wpa_pairwise_cipher_suite(const mac_vap_stru *mac_vap, hi_u8 *puc_num)
{
    hi_u8   num = 0;
    hi_u8   loop;
    wlan_mib_dot11_rsna_cfg_pwise_cpher_en_stru *wlan_mib_rsna_cfg_wpa_pairwise_cipher;

    wlan_mib_rsna_cfg_wpa_pairwise_cipher = mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher;

    for (loop = 0; loop < WLAN_PAIRWISE_CIPHER_SUITES; loop++) {
        if (wlan_mib_rsna_cfg_wpa_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_activated) {
            num++;
        }
    }
    *puc_num = num;
}

/*****************************************************************************
 ��������  : ��ȡʵ�ֵ�pairwise cipher suites����
 �������  : pst_mac_vap: ָ��vap
 �������  : puc_num    : ʵ�ֵ�pairwise cipher suites����
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_mib_get_wpa2_pairwise_cipher_suite(const mac_vap_stru *mac_vap, hi_u8 *puc_num)
{
    hi_u8   num = 0;
    hi_u8   loop;
    wlan_mib_dot11_rsna_cfg_pwise_cpher_en_stru *wlan_mib_rsna_cfg_wpa2_pairwise_cipher;

    wlan_mib_rsna_cfg_wpa2_pairwise_cipher = mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher;

    for (loop = 0; loop < WLAN_PAIRWISE_CIPHER_SUITES; loop++) {
        if (wlan_mib_rsna_cfg_wpa2_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_activated) {
            num++;
        }
    }
    *puc_num = num;
}

/*****************************************************************************
 ��������  : ��ȡʵ�ֵ�authentication suites����
 �������  : pst_mac_vap: ָ��vap
 �������  : puc_num    : ʵ�ֵ�authentication suites����
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2019��1��23��
    ��    ��   : Hisilicon
    �޸�����   : ��������uc_is_mesh_rsn

*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_mib_get_authentication_suite(const mac_vap_stru *mac_vap, hi_u8 *puc_num)
{
    hi_u8 num = 0;
    hi_u8 loop;
    hi_u8 auth_suite_num = MAC_AUTHENTICATION_SUITE_NUM;
    wlan_mib_dot11_rsna_cfg_authentication_suites_en_stru *wlan_mib_rsna_cfg_auth_suite;

    wlan_mib_rsna_cfg_auth_suite = mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite;

    for (loop = 0; loop < auth_suite_num; loop++) {
        if (wlan_mib_rsna_cfg_auth_suite[loop].dot11_rsna_config_authentication_suite_activated) {
            num++;
        }
    }
    *puc_num = num;
}

/*****************************************************************************
 ��������  : ��ȡʵ�ֵ�pairwise cipher suites �����׼�ֵ
 �������  : pst_mac_vap        : ָ��vap
 �������  : puc_pairwise_value : ʵ�ֵ�pairwise cipher suites �����׼�ֵ
 �޸���ʷ      :
  1.��    ��   : 2014��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_mib_get_wpa2_pairwise_cipher_suite_value(const mac_vap_stru *mac_vap,
    hi_u8 *puc_pairwise_value, hi_u8 pairwise_len)
{
    hi_u8 loop;
    hi_u8 pairwise_index = 0;
    wlan_mib_dot11_rsna_cfg_pwise_cpher_en_stru *wlan_mib_rsna_cfg_wpa2_pairwise_cipher;

    wlan_mib_rsna_cfg_wpa2_pairwise_cipher = mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher;

    for (loop = 0; loop < pairwise_len; loop++) {
        if (wlan_mib_rsna_cfg_wpa2_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_activated) {
            puc_pairwise_value[pairwise_index++] =
                wlan_mib_rsna_cfg_wpa2_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_implemented;
        }
    }
}

/*****************************************************************************
 ��������  : ��ȡʵ�ֵ�pairwise cipher suites �����׼�ֵ
 �������  : pst_mac_vap        : ָ��vap
 �������  : puc_pairwise_value : ʵ�ֵ�pairwise cipher suites �����׼�ֵ
 �޸���ʷ      :
  1.��    ��   : 2014��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_mib_get_wpa_pairwise_cipher_suite_value(const mac_vap_stru *mac_vap,
    hi_u8 *puc_pairwise_value, hi_u8 pairwise_len)
{
    hi_u8 loop;
    hi_u8 pairwise_index = 0;
    wlan_mib_dot11_rsna_cfg_pwise_cpher_en_stru *wlan_mib_rsna_cfg_wpa_pairwise_cipher;

    wlan_mib_rsna_cfg_wpa_pairwise_cipher = mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher;

    for (loop = 0; loop < pairwise_len; loop++) {
        if (wlan_mib_rsna_cfg_wpa_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_activated) {
            puc_pairwise_value[pairwise_index++] =
                wlan_mib_rsna_cfg_wpa_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_implemented;
        }
    }
}

/*****************************************************************************
 ��������  : ���� RSN��֤�׼���Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��08��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_mib_set_rsna_auth_suite(const mac_vap_stru *mac_vap, hi_u8 auth_value)
{
    hi_u8 index;

    if ((auth_value == WLAN_AUTH_SUITE_1X) || (auth_value == WLAN_AUTH_SUITE_PSK)) {
        index = 0;
    } else if ((auth_value == WLAN_AUTH_SUITE_1X_SHA256) || (auth_value == WLAN_AUTH_SUITE_PSK_SHA256)) {
        index = 1;
    } else {
        return;
    }
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[index].dot11_rsna_config_authentication_suite_implemented = \
        auth_value;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[index].dot11_rsna_config_authentication_suite_activated   = \
        HI_TRUE;
}

WIFI_ROM_TEXT hi_void mac_mib_set_rsnaconfig_wpa_pairwise_cipher_implemented(const mac_vap_stru *mac_vap,
    hi_u8 pairwise_value)
{
    hi_u8 index;

    if (pairwise_value == WLAN_80211_CIPHER_SUITE_CCMP) {
        index = 0;
    } else if (pairwise_value == WLAN_80211_CIPHER_SUITE_TKIP) {
        index = 1;
    } else {
        hi_diag_log_msg_e1(247, /* line:247 as id */
            "{mac_mib_set_RSNAConfigWpaPairwiseCipherImplemented::invalid uc_pairwise_value[%d].}", pairwise_value);
        return;
    }
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_implemented =
        pairwise_value;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_activated =
        HI_TRUE;
}

WIFI_ROM_TEXT hi_void mac_mib_set_rsnaconfig_wpa2_pairwise_cipher_implemented(const mac_vap_stru *mac_vap,
    hi_u8 pairwise_value)
{
    hi_u8 index;

    if (pairwise_value == WLAN_80211_CIPHER_SUITE_CCMP) {
        index = 0;
    } else if (pairwise_value == WLAN_80211_CIPHER_SUITE_TKIP) {
        index = 1;
    } else {
        hi_diag_log_msg_e1(267, /* line:267 as id */
            "{mac_mib_set_RSNAConfigWpa2PairwiseCipherImplemented::invalid uc_pairwise_value[%d].}", pairwise_value);
        return;
    }
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_implemented =
        pairwise_value;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_activated =
        HI_TRUE;
}

/*****************************************************************************
 ��������  : ����ssid mibֵ
 �������  : pst_mac_vap: ָ��mac vap�ṹ��
             uc_len     : ��������
             pc_param   : ����
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_mib_set_ssid(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    mac_cfg_ssid_param_stru    *param = HI_NULL;
    hi_u8                   ssid_len;
    hi_u8                  *puc_mib_ssid = HI_NULL;
    hi_unref_param(len);
    param   = (mac_cfg_ssid_param_stru *)puc_param;
    ssid_len = param->ssid_len;       /* ���Ȳ������ַ�����β'\0' */
    if (ssid_len > WLAN_SSID_MAX_LEN - 1) {
        ssid_len = WLAN_SSID_MAX_LEN - 1;
    }
    puc_mib_ssid = mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid;
    if (memcpy_s(puc_mib_ssid, WLAN_SSID_MAX_LEN, param->ac_ssid, ssid_len) != EOK) {
        return HI_FAIL;
    }
    puc_mib_ssid[ssid_len] = '\0';
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡssid mibֵ
*****************************************************************************/
hi_u32  mac_mib_get_ssid(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param)
{
    mac_cfg_ssid_param_stru *param = HI_NULL;
    hi_u8                ssid_len;
    hi_u8               *puc_mib_ssid = HI_NULL;

    puc_mib_ssid = mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid;
    ssid_len  = (hi_u8)strlen((hi_char *)puc_mib_ssid);
    param = (mac_cfg_ssid_param_stru *)puc_param;
    param->ssid_len = ssid_len;
    if (memcpy_s(param->ac_ssid, WLAN_SSID_MAX_LEN, puc_mib_ssid, ssid_len) != EOK) {
        return HI_FAIL;
    }
    *puc_len = sizeof(mac_cfg_ssid_param_stru);
    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

