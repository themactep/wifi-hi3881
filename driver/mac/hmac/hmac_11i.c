/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: STA side management frame processing.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_resource.h"
#include "mac_frame.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "mac_vap.h"
#include "hmac_11i.h"
#include "hmac_main.h"
#include "hmac_ext_if.h"
#include "hmac_crypto_tkip.h"
#include "hmac_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
#define cipher_suite_no_encrpy(i) (((i) & WLAN_ENCRYPT_BIT) ? 0 : 1)
#define cipher_suite_is_wep104(i) ((((i) & WLAN_WEP104_BIT) == WLAN_WEP104_BIT) ? 1 : 0)
#define cipher_suite_is_wep40(i)  ((((i) & WLAN_WEP104_BIT) == WLAN_WEP_BIT) ? 1 : 0)
#define cipher_suite_is_wpa(i)    ((((i) & WLAN_WPA_BIT) == WLAN_WPA_BIT) ? 1 : 0)
#define cipher_suite_is_wpa2(i)   ((((i) & WLAN_WPA2_BIT) == WLAN_WPA2_BIT) ? 1 : 0)
#define cipher_suite_is_tkip(i)   ((((i) & WLAN_TKIP_BIT) == WLAN_TKIP_BIT) ? 1 : 0)
#define cipher_suite_is_ccmp(i)   ((((i) & WLAN_CCMP_BIT) == WLAN_CCMP_BIT) ? 1 : 0)

/*****************************************************************************
 ��������  : ��ȡkey
 �޸���ʷ      :
  1.��    ��   : 2013��11��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static wlan_priv_key_param_stru *hmac_get_key_info(mac_vap_stru *mac_vap, hi_u8 *mac_addr,
                                                   hi_u8 pairwise, hi_u8 key_index,
                                                   hi_u8 *pus_user_idx)
{
    hi_u32 ret;
    mac_user_stru *mac_user = HI_NULL;
    hi_u8 macaddr_is_zero;

    if (mac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_WPA, "{hmac_get_key_info::mac_vap=%p,mac_addr=%p.}", (uintptr_t)mac_vap);
        return HI_NULL;
    }

    /* 1.1 ����mac addr �ҵ���Ӧsta������ */
    macaddr_is_zero = mac_addr_is_zero(mac_addr);
    if (!mac_11i_is_ptk(macaddr_is_zero, pairwise)) {
        /* ������鲥�û�������ʹ��mac��ַ������,���������ҵ��鲥user�ڴ����� */
        *pus_user_idx = mac_vap->multi_user_idx;
    } else {                    /* �����û� */
        ret = mac_vap_find_user_by_macaddr(mac_vap, mac_addr, OAL_MAC_ADDR_LEN, pus_user_idx);
        if (ret != HI_SUCCESS) {
            return HI_NULL;
        }
    }

    mac_user = mac_user_get_user_stru(*pus_user_idx);
    if (mac_user == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_get_key_info::mac_res_get_mutil_mac_user null.}");
        return HI_NULL;
    }

    oam_info_log2(mac_vap->vap_id, OAM_SF_WPA,
                  "{hmac_get_key_info::key_index=%d,pairwise=%d.}", key_index, pairwise);

    if (mac_addr != HI_NULL) {
        oam_info_log4(mac_vap->vap_id, OAM_SF_WPA,
                  "{hmac_get_key_info::mac_addr[%d] = XX:XX:XX:%02X:%02X:%02X.}",
                  *pus_user_idx, mac_addr[3], mac_addr[4], mac_addr[5]); /* 3 4 5 Ԫ������ */
    }

    return mac_user_get_key(mac_user, key_index);
}

#ifdef _PRE_WLAN_FEATURE_WAPI
/*****************************************************************************
 ��������  : ����wapi key
 �޸���ʷ      :
  1.��    ��   : 2015��2��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_wapi_add_key(mac_vap_stru *mac_vap, mac_addkey_param_stru *payload_addkey_params)
{
    hi_u8 key_index;
    hi_u8 pairwise;
    hi_u8 *mac_addr = HI_NULL;
    mac_key_params_stru *key_param = HI_NULL;
    hmac_wapi_stru *wapi = HI_NULL;
    hi_u32 ret;
    hi_u8  user_index = 0;
    mac_device_stru *mac_dev = HI_NULL;

    key_index = payload_addkey_params->key_index;
    if (key_index >= HMAC_WAPI_MAX_KEYID) {
        oam_error_log1(0, OAM_SF_WPA, "{hmac_config_wapi_add_key::keyid==%u Err!.}", key_index);
        return HI_FAIL;
    }

    pairwise = payload_addkey_params->pairwise;
    mac_addr = (hi_u8 *)payload_addkey_params->auc_mac_addr;
    key_param = &payload_addkey_params->key;

    if (key_param->key_len != (WAPI_KEY_LEN * 2)) /* ����2�� */
        if (key_param->key_len != (WAPI_KEY_LEN * 2)) { /* ����2�� */
            oam_error_log1(0, OAM_SF_WPA, "{hmac_config_wapi_add_key:: key_len %d Err!.}", key_param->key_len);
            return HI_FAIL;
        }

    if (pairwise == HI_TRUE) {
        ret = mac_vap_find_user_by_macaddr(mac_vap, mac_addr, OAL_MAC_ADDR_LEN, &user_index);
        if (ret != HI_SUCCESS) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_ANY,
                           "{hmac_config_wapi_add_key::mac_vap_find_user_by_macaddr failed. %u}", ret);
            return HI_FAIL;
        }
    }

    wapi = hmac_user_get_wapi_ptr(mac_vap, pairwise, user_index);
    if (wapi == HI_NULL) {
        oam_error_log0(0, OAM_SF_WPA, "{hmac_config_wapi_add_key:: get pst_wapi  Err!.}");
        return HI_FAIL;
    }

    hmac_wapi_add_key(wapi, key_index, key_param->auc_key);
    mac_dev = mac_res_get_dev();
    mac_dev->wapi = HI_TRUE;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����wapi key����ͬ��
 �޸���ʷ      :
  1.��    ��   : 2015��2��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ��ͬһ���¼��ص���������ģ��Ķ�һ����Ҫ�Ķ����еġ���Щ��Ҫconst ��Щ����Ҫ������û�а취�ģ�lint_t�澯���� */
hi_u32 hmac_config_wapi_add_key_and_sync(const mac_vap_stru *mac_vap,
                                         mac_addkey_param_stru *payload_addkey_params)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u32 ret;

    oam_warning_log2(0, OAM_SF_WPA, "{hmac_config_wapi_add_key_and_sync:: key idx==%u, pairwise==%u}",
                     payload_addkey_params->key_index, payload_addkey_params->pairwise);

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_wapi_add_key_and_sync::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    ret = hmac_config_wapi_add_key(hmac_vap->base_vap, payload_addkey_params);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_wapi_add_key_and_sync::hmac_config_wapi_add_key fail[%d].}", ret);
        return ret;
    }

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_ADD_WAPI_KEY, 0, HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_wapi_add_key_and_sync::WLAN_CFGID_ADD_WAPI_KEY send fail[%d].}", ret);
        return ret;
    }

    return ret;
}
#endif /* #ifdef _PRE_WLAN_FEATURE_WAPI */

/*****************************************************************************
 �� �� ��  : hmac_config_11i_add_key
 ��������  : add key �߼������¼���DMAC
 �������  : frw_event_mem_stru *event_mem
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��12��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_11i_add_key(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8                  user_idx = 0;

    /* 2.1 ��ȡ���� */
    mac_addkey_param_stru *payload_addkey_params = (mac_addkey_param_stru *)puc_param;
    hi_u8 key_index = payload_addkey_params->key_index;
    hi_u8 pairwise  = payload_addkey_params->pairwise;
    hi_u8 *mac_addr = (hi_u8 *)payload_addkey_params->auc_mac_addr;
    mac_key_params_stru *key = &(payload_addkey_params->key);

#ifdef _PRE_WLAN_FEATURE_WAPI
    if (oal_unlikely(key->cipher == WLAN_CIPHER_SUITE_SMS4)) {
        return hmac_config_wapi_add_key_and_sync(mac_vap, payload_addkey_params);
    }
#endif

    /* 2.2 ����ֵ���ֵ��� */
    if (key_index >= WLAN_NUM_TK + WLAN_NUM_IGTK) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_key::invalid uc_key_index[%d].}", key_index);
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    oam_info_log3(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_key::mac addr=XX:XX:XX:%02X:%02X:%02X}",
                  mac_addr[3], mac_addr[4], mac_addr[5]); /* 3 4 5 Ԫ������ */

    if (pairwise == HI_TRUE) {
        /* ������Կ����ڵ����û��� */
        if (mac_vap_find_user_by_macaddr(mac_vap, mac_addr, OAL_MAC_ADDR_LEN, &user_idx) != HI_SUCCESS) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_key::find_user_by_macaddr fail.}");
            return HI_FAIL;
        }
    } else {
        /* �鲥��Կ������鲥�û��� */
        user_idx = mac_vap->multi_user_idx;
    }

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_key::get_mac_user null.idx:%u}", user_idx);
        return HI_ERR_CODE_SECURITY_USER_INVAILD;
    }
#ifdef _PRE_WLAN_FEATURE_WAPI
    /* 11i������£��ص�wapi�˿� */
    hmac_wapi_reset_port(&hmac_user->wapi);
    mac_device_stru *mac_dev = mac_res_get_dev();
    mac_dev->wapi = HI_FALSE;
#endif

    /* 3.1 ���������Ը��µ��û��� */
    hi_u32 ret = mac_vap_add_key(mac_vap, hmac_user->base_user, key_index, key);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_key::mac_11i_add_key fail[%d].}", ret);
        return ret;
    }
    /* �����û�8021x�˿ںϷ��Ե�״̬Ϊ�Ϸ� */
    hmac_user->base_user->port_valid = HI_TRUE;

    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_ADD_KEY, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_key:hmac_config_send_event fail[%d]}", ret);
    }

    return ret;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
��������  : ��ȡ��Կ������Ҫ���¼���DMAC,ֱ�Ӵ�hmac��������������
�������  : frw_event_mem_stru *event_mem
�� �� ֵ  : 0:�ɹ�,����:ʧ��
�޸���ʷ      :
1.��    ��   : 2013��8��16��
    ��    ��   : Hisilicon
  �޸�����   : �����ɺ���
2.��    ��   : 2014��1��4��
    ��    ��   : Hisilicon
  �޸�����   : ʹ�þֲ��������malloc���Լ����ͷ��ڴ�ĸ��Ӷ�
*****************************************************************************/
hi_u32 hmac_config_11i_get_key(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    wlan_priv_key_param_stru *priv_key = HI_NULL;
    oal_key_params_stru key;
    hi_u8 key_index;
    hi_u8 pairwise;
    hi_u8 *mac_addr = HI_NULL;
    hi_void *cookie = HI_NULL;
    mac_getkey_param_stru *payload_getkey_params = HI_NULL;
    hi_u8 us_user_idx  = MAC_INVALID_USER_ID;
    hi_unref_param(us_len);

    /* 2.1 ��ȡ���� */
    payload_getkey_params = (mac_getkey_param_stru *)puc_param;
    key_index = payload_getkey_params->key_index;
    pairwise = payload_getkey_params->pairwise;
    mac_addr = payload_getkey_params->puc_mac_addr;
    cookie = payload_getkey_params->cookie;

    /* 2.2 ����ֵ���ֵ��� */
    if (key_index >= WLAN_NUM_TK + WLAN_NUM_IGTK) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_get_key::uc_key_index invalid[%d].}",
                       key_index);
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    /* 3.1 ��ȡ��Կ */
    priv_key = hmac_get_key_info(mac_vap, mac_addr, pairwise, key_index, &us_user_idx);
    if (priv_key == HI_NULL) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_11i_get_key::key is null.pairwise[%d], key_idx[%d]}", pairwise, key_index);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �Ĵ����ֻ�ȡ��Կ��Ϣ����Ϊ0 ������ֵ,��Ӧ��Ϊerror �����ӡ */
    if (priv_key->key_len == 0) {
        oam_info_log2(mac_vap->vap_id, OAM_SF_WPA,
                      "{hmac_config_11i_get_key::key len = 0.pairwise[%d], key_idx[%d]}", pairwise, key_index);
        return HI_ERR_CODE_SECURITY_KEY_LEN;
    }

    /* 4.1 ��Կ��ֵת�� */
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&key, sizeof(oal_key_params_stru), 0, sizeof(key));
    key.key = priv_key->auc_key;
    key.key_len = (hi_s32) priv_key->key_len;
    key.seq = priv_key->auc_seq;
    key.seq_len = (hi_s32) priv_key->seq_len;
    key.cipher = priv_key->cipher;

    /* 5.1 ���ûص����� */
    if (payload_getkey_params->callback != HI_NULL) {
        payload_getkey_params->callback(cookie, &key);
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ����remove key�¼������¼���DMAC
 �������  : mac_vap_stru *pst_mac_vap, hi_u16 us_len, hi_u8 *puc_param
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_11i_remove_key(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *param)
{
    mac_removekey_param_stru *removekey = (mac_removekey_param_stru *)param;
    mac_user_stru            *mac_user  = HI_NULL;
    wlan_cfgid_enum_uint16    cfgid     = WLAN_CFGID_REMOVE_WEP_KEY;
    hi_u8                     user_idx  = MAC_INVALID_USER_ID;

    /* 2.1 ��ȡ���� */
    hi_u8 key_index = removekey->key_index;
    hi_u8 pairwise  = removekey->pairwise;

    oam_info_log2(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_remove_key::key%d,pairwise%d}", key_index, pairwise);

    /* 2.2 ����ֵ���ֵ��� */
    if ((key_index >= WLAN_NUM_TK + WLAN_NUM_IGTK) || (key_index >= WLAN_NUM_DOT11WEPDEFAULTKEYVALUE)) {
        /* �ں˻��·�ɾ��6 ���鲥��Կ����������6���鲥��Կ����ռ� */
        oam_info_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_remove_key::invalid key_index%d}", key_index);
        return HI_SUCCESS;
    }

    /* 3.1 ��ȡ������Կ��Ϣ */
    wlan_priv_key_param_stru *key = hmac_get_key_info(mac_vap, removekey->auc_mac_addr, pairwise, key_index, &user_idx);
    if (key == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_remove_key::user_idx=%d}", user_idx);
        return ((user_idx == MAC_INVALID_USER_ID) ? HI_SUCCESS : HI_ERR_CODE_SECURITY_USER_INVAILD);
    }

    if (key->key_len == 0) {
        /* �����⵽��Կû��ʹ�ã� ��ֱ�ӷ�����ȷ */
        oam_info_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_remove_key::ul_key_len=0.}");
        return HI_SUCCESS;
    }

    /* 4.1 ������wep����wpa */
    if ((key->cipher == WLAN_CIPHER_SUITE_WEP40) || (key->cipher == WLAN_CIPHER_SUITE_WEP104)) {
        mac_mib_set_wep(mac_vap, key_index);
    } else {
        hi_u8 macaddr_is_zero = mac_addr_is_zero(removekey->auc_mac_addr);
        if (mac_11i_is_ptk(macaddr_is_zero, pairwise)) {
            mac_user = mac_vap_get_user_by_addr(mac_vap, removekey->auc_mac_addr);
            if (mac_user == HI_NULL) {
                return HI_ERR_CODE_SECURITY_USER_INVAILD;
            }
            mac_user->user_tx_info.security.cipher_key_type = HAL_KEY_TYPE_BUTT;
        } else {
            mac_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
            if (mac_user == HI_NULL) {
                return HI_ERR_CODE_SECURITY_USER_INVAILD;
            }
        }
        cfgid = WLAN_CFGID_REMOVE_KEY;
        mac_user->port_valid = HI_FALSE;
    }

    /* 4.2 ���¼���dmac�㴦�� */
    hi_u32 ret = hmac_config_send_event(mac_vap, cfgid, us_len, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_remove_key:SendEvent Err%d,cfgid%d}", ret, cfgid);
        return ret;
    }

    /* 5.1 ɾ����Կ�ɹ���������Կ����Ϊ0 */
    key->key_len = 0;

    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_config_11i_set_default_key
 ��������  : ����set default key�¼������¼���DMAC
 �������  : mac_vap_stru *pst_mac_vap, hi_u16 us_len, hi_u8 *puc_param
 �������  : hi_u32
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2014��7��31��
    ��    ��   : Hisilicon
    �޸�����   : �ϲ���������֡Ĭ����Կ�����ù���֡Ĭ����Կ����
*****************************************************************************/
/* ��ͬһ���¼��ص���������ģ��Ķ�һ����Ҫ�Ķ����еġ���Щ��Ҫconst ��Щ����Ҫ������û�а취�ģ�lint_t�澯���� */
hi_u32 hmac_config_11i_set_default_key(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret = HI_SUCCESS;
    hi_u8 key_index;
    hi_u8 unicast;
    hi_u8 multicast;
    mac_setdefaultkey_param_stru *payload_setdefaultkey_params = HI_NULL;

    /* 2.1 ��ȡ���� */
    payload_setdefaultkey_params = (mac_setdefaultkey_param_stru *)puc_param;
    key_index = payload_setdefaultkey_params->key_index;
    unicast = payload_setdefaultkey_params->unicast;
    multicast = payload_setdefaultkey_params->multicast;

    /* 2.2 ����ֵ���ֵ��� */
    if (key_index >= (WLAN_NUM_TK + WLAN_NUM_IGTK)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_11i_set_default_key::invalid uc_key_index[%d].}", key_index);
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    /* 2.3 ������Ч�Լ�� */
    if ((multicast == HI_FALSE) && (unicast == HI_FALSE)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_11i_set_default_key::not ptk or gtk,invalid mode.}");
        return HI_ERR_CODE_SECURITY_PARAMETERS;
    }

    if (key_index >= WLAN_NUM_TK) {
        /* 3.1 ����default mgmt key���� */
        ret = mac_vap_set_default_mgmt_key(mac_vap, key_index);
    } else {
        ret = mac_vap_set_default_key(mac_vap, key_index);
    }

    if (ret != HI_SUCCESS) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_11i_set_default_key::set key[%d] failed[%d].}", key_index, ret);
        return ret;
    }

    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DEFAULT_KEY, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_11i_set_default_key::hmac_config_send_event failed[%d].}", ret);
    }
    oam_info_log3(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_set_default_key::key_id[%d] un[%d] mu[%d] OK}",
                  key_index, unicast, multicast);
    return ret;
}

/*****************************************************************************
 ��������  : add wep���ܣ����¼���DMAC
 �������  : mac_vap_stru *pst_mac_vap, hi_u16 us_len, hi_u8 *puc_param
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_11i_add_wep_entry(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_user_stru *mac_user = HI_NULL;
    hi_u32 ret;

    mac_user = mac_vap_get_user_by_addr(mac_vap, puc_param);
    if (mac_user == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_11i_add_wep_entry::mac_user NULL}");
        return HI_ERR_CODE_PTR_NULL;
    }

    ret = mac_user_update_wep_key(mac_user, mac_vap->multi_user_idx);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_11i_add_wep_entry::mac_wep_add_usr_key failed[%d].}", ret);
        return ret;
    }

    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_ADD_WEP_ENTRY, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                         "{hmac_config_11i_add_wep_entry::hmac_config_send_event failed[%d].}", ret);
    }

    /* �����û��ķ��ͼ����׼� */
    oam_info_log1(mac_vap->vap_id, OAM_SF_WPA,
                  "{hmac_config_11i_add_wep_entry:: usridx[%d] OK.}", mac_user->us_assoc_id);

    return ret;
}

/*****************************************************************************
 ��������  : ��ʼ���������ݡ�
 �޸���ʷ      :
  1.��    ��   : 2013��10��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_init_security(mac_vap_stru *mac_vap, hi_u8 *mac_addr, hi_u16 addr_len)
{
    hi_u32 ret = HI_SUCCESS;
    hi_u16 us_len;
    hi_u8 *puc_param = HI_NULL;

    if (mac_is_wep_enabled(mac_vap) == HI_TRUE) {
        puc_param = mac_addr;
        us_len = addr_len;
        ret = hmac_config_11i_add_wep_entry(mac_vap, us_len, puc_param);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ��ⵥ��wpa��Կ�Ƿ�ƥ��
 �������  : wlan_mib_ieee802dot11_stru *pst_mib_info
             hi_u8 uc_policy
 �� �� ֵ  : hi_u8    HI_TRUE:ƥ��ɹ�
                                    HI_FALSE:ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_check_pcip_wpa_policy(const wlan_mib_ieee802dot11_stru *mib_info, hi_u8 policy)
{
    hi_u8 loop = 0;
    for (loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
        /* ��ⵥ����Կ�Ƿ�ʹ�ܺ�ƥ�� */
        if ((mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_activated ==
            HI_TRUE)
            && (mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_implemented
                == policy)) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ��ⵥ��wpa2��Կ�Ƿ�ƥ��
 �������  : wlan_mib_ieee802dot11_stru *pst_mib_info
             hi_u8 uc_policy
 �� �� ֵ  : hi_u8    HI_TRUE:ƥ��ɹ�
                                    HI_FALSE:ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_check_pcip_wpa2_policy(const wlan_mib_ieee802dot11_stru *mib_info, hi_u8 policy)
{
    hi_u8 loop = 0;
    for (loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
        /* ��ⵥ����Կ�Ƿ�ʹ�ܺ�ƥ�� */
        if ((mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_activated ==
            HI_TRUE)
            && (mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[loop].dot11_rsna_config_pairwise_cipher_implemented
                == policy)) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ��ⵥ����Կ�Ƿ�ƥ��
 �������  : wlan_mib_ieee802dot11_stru *pst_mib_info
             hi_u8 uc_policy
             hi_u8 uc_80211i_mode
 �� �� ֵ  : hi_u32    HI_SUCCESS:ƥ��ɹ�
                           HI_FAIL:ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��12��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_check_pcip_policy(const wlan_mib_ieee802dot11_stru *mib_info,
                              hi_u8 policy, hi_u8 is_80211i_mode)
{
    hi_u8 ret = HI_FALSE;

    if (is_80211i_mode == DMAC_WPA_802_11I) {
        ret = hmac_check_pcip_wpa_policy(mib_info, policy);
    } else if (is_80211i_mode == DMAC_RSNA_802_11I) {
        ret = hmac_check_pcip_wpa2_policy(mib_info, policy);
    } else {
        ret = HI_FALSE;
    }

    if (ret == HI_TRUE) {
        return HI_SUCCESS;
    } else {
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }
}

/*****************************************************************************
 ��������  : ���RSN�����Ƿ�ƥ��
 �������  : [1]mac_vap
             [2]puc_rsn_ie
             [3]pen_status_code
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_check_rsn_capability(const mac_vap_stru *mac_vap, const hi_u8 *puc_rsn_ie,
                                 mac_status_code_enum_uint16 *pen_status_code)
{
    wlan_mib_ieee802dot11_stru *mib_info = HI_NULL;
    hi_u16 us_rsn_capability;
    hi_u8 preauth_activated;
    hi_u8 dot11_rsnamfpr;
    hi_u8 dot11_rsnamfpc;

    mib_info = mac_vap->mib_info;
    if (mib_info == HI_NULL) {
        *pen_status_code = MAC_INVALID_RSN_INFO_CAP;
        oam_error_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_check_rsn_capability::pst_mib_info null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    us_rsn_capability = mac_get_rsn_capability(puc_rsn_ie);

    /* 2.1 Ԥ��֤������� */
    preauth_activated = us_rsn_capability & BIT0;
    if (preauth_activated != mib_info->wlan_mib_privacy.dot11_rsna_preauthentication_activated) {
        *pen_status_code = MAC_INVALID_RSN_INFO_CAP;
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                         "{hmac_check_rsn_capability::VAP not supported PreauthActivated[%d].}", preauth_activated);
        return HI_ERR_CODE_SECURITY_AUTH_TYPE;
    }

    /* 3.1 ����֡����(80211w)������� */
    dot11_rsnamfpr = (us_rsn_capability & BIT6) ? HI_TRUE : HI_FALSE;
    dot11_rsnamfpc = (us_rsn_capability & BIT7) ? HI_TRUE : HI_FALSE;
    /* 3.1.1 ����ǿ�ƣ��Զ�û��MFP���� */
    if ((mib_info->wlan_mib_privacy.dot11_rsnamfpr == HI_TRUE) && (dot11_rsnamfpc == HI_FALSE)) {
        *pen_status_code = MAC_MFP_VIOLATION;
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                         "{hmac_check_rsn_capability::refuse with NON MFP[%d].}", preauth_activated);
        return HI_ERR_CODE_SECURITY_CAP_MFP;
    }
    /* 3.1.2 �Զ�ǿ�ƣ�����û��MFP���� */
    if ((mib_info->wlan_mib_privacy.dot11_rsnamfpc == HI_FALSE) && (dot11_rsnamfpr == HI_TRUE)) {
        *pen_status_code = MAC_MFP_VIOLATION;
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                         "{hmac_check_rsn_capability::VAP not supported RSNA MFP[%d].}", preauth_activated);
        return HI_ERR_CODE_SECURITY_CAP_MFP;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����WPA/WPA2ģʽ��ȡWPA/WPA2 oui
 �޸���ʷ      :
  1.��    ��   : 2013��12��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_security_oui(hi_u8 is_80211i_mode, hi_u8 *auc_oui)
{
    if (is_80211i_mode == DMAC_WPA_802_11I) {
        auc_oui[0] = (hi_u8)MAC_WLAN_OUI_MICRO0;
        auc_oui[1] = (hi_u8)MAC_WLAN_OUI_MICRO1;
        auc_oui[2] = (hi_u8)MAC_WLAN_OUI_MICRO2; /* 2 Ԫ������ */
    } else if (is_80211i_mode == DMAC_RSNA_802_11I) {
        auc_oui[0] = (hi_u8)MAC_WLAN_OUI_RSN0;
        auc_oui[1] = (hi_u8)MAC_WLAN_OUI_RSN1;
        auc_oui[2] = (hi_u8)MAC_WLAN_OUI_RSN2; /* 2 Ԫ������ */
    } else {
        return HI_ERR_WIFI_HMAC_INVALID_PARAMETER;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����ݰ�����ȡ�����������׼���Ϣ
 �������  : hi_u8 *puc_frame   WPA/WPA2 ��ϢԪ���У�����ĵ�����ʼ��ַ
             hi_u8 *puc_len     ������Ϣ����
             hi_u8 *puc_oui     WPA/WPA2 ��ϢԪ��OUI
 �� �� ֵ  : hi_u8              ��ȡ�ĵ����׼���Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��8��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_get_pcip_policy_auth(const hi_u8 *puc_frame, hi_u8 *puc_len)
{
    hi_u8 indext;
    hi_u8 pcip_policy = 0;

    /*************************************************************************/
    /*                  RSN Element Pairwise Ciper Format                    */
    /* --------------------------------------------------------------------- */
    /* | Pairwise Cipher Count | Pairwise Cipher Suite List |                */
    /* --------------------------------------------------------------------- */
    /* |         2             |           4*m              |                */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    /* ��ȡ���ݰ��У��ɶ���Կ�׼��ܵ��ֽ��� */
    *puc_len = (hi_u8) (puc_frame[0] * 4) + 2; /* 4 2 ���ڼ��� */

    /* ASSOC REQ �еĵ����׼�����ֻ��Ϊ1�� */
    if (puc_frame[0] == 1) {
        indext = 2;          /* ���Ե����׼���2 �ֽ� */
        indext += MAC_OUI_LEN;       /* ����OUI ���� */
        pcip_policy = puc_frame[indext];  /* ��ȡ���������׼� */
    } else {
        pcip_policy = 0xFF;
    }

    return pcip_policy;
}

/*****************************************************************************
 ��������  : �����ݰ�����ȡ����֤�׼���Ϣ
 �������  : [1]puc_frame
             [2]len
 �� �� ֵ  : hi_u8
*****************************************************************************/
hi_u8 hmac_get_auth_policy_auth(const hi_u8 *puc_frame, hi_u8 *len)
{
    hi_u8 index;
    hi_u8 auth_policy = 0;

    /*************************************************************************/
    /*                  RSN Element AKM Suite Format                         */
    /* --------------------------------------------------------------------- */
    /* |    AKM Cipher Count   |   AKM Cipher Suite List    |                */
    /* --------------------------------------------------------------------- */
    /* |         2             |           4*s              |                */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    /* ��ȡ���ݰ��У���֤�׼��ܵ��ֽ��� */
    *len = (hi_u8) (puc_frame[0] * 4) + 2; /* 4 2 ���ڼ��� */

    /* ASSOC REQ �еĵ����׼�����ֻ��Ϊ1�� */
    if (puc_frame[0] == 1) {
        index = 2;           /* ����AKM �׼�����2�ֽ� */
        index += MAC_OUI_LEN;        /* ����OUI ���� */
        auth_policy = puc_frame[index];   /* ��ȡ��֤�׼� */
    } else {
        auth_policy = 0xFF;
    }
    return auth_policy;
}

/*****************************************************************************
 ��������  : STA ���ɨ�赽�ĵ��������������豸�����Ƿ�ƥ�䡣
 �������  : [1]mib_info
             [2]puc_pcip_policy_match
             [3]is_802_11i_mode
             [4]puc_pcip_policy
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_check_join_req_parewise_cipher_supplicant(const wlan_mib_ieee802dot11_stru *mib_info,
                                                      hi_u8 *puc_pcip_policy_match,
                                                      hi_u8 is_802_11i_mode, const hi_u8 *puc_pcip_policy)
{
    hi_u8 loop = 0;
    hi_u8 ret = HI_FALSE;
    if (puc_pcip_policy == HI_NULL || puc_pcip_policy_match == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY,
            "{hmac_check_join_req_parewise_cipher_supplicant::puc_pcip_policy/puc_pcip_policy_match is NULL!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ʼ���õ���ƥ��Ϊ��Ч���� */
    *puc_pcip_policy_match = 0xFF;

    /* ��STA mib �в��Һ� AP ����ƥ��ĵ������ܷ�ʽ */
    for (loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
        if (puc_pcip_policy[loop] == WLAN_80211_CIPHER_SUITE_GROUP_CIPHER) {
            /* �ɶ���Կ�׼�ѡ���鲥�����׼� */
            *puc_pcip_policy_match = WLAN_80211_CIPHER_SUITE_GROUP_CIPHER;
            break;
        } else if (puc_pcip_policy[loop] == 0xFF) {
            /* ���û���ҵ����������ҳɶԼ����׼� */
            continue;
        }

        /* ���ɶ���Կ�׼� */
        /* ��ⵥ����Կ�׼� */
        if (is_802_11i_mode == DMAC_WPA_802_11I) {
            ret = hmac_check_pcip_wpa_policy(mib_info, puc_pcip_policy[loop]);
        } else {
            ret = hmac_check_pcip_wpa2_policy(mib_info, puc_pcip_policy[loop]);
        }
        if (ret == HI_TRUE) {
            *puc_pcip_policy_match = puc_pcip_policy[loop];
            if (WLAN_80211_CIPHER_SUITE_CCMP == puc_pcip_policy[loop]) {
                break;
            }
        }
    }

    /* ��ⵥ����Կ�Ƿ�ƥ��ɹ� */
    if (*puc_pcip_policy_match == 0xFF) {
        oam_error_log0(0, OAM_SF_WPA, "{hmac_check_join_req_parewise_cipher_supplicant::pariwise not match.}");
        for (loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
            oam_error_log2(0, OAM_SF_WPA, "{hmac_check_join_req_parewise_cipher_supplicant::user pairwise[%d]=%d.}",
                           loop, puc_pcip_policy[loop]);
        }
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : STA ���ɨ�赽����֤�׼����豸�����Ƿ�ƥ�䡣
 �������  : [1]pst_mib_info
             [2]puc_auth_policy_match
             [3]puc_auth_policy
 �� �� ֵ  : static hi_u32
*****************************************************************************/
static hi_u32 hmac_check_join_req_auth_suite_supplicant(const wlan_mib_ieee802dot11_stru *mib_info,
                                                        hi_u8 *puc_auth_policy_match,
                                                        const hi_u8 *puc_auth_policy)
{
    hi_u8 loop = 0;

    /* ������֤ƥ��Ϊ��Ч���� */
    *puc_auth_policy_match = 0xFF;

    /* ����STA �� AP ����ƥ�����֤��ʽ */
    for (loop = 0; loop < MAC_AUTHENTICATION_SUITE_NUM; loop++) {
        /* ���û���ҵ���Ӧ����֤�׼�������� */
        if (puc_auth_policy[loop] == 0xFF) {
            continue;
        }

        /* ����ҵ���Ӧ��֤�׼�����ͱ�����֤�׼��Ƚ� */
        if (mac_check_auth_policy(mib_info, puc_auth_policy[loop]) == HI_TRUE) {
            *puc_auth_policy_match = puc_auth_policy[loop];
        }
    }

    if (*puc_auth_policy_match == 0xFF) {
        oam_error_log1(0, OAM_SF_WPA, "{hmac_check_join_req_security_cap_supplicant::user auth=%d.}",
                       puc_auth_policy[0]);
        return HI_ERR_CODE_SECURITY_AUTH_TYPE;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : STA ���ɨ�赽�� RSN/WPA �����������豸�����Ƿ�ƥ�䡣
 �������  : mac_bss_dscr_stru *st_bss_dscr     AP  ��BSS �ṹ
             hi_u8  uc_802_11i_mode         STA ֧�ֵİ�ȫ����ģʽ
             hi_u8 *puc_grp_policy_match
             hi_u8 *puc_pcip_policy_match
             hi_u8 *puc_auth_policy_match
             hi_u8  uc_802_11i_mode         WPA/WPA2
 �� �� ֵ  : hi_u32 HI_SUCCESS  ƥ��ɹ�
                        HI_FAIL  ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��8��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_check_join_req_security_cap_supplicant(mac_bss_dscr_stru *bss_dscr,
                                                          const wlan_mib_ieee802dot11_stru *mib_info,
                                                          const hmac_cap_supplicant_info_stru *cap_supplicant_info,
                                                          hi_u8 is_802_11i_mode)
{
    hi_u8 *puc_pcip_policy = HI_NULL;
    hi_u8 *puc_auth_policy = HI_NULL;
    hi_u8 grp_policy = 0;
    hi_u32 check_status;

    if ((bss_dscr->bss_sec_info.bss_80211i_mode & is_802_11i_mode) != is_802_11i_mode) {
        oam_error_log1(0, OAM_SF_WPA, "{hmac_check_join_req_security_cap_supplicant::80211i modeh=%d.}",
                       is_802_11i_mode);
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }

    if (is_802_11i_mode == DMAC_RSNA_802_11I) {
        puc_pcip_policy = bss_dscr->bss_sec_info.auc_rsn_pairwise_policy;
        puc_auth_policy = bss_dscr->bss_sec_info.auc_rsn_auth_policy;
        grp_policy = bss_dscr->bss_sec_info.rsn_grp_policy;
    } else {
        puc_pcip_policy = bss_dscr->bss_sec_info.auc_wpa_pairwise_policy;
        puc_auth_policy = bss_dscr->bss_sec_info.auc_wpa_auth_policy;
        grp_policy = bss_dscr->bss_sec_info.wpa_grp_policy;
    }

    /* �鲥��Կ */
    *(cap_supplicant_info->puc_grp_policy_match) = grp_policy;

    /* ��鵥����Կ�׼� */
    check_status = hmac_check_join_req_parewise_cipher_supplicant(mib_info, cap_supplicant_info->puc_pcip_policy_match,
                                                                  is_802_11i_mode, puc_pcip_policy);
    if (check_status != HI_SUCCESS) {
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }

    /* �����֤��Կ�׼� */
    check_status = hmac_check_join_req_auth_suite_supplicant(mib_info, cap_supplicant_info->puc_auth_policy_match,
                                                             puc_auth_policy);
    if (check_status != HI_SUCCESS) {
        return HI_ERR_CODE_SECURITY_AUTH_TYPE;
    }

    oam_info_log3(0, OAM_SF_WPA, "{hmac_check_join_req_security_cap_supplicant::group=%d, pairwise=%d, auth=%d.}",
                  *(cap_supplicant_info->puc_grp_policy_match), *(cap_supplicant_info->puc_pcip_policy_match),
                  *(cap_supplicant_info->puc_auth_policy_match));

    return HI_SUCCESS;
}

static hi_u32 hmac_check_security_capability_supplicant_check(const mac_vap_stru *mac_vap,
    const mac_bss_dscr_stru *bss_dscr)
{
    oam_info_log4(mac_vap->vap_id, OAM_SF_WPA,
        "{hmac_check_security_capability_supplicant_check :: mode %d,active %d,wpa %d,wpa2 %d}",
        bss_dscr->bss_sec_info.bss_80211i_mode, mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated,
        mac_vap->cap_flag.wpa, mac_vap->cap_flag.wpa2);

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_check_security_capability_supplicant_check::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (hmac_vap->wps_active == HI_TRUE) {
        oam_info_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_check_security_capability_supplicant_check::WPS enable.}");
        return HI_CONTINUE;
    }
#ifdef _PRE_WLAN_FEATURE_MESH
    if (bss_dscr->is_hisi_mesh == HI_TRUE) {
        oam_info_log0(0, OAM_SF_WPA,
            "{hmac_check_security_capability_supplicant_check::Connect Hisi-Mesh,no need check!.}");
        return HI_CONTINUE;
    }
#endif

    return HI_SUCCESS;
}


/*****************************************************************************
 ��������  : STA ��JOIN ǰ�����������Ƿ�ƥ��
 �������  : mac_vap_stru pst_mac_vap
             mac_bss_dscr_stru *pst_bss_dscr
 �� �� ֵ  : hi_u32 HI_SUCCESS ƥ��ɹ�
                        HI_FAIL ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��9��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_check_security_capability_supplicant(const mac_vap_stru *mac_vap, mac_bss_dscr_stru *bss_dscr)
{
    hi_u8 grp_policy_match = 0xFF;
    hi_u8 pcip_policy_match = 0xFF;
    hi_u8 auth_policy_match = 0xFF;
    hi_u8 is_80211i_mode = 0x00;
    hi_u32 ret = HI_FAIL;
    hmac_cap_supplicant_info_stru supplicant_info;
    wlan_mib_ieee802dot11_stru *mib_info = mac_vap->mib_info;   /* ������ MIB ֵ */

    hi_u32 retval = hmac_check_security_capability_supplicant_check(mac_vap, bss_dscr);
    if (retval == HI_ERR_CODE_PTR_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    } else if (retval == HI_CONTINUE) {
        return HI_SUCCESS;
    }

    if (mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated == HI_TRUE) {
        /* ���STA �� AP ���������Ƿ�ƥ��, �����µ���Ӧ��match �� */
        /* ��WPA/WPA2 ���ģʽ�£�����ѡ��WPA2 */
        supplicant_info.puc_grp_policy_match = &grp_policy_match;
        supplicant_info.puc_pcip_policy_match = &pcip_policy_match;
        supplicant_info.puc_auth_policy_match = &auth_policy_match;
        if ((bss_dscr->bss_sec_info.bss_80211i_mode & DMAC_RSNA_802_11I) && (mac_vap->cap_flag.wpa2 == HI_TRUE)) {
            ret = hmac_check_join_req_security_cap_supplicant(bss_dscr, mib_info, &supplicant_info, DMAC_RSNA_802_11I);
            if (ret == HI_SUCCESS) {
                is_80211i_mode = DMAC_RSNA_802_11I;
            }
        }

        if ((ret == HI_FAIL) && (bss_dscr->bss_sec_info.bss_80211i_mode & DMAC_WPA_802_11I) &&
            (mac_vap->cap_flag.wpa == HI_TRUE)) {
            ret = hmac_check_join_req_security_cap_supplicant(bss_dscr, mib_info, &supplicant_info, DMAC_WPA_802_11I);
            if (ret == HI_SUCCESS) {
                is_80211i_mode = DMAC_WPA_802_11I;
            }
        }

        if (ret != HI_SUCCESS) {
            oam_error_log1(0, OAM_SF_WPA, "{hmac_check_security_capability_supplicant::WPA & WPA2 not match[%d]}", ret);
            return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
        }

        bss_dscr->bss_sec_info.bss_80211i_mode = is_80211i_mode;
        bss_dscr->bss_sec_info.grp_policy_match = grp_policy_match;
        bss_dscr->bss_sec_info.pairwise_policy_match = pcip_policy_match;
        bss_dscr->bss_sec_info.auth_policy_match = auth_policy_match;
    } else { /* ��vap��֧��rsn,�Զ�֧��rsn, ����ʧ�� */
        if (bss_dscr->bss_sec_info.bss_80211i_mode & (DMAC_RSNA_802_11I | DMAC_WPA_802_11I)) {
            oam_error_log1(0, OAM_SF_WPA, "{hmac_check_security_capability_supplicant::WPA/WPA2 not support! mode=%d}",
                bss_dscr->bss_sec_info.bss_80211i_mode);
            return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �������join ��AP������Ϣ�Ƿ�ƥ��
 �������  : mac_vap_stru pst_mac_vap         STA �Լ�
             mac_bss_dscr_stru *pst_bss_dscr  AP bss ��Ϣ
 �� �� ֵ  : hi_u32 HI_SUCCESS ƥ��ɹ�
                        HI_FAIL ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��9��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_check_capability_mac_phy_supplicant(mac_vap_stru *mac_vap, mac_bss_dscr_stru *bss_dscr)
{
    hi_u32 ret;

    /* ����Э��ģʽ���³�ʼ��STA HT/VHT mibֵ */
    mac_vap_config_vht_ht_mib_by_protocol(mac_vap);

    hi_u8 check_bss_ret = hmac_check_bss_cap_info(bss_dscr->us_cap_info, mac_vap);
    if (check_bss_ret != HI_TRUE) {
        /* DTS2016052803102 MAC���������ϸ��� */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                         "{hmac_check_capability_mac_phy_supplicant::hmac_check_bss_cap_info Err[%d]}", check_bss_ret);
    }

    /* check bss capability info PHY,����PHY������ƥ���AP */
    mac_vap_check_bss_cap_info_phy_ap(bss_dscr->us_cap_info, mac_vap);

    ret = hmac_check_security_capability_supplicant(mac_vap, bss_dscr);
    if (ret != HI_SUCCESS) {
        /* DTS2016052803102 ���������ϸ��飬����IE��ƥ��������ֹ��� */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
            "{hmac_check_capability_mac_phy_supplicant::hmac_check_security_capability_supplicant failed[%d].}",
            ret);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����STA �ĵ������ܷ�ʽ�ͱ���ģʽ������STA ��������
             ��WEP / TKIP ����ģʽ�£����ܹ�����HT MODE
 �������  : mac_vap_stru *pst_mac_vap
 �޸���ʷ      :
  1.��    ��   : 2013��9��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_update_pcip_policy_prot_supplicant(mac_vap_stru *mac_vap, hi_u8 pcip_policy_match)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_cfg_mode_param_stru cfg_mode;
    hi_u8 protocol_fall_flag = HI_FALSE;

    cfg_mode.protocol = mac_vap->protocol;

    if ((pcip_policy_match == WLAN_80211_CIPHER_SUITE_TKIP) ||
        (pcip_policy_match == WLAN_80211_CIPHER_SUITE_WEP_104) ||
        (pcip_policy_match == WLAN_80211_CIPHER_SUITE_WEP_40) ||
        (pcip_policy_match == WLAN_80211_CIPHER_SUITE_WAPI)) {
        if ((mac_vap->protocol >= WLAN_HT_MODE) && (mac_vap->protocol < WLAN_PROTOCOL_BUTT)) {
            if (mac_vap->channel.band == WLAN_BAND_2G) {
                cfg_mode.protocol = WLAN_MIXED_ONE_11G_MODE;
                mac_vap->channel.en_bandwidth = WLAN_BAND_WIDTH_20M;
                protocol_fall_flag = HI_TRUE;
            }
        }
    }
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_update_pcip_policy_prot_supplicant::pst_hmac_vap null.}");
        return;
    }
    /* ��Э���ָ�����Ҫ��bit_protocol_fall���� */
    hmac_vap->protocol_fall = protocol_fall_flag;

    if (cfg_mode.protocol >= WLAN_HT_MODE) {
        hmac_vap->tx_aggr_on = HI_TRUE;
    } else {
        hmac_vap->tx_aggr_on = HI_FALSE;
    }

    mac_vap_init_by_protocol(mac_vap, cfg_mode.protocol);

    oam_info_log2(mac_vap->vap_id, OAM_SF_WPA,
                  "{hmac_update_pcip_policy_prot_supplicant::en_protocol=%d, bandwidth=%d.}", mac_vap->protocol,
                  mac_vap->channel.en_bandwidth);
}

/*****************************************************************************
 ��������  : ����STA ���ܵ�mib ��Ϣ
 �������  : mac_vap_stru          *pst_mac_vap     STA ������Ϣ
             hmac_join_req_stru    *pst_join_req    STA join ��AP bss ��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��8��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_update_current_join_req_parms_11i(mac_vap_stru *mac_vap, const mac_bss_80211i_info_stru *is_11i)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u8 grp_policy_match;  /* STA �� AP ����ƥ����鲥�����׼� */
    hi_u8 pcip_policy_match; /* STA �� AP ����ƥ��ĵ��������׼� */
    hi_u8 auth_policy_match; /* STA �� AP ����ƥ�����֤ģʽ */
    hi_u8 is_80211i_mode;       /* STA �Լ�֧�ֵİ�ȫģʽ */
    hi_u16 ciphersize = 0;

    /* ����ƥ��ֵ������join ʱ��STA ��mib */
    grp_policy_match = is_11i->grp_policy_match;
    pcip_policy_match = is_11i->pairwise_policy_match;
    auth_policy_match = is_11i->auth_policy_match;
    is_80211i_mode = is_11i->bss_80211i_mode;

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_update_current_join_req_parms_11i::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked != HI_TRUE) {
        /* DTS2014110702909 ��Э��Ĳ������������Ҫ���»ָ�  */
        if (hmac_vap->protocol_fall == HI_TRUE) {
            hmac_update_pcip_policy_prot_supplicant(mac_vap, WLAN_80211_CIPHER_SUITE_NO_ENCRYP);
        }
        return HI_SUCCESS;
    }

    /* ʹ��RSN */
    if (mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated != HI_TRUE) {
        /* ��WEP / TKIP ����ģʽ�£����ܹ�����HT MODE */
        hmac_update_pcip_policy_prot_supplicant(mac_vap, WLAN_80211_CIPHER_SUITE_WEP_40);
        return HI_SUCCESS;
    }

    /* ��WEP / TKIP ����ģʽ�£����ܹ�����HT MODE */
    hmac_update_pcip_policy_prot_supplicant(mac_vap, pcip_policy_match);

    /* ����STA ��MIB ��Ϣ */
    /* �����鲥mib ֵ���鲥��Ϣ������AP */
    if (mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher != grp_policy_match) {
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher = grp_policy_match;
        if (grp_policy_match == WLAN_80211_CIPHER_SUITE_CCMP) {
            ciphersize = WLAN_CCMP_KEY_LEN * 8;      /* CCMP ���ܷ�ʽ����Կ����(BITS) 8: 8λ */
        } else if (grp_policy_match == WLAN_80211_CIPHER_SUITE_TKIP) {
            ciphersize = WLAN_TKIP_KEY_LEN * 8;      /* TKIP ���ܷ�ʽ�µ���Կ����(BITS) 8: 8λ */
        }
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher_size = ciphersize;
    }

    /* ����MIB ֵ */
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_pairwise_cipher_requested = pcip_policy_match;
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_group_cipher_requested = grp_policy_match;

    /* STA ���汾�� 80211i_mode ָ��ΪWPA ���� WPA2 */
    hmac_vap->is80211i_mode = is_80211i_mode;

    oam_info_log4(mac_vap->vap_id, OAM_SF_WPA,
                  "{hmac_update_current_join_req_parms_11i::mode=%d group=%d pairwise=%d auth=%d.}",
                  is_80211i_mode, grp_policy_match, pcip_policy_match, auth_policy_match);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����micУ����
 �������  : ivͷ�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2014��1��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_en_mic(const hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf, hi_u8 *puc_iv_len)
{
    wlan_priv_key_param_stru *key = HI_NULL;
    hi_u32 ret = HI_SUCCESS;
    wlan_ciper_protocol_type_enum_uint8 cipher_type;
    wlan_cipher_key_type_enum_uint8 key_type;

    *puc_iv_len = 0;
    key_type = hmac_user->base_user->user_tx_info.security.cipher_key_type;
    cipher_type = hmac_user->base_user->key_info.cipher_type;
    key = mac_user_get_key(hmac_user->base_user, key_type - 1);
    if (key == HI_NULL) {
        oam_error_log1(0, OAM_SF_WPA, "{hmac_en_mic::mac_user_get_key FAIL. en_key_type[%d]}", key_type);
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    switch (cipher_type) {
        case WLAN_80211_CIPHER_SUITE_TKIP:
            if (key_type == 0 || key_type > 5) { /* 5 �߽� */
                return HI_ERR_CODE_SECURITY_KEY_TYPE;
            }

            ret = hmac_crypto_tkip_enmic(key, netbuf);
            if (ret != HI_SUCCESS) {
                oam_error_log1(0, OAM_SF_WPA,
                               "{hmac_en_mic::hmac_crypto_tkip_enmic failed[%d].}", ret);
                return ret;
            }

            *puc_iv_len = WEP_IV_FIELD_SIZE + EXT_IV_FIELD_SIZE;
            break;
        case WLAN_80211_CIPHER_SUITE_CCMP:
            *puc_iv_len = WEP_IV_FIELD_SIZE + EXT_IV_FIELD_SIZE;
            break;
        default:
            break;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : mic��У��
 �޸���ʷ      :
  1.��    ��   : 2014��1��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_de_mic(const hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf)
{
    wlan_priv_key_param_stru *key = HI_NULL;
    hi_u32 ret = HI_SUCCESS;
    wlan_ciper_protocol_type_enum_uint8 cipher_type;
    wlan_cipher_key_type_enum_uint8 key_type;

    key_type = hmac_user->base_user->user_tx_info.security.cipher_key_type;
    cipher_type = hmac_user->base_user->key_info.cipher_type;
    key = mac_user_get_key(hmac_user->base_user, key_type - 1);
    if (key == HI_NULL) {
        oam_error_log1(0, OAM_SF_WPA, "{hmac_de_mic::mac_user_get_key FAIL. en_key_type[%d]}", key_type);
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    switch (cipher_type) {
        case WLAN_80211_CIPHER_SUITE_TKIP:
            if (key_type == 0 || key_type > 5) { /* 5 �߽� */
                oam_error_log0(hmac_user->base_user->vap_id, OAM_SF_WPA,
                               "{hmac_de_mic::key_type is err code security key type.}");
                return HI_ERR_CODE_SECURITY_KEY_TYPE;
            }
            ret = hmac_crypto_tkip_demic(key, netbuf);
            if (ret != HI_SUCCESS) {
                oam_error_log1(hmac_user->base_user->vap_id, OAM_SF_WPA,
                               "{hmac_de_mic::hmac_crypto_tkip_demic failed[%d].}", ret);
                return ret;
            }
            break;
        default:
            break;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ap �� sta ���յ�MIC faile �¼�����
 �������  :
 �޸���ʷ      :
  1.��    ��   : 2013��8��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_rx_tkip_mic_failure_process(frw_event_mem_stru *event_mem)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    frw_event_stru *event = HI_NULL;
    frw_event_mem_stru *hmac_event_mem = HI_NULL;
    frw_event_hdr_stru *event_hdr = HI_NULL;
    dmac_to_hmac_mic_event_stru *mic_event = HI_NULL;

    /* ��ȡ�¼�ͷ���¼��ṹ��ָ�� */
    event = (frw_event_stru *)event_mem->puc_data;
    event_hdr = &(event->event_hdr);
    mic_event = (dmac_to_hmac_mic_event_stru *)(event->auc_event_data);

    /* ��mic�¼��׵�WAL */
    hmac_event_mem = frw_event_alloc(sizeof(dmac_to_hmac_mic_event_stru));
    if (hmac_event_mem == HI_NULL) {
        oam_error_log0(event_hdr->vap_id, OAM_SF_WPA,
                       "{hmac_rx_tkip_mic_failure_process::pst_hmac_event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)hmac_event_mem->puc_data;

    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CTX,
                       HMAC_HOST_CTX_EVENT_SUB_TYPE_MIC_FAILURE,
                       sizeof(dmac_to_hmac_mic_event_stru),
                       FRW_EVENT_PIPELINE_STAGE_0,
                       event_hdr->vap_id);

    /* ȥ������STA mac��ַ */
    if (memcpy_s((hi_u8 *)frw_get_event_payload(event_mem), sizeof(dmac_to_hmac_mic_event_stru),
                 (hi_u8 *)mic_event, sizeof(dmac_to_hmac_mic_event_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_rx_tkip_mic_failure_process::pst_mic_event memcpy_s fail.");
        frw_event_free(hmac_event_mem);
        return HI_FAIL;
    }

    /* �ַ��¼� */
    frw_event_dispatch_event(hmac_event_mem);
    frw_event_free(hmac_event_mem);
    return HI_SUCCESS;
#else
    hi_unref_param(event_mem);
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : �������ݣ���ȫ��ع���
 �������  : (1)vap
             (2)mac��ַ
             (3)������������
 �� �� ֵ  : �ɹ�����ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_11i_ether_type_filter(const hmac_vap_stru *hmac_vap, const hi_u8 *mac_addr, hi_u16 us_ether_type)
{
    mac_user_stru *mac_user = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u32 ret = HI_SUCCESS;

    mac_vap = hmac_vap->base_vap;
    if (mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated == HI_TRUE) { /* �ж��Ƿ�ʹ��WPA/WPA2 */
        mac_user = mac_vap_get_user_by_addr(hmac_vap->base_vap, mac_addr);
        if (mac_user == HI_NULL) {
            oam_info_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_11i_ether_type_filter:: user filterd.}");
            return HI_ERR_CODE_SECURITY_USER_INVAILD;
        }

        if (mac_user->port_valid != HI_TRUE) {  /* �ж϶˿��Ƿ�� */
            /* ��������ʱ����Է�EAPOL ������֡������ */
            if (hi_swap_byteorder_16(ETHER_TYPE_PAE) != us_ether_type) {
                oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                                 "{hmac_11i_ether_type_filter::TYPE 0x%04x not permission.}", us_ether_type);
                ret = HI_ERR_CODE_SECURITY_PORT_INVALID;
            }
        } else if (hi_swap_byteorder_16(ETHER_TYPE_PAE) == us_ether_type) { /* EAPOL�շ�ά����Ϣ */
            oam_info_log0(mac_vap->vap_id, OAM_SF_WPA, "{hmac_11i_ether_type_filter::rx EAPOL.}");
        }
    }
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
