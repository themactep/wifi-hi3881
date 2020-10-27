/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: mac_user.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */
/* 1 ͷ�ļ����� */
#include "oam_ext_if.h"
#include "mac_resource.h"
#include "mac_device.h"
#include "mac_user.h"
#include "hmac_11i.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#define __WIFI_ROM_SECTION__                    /* ����ROM����ʼλ�� */
WIFI_ROM_BSS hi_u16  g_us_user_res_map = 0;     /* user��Դmap�� ���֧��16���û� */
WIFI_ROM_BSS  hi_u8  *g_puc_mac_user_res = HI_NULL;

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : mac user��Դ��ʼ��,����user���������ڴ�
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_user_res_init(const hi_u8 user_num)
{
    hi_u32  user_size = sizeof(mac_user_stru) * user_num;
    /* mac user �ڷ�offloadģʽ�´���������������,�Ѿ������������ */
    if (g_puc_mac_user_res != HI_NULL) {
        return HI_SUCCESS;
    }
    g_puc_mac_user_res = hi_malloc(HI_MOD_ID_WIFI_DRV, user_size);
    if (g_puc_mac_user_res == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{mac_user_res_init::mem alloc user res null.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    /* ��ȫ��̹���6.6����(3)�Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(g_puc_mac_user_res, user_size, 0, user_size);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : mac �û���Դ��ȥ��ʼ��
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_res_exit(hi_void)
{
    if (g_puc_mac_user_res != HI_NULL) {
        hi_free(HI_MOD_ID_WIFI_DRV, g_puc_mac_user_res);
        g_puc_mac_user_res = HI_NULL;
    }
}

/*****************************************************************************
 ��������  : ��ȡȫ���û����� ���������û��ڴ� user����=���õĵ����û� + vap����(�鲥�û�)
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_user_get_user_num(hi_void)
{
    hi_u8 ucast_user_num = oal_mem_get_user_res_num();   /* �����û� = �û������� */
    /* �鲥�û� = vap��-1(����vap���鲥�û�) */
    hi_u8 mcast_user_num = oal_mem_get_vap_res_num() - WLAN_CFG_VAP_NUM_PER_DEVICE;
    hi_u8 user_num = ucast_user_num + mcast_user_num;
    /* USER��Դ����ʱ�������У��˴�����У�� */
    return user_num;
}

/*****************************************************************************
 ��������  : ����һ��δʹ��user��Դ
 �� �� ֵ  : δʹ�õ�user��Դid
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_user_alloc_user_res(hi_void)
{
    hi_u8 user_idx;
    hi_u8 user_num = mac_user_get_user_num();
    user_idx = oal_bit_find_first_zero((hi_u32)g_us_user_res_map, user_num);
    if (user_idx >= user_num) {
        oam_error_log2(0, OAM_SF_ANY, "{mac_user_alloc_user_res::alloc user res fail. res mac[%x], max user spec[%d].}",
                       g_us_user_res_map, user_num);
        user_idx = MAC_INVALID_USER_ID;
    } else {
        /* ����Ӧ��res��־λ��1 */
        g_us_user_res_map |= (hi_u16)(BIT0 << user_idx);
    }
    return user_idx;
}

/*****************************************************************************
 ��������  : user��ʼ��ʱ ��ȡ��ӦMAC USER�������ڴ�
             ��������hmac dmac����ƥ���ϵ ��ε��ô���У��
 �������  : ��ӦMAC USER�ڴ�����
 �� �� ֵ  : ��Ӧ�ڴ��ַ
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 *mac_user_init_get_user_stru(hi_u8 idx)
{
    return (g_puc_mac_user_res + sizeof(mac_user_stru) * idx);
}

/*****************************************************************************
 ��������  : ��ȡ��ӦMAC USER�������ڴ�
 �������  : ��ӦMAC USER�ڴ�����
 �� �� ֵ  : ��Ӧ�ڴ��ַ
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT mac_user_stru *mac_user_get_user_stru(hi_u8 idx)
{
    hi_u8 user_num = mac_user_get_user_num();
    mac_user_stru*    mac_user = HI_NULL;
    if ((g_puc_mac_user_res == HI_NULL) || (idx >= user_num)) {
        return HI_NULL;
    }
    mac_user = (mac_user_stru *)(g_puc_mac_user_res + sizeof(mac_user_stru) * idx);
    /* user id=0Ϊ����user,������Ϊ0 */
    if ((mac_user->is_user_alloced != MAC_USER_ALLOCED) && (idx != 0)) {
        /* ��ȡ�û�ʱ�û��Ѿ��ͷ�����������ֱ�ӷ��ؿ�ָ�뼴�� */
        return HI_NULL;
    }
    return mac_user;
}

/*****************************************************************************
 ��������  : ɾ��һ����ʹ��ʹ��user��Դ
             OFFLOADģʽ��dmac hmac�����ͷţ���OFFLOADģʽ��ͳһ��hmac������ͷ�
 �������  : vap��Դid
 �޸���ʷ      :
  1.��    ��   : 2019��5��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_free_user_res(hi_u8 idx)
{
    g_us_user_res_map &= (~((hi_u16)BIT0 << idx)); // ~���������ʽ�����б��������޷�����,�󱨸澯��lin_t e502�澯����
}

/*****************************************************************************
 ��������  : ���wep��Կ��ָ������Կ��
 �޸���ʷ      :
  1.��    ��   : 2015��5��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_user_add_key_common(mac_user_stru *mac_user, hi_u8 key_index,
    const mac_key_params_stru *key)
{
    hi_s32 key_max_len;

    if (key_index >= WLAN_NUM_TK) {
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    if (((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_WEP_40) ||
        ((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_WEP_104)) {
        key_max_len = WLAN_WEP104_KEY_LEN;
    } else if (((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_TKIP) ||
        ((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_CCMP)) {
        key_max_len = WLAN_WPA_KEY_LEN;
    } else {
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }

    if (key->key_len > key_max_len) {
        return HI_ERR_CODE_SECURITY_KEY_LEN;
    }

    if ((hi_u32)key->seq_len > WLAN_WPA_SEQ_LEN) {
        return HI_ERR_CODE_SECURITY_KEY_LEN;
    }

    mac_user->key_info.ast_key[key_index].cipher    = key->cipher;
    mac_user->key_info.ast_key[key_index].key_len   = (hi_u32)key->key_len;
    mac_user->key_info.ast_key[key_index].seq_len   = (hi_u32)key->seq_len;

    if (memcpy_s(mac_user->key_info.ast_key[key_index].auc_key, WLAN_WPA_KEY_LEN, key->auc_key,
        (hi_u32)key->key_len) != EOK) {
        return HI_FAIL;
    }
    if (memcpy_s(mac_user->key_info.ast_key[key_index].auc_seq, WLAN_WPA_SEQ_LEN, key->auc_seq,
        (hi_u32)key->seq_len) != EOK) {
        return HI_FAIL;
    }

    if (((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_WEP_40) ||
        ((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_WEP_104)) {
        mac_user->user_tx_info.security.cipher_key_type = WLAN_KEY_TYPE_TX_GTK;
    } else {
        mac_user->key_info.cipher_type    = (hi_u8)key->cipher;
        mac_user->key_info.default_index  = key_index;
    }

    return HI_SUCCESS;
}

WIFI_ROM_TEXT hi_u32 mac_user_add_wep_key(mac_user_stru *mac_user, hi_u8 key_index, const mac_key_params_stru *key)
{
    return mac_user_add_key_common(mac_user, key_index, key);
}

/*****************************************************************************
 �� �� ��  : mac_user_add_rsn_key
 ��������  : ����rsn������Ϣ
 �������  :
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_user_add_rsn_key(mac_user_stru *mac_user, hi_u8 key_index, const mac_key_params_stru *key)
{
    return mac_user_add_key_common(mac_user, key_index, key);
}

/*****************************************************************************
 ��������  : ����bip��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_user_add_bip_key(mac_user_stru *mac_user, hi_u8 key_index, const mac_key_params_stru *key)
{
    /* keyidУ�� */
    if (key_index < WLAN_NUM_TK || key_index > WLAN_MAX_IGTK_KEY_INDEX) {
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }

    if (memcpy_s(mac_user->key_info.ast_key[key_index].auc_key, WLAN_WPA_KEY_LEN, key->auc_key,
        (hi_u32)key->key_len) != EOK) {
        return HI_FAIL;
    }
    if (memcpy_s(mac_user->key_info.ast_key[key_index].auc_seq, WLAN_WPA_SEQ_LEN, key->auc_seq,
        (hi_u32)key->seq_len) != EOK) {
        return HI_FAIL;
    }
    mac_user->key_info.ast_key[key_index].cipher    = key->cipher;
    mac_user->key_info.ast_key[key_index].key_len   = (hi_u32)key->key_len;
    mac_user->key_info.ast_key[key_index].seq_len   = (hi_u32)key->seq_len;

    mac_user->key_info.igtk_key_index = key_index;
    return  HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼ���û�����Կ��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��5��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_init_key(mac_user_stru *mac_user)
{
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&mac_user->key_info, sizeof(mac_key_mgmt_stru), 0, sizeof(mac_key_mgmt_stru));
    mac_user->key_info.cipher_type  = WLAN_80211_CIPHER_SUITE_NO_ENCRYP;
    mac_user->key_info.last_gtk_key_idx = 0xFF;
}

/*****************************************************************************
 ��������  : ��ʼ��mac user��������
 �������  : pst_mac_user: ָ��user�Ľṹ��
             uc_user_idx : �û�����
             puc_mac_addr: MAC��ַ
             uc_vap_id   :
 �޸���ʷ      :
  1.��    ��   : 2013��8��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_init(mac_user_stru *mac_user, hi_u8 user_idx, const hi_u8 *mac_addr,
    hi_u8 vap_id)
{
    /* ��ʼ��0 */
    if (memset_s(mac_user, sizeof(mac_user_stru), 0, sizeof(mac_user_stru)) != EOK) {
        return;
    }
    mac_user->is_user_alloced = MAC_USER_ALLOCED;
    mac_user->vap_id     = vap_id;
    mac_user->us_assoc_id   = user_idx;
    /* ��ʼ����Կ */
    mac_user->user_tx_info.security.cipher_key_type      = WLAN_KEY_TYPE_PTK;
    mac_user->user_tx_info.security.cipher_protocol_type = WLAN_80211_CIPHER_SUITE_NO_ENCRYP;
    /* ��ʼ����ȫ������Ϣ */
    mac_user_init_key(mac_user);
    mac_user_set_key(mac_user, WLAN_KEY_TYPE_PTK, WLAN_80211_CIPHER_SUITE_NO_ENCRYP, 0);
    mac_user->port_valid = HI_FALSE;
    mac_user->user_asoc_state = MAC_USER_STATE_BUTT;

    if (mac_addr == HI_NULL) {
        mac_user->is_multi_user   = HI_TRUE;
        mac_user->user_asoc_state = MAC_USER_STATE_ASSOC;
    } else {
        /* ��ʼ��һ���û��Ƿ����鲥�û��ı�־���鲥�û���ʼ��ʱ������ñ����� */
        mac_user->is_multi_user = HI_FALSE;
        /* ����mac��ַ */
        if (memcpy_s(mac_user->user_mac_addr, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            return;
        }
    }
    mac_user->mesh_user_leave = HI_FALSE;
    /* ��ʼ������ */
    mac_user_set_pmf_active(mac_user, HI_FALSE);
    mac_user_set_avail_num_spatial_stream(mac_user, MAC_USER_INIT_STREAM);
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    /* RSSIͳ������ʼ�� */
    mac_user->rx_conn_rssi = WLAN_RSSI_DUMMY_MARKER;
#endif
}

/*****************************************************************************
 ��������  : ���ÿ��ô������Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��4��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  1.��    ��   : 2015��5��27��
    ��    ��   : Hisilicon
    �޸�����   : ���Э���л�, �Դ�����½��������ж�
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_set_bandwidth_info(mac_user_stru *mac_user,
    wlan_bw_cap_enum_uint8 avail_bandwidth, wlan_bw_cap_enum_uint8 cur_bandwidth)
{
    mac_user->avail_bandwidth = avail_bandwidth;
    mac_user->cur_bandwidth   = cur_bandwidth;
    /* Autorate��Э���11n�л���11b��, cur_bandwidth���Ϊ20M
       ��ʱ�������������Ϊ40M, cur_bandwidth����Ҫ����20M */
    if ((WLAN_LEGACY_11B_MODE == mac_user->cur_protocol_mode) &&
        (WLAN_BW_CAP_20M != mac_user->cur_bandwidth)) {
        mac_user->cur_bandwidth = WLAN_BW_CAP_20M;
    }
}

/*****************************************************************************
 ��������  : ��ȡ�û��Ĵ���
 �޸���ʷ      :
  1.��    ��   : 2013��10��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_get_sta_cap_bandwidth(mac_user_stru *mac_user,
                                                     wlan_bw_cap_enum_uint8 *pen_bandwidth_cap)
{
    mac_user_ht_hdl_stru         *mac_ht_hdl = HI_NULL;

    *pen_bandwidth_cap = WLAN_BW_CAP_20M;
    /* ��ȡHT��VHT�ṹ��ָ�� */
    mac_ht_hdl  = &(mac_user->ht_hdl);

    if (mac_ht_hdl->ht_capable) {
        if (mac_ht_hdl->ht_capinfo.supported_channel_width == HI_TRUE) {
            *pen_bandwidth_cap  = WLAN_BW_CAP_40M;
        }
    } else {
        /* else��֧����Ҫ���� ʹ��Ĭ��ֵ20M */
    }
    mac_user_set_bandwidth_cap(mac_user, *pen_bandwidth_cap);
}

/*****************************************************************************
 ��������  : ����en_user_asoc_state ��ͳһ�ӿ�
 �޸���ʷ      :
  1.��    ��   : 2015��5��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_set_asoc_state(mac_user_stru *mac_user, mac_user_asoc_state_enum_uint8 value)
{
    mac_user->user_asoc_state = value;
}

/*****************************************************************************
 ��������  : ���û���ht��Ϣ��������
 �޸���ʷ      :
  1.��    ��   : 2015��5��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_set_ht_hdl(mac_user_stru *mac_user, const mac_user_ht_hdl_stru *ht_hdl)
{
    if (memcpy_s((hi_u8 *)(&mac_user->ht_hdl), sizeof(mac_user_ht_hdl_stru), (hi_u8 *)ht_hdl,
                 sizeof(mac_user_ht_hdl_stru)) != EOK) {
        return;
    }
}

/*****************************************************************************
 ��������  : ��ȡ�û���ht��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��5��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_user_get_ht_hdl(const mac_user_stru *mac_user, mac_user_ht_hdl_stru *ht_hdl)
{
    if (memcpy_s((hi_u8 *)ht_hdl, sizeof(mac_user_ht_hdl_stru), (hi_u8 *)(&mac_user->ht_hdl),
        sizeof(mac_user_ht_hdl_stru)) != EOK) {
        return;
    }
}

/*****************************************************************************
 ��������  : �����û�wep������Կ��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��1��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_user_update_wep_key(mac_user_stru *mac_usr, hi_u8 multi_user_idx)
{
    mac_user_stru        *multi_user   = HI_NULL;

    multi_user = mac_user_get_user_stru(multi_user_idx);
    if (multi_user == HI_NULL) {
        return HI_ERR_CODE_SECURITY_USER_INVAILD;
    }
    if (multi_user->key_info.cipher_type != WLAN_80211_CIPHER_SUITE_WEP_104 &&
        multi_user->key_info.cipher_type != WLAN_80211_CIPHER_SUITE_WEP_40) {
        oam_error_log1(0, OAM_SF_WPA, "{mac_wep_add_usr_key::en_cipher_type==%d}", multi_user->key_info.cipher_type);
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }
    if (multi_user->key_info.default_index >= WLAN_MAX_WEP_KEY_COUNT) {
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }
    /* wep�����£������鲥�û�����Կ��Ϣ�������û� */
    /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memcpy_s(&mac_usr->key_info, sizeof(mac_key_mgmt_stru), &multi_user->key_info, sizeof(mac_key_mgmt_stru));
    mac_usr->user_tx_info.security.cipher_key_type = mac_usr->key_info.default_index + HAL_KEY_TYPE_PTK;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ж�mac��ַ�Ƿ�ȫ0
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_addr_is_zero(const hi_u8 *mac_addr)
{
    hi_u8 zero_mac_addr[OAL_MAC_ADDR_LEN] = {0};

    if (mac_addr == HI_NULL) {
        return HI_TRUE;
    }

    return (0 == memcmp(zero_mac_addr, mac_addr, OAL_MAC_ADDR_LEN));
}

/* ����ROM�ν���λ�� ����ROM���������SECTION�� */
#undef __WIFI_ROM_SECTION__

/*****************************************************************************
 ��������  : ����en_key_type��������Ӧ�ĺ���������vap��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
wlan_priv_key_param_stru *mac_user_get_key(mac_user_stru *mac_user, hi_u8 key_id)
{
    if (key_id >= WLAN_NUM_TK + WLAN_NUM_IGTK) {
        return HI_NULL;
    }
    return &mac_user->key_info.ast_key[key_id];
}

/*****************************************************************************
 ��������  : ����AP��operation ie��ȡap�Ĺ�������
 �޸���ʷ      :
  1.��    ��   : 2014��4��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_user_get_ap_opern_bandwidth(mac_user_stru *mac_user, wlan_bw_cap_enum_uint8 *pen_bandwidth_cap)
{
    mac_user_ht_hdl_stru         *mac_ht_hdl = HI_NULL;
    wlan_bw_cap_enum_uint8        bandwidth_cap;

    bandwidth_cap = WLAN_BW_CAP_20M;
    /* ��ȡHT��VHT�ṹ��ָ�� */
    mac_ht_hdl  = &(mac_user->ht_hdl);

    if (mac_ht_hdl->ht_capable) {
        if (mac_ht_hdl->secondary_chan_offset != MAC_SCN) {
            bandwidth_cap = WLAN_BW_CAP_40M;
        }
    }

    *pen_bandwidth_cap = bandwidth_cap;
    mac_user_set_bandwidth_cap(mac_user, bandwidth_cap);
}

/*****************************************************************************
 ��������  : ����ht cap��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��5��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_user_set_ht_capable(mac_user_stru *mac_user, hi_u8 ht_capable)
{
    mac_user->ht_hdl.ht_capable = ht_capable;
}

/*****************************************************************************
 ��������  : ���ø����û�bit_spectrum_mgmt��������Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��5��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_user_set_spectrum_mgmt(mac_user_stru *mac_user, hi_u8 spectrum_mgmt)
{
    mac_user->cap_info.spectrum_mgmt = spectrum_mgmt;
}

/*****************************************************************************
 ��������  : �����û����������bit_apsd����
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_user_set_apsd(mac_user_stru *mac_user, hi_u8 apsd)
{
    mac_user->cap_info.apsd = apsd;
}

hi_u8 mac_user_is_user_valid(hi_u8 idx)
{
    return (g_us_user_res_map & ((hi_u16)BIT0 << idx)) ? HI_TRUE : HI_FALSE;
}
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
