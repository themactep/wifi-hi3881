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
#include "mac_resource.h"
#include "mac_regdomain.h"
#include "dmac_ext_if.h"
#include "hi_isr.h"
#include "hmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ȫ�ֱ�������
*****************************************************************************/
#define __WIFI_ROM_SECTION__        /* ����ROM����ʼλ�� */
WIFI_ROM_BSS hi_u8  g_vap_res_map = 0;       /* vap ��Դmap�� */
WIFI_ROM_BSS hi_u8  *g_puc_mac_vap_res = HI_NULL;
/* WME��ʼ�������壬����OFDM��ʼ�� APģʽ ֵ������TGn 9 Appendix D: Default WMM AC Parameters */
WIFI_ROM_RODATA static const mac_wme_param_stru g_ast_wmm_initial_params_ap[WLAN_WME_AC_BUTT] = {
    /* AIFS, cwmin, cwmax, txop */
    /* BE */
    {  3,    4,     6,     0, },
    /* BK */
    {  7,    4,     10,    0, },
    /* VI */
    {  1,    3,     4,     3008, },
    /* VO */
    {  1,    2,     3,     1504, },
};

/* WMM��ʼ�������壬����OFDM��ʼ�� STAģʽ */
WIFI_ROM_RODATA static const mac_wme_param_stru g_ast_wmm_initial_params_sta[WLAN_WME_AC_BUTT] = {
    /* AIFS, cwmin, cwmax, txop */
    /* BE */
    {  3,    3,     10,     0, },
    /* BK */
    {  7,    4,     10,     0, },
    /* VI */
    {  2,    3,     4,     3008, },
    /* VO */
    {  2,    2,     3,     1504, },
};

/* WMM��ʼ�������壬aput������bss��STA��ʹ�õ�EDCA���� */
WIFI_ROM_RODATA static const mac_wme_param_stru g_ast_wmm_initial_params_bss[WLAN_WME_AC_BUTT] = {
    /* AIFS, cwmin, cwmax, txop */
    /* BE */
    {  3,    4,     10,     0, },
    /* BK */
    {  7,    4,     10,     0, },
    /* VI */
    {  2,    3,     4,     3008, },
    /* VO */
    {  2,    2,     3,     1504, },
};

/*****************************************************************************
 ��������  : ����һ��δʹ��vap��Դ
 �� �� ֵ  : δʹ�õ�vap��Դid
 �޸���ʷ      :
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_vap_alloc_vap_res(hi_void)
{
    hi_u8 vap_res_idx;
    hi_u8 vap_res_num = oal_mem_get_vap_res_num();
    vap_res_idx = oal_bit_find_first_zero((hi_u32)g_vap_res_map, vap_res_num);
    if (vap_res_idx >= vap_res_num) {
        oam_error_log1(0, OAM_SF_ANY, "{mac_vap_alloc_vap_res:: alloc vap res fail. res[%x].}", g_vap_res_map);
        vap_res_idx = MAC_VAP_RES_ID_INVALID;
    } else {
        /* ����Ӧ��res��־λ��1 */
        g_vap_res_map |= (hi_u8)(BIT0 << vap_res_idx);
    }
    return vap_res_idx;
}

/*****************************************************************************
 ��������  : ɾ��һ����ʹ��vap��Դmap��־λ,�ڴ治��Ҫ�ͷ�(����ж��ʱ�ͷ�)������(������ʼ��ʱ����)
             OFFLOADģʽ��dmac hmac�����ͷţ���OFFLOADģʽ��ͳһ��hmac������ͷ�
 �������  : vap��Դid
 �޸���ʷ      :
  1.��    ��   : 2019��5��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_free_vap_res(hi_u8 idx)
{
    g_vap_res_map &= (~((hi_u8)(BIT0 << idx)));
}

/*****************************************************************************
 ��������  : mac vap��Դ��ʼ��,����vap���������ڴ�
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_res_init(const hi_u8 vap_num)
{
    hi_u32  vap_size = sizeof(mac_vap_stru) * vap_num;
    /* mac user �ڷ�offloadģʽ�´���������������,�Ѿ������������ */
    if (g_puc_mac_vap_res != HI_NULL) {
        return HI_SUCCESS;
    }
    g_puc_mac_vap_res = hi_malloc(HI_MOD_ID_WIFI_DRV, vap_size);
    if (g_puc_mac_vap_res == HI_NULL) {
        hi_diag_log_msg_e1(0, "{mac_vap_res_init::mem alloc vap res null. size = %d.}", vap_size);
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    /* ��ȫ��̹���6.6����(3)�Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(g_puc_mac_vap_res, vap_size, 0, vap_size);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : mac vap��Դȥ��ʼ��
 �޸���ʷ      :
  1.��    ��   : 2019��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_res_exit(hi_void)
{
    if (g_puc_mac_vap_res != HI_NULL) {
        hi_free(HI_MOD_ID_WIFI_DRV, g_puc_mac_vap_res);
        g_puc_mac_vap_res = HI_NULL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡmac vap�ṹ��
 �������  : vap��Դid
 �޸���ʷ      :
  1.��    ��   : 2019��5��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT mac_vap_stru *mac_vap_get_vap_stru(hi_u8 idx)
{
    hi_u8 vap_res_num = oal_mem_get_vap_res_num();
    if (oal_unlikely(idx >= vap_res_num)) {
        return HI_NULL;
    }
    return (mac_vap_stru *)(g_puc_mac_vap_res + idx * sizeof(mac_vap_stru));
}

/*****************************************************************************
 ��������  : �ж�vap�Ƿ����
 �������  : vap��Դid
 �޸���ʷ      :
  1.��    ��   : 2019��5��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_is_valid(hi_u8 idx)
{
    if (oal_unlikely(idx >= oal_mem_get_vap_res_num())) {
        return HI_FALSE;
    }
    if (g_vap_res_map & (BIT0 << idx)) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ��ȡap����sta ������ָ��
 �������  : en_vap_mode: en_vap_mode��ǰģʽ
 �� �� ֵ  : wmm����ָ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT mac_wme_param_stru *mac_get_wmm_cfg(wlan_vap_mode_enum_uint8 vap_mode)
{
    /* �ο���֤�����ã�û�а���Э�����ã�WLAN_VAP_MODE_BUTT��ʾ��ap�㲥��sta��edca���� */
    if (vap_mode == WLAN_VAP_MODE_BUTT) {
        return (mac_wme_param_stru  *)g_ast_wmm_initial_params_bss;
    } else if(vap_mode == WLAN_VAP_MODE_BSS_AP) {
        return (mac_wme_param_stru  *)g_ast_wmm_initial_params_ap;
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    } else if (vap_mode == WLAN_VAP_MODE_MESH) {
        return (mac_wme_param_stru  *)g_ast_wmm_initial_params_ap;
#endif
    }

    return (mac_wme_param_stru  *)g_ast_wmm_initial_params_sta;
}

/*****************************************************************************
 ��������  : ��ʼ��wme����, ��sta֮���ģʽ
 �������  : pst_wme_param: wme����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2012��12��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_init_wme_param(const mac_vap_stru *mac_vap)
{
    const mac_wme_param_stru   *wmm_param = HI_NULL;
    const mac_wme_param_stru   *wmm_param_sta = HI_NULL;
    hi_u8                       ac_type;

    wmm_param = mac_get_wmm_cfg(mac_vap->vap_mode);
    for (ac_type = 0; ac_type < WLAN_WME_AC_BUTT; ac_type++) {
        /* VAP�����EDCA���� */
        mac_vap->mib_info->wlan_mib_qap_edac[ac_type].dot11_qapedca_table_aifsn   =
            wmm_param[ac_type].aifsn;
        mac_vap->mib_info->wlan_mib_qap_edac[ac_type].dot11_qapedca_table_c_wmin   =
            wmm_param[ac_type].logcwmin;
        mac_vap->mib_info->wlan_mib_qap_edac[ac_type].dot11_qapedca_table_c_wmax   =
            wmm_param[ac_type].us_logcwmax;
        mac_vap->mib_info->wlan_mib_qap_edac[ac_type].dot11_qapedca_table_txop_limit =
            wmm_param[ac_type].txop_limit;
    }

    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
        || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
    ) {
        /* APģʽʱ�㲥��STA��EDCA������ֻ��APģʽ��Ҫ��ʼ����ֵ��ʹ��WLAN_VAP_MODE_BUTT�� */
        wmm_param_sta = mac_get_wmm_cfg(WLAN_VAP_MODE_BUTT);

        for (ac_type = 0; ac_type < WLAN_WME_AC_BUTT; ac_type++) {
            mac_vap->mib_info->ast_wlan_mib_edca[ac_type].dot11_edca_table_aifsn     =
                wmm_param_sta[ac_type].aifsn;
            mac_vap->mib_info->ast_wlan_mib_edca[ac_type].dot11_edca_table_c_wmin     =
                wmm_param_sta[ac_type].logcwmin;
            mac_vap->mib_info->ast_wlan_mib_edca[ac_type].dot11_edca_table_c_wmax     =
                wmm_param_sta[ac_type].us_logcwmax;
            mac_vap->mib_info->ast_wlan_mib_edca[ac_type].dot11_edca_table_txop_limit =
                wmm_param_sta[ac_type].txop_limit;
        }
    }
}

/*****************************************************************************
 ��������  : ���ӹ����û�����ȡhashֵ������hash����
 �������  : vap�����ڴ�ָ�룬�Լ�user����ָ��(user������Ҫ�ڵ��ô˺���ǰ���벢��ֵ)
 �޸���ʷ      :
  1.��    ��   : 2012��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_add_assoc_user(mac_vap_stru *mac_vap, hi_u8 user_idx)
{
    mac_user_stru              *user = HI_NULL;
    mac_res_user_hash_stru     *hash = HI_NULL;
    hi_u32                  rslt;
    hi_u8                   hash_idx;
    hi_list                    *dlist_head = HI_NULL;
    unsigned long            irq_save;
    user = mac_user_get_user_stru(user_idx);
    if (oal_unlikely(user == HI_NULL)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_add_assoc_user::pst_user[%d] null.}", user_idx);
        return HI_ERR_CODE_PTR_NULL;
    }
    user->user_hash_idx = mac_calculate_hash_value(user->user_mac_addr);
    rslt = mac_res_alloc_hash(&hash_idx);
    if (rslt != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_add_assoc_user::alloc hash failed[%d].}", rslt);
        return rslt;
    }
    hash = mac_res_get_hash(hash_idx);

    if (mac_vap_user_exist(&(user->user_dlist), &(mac_vap->mac_user_list_head))) {
        mac_res_free_hash(hash_idx);
        oam_error_log1(mac_vap->vap_id, OAM_SF_ASSOC,
            "{mac_vap_add_assoc_user::user[%d] already exist.}", user_idx);
        return HI_ERR_CODE_PTR_NULL;
    }
    hash->us_hash_res_idx = hash_idx; /* ��¼HASH��Ӧ����Դ������ֵ */
    hash->user_idx = user_idx; /* ��¼��Ӧ���û�����ֵ */
    dlist_head = &(mac_vap->ast_user_hash[user->user_hash_idx]);
    hi_list_head_insert(&(hash->entry), dlist_head);
    dlist_head = &(mac_vap->mac_user_list_head); /* ����˫�������ͷ */
    hi_list_head_insert(&(user->user_dlist), dlist_head);

    oal_spin_lock_irq_save(&mac_vap->cache_user_lock, &irq_save);

    if (memcpy_s(mac_vap->auc_cache_user_mac_addr, WLAN_MAC_ADDR_LEN, /* ����cache user */
                 user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ASSOC, "{mac_vap_add_assoc_user::mem safe func err!}");
        oal_spin_unlock_irq_restore(&mac_vap->cache_user_lock, &irq_save);
        return HI_FAIL;
    }
    mac_vap->cache_user_id = user_idx;

    oal_spin_unlock_irq_restore(&mac_vap->cache_user_lock, &irq_save);

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) { /* ��¼STAģʽ�µ���֮������VAP��id */
        mac_vap_set_assoc_id(mac_vap, user_idx);
    }
    mac_vap->user_nums++; /* vap�ѹ��� user����++ */
    return HI_SUCCESS;
}

WIFI_ROM_TEXT hi_u32 mac_vap_user_remove_list(const hi_list *hash_head, mac_user_stru *user, hi_u8 user_idx)
{
    mac_user_stru          *user_temp = HI_NULL;
    hi_list                *entry = HI_NULL;
    mac_res_user_hash_stru *user_hash = HI_NULL;
    hi_list                *dlist_tmp = HI_NULL;
    hi_u32                  ret = HI_FAIL;

    hi_list_for_each_safe(entry, dlist_tmp, hash_head) {
        user_hash = (mac_res_user_hash_stru *)entry;
        user_temp = mac_user_get_user_stru(user_hash->user_idx);
        if (user_temp == HI_NULL) {
            continue;
        }
        if (!oal_compare_mac_addr(user->user_mac_addr, user_temp->user_mac_addr, WLAN_MAC_ADDR_LEN)) {
            hi_list_delete(entry);
            /* ��˫�������в�� */
            hi_list_delete(&(user->user_dlist));
            mac_res_free_hash(user_hash->us_hash_res_idx);

            /* ��ʼ����Ӧ��Ա */
            user->user_hash_idx = 0xff;
            user->us_assoc_id   = user_idx;
            user->is_multi_user = HI_FALSE;
            /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
            memset_s(user->user_mac_addr, WLAN_MAC_ADDR_LEN, 0, WLAN_MAC_ADDR_LEN);
            user->vap_id          = 0x0f;
            user->user_asoc_state = MAC_USER_STATE_BUTT;

            ret = HI_SUCCESS;
        }
    }

    return ret;
}

/*****************************************************************************
 ��������  : ɾ���û������û���˫��������ɾ��������hash����ɾ��
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_del_user(mac_vap_stru *mac_vap, hi_u8 user_idx)
{
    mac_user_stru          *user = HI_NULL;
    hi_list                *hash_head = HI_NULL;
    hi_u32                 ret;
    unsigned long            irq_save;

    oal_spin_lock_irq_save(&mac_vap->cache_user_lock, &irq_save);

    if (user_idx == mac_vap->cache_user_id) { /* ��cache user id�Ա� , ��������cache user */
        oal_set_mac_addr_zero(mac_vap->auc_cache_user_mac_addr);
        mac_vap->cache_user_id = MAC_INVALID_USER_ID;
    }

    oal_spin_unlock_irq_restore(&mac_vap->cache_user_lock, &irq_save);

    user = mac_user_get_user_stru(user_idx);
    if (oal_unlikely(user == HI_NULL)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ASSOC,
            "{mac_vap_del_user::pst_user null, user_idx is %d}", user_idx);
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_user_set_asoc_state(user, MAC_USER_STATE_BUTT);
    if (user->user_hash_idx >= MAC_VAP_USER_HASH_MAX_VALUE) {
        /* ADD USER���ʧ�������ظ�ɾ��User�����ܽ���˷�֧ */
        oam_error_log1(mac_vap->vap_id, OAM_SF_ASSOC,
            "{mac_vap_del_user::hash idx invaild %u}", user->user_hash_idx);
        return HI_FAIL;
    }

    hash_head = &(mac_vap->ast_user_hash[user->user_hash_idx]);
    ret = mac_vap_user_remove_list(hash_head, user, user_idx);
    if (ret == HI_SUCCESS) {
        /* vap�ѹ��� user����-- */
        if (mac_vap->user_nums) {
            mac_vap->user_nums--;
        }
        /* STAģʽ�½�������VAP��id��Ϊ�Ƿ�ֵ */
        if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            mac_vap_set_assoc_id(mac_vap, 0xff);
        }
        return HI_SUCCESS;
    }

    oam_warning_log1(mac_vap->vap_id, OAM_SF_ASSOC,
        "{mac_vap_del_user::delete user failed,user idx is %d.}", user_idx);

    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ����user MAC��ַ����user����
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_find_user_by_macaddr(mac_vap_stru *mac_vap, const hi_u8 *sta_mac_addr, hi_u8 mac_addr_len,
    hi_u8 *puc_user_idx)
{
    mac_user_stru              *mac_user = HI_NULL;
    hi_u32                  user_hash_value;
    mac_res_user_hash_stru     *hash = HI_NULL;
    hi_list                    *entry = HI_NULL;
    unsigned long            irq_save;

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        mac_user = mac_user_get_user_stru(mac_vap->assoc_vap_id);
        if (mac_user == HI_NULL) {
            return HI_FAIL;
        }
        if (!oal_compare_mac_addr(mac_user->user_mac_addr, sta_mac_addr, mac_addr_len)) {
            *puc_user_idx = mac_vap->assoc_vap_id;
            return (hi_u32)((*puc_user_idx != MAC_INVALID_USER_ID) ? HI_SUCCESS : HI_FAIL);
        }
        return HI_FAIL;
    }

    oal_spin_lock_irq_save(&mac_vap->cache_user_lock, &irq_save);

    /* ��cache user�Ա� , �����ֱ�ӷ���cache user id */
    if (!oal_compare_mac_addr(mac_vap->auc_cache_user_mac_addr, sta_mac_addr, mac_addr_len)) {
        *puc_user_idx = mac_vap->cache_user_id;
        oal_spin_unlock_irq_restore(&mac_vap->cache_user_lock, &irq_save);
        return (hi_u32)((*puc_user_idx != MAC_INVALID_USER_ID) ? HI_SUCCESS : HI_FAIL);
    }

    user_hash_value = mac_calculate_hash_value(sta_mac_addr);
    hi_list_for_each(entry, &(mac_vap->ast_user_hash[user_hash_value])) {
        hash = (mac_res_user_hash_stru *)entry;

        mac_user = mac_user_get_user_stru(hash->user_idx);
        if (mac_user == HI_NULL) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_ANY,
                           "{mac_vap_find_user_by_macaddr::pst_mac_user null.user idx %d}",
                           hash->user_idx);
            continue;
        }

        /* ��ͬ��MAC��ַ */
        if (!oal_compare_mac_addr(mac_user->user_mac_addr, sta_mac_addr, mac_addr_len)) {
            *puc_user_idx = hash->user_idx;
            /* ����cache user */
            if (memcpy_s(mac_vap->auc_cache_user_mac_addr, WLAN_MAC_ADDR_LEN,
                         mac_user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
                oam_error_log0(0, 0, "{mac_vap_find_user_by_macaddr::mem safe func err!}");
                continue;
            }
            mac_vap->cache_user_id = (hi_u8)hash->user_idx;
            oal_spin_unlock_irq_restore(&mac_vap->cache_user_lock, &irq_save);
            return (hi_u32)((*puc_user_idx != MAC_INVALID_USER_ID) ? HI_SUCCESS : HI_FAIL);
        }
    }
    oal_spin_unlock_irq_restore(&mac_vap->cache_user_lock, &irq_save);

    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ��ʼ��11n��mib
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_mib_11n(const mac_vap_stru  *mac_vap)
{
    wlan_mib_ieee802dot11_stru    *mib_info = HI_NULL;
    mac_device_stru               *mac_dev = HI_NULL;
    mac_dev = mac_res_get_dev();
    mib_info = mac_vap->mib_info;
    mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented = HI_FALSE;
    mib_info->phy_ht.dot11_ldpc_coding_option_implemented         = HI_FALSE;
    mib_info->phy_ht.dot11_ldpc_coding_option_activated           = HI_FALSE;
    mib_info->phy_ht.dot11_tx_stbc_option_activated               = HI_FALSE;
    mib_info->phy_ht.dot112_g_forty_m_hz_operation_implemented      = HI_FALSE;
    mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented    = HI_TRUE;
    mib_info->phy_ht.dot112_g_short_gi_option_in_forty_implemented   = HI_FALSE;
    mib_info->phy_ht.dot11_tx_stbc_option_implemented = mac_dev->tx_stbc;
    mib_info->phy_ht.dot11_rx_stbc_option_implemented = mac_dev->rx_stbc;
    mib_info->wlan_mib_operation.dot11_obss_scan_passive_dwell = 20; /* obss����ɨ��ʱÿ���ŵ���ɨ��ʱ�� 20 TUs */
    mib_info->wlan_mib_operation.dot11_obss_scan_active_dwell  = 10; /* ����ɨ��ʱ�� 10TUs */
    /* ��ֹhostĬ�ϲ��������ap�·�����һ�£���ִ��ɨ��,�ؽ�300s��С
        host����obss ɨ����������300s�ʴ˴�ֻҪС��300���� */
    mib_info->wlan_mib_operation.dot11_bss_width_trigger_scan_interval           = 299; /* ����Ϊ299 */
    mib_info->wlan_mib_operation.dot11_obss_scan_passive_total_per_channel       = 200; /* ����Ϊ200 */
    mib_info->wlan_mib_operation.dot11_obss_scan_active_total_per_channel        = 20;  /* ����Ϊ20 */
    mib_info->wlan_mib_operation.dot11_bss_width_channel_transition_delay_factor = 5;   /* ����Ϊ5 */
    mib_info->wlan_mib_operation.dot11_obss_scan_activity_threshold              = 25;  /* ����Ϊ25 */
    mac_mib_init_2040(mac_vap);
}

/*****************************************************************************
 ��������  : ��ʼ��11i mib��Ϣ
 �������  : pst_vap ָ��VAP�û���ָ��
 �޸���ʷ      :
  1.��    ��   : 2013��6��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_mib_11i(const mac_vap_stru  *mac_vap)
{
    /* WEP��WAPI���ܷ�ʽʱ��IBSS����Ҫȥʹ�� */
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated                   = HI_FALSE;
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpr                        = HI_FALSE;
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpc                        = HI_FALSE;
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_preauthentication_activated  = HI_FALSE;
    mac_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked                  = HI_FALSE;
    /* Version��ϢΪ1 */
    /* see <80211-2012> chapter 8.4.2.27 RSN elemet  */
    /* RSN Version 1 is defined in this standard */
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_version = MAC_RSN_IE_VERSION;
    if (mac_vap->cap_flag.wpa2) {
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher = WLAN_80211_CIPHER_SUITE_CCMP;
        /* CCMP���ܷ�ʽ��GTK��bitλΪ256 */
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher_size = WLAN_CCMP_KEY_LEN * 8; /* ��8תbit */
    }
    if (mac_vap->cap_flag.wpa) {
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher = WLAN_80211_CIPHER_SUITE_TKIP;
        /* TKIP���ܷ�ʽ��GTK��bitλΪ256 */
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher_size = WLAN_TKIP_KEY_LEN * 8; /* ��8תbit */
    }
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_pairwise_cipher_requested       = 0;
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_group_cipher_requested          = 0;
    /* wpa PairwiseCipher CCMP */
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[0].dot11_rsna_config_pairwise_cipher_implemented  =
        WLAN_80211_CIPHER_SUITE_CCMP;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[0].dot11_rsna_config_pairwise_cipher_activated    =
        HI_FALSE;
    /* wpa PairwiseCipher TKIP */
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[1].dot11_rsna_config_pairwise_cipher_implemented  =
        WLAN_80211_CIPHER_SUITE_TKIP;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher[1].dot11_rsna_config_pairwise_cipher_activated    =
        HI_FALSE;
    /* wpa2 PairwiseCipher CCMP */
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[0].dot11_rsna_config_pairwise_cipher_implemented =
        WLAN_80211_CIPHER_SUITE_CCMP;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[0].dot11_rsna_config_pairwise_cipher_activated   =
        HI_FALSE;
    /* wpa2 PairwiseCipher TKIP */
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[1].dot11_rsna_config_pairwise_cipher_implemented =
        WLAN_80211_CIPHER_SUITE_TKIP;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher[1].dot11_rsna_config_pairwise_cipher_activated   =
        HI_FALSE;
    /* AuthenticationSuite */
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[0].dot11_rsna_config_authentication_suite_implemented =
        WLAN_AUTH_SUITE_PSK;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[0].dot11_rsna_config_authentication_suite_activated   =
        HI_FALSE;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[1].dot11_rsna_config_authentication_suite_implemented =
        WLAN_AUTH_SUITE_PSK_SHA256;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[1].dot11_rsna_config_authentication_suite_activated   =
        HI_FALSE;
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_number_of_ptksa_replay_counters_implemented = 0;
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_number_of_gtksa_replay_counters_implemented = 0;
}

/*****************************************************************************
��������  : ��ʼ��11a 11g����
�޸���ʷ      :
  1.��    ��   : 2013��7��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_legacy_rates(mac_vap_stru *mac_vap, mac_data_rate_stru *rates)
{
    hi_u8                      rate_index;
    hi_u8                      curr_rate_index = 0;
    mac_data_rate_stru            *puc_orig_rate = HI_NULL;
    mac_data_rate_stru            *puc_curr_rate = HI_NULL;
    hi_u8                      rates_num;

    /* ��ʼ�����ʼ� */
    rates_num = MAC_DATARATES_PHY_80211G_NUM;
    /* ��ʼ�����ʸ������������ʸ������ǻ������ʸ��� */
    mac_vap->curr_sup_rates.rate.rs_nrates = MAC_NUM_DR_802_11G;
    mac_vap->curr_sup_rates.br_rate_num       = MAC_NUM_BR_802_11G;
    mac_vap->curr_sup_rates.nbr_rate_num      = MAC_NUM_NBR_802_11G;
    mac_vap->curr_sup_rates.min_rate          = 6;  /* ��С������������Ϊ6 */
    mac_vap->curr_sup_rates.max_rate          = 24; /* ��������������Ϊ24 */
    /* �����ʿ�����VAP�ṹ���µ����ʼ��� */
    for (rate_index = 0; rate_index < rates_num; rate_index++) {
        puc_orig_rate = &rates[rate_index];
        puc_curr_rate = &(mac_vap->curr_sup_rates.rate.ast_rs_rates[curr_rate_index]);
        /* Basic Rates */
        if ((puc_orig_rate->mbps == 6) || (puc_orig_rate->mbps == 12) || /* �ж�mbps 6/12 */
            (puc_orig_rate->mbps == 24)) {                               /* �ж�mbps 24 */
            if (memcpy_s(puc_curr_rate, sizeof(mac_data_rate_stru), puc_orig_rate,
                sizeof(mac_data_rate_stru)) != EOK) {
                continue;
            }
            puc_curr_rate->mac_rate |= 0x80;
            curr_rate_index++;
        } else if ((puc_orig_rate->mbps == 9) || (puc_orig_rate->mbps == 18) || /* �ж�mbps 9/18 */
            (puc_orig_rate->mbps == 36) || (puc_orig_rate->mbps == 48) ||      /* �ж�mbps 36/48 */
            (puc_orig_rate->mbps == 54)) {                                     /* �ж�mbps 54 */
            /* Non-basic rates */
            if (memcpy_s(puc_curr_rate, sizeof(mac_data_rate_stru), puc_orig_rate,
                sizeof(mac_data_rate_stru)) != EOK) {
                return;
            }
            curr_rate_index++;
        }
        if (curr_rate_index == mac_vap->curr_sup_rates.rate.rs_nrates) {
            break;
        }
    }
}

/*****************************************************************************
��������  : ��ʼ��11b����
�޸���ʷ      :
  1.��    ��   : 2013��7��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_11b_rates(mac_vap_stru *mac_vap, mac_data_rate_stru *rates)
{
    hi_u8                      rate_index;
    hi_u8                      curr_rate_index = 0;
    mac_data_rate_stru            *puc_orig_rate = HI_NULL;
    mac_data_rate_stru            *puc_curr_rate = HI_NULL;
    hi_u8                      rates_num;

    /* ��ʼ�����ʼ� */
    rates_num = MAC_DATARATES_PHY_80211G_NUM;
    /* ��ʼ�����ʸ������������ʸ������ǻ������ʸ��� */
    mac_vap->curr_sup_rates.rate.rs_nrates = MAC_NUM_DR_802_11B;
    mac_vap->curr_sup_rates.br_rate_num       = 0;
    mac_vap->curr_sup_rates.nbr_rate_num      = MAC_NUM_NBR_802_11B;
    mac_vap->curr_sup_rates.min_rate          = 1;
    mac_vap->curr_sup_rates.max_rate          = 2; /* ��������������Ϊ2 */
    /* �����ʿ�����VAP�ṹ���µ����ʼ��� */
    for (rate_index = 0; rate_index < rates_num; rate_index++) {
        puc_orig_rate = &rates[rate_index];
        puc_curr_rate = &(mac_vap->curr_sup_rates.rate.ast_rs_rates[curr_rate_index]);
        /*  Basic Rates  */
        if ((puc_orig_rate->mbps == 1) || (puc_orig_rate->mbps == 2) ||     /* mbps 1/2 ΪBasic Rates */
            ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) &&
             ((puc_orig_rate->mbps == 5) || (puc_orig_rate->mbps == 11)))) { /* mbps 5/11 ΪBasic Rates */
            mac_vap->curr_sup_rates.br_rate_num++;
            if (memcpy_s(puc_curr_rate, sizeof(mac_data_rate_stru), puc_orig_rate, sizeof(mac_data_rate_stru)) != EOK) {
                oam_error_log0(0, 0, "{mac_vap_init_11b_rates::mem safe func err!}");
                continue;
            }
            puc_curr_rate->mac_rate |= 0x80;
            curr_rate_index++;
        } else if (((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) /* Non-basic rates */
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
                || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        ) && ((puc_orig_rate->mbps == 5) || (puc_orig_rate->mbps == 11))) { /* �ж�mbps 5/11 */
            if (memcpy_s(puc_curr_rate, sizeof(mac_data_rate_stru), puc_orig_rate, sizeof(mac_data_rate_stru)) != EOK) {
                oam_error_log0(0, 0, "{mac_vap_init_11b_rates::mem safe func err!}");
                continue;
            }
            /* ��ʼ��11b����ʱ������λ��0 */
            puc_curr_rate->mac_rate &= 0x7f;
            curr_rate_index++;
        } else {
            continue;
        }
        if (curr_rate_index == mac_vap->curr_sup_rates.rate.rs_nrates) {
            break;
        }
    }
}

/*****************************************************************************
��������  : ��ʼ��11g ���1����
�޸���ʷ      :
  1.��    ��   : 2013��7��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_11g_mixed_one_rates(mac_vap_stru *mac_vap, mac_data_rate_stru *rates)
{
    hi_u8                      rate_index;
    mac_data_rate_stru            *puc_orig_rate = HI_NULL;
    mac_data_rate_stru            *puc_curr_rate = HI_NULL;
    hi_u8                      rates_num;

    /* ��ʼ�����ʼ� */
    rates_num = MAC_DATARATES_PHY_80211G_NUM;
    /* ��ʼ�����ʸ������������ʸ������ǻ������ʸ��� */
    mac_vap->curr_sup_rates.rate.rs_nrates = MAC_NUM_DR_802_11G_MIXED;
    mac_vap->curr_sup_rates.br_rate_num       = MAC_NUM_BR_802_11G_MIXED_ONE;
    mac_vap->curr_sup_rates.nbr_rate_num      = MAC_NUM_NBR_802_11G_MIXED_ONE;
    mac_vap->curr_sup_rates.min_rate          = 1;
    mac_vap->curr_sup_rates.max_rate          = 11; /* max_rate ����Ϊ11 */
    /* �����ʿ�����VAP�ṹ���µ����ʼ��� */
    for (rate_index = 0; rate_index < rates_num; rate_index++) {
        puc_orig_rate = &rates[rate_index];
        puc_curr_rate = &(mac_vap->curr_sup_rates.rate.ast_rs_rates[rate_index]);
        if (memcpy_s(puc_curr_rate, sizeof(mac_data_rate_stru), puc_orig_rate, sizeof(mac_data_rate_stru)) != EOK) {
            continue;
        }
        /* Basic Rates */
        if ((puc_orig_rate->mbps == 1) || (puc_orig_rate->mbps == 2)         /* mbps 1/2 ΪBasic Rates */
            || (puc_orig_rate->mbps == 5) || (puc_orig_rate->mbps == 11)) { /* mbps 5/11 ΪBasic Rates */
            puc_curr_rate->mac_rate |= 0x80;
        }
    }
}

/*****************************************************************************
��������  : ��ʼ��11g mixed two����
�޸���ʷ      :
  1.��    ��   : 2013��7��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_11g_mixed_two_rates(mac_vap_stru *mac_vap, mac_data_rate_stru *rates)
{
    hi_u8                      rate_index;
    mac_data_rate_stru            *puc_orig_rate = HI_NULL;
    mac_data_rate_stru            *puc_curr_rate = HI_NULL;
    hi_u8                      rates_num;

    /* ��ʼ�����ʼ� */
    rates_num = MAC_DATARATES_PHY_80211G_NUM;
    /* ��ʼ�����ʸ������������ʸ������ǻ������ʸ��� */
    mac_vap->curr_sup_rates.rate.rs_nrates = MAC_NUM_DR_802_11G_MIXED;
    mac_vap->curr_sup_rates.br_rate_num       = MAC_NUM_BR_802_11G_MIXED_TWO;
    mac_vap->curr_sup_rates.nbr_rate_num      = MAC_NUM_NBR_802_11G_MIXED_TWO;
    mac_vap->curr_sup_rates.min_rate          = 1;
    mac_vap->curr_sup_rates.max_rate          = 24; /* max_rate����Ϊ24 */
    /* �����ʿ�����VAP�ṹ���µ����ʼ��� */
    for (rate_index = 0; rate_index < rates_num; rate_index++) {
        puc_orig_rate = &rates[rate_index];
        puc_curr_rate = &(mac_vap->curr_sup_rates.rate.ast_rs_rates[rate_index]);
        if (memcpy_s(puc_curr_rate, sizeof(mac_data_rate_stru), puc_orig_rate, sizeof(mac_data_rate_stru)) != EOK) {
            continue;
        }
        /* Basic Rates */
        if ((puc_orig_rate->mbps == 1) || (puc_orig_rate->mbps == 2) ||   /* mbps 1/2 ΪBasic Rates */
            (puc_orig_rate->mbps == 5) || (puc_orig_rate->mbps == 11) || /* mbps 5/11 ΪBasic Rates */
            (puc_orig_rate->mbps == 6) || (puc_orig_rate->mbps == 12)    /* mbps 6/12 ΪBasic Rates */
            || (puc_orig_rate->mbps == 24)) {                            /* mbps 24 ΪBasic Rates */
            puc_curr_rate->mac_rate |= 0x80;
        }
    }
}

/*****************************************************************************
��������  : ��ʼ��11n����
�޸���ʷ      :
  1.��    ��   : 2013��7��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_vap_init_11n_rates(const mac_vap_stru *mac_vap)
{
    wlan_mib_ieee802dot11_stru    *mib_info = HI_NULL;

    mib_info = mac_vap->mib_info;
    /* MCS���MIBֵ��ʼ�� */
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(mib_info->supported_mcsrx.auc_dot11_supported_mcs_rx_value, WLAN_HT_MCS_BITMASK_LEN, 0,
        WLAN_HT_MCS_BITMASK_LEN);
    mib_info->supported_mcsrx.auc_dot11_supported_mcs_rx_value[0] = 0xFF; /* ֧�� RX MCS 0-7��8λȫ��Ϊ1 */
    mib_info->supported_mcstx.auc_dot11_supported_mcs_tx_value[0] = 0xFF; /* ֧�� TX MCS 0-7��8λȫ��Ϊ1 */
}

/*****************************************************************************
 ��������  : ��ʼ��p2p vap�����ʼ�
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_init_p2p_rates(mac_vap_stru *mac_vap, mac_data_rate_stru *rates)
{
    mac_vap_init_legacy_rates(mac_vap, rates);
    /* begin:DTS2015041102828 1102 ��listen channel��probe respons Я�����ʼ����ظ�IE.  */
    mac_vap_init_11n_rates(mac_vap);
}

WIFI_ROM_TEXT hi_void mac_vap_init_rates_by_protocol(mac_vap_stru *mac_vap, wlan_protocol_enum_uint8 vap_protocol,
                                                     mac_data_rate_stru *rates)
{
    /* STAģʽĬ��Э��ģʽ��11n����ʼ�����ʼ�Ϊ�������ʼ� */
#ifdef _PRE_WLAN_FEATURE_P2P_ROM
    if (!is_legacy_vap(mac_vap)) {
        mac_vap_init_p2p_rates(mac_vap, rates);
        return;
    }
#endif
    if ((vap_protocol == WLAN_HT_ONLY_MODE) || (vap_protocol == WLAN_HT_MODE)) {
        mac_vap_init_11g_mixed_one_rates(mac_vap, rates);
        mac_vap_init_11n_rates(mac_vap);
    } else if (vap_protocol == WLAN_LEGACY_11G_MODE) {
        mac_vap_init_legacy_rates(mac_vap, rates);
    } else if (vap_protocol == WLAN_LEGACY_11B_MODE) {
        mac_vap_init_11b_rates(mac_vap, rates);
    } else if (vap_protocol == WLAN_MIXED_ONE_11G_MODE) {
        mac_vap_init_11g_mixed_one_rates(mac_vap, rates);
    } else if (vap_protocol == WLAN_MIXED_TWO_11G_MODE) {
        mac_vap_init_11g_mixed_two_rates(mac_vap, rates);
    } else {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY,
            "{mac_vap_init_rates_by_protocol::protocol[%d] isn't supportted.}",vap_protocol);
    }
}

/*****************************************************************************
��������  : ��ʼ�����ʼ�
�޸���ʷ      :
 1.��    ��   : 2013��7��30��
    ��    ��   : Hisilicon
   �޸�����   : �����ɺ���
 2.��    ��   : 2013��11��6��
    ��    ��   : Hisilicon
   �޸�����   : �޸Ĳ�ͬЭ��ģʽ���ʳ�ʼ��

*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_init_rates(mac_vap_stru *mac_vap)
{
    mac_device_stru               *mac_dev = HI_NULL;
    wlan_protocol_enum_uint8       vap_protocol;
    mac_data_rate_stru            *rates = HI_NULL;

    mac_dev = mac_res_get_dev();
    /* ��ʼ�����ʼ� */
    rates   = &mac_dev->mac_rates_11g[0];
    vap_protocol = mac_vap->protocol;
    mac_vap_init_rates_by_protocol(mac_vap, vap_protocol, rates);
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM

/*****************************************************************************
��������  : ����wpa�·���mesh���ò�������Mesh���Mibֵ
                            ��ǰֻ֧������auth protocol
�������  :mac_vap_stru *pst_vap
                            hi_u8 uc_mesh_formation_info
                            hi_u8 uc_mesh_capability
�޸���ʷ      :
 1.��    ��   : 2019��3��19��
    ��    ��   : Hisilicon
   �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_set_mib_mesh(const mac_vap_stru *mac_vap, hi_u8 mesh_auth_protocol)
{
    /* �����֮ǰ����Ϣ */
    mac_mib_set_mesh_security(mac_vap, HI_FALSE);
    mac_mib_clear_mesh_auth_protocol(mac_vap);

    if (mesh_auth_protocol == 0) {
        mac_mib_set_mesh_security(mac_vap, HI_FALSE);
        mac_mib_set_mesh_auth_protocol(mac_vap, 0);
    } else {
        mac_mib_set_mesh_security(mac_vap, HI_TRUE);
        mac_mib_set_mesh_auth_protocol(mac_vap, mesh_auth_protocol);
    }

    oam_warning_log2(mac_vap->vap_id, OAM_SF_ANY,
                     "{mac_vap_set_mib_mesh::meshSecurityActivated = %d , meshactiveAuthenticationProtocol = %d}",
                     mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_security_activated,
                     mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol);
}
#endif

/*****************************************************************************
 ��������  : ɾ��P2P vap num�Ĺ��ܺ���
 �޸���ʷ      :
  1.��    ��   : 2014��11��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_dec_p2p_num(const mac_vap_stru *mac_vap)
{
    mac_device_stru               *mac_dev = HI_NULL;

    mac_dev     = mac_res_get_dev();
    if (is_p2p_dev(mac_vap)) {
        mac_dev->p2p_info.p2p_device_num--;
    } else if (is_p2p_go(mac_vap) || is_p2p_cl(mac_vap)) {
        mac_dev->p2p_info.p2p_goclient_num--;
    }
}

/*****************************************************************************
 ��������  : add p2p vapʱͬ������p2p�豸�ļ�����
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_inc_p2p_num(const mac_vap_stru *mac_vap)
{
    mac_device_stru               *mac_dev = HI_NULL;

    mac_dev = mac_res_get_dev();
    if (is_p2p_dev(mac_vap)) {
        /* device��sta������1 */
        mac_dev->sta_num++;
        mac_dev->p2p_info.p2p_device_num++;
    } else if (is_p2p_go(mac_vap)) {
        mac_dev->p2p_info.p2p_goclient_num++;
    } else if (is_p2p_cl(mac_vap)) {
        mac_dev->p2p_info.p2p_goclient_num++;
    }
}

/*****************************************************************************
��������  : ���û�̬ IE ��Ϣ�������ں�̬��
�������  : mac_vap_stru *pst_mac_vap
          oal_net_dev_ioctl_data_stru *pst_ioctl_data
          enum WPS_IE_TYPE en_type
�޸���ʷ      :
 1.��    ��   : 2015��4��28��
    ��    ��   : Hisilicon
  �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_save_app_ie(mac_vap_stru *mac_vap, const oal_app_ie_stru *app_ie,
    en_app_ie_type_uint8 type)
{
    hi_u8           *puc_ie = HI_NULL;
    hi_u32           ie_len;

    if (type >= OAL_APP_IE_NUM) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{mac_vap_save_app_ie::invalid en_type[%d].}", type);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    ie_len = app_ie->ie_len;
    /* �������WPS ����Ϊ0�� ��ֱ���ͷ�VAP ����Դ */
    if (ie_len == 0) {
        if (mac_vap->ast_app_ie[type].puc_ie != HI_NULL) {
            oal_mem_free(mac_vap->ast_app_ie[type].puc_ie);
        }
        mac_vap->ast_app_ie[type].puc_ie         = HI_NULL;
        mac_vap->ast_app_ie[type].ie_len      = 0;
        return HI_SUCCESS;
    }
    /* �������͵�IE�Ƿ���Ҫ�����ڴ� */
    if ((mac_vap->ast_app_ie[type].ie_len < ie_len) || (mac_vap->ast_app_ie[type].puc_ie == HI_NULL)) {
        /* �����ǰ���ڴ�ռ�С������ϢԪ����Ҫ�ĳ��ȣ�����Ҫ���������ڴ� */
        puc_ie = oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, (hi_u16)(ie_len));
        if (puc_ie == HI_NULL) {
            oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG,
                             "{mac_vap_set_app_ie::LOCAL_MEM_POOL is empty!,len[%d], en_type[%d].}",
                             app_ie->ie_len, type);
            return HI_ERR_CODE_ALLOC_MEM_FAIL;
        }
        if (mac_vap->ast_app_ie[type].puc_ie != HI_NULL) {
            oal_mem_free(mac_vap->ast_app_ie[type].puc_ie);
        }
        mac_vap->ast_app_ie[type].puc_ie = puc_ie;
    }
    if (memcpy_s((hi_void*)mac_vap->ast_app_ie[type].puc_ie, ie_len, (hi_void*)app_ie->auc_ie, ie_len) != EOK) {
        if (puc_ie != HI_NULL) {
            oal_mem_free(puc_ie);
            mac_vap->ast_app_ie[type].puc_ie = HI_NULL;
        }
        return HI_FAIL;
    }
    mac_vap->ast_app_ie[type].ie_len = ie_len;
    return HI_SUCCESS;
}

 /*****************************************************************************
 ��������  : mac vap exit
 �޸���ʷ      :
  1.��    ��   : 2013��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_exit(mac_vap_stru *mac_vap)
{
    mac_device_stru               *mac_dev = HI_NULL;
    hi_u8                      index;

    /* �ͷ���hmac�йص��ڴ� */
    mac_vap_free_mib(mac_vap);
    /* �ͷ�WPS��ϢԪ���ڴ� */
    for (index = 0; index < OAL_APP_IE_NUM; index++) {
        mac_vap_clear_app_ie(mac_vap, index);
    }
    /* ҵ��vap��ɾ������device��ȥ�� */
    mac_dev     = mac_res_get_dev();
    /* ҵ��vap�Ѿ�ɾ������device��ȥ�� */
    for (index = 0; index < mac_dev->vap_num; index++) {
        /* ��device���ҵ�vap id */
        if (mac_dev->auc_vap_id[index] == mac_vap->vap_id) {
            /* ����������һ��vap��������һ��vap id�ƶ������λ�ã�ʹ�ø������ǽ��յ� */
            if (index < (mac_dev->vap_num - 1)) {
                mac_dev->auc_vap_id[index] = mac_dev->auc_vap_id[mac_dev->vap_num - 1];
                break;
            }
        }
    }
    /* device�µ�vap������1 */
    mac_dev->vap_num--;
    /* �����������ɾ����vap id����֤��������Ԫ�ؾ�Ϊδɾ��vap */
    mac_dev->auc_vap_id[mac_dev->vap_num] = 0;
    /* device��sta������1 */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        mac_dev->sta_num--;
    }
#ifdef _PRE_WLAN_FEATURE_P2P_ROM
    mac_dec_p2p_num(mac_vap);
#endif
    mac_vap->protocol  = WLAN_PROTOCOL_BUTT;
    /* ���1��vapɾ��ʱ�����device��������Ϣ */
    if (mac_dev->vap_num == 0) {
        mac_dev->max_channel   = 0;
        mac_dev->max_band      = WLAN_BAND_BUTT;
        mac_dev->max_bandwidth = WLAN_BAND_WIDTH_BUTT;
    }
    /* ɾ��֮��vap��״̬��λ�Ƿ� */
    mac_vap_state_change(mac_vap, MAC_VAP_STATE_BUTT);
}

/*****************************************************************************
 ��������  : mib��ʼ������
 �޸���ʷ      :
  1.��    ��   : 2013��7��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2013��11��6��
    ��    ��   : Hisilicon
    �޸�����   : ����HT only��VHT onlyЭ��ģʽ�ĳ�ʼ��
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_init_mib(const mac_vap_stru *mac_vap)
{
    wlan_mib_ieee802dot11_stru *mib_info = HI_NULL;
    hi_u8 idx;

    mib_info = mac_vap->mib_info;
    /* ��������mibֵ��ʼ�� */
    mib_info->wlan_mib_sta_config.dot11_dtim_period             = WLAN_DTIM_DEFAULT;
    mib_info->wlan_mib_operation.dot11_rts_threshold            = WLAN_RTS_MAX;
    mib_info->wlan_mib_operation.dot11_fragmentation_threshold  = WLAN_FRAG_THRESHOLD_MAX;
    mib_info->wlan_mib_sta_config.dot11_desired_bss_type         = WLAN_MIB_DESIRED_BSSTYPE_INFRA;
    mib_info->wlan_mib_sta_config.dot11_beacon_period           = WLAN_BEACON_INTVAL_DEFAULT;
    mib_info->phy_hrdsss.dot11_short_preamble_option_implemented  = WLAN_LEGACY_11B_MIB_SHORT_PREAMBLE;
    mib_info->phy_hrdsss.dot11_pbcc_option_implemented           = HI_FALSE;
    mib_info->phy_hrdsss.dot11_channel_agility_present           = HI_FALSE;
    mib_info->wlan_mib_sta_config.dot11_multi_domain_capability_activated = HI_TRUE;
    mib_info->wlan_mib_sta_config.dot11_spectrum_management_required = HI_TRUE;
    mib_info->wlan_mib_sta_config.dot11_extended_channel_switch_activated = HI_FALSE;
    mib_info->wlan_mib_sta_config.dot11_qos_option_implemented   = HI_TRUE;
    mib_info->wlan_mib_sta_config.dot11_apsd_option_implemented  = HI_FALSE;
    mib_info->wlan_mib_sta_config.dot11_qbss_load_implemented    = HI_TRUE;
    mib_info->wlan_mib_sta_config.dot11_radio_measurement_activated = HI_FALSE;
    mib_info->wlan_mib_sta_config.dot11_immediate_block_ack_option_implemented = HI_TRUE;
    mib_info->wlan_mib_sta_config.dot11_delayed_block_ack_option_implemented   = HI_FALSE;
    mib_info->wlan_mib_sta_config.dot11_authentication_response_time_out = WLAN_AUTH_TIMEOUT;
    mib_info->wlan_mib_operation.dot11_ht_protection = WLAN_MIB_HT_NO_PROTECTION;
    mib_info->wlan_mib_operation.dot11_rifs_mode = HI_TRUE;
    mib_info->wlan_mib_operation.dot11_non_gf_entities_present = HI_FALSE;
    mib_info->wlan_mib_operation.dot11_lsigtxop_full_protection_activated = HI_TRUE;
    mib_info->wlan_mib_sta_config.dot11_association_response_time_out = WLAN_ASSOC_TIMEOUT;
    mib_info->wlan_mib_sta_config.dot11_association_sa_query_maximum_timeout = WLAN_SA_QUERY_RETRY_TIME;
    mib_info->wlan_mib_sta_config.dot11_association_sa_query_retry_timeout   = WLAN_SA_QUERY_MAXIMUM_TIME;
    /* ��֤�㷨���ʼ�� */
    mib_info->wlan_mib_auth_alg.dot11_authentication_algorithm = WLAN_WITP_AUTH_OPEN_SYSTEM;
    mib_info->wlan_mib_auth_alg.dot11_authentication_algorithms_activated = HI_FALSE;
    /* WEP ȱʡKey���ʼ�� */
    for (idx = 0; idx < WLAN_NUM_DOT11WEPDEFAULTKEYVALUE; idx++) {
        mib_info->ast_wlan_mib_wep_dflt_key[idx].auc_dot11_wep_default_key_value[WLAN_WEP_SIZE_OFFSET] =
            40; /* ��С��ʼ��Ϊ WEP-40  */
    }
    /*    ���˽�б��ʼ��  */
    mib_info->wlan_mib_privacy.dot11_privacy_invoked                 = HI_FALSE;
    mib_info->wlan_mib_privacy.dot11_wep_default_key_id                = 0;
    mac_vap_init_wme_param(mac_vap);
    mac_vap_init_mib_11i(mac_vap);
    /* Ĭ��11n 11acʹ�ܹرգ�����Э��ģʽʱ�� */
    mac_vap_init_mib_11n(mac_vap);
    mib_info->wlan_mib_sta_config.dot11_power_management_mode = WLAN_MIB_PWR_MGMT_MODE_ACTIVE;
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    mac_vap_init_mib_mesh(mac_vap);
#endif
}

/*****************************************************************************
 ��������  : ����VAP Э��ģʽ����ʼ��vap HT/VHT ��Ӧ MIB ����
 �������  : pst_mac_vap: ָ��vap
 �޸���ʷ      :
  1.��    ��   : 2013��12��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_config_vht_ht_mib_by_protocol(const mac_vap_stru *mac_vap)
{
    if (mac_vap->mib_info == HI_NULL) {
        oam_error_log3(mac_vap->vap_id, OAM_SF_ASSOC,
            "{mac_vap_config_vht_ht_mib_by_protocol::pst_mib_info null,vap mode[%d] state[%d] user num[%d].}",
            mac_vap->vap_mode, mac_vap->vap_state, mac_vap->user_nums);
        return HI_FAIL;
    }
    if ((mac_vap->protocol == WLAN_HT_MODE) || (mac_vap->protocol == WLAN_HT_ONLY_MODE)) {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented = HI_TRUE;
    } else {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented = HI_FALSE;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����Э���ʼ��vap��Ӧ����
 �������  : pst_mac_vap: ָ��vap
             en_protocol: Э��ö�� ���ú���  :
 �޸���ʷ      :
  1.��    ��   : 2013��11��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_init_by_protocol(mac_vap_stru *mac_vap, wlan_protocol_enum_uint8 protocol)
{
    mac_vap->protocol          = protocol;
    if (protocol < WLAN_HT_MODE) {
        mac_vap_cap_init_legacy(mac_vap);
    } else {
        mac_vap_cap_init_htvht(mac_vap);
    }
    /* ����Э��ģʽ����mibֵ */
    if (mac_vap_config_vht_ht_mib_by_protocol(mac_vap) != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ݴ������vap��mibֵ
 �޸���ʷ      :
  1.��    ��   : 2014��5��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_change_mib_by_bandwidth(const mac_vap_stru *mac_vap,
    wlan_channel_bandwidth_enum_uint8 bandwidth)
{
    wlan_mib_ieee802dot11_stru *mib_info = HI_NULL;

    mib_info = mac_vap->mib_info;
    if (mib_info == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_change_mib_by_bandwidth::pst_mib_info null.}");
        return;
    }

    /* ����short giʹ��mib, Ĭ��ȫʹ�ܣ����ݴ�����Ϣ���� */
    mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented           = HI_TRUE;
    if (WLAN_BAND_WIDTH_20M == bandwidth) {
        mac_mib_set_forty_mhz_operation_implemented(mac_vap, HI_FALSE);
        mac_mib_set_shortgi_option_in_forty_implemented(mac_vap, HI_FALSE);
    }
}
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
WIFI_ROM_TEXT static hi_void mac_vap_stru_mesh_info(mac_vap_stru *mac_vap)
{
    mac_vap->cap_flag.hide_meshid = HI_TRUE;
    mac_vap->report_times_limit = MAC_MAX_REPORT_TIME;
    mac_vap->report_tx_cnt_limit = MAC_MAX_REPORT_TX_CNT;
    mac_vap->priority = 0x0;                             /* ��ʼ��Ϊ������ȼ� */
    mac_vap->mnid = MAC_MESH_INVALID_ID;                 /* ��ʼ��Ϊ��Чֵ */
    mac_vap->is_mbr = HI_FALSE;
    mac_vap->mesh_accept_sta = HI_FALSE;                  /* ��ʼMeshδ������������֧��STA���� */
    mac_vap->mesh_tbtt_adjusting = HI_FALSE;             /* ��ʼMeshδ�ڵ���tbtt */
}
#endif
WIFI_ROM_TEXT static hi_u32 mac_vap_init_mode(mac_vap_stru *mac_vap, const mac_cfg_add_vap_param_stru *param)
{
    switch (mac_vap->vap_mode) {
        case WLAN_VAP_MODE_CONFIG:
            return HI_SUCCESS;
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
        case WLAN_VAP_MODE_MESH:
            mac_vap_stru_mesh_info(mac_vap);
#endif
        /* fall-through */
        case WLAN_VAP_MODE_BSS_STA:
        case WLAN_VAP_MODE_BSS_AP:
            mac_vap->assoc_vap_id = 0xff;
            mac_vap->tx_power     = WLAN_MAX_TXPOWER;
            mac_vap->protection.protection_mode    = WLAN_PROT_NO;
            mac_vap->cap_flag.dsss_cck_mode_40mhz = HI_FALSE;
            mac_vap->cap_flag.uapsd      = HI_FALSE;
#ifdef _PRE_WLAN_FEATURE_UAPSD
            if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
                || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
            ) {
                mac_vap->cap_flag.uapsd      = param->uapsd_enable;
            }
#endif
            /* ��ʼ��dpd���� */
            mac_vap->cap_flag.dpd_enbale = HI_TRUE;
            mac_vap->cap_flag.keepalive  = HI_TRUE;
            mac_vap->channel.band         = WLAN_BAND_BUTT;
            mac_vap->channel.en_bandwidth    = WLAN_BAND_WIDTH_BUTT;
            mac_vap->protocol  = WLAN_PROTOCOL_BUTT;
            /* �����Զ��������� */
            mac_vap->protection.auto_protection = HI_SWITCH_ON;
            /* ����VAP״̬Ϊ��ʼ״̬INIT */
            mac_vap_state_change(mac_vap, MAC_VAP_STATE_INIT);
            /* ��mac vap�µ�uapsd��״̬,����״̬���в���������host device uapsd��Ϣ��ͬ�� */
#ifdef _PRE_WLAN_FEATURE_STA_PM
            /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
            memset_s(&(mac_vap->sta_uapsd_cfg), sizeof(mac_cfg_uapsd_sta_stru), 0, sizeof(mac_cfg_uapsd_sta_stru));
#endif
            break;
        default:
            oam_warning_log1(0, OAM_SF_ANY, "{mac_vap_init_mode::invalid vap mode[%d].}", mac_vap->vap_mode);
            return HI_ERR_CODE_INVALID_CONFIG;
    }
    return HI_SUCCESS;
}

WIFI_ROM_TEXT static hi_u32 mac_vap_init_mib(mac_vap_stru *mac_vap, hi_u8 vap_id)
{
    mac_device_stru            *mac_dev = mac_res_get_dev();
    wlan_mib_ieee802dot11_stru *mib_info = HI_NULL;

    /* ����MIB�ڴ�ռ䣬����VAPû��MIB */
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) || (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) ||
        (mac_vap->vap_mode == WLAN_VAP_MODE_WDS)
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
        || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
    ) {
        mac_vap->mib_info = oal_mem_alloc(OAL_MEM_POOL_ID_MIB, sizeof(wlan_mib_ieee802dot11_stru));
        if (mac_vap->mib_info == HI_NULL) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_init_mib::pst_mib_info alloc null, size[%d].}",
                           sizeof(wlan_mib_ieee802dot11_stru));
            return HI_ERR_CODE_ALLOC_MEM_FAIL;
        }
        mib_info = mac_vap->mib_info;
        /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
        memset_s(mib_info, sizeof(wlan_mib_ieee802dot11_stru), 0, sizeof(wlan_mib_ieee802dot11_stru));
        if (memcpy_s(mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN,
                     mac_dev->auc_hw_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            mac_vap_free_mib(mac_vap);
            return HI_FAIL;
        }
        /* VAP��mac��ַΪdevice��ַ�����һ��ֵ+vap id */
        mib_info->wlan_mib_sta_config.auc_dot11_station_id[WLAN_MAC_ADDR_LEN - 1] += vap_id;
        mac_init_mib(mac_vap);
        /* sta������������� */
        if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            mac_vap->protocol = WLAN_HT_MODE;
            mac_vap->channel.en_bandwidth = WLAN_BAND_WIDTH_20M;
            mac_vap->channel.band = WLAN_BAND_2G;
            if (HI_SUCCESS != mac_vap_init_by_protocol(mac_vap, WLAN_HT_MODE)) {
                mac_vap_free_mib(mac_vap);
                return HI_ERR_CODE_INVALID_CONFIG;
            }
            mac_vap_init_rates(mac_vap);
        }
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : mac vap init
 �޸���ʷ      :
  1.��    ��   : 2013��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_init(mac_vap_stru *mac_vap, hi_u8 vap_id, const mac_cfg_add_vap_param_stru *param)
{
    hi_u32 loop;
    hi_u32 ret;

    if (memset_s(mac_vap, sizeof(mac_vap_stru), 0, sizeof(mac_vap_stru)) != EOK) {
        return HI_FAIL;
    }

    mac_vap->vap_id      = vap_id;
    mac_vap->vap_mode    = param->vap_mode;
    mac_vap->cap_flag.disable_2ght40 = HI_TRUE;
    mac_vap->ch_switch_info.new_bandwidth = WLAN_BAND_WIDTH_BUTT;

    for (loop = 0; loop < MAC_VAP_USER_HASH_MAX_VALUE; loop++) {
        hi_list_init(&(mac_vap->ast_user_hash[loop]));
    }
    hi_list_init(&mac_vap->mac_user_list_head);

    ret = mac_vap_init_mode(mac_vap, param);
    if (ret != HI_SUCCESS) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_init_mode fail.}");
        return ret;
    }

    ret = mac_vap_init_mib(mac_vap, vap_id);
    if (ret != HI_SUCCESS) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_init_mib fail.}");
        return ret;
    }
    oal_spin_lock_init(&mac_vap->cache_user_lock);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : add wep key�߼������¼���DMAC
 �������  : mac_vap_stru *pst_mac_vap, hi_u16 us_len, hi_u8 *puc_param
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��5��12��
    ��    ��   : Hisilicon
    �޸�����   : wep��Կ�������鲥�û���
*****************************************************************************/
WIFI_ROM_TEXT static hi_u32 mac_vap_add_wep_key(const mac_vap_stru *mac_vap, hi_u16 us_len, hi_u8 *puc_param)
{
    mac_wep_key_param_stru    *wep_addkey_params = HI_NULL;
    mac_user_stru             *multi_user        = HI_NULL;
    wlan_priv_key_param_stru  *wep_key           = HI_NULL;
    hi_u32                     cipher_type        = WLAN_CIPHER_SUITE_WEP40;
    hi_u8                      wep_cipher_type    = WLAN_80211_CIPHER_SUITE_WEP_40;

    hi_unref_param(us_len);

    wep_addkey_params = (mac_wep_key_param_stru*)puc_param;
    /* wep ��Կ���Ϊ4�� */
    if (wep_addkey_params->key_index >= WLAN_MAX_WEP_KEY_COUNT) {
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }
    switch (wep_addkey_params->key_len) {
        case WLAN_WEP40_KEY_LEN:
            wep_cipher_type = WLAN_80211_CIPHER_SUITE_WEP_40;
            cipher_type     = WLAN_CIPHER_SUITE_WEP40;
            break;
        case WLAN_WEP104_KEY_LEN:
            wep_cipher_type = WLAN_80211_CIPHER_SUITE_WEP_104;
            cipher_type     = WLAN_CIPHER_SUITE_WEP104;
            break;
        default:
            return HI_ERR_CODE_SECURITY_KEY_LEN;
    }
    /* WEP��Կ��Ϣ��¼���鲥�û��� */
    multi_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
    if (multi_user == HI_NULL) {
        return HI_ERR_CODE_SECURITY_USER_INVAILD;
    }
    mac_mib_set_privacyinvoked(mac_vap, HI_TRUE);
    /* ��ʼ���鲥�û��İ�ȫ��Ϣ */
    if (wep_addkey_params->default_key) {
        multi_user->key_info.cipher_type     = wep_cipher_type;
        multi_user->key_info.default_index   = wep_addkey_params->key_index;
        multi_user->key_info.igtk_key_index  = 0xff; /* wepʱ����Ϊ��Ч */
        multi_user->key_info.gtk            = 0;
    }

    wep_key   = &multi_user->key_info.ast_key[wep_addkey_params->key_index];
    wep_key->cipher        = cipher_type;
    wep_key->key_len       = (hi_u32)wep_addkey_params->key_len;

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(wep_key->auc_key, WLAN_WPA_KEY_LEN, 0, WLAN_WPA_KEY_LEN);
    if (memcpy_s(wep_key->auc_key, WLAN_WPA_KEY_LEN, wep_addkey_params->auc_wep_key,
                 wep_addkey_params->key_len) != EOK) {
        return HI_FAIL;
    }
    multi_user->user_tx_info.security.cipher_key_type      =
        wep_addkey_params->key_index + HAL_KEY_TYPE_PTK;
    multi_user->user_tx_info.security.cipher_protocol_type = wep_cipher_type;
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_PMF
/*****************************************************************************
 ��������  : ��ȡpmf����������
 �޸���ʷ      :
  1.��    ��   : 2015��2��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_u32 mac_vap_init_pmf(mac_vap_stru *mac_vap,
                                             const mac_cfg80211_connect_security_stru *mac_security_param)
{
    if (!mac_mib_get_rsnaactivated(mac_vap)) {
        return HI_TRUE;
    }
    switch (mac_security_param->pmf_cap) {
        case MAC_PMF_DISABLED: {
            mac_mib_set_dot11_rsnamfpc(mac_vap, HI_FALSE);
            mac_mib_set_dot11_rsnamfpr(mac_vap, HI_FALSE);
        }
        break;
        case MAC_PMF_ENABLED:  {
            mac_mib_set_dot11_rsnamfpc(mac_vap, HI_TRUE);
            mac_mib_set_dot11_rsnamfpr(mac_vap, HI_FALSE);
        }
        break;
        case MAC_PME_REQUIRED: {
            mac_mib_set_dot11_rsnamfpc(mac_vap, HI_TRUE);
            mac_mib_set_dot11_rsnamfpr(mac_vap, HI_TRUE);
        }
        break;
        default: {
            return HI_FALSE;
        }
    }

    if (MAC_NL80211_MFP_REQUIRED == mac_security_param->mgmt_proteced) {
        mac_vap->user_pmf_cap = HI_TRUE;
    } else {
        mac_vap->user_pmf_cap = HI_FALSE;
    }
    return HI_SUCCESS;
}
#endif

WIFI_ROM_TEXT hi_void mac_vap_init_crypto_suites(mac_vap_stru *mac_vap, const mac_cfg80211_crypto_settings_stru *crypto)
{
    hi_u8 loop = 0;

    /* ��ʼ��������Կ�׼� */
    if (crypto->wpa_versions == WITP_WPA_VERSION_1) {
        mac_vap->cap_flag.wpa = HI_TRUE;
        for (loop = 0; loop < crypto->n_ciphers_pairwise; loop++) {
            mac_mib_set_rsnaconfig_wpa_pairwise_cipher_implemented(mac_vap, crypto->ciphers_pairwise[loop]);
        }
    } else if (crypto->wpa_versions == WITP_WPA_VERSION_2) {
        mac_vap->cap_flag.wpa2 = HI_TRUE;
        for (loop = 0; loop < crypto->n_ciphers_pairwise; loop++) {
            mac_mib_set_rsnaconfig_wpa2_pairwise_cipher_implemented(mac_vap, crypto->ciphers_pairwise[loop]);
        }
    }

    /* ��ʼ����֤�׼� */
    for (loop = 0; loop < crypto->n_akm_suites; loop++) {
        mac_mib_set_rsnaconfig_authentication_suite_implemented(mac_vap, crypto->akm_suites[loop], loop);
    }
}

/*****************************************************************************
 ��������  : �����ں��·��Ĺ�����������ֵ������ص�mib ֵ
 �������  : mac_vap_stru                        *pst_mac_vap
             mac_cfg80211_connect_param_stru     *pst_mac_connect_param
 �޸���ʷ      :
  1.��    ��   : 2014��1��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_init_privacy(mac_vap_stru *mac_vap, mac_cfg80211_connect_security_stru *mac_sec_param)
{
    mac_wep_key_param_stru              wep_key = {0};
    mac_cfg80211_crypto_settings_stru  *crypto = HI_NULL;
    hi_u32                          ret  = HI_SUCCESS;

    mac_mib_set_privacyinvoked(mac_vap, HI_FALSE);
#if defined (_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    /* ��ʼ�� RSNActive ΪFALSE */
    mac_mib_set_rsnaactivated(mac_vap, HI_FALSE);
#endif
    /* ��������׼���Ϣ */
    mac_mib_set_rsnaclear_wpa_pairwise_cipher_implemented(mac_vap);
    mac_mib_set_rsnaclear_wpa2_pairwise_cipher_implemented(mac_vap);
    mac_vap->cap_flag.wpa  = HI_FALSE;
    mac_vap->cap_flag.wpa2 = HI_FALSE;

    /* ������ */
    if (!mac_sec_param->privacy) {
        return HI_SUCCESS;
    }

    /* WEP���� */
    if (mac_sec_param->wep_key_len != 0) {
        wep_key.key_len   = mac_sec_param->wep_key_len;
        wep_key.key_index = mac_sec_param->wep_key_index;
        wep_key.default_key = HI_TRUE;
        if (memcpy_s(wep_key.auc_wep_key, WLAN_WEP104_KEY_LEN,
                     mac_sec_param->auc_wep_key, WLAN_WEP104_KEY_LEN) != EOK) {
            return HI_FAIL;
        }
        ret = mac_vap_add_wep_key(mac_vap, sizeof(mac_wep_key_param_stru), (hi_u8 *)&wep_key);
        if (ret != HI_SUCCESS) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_WPA, "{mac_vap_init_privacy::wep_key failed[%d].}", ret);
        }
        return ret;
    }

    /* WPA/WPA2���� */
    crypto = &(mac_sec_param->crypto);
    if ((crypto->n_ciphers_pairwise > WLAN_PAIRWISE_CIPHER_SUITES) ||
        (crypto->n_akm_suites > MAC_AUTHENTICATION_SUITE_NUM)) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_WPA, "{mac_vap_init_privacy::cipher[%d] akm[%d] unexpected.}",
                       crypto->n_ciphers_pairwise, crypto->n_akm_suites);
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }

    /* ��ʼ��RSNA mib Ϊ TRUR */
    mac_mib_set_privacyinvoked(mac_vap, HI_TRUE);
    mac_mib_set_rsnaactivated(mac_vap, HI_TRUE);

    /* ��ʼ���鲥��Կ�׼� */
    mac_mib_set_rsnacfggroupcipher(mac_vap, (hi_u8)(crypto->cipher_group));

#ifdef _PRE_WLAN_FEATURE_PMF
    ret = mac_vap_init_pmf(mac_vap, mac_sec_param);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{mac_11i_init_privacy::mac_11w_init_privacy failed[%d].}", ret);
        return ret;
    }
#endif
    /* ��ʼ��������Կ�׼�����֤�׼� */
    mac_vap_init_crypto_suites(mac_vap, crypto);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����mac��ַ��ȡmac_userָ��
*****************************************************************************/
WIFI_ROM_TEXT mac_user_stru *mac_vap_get_user_by_addr(mac_vap_stru *mac_vap, const hi_u8 *mac_addr)
{
    hi_u32              ret;
    hi_u8               user_idx   = 0xff;
    mac_user_stru          *mac_user = HI_NULL;

    /* ����mac addr�ҵ�sta���� */
    ret = mac_vap_find_user_by_macaddr(mac_vap, mac_addr, WLAN_MAC_ADDR_LEN, &user_idx);
    if (ret != HI_SUCCESS) {
        oam_info_log1(0, OAM_SF_ANY, "{mac_vap_get_user_by_addr::find_user_by_macaddr failed[%d].}", ret);
        if (mac_addr != HI_NULL) {
            oam_info_log3(0, OAM_SF_ANY, "{mac_vap_get_user_by_addr::mac[%x:XX:XX:XX:%x:%x] cant be found!}",
                mac_addr[0], mac_addr[4], mac_addr[5]); /* ά���¼[0]��[4]��[5] */
        }
        return HI_NULL;
    }
    /* ����sta�����ҵ�user�ڴ����� */
    mac_user = mac_user_get_user_stru(user_idx);
    if (mac_user == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{mac_vap_get_user_by_addr::user ptr null.}");
    }
    return mac_user;
}

WIFI_ROM_TEXT static hi_u32 mac_vap_config_group_cipher(const mac_vap_stru *mac_vap,
    const mac_beacon_param_stru *beacon_param, wlan_mib_dot11_rsna_config_entry_stru *mib_rsna_cfg)
{
    switch (beacon_param->group_crypto) {
        case WLAN_80211_CIPHER_SUITE_TKIP:
            mib_rsna_cfg->dot11_rsna_config_group_cipher_size = WLAN_TKIP_KEY_LEN * 8; /* ��8ת��bit�� */
            break;
        case WLAN_80211_CIPHER_SUITE_CCMP:
            mib_rsna_cfg->dot11_rsna_config_group_cipher_size = WLAN_CCMP_KEY_LEN * 8; /* ��8ת��bit�� */
            break;
        default:
            if (mac_vap != HI_NULL) {
                oam_error_log1(mac_vap->vap_id, OAM_SF_CFG,
                    "{mac_vap_config_group_cipher::UNEXPECTED group_crypto[%d].}", beacon_param->group_crypto);
            }

            return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }
    mib_rsna_cfg->dot11_rsna_config_group_cipher     = beacon_param->group_crypto;

    return HI_SUCCESS;
}

/* ���֮ǰ�ļ���������Ϣ
 */
WIFI_ROM_TEXT static hi_void mac_vap_clear_auth_suite(mac_vap_stru *mac_vap)
{
    mac_mib_set_rsnaclear_wpa_pairwise_cipher_implemented(mac_vap);
    mac_mib_set_rsnaclear_wpa2_pairwise_cipher_implemented(mac_vap);
    mac_mib_set_privacyinvoked(mac_vap, HI_FALSE);
    mac_mib_set_rsnaactivated(mac_vap, HI_FALSE);
    mac_vap->cap_flag.wpa  = HI_FALSE;
    mac_vap->cap_flag.wpa2 = HI_FALSE;
    mac_mib_clear_rsna_auth_suite(mac_vap);
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
WIFI_ROM_TEXT static hi_u32 mac_vap_config_mesh_group_cipher(const mac_vap_stru *mac_vap,
    const mac_beacon_param_stru *beacon_param, wlan_mib_dot11_rsna_config_entry_stru *mib_rsna_cfg)
{
    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_mesh_activated == HI_TRUE) {
        if (beacon_param->group_crypto != WLAN_80211_CIPHER_SUITE_CCMP) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_CFG,
                           "{mac_vap_config_mesh_group_cipher::[MESH]UNEXPECTED group_crypto[%d].}",
                           beacon_param->group_crypto);
            return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
        }
        mib_rsna_cfg->dot11_rsna_config_group_cipher = beacon_param->group_crypto;
        mib_rsna_cfg->dot11_rsna_config_group_cipher_size = WLAN_CCMP_KEY_LEN * 8; /* ��8 ת��bit�� */
    }

    return HI_SUCCESS;
}

WIFI_ROM_TEXT static hi_u32 mac_mesh_vap_config_beacon(const mac_vap_stru *mac_vap,
    mac_beacon_operation_type_uint8 operation_type, const mac_beacon_param_stru *beacon_param,
    wlan_mib_dot11_rsna_config_entry_stru *mib_rsna_cfg)
{
    hi_u32 ret;
    if (operation_type == MAC_SET_BEACON) {
        ret = mac_vap_config_mesh_group_cipher(mac_vap, beacon_param, mib_rsna_cfg);
        if (ret != HI_SUCCESS) {
            return ret;
        }
    } else {
        ret = mac_vap_config_group_cipher(mac_vap, beacon_param, mib_rsna_cfg);
        if (ret != HI_SUCCESS) {
            return ret;
        }
    }
    return ret;
}
#endif

WIFI_ROM_TEXT static hi_void mac_vap_authentication_suite_config(mac_vap_stru *mac_vap,
    wlan_mib_dot11_rsna_config_entry_stru *mib_rsna_cfg, const mac_beacon_param_stru *beacon_param)
{
    hi_u32 loop;

    /* ������֤�׼� */
    for (loop = 0; loop < MAC_AUTHENTICATION_SUITE_NUM; loop++) {
        if (beacon_param->auc_auth_type[loop] == 0xff) {
            continue;
        }
        mac_mib_set_rsna_auth_suite(mac_vap, beacon_param->auc_auth_type[loop]);
    }

    if (beacon_param->crypto_mode & WLAN_WPA_BIT) {
        mac_vap->cap_flag.wpa = HI_TRUE;
        /* ����WPA������Կ�׼� */
        for (loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
            if (beacon_param->auc_pairwise_crypto_wpa[loop] == 0xff) {
                continue;
            }
            mac_mib_set_rsnaconfig_wpa_pairwise_cipher_implemented(mac_vap,
                                                                   beacon_param->auc_pairwise_crypto_wpa[loop]);
        }
    }

    if (beacon_param->crypto_mode & WLAN_WPA2_BIT) {
        mac_vap->cap_flag.wpa2 = HI_TRUE;
        /* ����WPA2������Կ�׼� */
        for (loop = 0; loop < MAC_PAIRWISE_CIPHER_SUITES_NUM; loop++) {
            /* DTS2015031010201 WIFI_SW: B130�汾��CI ��֤����SVN�ڵ�3399������汾��2.4G��ϼ����Ĵ�����ʧ��  */
            if (beacon_param->auc_pairwise_crypto_wpa2[loop] == 0xff) {
                continue;
            }
            mac_mib_set_rsnaconfig_wpa2_pairwise_cipher_implemented(mac_vap,
                                                                    beacon_param->auc_pairwise_crypto_wpa2[loop]);
        }

        /* RSN ���� */
        mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpr  =
            (beacon_param->us_rsn_capability & BIT6) ? HI_TRUE : HI_FALSE;
        mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpc  =
            (beacon_param->us_rsn_capability & BIT7) ? HI_TRUE : HI_FALSE;
        mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_preauthentication_activated =
            beacon_param->us_rsn_capability & BIT0;
        mib_rsna_cfg->dot11_rsna_config_number_of_ptksa_replay_counters_implemented =
            (beacon_param->us_rsn_capability & 0x0C) >> 2; /* ����2 bit */
        mib_rsna_cfg->dot11_rsna_config_number_of_gtksa_replay_counters_implemented =
            (beacon_param->us_rsn_capability & 0x30) >> 4; /* ����4 bit */
    }
}

/*****************************************************************************
 ��������  : ��λ11X�˿�
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_u32 mac_vap_config_beacon(mac_vap_stru *mac_vap,
    mac_beacon_operation_type_uint8 operation_type, const mac_beacon_param_stru *beacon_param)
{
    mac_user_stru                        *multi_user = HI_NULL;
    wlan_mib_dot11_rsna_config_entry_stru   *mib_rsna_cfg = HI_NULL;
    hi_u32                               ret;

    if (operation_type >= MAC_BEACON_OPERATION_BUTT) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_CFG, "{mac_vap_add_beacon::en_operation_type:%d error [idx:%d]}",
            operation_type, mac_vap->multi_user_idx);
    }

    /* ���֮ǰ�ļ���������Ϣ */
    mac_vap_clear_auth_suite(mac_vap);

    mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpr = HI_FALSE;
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpc = HI_FALSE;

    if (operation_type == MAC_ADD_BEACON) {
        /* ����鲥��Կ��Ϣ */
        multi_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
        if (multi_user == HI_NULL) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_CFG, "{mac_vap_add_beacon::pst_multi_user null [idx:%d] .}",
                           mac_vap->multi_user_idx);
            return HI_ERR_CODE_PTR_NULL;
        }
    }

    if (!beacon_param->privacy) {
        return HI_SUCCESS;
    }
    /* ʹ�ܼ��� */
    mac_mib_set_privacyinvoked(mac_vap, HI_TRUE);
    mib_rsna_cfg = &mac_vap->mib_info->wlan_mib_rsna_cfg;
    if ((beacon_param->crypto_mode & (WLAN_WPA_BIT | WLAN_WPA2_BIT)) == 0) {
        return HI_SUCCESS;
    }
    /* WEP����ʱ����addbeacon����֮ǰ���Ѿ�ͨ��add key��������Կ�� */
    if (operation_type == MAC_ADD_BEACON) {
        mac_user_init_key(multi_user);
        /* ������ǰ���if����Ѿ��ж���multi_user�ǿգ��󱨸澯��lin_t e613�澯���� */
        multi_user->user_tx_info.security.cipher_key_type = WLAN_KEY_TYPE_TX_GTK;
    }
    mac_mib_set_rsnaactivated(mac_vap, HI_TRUE);

    /* �����鲥�׼� */
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    ret = mac_mesh_vap_config_beacon(mac_vap, operation_type, beacon_param, mib_rsna_cfg);
    if (ret != HI_SUCCESS) {
        return ret;
    }
#else
    ret = mac_vap_config_group_cipher(mac_vap, beacon_param, mib_rsna_cfg);
    if (ret != HI_SUCCESS) {
        return ret;
    }
#endif
    /* ������֤�׼� */
    mac_vap_authentication_suite_config(mac_vap, mib_rsna_cfg, beacon_param);
    return HI_SUCCESS;
}
/* mac_vap_add_beacon->mac_vap_config_beacon->mac_vap_clear_auth_suite�������޸ģ�lin_t e818�澯���� */
WIFI_ROM_TEXT hi_u32 mac_vap_add_beacon(mac_vap_stru *mac_vap, const mac_beacon_param_stru *beacon_param)
{
    return mac_vap_config_beacon(mac_vap, MAC_ADD_BEACON, beacon_param);
}

/*****************************************************************************
 ��������  : ����en_key_type��������Ӧ�ĺ���������vap��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_add_key(const mac_vap_stru *mac_vap, mac_user_stru *mac_user, hi_u8 key_id,
                                     const mac_key_params_stru *key)
{
    hi_u32 ret;

    if (((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_WEP_40) ||
        ((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_WEP_104)) {
        /* ����mib */
        mac_mib_set_privacyinvoked(mac_vap, HI_TRUE);
        mac_mib_set_rsnaactivated(mac_vap, HI_FALSE);
        mac_mib_set_rsnacfggroupcipher(mac_vap, (hi_u8)key->cipher);
        ret = mac_user_add_wep_key(mac_user, key_id, key);
    } else if (((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_TKIP) ||
        ((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_CCMP)) {
        ret = mac_user_add_rsn_key(mac_user, key_id, key);
    } else if ((hi_u8)key->cipher == WLAN_80211_CIPHER_SUITE_BIP) {
        ret = mac_user_add_bip_key(mac_user, key_id, key);
    } else {
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��ȡmac��������default_key_id
 �޸���ʷ      :
  1.��    ��   : 2015��5��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_vap_get_default_key_id(const mac_vap_stru *mac_vap)
{
    mac_user_stru            *multi_user = HI_NULL;
    hi_u8                     default_key_id;

    /* �������������鲥�û���Կ��Ϣ�в�����Կ */
    multi_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
    if (multi_user == HI_NULL) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
            "{mac_vap_get_default_key_id::multi_user[%d] NULL}", mac_vap->multi_user_idx);
        return 0;
    }

    if ((multi_user->key_info.cipher_type != WLAN_80211_CIPHER_SUITE_WEP_40) &&
        (multi_user->key_info.cipher_type != WLAN_80211_CIPHER_SUITE_WEP_104)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
            "{mac_vap_get_default_key_id::unexpectd cipher_type[%d]}", multi_user->key_info.cipher_type);
        return 0;
    }
    default_key_id = multi_user->key_info.default_index;
    if (default_key_id >= WLAN_NUM_TK) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
            "{mac_vap_get_default_key_id::unexpectd keyid[%d]}", default_key_id);
        return 0;
    }
    return default_key_id;
}

/*****************************************************************************
 ��������  : ����hmac��������default_key
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_set_default_key(const mac_vap_stru *mac_vap, hi_u8  key_index)
{
    wlan_priv_key_param_stru     *wep_key = HI_NULL;
    mac_user_stru                *multi_user = HI_NULL;

    /* 1.1 �����wep ���ܣ���ֱ�ӷ��� */
    if (!mac_is_wep_enabled(mac_vap)) {
        return HI_SUCCESS;
    }

    /* 2.1 �������������鲥�û���Կ��Ϣ�в�����Կ */
    multi_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
    if (multi_user == HI_NULL) {
        return HI_ERR_CODE_SECURITY_USER_INVAILD;
    }
    wep_key   = &multi_user->key_info.ast_key[key_index];
    if (wep_key->cipher != WLAN_CIPHER_SUITE_WEP40 &&
        wep_key->cipher != WLAN_CIPHER_SUITE_WEP104) {
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }

    /* 3.1 ������Կ���ͼ�default id */
    multi_user->key_info.cipher_type     = (hi_u8)(wep_key->cipher);
    multi_user->key_info.default_index   = key_index;
    /* 4.1 ����mib���� */
    mac_mib_set_wep_default_keyid(mac_vap, key_index);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ù���֡��Կ
 �޸���ʷ      :
  1.��    ��   : 2014��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_vap_set_default_mgmt_key(const mac_vap_stru *mac_vap, hi_u8 key_index)
{
    mac_user_stru                *multi_user = HI_NULL;

    /* ����֡������Ϣ�������鲥�û��� */
    multi_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
    if (multi_user == HI_NULL) {
        return HI_ERR_CODE_SECURITY_USER_INVAILD;
    }
    /* keyidУ�� */
    if (key_index < WLAN_NUM_TK || key_index > WLAN_MAX_IGTK_KEY_INDEX) {
        return HI_ERR_CODE_SECURITY_KEY_ID;
    }
    if ((hi_u8)multi_user->key_info.ast_key[key_index].cipher != WLAN_80211_CIPHER_SUITE_BIP) {
        return HI_ERR_CODE_SECURITY_CHIPER_TYPE;
    }
    /* ����IGTK��keyid */
    multi_user->key_info.igtk_key_index   = key_index;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼ��STA ��������£����ݹ��˵Ĳ�����
 �޸���ʷ      :
  1.��    ��   : 2013��9��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_init_user_security_port(const mac_vap_stru  *mac_vap,
                                                      mac_user_stru *mac_user)
{
    mac_user->port_valid = HI_TRUE;
    if (!mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated) {
        return;
    }
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_MESH) && (mac_user->is_mesh_user == HI_TRUE)) {
        if (mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_security_activated != HI_TRUE) {
            oam_warning_log0(0, OAM_SF_WPA, "{mac_vap_init_user_security_port::dot11MeshSecurityActivated is FALSE!.}");
            return;
        }
        if (mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol !=
            MAC_MESH_AUTH_PROTO_SAE) {
            oam_warning_log0(0, OAM_SF_WPA,
                "{mac_vap_init_user_security_port::dot11MeshActiveAuthenticationProtocol isn't SAE!.}");
            return;
        }
        mac_user->port_valid = HI_FALSE;
        mac_user_init_key(mac_user);
        return;
    }
#endif

    /* �Ƿ����WPA ��WPA2 ���ܷ�ʽ */
    if (!(mac_vap->cap_flag.wpa) && !(mac_vap->cap_flag.wpa2)) {
        return;
    }
    /* STA��Ҫ����Ƿ����802.1X ��֤��ʽ */
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA &&
         mac_check_auth_policy(mac_vap->mib_info, WLAN_AUTH_SUITE_1X)) ||
        ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
        || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
    )) {
        mac_user->port_valid = HI_FALSE;
    }
    /* DTS2015081201896:����û��Ѿ�����������Ҫ��ʼ���û���������Ϊ������ */
    mac_user_init_key(mac_user);
}

/*****************************************************************************
 ��������  : ��λ11X�˿�
 �޸���ʷ      :
  1.��    ��   : 2015��6��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* mac_vap_set_beacon->mac_vap_config_beacon->mac_vap_clear_auth_suite�������޸ģ�lin_t e818�澯���� */
WIFI_ROM_TEXT hi_u32 mac_vap_set_beacon(mac_vap_stru *mac_vap, const mac_beacon_param_stru *beacon_param)
{
    return mac_vap_config_beacon(mac_vap, MAC_SET_BEACON, beacon_param);
}

/*****************************************************************************
 ��������  : ��ȡvap�Ĵ���������Ϣ��ȡvap��������
 �޸���ʷ      :
  1.��    ��   : 2014��4��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_vap_get_bandwidth_cap(mac_vap_stru *mac_vap, wlan_bw_cap_enum_uint8 *pen_cap)
{
    mac_channel_stru            *channel = HI_NULL;
    wlan_bw_cap_enum_uint8       band_cap = WLAN_BW_CAP_20M;

    channel = &(mac_vap->channel);
    if (WLAN_BAND_WIDTH_40PLUS == channel->en_bandwidth || WLAN_BAND_WIDTH_40MINUS == channel->en_bandwidth) {
        band_cap = WLAN_BW_CAP_40M;
    } else if (channel->en_bandwidth >= WLAN_BAND_WIDTH_80PLUSPLUS) {
        band_cap = WLAN_BW_CAP_80M;
    }
    *pen_cap = band_cap;
}

/*****************************************************************************
 ��������  : �ж��Ƿ�����WEP����
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_is_wep_allowed(const mac_vap_stru *mac_vap)
{
    hi_u8 grp_policy ;

    if (mac_mib_get_rsnaactivated(mac_vap)) {
        grp_policy = mac_mib_get_rsnacfggroupcipher(mac_vap);
        if ((grp_policy == WLAN_80211_CIPHER_SUITE_WEP_40) || (grp_policy == WLAN_80211_CIPHER_SUITE_WEP_104)) {
            return HI_TRUE;
        }
        return HI_FALSE;
    } else {
        return mac_is_wep_enabled(mac_vap);
    }
}

/*****************************************************************************
 ��������  : ��ȡ����ģʽ����
 �������  : mac_vap_stru        : mac VAP�ṹ�壬 ����sta��Ϣ
             pst_mac_sta         : mac user�ṹ�壬 ����ap��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT wlan_prot_mode_enum_uint8 mac_vap_get_user_protection_mode(const mac_vap_stru *mac_vap,
    const mac_user_stru *mac_user)
{
    wlan_prot_mode_enum_uint8           protection_mode = WLAN_PROT_NO;

    if ((mac_vap == HI_NULL) || (mac_user == HI_NULL)) {
        return protection_mode;
    }

    /* ��2GƵ���£����AP���͵�beacon֡ERP ie��Use Protection bit��Ϊ1���򽫱�����������ΪERP���� */
    if ((WLAN_BAND_2G == mac_vap->channel.band) &&
        (mac_user->cap_info.erp_use_protect == HI_TRUE)) {
        protection_mode = WLAN_PROT_ERP;
    } else if ((mac_user->ht_hdl.ht_protection == WLAN_MIB_HT_NON_HT_MIXED)
        || (mac_user->ht_hdl.ht_protection == WLAN_MIB_HT_NONMEMBER_PROTECTION)) {
        /* ���AP���͵�beacon֡ht operation ie��ht protection�ֶ�Ϊmixed��non-member���򽫱�����������ΪHT���� */
        protection_mode = WLAN_PROT_HT;
    } else if (mac_user->ht_hdl.nongf_sta_present == HI_TRUE) {
        /* ���AP���͵�beacon֡ht operation ie��non-gf sta present�ֶ�Ϊ1���򽫱�����������ΪGF���� */
        protection_mode = WLAN_PROT_GF;
    } else {
        /* ʣ�µ������������ */
        protection_mode = WLAN_PROT_NO;
    }

    return protection_mode;
}

/*****************************************************************************
 ��������  : ��ѯ�Ƿ����ʹ��lsigtxop����
 �������  : pst_mac_vap : mac vap�ṹ��ָ��
 �������  : ��
 �� �� ֵ  : hi_bool : 0: ������ʹ��lsig txop����
                             1: ����ʹ��lsig txop����
 �޸���ʷ      :
  1.��    ��   : 2014��4��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_bool mac_protection_lsigtxop_check(const mac_vap_stru *mac_vap)
{
    mac_user_stru  *mac_user = HI_NULL;

    /* �������11nվ�㣬��֧��lsigtxop���� */
    if ((mac_vap->protocol != WLAN_HT_MODE) &&
        (mac_vap->protocol != WLAN_HT_ONLY_MODE) &&
        (mac_vap->protocol != WLAN_HT_11G_MODE)) {
        return HI_FALSE;
    }

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        mac_user = (mac_user_stru *)mac_user_get_user_stru(mac_vap->assoc_vap_id); /* user�������AP����Ϣ */
        if ((mac_user == HI_NULL) || (mac_user->ht_hdl.lsig_txop_protection_full_support == HI_FALSE)) {
            return HI_FALSE;
        } else {
            return HI_TRUE;
        }
    }
    /* BSS ������վ�㶼֧��Lsig txop protection, ��ʹ��Lsig txop protection���ƣ�����С, AP��STA���ò�ͬ���ж� */
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) &&
        mac_mib_get_lsig_txop_full_protection_activated(mac_vap)) {
        return HI_TRUE;
    } else {
        return HI_FALSE;
    }
}

/*****************************************************************************
 ��������  : ����rts ���Ͳ���,host,device����,
 �������  : pst_hmac_vap : hmac vap�ṹ��ָ��
             en_flag      : 0:�ر�lsig txop��������   / 1: ��lsig txop��������
 �޸���ʷ      :
  1.��    ��   : 2014��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_protection_set_rts_tx_param(mac_vap_stru *mac_vap, hi_u8 flag,
    wlan_prot_mode_enum_uint8 prot_mode, mac_cfg_rts_tx_param_stru *rts_tx_param)
{
    if ((mac_vap == HI_NULL) || (rts_tx_param == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ASSOC,
            "{mac_protection_set_rts_tx_param_etc::param null,pst_mac_vap[%p] pst_rts_tx_param[%p]}",
            (uintptr_t)mac_vap, (uintptr_t)rts_tx_param);
        return;
    }
    /* ����խ����RTS���ʲ��� */
    if ((mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_5M) ||
        (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_10M)) {
        rts_tx_param->band = WLAN_BAND_2G;
        rts_tx_param->auc_protocol_mode[0]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE;
        rts_tx_param->auc_rate[0]             = WLAN_LEGACY_OFDM_24M_BPS;
        rts_tx_param->auc_protocol_mode[1]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE;
        rts_tx_param->auc_rate[1]             = WLAN_LEGACY_OFDM_6M_BPS;
        rts_tx_param->auc_protocol_mode[2]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[2] */
        rts_tx_param->auc_rate[2]             = WLAN_LEGACY_OFDM_6M_BPS;            /* ����auc_rate[2] */
        rts_tx_param->auc_protocol_mode[3]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[3] */
        rts_tx_param->auc_rate[3]             = WLAN_LEGACY_OFDM_6M_BPS;            /* ����auc_rate[3] */
        return;
    }

    /* ֻ������erp����ʱ��RTS[0~2]���ʲ���Ϊ5.5Mpbs(11b), ����ʱ��Ϊ24Mpbs(leagcy ofdm) */
    if ((prot_mode == WLAN_PROT_ERP) && (flag == HI_SWITCH_ON)) {
        rts_tx_param->band = WLAN_BAND_2G;

        /* RTS[0~2]��Ϊ5.5Mbps, RTS[3]��Ϊ1Mbps */
        rts_tx_param->auc_protocol_mode[0]    = WLAN_11B_PHY_PROTOCOL_MODE;
        rts_tx_param->auc_rate[0]             = WLAN_LONG_11B_5_HALF_M_BPS;
        rts_tx_param->auc_protocol_mode[1]    = WLAN_11B_PHY_PROTOCOL_MODE;
        rts_tx_param->auc_rate[1]             = WLAN_LONG_11B_5_HALF_M_BPS;
        rts_tx_param->auc_protocol_mode[2]    = WLAN_11B_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[2] */
        rts_tx_param->auc_rate[2]             = WLAN_LONG_11B_5_HALF_M_BPS; /* ����auc_rate[2] */
        rts_tx_param->auc_protocol_mode[3]    = WLAN_11B_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[3] */
        rts_tx_param->auc_rate[3]             = WLAN_LONG_11B_1_M_BPS;      /* ����auc_rate[3] */
    } else {
        rts_tx_param->band = mac_vap->channel.band;

        /* RTS[0~2]��Ϊ24Mbps */
        rts_tx_param->auc_protocol_mode[0]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE;
        rts_tx_param->auc_rate[0]             = WLAN_LEGACY_OFDM_24M_BPS;
        rts_tx_param->auc_protocol_mode[1]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE;
        rts_tx_param->auc_rate[1]             = WLAN_LEGACY_OFDM_24M_BPS;
        rts_tx_param->auc_protocol_mode[2]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[2] */
        rts_tx_param->auc_rate[2]             = WLAN_LEGACY_OFDM_24M_BPS;           /* ����auc_rate[2] */

        /* 2G��RTS[3]��Ϊ1Mbps */
        if (WLAN_BAND_2G == rts_tx_param->band) {
            rts_tx_param->auc_protocol_mode[3]    = WLAN_11B_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[3] */
            rts_tx_param->auc_rate[3]             = WLAN_LONG_11B_1_M_BPS;      /* ����auc_rate[3] */
        } else {
            /* 5G��RTS[3]��Ϊ24Mbps */
            rts_tx_param->auc_protocol_mode[3]    = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE; /* ����auc_protocol_mode[3] */
            rts_tx_param->auc_rate[3]             = WLAN_LEGACY_OFDM_24M_BPS;           /* ����auc_rate[3] */
        }
    }
}


/* ����ROM�ν���λ�� ����ROM���������SECTION�� */
#undef __WIFI_ROM_SECTION__

/*****************************************************************************
 ��������  : ����user MAC��ַ����user����
 �������  : vap����ָ�룬�Լ�user MAC��ַ
 �������  : user����ָ��
 �޸���ʷ      :
  1.��    ��   : 2012��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_device_find_user_by_macaddr(const mac_vap_stru *mac_vap, const hi_u8 *sta_mac_addr, hi_u8 addr_len,
    hi_u8 *puc_user_idx)
{
    mac_device_stru        *mac_dev  = HI_NULL;
    mac_vap_stru           *mac_vap_temp = HI_NULL;
    hi_u8                   vap_id;
    hi_u8                   vap_idx;
    hi_u32                  ret;

    /* ��ȡdevice */
    mac_dev = mac_res_get_dev();
    /* ��device�µ�����vap���б��� */
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        vap_id = mac_dev->auc_vap_id[vap_idx];
        /* ����vap����Ҫ���� */
        if (vap_id == WLAN_CFG_VAP_ID) {
            continue;
        }
        /* ��vap����Ҫ���� */
        if (vap_id == mac_vap->vap_id) {
            continue;
        }
        mac_vap_temp = mac_vap_get_vap_stru(vap_id);
        if (mac_vap_temp == HI_NULL) {
            continue;
        }
        /* ֻ����APģʽ */
        if ((mac_vap_temp->vap_mode != WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
            && (mac_vap_temp->vap_mode != WLAN_VAP_MODE_MESH)
#endif
        ) {
            continue;
        }
        ret = mac_vap_find_user_by_macaddr(mac_vap_temp, sta_mac_addr, addr_len, puc_user_idx);
        if (ret == HI_SUCCESS) {
            return HI_SUCCESS;
        }
    }

    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ����mib��Ϣ�е�ǰ�ŵ�
 �������  : Ƶ��:wlan_channel_band_enum_uint8 en_band,
             �ŵ�:hi_u8 uc_channel
 �޸���ʷ      :
  1.��    ��   : 2013��7��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_vap_set_current_channel(mac_vap_stru *mac_vap, wlan_channel_band_enum_uint8 band, hi_u8 channel)
{
    hi_u8  channel_idx = 0;
    hi_u32 ret;

    /* ����ŵ��� */
    ret = mac_is_channel_num_valid(band, channel);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    /* �����ŵ����ҵ������� */
    ret = mac_get_channel_idx_from_num(band, channel, &channel_idx);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    mac_vap->channel.chan_number = channel;
    mac_vap->channel.band        = band;
    mac_vap->channel.idx         = channel_idx;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡĳ����������
 �޸���ʷ      :
  1.��    ��   : 2013��7��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_vap_get_curr_baserate(mac_vap_stru *mac_vap, hi_u8 br_idx)
{
    hi_u8          loop;
    hi_u8          found_br_num = 0;
    hi_u8          rate_num;
    mac_rateset_stru  *rate = HI_NULL;

    rate = &(mac_vap->curr_sup_rates.rate);
    rate_num = rate->rs_nrates;
    /* ����base rate ����¼���ҵ��ĸ����������ԱȽϲ����� */
    for (loop = 0; loop < rate_num; loop++) {
        if (((rate->ast_rs_rates[loop].mac_rate) & 0x80) != 0) {
            if (br_idx == found_br_num) {
                return rate->ast_rs_rates[loop].mac_rate;
            }
            found_br_num++;
        }
    }
    /* δ�ҵ������ش��� */
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ���������Ϣ����PHY��ص���Ϣ
 �������  : ��check_bss_capability_phy
 �޸���ʷ      :
  1.��    ��   : 2013��7��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
 �޸���ʷ      :
  2.��    ��   : 2013��12��6��
    ��    ��   : Hisilicon
    �޸�����   : �޸ĺ�������ת��ΪAP��STA��������
*****************************************************************************/
hi_void mac_vap_check_bss_cap_info_phy_ap(hi_u16 us_cap_info, const mac_vap_stru *mac_vap)
{
    mac_cap_info_stru  *cap_info = (mac_cap_info_stru *)(&us_cap_info);

    if (mac_vap->channel.band != WLAN_BAND_2G) {
        return;
    }
    /* PBCC */
    if ((mac_vap->mib_info->phy_hrdsss.dot11_pbcc_option_implemented == HI_FALSE) &&
        (cap_info->pbcc == 1)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_check_bss_cap_info_phy_ap::PBCC is different.}");
    }
    /* Channel Agility */
    if ((mac_vap->mib_info->phy_hrdsss.dot11_channel_agility_present == HI_FALSE) &&
        (cap_info->channel_agility == 1)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY,
                       "{mac_vap_check_bss_cap_info_phy_ap::Channel Agility is different.}");
    }
    /* DSSS-OFDM Capabilities 31h��֧�� �Է�֧���򱨴� */
    if (cap_info->dsss_ofdm == 1) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY,
                       "{mac_vap_check_bss_cap_info_phy_ap::DSSS-OFDM Capabilities is different.}");
    }
}

/*****************************************************************************
 ��������  : ���÷�����������user_idx
 �������  : pst_mac_vap :mac vap�ṹָ��
             pst_cb_ctrl:����֡�Ŀ����ֶ�
             puc_data:������Ŀ��MAC��ַ
 �޸���ʷ      :
  1.��    ��   : 2017��8��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_vap_set_cb_tx_user_idx(mac_vap_stru *mac_vap, hi_void *tx_ctl, const hi_u8 *mac_addr)
{
    hmac_tx_ctl_stru *tx_ctl_temp = (hmac_tx_ctl_stru *)tx_ctl;
    hi_u8 user_idx = MAC_INVALID_USER_ID;
    hi_u32 ret;

    ret = mac_vap_find_user_by_macaddr(mac_vap, mac_addr, WLAN_MAC_ADDR_LEN, &user_idx);
    if (ret != HI_SUCCESS) {
        oam_warning_log4(mac_vap->vap_id, OAM_SF_ANY,
            "{mac_vap_set_cb_tx_user_idx:: cannot find user_idx from xx:xx:xx:%x:%x:%x, set TX_USER_IDX %d.}",
            mac_addr[3], mac_addr[4], mac_addr[5], MAC_INVALID_USER_ID); /* ά���¼[3]��[4]��[5] */
        tx_ctl_temp->us_tx_user_idx = MAC_INVALID_USER_ID;
        return;
    }

    tx_ctl_temp->us_tx_user_idx = user_idx;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
