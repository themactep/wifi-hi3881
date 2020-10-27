/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Configure the implementation of the hmac interface to implement the source file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hcc_hmac_if.h"
#include "frw_timer.h"
#include "hmac_config.h"
#include "hmac_user.h"
#include "hmac_vap.h"
#include "hmac_mgmt_classifier.h"
#include "mac_ie.h"
#include "mac_pm_driver.h"
#include "hmac_rx_filter.h"
#include "hmac_device.h"
#include "plat_pm_wlan.h"
#include "hmac_fsm.h"
#include "hmac_mgmt_bss_comm.h"
#include "hmac_mgmt_ap.h"
#include "hmac_mgmt_sta.h"
#include "hmac_tx_data.h"
#include "hmac_scan.h"
#include "hmac_sme_sta.h"
#include "hmac_tx_amsdu.h"
#include "hmac_blockack.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  2 �ڲ���������
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_BTCOEX
hi_u32 hmac_btcoex_delba_foreach_user(mac_vap_stru *mac_vap);
#endif

/*****************************************************************************
  3 ȫ�ֱ�������
*****************************************************************************/
hi_bool g_wlan_pm_on = HI_FALSE;
frw_timeout_stru g_pm_apdown_timer = { 0 };
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
hmac_reg_info_receive_event g_hmac_reg_info_receive_event = { 0 };
#endif

typedef struct {
    wlan_protocol_enum_uint8 protocol_mode;  /* widö�� */
} hmac_protocol_stru;

#define PM_APDOWN_ENTERY_TIME 200000

#ifdef _PRE_WLAN_FEATURE_INTRF_MODE
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
static hi_bool g_hist_ampdu_tx_on = HI_TRUE; /* ����ۺϿ��ر�־ */
#endif
#endif
/*****************************************************************************
  3 ��������
*****************************************************************************/
/*****************************************************************************
 ��������  : ɾ��BA�Ự����������(�൱�ڽ��յ�DELBA֡)
*****************************************************************************/
hi_u32 hmac_config_delba_req(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_delba_req_param_stru *delba_req = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_action_mgmt_args_stru action_args;   /* ������дACTION֡�Ĳ��� */
    hmac_tid_stru *hmac_tid = HI_NULL;
    hi_u32 ret;

    hi_unref_param(us_len);

    delba_req = (mac_cfg_delba_req_param_stru *)puc_param;
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    /* ��ȡ�û���Ӧ������ */
    hmac_user = mac_vap_get_hmac_user_by_addr(mac_vap, delba_req->auc_mac_addr, WLAN_MAC_ADDR_LEN);
    if (hmac_vap == HI_NULL || hmac_user == HI_NULL) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_delba_req::hmac_vap/hmac_user null! hmac_vap=%p, hmac_user=%p}",
            (uintptr_t)hmac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_tid = &(hmac_user->ast_tid_info[delba_req->tidno]);

    /* �鿴�Ự�Ƿ���� */
    if (delba_req->direction == MAC_RECIPIENT_DELBA) {
        if (hmac_tid->ba_rx_info == HI_NULL) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_delba_req::the rx hdl is not exist.}");
            return HI_SUCCESS;
        }
    } else {
        if (hmac_tid->ba_tx_info == HI_NULL) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_delba_req::the tx hdl is not exist.}");
            return HI_SUCCESS;
        }
    }

    /*
       ����BA�Ựʱ��st_action_args(DELBA_REQ)�ṹ������Ա��������
       (1)uc_category:action�����
       (2)uc_action:BA action�µ����
       (3)ul_arg1:BA�Ự��Ӧ��TID
       (4)ul_arg2:ɾ��ba�Ự�ķ����
       (5)ul_arg3:ɾ��ba�Ự��ԭ��
       (6)ul_arg5:ba�Ự��Ӧ���û�
     */
    action_args.category = MAC_ACTION_CATEGORY_BA;
    action_args.action = MAC_BA_ACTION_DELBA;
    action_args.arg1 = delba_req->tidno;   /* ������֡��Ӧ��TID�� */
    action_args.arg2 = delba_req->direction;       /* ADDBA_REQ�У�buffer_size��Ĭ�ϴ�С */
    action_args.arg3 = MAC_UNSPEC_REASON; /* BA�Ự��ȷ�ϲ��� */
    action_args.puc_arg5 = delba_req->auc_mac_addr;      /* ba�Ự��Ӧ��user */

    /* ����BA�Ự */
    ret = hmac_mgmt_tx_action(hmac_vap, hmac_user, &action_args);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "hmac_mgmt_tx_action return NON SUCCESS. ");
    }

    return HI_SUCCESS;
}

#if defined(_PRE_WLAN_FEATURE_SIGMA) || defined(_PRE_DEBUG_MODE)
/*****************************************************************************
 ��������  : ����BA�Ự����������
*****************************************************************************/
hi_u32 hmac_config_addba_req(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_addba_req_param_stru *addba_req = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_action_mgmt_args_stru action_args;   /* ������дACTION֡�Ĳ��� */
    hi_u8  ampdu_support;
    hi_u32 ret;

    hi_unref_param(us_len);

    addba_req = (mac_cfg_addba_req_param_stru *)puc_param;
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    /* ��ȡ�û���Ӧ������ */
    hmac_user = mac_vap_get_hmac_user_by_addr(mac_vap, addba_req->auc_mac_addr, WLAN_MAC_ADDR_LEN);
    if (hmac_vap == HI_NULL || hmac_user == HI_NULL) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_addba_req::hmac_vap/hmac_user null! hmac_vap=%p, hmac_user=%p}",
            (uintptr_t)hmac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����BA�Ự���Ƿ���Ҫ�ж�VAP��AMPDU��֧���������Ϊ��Ҫʵ�ֽ���BA�Ựʱ��һ����AMPDU */
    ampdu_support = hmac_user_xht_support(hmac_user);
    /* �ֶ�����ba�Ự������������������ */
    if (ampdu_support) {
        /*
           ����BA�Ựʱ��st_action_args(ADDBA_REQ)�ṹ������Ա��������
           (1)uc_category:action�����
           (2)uc_action:BA action�µ����
           (3)ul_arg1:BA�Ự��Ӧ��TID
           (4)ul_arg2:BUFFER SIZE��С
           (5)ul_arg3:BA�Ự��ȷ�ϲ���
           (6)ul_arg4:TIMEOUTʱ��
         */
        action_args.category = MAC_ACTION_CATEGORY_BA;
        action_args.action = MAC_BA_ACTION_ADDBA_REQ;
        action_args.arg1 = addba_req->tidno;       /* ������֡��Ӧ��TID�� */
        action_args.arg2 = addba_req->us_buff_size;   /* ADDBA_REQ�У�buffer_size��Ĭ�ϴ�С */
        action_args.arg3 = addba_req->ba_policy;   /* BA�Ự��ȷ�ϲ��� */
        action_args.arg4 = addba_req->us_timeout;     /* BA�Ự�ĳ�ʱʱ������Ϊ0 */

        /* ����BA�Ự */
        ret = hmac_mgmt_tx_action(hmac_vap, hmac_user, &action_args);
        if (ret != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "hmac_mgmt_tx_action return NON SUCCESS. ");
        }
    }
    return HI_SUCCESS;
}
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : hmac����amsdu tx ����
*****************************************************************************/
hi_u32 hmac_config_set_amsdu_tx_on(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_ampdu_tx_on_param_stru  *ampdu_tx_on_param = HI_NULL;
    hmac_vap_stru                   *hmac_vap = HI_NULL;
    hi_list                         *entry = HI_NULL;
    hi_list                         *user_list_head = HI_NULL;
    mac_user_stru                   *user_tmp = HI_NULL;
    hmac_user_stru                  *hmac_user = HI_NULL;

    hi_unref_param(us_len);
    if (oal_unlikely(mac_vap == HI_NULL || puc_param == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_config_set_amsdu_tx_on:: parma null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_amsdu_tx_on::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    ampdu_tx_on_param = (mac_cfg_ampdu_tx_on_param_stru *)puc_param;
    hmac_vap->amsdu_active = ampdu_tx_on_param->aggr_tx_on;
    /* ����AMSDU��Ϊvap �������û�(���鲥�û�)����amsduָ�� �ر����ͷ����е�ָ�� */
    user_list_head = &(mac_vap->mac_user_list_head);
    for (entry = user_list_head->next; entry != user_list_head;) {
        user_tmp = hi_list_entry(entry, mac_user_stru, user_dlist);
        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru((hi_u8)user_tmp->us_assoc_id);
        if (hmac_user == HI_NULL) {
            continue;
        }
        entry = entry->next;
        if (user_tmp->is_multi_user) {
            continue;
        }
        if (hmac_vap->amsdu_active) {
            /* ����AMSDU ����ָ�����ָ��tid���� */
            hmac_amsdu_mem_alloc(hmac_user, ampdu_tx_on_param->tid, ampdu_tx_on_param->max_num);
        } else {
            /* �ر�AMSDU ��վۺ϶��в��ͷ�ָ��,�ͷ����ͷ����� */
            hmac_amsdu_mem_free(hmac_user);
        }
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ������ö��ֵת��Ϊ��Ӧ���ַ���Ϣ ��VAPinfo�����ӡ
*****************************************************************************/
static hi_u32 hmac_config_bw2string(hi_u32 bw)
{
    switch (bw) {
        case WLAN_BAND_WIDTH_20M:
            return 0x20;
        case WLAN_BAND_WIDTH_40PLUS:
            return 0x40B;
        case WLAN_BAND_WIDTH_40MINUS:
            return 0x40A;
        case WLAN_BAND_WIDTH_80PLUSPLUS:
            return 0x80AA;
        case WLAN_BAND_WIDTH_80PLUSMINUS:
            return 0x80AB;
        case WLAN_BAND_WIDTH_80MINUSPLUS:
            return 0x80BA;
        case WLAN_BAND_WIDTH_80MINUSMINUS:
            return 0x80BB;
        case WLAN_BAND_WIDTH_5M:
            return 0x5;
        case WLAN_BAND_WIDTH_10M:
            return 0x10;
        default :
            return 0xFFFF;
    }
}

/*****************************************************************************
 ��������  : ��ӡvap������Ϣ
*****************************************************************************/
hi_u32 hmac_config_vap_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru   *hmac_vap = HI_NULL;
    mac_user_stru   *mac_user = HI_NULL;
    hi_u8           loop;

    hi_unref_param(us_len);
    hi_unref_param(puc_param);

    if (mac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) {
        oam_warning_log0(0, 0, "{hmac_config_vap_info::this is config vap! can't get info.}");
        return HI_FAIL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, 0, "{hmac_config_vap_info::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    oam_warning_log4(0, 0, "vap id: %d, vap state: %d, vap mode: %d, P2P mode:%d",
        mac_vap->vap_id, mac_vap->vap_state, mac_vap->vap_mode, mac_vap->p2p_mode);
    /* AP/STA��Ϣ��ʾ */
    mac_user = mac_user_get_user_stru(mac_vap->assoc_vap_id);
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) && (mac_user != HI_NULL)) {
        oam_warning_log3(0, 0, "avaliable protocol: %d, current protocol: %d, channel number:%d.",
            mac_vap->protocol, mac_user->cur_protocol_mode, mac_vap->channel.chan_number);
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP
#ifdef _PRE_WLAN_FEATURE_MESH
              || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)

#endif
    ) {
        oam_warning_log4(0, 0, "protocol:%d, channel number:%d, associated user number:%d, beacon interval:%d.",
            mac_vap->protocol, mac_vap->channel.chan_number, mac_vap->user_nums,
            mac_vap->mib_info->wlan_mib_sta_config.dot11_beacon_period);
        oam_warning_log1(0, 0, "hide_ssid :%d", mac_vap->cap_flag.hide_ssid);
    } else {
        oam_warning_log1(0, 0, "protocol: %d.", mac_vap->protocol);
    }
    hi_u32 bandwidth = hmac_config_bw2string(mac_vap->channel.en_bandwidth);
    hi_unref_param(bandwidth);
    oam_warning_log0(0, 0, "0-11a, 1-11b, 3-11bg, 4-11g, 5-11bgn, 6-11ac, 7-11nonly, 8-11aconly, 9-11ng, other-error.");
    oam_warning_log2(0, 0, "band: %x G, bandwidth: %x M[80A=80+,80B=80-,80AB=80+-]",
        (mac_vap->channel.band == WLAN_BAND_2G) ? 2 : 0xFF, bandwidth); /* ֻ֧��2G,���������쳣ֵ0XFF */
    oam_warning_log4(0, 0, "amsdu=%d, uapsd=%d, wpa=%d, wpa2=%d.", hmac_vap->amsdu_active,
        mac_vap->cap_flag.uapsd, mac_vap->cap_flag.wpa, mac_vap->cap_flag.wpa2);
    oam_warning_log4(0, 0, "wps=%d, keepalive=%d, shortgi=%d, tx power=%d.", hmac_vap->wps_active,
        mac_vap->cap_flag.keepalive, mac_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented,
        mac_vap->tx_power);
    /* APP IE ��Ϣ */
    for (loop = 0; loop < OAL_APP_IE_NUM; loop++) {
        oam_warning_log3(0, 0, "APP IE:type= %d, addr = %p, len = %d.", loop,
            (uintptr_t)mac_vap->ast_app_ie[loop].puc_ie, mac_vap->ast_app_ie[loop].ie_len);
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����AMPDU��������
*****************************************************************************/
hi_u32 hmac_config_ampdu_start(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_ampdu_start_param_stru *ampdu_start = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_action_mgmt_args_stru action_args;
    hi_u8 ret;
    hi_u32 result;

    hi_unref_param(us_len);

    ampdu_start = (mac_cfg_ampdu_start_param_stru *)puc_param;
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    /* ��ȡ�û���Ӧ������ */
    hmac_user = mac_vap_get_hmac_user_by_addr(mac_vap, ampdu_start->auc_mac_addr, WLAN_MAC_ADDR_LEN);
    if (hmac_vap == HI_NULL || hmac_user == HI_NULL) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_ampdu_start::hmac_vap/hmac_user null! hmac_vap=%p, hmac_user=%p}",
            (uintptr_t)hmac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    ret = hmac_tid_need_ba_session(hmac_vap, hmac_user, ampdu_start->tidno, HI_NULL);
    if (ret == HI_TRUE) {
        /*
           ����BA�Ựʱ��st_action_args�ṹ������Ա��������
           (1)uc_category:action�����
           (2)uc_action:BA action�µ����
           (3)ul_arg1:BA�Ự��Ӧ��TID
           (4)ul_arg2:BUFFER SIZE��С
           (5)ul_arg3:BA�Ự��ȷ�ϲ���
           (6)ul_arg4:TIMEOUTʱ��
         */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_ampdu_start::uc_tidno=%d.}",
                         ampdu_start->tidno);
        action_args.category = MAC_ACTION_CATEGORY_BA;
        action_args.action = MAC_BA_ACTION_ADDBA_REQ;
        action_args.arg1 = ampdu_start->tidno;     /* ������֡��Ӧ��TID�� */
        action_args.arg2 = WLAN_AMPDU_TX_MAX_BUF_SIZE;    /* ADDBA_REQ�У�buffer_size��Ĭ�ϴ�С */
        action_args.arg3 = MAC_BA_POLICY_IMMEDIATE;       /* BA�Ự��ȷ�ϲ��� */
        action_args.arg4 = 0;     /* BA�Ự�ĳ�ʱʱ������Ϊ0 */

        /* ����BA�Ự */
        result = hmac_mgmt_tx_action(hmac_vap, hmac_user, &action_args);
        if (result != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "hmac_mgmt_tx_action return NON SUCCESS. ");
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����amsdu+ampdu���ϾۺϵĿ���
*****************************************************************************/
hi_u32 hmac_config_amsdu_ampdu_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_s32 l_value;

    hi_unref_param(us_len);

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_amsdu_ampdu_switch::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    l_value = *((hi_s32 *)puc_param);
    hmac_vap->amsdu_ampdu_active = (hi_u8) l_value;
    oam_warning_log1(0, 0, "hmac_config_amsdu_ampdu_switch:: switch_value[%d]", hmac_vap->amsdu_ampdu_active);
    return HI_SUCCESS;
}

#endif

/*****************************************************************************
 ��������  : ��ӡuser��Ϣ
*****************************************************************************/
hi_u32 hmac_config_user_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_USER_INFO, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_user_info::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ���÷�����������Ϣ
*****************************************************************************/
hi_u32 hmac_config_set_dscr_param(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_DSCR, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_set_dscr_param:: send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ɾ��hmac ba��ʱ��ʱ�������ú�����50�в��
 *****************************************************************************/
hi_u32 hmac_proc_dev_sleep_req_del_ba_timer(const hmac_vap_stru *hmac_vap, hi_u32 pm_wlan_state)
{
    hi_list *entry = HI_NULL;
    hi_list *user_list_head = HI_NULL;
    mac_user_stru *mac_user = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hi_u8 tid_num;

     /* ������ VAP �������û� */
    if (hmac_vap->base_vap == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_proc_dev_sleep_req_del_ba_timer::hmac_vap->base_vap is null.}");
        return HI_FAIL;
    }

    user_list_head = &(hmac_vap->base_vap->mac_user_list_head);
    for (entry = user_list_head->next; entry != user_list_head; entry = entry->next) {
        mac_user = hi_list_entry(entry, mac_user_stru, user_dlist);
        /*lint -e774*/
        if (mac_user == HI_NULL) {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_proc_dev_sleep_req_del_ba_timer::mac user is null.}");
            return HI_FAIL;
        }
        /*lint +e774*/
        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(mac_user->us_assoc_id);
        if (hmac_user == HI_NULL) {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_proc_dev_sleep_req_del_ba_timer::hmac user is null.}");
            return HI_FAIL;
        }

        for (tid_num = 0; tid_num < WLAN_TID_MAX_NUM; tid_num++) {
            hmac_ba_rx_stru *rx_ba = hmac_user->ast_tid_info[tid_num].ba_rx_info;
            if ((rx_ba == HI_NULL) || (rx_ba->ba_timer.is_registerd == HI_FALSE)) {
                continue;
            }
            if ((pm_wlan_state == WLAN_PM_WORK) && (rx_ba->ba_timer.func != HI_NULL)) {
                if (rx_ba->ba_timer.timeout_arg == HI_NULL) {
                    continue;
                }
                /* work��ֱ�ӵ��ó�ʱ�ص����� */
                rx_ba->ba_timer.func(rx_ba->ba_timer.timeout_arg);
            } else if (pm_wlan_state == WLAN_PM_DEEP_SLEEP) {
                /* ��˯��ֱ�ӽ��ö�ʱ�� */
                frw_timer_stop_timer(&(rx_ba->ba_timer));
            }
            /* ������������Ҫ���� */
        }
    }

    return HI_SUCCESS;
}

hi_u32 hmac_proc_dev_sleep_req(const frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u32 sleep_type;
    hi_u32 *data = HI_NULL;
    hi_u32 pm_wlan_state;
    hi_u8 *pm_wlan_need_stop_ba = mac_get_pm_wlan_need_stop_ba();
    hi_u32 ret;

    event = (frw_event_stru *)(event_mem->puc_data);
    data = (hi_u32 *)(event->auc_event_data);
    sleep_type = *data;
    hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_proc_dev_sleep_req::hmac vap is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (sleep_type == WLAN_PM_LIGHT_SLEEP) {
        pm_wlan_state = WLAN_PM_LIGHT_SLEEP;
    } else if (sleep_type == WLAN_PM_DEEP_SLEEP) {
        *pm_wlan_need_stop_ba = HI_TRUE;
        pm_wlan_state = WLAN_PM_DEEP_SLEEP;
    } else if (sleep_type == WLAN_PM_WORK) {
        *pm_wlan_need_stop_ba = HI_FALSE;
        pm_wlan_state = WLAN_PM_WORK;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_proc_dev_sleep_req::state is wrong.}");
        return HI_FAIL;
    }

    /* ɾ��hmac ba��ʱ��ʱ�� */
    ret = hmac_proc_dev_sleep_req_del_ba_timer(hmac_vap, pm_wlan_state);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_proc_dev_sleep_req::del ba timeout timer not succ[%d]}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����Э��ģʽͬ���¼�
 �޸���ʷ      :
  1.��    ��   : 2015��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_syn_info_event(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u32 relt;
    dmac_to_hmac_syn_info_event_stru *syn_info_event = HI_NULL;

    event = (frw_event_stru *)event_mem->puc_data;
    syn_info_event = (dmac_to_hmac_syn_info_event_stru *)event->auc_event_data;
    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(syn_info_event->user_index);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_syn_info_event: pst_hmac_user null,user_idx=%d.}",
                         syn_info_event->user_index);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap = mac_vap_get_vap_stru(hmac_user->base_user->vap_id);
    if (mac_vap == HI_NULL) {
        oam_warning_log2(0, OAM_SF_ANY, "{hmac_syn_info_event: pst_mac_vap null! vap_idx=%d, user_idx=%d.}",
                         hmac_user->base_user->vap_id, syn_info_event->user_index);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_user->base_user->cur_protocol_mode = syn_info_event->cur_protocol;
    hmac_user->base_user->cur_bandwidth = syn_info_event->cur_bandwidth;
    relt = hmac_config_user_info_syn(mac_vap, hmac_user->base_user);
    return relt;
}

/*****************************************************************************
 ��������  : ����Voice�ۺ�ͬ���¼�
 �޸���ʷ      :
  1.��    ��   : 2015��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_voice_aggr_event(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    dmac_to_hmac_voice_aggr_event_stru *voice_aggr_event = HI_NULL;
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_P2P, "{hmac_voice_aggr_event::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    event = (frw_event_stru *)event_mem->puc_data;
    voice_aggr_event = (dmac_to_hmac_voice_aggr_event_stru *)event->auc_event_data;

    mac_vap = mac_vap_get_vap_stru(voice_aggr_event->vap_id);
    if (mac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY, "{hmac_voice_aggr_event: pst_mac_vap null! vap_idx=%d}",
                       voice_aggr_event->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_vap->voice_aggr = voice_aggr_event->voice_aggr;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����¼��ڴ�
 �������  : pst_mac_vap: ָ��vap
             en_syn_type: �¼���subtype, ��ͬ����Ϣ����
             ppst_syn_msg  : ָ��ͬ����Ϣpayload��ָ��
             ppst_event_mem: ָ���¼��ڴ��ָ��
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_alloc_event(const mac_vap_stru *mac_vap,
                                      hmac_to_dmac_syn_type_enum_uint8 syn_type,
                                      hmac_to_dmac_cfg_msg_stru **syn_msg,
                                      frw_event_mem_stru **event_mem, hi_u16 us_len)
{
    frw_event_mem_stru *event_mem_value = HI_NULL;
    frw_event_stru *event = HI_NULL;

    event_mem_value = frw_event_alloc(us_len + sizeof(hmac_to_dmac_cfg_msg_stru) - 4); /* 4 ���ڼ��� */
    if (oal_unlikely(event_mem_value == HI_NULL)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_config_alloc_event::event_mem null, us_len = %d }", us_len);
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    event = (frw_event_stru *)event_mem_value->puc_data;

    /* ����¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CRX,
                       syn_type,
                       (us_len + sizeof(hmac_to_dmac_cfg_msg_stru) - 4), /* 4 ���ڼ��� */
                       FRW_EVENT_PIPELINE_STAGE_1,
                       mac_vap->vap_id);
    /* ���θ�ֵ */
    *event_mem = event_mem_value;
    *syn_msg = (hmac_to_dmac_cfg_msg_stru *)event->auc_event_data;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���¼���DMAC��, ͬ��DMAC����
 �������  : pst_mac_vap  : VAP
             en_cfg_id: ����id
             us_len: ��Ϣ����
             puc_param: ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_send_event(const mac_vap_stru *mac_vap,
                              wlan_cfgid_enum_uint16 cfg_id, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    frw_event_mem_stru *event_mem = HI_NULL;
    hmac_to_dmac_cfg_msg_stru *syn_msg = HI_NULL;

    ret = hmac_config_alloc_event(mac_vap, HMAC_TO_DMAC_SYN_CFG, &syn_msg, &event_mem, us_len);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_send_event::hmac_config_alloc_event failed[%d].}", ret);
        return ret;
    }
    syn_msg->syn_id = cfg_id;
    syn_msg->us_len = us_len;
    /* ��д����ͬ����Ϣ���� */
    if (puc_param != HI_NULL) {
        if (memcpy_s(syn_msg->auc_msg_body, syn_msg->us_len, puc_param, (hi_u32) us_len) != EOK) {
            frw_event_free(event_mem);
            oam_error_log0(0, OAM_SF_CFG, "hmac_config_send_event:: puc_param memcpy_s fail.");
            return HI_FAIL;
        }
    }
    /* �׳��¼� */
    ret = hcc_hmac_tx_control_event(event_mem,
        us_len + (hi_u16)oal_offset_of(hmac_to_dmac_cfg_msg_stru, auc_msg_body));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_send_event::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }

    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��start vap�¼�
 �޸���ʷ      :
  1.��    ��   : 2015��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_start_vap_event(const mac_vap_stru *mac_vap, hi_u8 mgmt_rate_init_flag)
{
    hi_u32 ret;
    mac_cfg_start_vap_param_stru start_vap_param;

    /* DMAC��ʹ��netdev��Ա */
    start_vap_param.net_dev = HI_NULL;
    start_vap_param.mgmt_rate_init_flag = mgmt_rate_init_flag;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    start_vap_param.protocol = mac_vap->protocol;
    start_vap_param.band = mac_vap->channel.band;
    start_vap_param.uc_bandwidth = mac_vap->channel.en_bandwidth;
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    start_vap_param.p2p_mode = mac_vap->p2p_mode;
#endif

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_START_VAP, sizeof(mac_cfg_start_vap_param_stru),
                                 (hi_u8 *)&start_vap_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_start_vap_event::Start_vap failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ��ȡg_wlan_pm_switch�ṹ
*****************************************************************************/
hi_bool hmac_get_wlan_pm_switch(hi_void)
{
    return g_wlan_pm_on;
}

/*****************************************************************************
 ��������  : ����g_wlan_pm_switch�ṹ
*****************************************************************************/
hi_void hmac_set_wlan_pm_switch(hi_bool wlan_pm_switch)
{
    g_wlan_pm_on = wlan_pm_switch;
}

/*****************************************************************************
 ��������  : ����ģʽ�¼������¼���dmac��
 �޸���ʷ      :
  1.��    ��   : 2015��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_set_mode_event(const mac_vap_stru *mac_vap)
{
    hi_u32 ret;
    mac_cfg_mode_param_stru prot_param;

    /* ���ô���ģʽ��ֱ�����¼���DMAC���üĴ��� */
    prot_param.protocol = mac_vap->protocol;
    prot_param.band = mac_vap->channel.band;
    prot_param.en_bandwidth = mac_vap->channel.en_bandwidth;

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_MODE, sizeof(mac_cfg_mode_param_stru), (hi_u8 *) &prot_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log4(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_set_mode_event::mode_set failed[%d],protocol[%d], band[%d], bandwidth[%d].}", ret,
                         mac_vap->protocol, mac_vap->channel.band,
                         mac_vap->channel.en_bandwidth);
    }
    return ret;
}

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
/*****************************************************************************
 ��������  : ͬ��ģʽ֪ͨ�����Ϣ
 �� �� ֵ  : hi_u32
 �޸���ʷ      :
  1.��    ��   : 2015��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_update_opmode_event(mac_vap_stru *mac_vap, mac_user_stru *mac_user,
                                       hi_u8 mgmt_frm_type)
{
    hi_u32 relt;
    mac_user_opmode_stru user_opmode;
    /* opmodeϢͬ��dmac */
    user_opmode.avail_num_spatial_stream = mac_user->avail_num_spatial_stream;
    user_opmode.avail_bf_num_spatial_stream = mac_user->avail_bf_num_spatial_stream;
    user_opmode.avail_bandwidth = mac_user->avail_bandwidth;
    user_opmode.cur_bandwidth = mac_user->cur_bandwidth;
    user_opmode.user_idx = (hi_u8)mac_user->us_assoc_id;
    user_opmode.frame_type = mgmt_frm_type;

    relt = hmac_config_send_event(mac_vap, WLAN_CFGID_UPDATE_OPMODE, sizeof(mac_user_opmode_stru),
                                  (hi_u8 *)(&user_opmode));
    if (oal_unlikely(relt != HI_SUCCESS)) {
        oam_warning_log1(mac_user->vap_id, OAM_SF_CFG,
                         "{hmac_config_update_opmode_event::opmode_event send failed[%d].}", relt);
    }
    return relt;
}
#endif

/*****************************************************************************
 ��������  : ͨ�õĴ�hmacͬ�����dmac����
 �޸���ʷ      :
  1.��    ��   : 2013��5��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_sync_cmd_common(const mac_vap_stru *mac_vap, wlan_cfgid_enum_uint16 cfg_id, hi_u16 us_len,
                                   const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, cfg_id, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_sync_cmd_common::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2014��5��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_normal_check_vap_num(const mac_device_stru *mac_dev,
                                               const mac_cfg_add_vap_param_stru *param)
{
    if (param == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_config_normal_check_vap_num::param is null.}");
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    if (param->p2p_mode != WLAN_LEGACY_VAP_MODE) {
        /* P2P VAP����У�� */
        return hmac_p2p_check_vap_num(mac_dev, param->p2p_mode);
    }
#endif

    if ((param->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        || (param->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        ) {
        /* AP����������1 */
        if ((mac_dev->vap_num - mac_dev->sta_num) >= WLAN_AP_NUM_PER_DEVICE) {
            oam_warning_log0(0, OAM_SF_CFG,
                "{hmac_config_normal_check_vap_num::create vap fail, because at least 1 ap exist.}");
            return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
        }
    } else if (param->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        if (mac_dev->sta_num >= WLAN_STA_NUM_PER_DEVICE) {
            /* �Ѵ�����STA�����ﵽ���ֵ */
            oam_warning_log1(0, OAM_SF_CFG,
                "{hmac_config_normal_check_vap_num::create vap fail, because sta num [%d] is more than 2.}",
                mac_dev->sta_num);
            return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
        }
    }

    return HI_SUCCESS;
}

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
/*****************************************************************************
 ��������  : ��������vap���¼�
 �޸���ʷ      :
  1.��    ��   : 2013��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_cfg_vap_send_event(const mac_device_stru *mac_dev)
{
    hi_unref_param(mac_dev);
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u32 ret;

    /* ���¼���DMAC,��DMAC�������VAP���� */
    event_mem = frw_event_alloc(0);
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_cfg_vap_send_event::event_mem null.}");
        return HI_FAIL;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CRX,
                       HMAC_TO_DMAC_SYN_CREATE_CFG_VAP,
                       0,
                       FRW_EVENT_PIPELINE_STAGE_1,
                       WLAN_CFG_VAP_ID);

    ret = hcc_hmac_tx_control_event(event_mem, sizeof(hi_u16));
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_cfg_vap_send_event::frw_event_dispatch_event failed[%d].}", ret);
    }

    /* �ͷ��¼� */
    frw_event_free(event_mem);

    return ret;
}
#endif

/*****************************************************************************
 ��������      : ����ϵͳ�͹��Ŀ���
 �޸���ʷ      :
  1.��    ��   : 2018��12��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_pm_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    hi_u32 pm_cfg;
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_vap_stru *vap = HI_NULL; /* ҵ��vap */
    mac_device_stru *mac_dev = mac_res_get_dev();
    hi_u8 vap_idx;

    pm_cfg = *(hi_u32 *)puc_param;
    /* Ѱ��STA */
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (vap == HI_NULL) {
            continue;
        }
        if (vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            break;
        }
    }

    if (vap != HI_NULL) {
        hmac_vap = hmac_vap_get_vap_stru(vap->vap_id);
        if (hmac_vap == HI_NULL) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_pm_switch::pst_hmac_vap null.}");
            return HI_ERR_CODE_PTR_NULL;
        }

        if ((pm_cfg & BIT0) == MAC_STA_PM_SWITCH_OFF) {
            if (hmac_vap->ps_sw_timer.is_registerd == HI_TRUE) {
                frw_timer_immediate_destroy_timer(&(hmac_vap->ps_sw_timer));
            }
        }
    }

    /*
     * PM_SWITCH �� DTIM_TIMES ���ò���
     * PM_SWITCH BIT[0]
     * DTIM_TIMES BIT[31:1]
     */
    if ((pm_cfg & BIT0) == MAC_STA_PM_SWITCH_ON) {
        hmac_set_wlan_pm_switch(HI_TRUE);
    } else {
        hmac_set_wlan_pm_switch(HI_FALSE);
        if (g_pm_apdown_timer.is_registerd == HI_TRUE) {
            frw_timer_immediate_destroy_timer(&g_pm_apdown_timer);
        }
    }

    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_PM_SWITCH, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_set_pm_switch::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

static hi_u32 hmac_config_init_hmac_vap(hi_u8 vap_id, hmac_vap_stru *hmac_vap, mac_device_stru *mac_dev,
    mac_cfg_add_vap_param_stru *param)
{
    hi_u32         ret;
    param->vap_id = vap_id;
    /* ��ʼ��HMAC VAP */
    ret = hmac_vap_init(hmac_vap, vap_id, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_init_hmac_vap::hmac_vap_init failed[%d].}", ret);
        if (hmac_vap->base_vap->mib_info != HI_NULL) {
            oal_mem_free(hmac_vap->base_vap->mib_info);
        }

        /* �쳣�����ͷ��ڴ� */
        mac_vap_free_vap_res(vap_id);
        return ret;
    }

    /* ���÷��ҵ�net_deviceָ�� */
#ifdef _PRE_WLAN_FEATURE_P2P
    if (param->p2p_mode == WLAN_P2P_DEV_MODE) {
        /* p2p0 DEV ģʽvap������pst_p2p0_net_device ��Աָ���Ӧ��net_device */
        hmac_vap->p2p0_net_device = param->net_dev;
        mac_dev->p2p_info.p2p0_vap_idx = hmac_vap->base_vap->vap_id;
    }
#endif
    hmac_vap->net_device = param->net_dev;

    /* �����뵽��mac_vap�ռ�ҵ�net_device ml_privָ����ȥ */
    oal_net_dev_priv(param->net_dev) = hmac_vap->base_vap;
    /* ����hmac�鲥�û� */
    hmac_user_add_multi_user(hmac_vap->base_vap, &param->muti_user_id);
    mac_vap_set_multi_user_idx(hmac_vap->base_vap, param->muti_user_id);
    mac_device_set_vap_id(mac_dev, hmac_vap->base_vap, param, vap_id, HI_TRUE);
#ifdef _PRE_WLAN_FEATURE_P2P
    if (param->vap_mode == WLAN_VAP_MODE_BSS_STA && param->p2p_mode == WLAN_P2P_DEV_MODE) {
        mac_dev->sta_num++;
    }
#endif

    if (param->vap_mode == WLAN_VAP_MODE_BSS_AP
#ifdef _PRE_WLAN_FEATURE_MESH
        || param->vap_mode == WLAN_VAP_MODE_MESH
#endif
        ) {
            param->uapsd_enable = hmac_vap->base_vap->cap_flag.uapsd;
    }
    return HI_SUCCESS;
}

static hi_u32 hmac_config_set_station_id(const hmac_vap_stru *hmac_vap, mac_device_stru *mac_dev, hi_u8 vap_id,
    const mac_cfg_add_vap_param_stru *param)
{
    mac_cfg_staion_id_param_stru station_id_param = {0};
    hi_u32         ret;
    /* ����mac��ַ */
    if (memcpy_s(station_id_param.auc_station_id, WLAN_MAC_ADDR_LEN,
        param->net_dev->dev_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        /* �˴�����������Ҫ��Ӧmac_device_set_vap_id�������˲��� */
        mac_device_set_vap_id(mac_dev, hmac_vap->base_vap, param, vap_id, HI_FALSE);

        /* �쳣�����ͷ��ڴ� */
        oal_mem_free(hmac_vap->base_vap->mib_info);

        mac_vap_free_vap_res(vap_id);
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_set_station_id::mem safe function err!}");
        return HI_FAIL;
    }
    station_id_param.p2p_mode = param->p2p_mode;
    ret = hmac_config_set_mac_addr(hmac_vap->base_vap, sizeof(mac_cfg_staion_id_param_stru),
        (hi_u8 *)(&station_id_param));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        /* �˴�����������Ҫ��Ӧmac_device_set_vap_id�������˲��� */
        mac_device_set_vap_id(mac_dev, hmac_vap->base_vap, param, vap_id, HI_FALSE);

        /* �쳣�����ͷ��ڴ� */
        oal_mem_free(hmac_vap->base_vap->mib_info);

        mac_vap_free_vap_res(vap_id);
        oam_error_log1(0, OAM_SF_CFG, "{hmac_config_set_station_id::hmac_config_set_mac_addr failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : ����HMAC ҵ��VAP
 �������  : pst_vap   : ָ������vap
             us_len    : ��������
             puc_param : ����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2012��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_add_vap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    mac_device_stru *mac_dev = mac_res_get_dev();

    if (oal_unlikely((mac_vap == HI_NULL) || (puc_param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_add_vap::param null,pst_vap=%p puc_param=%p.}",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_cfg_add_vap_param_stru *param = (mac_cfg_add_vap_param_stru *)puc_param;
#ifdef _PRE_WLAN_FEATURE_P2P
    if (param->p2p_mode == WLAN_P2P_CL_MODE) {
        return hmac_p2p_add_gc_vap(mac_dev, us_len, puc_param);
    }
#endif
    /* VAP�����ж� */
    ret = hmac_config_normal_check_vap_num(mac_dev, param);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* ����Դ������ vap id */
    hi_u8 vap_id = mac_vap_alloc_vap_res();
    if (oal_unlikely(vap_id == MAC_VAP_RES_ID_INVALID)) {
        return HI_FAIL;
    }
    /* ����Դ�ػ�ȡ�����뵽��hmac vap */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(vap_id);
    if (hmac_vap == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    ret =  hmac_config_init_hmac_vap(vap_id, hmac_vap, mac_dev, param);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(hmac_vap->base_vap, WLAN_CFGID_ADD_VAP, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        /* �˴�����������Ҫ��Ӧmac_device_set_vap_id�������˲��� */
        mac_device_set_vap_id(mac_dev, hmac_vap->base_vap, param, vap_id, HI_FALSE);

        /* �쳣�����ͷ��ڴ� */
        oal_mem_free(hmac_vap->base_vap->mib_info);

        mac_vap_free_vap_res(vap_id);

        oam_error_log1(0, OAM_SF_CFG, "{hmac_config_add_vap::hmac_config_alloc_event failed[%d].}", ret);
        return ret;
    }
    /* ����֡���� */
    hmac_set_rx_filter_value(hmac_vap->base_vap);

    /* ����station id */
    ret = hmac_config_set_station_id(hmac_vap, mac_dev, vap_id, param);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    oam_warning_log2(vap_id, OAM_SF_ANY, "{hmac_config_add_vap::add vap [%d] success! vap_id is %d",
                     param->vap_mode, param->vap_id);

    return HI_SUCCESS;
}

hi_void hmac_config_del_timer_user_vap(hmac_vap_stru *hmac_vap)
{
    /* �������е�timer */
    if (hmac_vap->mgmt_timer.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->mgmt_timer));
        hmac_vap->mgmt_timer.is_registerd = HI_FALSE;
    }
    if (hmac_vap->scan_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->scan_timeout));
        hmac_vap->scan_timeout.is_registerd = HI_FALSE;
    }
    if (hmac_vap->scanresult_clean_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->scanresult_clean_timeout));
        hmac_vap->scanresult_clean_timeout.is_registerd = HI_FALSE;
    }
#ifdef _PRE_WLAN_FEATURE_STA_PM
    if (hmac_vap->ps_sw_timer.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->ps_sw_timer));
        hmac_vap->ps_sw_timer.is_registerd = HI_FALSE;
    }
#endif
}

hi_u32 hmac_config_del_timer_user(mac_vap_stru *mac_vap, hmac_vap_stru *hmac_vap)
{
    /* DTS2015060903681 */
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP
#ifdef _PRE_WLAN_FEATURE_MESH
        || (mac_vap->vap_mode == (hi_u8)WLAN_VAP_MODE_MESH)
#endif
        ) {
        hmac_vap->edca_opt_flag_ap = 0;
        frw_timer_immediate_destroy_timer(&(hmac_vap->edca_opt_timer));
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        hmac_vap->edca_opt_flag_sta = 0;
    }
#endif

    /* ���������VAP, ȥע������vap��Ӧ��net_device, �ͷţ����� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) {
        /* ��ע��netdevice֮ǰ�Ƚ�ָ�븳Ϊ�� */
        oal_net_device_stru *netdev = hmac_vap->net_device;
        hmac_vap->net_device = HI_NULL;
        oal_net_unregister_netdev(netdev);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        oal_net_free_netdev(netdev);
#endif
        mac_vap_free_vap_res(mac_vap->vap_id);
        return HI_SUCCESS;
    }

    /* ҵ��vap net_device����WAL�ͷţ��˴���Ϊnull */
#ifdef _PRE_WLAN_FEATURE_P2P
    /* ���p2p0,��Ҫɾ��hmac �ж�Ӧ��p2p0 netdevice ָ�� */
    hmac_vap->p2p0_net_device = (mac_vap->p2p_mode == WLAN_P2P_DEV_MODE) ? HI_NULL : hmac_vap->p2p0_net_device;
#endif
    hmac_vap->net_device = HI_NULL;
    if (hmac_vap->puc_asoc_req_ie_buff != HI_NULL) {
        oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
        hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
    }
    hmac_config_del_timer_user_vap(hmac_vap);

    mac_vap_exit(mac_vap);

    return HI_CONTINUE;
}

/*****************************************************************************
 ��������  : ɾ��vap
 �������  : pst_vap   : ָ��vap��ָ��
             us_len    : ��������
             puc_param : ����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2013��5��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_del_vap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *param)
{
    if (oal_unlikely((mac_vap == HI_NULL) || (param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_del_vap:vap=%p,param=%p}", (uintptr_t)mac_vap, (uintptr_t)param);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_del_vap::hmac_vap_get_vap_stru failed.}");
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    if (mac_vap->p2p_mode == WLAN_P2P_CL_MODE) {
        return hmac_p2p_del_gc_vap(mac_vap, us_len, param);
    }
#endif

    if (mac_vap->vap_state != MAC_VAP_STATE_INIT) {
        oam_warning_log2(0, 0, "{hmac_config_del_vap:state=%d,mode=%d}", mac_vap->vap_state, mac_vap->vap_mode);
        return HI_FAIL;
    }

    hi_u32 ret = hmac_config_del_timer_user(mac_vap, hmac_vap);
    if (ret != HI_CONTINUE) {
        return ret;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* liteos��Ҫ��ʱ�·�˯��ָ�device�� */
    if (((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) ||
         (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)) && g_wlan_pm_on == HI_TRUE) {
        if (g_pm_apdown_timer.is_registerd == HI_TRUE) {
            frw_timer_immediate_destroy_timer(&g_pm_apdown_timer);
        }
        frw_timer_create_timer(&g_pm_apdown_timer, hmac_set_psm_timeout,
                               PM_APDOWN_ENTERY_TIME, (hi_void *)hmac_vap, HI_FALSE);
    }
#endif
    mac_vap_free_vap_res(mac_vap->vap_id);

    /***************************************************************************
                          ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DEL_VAP, us_len, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        /* ���˳�����֤Devce�ҵ�������¿����µ� */
        oam_error_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_del_vap::hmac_config_send_event failed[%d].}", ret);
    }

    oam_warning_log3(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_del_vap:Del succ.vap_mode=%d,p2p_mode=%d,user idx[%d]}",
                     mac_vap->vap_mode, mac_vap->p2p_mode, mac_vap->multi_user_idx);
    /* ��dmac�������鲥�û�����֮�����ͷ��鲥�û� */
    hmac_user_del_multi_user(mac_vap->multi_user_idx);

    /* ҵ��vap��ɾ������device��ȥ�� */
    mac_device_stru *mac_dev = mac_res_get_dev();
    oam_warning_log1(0, OAM_SF_ANY, "uc_vap_num = %d", mac_dev->vap_num);
    if (mac_dev->vap_num == 0) {
        hmac_config_host_dev_exit(mac_vap, 0, HI_NULL);
        wlan_pm_close();
    }

    return ret;
}

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
/*****************************************************************************
 ��������  : ����Ĭ��Ƶ�����ŵ�������
 �������  : pst_mac_vap : ָ��vap
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2015��3��37��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_def_chan(mac_vap_stru *mac_vap)
{
    hi_u8 channel;
    mac_cfg_mode_param_stru param;

    if (((mac_vap->channel.band == WLAN_BAND_BUTT) ||
         (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_BUTT) ||
         (mac_vap->protocol == WLAN_PROTOCOL_BUTT))
        && (!is_p2p_go(mac_vap))) {
        param.band = WLAN_BAND_2G;
        param.en_bandwidth = WLAN_BAND_WIDTH_20M;
        param.protocol = WLAN_HT_MODE;
        hmac_config_set_mode(mac_vap, sizeof(param), (hi_u8 *) &param);
    }

    if ((mac_vap->channel.chan_number == 0) && (!is_p2p_go(mac_vap))) {
        mac_vap->channel.chan_number = 6; /* number ��ֵΪ 6 */
        channel = mac_vap->channel.chan_number;
        hmac_config_set_freq(mac_vap, sizeof(hi_u32), &channel);
    }

    return HI_SUCCESS;
}

#endif /* #if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) */

hi_u32 hmac_config_ap_mesh_start(mac_vap_stru *mac_vap, hmac_vap_stru *hmac_vap)
{
    /* P2P GO ������δ����ssid ��Ϣ������Ϊup ״̬����Ҫ���ssid ���� */
    hi_u8 *puc_ssid = mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid;
    if ((strlen((const hi_char *)puc_ssid) == 0) && (!is_p2p_go(mac_vap))) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::ssid length=0.}");
        return HI_FAIL;    /* û����SSID��������VAP */
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    hi_u8 *puc_meshid = mac_vap->mib_info->wlan_mib_mesh_sta_cfg.auc_dot11_mesh_id;
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_MESH) && (strlen((const hi_char *)puc_meshid) == 0)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::mesh vap meshid length=0.}");
        return HI_FAIL;    /* û����Meshid��������VAP */
    }
#endif

    /* ����AP��״̬��Ϊ WAIT_START */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_AP_WAIT_START);

    if (is_legacy_vap(hmac_vap->base_vap)) {
        /* l00311403: 02ʹ��hostapd���г�ʼɨ�裬51ʹ��������ʼɨ�� */
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        hmac_config_def_chan(mac_vap);
#endif
    }

    /* ���� en_status ���� MAC_CHNL_AV_CHK_NOT_REQ(������) ���� MAC_CHNL_AV_CHK_COMPLETE(������) */
    /* ���Э�� Ƶ�� �����Ƿ����� */
    if ((mac_vap->channel.band == WLAN_BAND_BUTT) || (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_BUTT) ||
        (mac_vap->protocol == WLAN_PROTOCOL_BUTT)) {
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_INIT);

        if (is_p2p_go(mac_vap)) {
            /* wpa_supplicant ��������vap up�� ��ʱ��δ��vap �����ŵ��������Э��ģʽ��Ϣ��
               wpa_supplicant ��cfg80211_start_ap �ӿ�����GO �ŵ��������Э��ģʽ��Ϣ��
               �ʴ˴����û�������ŵ��������Э��ģʽ��ֱ�ӷ��سɹ���������ʧ�ܡ� */
            oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG,
                "{hmac_config_start_vap::set band bandwidth protocol first.band[%d], bw[%d], protocol[%d]}",
                mac_vap->channel.band, mac_vap->channel.en_bandwidth, mac_vap->protocol);
            return HI_SUCCESS;
        } else {
            oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::set bandwidth protocol first}");
            return HI_FAIL;
        }
    }

    /* ����ŵ����Ƿ����� */
    if ((mac_vap->channel.chan_number == 0) && (!is_p2p_go(mac_vap))) {
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_INIT);
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::set channel number first.}");
        return HI_FAIL;
    }

    /* ����bssid */
    mac_vap_set_bssid(mac_vap, mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN);

    /* �����Ż�����ͬƵ���µ�������һ�� */
    if (mac_vap->channel.band == WLAN_BAND_2G) {
        mac_mib_set_short_preamble_option_implemented(mac_vap, WLAN_LEGACY_11B_MIB_SHORT_PREAMBLE);
        mac_mib_set_spectrum_management_required(mac_vap, HI_FALSE);
    } else {
        mac_mib_set_short_preamble_option_implemented(mac_vap, WLAN_LEGACY_11B_MIB_LONG_PREAMBLE);
        mac_mib_set_spectrum_management_required(mac_vap, HI_TRUE);
    }

    /* ����AP��״̬��Ϊ UP */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_UP);

    /* allow sleep when ap up */
    wlan_pm_add_vote(HI_PM_ID_AP);

    return HI_CONTINUE;
}

/*****************************************************************************
 �� �� ��  : hmac_config_start_vap
 ��������  : hmac����VAP
 �������  : pst_mac_vap : ָ��vap
             us_len      : ��������
             puc_param   : ����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2012��12��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_start_vap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *param)
{
    mac_cfg_start_vap_param_stru *start_vap_param = (mac_cfg_start_vap_param_stru *)param;

    if (oal_unlikely((mac_vap == HI_NULL) || (param == HI_NULL) || (us_len != us_len))) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_start_vap:vap=%p param=%p}", (uintptr_t)mac_vap, (uintptr_t)param);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_state_enum_uint8 state = mac_vap->vap_state;
    if (state == MAC_VAP_STATE_BUTT) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::the vap has been deleted.}");
        return HI_FAIL;
    }

    /* ����Ѿ���up״̬���򷵻سɹ� */
    if ((state == MAC_VAP_STATE_UP) || (state == MAC_VAP_STATE_AP_WAIT_START) || (state == MAC_VAP_STATE_STA_FAKE_UP)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::state=%d,duplicate start}", state);
        return HI_SUCCESS;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP
#ifdef _PRE_WLAN_FEATURE_MESH
        || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        ) {
        hi_u32 ap_ret = hmac_config_ap_mesh_start(mac_vap, hmac_vap);
        if (ap_ret != HI_CONTINUE) {
            return ap_ret;
        }
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
#ifdef _PRE_WLAN_FEATURE_P2P
        /* p2p0��p2p-p2p0 ��VAP �ṹ������p2p cl�����޸�vap ״̬ */
        if (start_vap_param->p2p_mode != WLAN_P2P_CL_MODE) {
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
        }
#else
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
#endif
    } else {
        /* ������֧ �ݲ�֧�� ������ */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::mode[%d]Err}", mac_vap->vap_mode);
    }

    mac_vap_init_rates(mac_vap);

    hi_u32 ret = hmac_config_start_vap_event(mac_vap, start_vap_param->mgmt_rate_init_flag);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap::hmac_config_send_event Err=%d}", ret);
        return ret;
    }

    oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_start_vap:host start vap ok}");

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ָ����Э��ģʽ����VAP���ʼ�
 �������  : pst_mac_vap : ָ��vap
             pst_cfg_mode: Э��ģʽ��ز���
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2014��8��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_sta_update_rates(mac_vap_stru *mac_vap, const mac_cfg_mode_param_stru *cfg_mode)
{
    hi_u32 ret;
    hmac_vap_stru *hmac_vap = HI_NULL;

    if (mac_vap->vap_state == MAC_VAP_STATE_BUTT) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_sta_update_rates::the vap has been deleted.}");

        return HI_FAIL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_sta_update_rates::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (cfg_mode->protocol >= WLAN_HT_MODE) {
        hmac_vap->tx_aggr_on = HI_TRUE;
    } else {
        hmac_vap->tx_aggr_on = HI_FALSE;
    }

    mac_vap_init_by_protocol(mac_vap, cfg_mode->protocol);
    mac_vap->channel.band = cfg_mode->band;
    mac_vap->channel.en_bandwidth = cfg_mode->en_bandwidth;
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_start_vap_event(mac_vap, HI_FALSE);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_sta_update_rates::hmac_config_send_event failed[%d].}", ret);
        mac_vap_init_by_protocol(mac_vap, hmac_vap->preset_para.protocol);
        mac_vap->channel.band = hmac_vap->preset_para.band;
        mac_vap->channel.en_bandwidth = hmac_vap->preset_para.en_bandwidth;
        return ret;
    }

    return HI_SUCCESS;
}

hi_u32 hmac_config_del_user(mac_vap_stru *mac_vap, const hmac_vap_stru *hmac_vap)
{
    hi_list *user_list_head = &(mac_vap->mac_user_list_head);

    for (hi_list *entry = user_list_head->next; entry != user_list_head;) {
        mac_user_stru  *user_tmp  = hi_list_entry(entry, mac_user_stru, user_dlist);
        hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru((hi_u8)user_tmp->us_assoc_id);
        if (hmac_user == HI_NULL) {
            continue;
        }

        /* ָ��˫��������һ�� */
        entry = entry->next;

        /* ����֡�����Ƿ��� */
        hi_u8 is_protected = user_tmp->cap_info.pmf_active;
#ifdef _PRE_WLAN_FEATURE_MESH
        if (user_tmp->is_mesh_user == HI_TRUE) {
            hmac_handle_close_peer_mesh(hmac_vap, hmac_user->base_user->user_mac_addr, WLAN_MAC_ADDR_LEN,
                HMAC_REPORT_DISASSOC, MAC_DISAS_LV_SS);
            /* ɾ���û� (��������ɾ��) */
            hmac_user_del(mac_vap, hmac_user);
        } else {
#endif
            /* ��ȥ����֡ */
            hmac_mgmt_send_disassoc_frame(mac_vap, user_tmp->user_mac_addr, MAC_DISAS_LV_SS, is_protected);

            /* ɾ���û��¼��ϱ����ϲ� */
            if (is_ap(mac_vap)) {
                hmac_handle_disconnect_rsp_ap(hmac_vap, hmac_user);
            } else if (is_sta(mac_vap)) {
                hmac_sta_disassoc_rsp(hmac_vap, MAC_DISAS_LV_SS, DMAC_DISASOC_MISC_KICKUSER);
            }

            /* ɾ���û� */
            hmac_user_del(mac_vap, hmac_user);
#ifdef _PRE_WLAN_FEATURE_MESH
        }
#endif
    }

    /* VAP��user����Ӧ��Ϊ�� */
    if (hi_is_list_empty_optimize(&mac_vap->mac_user_list_head) == HI_FALSE) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_down_vap::st_mac_user_list_head is not empty.}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ͣ��vap
 �������  : pst_mac_vap : ָ��vap
             us_len      : ��������
             puc_param   : ����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2013��5��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_down_vap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *param)
{
    if (oal_unlikely((mac_vap == HI_NULL) || (param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_down_vap:vap=%p param=%p}", (uintptr_t)mac_vap, (uintptr_t)param);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_cfg_down_vap_param_stru *param_tmp = (mac_cfg_down_vap_param_stru *)param;

    /* ���vap�Ѿ���down��״̬��ֱ�ӷ��� */
    if (mac_vap->vap_state == MAC_VAP_STATE_INIT) {
        /* DTS2015120107074 �ж�VAP�Ƿ�down��wal��ͨ�������豸down/up���ж�,
           hmac��ͨ��INIT״̬�ж�,����״̬Ӧ�ñ���һ�� */
        /* ����net_device��flags��־ */
        if ((param_tmp->net_dev != HI_NULL) && (oal_netdevice_flags(param_tmp->net_dev) & OAL_IFF_RUNNING)) {
            oal_netdevice_flags(param_tmp->net_dev) &= (~OAL_IFF_RUNNING);
        }

        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_down_vap::vap already down.}");
        return HI_SUCCESS;
    }

    mac_device_stru *mac_dev    = mac_res_get_dev();
    hmac_vap_stru   *hmac_vap   = hmac_vap_get_vap_stru(mac_vap->vap_id);
    mac_user_stru   *multi_user = mac_user_get_user_stru(mac_vap->multi_user_idx);
    if ((hmac_vap == HI_NULL) || (multi_user == HI_NULL)) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_down_vap::hmac_vap[%p]/multi_user[%p] null}", (uintptr_t)hmac_vap, (uintptr_t)multi_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����net_device��flags��־ */
    if (param_tmp->net_dev != HI_NULL) {
        oal_netdevice_flags(param_tmp->net_dev) &= (~OAL_IFF_RUNNING);
    }

    /* ����vap�������û�, ɾ���û� */
    if (hmac_config_del_user(mac_vap, hmac_vap) != HI_SUCCESS) {
        return HI_FAIL;
    }

    /* ��ʼ���鲥�û��İ�ȫ��Ϣ */
    mac_user_init_key(multi_user);
    multi_user->user_tx_info.security.cipher_key_type = WLAN_KEY_TYPE_TX_GTK;

    /* staģʽʱ ��desired ssid MIB���ÿ� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        if (memset_s(mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid, WLAN_SSID_MAX_LEN, 0,
                     WLAN_SSID_MAX_LEN) != EOK) {
            return HI_FAIL;
        }
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) { /* AP down״̬��ҪͶsleepƱ */
        wlan_pm_remove_vote(HI_PM_ID_AP);
    }

    /***************************************************************************
                         ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DOWN_VAP, us_len, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_down_vap::hmac_config_send_event Err[%d].}", ret);
        return ret;
    }

    mac_vap_state_enum_uint8 vap_state = MAC_VAP_STATE_INIT;
#ifdef _PRE_WLAN_FEATURE_P2P
    vap_state = (param_tmp->p2p_mode == WLAN_P2P_CL_MODE) ? MAC_VAP_STATE_STA_SCAN_COMP : vap_state;
#endif
    mac_vap_state_change(mac_vap, vap_state);

    hmac_vap->auth_mode = WLAN_WITP_AUTH_OPEN_SYSTEM;
    hmac_set_rx_filter_value(mac_vap);

    oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_down_vap::SUCC!Now remaining%d vap}", mac_dev->vap_num);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡģʽ ����Э�� Ƶ�� ����
 �������  : pst_mac_vap: ָ��vap��ָ��
 �������  : pus_len    : ��������
             puc_param  : ����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2012��12��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_mode(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    mac_cfg_mode_param_stru *prot_param = HI_NULL;

    prot_param = (mac_cfg_mode_param_stru *)puc_param;

    prot_param->protocol = mac_vap->protocol;
    prot_param->band = mac_vap->channel.band;
    prot_param->en_bandwidth = mac_vap->channel.en_bandwidth;

    *pus_len = sizeof(mac_cfg_mode_param_stru);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����modeʱ��Э�� Ƶ�� ����������
 �������  : pst_mac_device: device�ṹ��
             pst_prot_param: pst_prot_param���������·��Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��7��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_device_check_param(const mac_device_stru *mac_dev,
                                             wlan_protocol_enum_uint8 protocol)
{
    switch (protocol) {
        case WLAN_LEGACY_11A_MODE:
        case WLAN_LEGACY_11B_MODE:
        case WLAN_LEGACY_11G_MODE:
        case WLAN_MIXED_ONE_11G_MODE:
        case WLAN_MIXED_TWO_11G_MODE:
            break;

        case WLAN_HT_MODE:
        case WLAN_HT_ONLY_MODE:
        case WLAN_HT_11G_MODE:
            if (mac_dev->protocol_cap < WLAN_PROTOCOL_CAP_HT) {
                /* ����11nЭ�飬��device��֧��HTģʽ */
                oam_warning_log2(0, OAM_SF_CFG,
                    "{hmac_config_device_check_param::not support HT mode,en_protocol=%d en_protocol_cap=%d.}",
                    protocol, mac_dev->protocol_cap);
                return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
            }
            break;

        case WLAN_VHT_MODE:
        case WLAN_VHT_ONLY_MODE:
            if (mac_dev->protocol_cap < WLAN_PROTOCOL_CAP_VHT) {
                /* ����11acЭ�飬��device��֧��VHTģʽ */
                oam_warning_log2(0, OAM_SF_CFG,
                    "{hmac_config_device_check_param::not support VHT mode,en_protocol=%d en_protocol_cap=%d.}",
                    protocol, mac_dev->protocol_cap);
                return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
            }
            break;

        default:
            oam_warning_log0(0, OAM_SF_CFG, "{hmac_config_device_check_param::mode param does not in the list.}");
            break;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����modeʱ��Э�� Ƶ�� ����������
 �������  : pst_mac_device: device�ṹ��
             pst_prot_param: pst_prot_param���������·��Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��7��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_check_mode_param(const mac_device_stru *mac_dev,
                                           const mac_cfg_mode_param_stru *prot_param)
{
    /* ����device�����Բ������м�� */
    hi_u32 ret = hmac_config_device_check_param(mac_dev, prot_param->protocol);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_check_mode_param::check_param Err=%d}", ret);
        return ret;
    }

    if ((prot_param->en_bandwidth > WLAN_BAND_WIDTH_40MINUS)
        && (mac_dev->bandwidth_cap < WLAN_BW_CAP_80M)) {
        /* ����80M������device������֧��80M�����ش����� */
        oam_warning_log2(0, OAM_SF_CFG,
            "{hmac_config_check_mode_param::not support 80MHz bandwidth,en_protocol=%d en_protocol_cap=%d.}",
            prot_param->en_bandwidth, mac_dev->bandwidth_cap);
        return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
    }

    if ((WLAN_BAND_2G != prot_param->band) || (WLAN_BAND_CAP_2G != mac_dev->band_cap)) {
        /* ����2GƵ������device��֧��2G */
        oam_warning_log2(0, OAM_SF_CFG,
                         "{hmac_config_check_mode_param::not support 5GHz band,en_protocol=%d en_protocol_cap=%d.}",
                         prot_param->band, mac_dev->band_cap);
        return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���״����ô���ʱ���������ô����������ô������
 �������  : en_bw_device: �״����õĴ���
             en_bw_config: ���������������õĴ���
 �޸���ʷ      :
  1.��    ��   : 2013��11��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_set_mode_check_bandwith(wlan_channel_bandwidth_enum_uint8 bw_device,
                                                  wlan_channel_bandwidth_enum_uint8 bw_config)
{
    /* Ҫ���ô�����20M */
    if (WLAN_BAND_WIDTH_20M == bw_config) {
        return HI_SUCCESS;
    }

    /* Ҫ���ô������״����ô�����ͬ */
    if (bw_device == bw_config) {
        return HI_SUCCESS;
    }

    switch (bw_device) {
        case WLAN_BAND_WIDTH_80PLUSPLUS:
        case WLAN_BAND_WIDTH_80PLUSMINUS:
            if (WLAN_BAND_WIDTH_40PLUS == bw_config) {
                return HI_SUCCESS;
            }
            break;

        case WLAN_BAND_WIDTH_80MINUSPLUS:
        case WLAN_BAND_WIDTH_80MINUSMINUS:
            if (WLAN_BAND_WIDTH_40MINUS == bw_config) {
                return HI_SUCCESS;
            }
            break;

        default:
            break;
    }

    return HI_FAIL;
}

hi_u32 hmac_config_mac_vap_dev(mac_vap_stru *mac_vap, mac_device_stru *mac_dev,
    const mac_cfg_mode_param_stru *prot_param)
{
    /* ����Э�����vap���� */
    mac_vap_init_by_protocol(mac_vap, prot_param->protocol);
    mac_vap_init_rates(mac_vap);

    /* ���ݴ�����Ϣ����Mib */
    mac_vap_change_mib_by_bandwidth(mac_vap, prot_param->en_bandwidth);

    /* ����device��Ƶ�μ���������Ϣ */
    if (mac_dev->max_bandwidth == WLAN_BAND_WIDTH_BUTT) {
        mac_dev->max_bandwidth = prot_param->en_bandwidth;
        mac_dev->max_band      = prot_param->band;
    }

    /***************************************************************************
     ���¼���DMAC��, ���üĴ���
    ***************************************************************************/
    hi_u32 ret = hmac_set_mode_event(mac_vap);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_mode::hmac_config_send_event failed[%d]}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����ģʽ ����Э�� Ƶ�� ����
 �������  : pst_mac_vap: ָ��VAP��ָ��
             us_len     : ��������
             puc_param  : ����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2012��12��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �������ģ�hmac��������Ӧ����
                           1������У�鲢����hmac vap�µ���Ϣ
                           2������mac vap�µ���Ϣ��mib��Ϣ
                           3������mac device�µ���Ϣ
                           4���������¼���dmac
*****************************************************************************/
hi_u32 hmac_config_set_mode(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(us_len);

    /* ��ȡdevice ,����ģʽʱ��device�±���������һ��vap */
    mac_device_stru *mac_dev = mac_res_get_dev();
    if (mac_dev->vap_num == 0) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_mode::no vap in device.}");
        return HI_ERR_CODE_MAC_DEVICE_NULL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_mode::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ������ò����Ƿ���device������ */
    mac_cfg_mode_param_stru *prot_param = (mac_cfg_mode_param_stru *)puc_param;
    hi_u32 ret = hmac_config_check_mode_param(mac_dev, prot_param);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* device�Ѿ�����ʱ����ҪУ����Ƶ�Ρ������Ƿ�һ�� */
    if ((mac_dev->max_bandwidth != WLAN_BAND_WIDTH_BUTT) && (!mac_dev->dbac_enabled)) {
        if (mac_dev->max_band != prot_param->band) {
            oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_mode::previous vapBand=%d,mismatchWith=%d}",
                mac_dev->max_band,  prot_param->band);
            return HI_FAIL;
        }

        ret = hmac_config_set_mode_check_bandwith(mac_dev->max_bandwidth, prot_param->en_bandwidth);
        if (ret != HI_SUCCESS) {
            oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG,
                "{hmac_config_set_mode::config_set_mode_check_bandwith Err=%d,previous vap bandwidth[%d,current=%d]}",
                ret, mac_dev->max_bandwidth, prot_param->en_bandwidth);
            return ret;
        }
    }

    hmac_vap->tx_aggr_on = (prot_param->protocol >= WLAN_HT_MODE) ? HI_TRUE : HI_FALSE;

    wlan_channel_bandwidth_enum_uint8 cur_bw = mac_vap->channel.en_bandwidth;
    /* ����STAЭ�����ñ�־λ */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        hmac_vap->preset_para.protocol = prot_param->protocol;
        if ((cur_bw != WLAN_BAND_WIDTH_5M) && (cur_bw != WLAN_BAND_WIDTH_10M)) {
            hmac_vap->preset_para.en_bandwidth = prot_param->en_bandwidth;
        }
        hmac_vap->preset_para.band = prot_param->band;
    }

    /* ��¼Э��ģʽ, band, bandwidth��mac_vap�� */
    mac_vap->protocol     = prot_param->protocol;
    mac_vap->channel.band = prot_param->band;

    mac_vap->channel.en_bandwidth = ((cur_bw != WLAN_BAND_WIDTH_5M) && (cur_bw != WLAN_BAND_WIDTH_10M)) ?
        prot_param->en_bandwidth : cur_bw;

    oam_info_log3(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_mode::protocol=%d, band=%d, bandwidth=%d.}",
                  mac_vap->protocol, mac_vap->channel.band, mac_vap->channel.en_bandwidth);

    ret = hmac_config_mac_vap_dev(mac_vap, mac_dev, prot_param);
    return ret;
}

/*****************************************************************************
 ��������  : ����stationIDֵ����MAC��ַ
 �������  : event_hdr:�¼�ͷ
             pst_param    :����
 �� �� ֵ  : HI_SUCCESS ������������
 �޸���ʷ      :
  1.��    ��   : 2012��12��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_mac_addr(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
#ifdef _PRE_WLAN_FEATURE_P2P
    mac_cfg_staion_id_param_stru *station_id_param = HI_NULL;
    wlan_p2p_mode_enum_uint8 p2p_mode;
#endif
    hi_u32 ret;

#ifdef _PRE_WLAN_FEATURE_P2P
    /* P2P ����MAC ��ַmib ֵ��Ҫ����P2P DEV ��P2P_CL/P2P_GO,P2P_DEV MAC ��ַ���õ�p2p0 MIB �� */
    station_id_param = (mac_cfg_staion_id_param_stru *)puc_param;
    p2p_mode = station_id_param->p2p_mode;
    if (p2p_mode == WLAN_P2P_DEV_MODE) {
        /* �����p2p0 device��������MAC ��ַ��auc_p2p0_dot11StationID ��Ա�� */
        if (memcpy_s(mac_vap->mib_info->wlan_mib_sta_config.auc_p2p0_dot11_station_id, WLAN_MAC_ADDR_LEN,
                     station_id_param->auc_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{hmac_config_set_mac_addr::memcpy_s fail.}");
            return HI_FAIL;
        }
    } else {
        /* ����mibֵ, Station_ID */
        mac_mib_set_station_id(mac_vap, (hi_u8) us_len, puc_param);
    }
#else
    /* ����mibֵ, Station_ID */
    mac_mib_set_station_id(mac_vap, (hi_u8) us_len, puc_param);
#endif

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_STATION_ID, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_mac_addr::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : hmac��SSID
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_ssid(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    /* ��ȡmibֵ */
    return mac_mib_get_ssid(mac_vap, (hi_u8 *)pus_len, puc_param);
}

/*****************************************************************************
 ��������  : hmac��SSID
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_ssid(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ����mibֵ */
    mac_mib_set_ssid(mac_vap, (hi_u8) us_len, puc_param);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    return hmac_config_send_event(mac_vap, WLAN_CFGID_SSID, us_len, puc_param);
#else
    return HI_SUCCESS;
#endif
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ���ö�ǰ��������λ
 �޸���ʷ      :
  1.��    ��   : 2013��1��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_shpreamble(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ����mibֵ */
    mac_mib_set_shpreamble(mac_vap, (hi_u8) us_len, puc_param);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SHORT_PREAMBLE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_shpreamble::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
#else
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ��ǰ��������λ
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_shpreamble(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    /* ��mibֵ */
    return mac_mib_get_shpreamble(mac_vap, (hi_u8 *)pus_len, puc_param);
}
#endif

/*****************************************************************************
 ��������  : 20M short gi��������
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_shortgi20(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_s32 l_value;
    hi_unref_param(us_len);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    shortgi_cfg_stru shortgi_cfg;

    shortgi_cfg.type = SHORTGI_20_CFG_ENUM;
#endif
    l_value = *((hi_s32 *)puc_param);

    if (l_value != 0) {
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        shortgi_cfg.enable = HI_TRUE;
#endif
        mac_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented = HI_TRUE;
    } else {
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        shortgi_cfg.enable = HI_FALSE;
#endif
        mac_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented = HI_FALSE;
    }

    /* hi1131-cb : Need to send to Dmac via sdio */
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* �����¼������¼� WLAN_CFGID_SHORTGI ͨ���¼ӵĽӿں���ȡ���ؼ����ݴ���skb��ͨ��sdio���� */
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SHORTGI, SHORTGI_CFG_STRU_LEN, (hi_u8 *)&shortgi_cfg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_set_shortgi20::hmac_config_send_event failed[%u].}", ret);
    }
    return ret;
#else
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ��ȡ20M short gi
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_shortgi20(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    hi_s32 l_value;

    l_value = mac_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented;

    *((hi_s32 *)puc_param) = l_value;

    *pus_len = sizeof(l_value);

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ���ñ���ģʽ
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_prot_mode(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_s32 l_value;

    l_value = *((hi_s32 *)puc_param);
    if (oal_unlikely(l_value >= WLAN_PROT_BUTT)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_prot_mode::invalid value[%d].}",
                         l_value);
        return HI_ERR_CODE_INVALID_CONFIG;
    }
    mac_vap->protection.protection_mode = (hi_u8) l_value;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_PROT_MODE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_prot_mode::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
#else
    hi_unref_param(us_len);
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ��ȡ����ģʽ
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_prot_mode(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    *((hi_s32 *)puc_param) = mac_vap->protection.protection_mode;
    *pus_len = sizeof(hi_s32);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ������֤ģʽ
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_auth_mode(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 value;
    hmac_vap_stru *hmac_vap = HI_NULL;

    hi_unref_param(us_len);

    value = *((hi_u32 *)puc_param);
    /* Ĭ��OPEN */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_auth_mode::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap->auth_mode = WLAN_WITP_AUTH_OPEN_SYSTEM;
    if (value & BIT1) {
        hmac_vap->auth_mode = WLAN_WITP_AUTH_SHARED_KEY;
    }
    /* ֧��OPEN��SHARE KEY */
    if ((value & BIT0) && (value & BIT1)) {
        hmac_vap->auth_mode = WLAN_WITP_ALG_AUTH_BUTT;
    }

    oam_info_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_auth_mode::set auth mode[%d] succ.}",
                  hmac_vap->auth_mode);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ��֤ģʽ
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_auth_mode(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_get_auth_mode::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    *((hi_s32 *)puc_param) = hmac_vap->auth_mode;
    *pus_len = sizeof(hi_s32);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����beacon interval
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_bintval(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    mac_device_stru *mac_dev = HI_NULL;
    hi_u8 vap_idx;
    mac_vap_stru *mac_vap_tmp = HI_NULL;

    mac_dev = mac_res_get_dev();
    /* ����device�µ�ֵ */
    mac_dev->beacon_interval  = *((hi_u32 *)puc_param);
    /* ����device������vap */
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap_tmp = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap_tmp == HI_NULL) {
            oam_error_log1(mac_vap_tmp->vap_id, OAM_SF_SCAN, "{hmac_config_set_bintval::pst_mac_vap(%d) null.}",
                           mac_dev->auc_vap_id[vap_idx]);
            continue;
        }

        /* ֻ��AP VAP��Ҫbeacon interval */
        if ((mac_vap_tmp->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
            || (mac_vap_tmp->vap_mode == WLAN_VAP_MODE_MESH)
#endif
            ) {
            /* ����mibֵ */
            mac_mib_set_beacon_period(mac_vap_tmp, (hi_u8) us_len, puc_param);
        }
    }

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_BEACON_INTERVAL, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_bintval::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��ȡbeacon interval
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_bintval(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    /* ��ȡmibֵ */
    return mac_mib_get_beacon_period(mac_vap, (hi_u8 *)pus_len, puc_param);
}

/*****************************************************************************
 ��������  : ����dtim period
 �޸���ʷ      :
  1.��    ��   : 2013��9��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_dtimperiod(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ����mibֵ */
    mac_mib_set_dtim_period(mac_vap, (hi_u8) us_len, puc_param);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DTIM_PERIOD, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_bintval::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
#else
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ��ȡdtim period
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��9��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_dtimperiod(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    /* ��ȡmibֵ */
    return mac_mib_get_dtim_period(mac_vap, (hi_u8 *)pus_len, puc_param);
}
#endif

/*****************************************************************************
 ��������  : ���÷��͹���
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_txpower(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_s32 l_value;
    hi_u32 ret;

    l_value = *((hi_s32 *)puc_param);

    mac_vap_set_tx_power(mac_vap, (hi_u8) l_value);

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_TX_POWER, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_txpower::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��ȡ���͹���
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_txpower(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    *((hi_s32 *)puc_param) = mac_vap->tx_power;
    *pus_len = sizeof(hi_s32);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����Ƶ��
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_freq(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *channel)
{
    mac_cfg_channel_param_stru  l_channel_param;
    mac_device_stru            *mac_dev = mac_res_get_dev();

    hi_u32 ret = mac_is_channel_num_valid(mac_vap->channel.band, (*channel));
    if (ret != HI_SUCCESS) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::channel=%d,Err=%d}", (*channel), ret);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

#ifdef _PRE_WLAN_FEATURE_11D
    /* �ŵ�14���⴦��ֻ��11bЭ��ģʽ����Ч */
    if (((*channel) == 14) && (mac_vap->protocol != WLAN_LEGACY_11B_MODE)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::protocol=%d}", mac_vap->protocol);
        return HI_ERR_CODE_INVALID_CONFIG;
    }
#endif

    mac_vap->channel.chan_number = (*channel);
    ret = mac_get_channel_idx_from_num(mac_vap->channel.band, (*channel), &(mac_vap->channel.idx));
    if (ret != HI_SUCCESS) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::get Channel Err.band=%u,channel=%u}",
                         mac_vap->channel.band, mac_vap->channel.idx);
        return ret;
    }

    /* ��DBACʱ���״������ŵ�ʱ���õ�Ӳ�� */
    if ((mac_dev->vap_num == 1) || (mac_dev->max_channel == 0)) {
        mac_device_get_channel(mac_dev, &l_channel_param);
        l_channel_param.channel = (*channel);
        mac_device_set_channel(mac_dev, &l_channel_param);

        /***************************************************************************
            ���¼���DMAC��, ͬ��DMAC����
        ***************************************************************************/
        ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CURRENT_CHANEL, us_len, channel);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::hmac_config_send_event Err=%d}", ret);
            return ret;
        }
#ifdef _PRE_WLAN_FEATURE_DBAC
    } else if (mac_dev->dbac_enabled) {
        /***************************************************************************
            ���¼���DMAC��, ͬ��DMAC����
        ***************************************************************************/
        ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CURRENT_CHANEL, us_len, channel);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::hmac_config_send_event Err=%d}", ret);
            return ret;
        }

        oam_info_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::do not check channel while DBAC enabled.}");
#endif
    } else if (mac_dev->max_channel != (*channel)) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_freq::previous vap channel=%d,mismatch=%d}",
                         mac_dev->max_channel, (*channel));

        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡƵ��
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_freq(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    *((hi_u32 *)puc_param) = mac_vap->channel.chan_number;

    *pus_len = sizeof(hi_u32);

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ����WMM����
 �������  : event_hdr: �¼�ͷ
             us_len       : ��������
             puc_param    : ����
 �޸���ʷ      :
  1.��    ��   : 2013��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������: �����ھۣ��ұ������ĺ�û�д�, �������� */
hi_u32 hmac_config_set_wmm_params(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret      = HI_SUCCESS;
    hi_u8  syn_flag;        /* Ĭ�ϲ���Ҫͬ����dmac */

    syn_flag = HI_FALSE;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* offloadģʽ�¾���Ҫͬ����dmac */
    syn_flag = HI_TRUE;
#endif

    hmac_config_wmm_para_stru *cfg_stru = (hmac_config_wmm_para_stru *)puc_param;

    hi_u32 ac    = cfg_stru->ac;
    hi_u32 value = cfg_stru->value;
    wlan_cfgid_enum_uint16 cfg_id = (hi_u16)cfg_stru->cfg_id;

    if (ac >= WLAN_WME_AC_BUTT) {
        oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_set_wmm_params::invalid param,en_cfg_id=%d, ul_ac=%d, ul_value=%d.}", cfg_id, ac, value);
        return HI_FAIL;
    }

    /* ����sub-ioctl id��дWID */
    switch (cfg_id) {
        case WLAN_CFGID_EDCA_TABLE_CWMIN:
            if ((value > WLAN_QEDCA_TABLE_CWMIN_MAX) || (value < WLAN_QEDCA_TABLE_CWMIN_MIN)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_c_wmin = value;
            break;
        case WLAN_CFGID_EDCA_TABLE_CWMAX:
            if ((value > WLAN_QEDCA_TABLE_CWMAX_MAX) || (value < WLAN_QEDCA_TABLE_CWMAX_MIN)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_c_wmax = value;
            break;
        case WLAN_CFGID_EDCA_TABLE_AIFSN:
            if ((value < WLAN_QEDCA_TABLE_AIFSN_MIN) || (value > WLAN_QEDCA_TABLE_AIFSN_MAX)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_aifsn = value;
            break;
        case WLAN_CFGID_EDCA_TABLE_TXOP_LIMIT:
            if (value > WLAN_QEDCA_TABLE_TXOP_LIMIT_MAX) {
                return HI_FAIL;
            }
            mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_txop_limit = value;
            break;
        case WLAN_CFGID_EDCA_TABLE_MSDU_LIFETIME:
            if (value > WLAN_QEDCA_TABLE_MSDU_LIFETIME_MAX) {
                return HI_FAIL;
            }
            mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_msdu_lifetime = value;
            break;
        case WLAN_CFGID_EDCA_TABLE_MANDATORY:
            if ((value != HI_TRUE) && (value != HI_FALSE)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_mandatory = (hi_u8) value;
            break;
        case WLAN_CFGID_QEDCA_TABLE_CWMIN:
            if ((value > WLAN_QEDCA_TABLE_CWMIN_MAX) || (value < WLAN_QEDCA_TABLE_CWMIN_MIN)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->wlan_mib_qap_edac[ac].dot11_qapedca_table_c_wmin = value;
            syn_flag = HI_TRUE;
            break;
        case WLAN_CFGID_QEDCA_TABLE_CWMAX:
            if ((value > WLAN_QEDCA_TABLE_CWMAX_MAX) || (value < WLAN_QEDCA_TABLE_CWMAX_MIN)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->wlan_mib_qap_edac[ac].dot11_qapedca_table_c_wmax = value;
            syn_flag = HI_TRUE;
            break;
        case WLAN_CFGID_QEDCA_TABLE_AIFSN:
            if ((value < WLAN_QEDCA_TABLE_AIFSN_MIN) || (value > WLAN_QEDCA_TABLE_AIFSN_MAX)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->wlan_mib_qap_edac[ac].dot11_qapedca_table_aifsn = value;
            syn_flag = HI_TRUE;
            break;
        case WLAN_CFGID_QEDCA_TABLE_TXOP_LIMIT:
            if (value > WLAN_QEDCA_TABLE_TXOP_LIMIT_MAX) {
                return HI_FAIL;
            }
            mac_vap->mib_info->wlan_mib_qap_edac[ac].dot11_qapedca_table_txop_limit = value;
            syn_flag = HI_TRUE;
            break;
        case WLAN_CFGID_QEDCA_TABLE_MSDU_LIFETIME:
            if (value > WLAN_QEDCA_TABLE_MSDU_LIFETIME_MAX) {
                return HI_FAIL;
            }
            mac_vap->mib_info->wlan_mib_qap_edac[ac].dot11_qapedca_table_msdu_lifetime = value;
            syn_flag = HI_TRUE;
            break;
        case WLAN_CFGID_QEDCA_TABLE_MANDATORY:
            /* offloadģʽ�� ����Ҫͬ����dmac */
            if ((value != HI_TRUE) && (value != HI_FALSE)) {
                return HI_FAIL;
            }
            mac_vap->mib_info->wlan_mib_qap_edac[ac].dot11_qapedca_table_mandatory = (hi_u8) value;
            break;
        default:
            return HI_FAIL;
    }

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    if (syn_flag) {
        ret = hmac_config_send_event(mac_vap, cfg_id, us_len, puc_param);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_wmm_params::send_event failed[%d].}", ret);
        }
    }
    return ret;
}

/*****************************************************************************
 ��������  : ��ȡEDCA����
 �������  : event_hdr: �¼�ͷ
 �������  : pus_len      : ��������
             puc_param    : ����
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_wmm_params(mac_vap_stru *mac_vap, hi_u16 *us_len, hi_u8 *puc_param)
{
    hmac_config_wmm_para_stru *cfg_stru = (hmac_config_wmm_para_stru *)puc_param;
    hi_u32                     value    = 0xFFFFFFFF;

    *us_len = sizeof(hmac_config_wmm_para_stru);

    if (cfg_stru->ac >= WLAN_WME_AC_BUTT) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_get_wmm_params::cfg_id=%d,ac=%d}", cfg_stru->cfg_id, cfg_stru->ac);
        return HI_FALSE;
    }

    /* ����sub-ioctl id��дWID */
    if (cfg_stru->cfg_id == WLAN_CFGID_EDCA_TABLE_CWMIN) {
        value = mac_vap->mib_info->ast_wlan_mib_edca[cfg_stru->ac].dot11_edca_table_c_wmin;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_EDCA_TABLE_CWMAX) {
        value = mac_vap->mib_info->ast_wlan_mib_edca[cfg_stru->ac].dot11_edca_table_c_wmax;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_EDCA_TABLE_AIFSN) {
        value = mac_vap->mib_info->ast_wlan_mib_edca[cfg_stru->ac].dot11_edca_table_aifsn;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_EDCA_TABLE_TXOP_LIMIT) {
        value = mac_vap->mib_info->ast_wlan_mib_edca[cfg_stru->ac].dot11_edca_table_txop_limit;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_EDCA_TABLE_MSDU_LIFETIME) {
        value = mac_vap->mib_info->ast_wlan_mib_edca[cfg_stru->ac].dot11_edca_table_msdu_lifetime;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_EDCA_TABLE_MANDATORY) {
        value = mac_vap->mib_info->ast_wlan_mib_edca[cfg_stru->ac].dot11_edca_table_mandatory;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_QEDCA_TABLE_CWMIN) {
        value = mac_vap->mib_info->wlan_mib_qap_edac[cfg_stru->ac].dot11_qapedca_table_c_wmin;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_QEDCA_TABLE_CWMAX) {
        value = mac_vap->mib_info->wlan_mib_qap_edac[cfg_stru->ac].dot11_qapedca_table_c_wmax;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_QEDCA_TABLE_AIFSN) {
        value = mac_vap->mib_info->wlan_mib_qap_edac[cfg_stru->ac].dot11_qapedca_table_aifsn;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_QEDCA_TABLE_TXOP_LIMIT) {
        value = mac_vap->mib_info->wlan_mib_qap_edac[cfg_stru->ac].dot11_qapedca_table_txop_limit;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_QEDCA_TABLE_MSDU_LIFETIME) {
        value = mac_vap->mib_info->wlan_mib_qap_edac[cfg_stru->ac].dot11_qapedca_table_msdu_lifetime;
    } else if (cfg_stru->cfg_id == WLAN_CFGID_QEDCA_TABLE_MANDATORY) {
        value = mac_vap->mib_info->wlan_mib_qap_edac[cfg_stru->ac].dot11_qapedca_table_mandatory;
    }

    cfg_stru->value = value;
    return HI_SUCCESS;
}
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
hi_u32 hmac_config_set_reset_state(mac_vap_stru *mac_vap, hi_u16 us_len, hi_u8 *puc_param)
{
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_config_set_reset_state::pst_mac_vap[%p] NULL or pst_puc_param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }
    hi_unref_param(mac_vap);
    hi_unref_param(us_len);
    hi_u32 ret = HI_SUCCESS;
    mac_reset_sys_stru *reset_sys = HI_NULL;
    mac_device_stru *mac_dev = HI_NULL;

    reset_sys = (mac_reset_sys_stru *)puc_param;
    mac_dev = mac_res_get_dev();
    mac_dev->reset_in_progress = reset_sys->value;
    return ret;
}
#endif

/*****************************************************************************
 ��������  : ����Channnelʱ��Э�� Ƶ�� ����������
 �������  : pst_mac_device: device�ṹ��
             pst_prot_param: pst_prot_param���������·��Ĳ���
 ��������  :hmac_config_set_channel
 �޸���ʷ      :
  1.��    ��   : 2014��8��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_set_channel_check_param(const mac_device_stru *mac_dev,
                                                  const mac_cfg_channel_param_stru *prot_param)
{
    /* ����device�����Բ������м�� */
    if ((prot_param->en_bandwidth > WLAN_BAND_WIDTH_40MINUS)
        && (mac_dev->bandwidth_cap < WLAN_BW_CAP_80M)) {
        /* ����80M������device������֧��80M�����ش����� */
        oam_warning_log2(0, OAM_SF_CFG,
            "{hmac_config_set_channel_check_param::not support 80MHz bandwidth,en_protocol=%d en_protocol_cap=%d.}",
            prot_param->en_bandwidth, mac_dev->bandwidth_cap);
        return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
    }

    if ((WLAN_BAND_2G != prot_param->band) || (WLAN_BAND_CAP_2G != mac_dev->band_cap)) {
        oam_warning_log2(0, OAM_SF_CFG,
            "{hmac_config_set_channel_check_param::not support 5GHz band,en_protocol=%d en_protocol_cap=%d.}",
            prot_param->band, mac_dev->band_cap);
        return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
    }
    return HI_SUCCESS;
}

hi_u32 hmac_config_vap_set_channel(mac_vap_stru *mac_vap, const mac_cfg_channel_param_stru *channel_param,
    const mac_device_stru *mac_dev, hi_u8 *set_reg)
{
    hi_u32 ret;

#ifdef _PRE_WLAN_FEATURE_DBAC
    if (mac_dev->dbac_enabled) {
        mac_vap->channel.chan_number  = channel_param->channel;
        mac_vap->channel.band         = channel_param->band;
        mac_vap->channel.en_bandwidth = channel_param->en_bandwidth;
        ret = mac_get_channel_idx_from_num(channel_param->band, channel_param->channel, &(mac_vap->channel.idx));
        if (ret != HI_SUCCESS) {
            oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_channel:get chl Err=%d,band=%d,channel=%d}",
                ret, channel_param->band, channel_param->channel);
            return HI_FAIL;
        }

        /* ���ݴ�����Ϣ����Mib */
        mac_vap_change_mib_by_bandwidth(mac_vap, channel_param->en_bandwidth);

        *set_reg = HI_TRUE;
    } else {
#endif /* _PRE_WLAN_FEATURE_DBAC */
        for (hi_u8 vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
            mac_vap_stru *mac_vap_tmp = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
            if (mac_vap_tmp == HI_NULL) {
                continue;
            }
            mac_vap_tmp->channel.chan_number  = channel_param->channel;
            mac_vap_tmp->channel.band         = channel_param->band;
            mac_vap_tmp->channel.en_bandwidth = channel_param->en_bandwidth;

            ret = mac_get_channel_idx_from_num(channel_param->band, channel_param->channel,
                                               &(mac_vap_tmp->channel.idx));
            if (ret != HI_SUCCESS) {
                oam_warning_log3(mac_vap_tmp->vap_id, OAM_SF_CFG, "{hmac_config_set_channel:Err=%d,band=%d,channel=%d}",
                    ret, channel_param->band, channel_param->channel);
                continue;
            }

            /* ���ݴ�����Ϣ����Mib */
            mac_vap_change_mib_by_bandwidth(mac_vap_tmp, channel_param->en_bandwidth);
        }
#ifdef _PRE_WLAN_FEATURE_DBAC
    }
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : HMAC �������ŵ���Ϣ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_channel(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 set_reg = HI_FALSE;
    mac_cfg_channel_param_stru *channel_param = (mac_cfg_channel_param_stru *)puc_param;
    mac_device_stru            *mac_dev       = mac_res_get_dev();

    /* ������ò����Ƿ���device������ */
    hi_u32 ret = hmac_config_set_channel_check_param(mac_dev, channel_param);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* ����û��VAP up������£�����Ӳ��Ƶ��������Ĵ��� */
    hi_u32 up_vap_cnt = hmac_calc_up_vap_num(mac_dev);
    if (up_vap_cnt <= 1) {
        /* ��¼�״����õĴ���ֵ */
        mac_device_set_channel(mac_dev, channel_param);

        /***************************************************************************
         ���¼���DMAC��, ���üĴ���  �ñ�־λ
        ***************************************************************************/
        set_reg = HI_TRUE;
#ifdef _PRE_WLAN_FEATURE_DBAC
    } else if (mac_dev->dbac_enabled) {
        /* ����DBAC�������ŵ��ж� */
        /* �ŵ�����ֻ���APģʽ����APģʽ������ */
#endif /* _PRE_WLAN_FEATURE_DBAC */
    } else {
        /* �ŵ����ǵ�ǰ�ŵ� */
        if (mac_dev->max_channel != channel_param->channel) {
            oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_channel::previous channel=%d mismatch[%d]}",
                             mac_dev->max_channel, channel_param->channel);

            return HI_FAIL;
        }

        /* �����ܳ��������õĴ��� */
        ret = hmac_config_set_mode_check_bandwith(mac_dev->max_bandwidth, channel_param->en_bandwidth);
        if (ret != HI_SUCCESS) {
            oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG,
                "{hmac_config_set_channel:hmac_config_set_mode_check_bandwith Err=%d,previous bandwidth=%d,current=%d}",
                ret, mac_dev->max_bandwidth, channel_param->en_bandwidth);
            return HI_FAIL;
        }
    }

    ret = hmac_config_vap_set_channel(mac_vap, channel_param, mac_dev, &set_reg);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /***************************************************************************
     ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    if (set_reg == HI_TRUE) {
        ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CFG80211_SET_CHANNEL, us_len, puc_param);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_channel::send_event failed[%d]}", ret);
            return ret;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����modeʱ��Э�� Ƶ�� ����������
 �������  : pst_mac_device: device�ṹ��
             pst_prot_param: pst_prot_param���������·��Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��6��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_config_set_beacon_check_param(const mac_device_stru *mac_dev,
                                                 const mac_beacon_param_stru *prot_param)
{
    /* ����device�����Բ������м�� */
    return hmac_config_device_check_param(mac_dev, prot_param->protocol);
}

/*****************************************************************************
 ��������  : HMAC ������AP ��Ϣ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_beacon(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ��ȡdevice */
    mac_device_stru *mac_dev = mac_res_get_dev();
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (puc_param == HI_NULL || hmac_vap == HI_NULL) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_config_set_beacon::puc_param/hmac_vap null! puc_param=%p, hmac_vap=%p.}",
                       (uintptr_t)puc_param, (uintptr_t)hmac_vap);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_beacon_param_stru *beacon_param = (mac_beacon_param_stru *)puc_param;

    /* ���Э�����ò����Ƿ���device������ */
    hi_u32 ret = hmac_config_set_beacon_check_param(mac_dev, beacon_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_beacon::hmac_config_add_beacon_check_param failed[%d].}", ret);
        return ret;
    }
    hmac_vap->tx_aggr_on = (beacon_param->protocol >= WLAN_HT_MODE) ? HI_TRUE : HI_FALSE;

    /* ����Э��ģʽ */
    if ((beacon_param->privacy == HI_TRUE) && (beacon_param->crypto_mode & (WLAN_WPA_BIT | WLAN_WPA2_BIT))) {
        hmac_vap->auth_mode = WLAN_WITP_AUTH_OPEN_SYSTEM;        /* ǿ������VAP ��֤��ʽΪOPEN */
    }
    mac_vap_set_hide_ssid(mac_vap, beacon_param->hidden_ssid);

    /* 1102�������ں�start ap��change beacon�ӿڸ��ô˽ӿڣ���ͬ����change beaconʱ����������beacon����
       ��dtim���ڣ���ˣ�change beaconʱ��interval��dtim period����Ϊȫ�㣬��ʱ��Ӧ�ñ����õ�mib�� */
    /* ����VAP beacon interval�� dtim_period */
    if ((beacon_param->l_dtim_period != 0) || (beacon_param->l_interval != 0)) {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_dtim_period =
            (hi_u32) beacon_param->l_dtim_period;
        mac_vap->mib_info->wlan_mib_sta_config.dot11_beacon_period =
            (hi_u32) beacon_param->l_interval;
    }

    /* ����short gi */
    mac_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented = beacon_param->shortgi_20;
    mac_mib_set_shortgi_option_in_forty_implemented(mac_vap, beacon_param->shortgi_40);

    if (beacon_param->operation_type == MAC_ADD_BEACON) {
        mac_vap_add_beacon(mac_vap, beacon_param);
    } else {
        mac_vap_set_beacon(mac_vap, beacon_param);
    }

    mac_vap_init_by_protocol(mac_vap, beacon_param->protocol);

    mac_vap_init_rates(mac_vap);

#ifdef _PRE_WLAN_FEATURE_MESH
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        mac_vap_set_mib_mesh(mac_vap, beacon_param->mesh_auth_protocol);
    }
#endif

    /***************************************************************************
     ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CFG80211_CONFIG_BEACON, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_beacon::hmac_config_send_event fail[%d]}", ret);
    }

    return ret;
}

#ifdef _PRE_WLAN_FEATURE_BTCOEX
hi_u32  hmac_config_set_btcoex_en(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32          ret;
    mac_device_stru *mac_dev = HI_NULL;

    /* BT���治֧�ֶ�VAP��APģʽ */
    mac_dev = mac_res_get_dev();
    if ((hmac_calc_up_vap_num(mac_dev) > 1) || hmac_find_is_ap_up(mac_dev)) {
        hi_diag_log_msg_w0(0, "hmac_config_set_btcoex_en:: there is a up ap, don't support btcoex.");
        return HI_FAIL;
    }
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_BTCOEX_ENABLE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        hi_diag_log_msg_w1(0, "{hmac_config_set_btcoex_en::send event return err code [%d].}", ret);
    }

    return ret;
}
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 �� �� ��  : hmac_config_report_vap_info
 ��������  : ����flagsλ�ϱ���Ӧ��vap��Ϣ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_report_vap_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_REPORT_VAP_INFO, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_report_vap_info::hmac_config_send_event fail[%d].", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
/*****************************************************************************
 ��������  : rekey offload��Ϣ�·������¼���DMAC
 �������  : mac_vap_stru *pst_mac_vap, hi_u16 us_len, hi_u8 *puc_param
 �������  : hi_u32
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 �޸���ʷ      :
  1.��    ��   : 2016��8��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_rekey_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_REKEY, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_WPA,
                         "{hmac_config_set_rekey_info::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}
#endif

#ifdef _PRE_WLAN_RF_110X_CALI_DPD
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 hmac_config_start_dpd(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
       ���¼���DMAC��, ͬ��DMAC����
     ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_START_DPD, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_start_dpd::hmac_config_send_event fail[%d].", ret);
    }

    return ret;
}
#endif

hi_u32 hmac_dpd_data_processed_send(mac_vap_stru *mac_vap, hi_void *param)
{
    if (oal_unlikely((mac_vap == HI_NULL) || (param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_CALIBRATE, "{hmac_dpd_data_processed_send::param null, %p %p.}", mac_vap, param);
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CALIBRATE, "{hmac_scan_proc_scan_req_event::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    oal_netbuf_stru *netbuf_dpd_data = oal_netbuf_alloc(WLAN_LARGE_NETBUF_SIZE, 0, 4); /* align 4 */
    if (netbuf_dpd_data == HI_NULL) {
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CALIBRATE, "{hmac_dpd_data_processed_send::pst_netbuf_scan_result null.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    frw_event_stru *event = (frw_event_stru *) event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_DPD_DATA_PROCESSED,
                       sizeof(dmac_tx_event_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    if (memset_s(oal_netbuf_cb(netbuf_dpd_data), OAL_TX_CB_LEN, 0, OAL_TX_CB_LEN) != EOK) {
        oal_netbuf_free(netbuf_dpd_data);
        frw_event_free(event_mem);
        return HI_FALSE;
    }

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *) oal_netbuf_cb(netbuf_dpd_data);
    tx_ctl->frame_header_length = 0;
    tx_ctl->mac_head_type = 1;
    tx_ctl->frame_header = HI_NULL;

    dpd_cali_data_stru *dpd_cali_data = (dpd_cali_data_stru *)(oal_netbuf_data(netbuf_dpd_data));
    if (memcpy_s(dpd_cali_data, sizeof(dpd_cali_data_stru), param, sizeof(dpd_cali_data_stru)) != EOK) {
        oal_netbuf_free(netbuf_dpd_data);
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CFG, "hmac_dpd_data_processed_send::p_param memcpy_s fail.");
        return HI_FALSE;
    }

    dmac_tx_event_stru *dpd_event = (dmac_tx_event_stru *)event->auc_event_data;
    dpd_event->netbuf = netbuf_dpd_data;
    dpd_event->us_frame_len = sizeof(dpd_cali_data_stru);
    netbuf_dpd_data->data_len = sizeof(dpd_cali_data_stru);

    hi_u32 ret = hcc_hmac_tx_data_event(event_mem, netbuf_dpd_data, HI_FALSE);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(netbuf_dpd_data);
        oam_error_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }

    frw_event_free(event_mem);
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : �������mac addrɨ�迪��, 0�رգ�1��
 �޸���ʷ      :
  1.��    ��   : 2015��5��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_random_mac_addr_scan(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_device_stru *hmac_dev = HI_NULL;
    hi_u8 random_mac_addr_scan_switch;

    hi_unref_param(mac_vap);
    hi_unref_param(us_len);

    random_mac_addr_scan_switch = *((hi_u8 *)puc_param);

    /* ��ȡhmac device�ṹ�� */
    hmac_dev = hmac_get_device_stru();
    hmac_dev->scan_mgmt.is_random_mac_addr_scan = random_mac_addr_scan_switch;
    oam_info_log1(0, OAM_SF_SCAN,
        "{set set_random_mac_addr_scan SUCC[%d]!}", hmac_dev->scan_mgmt.is_random_mac_addr_scan);
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
/*****************************************************************************
 ��������  : ����rekey offload����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2019��10��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_rekey_offload_set_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_REKEY_OFFLOAD_SET_SWITCH, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_rekey_offload_set_switch::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

hi_void hmac_config_kick_user_disassoc(mac_vap_stru *mac_vap, const mac_cfg_kick_user_param_stru *kick_user_param,
    hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user)
{
#if defined(_PRE_WLAN_FEATURE_ARP_OFFLOAD) || defined(_PRE_WLAN_FEATURE_DHCP_OFFLOAD)
    mac_ip_addr_config_stru ip_addr_cfg = {.type = MAC_CONFIG_IPV4, .oper = MAC_IP_ADDR_DEL};
#endif

    /* ��ȥ��֤֡ */
    hmac_mgmt_send_disassoc_frame(mac_vap, hmac_user->base_user->user_mac_addr,
        kick_user_param->us_reason_code, (hi_u8)hmac_user->base_user->cap_info.pmf_active);

    /* �޸� state & ɾ�� user */
    hmac_handle_disconnect_rsp(hmac_vap, hmac_user, HMAC_REPORT_DISASSOC);
    /* ɾ���û� */
    hmac_user_del(mac_vap, hmac_user);

    /* �ر�arp offload���� */
#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
    hmac_config_arp_offload_setting(mac_vap, sizeof(mac_ip_addr_config_stru), (const hi_u8 *)&ip_addr_cfg);
#endif
    /* �ر�dhcp offload���� */
#ifdef _PRE_WLAN_FEATURE_DHCP_OFFLOAD
    hmac_config_dhcp_offload_setting(mac_vap, sizeof(mac_ip_addr_config_stru), (const hi_u8 *)&ip_addr_cfg);
#endif
    /* �ر�rekey offload���� */
#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
    hi_u8 rekey_offload = HI_FALSE;
    hmac_config_rekey_offload_set_switch(mac_vap, sizeof(hi_u8), (const hi_u8 *)&rekey_offload);
#endif
}

static hi_u32 hmac_config_kick_user_vap(mac_vap_stru *mac_vap, const mac_cfg_kick_user_param_stru *kick_user_param,
    hmac_vap_stru *hmac_vap)
{
    hi_u8                         uidx = 0;

    if (mac_vap_find_user_by_macaddr(mac_vap, kick_user_param->auc_mac_addr, WLAN_MAC_ADDR_LEN, &uidx) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user::mac_vap_find_user_by_macaddr}");
        if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
        }
        return HI_FAIL;
    }

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(uidx);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user::hmac_user null,user_idx:%d}", uidx);
        if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
        }
        return HI_ERR_CODE_PTR_NULL;
    }

    if (hmac_user->base_user->user_asoc_state != MAC_USER_STATE_ASSOC) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user:user unassociate,user_idx:%d}", uidx);
    }
#ifdef _PRE_WLAN_FEATURE_MESH
    if (hmac_user->base_user->is_mesh_user == HI_TRUE) {
        /* �������wpa�����ɾ���û�����ֱ�ӽ��û�ɾ������ */
        if (kick_user_param->us_reason_code == MAC_WPA_KICK_MESH_USER) {
            /* ɾ���û� */
            hmac_user_del(mac_vap, hmac_user);
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user::the mesh user is del}");
            return HI_SUCCESS;
        }
        hmac_handle_close_peer_mesh(hmac_vap, hmac_user->base_user->user_mac_addr, WLAN_MAC_ADDR_LEN,
            HMAC_REPORT_DISASSOC, DMAC_DISASOC_MISC_KICKUSER);

        return HI_SUCCESS;
    }
#endif

    hmac_config_kick_user_disassoc(mac_vap, kick_user_param, hmac_vap, hmac_user);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��������ȥ����1���û�
 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2014��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ߵ�ȫ��user�Ĺ���
*****************************************************************************/
hi_u32 hmac_config_kick_user(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_user_stru                *user_tmp = HI_NULL;
    hmac_user_stru               *hmac_user_tmp = HI_NULL;

    hi_unref_param(us_len);

    if (oal_unlikely(mac_vap == HI_NULL || puc_param == HI_NULL)) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_kick_user:vap=%p pa=%p}", (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user::en_vap_mode is WLAN_VAP_MODE_CONFIG.}");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    mac_cfg_kick_user_param_stru *kick_user_param = (mac_cfg_kick_user_param_stru *)puc_param;
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_config_kick_user::null param,pst_hmac_vap[%d].}", mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    oam_warning_log4(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user: user mac[XX:XX:XX:%02X:%02X:%02X]code %d}",
                     kick_user_param->auc_mac_addr[3], kick_user_param->auc_mac_addr[4], /* 3 4 Ԫ������ */
                     kick_user_param->auc_mac_addr[5], kick_user_param->us_reason_code); /* 5 Ԫ������ */

    /* �ߵ�ȫ��user (mesh��֧��) */
    if (oal_is_broadcast_ether_addr(kick_user_param->auc_mac_addr)
#ifdef _PRE_WLAN_FEATURE_MESH
        && (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)
#endif
        ) {
        hmac_mgmt_send_disassoc_frame(mac_vap, kick_user_param->auc_mac_addr,
                                      kick_user_param->us_reason_code, HI_FALSE);

        /* ����vap�������û�, ɾ���û� */
        hi_list *user_list_head = &(mac_vap->mac_user_list_head);
        for (hi_list *entry = user_list_head->next; entry != user_list_head;) {
            user_tmp = hi_list_entry(entry, mac_user_stru, user_dlist);
            hmac_user_tmp = (hmac_user_stru *)hmac_user_get_user_stru((hi_u8)user_tmp->us_assoc_id);
            if (oal_unlikely(hmac_user_tmp == HI_NULL)) {
                oam_error_log1(0, OAM_SF_CFG, "{hmac_config_kick_user::null param,user_tmp %d}", user_tmp->us_assoc_id);
                continue;
            }

            /* ָ��˫��������һ�� */
            entry = entry->next;

            /* �޸� state & ɾ�� user */
            hmac_handle_disconnect_rsp(hmac_vap, hmac_user_tmp, HMAC_REPORT_DISASSOC);

            /* ɾ���û� */
            hmac_user_del(mac_vap, hmac_user_tmp);
        }

        /* VAP��userͷָ�벻Ӧ��Ϊ�� */
        if (hi_is_list_empty_optimize(&mac_vap->mac_user_list_head) == HI_FALSE) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_kick_user::st_mac_user_list_head is not empty.}");
        }
        return HI_SUCCESS;
    }

    return hmac_config_kick_user_vap(mac_vap, kick_user_param, hmac_vap);
}

/*****************************************************************************
 ��������  : ��������non-HT�������dmac
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_rate(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RATE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_rate::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��������HT�������dmac
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_mcs(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_MCS, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_mcs::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : �������ô������dmac
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_bw(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32                              ret;
    mac_cfg_tx_comp_stru                *event_set_bw = HI_NULL;
    wlan_channel_bandwidth_enum_uint8   bandwidth      = WLAN_BAND_ASSEMBLE_20M;
    hmac_vap_stru                       *hmac_vap     = HI_NULL;

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_bw::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    event_set_bw = (mac_cfg_tx_comp_stru *)puc_param;
    if (event_set_bw->param == WLAN_BAND_ASSEMBLE_5M) {
        bandwidth = WLAN_BAND_WIDTH_5M;
    } else if (event_set_bw->param == WLAN_BAND_ASSEMBLE_10M) {
        bandwidth = WLAN_BAND_WIDTH_10M;
    } if (event_set_bw->param == WLAN_BAND_ASSEMBLE_20M) {
        bandwidth = WLAN_BAND_WIDTH_20M;
    }
    hmac_vap->preset_para.en_bandwidth = bandwidth;
    mac_vap->channel.en_bandwidth = bandwidth;
    /* խ������txop limit */
    if ((event_set_bw->param == WLAN_BAND_ASSEMBLE_5M) || (event_set_bw->param == WLAN_BAND_ASSEMBLE_10M)) {
        hi_u16 txop[WLAN_WME_AC_BUTT] = {0xfa0, 0xbb8, 0x11f8, 0x1388}; /* ��AC��txop limit */
        for (hi_u8 ac_type = 0; ac_type < WLAN_WME_AC_BUTT; ac_type++) {
            mac_vap->mib_info->ast_wlan_mib_edca[ac_type].dot11_edca_table_txop_limit = txop[ac_type];
            mac_vap->mib_info->wlan_mib_qap_edac[ac_type].dot11_qapedca_table_txop_limit = txop[ac_type];
        }
    }
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_BW, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_bw::hmac_config_send_event failed[%d].}",
                         ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��ȡ������Ϣ
*****************************************************************************/
hi_u32 hmac_config_get_bw(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    mac_cfg_tx_comp_stru *set_bw_param = HI_NULL;

    set_bw_param = (mac_cfg_tx_comp_stru *)puc_param;
    if (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_5M) {
        set_bw_param->param = WLAN_BAND_ASSEMBLE_5M;
    } else if (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_10M) {
        set_bw_param->param = WLAN_BAND_ASSEMBLE_10M;
    } else if (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_20M) {
        set_bw_param->param = WLAN_BAND_ASSEMBLE_20M;
    }

    *pus_len = sizeof(mac_cfg_tx_comp_stru);

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
/*****************************************************************************
 ��������  : �㲥���ݰ�
 �޸���ʷ      :
  1.��    ��   : 2014��3��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_bcast_pkt(mac_vap_stru *mac_vap, hi_u32 payload_len)
{
    oal_netbuf_stru *netbuf = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u32 ret;

    /* ��μ�� */
    if (mac_vap == HI_NULL || mac_vap->mib_info == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_config_bcast_pkt::pst_mac_vap/puc_param is null ptr!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{wal_config_bcast_pkt::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��� */
    netbuf =
        hmac_config_create_al_tx_packet(payload_len, (hi_u8)mac_vap->payload_flag,
                                        (hi_u8)hmac_vap->init_flag);
    if (netbuf == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_config_bcast_pkt::return null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (memset_s(oal_netbuf_cb(netbuf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        hmac_free_netbuf_list(netbuf);
        return HI_FAIL;
    }

    ret = hmac_tx_lan_to_wlan(mac_vap, netbuf);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY,
                         "{wal_config_bcast_pkt::hmac_tx_lan_to_wlan return error %d!}\r\n", ret);
        hmac_free_netbuf_list(netbuf);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : �����һ������
 �������  : size��ʾ���ĳ��ȣ� ������̫��ͷ���� ������FCS�� ȡֵ��ΧӦ��Ϊ60~1514
 �޸���ʷ      :
  1.��    ��   : 2013��9��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
oal_netbuf_stru *hmac_config_create_al_tx_packet(hi_u32 size,
                                                 mac_rf_payload_enum_uint8 payload_flag,
                                                 hi_u8 init_flag)
{
    static oal_netbuf_stru *netbuf = HI_NULL;
    hi_u32 loop = 0;
    hi_u32 l_reserve = 256;

    if (init_flag == HI_TRUE) {
        netbuf = oal_netbuf_alloc(size + l_reserve, l_reserve, 4);  /* align 4 */
        if (oal_unlikely(netbuf == HI_NULL)) {
            oam_error_log0(0, OAM_SF_TX, "hmac_config_create_al_tx_packet::alloc Fail");
            return HI_NULL;
        }
        oal_netbuf_put(netbuf, size);
    }

    if (netbuf == HI_NULL) {
        oam_error_log0(0, OAM_SF_TX, "hmac_config_create_al_tx_packet::pst_buf is not initiate");
        return HI_NULL;
    }

    switch (payload_flag) {
        case RF_PAYLOAD_ALL_ZERO:
            if (memset_s(netbuf->data, size, 0, size) != EOK) {
                oal_netbuf_free(netbuf);
                return HI_NULL;
            }
            break;
        case RF_PAYLOAD_ALL_ONE:
            if (memset_s(netbuf->data, size, 0xFF, size) != EOK) {
                oal_netbuf_free(netbuf);
                return HI_NULL;
            }
            break;
        case RF_PAYLOAD_RAND:
            netbuf->data[0] = oal_gen_random(18, 1); /* �������Ϊ18 */
            for (loop = 1; loop < size; loop++) {
                netbuf->data[loop] = oal_gen_random(18, 0); /* �������Ϊ18 */
            }
            break;
        default:
            break;
    }

    netbuf->next = HI_NULL;
    netbuf->prev = HI_NULL;

    if (memset_s(oal_netbuf_cb(netbuf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        oal_netbuf_free(netbuf);
        return HI_NULL;
    }
    return netbuf;
}

/*****************************************************************************
 ��������  : �������ó���ģʽ���dmac
 �޸���ʷ      :
  1.��    ��   : 2015��1��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_always_tx(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    mac_cfg_tx_comp_stru *event_set_bcast = HI_NULL;

    /* ʹ�ܳ��� */
    event_set_bcast = (mac_cfg_tx_comp_stru *)puc_param;
    mac_vap->al_tx_flag = (event_set_bcast->param == HI_SWITCH_OFF) ? HI_SWITCH_OFF : HI_SWITCH_ON;
    if (mac_vap->al_tx_flag) {
        mac_vap->cap_flag.keepalive = HI_FALSE;
        /* ������ʱ�رյ͹��� */
        hmac_set_wlan_pm_switch(HI_FALSE);
    } else {
        mac_vap_set_al_tx_first_run(mac_vap, HI_FALSE);
    }
    mac_vap_set_al_tx_payload_flag(mac_vap, event_set_bcast->payload_flag);

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_ALWAYS_TX, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_always_tx::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

#ifdef _PRE_WLAN_FEATURE_CSI
/****************************************************************************
 ��������  : hmac����wal��������CSI���������¼�,�����¼������׵�dmac
 �޸���ʷ      :
  1.��    ��   : 2019��1��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_csi_set_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 send_event_ret;

    /***************************************************************************
     ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    send_event_ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CSI_SWITCH, us_len, puc_param);
    if (send_event_ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CSI,
                         "{hmac_config_csi_set_switch::hmac_config_send_event failed[%d].}", send_event_ret);
        return send_event_ret;
    }
    return HI_SUCCESS;
}

/****************************************************************************
 ��������  : hmac����wal��������CSI���������¼�,�����¼������׵�dmac
 �޸���ʷ      :
  1.��    ��   : 2019��1��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_csi_set_config(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 send_event_ret;

    /***************************************************************************
     ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    send_event_ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CSI_SET_CONFIG, us_len, puc_param);
    if (send_event_ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CSI,
                         "{hmac_config_csi_set_config::hmac_config_send_event failed[%d].}", send_event_ret);
        return send_event_ret;
    }
    return HI_SUCCESS;
}

/****************************************************************************
 ��������  : HMAC�㴦��DMACģ�����CSI�ϱ��¼�����
 �޸���ʷ      :
  1.��    ��   : 2019��1��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_csi_data_report_event(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u32 send_event_ret;

    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_CSI, "{hmac_csi_data_report_event::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /***************************************************************************
     ���¼���WAL��, ͬ��WAL����
    ***************************************************************************/
    /* ����¼�ָ�� */
    event = (frw_event_stru *)event_mem->puc_data;
    mac_vap = mac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CSI, "{hmac_csi_data_report_event::pst_mac_vap null.}");
        return HI_FAIL;
    }

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CTX,
                       HMAC_HOST_CTX_EVENT_SUB_TYPE_CSI_REPORT,
                       sizeof(mac_csi_data_stru),
                       FRW_EVENT_PIPELINE_STAGE_0,
                       mac_vap->vap_id);

    /* �ַ��¼���WAL�� */
    send_event_ret = frw_event_dispatch_event(event_mem);
    if (send_event_ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CSI,
                         "{hmac_csi_data_report_event::frw_event_dispatch_event fail[%d].}", send_event_ret);
        return send_event_ret;
    }
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : �������ó���ģʽ���dmac
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_always_rx(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_always_rx::hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap->hmac_al_rx_flag = puc_param[0];
    hmac_vap->mac_filter_flag = puc_param[1];

    if (hmac_vap->hmac_al_rx_flag == HI_SWITCH_ON) {
        /* ���մ�ʱ�رյ͹��� */
        hmac_set_wlan_pm_switch(HI_FALSE);
    }

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_ALWAYS_RX, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_always_rx::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
    /* ����֡���� */
    ret = hmac_set_rx_filter_value(mac_vap);
#endif
    return ret;
}

#ifdef _PRE_DEBUG_MODE
/*****************************************************************************
 ��������  : �������ö�̬����У׼���dmac
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_dync_txpower(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DYNC_TXPOWER, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_dync_txpower::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : �ϱ�ĳһ��vap�µ��շ���ͳ��
 �޸���ʷ      :
  1.��    ��   : 2014��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_vap_pkt_stat(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(mac_vap);
    hi_unref_param(us_len);
    hi_unref_param(puc_param);
    return HI_SUCCESS;
}
#endif
#endif

/*****************************************************************************
 ��������  : hmac���ù�����
 �޸���ʷ      :
  1.��    ��   : 2013��10��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_country(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_country_stru      *country_param = HI_NULL;
    mac_regdomain_info_stru   *mac_regdom = HI_NULL;
    mac_regdomain_info_stru   *regdomain_info = HI_NULL;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hi_u32                     ret;
#endif
    hi_u32                     size;

    hi_unref_param(us_len);

    country_param = (mac_cfg_country_stru *)puc_param;
    mac_regdom    = (mac_regdomain_info_stru *)country_param->mac_regdom;
    size = sizeof(mac_regdomain_info_stru);
    /* ��ȡ������ȫ�ֱ��� */
    regdomain_info = mac_get_regdomain_info();
    /* ���¹�������Ϣ */
    if (mac_regdom != HI_NULL) {
        if (memcpy_s(regdomain_info, sizeof(mac_regdomain_info_stru), mac_regdom, size) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_config_set_country::pst_mac_regdom memcpy_s fail.");
            return HI_FAIL;
        }
    }
    /* �����ŵ��Ĺ�������Ϣ */
    mac_init_channel_list();
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_COUNTRY, (hi_u16)size, (hi_u8 *)mac_regdom);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oal_mem_free(mac_regdom);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_country::hmac_config_send_event failed[%d].}",
            ret);
        return ret;
    }
#else
    hi_unref_param(mac_vap);
#endif
    /* WAL�����ڴ��������˴��ͷ� */
    oal_mem_free(mac_regdom);
    return HI_SUCCESS;
}

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : hmac����ampdu tx ����
 �޸���ʷ      :
  1.��    ��   : 2015��5��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_ampdu_tx_on_sub(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_ampdu_tx_on_param_stru *ampdu_tx_on_param = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;

    hi_unref_param(us_len);

    if (oal_unlikely(mac_vap == HI_NULL || puc_param == HI_NULL)) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_set_ampdu_tx_on:: param null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_ampdu_tx_on::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    ampdu_tx_on_param = (mac_cfg_ampdu_tx_on_param_stru *)puc_param;
#if defined(_PRE_WLAN_FEATURE_HIPRIV) && defined(_PRE_WLAN_FEATURE_INTRF_MODE)
    if (ampdu_tx_on_param->aggr_tx_on == 2) { /* 2:�ָ���ʷֵ */
        hmac_vap->ampdu_tx_on_switch = g_hist_ampdu_tx_on;
    } else { /* ���ò������ֵ */
        g_hist_ampdu_tx_on = (hi_bool)hmac_vap->ampdu_tx_on_switch;
        hmac_vap->ampdu_tx_on_switch = ampdu_tx_on_param->aggr_tx_on;
    }
#else
    hmac_vap->ampdu_tx_on_switch = ampdu_tx_on_param->aggr_tx_on;
#endif
    oam_info_log1(0, OAM_SF_CFG, "{hmac_config_set_ampdu_tx_on:: ampdu_tx_on_switch[%d]!}\r\n",
                  hmac_vap->ampdu_tx_on_switch);

    return HI_SUCCESS;
}

hi_u32 hmac_config_set_ampdu_tx_on(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    return hmac_config_set_ampdu_tx_on_sub(mac_vap, us_len, puc_param);
}

hi_u32 hmac_config_set_ampdu_tx_on_from_dmac(mac_vap_stru *mac_vap, hi_u8 us_len, const hi_u8 *puc_param)
{
    return hmac_config_set_ampdu_tx_on_sub(mac_vap, us_len, puc_param);
}
#endif

/*****************************************************************************
 ��������  : ��ȡ�Զ�RSSI
*****************************************************************************/
hi_u32 hmac_config_query_rssi(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_RSSI, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_query_rssi::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : �����û����Ʊ���
 �������  : pst_mac_vap:  MAC VAP
             puc_param   : �ϲ������Ϣ
             us_len      : �ϲ��������
 �� �� ֵ  : HI_SUCCESS �ϱ��ɹ������������� �ϱ�ʧ��
*****************************************************************************/
hi_u32 hmac_send_custom_pkt(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    oal_netbuf_stru *pkt_buf = HI_NULL;
    hi_u16 us_pkt_len;
    hi_u8 *puc_data = HI_NULL;
    hmac_tx_ctl_stru *tx_ctl = HI_NULL;
    wlan_custom_pkt_stru *pkt_param = (wlan_custom_pkt_stru *)puc_param;

    hi_unref_param(us_len);

    if (pkt_param->puc_data == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �����û����ݵ�֡�� */
    if (pkt_param->us_len > WLAN_LARGE_NETBUF_SIZE) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_send_custom_pkt::pkt_param is null or pkt len too long.}");
        hi_free(HI_MOD_ID_WIFI_DRV, pkt_param->puc_data);
        return HI_FAIL;
    }

    /* ���뱨���ڴ� */
    pkt_buf = (oal_netbuf_stru *)oal_netbuf_alloc(pkt_param->us_len, 0, 4); /* align 4 */
    if (pkt_buf == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_send_custom_pkt::alloc netbuf failed.}");
        hi_free(HI_MOD_ID_WIFI_DRV, pkt_param->puc_data);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (memset_s(oal_netbuf_cb(pkt_buf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        hi_free(HI_MOD_ID_WIFI_DRV, pkt_param->puc_data);
        oal_netbuf_free(pkt_buf);
        return HI_FAIL;
    }
    puc_data = (hi_u8 *)oal_netbuf_header(pkt_buf);
    tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(pkt_buf);

    if (memcpy_s(puc_data, (hi_u32)pkt_param->us_len, pkt_param->puc_data, (hi_u32)pkt_param->us_len) != EOK) {
        oal_netbuf_free(pkt_buf);
        hi_free(HI_MOD_ID_WIFI_DRV, pkt_param->puc_data);
        return HI_FAIL;
    }
    us_pkt_len = (hi_u16)pkt_param->us_len;
    hi_free(HI_MOD_ID_WIFI_DRV, pkt_param->puc_data);

    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *) oal_netbuf_header(pkt_buf);
    tx_ctl->mac_head_type = 1;
    tx_ctl->us_tx_user_idx = 0xF;
    tx_ctl->us_mpdu_len = us_pkt_len;
    oal_netbuf_put(pkt_buf, (hi_u32) us_pkt_len);

    /* ���÷��͹���֡�ӿ� */
    if (hmac_tx_mgmt_send_event(mac_vap, pkt_buf, us_pkt_len) != HI_SUCCESS) {
        oal_netbuf_free(pkt_buf);
        oam_warning_log0(0, OAM_SF_CFG, "{hmac_send_custom_pkt::hmac_tx_mgmt_send_event failed.}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ��SAR
 �޸���ʷ      :
  1.��    ��   : 2014��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_reduce_sar(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_REDUCE_SAR, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "hmac_config_reduce_sar::hmac_config_send_event failed, error no[%d]!", ret);
        return ret;
    }
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : hmac��ȡ������
 �޸���ʷ      :
  1.��    ��   : 2013��10��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_country(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    hi_unref_param(pus_len);
    hi_unref_param(mac_vap);
    mac_cfg_get_country_stru *param = (mac_cfg_get_country_stru *)puc_param;;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    mac_regdomain_info_stru *regdomain_info = mac_get_regdomain_info();
    param->ac_country[0] = regdomain_info->ac_country[0];
    param->ac_country[1] = regdomain_info->ac_country[1]; /* 1 Ԫ������ */
    param->ac_country[2] = regdomain_info->ac_country[2]; /* 2 Ԫ������ */
#else
    hi_char *pc_curr_cntry = mac_regdomain_get_country();
    param->ac_country[0] = pc_curr_cntry[0];
    param->ac_country[1] = pc_curr_cntry[1]; /* 1 Ԫ������ */
    param->ac_country[2] = pc_curr_cntry[2]; /* 2 Ԫ������ */
#endif

    oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG, "hmac_config_get_country:: country[%C%C]\r\n",
        param->ac_country[0], param->ac_country[1]);
    *pus_len = sizeof(mac_cfg_get_country_stru);
    return HI_SUCCESS;
}

static hi_u32 hmac_config_connect_ie(mac_vap_stru *mac_vap, hmac_scanned_bss_info *scanned_bss_info,
    const mac_cfg80211_connect_param_stru *connect_param, const mac_bss_dscr_stru *bss_dscr,
    mac_cfg80211_connect_security_stru* conn_sec)
{
    hi_unref_param(scanned_bss_info);

    /* END:DTS2015080801057 WLAN���͵� assoc request ��Я��P2P IE */
    oal_app_ie_stru *app_ie = (oal_app_ie_stru *)oal_memalloc(sizeof(oal_app_ie_stru));
    if (app_ie == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_connect:: failed alloc app_ie}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }
    app_ie->ie_len = connect_param->ie_len;
    if ((connect_param->puc_ie != HI_NULL) &&
        (memcpy_s(app_ie->auc_ie, WLAN_WPS_IE_MAX_SIZE, connect_param->puc_ie, app_ie->ie_len) != EOK)) {
        oam_warning_log0(0, 0, "hmac_config_connect:puc_ie mem error");
        oal_free(app_ie);
        return HI_FAIL;
    }
    app_ie->app_ie_type = OAL_APP_ASSOC_REQ_IE;
    if (hmac_config_set_app_ie_to_vap(mac_vap, app_ie, app_ie->app_ie_type) != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "hmac_config_set_app_ie_to_vap return NON SUCCESS. ");
    }
    oal_free(app_ie);

    /* ������Ч dot11DTIMPeriod */
    if (bss_dscr->dtim_period > 0) {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_dtim_period = bss_dscr->dtim_period;
    }
    /* ���ù����û���������Ϣ */
    mac_vap->us_assoc_user_cap_info = bss_dscr->us_cap_info;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* ����ѡ����ȵ�rssi��ͬ����dmac����tpc�㷨��������tpc */
    conn_sec->rssi = scanned_bss_info->bss_dscr_info.rssi;
#endif /* _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE */

    hi_u32 ret = mac_vap_init_privacy(mac_vap, conn_sec);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_connect::mac_11i_init_privacy failed[%d]!}\r\n", ret);
        return ret;
    }

    if (!conn_sec->privacy) {
        mac_vap->user_pmf_cap = HI_FALSE;
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_config_connect_dev(const mac_vap_stru *mac_vap, const mac_cfg80211_connect_param_stru *connect_param,
    hmac_vap_stru *hmac_vap, hmac_bss_mgmt_stru *bss_mgmt)
{
    hi_unref_param(bss_mgmt);
    /* ����ع������������� */
    hmac_vap->reassoc_flag = HI_FALSE;
#ifdef _PRE_WLAN_FEATURE_WAPI
    bss_dscr->wapi = connect_param->wapi;
    if (bss_dscr->wapi) {
        mac_device_stru *mac_dev = mac_res_get_dev();
        if (mac_device_is_p2p_connected(mac_dev) == HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{wapi connect failed for p2p having been connected!.}");
            oal_spin_unlock(&(bss_mgmt->st_lock));
            return HI_FAIL;
        }
    }
#endif

    /* ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));

#ifdef _PRE_WLAN_FEATURE_P2P
    /* ����P2P/WPS IE ��Ϣ�� vap �ṹ���� */
    /* BEGIN:DTS2015080801057 WLAN���͵� assoc request ��Я��P2P IE */
    if (is_legacy_vap(mac_vap)) {
        hmac_p2p_del_ie(connect_param->puc_ie, &(connect_param->ie_len));
    }
#endif

    return HI_SUCCESS;
}

static hi_u32 hmac_config_connect_conn_init(const mac_cfg80211_connect_param_stru *connect_param,
    mac_cfg80211_connect_security_stru* conn_sec)
{
    /* �����ں��·��Ĺ�����������ֵ������ص�mib ֵ */
    /* �����·���join,��ȡ����ȫ��ص����� */
    conn_sec->wep_key_len = connect_param->wep_key_len;
    conn_sec->auth_type = connect_param->auth_type;
    conn_sec->privacy = connect_param->privacy;
    conn_sec->crypto = connect_param->crypto;
    conn_sec->wep_key_index = connect_param->wep_key_index;
    conn_sec->mgmt_proteced = connect_param->mfp;
    if (conn_sec->wep_key_len > WLAN_WEP104_KEY_LEN) {
        oam_error_log1(0, OAM_SF_ANY, "{hmac_config_connect:key_len[%d] > WLAN_WEP104_KEY_LEN}\r\n",
            conn_sec->wep_key_len);
        conn_sec->wep_key_len = WLAN_WEP104_KEY_LEN;
    }
    if ((connect_param->puc_wep_key != HI_NULL) && (memcpy_s(conn_sec->auc_wep_key, WLAN_WEP104_KEY_LEN,
        connect_param->puc_wep_key, conn_sec->wep_key_len) != EOK)) {
        oam_warning_log1(0, 0, "hmac_config_connect:mem error :: %p", (uintptr_t)connect_param->puc_wep_key);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

hi_u32 hmac_config_connect_hmac(mac_vap_stru *mac_vap, mac_cfg80211_connect_security_stru* conn_sec,
    const mac_cfg80211_connect_param_stru *connect_param, hmac_vap_stru *hmac_vap)
{
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    /* ��ȡ����ɨ���bss����Ľṹ�� */
    hmac_bss_mgmt_stru *bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt); /* ����ɨ���bss����Ľṹ�� */
    /* ������ɾ����ǰ���� */
    oal_spin_lock(&(bss_mgmt->st_lock));
    hmac_scanned_bss_info* scanned_bss_info = hmac_scan_find_scanned_bss_by_bssid(bss_mgmt, connect_param->puc_bssid);
    if (scanned_bss_info == HI_NULL) {
        oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_connect:find bss fail bssid::XX:XX:%02X:%02X:%02X}",
            connect_param->puc_bssid[3], connect_param->puc_bssid[4], connect_param->puc_bssid[5]); /* 3 4 5 Ԫ������ */

        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));
        return HI_FAIL;
    }

    if (memcmp(connect_param->puc_ssid, scanned_bss_info->bss_dscr_info.ac_ssid, (hi_u32) connect_param->ssid_len)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_connect::find the bss failed by ssid.}");
        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));
        return HI_FAIL;
    }

    mac_bss_dscr_stru* bss_dscr = &(scanned_bss_info->bss_dscr_info);

    if (hmac_config_connect_dev(mac_vap, connect_param, hmac_vap, bss_mgmt) != HI_SUCCESS) {
        return HI_FAIL;
    }

    hi_u32 ret = hmac_config_connect_ie(mac_vap, scanned_bss_info, connect_param, bss_dscr, conn_sec);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    hmac_vap->wps_active = conn_sec->wps_enable;
    ret = hmac_check_capability_mac_phy_supplicant(mac_vap, bss_dscr);
    if (ret != HI_SUCCESS) {
        /* DTS2016052803102 MAC/PHY ���������ϸ��� */
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_connect:check mac phy capability fail[%d]}\n", ret);
    }

    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CONNECT_REQ, sizeof(mac_cfg80211_connect_security_stru),
        (hi_u8 *) conn_sec);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA, "{hmac_config_connect::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return hmac_sta_initiate_join(mac_vap, bss_dscr);
}

/*****************************************************************************
 ��������  : hmac����
 �޸���ʷ      :
  1.��    ��   : 2015��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_connect(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg80211_connect_security_stru conn_sec;

    if (oal_unlikely(mac_vap == HI_NULL) || oal_unlikely(puc_param == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_config_connect:: connect failed, null ptr!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (us_len != sizeof(mac_cfg80211_connect_param_stru)) {
        oam_error_log1(0, OAM_SF_ANY, "{hmac_config_connect:: connect failed,unexpected param len![%x]!}\r\n", us_len);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /* ���ж�����VAP ��״̬�Ƿ�����VAP �������� */
    /* �������VAP �������򷵻��豸æ״̬           */
    mac_cfg80211_connect_param_stru *connect_param = (mac_cfg80211_connect_param_stru *)puc_param;

    if (hmac_config_connect_conn_init(connect_param, &conn_sec) != HI_SUCCESS) {
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_PMF
    conn_sec.pmf_cap = mac_get_pmf_cap(connect_param->puc_ie, connect_param->ie_len);
#endif
    conn_sec.wps_enable = HI_FALSE;
    if (mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WPS, connect_param->puc_ie,
        (hi_s32) (connect_param->ie_len))) {
        conn_sec.wps_enable = HI_TRUE;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_config_connect:connect failed,hmac_vap null.vap_id[%d]}", mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap->auth_mode = conn_sec.auth_type;

    return hmac_config_connect_hmac(mac_vap, &conn_sec, connect_param, hmac_vap);
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ��ȡ��������֡��tid
 �޸���ʷ      :
  1.��    ��   : 2013��10��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_tid(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    mac_device_stru *mac_dev = HI_NULL;
    mac_cfg_get_tid_stru *tid = HI_NULL;
    hi_unref_param(mac_vap);

    tid = (mac_cfg_get_tid_stru *)puc_param;
    mac_dev = mac_res_get_dev();
    tid->tid = mac_dev->tid;
    *pus_len = sizeof(tid->tid);

    oam_info_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_get_tid::en_tid=%d.}", tid->tid);
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����豸֧�ֵ��ŵ��б�
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_list_channel(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 chan_num;
    hi_u8 chan_idx;
    hi_u32 ret;
    hi_unref_param(us_len);

    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_list_channel::null param,pst_mac_vap=%p puc_param=%p.}",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_FAIL;
    }

    for (chan_idx = 0; chan_idx < MAC_CHANNEL_FREQ_2_BUTT; chan_idx++) {
        ret = mac_is_channel_idx_valid(MAC_RC_START_FREQ_2, chan_idx, HI_NULL);
        if (ret == HI_SUCCESS) {
            mac_get_channel_num_from_idx(MAC_RC_START_FREQ_2, chan_idx, &chan_num);

            /* ���2G�ŵ��� */
            oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_list_channel::2gCHA.NO=%d}\n",
                             chan_num);
        }
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ���û�̬ IE ��Ϣ�������ں�̬��
 �������  : mac_vap_stru *pst_mac_vap
             oal_net_dev_ioctl_data_stru *pst_ioctl_data
             enum WPS_IE_TYPE en_type
 �� �� ֵ  : static hi_u8*
 �޸���ʷ      :
  1.��    ��   : 2014��4��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_app_ie_to_vap(mac_vap_stru *mac_vap,
                                     oal_app_ie_stru *app_ie, en_app_ie_type_uint8 type)
{
    hi_u32 ret;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    oal_app_ie_stru tmp_app_ie;
#endif
    hi_u8 *puc_ie = HI_NULL;
    hi_u32 remain_len;

    if ((mac_vap == HI_NULL) || (app_ie == HI_NULL)) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_set_app_ie_to_vap::scan failed, set ie null ptr, %p, %p.}",
                       (uintptr_t)mac_vap, (uintptr_t)app_ie);

        return HI_ERR_CODE_PTR_NULL;
    }

    /* �Ƴ��������ظ�MAC_EID_EXT_CAPS */
    puc_ie = mac_find_ie(MAC_EID_EXT_CAPS, app_ie->auc_ie, app_ie->ie_len);
    if (puc_ie != HI_NULL) {
        app_ie->ie_len -= (hi_u32) (puc_ie[1] + MAC_IE_HDR_LEN);
        remain_len = app_ie->ie_len - (hi_u32) (puc_ie - app_ie->auc_ie);
        if (memmove_s(puc_ie, remain_len, puc_ie + (hi_u32) (puc_ie[1] + MAC_IE_HDR_LEN), remain_len) != EOK) {
            return HI_FAIL;
        }
    }

    ret = mac_vap_save_app_ie(mac_vap, app_ie, type);
    if (ret != HI_SUCCESS) {
        oam_error_log3(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_config_set_app_ie_to_vap::mac_vap_save_app_ie failed[%d], en_type[%d], len[%d].}", ret,
                       type, app_ie->ie_len);
        return ret;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    if (app_ie->app_ie_type >= OAL_APP_ASSOC_REQ_IE) {
        /* ֻ��OAL_APP_BEACON_IE��OAL_APP_PROBE_REQ_IE��OAL_APP_PROBE_RSP_IE ����Ҫ���浽device */
        return HI_SUCCESS;
    }
    tmp_app_ie.app_ie_type = app_ie->app_ie_type;
    tmp_app_ie.ie_len = app_ie->ie_len;

    /* ���·���ie���ͺͳ��ȱ��浽auc_buffer �У��������¼��·���DMAC */
    if (memcpy_s(tmp_app_ie.auc_ie, WLAN_WPS_IE_MAX_SIZE, app_ie->auc_ie, app_ie->ie_len) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_config_set_app_ie_to_vap::pst_app_ie->auc_ie memcpy_s fail.");
        return HI_FAIL;
    }
    /***************************************************************************
     ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_WPS_P2P_IE, sizeof(oal_app_ie_stru), (hi_u8 *) &tmp_app_ie);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log2(0, OAM_SF_CFG,
                         "{hmac_config_set_app_ie_to_vap::hmac_config_send_event failed[%d], vap id[%d].}", ret,
                         mac_vap->vap_id);
    }
#endif

    return ret; /* app_ie�ڱ������в��漰�ͷţ��󱨸澯��lin_t e429�澯���� */
}

/*****************************************************************************
 ��������  : ���÷�Ƭ����
 �޸���ʷ      :
  1.��    ��   : 2014��8��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_rts_threshold(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_rts_threshold_stru *rts_threshold = HI_NULL;
    hi_unref_param(us_len);

    if (oal_unlikely(mac_vap == HI_NULL || puc_param == HI_NULL || mac_vap->mib_info == HI_NULL)) {
        oam_error_log3(0, OAM_SF_CFG,
                       "{hmac_config_rts_threshold:: mac_vap/puc_param/mib_info is null ptr %p, %p, %p!}\r\n",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param, (uintptr_t)mac_vap->mib_info);
        return HI_ERR_CODE_PTR_NULL;
    }

    rts_threshold = (mac_cfg_rts_threshold_stru *)puc_param;
    mac_mib_set_rts_threshold(mac_vap, rts_threshold->rts_threshold);

    oam_info_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_rts_threshold: mib rts %d!}\r\n",
                  mac_vap->mib_info->wlan_mib_operation.dot11_rts_threshold);

    return HI_SUCCESS;
}

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ��ȡ�Ĵ���ֵ
 �޸���ʷ      :
  1.��    ��   : 2013��5��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_reg_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_REG_INFO, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_reg_info::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_WOW
/*****************************************************************************
 ��������  :
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_wow_set_param(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    hi_unref_param(us_len);
    hi_unref_param(puc_param);

    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_config_wow_set_param:oal_net_dev_priv(pst_net_dev) is null ptr!}\r\n");
        return HI_ERR_WIFI_HMAC_INVALID_PARAMETER;
    }

    ret = hmac_wow_set_dmac_cfg();
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "hmac_wow_set_dmac_cfg return NON SUCCESS. ");
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : hmac set FW no send any frame to driver
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_host_sleep_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 is_host_sleep;
    hi_unref_param(us_len);
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_host_sleep_switch::param null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    is_host_sleep = *(hi_u32 *)puc_param;

    hmac_wow_host_sleep_cmd(mac_vap, is_host_sleep);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : Hmac Enable/disable WOW events
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_wow(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 wow_event;
    hi_unref_param(us_len);

    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_set_wow::param null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    wow_event = *(hi_u32 *)puc_param;

    hisi_wlan_set_wow_event(wow_event);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : Hmac activate/deactivate wow hipriv
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_wow_activate_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 wow_en;
    mac_vap_stru *vap = HI_NULL;
    mac_device_stru *mac_dev = mac_res_get_dev();
    hi_unref_param(us_len);

    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_wow_en::param null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    for (hi_u8 vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (vap == HI_NULL) {
            continue;
        }
        if ((vap->vap_mode == WLAN_VAP_MODE_BSS_AP) && (vap->vap_state == MAC_VAP_STATE_UP)) {
            oam_warning_log0(0, 0, "hmac_config_wow_activate_switch:: AP EXIST, don't support wowEn");
            return HI_FAIL;
        }
    }

    wow_en = *(hi_u32 *)puc_param;

    hmac_wow_set_wow_en_cmd(wow_en);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : Hmac set wow pattern
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_wow_pattern(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_cfg_wow_pattern_param_stru *pattern = HI_NULL;
    hi_u32 ret;

    hi_unref_param(us_len);

    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_set_wow_pattern::param null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    pattern = (hmac_cfg_wow_pattern_param_stru *)puc_param;

    if (pattern->us_pattern_option == MAC_WOW_PATTERN_PARAM_OPTION_ADD) {
        ret = hisi_wlan_add_netpattern((hi_u32)pattern->us_pattern_index, &pattern->auc_pattern_value[0],
                                       pattern->pattern_len);
        if (ret != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_CFG, "hisi_wlan_add_netpattern return NON SUCCESS. ");
        }
    } else if (pattern->us_pattern_option == MAC_WOW_PATTERN_PARAM_OPTION_DEL) {
        hisi_wlan_del_netpattern((hi_u32)pattern->us_pattern_index);
    } else {
        hmac_wow_set_pattern_cmd(pattern);
    }

    return HI_SUCCESS;
}
#endif /* end of _PRE_WLAN_FEATURE_WOW */
#endif

#ifdef _PRE_WLAN_FEATURE_PROMIS
/*****************************************************************************
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2016��3��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_monitor_switch(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hi_u8 value = puc_param[0];

    mac_device_stru *mac_dev = mac_res_get_dev();
    if (value == 0) {
        mac_dev->promis_switch = HI_FALSE;
    } else {
        mac_dev->promis_switch = HI_TRUE;
    }
#endif

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_MONITOR_EN, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_monitor_switch::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ָ���û���ָ��tid����bar
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_send_bar(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SEND_BAR, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_send_bar::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��9��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_reg_write(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_REG_WRITE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_reg_write::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : hmac, �㷨��������ʾ��
 �޸���ʷ      :
  1.��    ��   : 2013��10��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_alg_param(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    frw_event_mem_stru *event_mem = HI_NULL;
    hmac_to_dmac_cfg_msg_stru *syn_msg = HI_NULL;

    ret = hmac_config_alloc_event(mac_vap, HMAC_TO_DMAC_SYN_ALG, &syn_msg, &event_mem, us_len);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_alg_send_event::hmac_config_alloc_event failed[%d].}", ret);
        return ret;
    }
    syn_msg->syn_id = WLAN_CFGID_ALG_PARAM;
    syn_msg->us_len = us_len;
    /* ��д����ͬ����Ϣ���� */
    if (puc_param != HI_NULL) {
        if (memcpy_s(syn_msg->auc_msg_body, us_len, puc_param, us_len) != EOK) {
            frw_event_free(event_mem);
            oam_error_log0(0, OAM_SF_CFG, "dmac_join_set_reg_event_process:: hmac_config_alloc_event memcpy_s fail.");
            return HI_FAIL;
        }
    }
    /* �׳��¼� */
    hcc_hmac_tx_control_event(event_mem, us_len + (hi_u16)oal_offset_of(hmac_to_dmac_cfg_msg_stru, auc_msg_body));
    frw_event_free(event_mem);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2014��6��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_forty_mhz_intolerant(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_config_set_forty_mhz_intolerant::mac_vap[%p] NULL or puc_param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }
    hi_unref_param(us_len);

    if ((*puc_param != 0) && (*puc_param != 1)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_FortyMHzIntolerant::invalid param[%d].",
                         *puc_param);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    mac_mib_set_forty_mhz_intolerant(mac_vap, (hi_u8) (*puc_param));

    oam_info_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_FortyMHzIntolerant::end func,puc_param=%d.}",
                  *puc_param);
    return HI_SUCCESS;
}

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ���÷�Ƭ����
 �޸���ʷ      :
  1.��    ��   : 2014��2��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_frag_threshold(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_frag_threshold_stru *frag_threshold = HI_NULL;

    hi_unref_param(us_len);

    if (oal_unlikely(mac_vap == HI_NULL || puc_param == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_config_frag_threshold:: pst_mac_vap/puc_param is null ptr %p, %p!}\r\n",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        oam_warning_log0(0, OAM_SF_ANY,
            "{hmac_config_frag_threshold::[MESH]pst_mac_vap is mesh,not support set frag threshold}\r\n");
        return HI_FAIL;
    }
#endif

    frag_threshold = (mac_cfg_frag_threshold_stru *)puc_param;

    if (mac_vap->mib_info == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{wal_config_frag_threshold:pst_mib_info is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_mib_set_frag_threshold(mac_vap, frag_threshold->frag_threshold);
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ��ӡ����֡��FCS��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��3��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_rx_fcs_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_RX_FCS_INFO, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_rx_fcs_info::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP_DEBUG
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ��edca������������
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2014��12��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_edca_opt_switch_sta(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 flag;
    hi_u32 ret;
    hmac_vap_stru *hmac_vap = HI_NULL;

    /* ��ȡhmac_vap */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_switch_sta, hmac_vap_get_vap_stru fail.vap_id = %u",
                         mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ���ò��� */
    flag = *puc_param;

    /* ����û�и��ģ�����Ҫ�������� */
    if (flag == hmac_vap->edca_opt_flag_sta) {
        oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_switch_sta, change nothing to flag:%d",
                         hmac_vap->edca_opt_flag_sta);
        return HI_SUCCESS;
    }

    /* ���ò���������������ֹͣedca����������ʱ�� */
    hmac_vap->edca_opt_flag_sta = flag;

    if (hmac_vap->edca_opt_flag_sta == 0) {
        mac_vap_init_wme_param(mac_vap);
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "hmac_edca_opt_adj_param_sta succ");
    }

    /* ����EDCA��ص�MAC�Ĵ��� */
    ret = hmac_sta_up_update_edca_params_machw(hmac_vap, MAC_WMM_SET_PARAM_TYPE_UPDATE_EDCA);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY,
                         "hmac_config_set_edca_opt_switch_sta: hmac_sta_up_update_edca_params_machw failed");
        return ret;
    }

    oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_switch_sta,config sucess, %d",
                     hmac_vap->edca_opt_flag_sta);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��edca������������
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2014��12��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_edca_opt_switch_ap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 flag;
    hmac_vap_stru *hmac_vap = HI_NULL;

    /* ��ȡhmac_vap */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_switch_ap, hmac_vap_get_vap_stru fail.vap_id = %u",
                         mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ���ò��� */
    flag = *puc_param;

    /* ����û�и��ģ�����Ҫ�������� */
    if (flag == hmac_vap->edca_opt_flag_ap) {
        oam_warning_log1(0, OAM_SF_ANY, "wal_hipriv_set_edca_opt_switch_ap, change nothing to flag:%d",
                         hmac_vap->edca_opt_flag_ap);
        return HI_SUCCESS;
    }

    /* ���ò���������������ֹͣedca����������ʱ�� */
    if (flag == 1) {
        hmac_vap->edca_opt_flag_ap = 1;
        frw_timer_restart_timer(&(hmac_vap->edca_opt_timer), hmac_vap->us_edca_opt_time_ms, HI_TRUE);
    } else {
        hmac_vap->edca_opt_flag_ap = 0;
        frw_timer_stop_timer(&(hmac_vap->edca_opt_timer));
    }

    oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_switch_ap succ, flag = %d",
                     hmac_vap->edca_opt_flag_ap);

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ����edca��������
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2014��12��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_edca_opt_cycle_ap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u16 us_cycle_ms;
    hmac_vap_stru *hmac_vap = HI_NULL;

    /* ��ȡhmac_vap */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_cycle_ap, hmac_vap_get_vap_stru fail.vap_id = %u",
                         mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    us_cycle_ms = *((hi_u16 *)puc_param);

    /* �ж�edca���������Ƿ��и��� */
    if (us_cycle_ms == hmac_vap->us_edca_opt_time_ms) {
        oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_cycle_ap, change nothing to cycle:%d",
                         hmac_vap->us_edca_opt_time_ms);
        return HI_SUCCESS;
    }

    /* ���edca������ʱ���������У�����Ҫ��ֹͣ���ٸ����µĲ���restart */
    hmac_vap->us_edca_opt_time_ms = us_cycle_ms;
    if (hmac_vap->edca_opt_flag_ap == 1) {
        frw_timer_stop_timer(&(hmac_vap->edca_opt_timer));
        FRW_TIMER_RESTART_TIMER(&(hmac_vap->edca_opt_timer), hmac_vap->us_edca_opt_time_ms, HI_TRUE);
    }

    oam_warning_log1(0, OAM_SF_ANY, "hmac_config_set_edca_opt_cycle_ap succ, cycle = %d",
                     hmac_vap->us_edca_opt_time_ms);

    return HI_SUCCESS;
}

#endif

#ifdef _PRE_WLAN_FEATURE_STA_PM
/*****************************************************************************
 ��������  : 120S�͹��Ķ�ʱ����ʱ������
*****************************************************************************/
hi_u32 hmac_set_psm_timeout(hi_void *puc_para)
{
    hmac_vap_stru *hmac_vap = (hmac_vap_stru *)puc_para;
    hi_u32 auto_powersave_val = 0;

    auto_powersave_val |= PM_SWITCH_ON;
    auto_powersave_val |= PM_SWITCH_AUTO_FLAG << 16; /* ����16λ */
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)&&(_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    wlan_pm_set_timeout(WLAN_SLEEP_DEFAULT_CHECK_CNT);
#endif

    if (g_wlan_pm_on == HI_FALSE) {
        oam_warning_log0(0, OAM_SF_CFG, "{hmac_set_psm_timeout::pm off.}");
        return HI_FALSE;
    }
    oam_warning_log0(0, OAM_SF_CFG, "{hmac_set_psm_timeout::set pm}");
    /***************************************************************************
    ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    return hmac_config_send_event(hmac_vap->base_vap, WLAN_CFGID_SET_PM_SWITCH,
                                  sizeof(auto_powersave_val), (hi_u8 *)&auto_powersave_val);
}

/*****************************************************************************
 ��������  : �͹��Ŀ��ƽӿ�
 �������  : [1]mac_vap
             [2]pm_ctrl_type
             [3]pm_enable
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_pm_by_module(mac_vap_stru *mac_vap, mac_pm_ctrl_type_enum pm_ctrl_type,
                                    mac_pm_switch_enum pm_enable)
{
    hi_u32 ret;
    mac_cfg_ps_open_stru ps_open = { 0 };

    if (pm_enable >= MAC_STA_PM_SWITCH_BUTT || pm_ctrl_type >= MAC_STA_PM_CTRL_TYPE_BUTT || mac_vap == HI_NULL) {
        oam_error_log3(0, OAM_SF_ANY,
            "hmac_config_set_pm_by_module, PARAM ERROR! pst_mac_vap = %p, pm_ctrl_type = %d, pm_enable = %d ",
            (uintptr_t)mac_vap, pm_ctrl_type, pm_enable);
        return HI_FAIL;
    }

    ps_open.pm_enable = pm_enable;
    ps_open.pm_ctrl_type = pm_ctrl_type;

    ret = hmac_config_set_sta_pm_on(mac_vap, sizeof(mac_cfg_ps_open_stru), (hi_u8 *) &ps_open);
    oam_warning_log3(0, OAM_SF_PWR, "hmac_config_set_pm_by_module, pm_module = %d, pm_enable = %d, cfg ret = %d ",
                     pm_ctrl_type, pm_enable, ret);

    return ret;
}
#endif

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
/*****************************************************************************
 �� �� ��  : hmac_config_set_obss_scan_param
 ��������  : ����ͬ��obss scan��ص�mibֵ
 �������  : mac_vap_stru *pst_mac_vap
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��3��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_obss_scan_param(const mac_vap_stru *mac_vap)
{
    hi_u32 ret;

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_OBSS_MIB, sizeof(wlan_mib_dot11_operation_entry_stru),
                                 (hi_u8 *)&mac_vap->mib_info->wlan_mib_operation);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_obss_scan_param::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : dmac_offload�ܹ���ͬ��user����״̬��device��
 �޸���ʷ      :
  1.��    ��   : 2014��12��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_user_asoc_state_syn(const mac_vap_stru *mac_vap, const mac_user_stru *mac_user)
{
    hi_u32 ret;
    mac_h2d_user_asoc_state_stru h2d_user_asoc_state_stru;

    h2d_user_asoc_state_stru.user_idx = (hi_u8)mac_user->us_assoc_id;
    h2d_user_asoc_state_stru.asoc_state = mac_user->user_asoc_state;
    /***************************************************************************
        ���¼���DMAC��, ͬ��user����״̬��device��
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_USER_ASOC_STATE_SYN, sizeof(mac_h2d_user_asoc_state_stru),
                                 (hi_u8 *)(&h2d_user_asoc_state_stru));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_user_asoc_state_syn::send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : dmac_offload�ܹ���ͬ��user������Ϣ��device��
 �޸���ʷ      :
  1.��    ��   : 2015��3��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_user_rate_info_syn(const mac_vap_stru *mac_vap, const mac_user_stru *mac_user)
{
    hi_u32 ret;
    mac_h2d_usr_rate_info_stru mac_h2d_usr_rate_info;

    mac_h2d_usr_rate_info.user_idx = (hi_u8)mac_user->us_assoc_id;
    mac_h2d_usr_rate_info.protocol_mode = mac_user->protocol_mode;
    /* legacy���ʼ���Ϣ��ͬ����dmac */
    mac_h2d_usr_rate_info.avail_rs_nrates = mac_user->avail_op_rates.rs_nrates;
    if (memcpy_s(mac_h2d_usr_rate_info.auc_avail_rs_rates, WLAN_MAX_SUPP_RATES,
                 mac_user->avail_op_rates.auc_rs_rates, WLAN_MAX_SUPP_RATES) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_config_user_rate_info_syn:: auc_rs_rates memcpy_s fail.");
        return HI_FAIL;
    }
    /* ht���ʼ���Ϣ��ͬ����dmac */
    mac_user_get_ht_hdl(mac_user, &mac_h2d_usr_rate_info.ht_hdl);
    /***************************************************************************
        ���¼���DMAC��, ͬ��user����״̬��device��
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_USER_RATE_SYN, sizeof(mac_h2d_usr_rate_info_stru),
                                 (hi_u8 *)(&mac_h2d_usr_rate_info));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_user_rate_info_syn::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : dmac_offload�ܹ���ͬ��sta vap��Ϣ�� dmac
 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_sta_vap_info_syn(const mac_vap_stru *mac_vap)
{
    hi_u32 ret;
    mac_h2d_vap_info_stru mac_h2d_vap_info;

    mac_h2d_vap_info.us_sta_aid = mac_vap->us_sta_aid;
    mac_h2d_vap_info.uapsd_cap = mac_vap->uapsd_cap;
    /***************************************************************************
        ���¼���DMAC��, ͬ��VAP����״̬��DMAC
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_STA_VAP_INFO_SYN, sizeof(mac_h2d_vap_info_stru),
                                 (hi_u8 *)(&mac_h2d_vap_info));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_sta_vap_info_syn::hmac_config_sta_vap_info_syn failed[%d].}", ret);
    }
    return ret;
}

#endif /* #if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) */

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����VAP mibֵ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 _hmac_config_set_mib(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ���������VAP, ֱ�ӷ��� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{_hmac_config_set_mib::this is config vap! can't set.}");
        return HI_FAIL;
    }

    mac_config_set_mib(mac_vap, us_len, puc_param);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_MIB, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{_hmac_config_set_mib::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
#else
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ��ȡVAP mibֵ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 _hmac_config_get_mib(const mac_vap_stru *mac_vap, const hi_u8 *puc_param)
{
    hi_u32 mib_value;
    hi_u32 mib_idx = *((hi_u32 *)puc_param);

    switch (mib_idx) {
        case WLAN_MIB_INDEX_SPEC_MGMT_IMPLEMENT:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_implemented;
            break;

        case WLAN_MIB_INDEX_FORTY_MHZ_OPERN_IMPLEMENT:
            mib_value = (hi_u32) mac_mib_get_forty_mhz_operation_implemented(mac_vap);
            break;

        case WLAN_MIB_INDEX_2040_COEXT_MGMT_SUPPORT:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot112040_bss_coexistence_management_support;
            break;

        case WLAN_MIB_INDEX_FORTY_MHZ_INTOL:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_forty_m_hz_intolerant;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_TRIGGER_INTERVAL:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_bss_width_trigger_scan_interval;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_TRANSITION_DELAY_FACTOR:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_bss_width_channel_transition_delay_factor;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_PASSIVE_DWELL:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_passive_dwell;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_ACTIVE_DWELL:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_active_dwell;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_PASSIVE_TOTAL_PER_CHANNEL:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_passive_total_per_channel;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_ACTIVE_TOTAL_PER_CHANNEL:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_active_total_per_channel;
            break;

        case WLAN_MIB_INDEX_OBSSSCAN_ACTIVITY_THRESHOLD:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_activity_threshold;
            break;

#ifdef _PRE_WLAN_FEATURE_MESH
        case WLAN_MIB_INDEX_MESH_ACCEPTING_PEER:
            mib_value = (hi_u32) mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_accepting_additional_peerings;
            break;
#endif
        default:
            oam_error_log1(mac_vap->vap_id, OAM_SF_CFG, "{_hmac_config_get_mib::invalid ul_mib_idx[%d].}", mib_idx);
            return HI_FAIL;
    }

    oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{_hmac_config_get_mib::mib vaule=%d.}", mib_value);

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : �û��ı�ͬ����������
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_protection_update_from_user(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32                  ret;
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_PROTECTION_UPDATE_STA_USER, us_len, puc_param);
    if (ret != HI_SUCCESS) {
        hi_diag_log_msg_w0(0, "{hmac_config_set_protection::hmac_config_send_event_etc failed.}");
    }
    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_config_vap_state_syn
 ��������  : HMACͬ��vap״̬��DMAC
    ��    ��   : Hisilicon
*****************************************************************************/
hi_u32 hmac_config_vap_state_syn(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��VAP����״̬��DMAC
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_VAP_STATE_SYN, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_vap_state_syn::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return ret;
}

/*****************************************************************************
 ��������  : dmac offloadģʽ��hmac��dmacͬ��user cap info����������
 �޸���ʷ      :
  1.��    ��   : 2015��5��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_user_cap_syn(const mac_vap_stru *mac_vap, const mac_user_stru *mac_user)
{
    hi_u32 ret;
    mac_h2d_usr_cap_stru mac_h2d_usr_cap;

    mac_h2d_usr_cap.user_idx = (hi_u8)mac_user->us_assoc_id;
    if (memcpy_s((hi_u8 *)(&mac_h2d_usr_cap.user_cap_info), sizeof(mac_user_cap_info_stru),
                 (hi_u8 *)(&mac_user->cap_info), sizeof(mac_user_cap_info_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_config_user_cap_syn:: st_cap_info memcpy_s fail.");
        return HI_FAIL;
    }
    /***************************************************************************
        ���¼���DMAC��, ͬ��VAP����״̬��DMAC
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_USER_CAP_SYN, sizeof(mac_h2d_usr_cap_stru),
                                 (hi_u8 *)(&mac_h2d_usr_cap));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_user_cap_syn::send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : dmac_offload�ܹ���ͬ��sta usr��״̬��dmac
 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_user_info_syn(const mac_vap_stru *mac_vap, const mac_user_stru *mac_user)
{
    hi_u32 ret;
    mac_h2d_usr_info_stru mac_h2d_usr_info;

    mac_h2d_usr_info.avail_bandwidth = mac_user->avail_bandwidth;
    mac_h2d_usr_info.cur_bandwidth = mac_user->cur_bandwidth;
    mac_h2d_usr_info.user_idx = (hi_u8)mac_user->us_assoc_id;
    mac_h2d_usr_info.user_pmf = mac_user->cap_info.pmf_active;
    mac_h2d_usr_info.arg1 = mac_user->ht_hdl.max_rx_ampdu_factor;
    mac_h2d_usr_info.arg2 = mac_user->ht_hdl.min_mpdu_start_spacing;
    mac_h2d_usr_info.user_asoc_state = mac_user->user_asoc_state;

    /* Э��ģʽ��Ϣͬ����dmac */
    mac_h2d_usr_info.avail_protocol_mode = mac_user->avail_protocol_mode;

    mac_h2d_usr_info.cur_protocol_mode = mac_user->cur_protocol_mode;
    mac_h2d_usr_info.protocol_mode = mac_user->protocol_mode;
    mac_h2d_usr_info.bandwidth_cap = mac_user->bandwidth_cap;

    /***************************************************************************
        ���¼���DMAC��, ͬ��VAP����״̬��DMAC
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_USR_INFO_SYN, sizeof(mac_h2d_usr_info),
                                 (hi_u8 *)(&mac_h2d_usr_info));
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_user_info_syn::hmac_config_send_event failed[%d],user_id[%d].}", ret,
                         mac_user->us_assoc_id);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��ʼ���û��ļ��ܶ˿ڱ�־
 �޸���ʷ      :
  1.��    ��   : 2015��5��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_init_user_security_port(const mac_vap_stru *mac_vap, mac_user_stru *mac_user)
{
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hi_u32 ret;
    mac_cfg80211_init_port_stru init_port;
#endif
    /* ��ʼ����֤�˿���Ϣ */
    mac_vap_init_user_security_port(mac_vap, mac_user);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* dmac offloadģʽ��ͬ����device�� */
    if (memcpy_s(init_port.auc_mac_addr, OAL_MAC_ADDR_LEN, mac_user->user_mac_addr, OAL_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_init_user_security_port:: auc_user_mac_addr memcpy_s fail.");
        return HI_FAIL;
    }
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_INIT_SECURTIY_PORT, OAL_MAC_ADDR_LEN, (hi_u8 *) &init_port);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_WPA,
                       "{hmac_config_user_security_port::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����û�����״̬��offloadģʽ��ͬ����Ϣ��dmac
 �޸���ʷ      :
  1.��    ��   : 2015��5��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_user_set_asoc_state(const mac_vap_stru *mac_vap, mac_user_stru *mac_user,
                                mac_user_asoc_state_enum_uint8 value)
{
    mac_user_set_asoc_state(mac_user, value);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* dmac offload�ܹ��£�ͬ��user����״̬��Ϣ��dmac */
    hi_u32 ret = hmac_config_user_asoc_state_syn(mac_vap, mac_user);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_user_set_asoc_state::user_asoc_state_syn failed[%d].}", ret);
    }
    return ret;
#else
    hi_unref_param(mac_vap);
    return HI_SUCCESS;
#endif
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ���þۺ�������
 �޸���ʷ      :
  1.��    ��   : 2014��10��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_ampdu_aggr_num(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_AGGR_NUM, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_ampdu_aggr_num::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : ͨ������mibֵ, ����AP��STBC����
 �޸���ʷ      :
  1.��    ��   : 2014��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_stbc_cap(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 value = *puc_param;

    hi_unref_param(us_len);

    if (oal_unlikely(mac_vap->mib_info == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG,
                       "{hmac_config_set_stbc_cap::pst_mac_vap->pst_mib_info null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (value == 0) {
        mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_implemented = HI_FALSE;
        mac_vap->mib_info->phy_ht.dot11_rx_stbc_option_implemented = HI_FALSE;
        mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_activated = HI_FALSE;
    } else {
        mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_implemented = HI_TRUE;
        mac_vap->mib_info->phy_ht.dot11_rx_stbc_option_implemented = HI_TRUE;
        mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_activated = HI_TRUE;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) /*hi1131-cb set at both side (HMAC to DMAC) */
    return hmac_config_send_event(mac_vap, WLAN_CFGID_SET_STBC_CAP, us_len, puc_param);
#else
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ��һ��igmpv2 reprt����
 �������  : size��ʾ���ĳ��ȣ� ������̫��ͷ���� ������FCS�� ȡֵ��ΧӦ��Ϊ60~1514
 �޸���ʷ      :
  1.��    ��   : 2018��12��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
oal_netbuf_stru *hmac_config_create_igmp_packet(hi_u32 size,
                                                hi_u8 tid, const hi_u8 *ra_mac_addr, const hi_u8 *ta_mac_addr)
{
    oal_netbuf_stru *netbuf = HI_NULL;
    mac_ether_header_stru *ether_header = HI_NULL;
    mac_ip_header_stru *ip = HI_NULL;
    hi_u32 loop = 0;
    hi_u32 l_reserve = 256;
    mac_igmp_header_stru *igmp_hdr = HI_NULL; /* igmp header for v1 v2 */

    netbuf = oal_netbuf_alloc(size + l_reserve, l_reserve, 4);  /* align 4 */
    if (oal_unlikely(netbuf == HI_NULL) || (ta_mac_addr == HI_NULL)) {
        return HI_NULL;
    }

    oal_netbuf_put(netbuf, size);
    if (memcpy_s(&netbuf->data[0], WLAN_MAC_ADDR_LEN, ra_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oal_netbuf_free(netbuf);
        return HI_NULL;
    }
    if (memcpy_s(&netbuf->data[6], WLAN_MAC_ADDR_LEN, ta_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) { /* 6 Ԫ������ */
        oal_netbuf_free(netbuf);
        return HI_NULL;
    }
    /* ֡������ ���6���ֽڱ���Ϊ0x00 */
    for (loop = 0; loop < size - 50; loop++) { /* size��ȥ50 */
        netbuf->data[14 + loop] = (hi_u8) loop; /* ѭ��������14 */
    }

    ether_header = (mac_ether_header_stru *)oal_netbuf_data(netbuf);

    ether_header->us_ether_type = oal_host2net_short(ETHER_TYPE_IP);
    ip = (mac_ip_header_stru *)(ether_header + 1);     /* ƫ��һ����̫��ͷ��ȡipͷ */
    ip->version_ihl = 0x45;
    ip->protocol = IPPROTO_IGMP;
    ip->tos = (hi_u8) (tid << WLAN_IP_PRI_SHIFT);
    /* ָ��igmpͷָ�� */
    igmp_hdr = (mac_igmp_header_stru *)(ip + 1);
    igmp_hdr->type = MAC_IGMPV2_REPORT_TYPE;
    igmp_hdr->group = hi_swap_byteorder_32(0xe0804020);

    netbuf->next = HI_NULL;
    netbuf->prev = HI_NULL;

    if (memset_s(oal_netbuf_cb(netbuf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        oal_netbuf_free(netbuf);
        return HI_NULL;
    }

    return netbuf;
}

#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
hi_u32 hmac_vap_start_xmit_check(oal_net_device_stru *netdev)
{
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_vap_start_xmit::pst_dev = HI_NULL!}\r\n");
        oal_netbuf_free(netbuf);
        return HI_SUCCESS;
    }

    /* ��ȡVAP�ṹ�� */
    mac_vap_stru *mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);
    /* ���VAP�ṹ�岻���ڣ��������� */
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_vap_start_xmit::pst_vap = HI_NULL!}\r\n");
        oal_netbuf_free(netbuf);
        return HI_SUCCESS;
    }

    return HI_CONTINUE;
}

/*****************************************************************************
 ��������  : �ҽӵ�VAP��Ӧnet_device�ṹ���µķ��ͺ���
 �������  : pst_buf: SKB�ṹ��,����dataָ��ָ����̫��ͷ
             pst_dev: net_device�ṹ��
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2012��11��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
oal_net_dev_tx_enum hmac_vap_start_xmit(oal_netbuf_stru *netbuf, oal_net_device_stru *netdev)
{
    hi_u32 ret = hmac_vap_start_xmit_check(netdev);
    if (ret == HI_SUCCESS) {
        return OAL_NETDEV_TX_OK;
    }

    mac_vap_stru *mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);

    netbuf = oal_netbuf_unshare(netbuf);
    if (netbuf == HI_NULL) {
        oam_error_log0(0, OAM_SF_TX, "{wal_vap_start_xmit::the unshare netbuf = HI_NULL!}\r\n");
        return OAL_NETDEV_TX_OK;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_TX, "{wal_vap_start_xmit::pst_hmac_vap[%d] = HI_NULL!}", mac_vap->vap_id);
        oal_netbuf_free(netbuf);
        return OAL_NETDEV_TX_OK;
    }

    /* ��ֹ��������̫�࣬���������������������������۰�̫�࣬skb�ڴ治�ܼ�ʱ�ͷţ���������޸�Ϊ300��
       MIPS���ͺ����ֵ����̧�� */
    if (oal_netbuf_list_num(&hmac_vap->tx_queue_head[hmac_vap->in_queue_id]) >= 300) { /* 300 �����ж� */
        /* �ؼ�֡��100�����棬��֤�ؼ�֡���������� */
        if (oal_netbuf_list_num(&hmac_vap->tx_queue_head[hmac_vap->in_queue_id]) < 400) { /* 400 �����ж� */
            hi_u8 data_type;

            data_type = mac_get_data_type_from_8023((hi_u8 *)oal_netbuf_payload(netbuf), MAC_NETBUFF_PAYLOAD_ETH);
            if ((data_type == MAC_DATA_EAPOL) || (data_type >= MAC_DATA_DHCP_DISCOVER && data_type <= MAC_DATA_DHCP_ACK)
                || (data_type == MAC_DATA_ARP_REQ) || (data_type == MAC_DATA_ARP_RSP)) {
                hi_task_lock();
                OAL_NETBUF_QUEUE_TAIL(&(hmac_vap->tx_queue_head[hmac_vap->in_queue_id]), netbuf);
                hi_task_unlock();
            } else {
                oal_netbuf_free(netbuf);
            }
        } else {
            oal_netbuf_free(netbuf);
        }

        if (g_tx_debug) {
            /* ����ά����Ϣ����tx_event_num��ֵ��ӡ�������û��������ϣ�����һֱping��ͨ����g_tx_debug���أ�
               �����ʱ��ֵ��Ϊ1���������쳣 */
            oam_error_log1(mac_vap->vap_id, OAM_SF_TX, "{wal_vap_start_xmit::tx_event_num value is [%d].}",
                           (hi_s32) hi_atomic_read(&(hmac_vap->tx_event_num)));
            oal_io_print("wal_vap_start_xmit too fast\n");
        }
    } else {
        if (g_tx_debug) {
            oal_io_print("wal_vap_start_xmit enqueue and post event\n");
        }

        hi_task_lock();
        OAL_NETBUF_QUEUE_TAIL(&(hmac_vap->tx_queue_head[hmac_vap->in_queue_id]), netbuf);
        hi_task_unlock();
    }

    hmac_tx_post_event(mac_vap);

    return OAL_NETDEV_TX_OK;
}

#endif

hi_u32 hmac_bridge_vap_xmit_check(oal_netbuf_stru *netbuf, const oal_net_device_stru *netdev)
{
    if (oal_unlikely(netbuf == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{hmac_bridge_vap_xmit::pst_buf = HI_NULL!}\r\n");
        return HI_FAIL;
    }

    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{hmac_bridge_vap_xmit::pst_dev = HI_NULL!}\r\n");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    /* ��ȡVAP�ṹ��, ���VAP�ṹ�岻���ڣ��������� */
    mac_vap_stru *mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{hmac_bridge_vap_xmit::pst_vap = HI_NULL!}\r\n");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_bridge_vap_xmit::pst_hmac_vap null.}");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
    if (mac_vap->al_tx_flag == HI_SWITCH_ON) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_TX, "{hmac_bridge_vap_xmit::the vap alway tx/rx!}");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ҽӵ�VAP��Ӧnet_device�ṹ���µķ��ͺ���
 �������  : pst_buf: SKB�ṹ��,����dataָ��ָ����̫��ͷ
             pst_dev: net_device�ṹ��
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2012��11��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
oal_net_dev_tx_enum hmac_bridge_vap_xmit(oal_netbuf_stru *netbuf, oal_net_device_stru *netdev)
{
    if (hmac_bridge_vap_xmit_check(netbuf, netdev) == HI_FAIL) {
        return OAL_NETDEV_TX_OK;
    }

    mac_vap_stru *mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    netbuf = oal_netbuf_unshare(netbuf);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    netbuf = oal_netbuf_unshare(netbuf, GFP_ATOMIC);
#endif
    if (oal_unlikely(netbuf == HI_NULL)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_TX, "{hmac_bridge_vap_xmit::the unshare netbuf = HI_NULL!}");
        return OAL_NETDEV_TX_OK;
    }

#ifdef _PRE_WLAN_FEATURE_WOW
    /* wow ���˿��� */
    if (HI_TRUE == hmac_wow_tx_check_filter_switch()) {
        oal_netbuf_free(netbuf);
        return OAL_NETDEV_TX_OK;
    }
#endif

    /* �ж�VAP��״̬�����û��UP/PAUSE���������� */
    if (oal_unlikely(!((mac_vap->vap_state == MAC_VAP_STATE_UP) || (mac_vap->vap_state == MAC_VAP_STATE_PAUSE)))) {
        oam_info_log1(mac_vap->vap_id, OAM_SF_TX,
            "{hmac_bridge_vap_xmit::vap state[%d] != MAC_VAP_STATE_{UP|PAUSE}}", mac_vap->vap_state);
        oal_netbuf_free(netbuf);
        return OAL_NETDEV_TX_OK;
    }

#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    /* �ڽ�cb�ֶ�����ǰ����extflagȡ�� */
    hi_u16 us_pbuf_flags = *((hi_u16 *)(netbuf->cb));
#endif

    oal_netbuf_next(netbuf) = HI_NULL;
    oal_netbuf_prev(netbuf) = HI_NULL;

    /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(oal_netbuf_cb(netbuf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    /* ��cb �ֶ��е�extflag��ֵ */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
        /*
        us_pbuf_flags:
        |BIT13       |BIT12           |
        |Ctrl PKT    |Compressed 6lo  |
        */
        tx_ctl->pbuf_flags = (us_pbuf_flags & (PBUF_FLAG_6LO_PKT | PBUF_FLAG_CTRL_PKT)) >> 12; /* ����12λ */
    }
#endif

    hi_u32 ret_value = (hmac_tx_lan_to_wlan(mac_vap, netbuf) != HI_SUCCESS) ?
        OAL_NETDEV_TX_BUSY : OAL_NETDEV_TX_OK;
    if (oal_unlikely(ret_value != OAL_NETDEV_TX_OK)) {
        hmac_free_netbuf_list(netbuf);
    }

    return OAL_NETDEV_TX_OK;
}

/*****************************************************************************
 ��������  : ɨ����ֹ
 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_scan_abort(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    hmac_device_stru *hmac_dev = HI_NULL;
    hi_u32 ret;

    oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                     "{hmac_config_scan_abort::vap_id[%d] scan abort.}", mac_vap->vap_id);

    hmac_dev = hmac_get_device_stru();

    /* ���·�����ANYɨ�裬����ɨ���ʱ��ָ���־Ϊ��ANYɨ�裬���·��ķ�ANYɨ�裬���︳��ֵ��Ӱ�� */
    hmac_dev->scan_mgmt.scan_record_mgmt.is_any_scan = HI_FALSE;

    /* BEGIN:DTS2015113002518 1102 ��Ϊap ��40M ������ִ��ɨ�裬ɨ����ɺ�VAP ״̬�޸�Ϊɨ��ǰ��״̬ */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_config_scan_abort::pst_hmac_vap is null, vap_id[%d].}", mac_vap->vap_id);
        return HI_ERR_CODE_MAC_DEVICE_NULL;
    }

    if (((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
         || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        ) && (hmac_dev->scan_mgmt.scan_record_mgmt.vap_last_state != MAC_VAP_STATE_BUTT)) {
        oam_warning_log1(0, OAM_SF_SCAN,
                         "{hmac_config_scan_abort::en_vap_last_state:%d}",
                         hmac_dev->scan_mgmt.scan_record_mgmt.vap_last_state);
        hmac_fsm_change_state(hmac_vap, hmac_dev->scan_mgmt.scan_record_mgmt.vap_last_state);
        hmac_dev->scan_mgmt.scan_record_mgmt.vap_last_state = MAC_VAP_STATE_BUTT;
    }
    /* END:DTS2015113002518 1102 ��Ϊap ��40M ������ִ��ɨ�裬ɨ����ɺ�VAP ״̬�޸�Ϊɨ��ǰ��״̬ */
    /* ���ɨ�����ϱ��Ļص������������ϱ� */
    if (hmac_dev->scan_mgmt.scan_record_mgmt.vap_id == mac_vap->vap_id) {
        hmac_dev->scan_mgmt.scan_record_mgmt.fn_cb = HI_NULL;
        /* DTS2015091100571 ɨ����ֹʱ��ֱ�����ɨ���־,����ȴ�devcie�ϱ�ɨ���������� */
        hmac_dev->scan_mgmt.is_scanning = HI_FALSE;
    }

    /***************************************************************************
                         ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SCAN_ABORT, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_config_scan_abort::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  :host���ѯstation info
 �������  : pst_mac_vap: mac_vap_stru
             us_len       : ��������
             puc_param    : ����
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2014��11��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_query_station_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_QUERY_STATION_STATS, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_phy_stat_info::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

#ifdef _PRE_WLAN_FEATURE_BTCOEX
/*****************************************************************************
 ��������  : ����ɾ��BA�Ự
 �޸���ʷ      :
  1.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_btcoex_delba_foreach_tid(mac_vap_stru *mac_vap, const mac_user_stru *mac_user,
                                            mac_cfg_delba_req_param_stru *mac_cfg_delba_param)
{
    hi_u32 ret = 0;

    if (memcpy_s(mac_cfg_delba_param->auc_mac_addr, WLAN_MAC_ADDR_LEN,
                 mac_user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_btcoex_delba_foreach_tid::mem safe function err!}");
        return HI_FAIL;
    }

    for (mac_cfg_delba_param->tidno = 0; mac_cfg_delba_param->tidno < WLAN_TID_MAX_NUM;
         mac_cfg_delba_param->tidno++) {
        ret = hmac_config_delba_req(mac_vap, 0, (hi_u8 *)mac_cfg_delba_param);
        if (ret != HI_SUCCESS) {
            oam_warning_log2(mac_vap->vap_id, OAM_SF_COEX,
                             "{hmac_btcoex_delba_foreach_tid::ul_ret: %d, tid: %d}", ret,
                             mac_cfg_delba_param->tidno);
            return ret;
        }
    }
    return ret;
}

/*****************************************************************************
 ��������  : hmacɾ��BA
 �޸���ʷ      :
  1.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_btcoex_delba_foreach_user(mac_vap_stru *mac_vap)
{
    hi_u32 ret = 0;
    mac_cfg_delba_req_param_stru mac_cfg_delba_param;
    mac_user_stru *mac_user = HI_NULL;
    hi_u8 user_idx;
    hi_list *entry = HI_NULL;
    mac_res_user_hash_stru *res_hash = HI_NULL;

    mac_cfg_delba_param.direction = MAC_RECIPIENT_DELBA;

    for (user_idx = 0; user_idx < MAC_VAP_USER_HASH_MAX_VALUE; user_idx++) {
        hi_list_for_each(entry, &(mac_vap->ast_user_hash[user_idx])) {
            res_hash = (mac_res_user_hash_stru *)entry;

            mac_user = mac_user_get_user_stru(res_hash->user_idx);
            if (mac_user == HI_NULL) {
                oam_warning_log1(mac_vap->vap_id, OAM_SF_COEX,
                                 "{hmac_btcoex_delba_foreach_user::pst_mac_user null, user_idx: %d.}",
                                 res_hash->user_idx);
                entry = res_hash->entry.next;
                continue;
            }
            ret = hmac_btcoex_delba_foreach_tid(mac_vap, mac_user, &mac_cfg_delba_param);
            if (ret != HI_SUCCESS) {
                return ret;
            }
        }
    }

    return ret;
}

/*****************************************************************************
 ��������  : hmacɾ��BA
 �޸���ʷ      :
  1.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_btcoex_rx_delba_trigger(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hmac_device_stru *hmac_dev = HI_NULL;
    d2h_btcoex_delba_event_stru *d2h_btcoex_delba = HI_NULL;
    hi_u32 ret;

    hi_unref_param(len);

    hmac_dev = hmac_get_device_stru();
    d2h_btcoex_delba = (d2h_btcoex_delba_event_stru *)puc_param;

    hmac_dev->d2h_btcoex_delba.need_delba = d2h_btcoex_delba->need_delba;
    hmac_dev->d2h_btcoex_delba.ba_size = d2h_btcoex_delba->ba_size;
    if (hmac_dev->d2h_btcoex_delba.need_delba) {
        ret = hmac_btcoex_delba_foreach_user(mac_vap);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(mac_vap->vap_id, OAM_SF_COEX, "{hmac_btcoex_syn:delba send failed:ul_ret: %d}",
                             ret);
            return ret;
        }
    }
    return HI_SUCCESS;
}
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : reg_info test
 �޸���ʷ      :
  1.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_wifitest_get_reg_info(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hmac_reg_info_receive_event *dmac_reg_info_response_event = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;

    hi_unref_param(len);

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_wifitest_get_reg_info::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_vap = hmac_vap->base_vap;
    dmac_reg_info_response_event = (hmac_reg_info_receive_event *)puc_param;
    g_hmac_reg_info_receive_event.reg_info_num = dmac_reg_info_response_event->reg_info_num;
    if (g_hmac_reg_info_receive_event.reg_info_num > REG_INFO_MAX_NUM) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY, "hmac_wifitest_get_reg_info:: reg numb is out of range[%d]",
                       g_hmac_reg_info_receive_event.reg_info_num);
        return HI_FAIL;
    }
    while (dmac_reg_info_response_event->reg_info_num) {
        g_hmac_reg_info_receive_event.val[dmac_reg_info_response_event->reg_info_num - 1] =
            dmac_reg_info_response_event->val[dmac_reg_info_response_event->reg_info_num - 1];
        dmac_reg_info_response_event->reg_info_num--;
    }

    g_hmac_reg_info_receive_event.flag = HI_TRUE;
    hi_wait_queue_wake_up_interrupt(&(hmac_vap->query_wait_q));

    return HI_SUCCESS;
}
#endif
#endif

/*****************************************************************************
 ��������  : ������ս��
 �޸���ʷ      :
  1.��    ��   : 2019��6��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_rx_fcs_info(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *param)
{
    hi_u32 succ_num;
    if (mac_vap == HI_NULL || param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_get_rx_fcs_info::pst_mac_vap[%p] NULL or pst_param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)param);
        return HI_ERR_CODE_PTR_NULL;
    }
    hi_unref_param(len);
    hi_unref_param(mac_vap);

    succ_num = *((hi_u32 *)param);
    /* ��ɾ,�Զ���������Ҫ�� */
#ifdef CUSTOM_AT_COMMAND
    hi_at_printf("+RXINFO:%d\r\n", succ_num);
    hi_at_printf("OK\r\n");
#endif
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
    printk("+RXINFO:%d\r\n", succ_num);
    printk("OK\r\n");
#endif
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MFG_TEST
hi_u32 hmac_print_ate_paras(const oal_at_rsp_stru *rsp, const hi_u8 *param, hi_u8 len)
{
    if ((len < ((OAL_AT_ATE_PARAS_BUTT + 1) << 2)) || (rsp->data_num != OAL_AT_ATE_PARAS_BUTT)) { /* 2:ÿ���ֶ�4�ֽ� */
        printk("ERROR\r\nReport data len invalid,len %d, data_num %d\r\n", len, rsp->data_num);
        return HI_FAIL;
    }
    hi_u32 *data = (hi_u32 *)(param + sizeof(oal_at_rsp_stru));
    printk("+RCALDATA:Efuse cali chance(s) left:%d times.\r\n", *((hi_s32 *)&data[OAL_AT_ATE_PARAS_USED_CNT]));
    printk("+RCALDATA:freq_offset %d\r\n", *((hi_s32 *)&data[OAL_AT_ATE_PARAS_FREQ_OFFSET]));
    printk("+RCALDATA:band_pwr_offset_0 %d\r\n", *((hi_s32 *)&data[OAL_AT_ATE_PARAS_BPWR_OFFSET_0]));
    printk("+RCALDATA:band_pwr_offset_1 %d\r\n", *((hi_s32 *)&data[OAL_AT_ATE_PARAS_BPWR_OFFSET_1]));
    printk("+RCALDATA:band_pwr_offset_2 %d\r\n", *((hi_s32 *)&data[OAL_AT_ATE_PARAS_BPWR_OFFSET_2]));

    printk("+RCALDATA:rate_pwr_offset_11n 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_OFFSET_11N]);
    printk("+RCALDATA:rate_pwr_offset_11g 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_OFFSET_11G]);
    printk("+RCALDATA:rate_pwr_offset_11b 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_OFFSET_11B]);
    printk("+RCALDATA:dbb_scale_0 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_SCALE_0]);
    printk("+RCALDATA:dbb_scale_1 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_SCALE_1]);
    printk("+RCALDATA:dbb_scale_2 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_SCALE_2]);
    printk("+RCALDATA:dbb_scale_3 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_SCALE_3]);
    printk("+RCALDATA:dbb_scale_4 0x%x\r\n", data[OAL_AT_ATE_PARAS_DBB_SCALE_4]);
    printk("+RCALDATA:freq_and_band_pwr_hybrid_offset 0x%x\r\n", data[OAL_AT_ATE_PARAS_HYBRID_DATA]);

    return HI_SUCCESS;
}

hi_u32 hmac_print_ate_mac(const oal_at_rsp_stru *rsp, const hi_u8 *param, hi_u8 len)
{
    if ((len < ((OAL_AT_ATE_MAC_BUTT + 1) << 2)) || (rsp->data_num != OAL_AT_ATE_MAC_BUTT)) { /* 2:ÿ���ֶ�4�ֽ� */
        printk("ERROR\r\nReport data len invalid,len %d, data_num %d\r\n", len, rsp->data_num);
        return HI_FAIL;
    }
    hi_u8 *mac = (hi_u8 *)(param + sizeof(oal_at_rsp_stru));

    printk("+EFUSEMAC:%02x:%02x:%02x:%02x:%02x:%02x\r\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); /* 0 1 2 3 4 5��mac��ַƫ�� */
    hi_u32 *times_left = (hi_u32 *)(param + sizeof(oal_at_rsp_stru) + AT_ATE_MAC_SIZE);
    printk("+EFUSEMAC:Efuse mac chance(s) left:%d times.\r\n", *times_left); /* ʣ��д�������� */

    return HI_SUCCESS;
}

hi_u32 hmac_report_mfg_test(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *param)
{
    if (mac_vap == HI_NULL || param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_config_set_pm_switch::pst_mac_vap[%p] NULL or pst_param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)param);
        return HI_ERR_CODE_PTR_NULL;
    }
    hi_unref_param(mac_vap);

    if (len < sizeof(oal_at_rsp_stru)) {
        printk("ERROR\r\nRsp format error\r\n");
        return HI_SUCCESS;
    }
    oal_at_rsp_stru *rsp = (oal_at_rsp_stru *)param;
    if (rsp->result != 0) { /* ʧ�� */
        printk("ERROR\r\n");
        return HI_SUCCESS;
    } else if (rsp->num != 0) { /* ���ӡ���� */
        switch (rsp->num) {
            case AT_RSP_ATE_PARAS:
                if (hmac_print_ate_paras(rsp, param, len) != HI_SUCCESS) {
                    return HI_SUCCESS;
                }
                break;
            case AT_RSP_ATE_MAC:
                if (hmac_print_ate_mac(rsp, param, len) != HI_SUCCESS) {
                    return HI_SUCCESS;
                }
                break;
            default:
                printk("ERROR\r\nInvalid rsp num %d\r\n", rsp->result);
                return HI_SUCCESS;
        }
    }
    printk("OK\r\n");
    return HI_SUCCESS;
}
#endif

hi_u32 hmac_report_mac_from_efuse(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *param)
{
    frw_event_mem_stru         *event_mem = HI_NULL;
    frw_event_stru             *event = HI_NULL;
    hi_u32                      ret;
    hi_unref_param(len);

    if (param == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_report_mac_from_efuse::puc_param is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���¼���WAL */
    event_mem = frw_event_alloc(ETHER_ADDR_LEN);
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_report_mac_from_efuse::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CTX,
                       HMAC_HOST_CTX_EVENT_GET_MAC_FROM_EFUSE,
                       WLAN_MAC_ADDR_LEN,
                       FRW_EVENT_PIPELINE_STAGE_0,
                       mac_vap->vap_id);

    if (memcpy_s(event->auc_event_data, WLAN_MAC_ADDR_LEN, param, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_report_mac_from_efuse:: param memcpy fail.");
        return HI_FAIL;
    }
     /* �ַ��¼���WAL�� */
    ret = frw_event_dispatch_event(event_mem);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_report_mac_from_efuse::frw_event_dispatch_event fail[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }
    frw_event_free(event_mem);
    return HI_SUCCESS;
}

hi_u32 hmac_config_report_tx_params(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *param)
{
    frw_event_mem_stru         *event_mem = HI_NULL;
    frw_event_stru             *event = HI_NULL;
    hi_u32                      ret;

    hi_unref_param(len);

    if (param == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_report_theory_goodput::puc_param is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���¼���WAL */
    event_mem = frw_event_alloc(sizeof(hamc_config_report_tx_params_stru) * WLAN_WME_AC_BUTT);
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_report_theory_goodput::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CTX,
                       HMAC_HOST_CTX_EVENT_REPORT_TX_PARAMS,
                       sizeof(hamc_config_report_tx_params_stru) * WLAN_WME_AC_BUTT,
                       FRW_EVENT_PIPELINE_STAGE_0,
                       mac_vap->vap_id);

    if (memcpy_s(event->auc_event_data, sizeof(hamc_config_report_tx_params_stru) * WLAN_WME_AC_BUTT, param,
        sizeof(hamc_config_report_tx_params_stru) * WLAN_WME_AC_BUTT) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_config_report_theory_goodput:: param memcpy fail.");
        return HI_FAIL;
    }

     /* �ַ��¼���WAL�� */
    ret = frw_event_dispatch_event(event_mem);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_report_theory_goodput::frw_event_dispatch_event fail[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }

    frw_event_free(event_mem);
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MFG_TEST
hi_u32 hmac_report_dbg_cal_data_from_dev(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *param)
{
    frw_event_mem_stru         *event_mem = HI_NULL;
    frw_event_stru             *event = HI_NULL;
    hi_u32                      ret;
    hi_unref_param(len);
    const hi_u8 data_size = 28;  /* 28:7������ֵ��ÿ��4�ֽ� */
    if (mac_vap == HI_NULL || param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_report_dbg_cal_data_from_dev::mac_vap[%p] NULL or param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)param);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���¼���WAL */
    event_mem = frw_event_alloc(data_size);
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_report_dbg_cal_data_from_dev::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CTX,
                       HMAC_HOST_CTX_EVENT_GET_DBG_CAL_DATA,
                       WLAN_MAC_ADDR_LEN,
                       FRW_EVENT_PIPELINE_STAGE_0,
                       mac_vap->vap_id);

    if (memcpy_s(event->auc_event_data, data_size, param, data_size) != EOK) {
        oam_error_log0(0, 0, "hmac_report_dbg_cal_data_from_dev:: memcpy_s fail.");
        return HI_FAIL;
    }
     /* �ַ��¼���WAL�� */
    ret = frw_event_dispatch_event(event_mem);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_report_dbg_cal_data_from_dev::frw_event_dispatch_event fail[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }
    frw_event_free(event_mem);
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : hmac����dmac�׻����Ĳ�ѯRSSIӦ��
 �޸���ʷ      :
  1.��    ��   : 2019��6��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32  hmac_proc_query_rssi_response(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    wlan_rssi_stru *rssi_param = HI_NULL;

    hi_unref_param(len);
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_proc_query_rssi_response::mac_vap[%p] NULL or pst_puc_param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_query_response::pst_hmac_vap null.}");
        return HI_FAIL;
    }

    rssi_param = (wlan_rssi_stru *)puc_param;
    hmac_vap->ap_rssi = rssi_param->rssi;
    hmac_vap->query_ap_rssi_flag = HI_TRUE;
    hi_wait_queue_wake_up_interrupt(&(hmac_vap->query_wait_q));

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_STA_UAPSD
/*****************************************************************************
 ��������  : sta uspad ��������
 �޸���ʷ      :
  1.��    ��   : 2015��2��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_uapsd_para(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_uapsd_sta_stru *uapsd_param = HI_NULL;
    mac_device_stru *mac_dev = HI_NULL;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hi_u32 ret;
#endif

    /* wmm */
    mac_dev = mac_res_get_dev();
    if (mac_dev->wmm == HI_FALSE) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_set_uapsd_para::wmm is off, not support uapsd mode}");
        return HI_FAIL;
    }

    /* mesh */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_PWR, "{hmac_config_set_uapsd_para::vap mode mesh,not support uapsd!}");
        return HI_FAIL;
    }

    /* խ�� */
    if ((mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_5M) ||
        (mac_vap->channel.en_bandwidth == WLAN_BAND_WIDTH_10M)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_PWR,
                         "{hmac_config_set_uapsd_para::narrow band[%dM] mode,not support uapsd!}",
                         mac_vap->channel.en_bandwidth);
        return HI_FAIL;
    }

    uapsd_param = (mac_cfg_uapsd_sta_stru *)puc_param;
    if (uapsd_param->max_sp_len >= MAC_APSD_SP_LEN_BUTT) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_PWR, "{hmac_config_set_uapsd_para::uc_max_sp_len[%d] > 6!}",
                       uapsd_param->max_sp_len);
        return HI_FAIL;
    }
    mac_vap_set_uapsd_para(mac_vap, uapsd_param);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /***************************************************************************
        ���¼���DMAC��, ͬ��VAP����״̬��DMAC
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_UAPSD_PARA, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_uapsd_para::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }
#else
    hi_unref_param(us_len);
#endif
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_STA_PM
/*****************************************************************************
 ��������  : ����staut�͹���ģʽ
 �޸���ʷ      :
  1.��    ��   : 2015��10��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_sta_pm_mode(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    return hmac_config_sync_cmd_common(mac_vap, WLAN_CFGID_SET_PS_MODE, us_len, puc_param);
}

/*****************************************************************************
 ��������  : ��staut�͹���
 �޸���ʷ      :
  1.��    ��   : 2015��10��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 _hmac_config_set_sta_pm_on(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_PWR, "{_hmac_config_set_sta_pm_on::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���·��򿪵͹��� */
    return hmac_config_sync_cmd_common(mac_vap, WLAN_CFGID_SET_STA_PM_ON, us_len, puc_param);
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 hmac_config_set_psm_offset(mac_vap_stru *mac_vap, hi_u16 len, const hi_u8 *param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_PSM_OFFSET, len, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id,
                         OAM_SF_CFG,
                         "{hmac_config_set_psm_offset::hmac_config_send_event failed[%d].}",
                         ret);
    }

    return ret;
}

hi_u32 hmac_config_set_sta_hw_ps_mode(mac_vap_stru *mac_vap, hi_u16 len, const hi_u8 *param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_STA_HW_PS_MODE, len, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id,
                         OAM_SF_CFG,
                         "{hmac_config_set_sta_hw_ps_mode::hmac_config_send_event failed[%d].}",
                         ret);
    }

    return ret;
}
#endif
#endif

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
/*****************************************************************************
 ��������  : ��ȡ����������ӡ��host�࣬�����Զ����ű���ȡ���
 �޸���ʷ      :
  1.��    ��   : 2015��2��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_thruput_info(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hi_unref_param(mac_vap);
    hi_unref_param(len);
    dmac_thruput_info_sync_stru *thruput_info = HI_NULL;

    thruput_info = (dmac_thruput_info_sync_stru *)puc_param;

    if (thruput_info != HI_NULL) {
        oal_io_print1("interval cycles: %u \n", thruput_info->cycles);
        oal_io_print1("sw tx succ num: %u \n", thruput_info->sw_tx_succ_num);
        oal_io_print1("sw tx fail num: %u \n", thruput_info->sw_tx_fail_num);
        oal_io_print1("sw rx ampdu succ num: %u \n", thruput_info->sw_rx_ampdu_succ_num);
        oal_io_print1("sw rx mpdu succ num: %u \n", thruput_info->sw_rx_mpdu_succ_num);
        oal_io_print1("sw rx fail num: %u \n", thruput_info->sw_rx_ppdu_fail_num);
        oal_io_print1("hw rx ampdu fcs fail num: %u \n", thruput_info->hw_rx_ampdu_fcs_fail_num);
        oal_io_print1("hw rx mpdu fcs fail num: %u \n", thruput_info->hw_rx_mpdu_fcs_fail_num);
        return HI_SUCCESS;
    } else {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_get_thruput_info::pst_thruput_info null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
}
#endif

#ifdef _PRE_WLAN_FEATURE_PMF
/*****************************************************************************
 ��������  : chip testǿ������pmf�������ҶԹ������vapҲ��Ч
 �޸���ʷ      :
  1.��    ��   : 2015��1��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_enable_pmf(mac_vap_stru *mac_vap, hi_u8 *puc_param)
{
    hi_u8 pmf_active;
    hi_list *entry = HI_NULL;
    hi_list *user_list_head = HI_NULL;
    mac_user_stru *user_tmp = HI_NULL;

    oal_io_print("hmac_enable_pmf: func start!");
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "hmac_enable_pmf:: pointer is null: pst_mac_vap[%p],puc_param[%p]",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    wlan_pmf_cap_status_uint8 *puc_pmf_cap = (wlan_pmf_cap_status_uint8 *)puc_param;

    switch (*puc_pmf_cap) {
        case MAC_PMF_DISABLED:
            mac_mib_set_dot11_rsnamfpr(mac_vap, HI_FALSE);
            mac_mib_set_dot11_rsnamfpc(mac_vap, HI_FALSE);
            mac_mib_set_dot11_rsnaactivated(mac_vap, HI_FALSE);
            pmf_active = HI_FALSE;
            break;
        case MAC_PMF_ENABLED:
            mac_mib_set_dot11_rsnamfpr(mac_vap, HI_FALSE);
            mac_mib_set_dot11_rsnamfpc(mac_vap, HI_TRUE);
            mac_mib_set_dot11_rsnaactivated(mac_vap, HI_TRUE);
            return HI_SUCCESS;
        case MAC_PME_REQUIRED:
            mac_mib_set_dot11_rsnamfpr(mac_vap, HI_TRUE);
            mac_mib_set_dot11_rsnamfpc(mac_vap, HI_TRUE);
            mac_mib_set_dot11_rsnaactivated(mac_vap, HI_TRUE);
            pmf_active = HI_TRUE;
            break;
        default:
            oal_io_print("hmac_enable_pmf: commend error!");
            return HI_FALSE;
    }

    if (mac_vap->vap_state == MAC_VAP_STATE_UP) {
        user_list_head = &(mac_vap->mac_user_list_head);

        for (entry = user_list_head->next; entry != user_list_head;) {
            user_tmp = hi_list_entry(entry, mac_user_stru, user_dlist);

            /* ָ��˫��������һ���ڵ� */
            entry = entry->next;
            if (user_tmp == HI_NULL) { // user_tmp��Ϊ�յĿ��ܣ��󱨸澯��lin_t e774�澯����
                oam_error_log0(0, OAM_SF_ANY, "hmac_enable_pmf:: pst_user_tmp is null");
                return HI_ERR_CODE_PTR_NULL;
            }
            mac_user_set_pmf_active(user_tmp, pmf_active);
        }
    }

    oal_io_print("hmac_enable_pmf: func end!");

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
/*****************************************************************************
 ��������      : ����ARP offload��Ϣ

 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_arp_offload_setting(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ����DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_ARP_OFFLOAD_SETTING, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_arp_offload_setting::hmac_config_send_event fail[%d].", ret);
    }

    return ret;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������      : ��ʾDevice���¼��IP��ַ

 �޸���ʷ      :
  1.��    ��   : 2015��8��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_arp_offload_show_info(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ����DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_ARP_OFFLOAD_SHOW_INFO, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_arp_offload_show_info::hmac_config_send_event fail[%d].", ret);
    }

    return ret;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_DHCP_OFFLOAD
/*****************************************************************************
 ��������      : ����IP��ַ��Ϣ

 �޸���ʷ      :
  1.��    ��   : 2019��10��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_dhcp_offload_setting(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ����DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DHCP_OFFLOAD_SETTING, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_config_dhcp_offload_setting::hmac_config_send_event fail[%d].", ret);
    }

    return ret;
}
#endif

#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
/*****************************************************************************
 ��������  : cfg vap h2d
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_cfg_vap_h2d(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(us_len);
    hi_u32 ret;
    mac_device_stru *mac_dev = HI_NULL;

    if (oal_unlikely((mac_vap == HI_NULL) || (puc_param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_CFG, "{hmac_config_add_vap::param null,pst_vap=%d puc_param=%d.}", (uintptr_t)mac_vap,
                       (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_dev = mac_res_get_dev();
    /***************************************************************************
    ���¼���DMAC��, ����dmac cfg vap
    ***************************************************************************/
    ret = hmac_cfg_vap_send_event(mac_dev);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_CFG, "{hmac_cfg_vap_send_event::hmac_config_send_event fail[%d].", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  :
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_pm_cfg_param(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_PM_CFG_PARAM, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_pm_cfg_param::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_cus_rf(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_CUS_RF, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cus_rf::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_cus_dts_cali(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_CUS_DTS_CALI, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cus_dts_cali::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_cus_nvram_params(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_CUS_NVRAM_PARAM, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cus_nvram_params::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

hi_u32 hmac_config_set_cus_fcc_tx_params(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_CUS_FCC_TX_PWR, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cus_fcc_tx_params::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

#ifdef _PRE_XTAL_FREQUENCY_COMPESATION_ENABLE
hi_u32 hmac_config_set_freq_comp(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_FREQ_COMP, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_freq_comp::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
/*****************************************************************************
 ��������  : ����ҵ��ʶ���ܿ���
 �� �� ֵ  : ������
 �޸���ʷ      :
  1.��    ��   : 2015��11��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_tx_classify_switch(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 flag;
    hmac_vap_stru *hmac_vap = HI_NULL;

    /* ��ȡhmac_vap */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_config_set_tx_classify_switch::hmac_vap_get_vap_stru fail.vap_id[%u]}",
                         mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ���ò��� */
    flag = *puc_param;

    /* ����û�и��ģ�����Ҫ�������� */
    if (flag == hmac_vap->tx_traffic_classify_flag) {
        oam_warning_log1(0, OAM_SF_ANY,
                         "hmac_config_set_tx_classify_switch::change nothing to flag:%d",
                         hmac_vap->tx_traffic_classify_flag);
        return HI_SUCCESS;
    }

    /* ���ò������� */
    hmac_vap->tx_traffic_classify_flag = flag;

    if (hmac_vap->tx_traffic_classify_flag == HI_SWITCH_OFF) {
        oam_warning_log0(0, OAM_SF_ANY,
                         "hmac_config_set_tx_classify_switch::flag = HI_SWITCH_OFF(0)");
        return HI_SUCCESS;
    } else if (hmac_vap->tx_traffic_classify_flag == HI_SWITCH_ON) {
        oam_warning_log0(0, OAM_SF_ANY,
                         "hmac_config_set_tx_classify_switch::flag = HI_SWITCH_ON(1)");
        return HI_SUCCESS;
    }

    return HI_FAIL;
}
#endif /* _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN */

/*****************************************************************************
 ��������  : ��sta device �͹���
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_sta_pm_on(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_cfg_ps_open_stru *sta_pm_open = HI_NULL;

    if (oal_unlikely((mac_vap == HI_NULL) || (puc_param == HI_NULL))) {
        oam_warning_log0(0, OAM_SF_PWR, "{wal_config_set_sta_pm_on::pst_mac_vap / puc_param null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_PWR,
                         "{wal_config_set_sta_pm_on::pst_hmac_vap null,vap state[%d].}", mac_vap->vap_state);
        return HI_ERR_CODE_PTR_NULL;
    }
    sta_pm_open = (mac_cfg_ps_open_stru *)puc_param;

    /* ����ϲ�����dhcp�ɹ���ʱȡ����ʱ���͹��ĵĶ�ʱ�� */
    if ((hmac_vap->ps_sw_timer.is_registerd == HI_TRUE)
        && (sta_pm_open->pm_enable > MAC_STA_PM_SWITCH_OFF)) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->ps_sw_timer));
    }

    return _hmac_config_set_sta_pm_on(mac_vap, us_len, puc_param);
}

#ifdef _PRE_WLAN_FEATURE_STA_PM
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 hmac_config_set_pm_param(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ����߼�����: ����bcn timeoutʱ��Ҫvap up,����ᵼ��bcn timeout�ж��޷���� */
    if (mac_vap->vap_state != MAC_VAP_STATE_UP) {
        oam_warning_log0(0, OAM_SF_PWR, "hmac_config_set_pm_param: need up vap first.");
        return HI_FAIL;
    }
    return hmac_config_sync_cmd_common(mac_vap, WLAN_CFGID_SET_PSM_PARAM, us_len, puc_param);
}
#endif
#endif

hi_u32 hmac_config_open_wmm(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 wmm = *(hi_u8 *)puc_param;
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    mac_device_stru *mac_dev = mac_res_get_dev();
    mac_dev->wmm = wmm;
    mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented = wmm;
    mac_vap->voice_aggr = !wmm;
#endif

    if ((wmm == HI_FALSE) && (mac_vap->cap_flag.uapsd == HI_TRUE)) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_open_wmm::config uapsd mode, not support turn off wmm}");
        return HI_FAIL;
    }

    return hmac_config_sync_cmd_common(mac_vap, WLAN_CFGID_WMM_SWITCH, us_len, puc_param);
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����VAP mibֵ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_mib(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    return _hmac_config_set_mib(mac_vap, us_len, puc_param);
}

/*****************************************************************************
 �� �� ��  : wal_config_get_mib
 ��������  : ��ȡVAP mibֵ
 �������  : ��
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_get_mib(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(us_len);
    return _hmac_config_get_mib(mac_vap, puc_param);
}
#endif

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  : Mesh �����û�״̬
 �޸���ʷ      :
  1.��    ��   : 2019��1��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_mesh_user(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8  user_index = 0;
    mac_cfg_set_mesh_user_param_stru *set_mesh = (mac_cfg_set_mesh_user_param_stru *)puc_param;
    hi_unref_param(us_len);

    /* �ж�����Ϊ�����û�����/�����û� */
    if (set_mesh->set == HI_SWITCH_OFF) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_set_mesh_user::not support add user.}");
        return HI_FAIL;
    } else {
        if (mac_vap_find_user_by_macaddr(mac_vap, set_mesh->auc_addr, WLAN_MAC_ADDR_LEN, &user_index) != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_UM, "{hmac_config_set_mesh_user::find_user failed}");
            return HI_FAIL;
        }
    }

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_index);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_UM, "{hmac_config_set_mesh_user::pst_hmac_user null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (hmac_user->base_user->is_mesh_user == HI_FALSE) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_UM, "{hmac_config_set_mesh_user::isNot meshUser,unsupport set state}");
        return HI_FAIL;
    }

    /* ��ȡ�ϲ��·�������״ֵ̬ */
    switch (set_mesh->plink_sta) {
        case HISI_PLINK_ESTAB:
            /* �����û�Я����beacon��probe rsp�е����ȼ� */
            hmac_user->has_rx_mesh_confirm = HI_FALSE;
            hmac_user->base_user->bcn_prio = set_mesh->bcn_prio;
            hmac_user->base_user->is_mesh_mbr = set_mesh->is_mbr;
            /* ��־���û��ڹ����׶����Ƿ�Ϊ�����ɫ */
            hmac_user->base_user->mesh_initiative_role = set_mesh->mesh_initiative_peering;
            /* Mesh��ESTAB״̬��Ϊ�����ɹ� */
            mac_user_set_asoc_state(hmac_user->base_user, MAC_USER_STATE_ASSOC);
            /* ֪ͨ�㷨 */
            hmac_user_add_notify_alg(mac_vap, user_index);

            /* ֪ͨDmac��Ӱ����� */
            hi_u32 ret = hmac_set_multicast_user_whitelist(mac_vap, set_mesh->auc_addr, WLAN_MAC_ADDR_LEN);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(mac_vap->vap_id, OAM_SF_UM, "{hmac_config_set_mesh_user::set whitelist fail=%d}", ret);
                return ret;
            }
            oam_warning_log1(hmac_user->base_user->vap_id, OAM_SF_ASSOC,
                "{hmac_config_set_mesh_user::mesh assoc mesh HI_SUCCESS! user_indx=%d.}", user_index);
            break;
        default:
            break;
    }
    return HI_SUCCESS;
}

hi_u32 hmac_config_encap_mesh_frame(mac_vap_stru *mac_vap, mac_action_data_stru *action_data,
    oal_netbuf_stru *data, hi_u8 us_action_code, hi_u32 *len)
{
    if (memset_s(oal_netbuf_cb(data), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]memset_s fail.}");
        oal_netbuf_free(data);
        goto error_handle;
    }

    if (memset_s((hi_u8 *)oal_netbuf_header(data), MAC_80211_FRAME_LEN, 0, MAC_80211_FRAME_LEN) != EOK) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]memset_s fail.}");
        oal_netbuf_free(data);
        goto error_handle;
    }

    if (us_action_code == MAC_SP_ACTION_MESH_PEERING_OPEN) {
        *len = hmac_encap_mesh_peering_open_frame(mac_vap, (oal_netbuf_header(data)), action_data);
    } else if (us_action_code == MAC_SP_ACTION_MESH_PEERING_CONFIRM) {
        *len = hmac_encap_mesh_peering_confirm_frame(mac_vap, (oal_netbuf_header(data)), action_data);
    } else if (us_action_code == MAC_SP_ACTION_MESH_PEERING_CLOSE) {
        *len = hmac_encap_mesh_peering_close_frame(mac_vap, (oal_netbuf_header(data)), action_data);
    } else if (us_action_code == MAC_SP_ACTION_MESH_GROUP_KEY_INFORM) {
        *len = hmac_encap_mesh_group_key_inform_frame(mac_vap, (oal_netbuf_header(data)), action_data);
    } else if (us_action_code == MAC_SP_ACTION_MESH_GROUP_KEY_ACK) {
        *len = hmac_encap_mesh_group_key_ack_frame(mac_vap, (oal_netbuf_header(data)), action_data);
    } else {
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY,
            "{hmac_config_send_mesh_action::[MESH]unsupported self-protected action code:%d}", us_action_code);
        goto error_handle;
    }

    if ((*len) == 0) {
        /* ��֡ʧ�� */
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]encap_mesh_frame Err}");
        oal_netbuf_free(data);
        goto error_handle;
    }
    oal_netbuf_put(data, *len);

    /* Ϊ��д����������׼������ */
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(data);
    tx_ctl->us_mpdu_len         = *len;    /* dmac������Ҫ��mpdu���� */
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header        = (mac_ieee80211_frame_stru *)oal_netbuf_header(data);
    tx_ctl->mac_head_type       = 1;

    mac_vap_set_cb_tx_user_idx(mac_vap, tx_ctl, action_data->puc_dst);

    oam_warning_log3(mac_vap->vap_id, OAM_SF_ANY,
        "{hmac_config_send_mesh_action::[MESH]Send Mesh Self-Protected Action[%d] to user [X:X:X:X:%x:%x].}",
        us_action_code, action_data->puc_dst[4], action_data->puc_dst[5]); /* 4 5 Ԫ������ */

    return HI_SUCCESS;

error_handle:
    /* �ͷ��ϲ������puc_data�ռ� */
    if (action_data->data_len > 0) {
        oal_free(action_data->puc_data);
        action_data->puc_data = HI_NULL;
    }

    return HI_FAIL;
}

hi_u32 hmac_config_mesh_send_event(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user,
    mac_action_data_stru *action_data, oal_netbuf_stru *data, hi_u32 len)
{
    hi_u8  us_action_code;
    hi_u32 ret;

    us_action_code = mac_get_action_code(action_data->puc_data);
    ret = hmac_tx_mgmt_send_event(mac_vap, data, len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(data);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]send_event Err%d}", ret);

        /* �ͷ��ϲ������puc_data�ռ� */
        if (action_data->data_len > 0) {
            oal_free(action_data->puc_data);
            action_data->puc_data = HI_NULL;
        }

        return HI_FAIL;
    }

    /* ����״̬ */
    if ((us_action_code == MAC_SP_ACTION_MESH_PEERING_OPEN) && (hmac_user != HI_NULL)) {
        hmac_user_set_asoc_state(mac_vap, hmac_user->base_user, MAC_USER_STATE_AUTH_COMPLETE);
    }

    /* �ͷ��ϲ������puc_data�ռ� */
    if (action_data->data_len > 0) {
        oal_free(action_data->puc_data);
        action_data->puc_data = HI_NULL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : Mesh ����Action ֡
 �޸���ʷ      :
  1.��    ��   : 2019��2��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_send_mesh_action(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8           user_index = 0;
    hi_u32          len = 0;
    hmac_user_stru *hmac_user = HI_NULL;

    hi_unref_param(us_len);

    mac_action_data_stru *action_data = (mac_action_data_stru *)puc_param;
    hmac_vap_stru        *hmac_vap    = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_send_mesh_action::pst_hmac_vap null.}");
        goto error_handle;
    }

    /* ��ȡAction category ��code */
    hi_u8 us_category    = mac_get_action_category(action_data->puc_data);
    hi_u8 us_action_code = mac_get_action_code(action_data->puc_data);
    if (us_category != MAC_ACTION_CATEGORY_SELF_PROTECTED) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_send_mesh_action::action category is wrong.}");
        goto error_handle;
    }

    hi_u32 ret = mac_vap_find_user_by_macaddr(mac_vap, action_data->puc_dst, WLAN_MAC_ADDR_LEN, &user_index);
    /* Mesh Peering Close֡�������û����͵�������յ�һ����δ�����ýڵ㷢����֡ */
    if (us_action_code != MAC_SP_ACTION_MESH_PEERING_CLOSE) {
        /* �ҵ��û� */
        if (ret != HI_SUCCESS) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]cannot find user}");
            goto error_handle;
        }

        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_index);
        if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]hmac/base user null}");
            goto error_handle;
        }

        if (hmac_user->base_user->is_mesh_user == HI_FALSE) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_UM, "{hmac_config_send_mesh_action::[MESH]is_mesh_user Err}");
            goto error_handle;
        }
    }

    /* ����ռ� */
    oal_netbuf_stru *data = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);   /* align 4 */
    if (data == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_config_send_mesh_action::[MESH]puc_data null.}");
        goto error_handle;
    }

    if (hmac_config_encap_mesh_frame(mac_vap, action_data, data, us_action_code, &len) != HI_SUCCESS) {
        return HI_FAIL;
    }

    return hmac_config_mesh_send_event(mac_vap, hmac_user, action_data, data, len);

error_handle:
    /* �ͷ��ϲ������puc_data�ռ� */
    if (action_data->data_len > 0) {
        oal_free(action_data->puc_data);
    }

    return HI_FAIL;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ���÷��ʹ����ϱ����Ʋ���(����ʹ��)
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_report_times_limit(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        return HI_FALSE;
    }

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_REPORT_TIMES_LIMIT, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_report_times_limit::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ���÷��ʹ����ϱ����Ʋ���(����ʹ��)
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_report_cnt_limit(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        return HI_FALSE;
    }

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_REPORT_CNT_LIMIT, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_report_cnt_limit::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : hmac��ȡmeshid
 �������  : event_hdr: �¼�ͷ
                            us_len       : ��������
                            puc_param    : ����
 �� �� ֵ  : hi_u32 ������
 �޸���ʷ      :
  1.��    ��   : 2019��3��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_meshid(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    /* ��ȡmibֵ */
    return mac_mib_get_meshid(mac_vap, (hi_u8 *)pus_len, puc_param);
}

/*****************************************************************************
 ��������  : hmac��meshid
 �������  : event_hdr: �¼�ͷ
                            us_len       : ��������
                            puc_param    : ����
 �� �� ֵ  : hi_u32 ������
 �޸���ʷ      :
  1.��    ��   : 2019��3��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_meshid(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    return hmac_config_send_event(mac_vap, WLAN_CFGID_MESHID, us_len, puc_param);
#else
    /* ����mibֵ */
    mac_mib_set_meshid(mac_vap, (hi_u8) us_len, puc_param);
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ����mesh Hisi-optimization�ֶ�
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_beacon_priority(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    hi_u8 priority;

    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_config_set_beacon_priority::pst_mac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_beacon_priority::not Mesh vap!.}");
        return HI_FAIL;
    }
    priority = *puc_param;

    oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_beacon_priority:: lwip set prioriy: %d}", priority);

    mac_vap->priority = priority;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_BEACON_PRIORITY, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_beacon_priority::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����mesh vap ��mnid
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_mnid(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_MNID, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_mnid::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����mesh vap Ϊmbr
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_en_mbr(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_MBR_EN, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_en_mbr::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : mesh�ϱ�new peer candidate�¼���wpa
 �������  : [1]event_mem
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_mesh_report_new_peer_candidate(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    frw_event_hdr_stru *event_hdr = HI_NULL;
    dmac_tx_event_stru *dtx_event = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u32 us_payload_len;
    hi_u32 ret;
    oal_netbuf_stru *netbuf = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_mesh_report_new_peer_candidate::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ�¼�ͷ���¼��ṹ��ָ�� */
    event = (frw_event_stru *)event_mem->puc_data;
    event_hdr = &(event->event_hdr);
    dtx_event = (dmac_tx_event_stru *)event->auc_event_data;
    netbuf = dtx_event->netbuf;

    mac_vap = mac_vap_get_vap_stru(event_hdr->vap_id);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_mesh_report_new_peer_candidate::pst_mac_vap null.}");

        /* �ͷ��ϱ���beacon���ڴ� */
        oal_netbuf_free(netbuf);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����Mesh Beacon���� */
    us_payload_len = dtx_event->us_frame_len;
    ret = hmac_config_new_peer_candidate_event(mac_vap, netbuf, us_payload_len);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "hmac_mesh_report_new_peer_candidate:report to wpa fail,ret = %d!", ret);
    }

    /* �ͷ��ϱ���beacon���ڴ� */
    oal_netbuf_free(netbuf);

    return ret;
}

/*****************************************************************************
 ��������  : meshͨ��wpa���mesh�û�
 �������  : mac_vap_stru *pst_mac_vap, hi_u8 uc_len, hi_u8 *puc_param
 �޸���ʷ      :
  1.��    ��   : 2019��5��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_add_mesh_user(mac_vap_stru *mac_vap, hi_u16 len, const hi_u8 *puc_param)
{
    mac_cfg_set_mesh_user_param_stru *add_mesh_user = HI_NULL;
    hi_u8                             user_index;
    hmac_user_stru                   *hmac_user = HI_NULL;
    hi_u32                            ret;
    mac_vap_stru                     *mac_vap_tmp = HI_NULL;
    hi_unref_param(len);

    add_mesh_user = (mac_cfg_set_mesh_user_param_stru *)puc_param;

    /* �ж�����Ϊ�����û�����/�����û� */
    if (add_mesh_user->set == HI_SWITCH_ON) {
        oam_warning_log0(0, OAM_SF_UM, "{hmac_config_add_mesh_user::not support set user state.}");
        return HI_FAIL;
    }
    /* mesh ���ж�accepting peer��ֵ��Ϊfalse������Զ�˽��� */
    if (mac_mib_get_accepting_peer(mac_vap) == HI_FALSE) {
        hi_diag_log_msg_w0(0, "{hmac_config_add_mesh_user::Mesh is not ready to accept peer connect.}");
        return HI_FAIL;
    }
    /* ����ͬһdevice�µ�����VAP���ҵ����û���ɾ��֮��������ҵ��ͨ����DBAC�����䳣�� */
    if (mac_device_find_user_by_macaddr(mac_vap, add_mesh_user->auc_addr, WLAN_MAC_ADDR_LEN,
        &user_index) == HI_SUCCESS) {
        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_index);
        if ((hmac_user != HI_NULL) && (hmac_user->base_user != HI_NULL)) {
            mac_vap_tmp = mac_vap_get_vap_stru(hmac_user->base_user->vap_id);
            if (mac_vap_tmp != HI_NULL) {
                hmac_user_del(mac_vap_tmp, hmac_user);
            }
        }
    }
    ret = hmac_user_add(mac_vap, add_mesh_user->auc_addr, WLAN_MAC_ADDR_LEN, &user_index);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_add_mesh_user::hmac_user_add failed[%d].}", ret);
        return ret;
    }

    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_index);
    if (hmac_user == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_UM, "{hmac_config_add_mesh_user::pst_hmac_user null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_user->base_user->is_mesh_user = HI_TRUE;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : mesh����new peer candidate��ʹ��
 �������  : mac_vap_stru *pst_mac_vap, hi_u8 uc_len, hi_u8 *puc_param
 �޸���ʷ      :
  1.��    ��   : 2019��6��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_new_peer_candidate_en(mac_vap_stru *mac_vap, hi_u16 len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    mac_device_stru *mac_dev = mac_res_get_dev();
    mac_vap_stru *mac_vap_first = HI_NULL;
    mac_vap_stru *mac_vap_second = HI_NULL;

    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        return HI_FALSE;
    }

    ret = mac_device_find_2up_vap(mac_dev, &mac_vap_first, &mac_vap_second);
    if (ret == HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_UM,
            "{hmac_config_new_peer_candidate_en::current mode is mbr,unsupport en auto-peer.}");
        return HI_FAIL;
    }
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_NEW_PEER_CONFIG_EN, len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_new_peer_candidate_en::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����mesh uc_accept_sta
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_mesh_accept_sta(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 accept_sta;
    hi_unref_param(us_len);

    accept_sta = *puc_param;

    mac_vap->mesh_accept_sta = accept_sta;

    return HI_SUCCESS;
}

/****************************************************************************
 ��������  : ����mesh�û���gtk
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_mesh_user_gtk(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_MESH_USER_GTK, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_mesh_user_gtk::[MESH]hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ����mesh accept peer
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_accept_peer(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u8 accept_peer;
    hi_unref_param(us_len);

    accept_peer = *puc_param;

    mac_mib_set_accepting_peer(mac_vap, accept_peer);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��new peer candidate�¼��ϱ�wpa
 �������  : mac_vap_stru *mac_vap, oal_netbuf_stru *beacon_netbuf, hi_u16 us_frame_len
 �� �� ֵ  : hi_u32
 �޸���ʷ      :
  1.��    ��   : 2019��8��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_new_peer_candidate_event(const mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf,
                                            hi_u32 payload_len)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u8 *puc_ie_payload = HI_NULL;
    hi_u8 *puc_payload = HI_NULL;
    hmac_rx_ctl_stru *cb = HI_NULL;
    mac_mesh_conf_ie_stru *mesh_conf_ie = HI_NULL;
    mac_ieee80211_frame_stru *frame_header = HI_NULL;
    hmac_report_new_peer_candidate_stru *wal_new_peer = HI_NULL;
    hi_u32 ret;

    puc_payload = (hi_u8 *)oal_netbuf_data(netbuf);
    cb = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    frame_header = (mac_ieee80211_frame_stru *)puc_payload;

    /* Probe Rsp��Beacon֡��ǰ��ΪTimestamp,beacon interval,capability�ֶΣ���tlv�ṹ������ֱ������mac_find_ie������
      �˴�����ƫ�ƣ���Element IDΪ0��SSID��Ϊ��ʼ��ַ����ָ��IE */
    puc_ie_payload = puc_payload + MAC_80211_FRAME_LEN;

    if (payload_len > MAC_SSID_OFFSET) {
        /* ����Mesh Configuration Element������ȡAccepting Peer�ֶ�ֵ */
        mesh_conf_ie = (mac_mesh_conf_ie_stru *)mac_find_ie(MAC_EID_MESH_CONF,
            puc_ie_payload + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN,
            payload_len - MAC_SSID_OFFSET);
    }
    if (mesh_conf_ie == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    event_mem = frw_event_alloc(sizeof(hmac_report_new_peer_candidate_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_mesh_report_new_peer_candidate::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;

    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_HOST_CTX, HMAC_HOST_CTX_EVENT_SUB_TYPE_NEW_PEER_CANDIDATE,
                       sizeof(hmac_report_new_peer_candidate_stru), FRW_EVENT_PIPELINE_STAGE_0, mac_vap->vap_id);

    wal_new_peer = (hmac_report_new_peer_candidate_stru *)(event->auc_event_data);
    wal_new_peer->bcn_prio = mac_get_hisi_beacon_prio(puc_ie_payload, (hi_s32)payload_len);
    wal_new_peer->accept_sta = mac_get_hisi_accept_sta(puc_ie_payload, (hi_s32)payload_len);
    wal_new_peer->is_mbr = mac_get_hisi_en_is_mbr(puc_ie_payload, (hi_s32)payload_len);
    wal_new_peer->link_num = mesh_conf_ie->mesh_formation_info.number_of_peerings;

    /* ���¼����޷������з��������������ֵrssi��Ҫ����Ϊ�޷�����������ʹ�õ�ʱ����ǿת -g- */
    wal_new_peer->rssi = (hi_u8)(cb->rssi_dbm);

    if (memcpy_s(wal_new_peer->auc_mac_addr, OAL_MAC_ADDR_LEN,
                 frame_header->auc_address2, OAL_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_mesh_report_new_peer_candidate:: auc_mac_addr memcpy_s fail.");
        frw_event_free(event_mem);
        return HI_FAIL;
    }

    /* �ַ��¼� */
    ret = frw_event_dispatch_event(event_mem);
    frw_event_free(event_mem);

    return ret;
}

/*****************************************************************************
 ��������  : hmac��ȡmesh�ڵ���Ϣ
 �޸���ʷ      :
  1.��    ��   : 2019��11��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_mesh_nodeinfo(mac_vap_stru *mac_vap, hi_u16 *pus_len, hi_u8 *puc_param)
{
    mac_cfg_mesh_nodeinfo_stru *param = HI_NULL;

    param = (mac_cfg_mesh_nodeinfo_stru *)puc_param;

    if (memset_s(param, sizeof(mac_cfg_mesh_nodeinfo_stru), 0, sizeof(mac_cfg_mesh_nodeinfo_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_config_get_mesh_nodeinfo:: memset_s fail.");
        return HI_FAIL;
    }
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) && (mac_vap->is_conn_to_mesh == HI_TRUE)) {
        param->node_type = MAC_HISI_MESH_STA;
    } else if ((mac_vap->vap_mode == WLAN_VAP_MODE_MESH) && (mac_vap->is_mbr == HI_FALSE)) {
        param->node_type = MAC_HISI_MESH_MG;
    } else if ((mac_vap->vap_mode == WLAN_VAP_MODE_MESH) && (mac_vap->is_mbr == HI_TRUE)) {
        param->node_type = MAC_HISI_MESH_MBR;
    } else {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_get_mesh_nodeinfo::unspec mesh node type.}");
        param->node_type = MAC_HISI_MESH_UNSPEC;
        *pus_len = sizeof(mac_cfg_mesh_nodeinfo_stru);
        return HI_SUCCESS;
    }
    param->privacy = mac_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked;
    param->mesh_accept_sta = mac_vap->mesh_accept_sta;
    param->priority = mac_vap->priority;
    param->user_num = mac_vap->user_nums;
    param->chan = mac_vap->channel.chan_number;

    *pus_len = sizeof(mac_cfg_mesh_nodeinfo_stru);

    oam_warning_log2(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_get_mesh_nodeinfo::node type=%d, chan=%d.}",
                     param->node_type, param->chan);

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ����vap �ش�������
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32 hmac_config_set_retry_limit(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RETRY_LIMIT, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_config_set_retry_limit::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

#ifdef FEATURE_DAQ
/*****************************************************************************
 ��������  : ��ȡ���ݲɼ����
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_data_acq_result(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32                   ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DATA_ACQ_REPORT, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_data_acq_result::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : �������ݲɼ����
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_data_acq_result(mac_vap_stru *mac_vap, hi_u8 us_len, const hi_u8 *puc_param)
{
    wlan_acq_result_addr_stru  *data_result_addr = HI_NULL;

    hi_unref_param(us_len);

    data_result_addr = (wlan_acq_result_addr_stru *)puc_param;

    oam_unrom_w_log4(mac_vap->vap_id, 0, "{hmac_get_data_acq_result::0x%x,0x%x,0x%x,0x%x}",
                     data_result_addr->start_addr, data_result_addr->middle_addr1,
                     data_result_addr->middle_addr2, data_result_addr->end_addr);

    return hmac_send_event_to_host(mac_vap, (const hi_u8*)data_result_addr,
        sizeof(wlan_acq_result_addr_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_ACQ_RESULT);
}

/*****************************************************************************
 ��������  : ��ѯ���ݲɼ�״̬
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_data_acq_status(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32                   ret;

    hi_unref_param(us_len);
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DATA_ACQ_STATUS, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_data_acq_status::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : �������ݲɼ�״̬
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_data_acq_status(mac_vap_stru *mac_vap, hi_u8 us_len, const hi_u8 *puc_param)
{
    hi_u8                value;

    hi_unref_param(us_len);

    value = *((hi_u8 *)puc_param);
    oam_warning_log1(mac_vap->vap_id, 0, "{hmac_get_data_acq_status::en_value[%d]}", value);

    return hmac_send_event_to_host(mac_vap, (const hi_u8*)(&value),
        sizeof(hi_u8), HMAC_HOST_CTX_EVENT_SUB_TYPE_ACQ_STATUS);
}

/*****************************************************************************
 ��������  : �������ݲɼ���Ϣ
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_data_acq_start(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32                   ret;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_DATA_ACQ_START, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_data_acq_start::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

#ifdef _PRE_WLAN_FEATURE_BW_HIEX
/*****************************************************************************
 ��������  : ����խ���л����������selfcts�Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2019��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_hiex_set_selfcts(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    wlan_selfcts_param_stru *param = HI_NULL;
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hi_u32          ret;
#endif

    param = (wlan_selfcts_param_stru *)puc_param;
    mac_vap->selfcts = param->selfcts;
    mac_vap->duration = param->duration;
    mac_vap->us_per = param->us_per;
    oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG,
        "{hmac_config_hiex_set_selfcts::enable[%d] duration[%d] per[%d].}",
        mac_vap->selfcts, mac_vap->duration, mac_vap->us_per);
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_SELFCTS, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_COEX,
                         "{hmac_config_hiex_set_selfcts::send event return err code [%d].}", ret);
        return ret;
    }
#else
    hi_unref_param(us_len);
#endif

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_MFG_TEST
/*****************************************************************************
 ��������  : �Ը�band��ƽ�����ʲ��������ݲ����¼���dmac
 �������  : [1]mac_vap
             [2]len �¼����ݵ����ݳ���
             [3]puc_param �¼����ݵ�����ָ��
 �������  : ��
 �� �� ֵ  : �¼������Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 hmac_config_set_cal_band_power(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ���¼���DMAC��, ͬ��DMAC���� */
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CAL_BAND_POWER, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cal_band_power::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ��������ݲ����¼���dmac
 �������  : [1]mac_vap
             [2]len �¼����ݵ����ݳ���
             [3]puc_param �¼����ݵ�����ָ��
 �������  : ��
 �� �� ֵ  : �¼������Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 hmac_config_set_cal_rate_power(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ���¼���DMAC��, ͬ��DMAC���� */
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CAL_RATE_POWER, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cal_rate_power::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ���г���Ƶƫ���ʲ��������ݲ����¼���dmac
 �������  : [1]mac_vap
             [2]len �¼����ݵ����ݳ���
             [3]puc_param �¼����ݵ�����ָ��
 �������  : ��
 �� �� ֵ  : �¼������Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 hmac_config_set_cal_freq(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /* ���¼���DMAC��, ͬ��DMAC���� */
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_CAL_FREQ, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cal_freq::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :MAC ���� EFUSE
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_efuse_mac(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_GET_EFUSE_MAC, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_get_efuse_mac::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  :MAC ���� EFUSE
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_efuse_mac(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_EFUSE_MAC, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_efuse_mac::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :��У׼ֵд��EFUSE
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2015��10��22��
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_dataefuse(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_DATAEFUSE, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_dataefuse::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :��ȡУ׼����
 �޸���ʷ      :
  1.��    ��   : 2020��03��09��
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_get_cal_data(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_GET_CAL_DATA, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_get_cal_data::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  :���÷��͹���ƫ��
 �޸���ʷ      :
  1.��    ��   : 2020��3��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_tx_pwr_offset(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_TX_PWR_OFFSET, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_tx_pwr_offset::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  :����cca��ֵ
 �� �� ֵ  : HI_SUCCESS �� ʧ�ܴ�����
 �޸���ʷ      :
  1.��    ��   : 2020��1��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_set_cca_th(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_CCA_TH, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_cca_th::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

hi_u32 hmac_config_get_efuse_mac_addr(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_GET_EFUSE_MAC_ADDR, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
            "{hmac_config_get_efuse_mac_addr::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

#if defined(_PRE_WLAN_FEATURE_HIPRIV) && defined(_PRE_WLAN_FEATURE_INTRF_MODE)
hi_u32 hmac_config_set_intrf_mode(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_INTRF_MODE_ON, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_set_intrf_mode::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}
#endif

hi_u32 hmac_config_notify_get_tx_params(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_NOTIFY_GET_TX_PARAMS, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_notify_get_goodput::hmac_config_send_event failed[%d].}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  :���Ϳ�������(ע��:������һ������Ƶ����)
 �޸���ʷ      :
  1.��    ��   : 2020��07��11��
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_config_minimize_boot_current(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    hi_u32 ret = hmac_config_send_event(mac_vap, WLAN_CFGID_MINIMIZE_BOOT_CURRET, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_config_minimize_boot_current::hmac_config_send_event failed[%d].}", ret);
    }
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
