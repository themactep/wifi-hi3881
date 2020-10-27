/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: AP mode framing file, framing of AP mode-specific frames.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_frame.h"
#include "mac_user.h"
#include "mac_vap.h"
#include "mac_mib.h"
#include "dmac_ext_if.h"
#include "hmac_config.h"
#include "hmac_encap_frame_ap.h"
#include "hmac_main.h"
#include "hmac_tx_data.h"
#include "hmac_mgmt_ap.h"
#include "hmac_11i.h"
#include "hmac_blockack.h"
#include "frw_timer.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ��װchtxt
 �޸���ʷ      :
  1.��    ��   : 2013��7��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_mgmt_encap_chtxt(hi_u8 *puc_frame, const hi_u8 *puc_chtxt,
                                     hi_u16 *pus_auth_rsp_len, hmac_user_stru *hmac_user)
{
    /* Challenge Text Element                  */
    /* --------------------------------------- */
    /* |Element ID | Length | Challenge Text | */
    /* --------------------------------------- */
    /* | 1         |1       |1 - 253         | */
    /* --------------------------------------- */
    puc_frame[6] = MAC_EID_CHALLENGE; /* 6 Ԫ������ */
    puc_frame[7] = WLAN_CHTXT_SIZE; /* 7 Ԫ������ */

    /* ��֤֡��������Challenge Text Element�ĳ��� */
    *pus_auth_rsp_len += (WLAN_CHTXT_SIZE + MAC_IE_HDR_LEN);
    /* ��challenge text������֡����ȥ */
    hi_u32 ret = (hi_u32)memcpy_s(&puc_frame[8], WLAN_CHTXT_SIZE, puc_chtxt, WLAN_CHTXT_SIZE); /* 8 ��ս�ֶ���ʼ��ַ */
    if (ret != EOK) {
        oam_error_log1(0, OAM_SF_CFG, "hmac_mgmt_encap_chtxt:: challenge text memcpy fail, ret[%d].", ret);
        return;
    }
    /* �������ĵ�challenge text */
    if (hmac_user->ch_text == HI_NULL) {
        /* �˴�ֻ������������֤�ɹ����߳�ʱ��ʱ���ͷ� */
        hmac_user->ch_text = (hi_u8 *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, WLAN_CHTXT_SIZE);
    }

    if (hmac_user->ch_text != HI_NULL) {
        ret = (hi_u32)memcpy_s(hmac_user->ch_text, WLAN_CHTXT_SIZE, puc_chtxt, WLAN_CHTXT_SIZE);
        if (ret != EOK) {
            oam_error_log1(0, OAM_SF_CFG, "hmac_mgmt_encap_chtxt:: save challenge text fail, ret[%d].", ret);
            return;
        }
    }
}

#ifdef _PRE_WLAN_FEATURE_PMF
/*****************************************************************************
 ��������  : ����õ� assoc rsp �������assoc comeback time
 �������  : pst_mac_vap   : mac vap ָ��
             pst_hmac_user : hamc user ָ��
 �� �� ֵ  : ����õ���assoc comeback timeֵ
 �޸���ʷ      :
  1.��    ��   : 2014��4��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_get_assoc_comeback_time(const mac_vap_stru *mac_vap, const hmac_user_stru *hmac_user)
{
    hi_u32 timeout = 0;

    hi_u32 now_time;
    hi_u32 passed_time;
    hi_u32 sa_query_maxtimeout;

    /* ��ȡ����ʱ�� */
    now_time = (hi_u32) hi_get_milli_seconds();

    /* ����ASSOCIATION_COMEBACK_TIME��ʹSTA��AP���SA Query����֮���ٷ��͹������� */
    /* ���sa Query Max timeoutֵ */
    sa_query_maxtimeout = mac_mib_get_dot11_association_saquery_maximum_timeout(mac_vap);

    /* �Ƿ�������sa Query�������ڽ��� */
    if ((hmac_user->sa_query_info.sa_query_interval_timer.is_enabled == HI_TRUE) &&
        (now_time >= hmac_user->sa_query_info.sa_query_start_time)) {
        /* ������SA Query���̽�����ſ��Խ���STA�������Ĺ���֡ */
        passed_time = now_time - hmac_user->sa_query_info.sa_query_start_time;
        timeout = sa_query_maxtimeout - passed_time;
    } else {
        /* ����������SA Query����Ԥ��ʱ�� */
        timeout = sa_query_maxtimeout;
    }

    return timeout;
}
#endif

hi_void  hmac_set_supported_rates_ie_asoc_rsp(const mac_user_stru *mac_user, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    hi_u8 nrates;
    hi_u8 idx;
    /**************************************************************************
                        ---------------------------------------
                        |Element ID | Length | Supported Rates|
                        ---------------------------------------
             Octets:    |1          | 1      | 1~8            |
                        ---------------------------------------
    The Information field is encoded as 1 to 8 octets, where each octet describes a single Supported
    Rate or BSS membership selector.
    **************************************************************************/
    puc_buffer[0] = MAC_EID_RATES;
    nrates = mac_user->avail_op_rates.rs_nrates;

    if (nrates > MAC_MAX_SUPRATES) {
        nrates = MAC_MAX_SUPRATES;
    }

    for (idx = 0; idx < nrates; idx++) {
        puc_buffer[MAC_IE_HDR_LEN + idx] = mac_user->avail_op_rates.auc_rs_rates[idx];
    }

    puc_buffer[1] = nrates;
    *puc_ie_len = MAC_IE_HDR_LEN + nrates;
}

hi_void  hmac_set_exsup_rates_ie_asoc_rsp(const mac_user_stru *mac_user, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    hi_u8 nrates;
    hi_u8 idx;

    /***************************************************************************
                   -----------------------------------------------
                   |ElementID | Length | Extended Supported Rates|
                   -----------------------------------------------
       Octets:     |1         | 1      | 1-255                   |
                   -----------------------------------------------
    ***************************************************************************/
    if (mac_user->avail_op_rates.rs_nrates <= MAC_MAX_SUPRATES) {
        *puc_ie_len = 0;
        return;
    }

    puc_buffer[0] = MAC_EID_XRATES;
    nrates = mac_user->avail_op_rates.rs_nrates - MAC_MAX_SUPRATES;
    puc_buffer[1] = nrates;

    for (idx = 0; idx < nrates; idx++) {
        puc_buffer[MAC_IE_HDR_LEN + idx] = mac_user->avail_op_rates.auc_rs_rates[idx + MAC_MAX_SUPRATES];
    }

    *puc_ie_len = MAC_IE_HDR_LEN + nrates;
}


hi_u32 hmac_mgmt_encap_asoc_rsp_ap_add_copy(const mac_vap_stru *mac_ap,
    const hmac_asoc_rsp_ap_info_stru *asoc_rsp_ap_info)
{
    if (mac_ap->mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���� Frame Control field */
    mac_hdr_set_frame_control(asoc_rsp_ap_info->puc_asoc_rsp, asoc_rsp_ap_info->us_type);
    /* ���� DA address1: STA MAC��ַ ���� SA address2: dot11MACAddress ���� DA address3: AP MAC��ַ (BSSID) */
    if ((memcpy_s(asoc_rsp_ap_info->puc_asoc_rsp + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN,
        asoc_rsp_ap_info->puc_sta_addr, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(asoc_rsp_ap_info->puc_asoc_rsp + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
            mac_ap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(asoc_rsp_ap_info->puc_asoc_rsp + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
            mac_ap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK)) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_asoc_rsp_ap::memcpy_s fail.}");
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �������Ӧ֡
 �޸���ʷ      :
  1.��    ��   : 2013��7��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_encap_asoc_rsp_ap(mac_vap_stru *mac_ap, hmac_asoc_rsp_ap_info_stru *asoc_rsp_ap_info)
{
    hi_u8  ie_len = 0;
    hi_u16 us_app_ie_len;

    /* ������ʼ��ַ��������㳤�� */
    hi_u8 *puc_asoc_rsp_original = asoc_rsp_ap_info->puc_asoc_rsp;

    /* ��ȡuser */
    mac_user_stru *mac_user = mac_user_get_user_stru(asoc_rsp_ap_info->assoc_id);
    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(asoc_rsp_ap_info->assoc_id);
    if (mac_user == HI_NULL || hmac_user == HI_NULL) {
        oam_error_log3(0, OAM_SF_ASSOC, "{hmac_mgmt_encap_asoc_rsp_ap::mac_user/hmac_user(%d) is null mac=%p, hmac=%p}",
            asoc_rsp_ap_info->assoc_id, (uintptr_t)mac_user, (uintptr_t)hmac_user);
        return 0;
    }
#ifdef _PRE_WLAN_FEATURE_PMF
    mac_timeout_interval_type_enum tie_type =
        (asoc_rsp_ap_info->status_code == MAC_REJECT_TEMP) ? MAC_TIE_ASSOCIATION_COMEBACK_TIME : MAC_TIE_BUTT;
#endif
    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    if (hmac_mgmt_encap_asoc_rsp_ap_add_copy(mac_ap, asoc_rsp_ap_info) != HI_SUCCESS) {
        return 0;
    }

    asoc_rsp_ap_info->puc_asoc_rsp += MAC_80211_FRAME_LEN;

    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Association Response Frame - Frame Body                  */
    /* --------------------------------------------------------------------- */
    /* | Capability Information |   Status Code   | AID | Supported  Rates | */
    /* --------------------------------------------------------------------- */
    /* |2                       |2                |2    |3-10              | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ���� capability information field */
    mac_set_cap_info_ap((hi_void *)mac_ap, asoc_rsp_ap_info->puc_asoc_rsp);
    asoc_rsp_ap_info->puc_asoc_rsp += MAC_CAP_INFO_LEN;
    /* ���� Status Code */
    mac_set_status_code_ie(asoc_rsp_ap_info->puc_asoc_rsp, asoc_rsp_ap_info->status_code);
    asoc_rsp_ap_info->puc_asoc_rsp += MAC_STATUS_CODE_LEN;
    /* ���� Association ID */
    mac_set_aid_ie(asoc_rsp_ap_info->puc_asoc_rsp, (hi_u16)asoc_rsp_ap_info->assoc_id);
    asoc_rsp_ap_info->puc_asoc_rsp += MAC_AID_LEN;
    /* ���� Supported Rates IE */
    hmac_set_supported_rates_ie_asoc_rsp(mac_user, asoc_rsp_ap_info->puc_asoc_rsp, &ie_len);
    asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
    /* ���� Extended Supported Rates IE */
    hmac_set_exsup_rates_ie_asoc_rsp(mac_user, asoc_rsp_ap_info->puc_asoc_rsp, &ie_len);
    asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
    /* ���� EDCA IE */
    mac_set_wmm_params_ie((hi_void *)mac_ap, asoc_rsp_ap_info->puc_asoc_rsp, mac_user->cap_info.qos, &ie_len);
    asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
#ifdef _PRE_WLAN_FEATURE_PMF
    /* ���� Timeout Interval (Association Comeback time) IE */
    hi_u32 timeout = hmac_get_assoc_comeback_time(mac_ap, hmac_user);
    mac_set_timeout_interval_ie(asoc_rsp_ap_info->puc_asoc_rsp, &ie_len, tie_type, timeout);
    asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
#endif
    if (mac_user->ht_hdl.ht_capable == HI_TRUE) {
        /* ���� HT-Capabilities Information IE */
        mac_set_ht_capabilities_ie((hi_void *)mac_ap, asoc_rsp_ap_info->puc_asoc_rsp, &ie_len);
        asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
        /* ���� HT-Operation Information IE */
        mac_set_ht_opern_ie((hi_void *)mac_ap, asoc_rsp_ap_info->puc_asoc_rsp, &ie_len);
        asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
        /* ���� Extended Capabilities Information IE */
        mac_set_ext_capabilities_ie((hi_void *)mac_ap, asoc_rsp_ap_info->puc_asoc_rsp, &ie_len);
        asoc_rsp_ap_info->puc_asoc_rsp += ie_len;
    }

    /* ���WPS��Ϣ */
    mac_add_app_ie((hi_void *)mac_ap, asoc_rsp_ap_info->puc_asoc_rsp, &us_app_ie_len, OAL_APP_ASSOC_RSP_IE);
    asoc_rsp_ap_info->puc_asoc_rsp += us_app_ie_len;

    return (hi_u32)(asoc_rsp_ap_info->puc_asoc_rsp - puc_asoc_rsp_original);
}

/*****************************************************************************
 ��������  : �ж�����challenge txt�Ƿ����
 �޸���ʷ      :
  1.��    ��   : 2013��6��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u8 hmac_mgmt_is_challenge_txt_equal(hi_u8 *puc_data, const hi_u8 *puc_chtxt)
{
    hi_u8 *puc_ch_text = 0;
    hi_u16 us_idx = 0;
    hi_u8 ch_text_len;

    if (puc_chtxt == HI_NULL) {
        return HI_FALSE;
    }
    /* Challenge Text Element                  */
    /* --------------------------------------- */
    /* |Element ID | Length | Challenge Text | */
    /* --------------------------------------- */
    /* | 1         |1       |1 - 253         | */
    /* --------------------------------------- */
    ch_text_len = puc_data[1];
    puc_ch_text = puc_data + 2; /* ��2 */

    for (us_idx = 0; us_idx < ch_text_len; us_idx++) {
        /* Return false on mismatch */
        if (puc_ch_text[us_idx] != puc_chtxt[us_idx]) {
            return HI_FALSE;
        }
    }

    return HI_TRUE;
}


hi_u32 hmac_encap_auth_rsp_get_user_idx_seq(mac_vap_stru *mac_vap, hi_u8 is_seq1, hi_u8 *mac_addr, hi_u8 addr_len,
    hi_u8 *puc_user_index)
{
    /* ���յ���һ����֤֡ʱ�û��Ѵ��� */
    if (!is_seq1) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_encap_auth_rsp_get_user_idx::user have been add at seq1}");
        return HI_FAIL;
    }
#ifdef _PRE_WLAN_FEATURE_MESH
    /* Accepting Peerֵ����Mesh������STA������Mesh Accepting STA���� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        if (mac_vap->mesh_accept_sta == HI_FALSE) {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_encap_auth_rsp_get_user_idx:mesh vap not accept sta connect!}");
            return HI_ERR_CODE_MESH_NOT_ACCEPT_PEER;
        }
    }
#endif
    hi_u32 ret = hmac_user_add(mac_vap, mac_addr, addr_len, puc_user_index);
    if (ret != HI_SUCCESS) {
        if (ret == HI_ERR_CODE_CONFIG_EXCEED_SPEC) {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_encap_auth_rsp_get_user_idx:add_assoc_user fail,users config spec}");
            return HI_ERR_CODE_CONFIG_EXCEED_SPEC;
        } else {
            oam_error_log1(0, OAM_SF_ANY, "{hmac_encap_auth_rsp_get_user_idx:add_assoc_user fail %d}", *puc_user_index);
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡuser idx,����û������ڣ���resend��λ�Ļ�����sta����ap
 �������  : 1.vapָ��
             2.sta��mac��ַ
             3.�Ƿ�Ϊseq1��־λ.���Ϊ�棬��ʾ����û�������,��Ҫ��sta����ap
 �������  : 1. puc_auth_resend �û����ڵ�������յ�seq1,seq1�ж�Ϊ�ش�֡��
                ��λ�˱�־
             2. puc_user_index ���ػ�ȡ����user idx
 �� �� ֵ  :��ȡ��������ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* puc_user_index��Ϊ��������mac_vap_find_user_by_macaddr�������ж������ݽ������޸ģ�lin_t e818�澯���� */
hi_u32 hmac_encap_auth_rsp_get_user_idx(mac_vap_stru *mac_vap,
                                        hmac_mac_addr_stru auth_mac_addr,
                                        hi_u8 is_seq1,
                                        hi_u8 *puc_auth_resend, hi_u8 *puc_user_index)
{
    hi_u8  user_idx;
    hi_u8 *mac_addr = auth_mac_addr.mac_addr;
    hi_u8  addr_len = auth_mac_addr.addr_len;

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_encap_auth_rsp_get_user_idx:hmac_vap_get_vap_stru failed!}");
        return HI_FAIL;
    }

    *puc_auth_resend = HI_FALSE;
    /* �ҵ��û� */
    if (mac_vap_find_user_by_macaddr(hmac_vap->base_vap, mac_addr, addr_len, puc_user_index) == HI_SUCCESS) {
        /* ��ȡhmac�û���״̬���������0��˵�����ظ�֡ */
        hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(*puc_user_index);
        if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_encap_auth_rsp_get_user_idx::hmac_user_get_user null}");
            return HI_FAIL;
        }
        /* en_user_asoc_stateΪö�ٱ�����ȡֵΪ1~4����ʼ��ΪMAC_USER_STATE_BUTT��
         * Ӧ��ʹ��!=MAC_USER_STATE_BUTT��Ϊ�жϣ�����ᵼ��WEP share���ܹ�����������
         */
        if (hmac_user->base_user->user_asoc_state != MAC_USER_STATE_BUTT) {
            *puc_auth_resend = HI_TRUE;
        }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        if (hmac_user->base_user->user_asoc_state == MAC_USER_STATE_ASSOC) {
            oal_net_device_stru *netdev = hmac_vap_get_net_device(mac_vap->vap_id);
            if (netdev != HI_NULL) {
                oal_kobject_uevent_env_sta_leave(netdev, mac_addr);
            }
        }
#endif
        return HI_SUCCESS;
    }

    /* ����ͬһdevice�µ�����VAP���ҵ����û���ɾ��֮��������ҵ��ͨ����DBAC�����䳣�� */
    if (mac_device_find_user_by_macaddr(hmac_vap->base_vap, mac_addr, addr_len, &user_idx) == HI_SUCCESS) {
        hmac_user_stru *hmac_user_tmp = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
        if ((hmac_user_tmp != HI_NULL) && (hmac_user_tmp->base_user != HI_NULL)) {
            mac_vap_stru *mac_vap_tmp = mac_vap_get_vap_stru(hmac_user_tmp->base_user->vap_id);
            if (mac_vap_tmp != HI_NULL) {
                hmac_user_del(mac_vap_tmp, hmac_user_tmp);
            }
        }
    }

    return hmac_encap_auth_rsp_get_user_idx_seq(mac_vap, is_seq1, mac_addr, addr_len, puc_user_index);
}

/*****************************************************************************
 ��������  : ����seq1��auth req
 �������  : 1.auth_rsp_param ����auth rsp����Ĳ���
 �������  : 1.puc_code ������
             2.pst_usr_ass_stat auth�������֮������Ӧ��user״̬
 �� �� ֵ  :��ȡ��������ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_ap_auth_process_code_enum_uint8 hmac_encap_auth_rsp_seq1(const hmac_auth_rsp_param_stru *auth_rsp_param,
                                                              hi_u8 *puc_code,
                                                              mac_user_asoc_state_enum_uint8 *usr_ass_stat)
{
    *puc_code = MAC_SUCCESSFUL_STATUSCODE;
    *usr_ass_stat = MAC_USER_STATE_BUTT;
    /* ��������ش� */
    if (auth_rsp_param->auth_resend != HI_TRUE) {
        if (auth_rsp_param->us_auth_type == WLAN_WITP_AUTH_OPEN_SYSTEM) {
            *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;

            return HMAC_AP_AUTH_SEQ1_OPEN_ANY;
        }

        if (auth_rsp_param->is_wep_allowed == HI_TRUE) {
            *usr_ass_stat = MAC_USER_STATE_AUTH_KEY_SEQ1;
            /* �˴����غ���Ҫwep����� */
            return HMAC_AP_AUTH_SEQ1_WEP_NOT_RESEND;
        }

        /* ��֧���㷨 */
        *puc_code = MAC_UNSUPT_ALG;
        return HMAC_AP_AUTH_BUTT;
    }

    /* ����û�״̬ */
    if ((auth_rsp_param->user_asoc_state == MAC_USER_STATE_ASSOC) &&
        (auth_rsp_param->us_auth_type == WLAN_WITP_AUTH_OPEN_SYSTEM)) {
        /* �û��Ѿ��������˲���Ҫ�κβ��� */
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;
        return HMAC_AP_AUTH_DUMMY;
    }

    if (auth_rsp_param->us_auth_type == WLAN_WITP_AUTH_OPEN_SYSTEM) {
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;

        return HMAC_AP_AUTH_SEQ1_OPEN_ANY;
    }

    if (auth_rsp_param->is_wep_allowed == HI_TRUE) {
        /* seqΪ1 ����֤֡�ش� */
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;
        return HMAC_AP_AUTH_SEQ1_WEP_RESEND;
    }
    /* ��֧���㷨 */
    *puc_code = MAC_UNSUPT_ALG;
    return HMAC_AP_AUTH_BUTT;
}

/*****************************************************************************
 ��������  : ����seq3��auth req
 �������  : 1.auth_rsp_param ����auth rsp����Ĳ���

 �������  : 1.puc_code ������
             2.pst_usr_ass_stat auth�������֮������Ӧ��user״̬

 �� �� ֵ  :��ȡ��������ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_ap_auth_process_code_enum_uint8 hmac_encap_auth_rsp_seq3(const hmac_auth_rsp_param_stru *auth_rsp_param,
                                                              hi_u8 *puc_code,
                                                              mac_user_asoc_state_enum_uint8 *usr_ass_stat)
{
    /* ��������ڣ����ش��� */
    if (auth_rsp_param->auth_resend == HI_FALSE) {
        *usr_ass_stat = MAC_USER_STATE_BUTT;
        *puc_code = MAC_SUCCESSFUL_STATUSCODE;
        return HMAC_AP_AUTH_BUTT;
    }
    /* ����û�״̬ */
    if ((auth_rsp_param->user_asoc_state == MAC_USER_STATE_ASSOC)
        && (auth_rsp_param->us_auth_type == WLAN_WITP_AUTH_OPEN_SYSTEM)) {
        /* �û��Ѿ��������˲���Ҫ�κβ��� */
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;
        *puc_code = MAC_SUCCESSFUL_STATUSCODE;
        return HMAC_AP_AUTH_DUMMY;
    }

    if (auth_rsp_param->us_auth_type == WLAN_WITP_AUTH_OPEN_SYSTEM) {
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;
        *puc_code = MAC_SUCCESSFUL_STATUSCODE;
        return HMAC_AP_AUTH_SEQ3_OPEN_ANY;
    }

    if (auth_rsp_param->user_asoc_state == MAC_USER_STATE_AUTH_KEY_SEQ1) {
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;
        *puc_code = MAC_SUCCESSFUL_STATUSCODE;
        return HMAC_AP_AUTH_SEQ3_WEP_COMPLETE;
    }

    if (auth_rsp_param->user_asoc_state == MAC_USER_STATE_AUTH_COMPLETE) {
        *usr_ass_stat = MAC_USER_STATE_AUTH_COMPLETE;
        *puc_code = MAC_SUCCESSFUL_STATUSCODE;
        return HMAC_AP_AUTH_SEQ3_WEP_COMPLETE;
    }

    if (auth_rsp_param->user_asoc_state == MAC_USER_STATE_ASSOC) {
        *usr_ass_stat = MAC_USER_STATE_AUTH_KEY_SEQ1;
        *puc_code = MAC_SUCCESSFUL_STATUSCODE;
        return HMAC_AP_AUTH_SEQ3_WEP_ASSOC;
    }

    /* ��֧���㷨 */
    *usr_ass_stat = MAC_USER_STATE_BUTT;
    *puc_code = MAC_UNSUPT_ALG;
    return HMAC_AP_AUTH_BUTT;
}

/*****************************************************************************
 ��������  : ����seq3��auth req
 �������  : 1.auth_rsp_param ����auth rsp����Ĳ�������

 �������  : 1.puc_code ������
             2.pst_usr_ass_stat auth�������֮������Ӧ��user״̬

 �� �� ֵ  :��ȡ��������ʧ��
 �޸���ʷ      :
  1.��    ��   : 2014��1��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_auth_rsp_fun hmac_encap_auth_rsp_get_func(hi_u16 us_auth_seq)
{
    hmac_auth_rsp_fun auth_rsp_fun = HI_NULL;
    switch (us_auth_seq) {
        case WLAN_AUTH_TRASACTION_NUM_ONE:
            auth_rsp_fun = hmac_encap_auth_rsp_seq1;
            break;
        case WLAN_AUTH_TRASACTION_NUM_THREE:
            auth_rsp_fun = hmac_encap_auth_rsp_seq3;
            break;
        default:
            auth_rsp_fun = HI_NULL;
            break;
    }
    return auth_rsp_fun;
}

/*****************************************************************************
 ��������  : �ж���֤�����Ƿ�֧��
 �������  : 1.pst_hmac_vap vapָ��
             2. us_auth_type ��֤����
 �� �� ֵ  :HI_SUCCESS-֧�֣�����-��֧��
 �޸���ʷ      :
  1.��    ��   : 2014��1��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_encap_auth_rsp_support(const hmac_vap_stru *hmac_vap, hi_u16 us_auth_type)
{
    /* �����֤�����Ƿ�֧�� ��֧�ֵĻ�״̬λ�ó�UNSUPT_ALG */
    if ((hmac_vap->auth_mode) != us_auth_type && (hmac_vap->auth_mode != WLAN_WITP_ALG_AUTH_BUTT)) {
        return HI_ERR_CODE_CONFIG_UNSUPPORT;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ɾ��hmac amsdu��ص���Ϣ Ƕ�׳�4������
*****************************************************************************/
static hi_void hmac_amsdu_clear(hmac_amsdu_stru *amsdu)
{
    oal_netbuf_stru *amsdu_net_buf = HI_NULL;

    /* tid��, �����ж� */
    oal_spin_lock_bh(&amsdu->st_amsdu_lock);

    if (amsdu->amsdu_timer.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(amsdu->amsdu_timer));
    }
    /* ��վۺ϶��� */
    if (amsdu->msdu_num != 0) {
        while (HI_TRUE != oal_netbuf_list_empty(&amsdu->msdu_head)) {
            amsdu_net_buf = oal_netbuf_delist(&(amsdu->msdu_head));
            if (amsdu_net_buf) {
                oal_netbuf_free(amsdu_net_buf);
            }
        }
        amsdu->msdu_num = 0;
    }
    /* tid����, ʹ�����ж� */
    oal_spin_unlock_bh(&amsdu->st_amsdu_lock);
}

/*****************************************************************************
 ��������  : ɾ��hmac tid��ص���Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��8��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_tid_clear(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user)
{
    hi_u8 loop;
    hmac_amsdu_stru *amsdu = HI_NULL;
    hmac_tid_stru *tid = HI_NULL;
#if defined(_PRE_WLAN_FEATURE_AMPDU_VAP)
    hmac_vap_stru *hmac_vap = HI_NULL;
#endif

#if defined(_PRE_WLAN_FEATURE_AMPDU_VAP)
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_tid_clear::pst_hmac_vap null.}");
        return;
    }
#else
    hi_unref_param(mac_vap);
#endif
    for (loop = 0; loop < WLAN_WME_MAX_TID_NUM; loop++) {
        amsdu = hmac_user->past_hmac_amsdu[loop];
        if (amsdu != HI_NULL) {
            hmac_amsdu_clear(amsdu);
        }

        tid = &(hmac_user->ast_tid_info[loop]);
        tid->tid_no = (hi_u8) loop;
        /* ������շ���Ự��� */
        if (tid->ba_rx_info != HI_NULL) {
            hmac_ba_reset_rx_handle(&tid->ba_rx_info, loop);
        }
        /* ������ͷ���Ự��� */
        if (tid->ba_tx_info != HI_NULL) {
            hmac_ba_reset_tx_handle(&tid->ba_tx_info);
        }
        hmac_user->ast_tid_info[loop].ba_flag = 0;
    }
}

/*****************************************************************************
 ��������  : ��װauth rsp֡��֡�壬CODEĬ����дΪSUCCESS����һ������ˢ��
*****************************************************************************/
hi_u16 hmac_encap_auth_rsp_body(const mac_vap_stru *mac_vap, oal_netbuf_stru *auth_rsp, const oal_netbuf_stru *auth_req)
{
    hi_u8            *puc_data = HI_NULL;
    hi_u8            *puc_frame = HI_NULL;
    hmac_tx_ctl_stru *tx_ctl = HI_NULL;
    hi_u8            mac_addr[WLAN_MAC_ADDR_LEN] = {0};
    hi_u16           auth_rsp_len;
    hi_u16           auth_type;
    hi_u16           auth_seq;

    puc_data = (hi_u8 *)oal_netbuf_header(auth_rsp);
    tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(auth_rsp);
    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���ú���ͷ��frame control�ֶ� */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_AUTH);
    /* ��ȡSTA�ĵ�ַ */
    mac_get_address2(oal_netbuf_header(auth_req), WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN);
    /* ��DA����ΪSTA�ĵ�ַ */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address1, WLAN_MAC_ADDR_LEN,
        mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_auth_rsp_body::copy address1 failed!}");
        return 0;
    }
    /* ��SA����Ϊdot11MacAddress */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address2, WLAN_MAC_ADDR_LEN,
        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_auth_rsp_body::copy address2 failed!}");
        return 0;
    }
    /* ����BSSID */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address3, WLAN_MAC_ADDR_LEN,
        mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_auth_rsp_body::copy address3 failed!}");
        return 0;
    }

    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Authentication Frame - Frame Body                        */
    /* --------------------------------------------------------------------- */
    /* |Auth Algo Number|Auth Trans Seq Number|Status Code| Challenge Text | */
    /* --------------------------------------------------------------------- */
    /* | 2              |2                    |2          | 3 - 256        | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ������֤���� */
    auth_type = mac_get_auth_alg(oal_netbuf_header(auth_req));
    /* ����auth transaction number */
    auth_seq = mac_get_auth_seq_num(oal_netbuf_header(auth_req));
    if (auth_seq > WLAN_AUTH_TRASACTION_NUM_FOUR) {
        oam_warning_log1(0, OAM_SF_AUTH, "{hmac_encap_auth_rsp_body::invalid auth seq [%d]}", auth_seq);
        return 0;
    }

    puc_frame = (hi_u8 *)(puc_data + MAC_80211_FRAME_LEN);
    /* ������֤��Ӧ֡�ĳ��� */
    auth_rsp_len = MAC_80211_FRAME_LEN + MAC_AUTH_ALG_LEN + MAC_AUTH_TRANS_SEQ_NUM_LEN + MAC_STATUS_CODE_LEN;
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru*)oal_netbuf_header(auth_rsp);
    tx_ctl->mac_head_type = 1;
    /* ������֤����IE */
    puc_frame[0] = (auth_type & 0x00FF);
    puc_frame[1] = (auth_type & 0xFF00) >> 8; /* ����8λ */
    /* ���յ���transaction number + 1���Ƹ��µ���֤��Ӧ֡ */
    puc_frame[2] = ((auth_seq + 1) & 0x00FF); /* 2 Ԫ������ */
    puc_frame[3] = ((auth_seq + 1) & 0xFF00) >> 8; /* 3 Ԫ������ ����8λ */
    /* ״̬Ϊ��ʼ��Ϊ�ɹ� */
    puc_frame[4] = MAC_SUCCESSFUL_STATUSCODE; /* 4 Ԫ������ */
    puc_frame[5] = 0; /* 5 Ԫ������ */

    return auth_rsp_len;
}

/*****************************************************************************
 ��������  : �����û���Ϣ����auth rsp֡��status code
*****************************************************************************/
hi_u32 hmac_update_status_code_by_user(const mac_vap_stru *mac_vap, hmac_tx_ctl_stru *tx_ctl, hi_u8 *puc_frame,
                                       hi_u16 auth_type, hi_u8 user_index)
{
    hmac_user_stru  *hmac_user = HI_NULL;
    hmac_vap_stru   *hmac_vap  = HI_NULL;

    /* ��ȡhmac userָ�� */
    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_index);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_update_status_code_by_user::hmac_user is NULL}");
        puc_frame[4] = MAC_UNSPEC_FAIL; /* 4 Ԫ������ */
        return HI_FAIL;
    }
    /* ��ȡhmac vapָ�� */
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if ((hmac_vap == HI_NULL) || (hmac_vap->base_vap != mac_vap)) {
        oam_error_log1(0, OAM_SF_AUTH,
                       "{hmac_update_status_code_by_user::vap is error, change user[idx=%d] state to BUTT!}",
                       hmac_user->base_user->us_assoc_id);
        puc_frame[4] = MAC_UNSPEC_FAIL; /* 4 Ԫ������ */
        mac_user_set_asoc_state(hmac_user->base_user, MAC_USER_STATE_BUTT);
        return HI_FAIL;
    }
    tx_ctl->us_tx_user_idx = user_index;
    /* �ж��㷨�Ƿ�֧�� */
    if (hmac_encap_auth_rsp_support(hmac_vap, auth_type) != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_AUTH, "{hmac_update_status_code_by_user::auth type[%d] not support!}", auth_type);
        puc_frame[4] = MAC_UNSUPT_ALG; /* 4 Ԫ������ */
        hmac_user_set_asoc_state(hmac_vap->base_vap, hmac_user->base_user, MAC_USER_STATE_BUTT);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����auth rsp֡��status code
*****************************************************************************/
hi_u32 hmac_update_auth_rsp_status_code(mac_vap_stru *mac_vap, oal_netbuf_stru *auth_rsp,
    const oal_netbuf_stru *auth_req, hi_u16 auth_rsp_len, hmac_auth_rsp_handle_stru *auth_rsp_handle)
{
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(auth_rsp);
    hi_u8            *puc_data = (hi_u8 *)oal_netbuf_header(auth_rsp);
    hi_u8            *puc_frame = (hi_u8 *)(puc_data + MAC_80211_FRAME_LEN); /* ��MAC HDR��֡����ʼλ�� */
    hmac_mac_addr_stru auth_mac_addr = {0};
    hi_u32             ret;
    hi_u16             auth_type = mac_get_auth_alg(oal_netbuf_header(auth_req));
    hi_u16             auth_seq = mac_get_auth_seq_num(oal_netbuf_header(auth_req)); /* auth transaction number */
    hi_u8              zero_mac_addr[WLAN_MAC_ADDR_LEN] = {0};
    hi_u8              mac_addr[WLAN_MAC_ADDR_LEN] = {0};
    hi_u8              user_index = 0xff;   /* Ĭ��Ϊ��Ч�û�id 0xff */

    /* ��ȡSTA�ĵ�ַ */
    mac_get_address2(oal_netbuf_header(auth_req), WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN);
    /* DTS2015092402932,�ж϶Զ�mac��ַ�Ƿ�Ϊ��Ч������Ϊȫ0 */
    if (memcmp(zero_mac_addr, mac_addr, WLAN_MAC_ADDR_LEN) == 0) {
        oam_warning_log0(0, OAM_SF_AUTH, "{hmac_update_auth_rsp_status_code::user mac is all 0 !}");
        puc_frame[4] = MAC_UNSPEC_FAIL; /* 4 Ԫ������ */
        tx_ctl->us_tx_user_idx = MAC_INVALID_USER_ID;
        tx_ctl->us_mpdu_len = auth_rsp_len;
        return HI_FAIL;
    }

    /* ��ȡ�û�idx */
    auth_mac_addr.mac_addr = mac_addr;
    auth_mac_addr.addr_len = WLAN_MAC_ADDR_LEN;
    ret = hmac_encap_auth_rsp_get_user_idx(mac_vap, auth_mac_addr, (WLAN_AUTH_TRASACTION_NUM_ONE == auth_seq),
                                           &auth_rsp_handle->auth_rsp_param.auth_resend, &user_index);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_AUTH, "{hmac_encap_auth_rsp::get_user_idx fail, error code[%d]!}", ret);
        puc_frame[4] = MAC_UNSPEC_FAIL; /* 4 Ԫ������ */
#ifdef _PRE_WLAN_FEATURE_MESH
        if (ret == HI_ERR_CODE_MESH_NOT_ACCEPT_PEER) {
            /* mesh�û���ʹ��MAC_AP_FULL status code */
            puc_frame[4] = MAC_AP_FULL; /* 4 Ԫ������ */
        }
#endif
        tx_ctl->us_tx_user_idx = MAC_INVALID_USER_ID;
        tx_ctl->us_mpdu_len = auth_rsp_len;
        return HI_FAIL;
    }
    /* ����user��ˢ��status code */
    tx_ctl->us_tx_user_idx = MAC_INVALID_USER_ID;   /* Ĭ������Ϊ��ЧID */
    tx_ctl->us_mpdu_len = auth_rsp_len;
    /* ��ֵ���� */
    auth_rsp_handle->auth_rsp_param.us_auth_type = auth_type;
    auth_rsp_handle->auth_rsp_fun = hmac_encap_auth_rsp_get_func(auth_seq);
    return hmac_update_status_code_by_user(mac_vap, tx_ctl, puc_frame, auth_type, user_index);
}

/*****************************************************************************
 ��������  : ����auth�ص��ķ���ֵ����auth��������
*****************************************************************************/
hi_u16 hmac_auth_rsp_handle_result(const hmac_vap_stru *hmac_vap, hmac_tx_ctl_stru *tx_ctl,
    hmac_ap_auth_process_code_enum_uint8 auth_proc_rst, hi_u8 *puc_frame, hi_u8 *puc_chtxt)
{
    hi_u16 auth_rsp_len = (hi_u16)tx_ctl->us_mpdu_len;

    /* ��ֱ�ӻ�ȡhmac vap�Լ�hmac user hmac_update_status_code_by_user���пմ��� */
    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(tx_ctl->us_tx_user_idx);

    /*  ���ݷ��ص�code���к������� */
    switch (auth_proc_rst) {
        case HMAC_AP_AUTH_SEQ1_OPEN_ANY:
        case HMAC_AP_AUTH_SEQ3_OPEN_ANY:
            mac_user_init_key(hmac_user->base_user);
            break;

        case HMAC_AP_AUTH_SEQ1_WEP_NOT_RESEND:
            hmac_config_11i_add_wep_entry(hmac_vap->base_vap, WLAN_MAC_ADDR_LEN, hmac_user->base_user->user_mac_addr);
            hmac_mgmt_encap_chtxt(puc_frame, puc_chtxt, &auth_rsp_len, hmac_user);
            /* Ϊ���û�����һ����ʱ������ʱ��֤ʧ�� */
            frw_timer_create_timer(&hmac_user->mgmt_timer, hmac_mgmt_timeout_ap,
                (hi_u16)hmac_vap->base_vap->mib_info->wlan_mib_sta_config.dot11_authentication_response_time_out,
                hmac_user, HI_FALSE);
            hmac_user->base_user->key_info.cipher_type =
                mac_get_wep_type(hmac_vap->base_vap, mac_mib_get_wep_default_keyid(hmac_vap->base_vap));
            break;

        case HMAC_AP_AUTH_SEQ1_WEP_RESEND:
            /* seqΪ1 ����֤֡�ش� */
            hmac_mgmt_encap_chtxt(puc_frame, puc_chtxt, &auth_rsp_len, hmac_user);
            /* ������ʱ��ʱ�� */
            frw_timer_restart_timer(&hmac_user->mgmt_timer, hmac_user->mgmt_timer.timeout, HI_FALSE);
            break;

        case HMAC_AP_AUTH_SEQ3_WEP_COMPLETE:
            if (hmac_mgmt_is_challenge_txt_equal(puc_chtxt, hmac_user->ch_text) == HI_TRUE) {
                mac_user_set_asoc_state(hmac_user->base_user, MAC_USER_STATE_AUTH_COMPLETE);
                oal_mem_free(hmac_user->ch_text);
                hmac_user->ch_text = HI_NULL;
                /* cancel timer for auth */
                frw_timer_immediate_destroy_timer(&hmac_user->mgmt_timer);
            } else {
                puc_frame[4] = MAC_CHLNG_FAIL; /* 4 Ԫ������ */
                mac_user_set_asoc_state(hmac_user->base_user, MAC_USER_STATE_BUTT);
            }
            break;

        case HMAC_AP_AUTH_SEQ3_WEP_ASSOC:
            hmac_mgmt_encap_chtxt(puc_frame, puc_chtxt, &auth_rsp_len, hmac_user);
            /* ������ʱ��ʱ�� */
            frw_timer_create_timer(&hmac_user->mgmt_timer, hmac_mgmt_timeout_ap,
                (hi_u16) hmac_vap->base_vap->mib_info->wlan_mib_sta_config.dot11_authentication_response_time_out,
                hmac_user, HI_FALSE);
            break;

        case HMAC_AP_AUTH_DUMMY:
            break;

        default:
            mac_user_init_key(hmac_user->base_user);
            hmac_user->base_user->user_asoc_state = MAC_USER_STATE_BUTT;
            break;
    }

    tx_ctl->us_mpdu_len = (hi_u32)auth_rsp_len; /* ���ȿ��ܱ��,����ˢ��CB�ֶγ�����Ϣ */
    return auth_rsp_len;
}

/*****************************************************************************
 ��������  : ��װauth rsp֡
 �������  : [1]mac_vap
             [2]puc_chtxt
             [3]auth_req
 �������  : [1]auth_rsp
 �� �� ֵ  : hi_u16
*****************************************************************************/
hi_u16 hmac_encap_auth_rsp(mac_vap_stru *mac_vap, oal_netbuf_stru *auth_rsp,
                           const oal_netbuf_stru *auth_req, hi_u8 *puc_chtxt, hi_u16 chtxt_len)
{
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(auth_rsp); /* rsp֡��tx cb�ֶ� */
    hmac_user_stru   *hmac_user = HI_NULL;
    hmac_vap_stru    *hmac_vap  = HI_NULL;
    hi_u8            *puc_frame = HI_NULL;
    hi_u16           auth_rsp_len;
    hmac_ap_auth_process_code_enum_uint8 auth_proc_rst; /* ��֤���� */
    hmac_auth_rsp_handle_stru auth_rsp_handle;

    hi_unref_param(chtxt_len);
    /* ��auth��Ӧ֡��ֵ ״̬��ΪSUCCESS */
    auth_rsp_len = hmac_encap_auth_rsp_body(mac_vap, auth_rsp, auth_req);
    if (auth_rsp_len == 0) {
        return auth_rsp_len;
    }
    /* ˢ��auth��Ӧ֡״̬���ֵ ʧ�ܺ󲻼�������ֱ�ӷ��ص�ǰ֡�� */
    if (hmac_update_auth_rsp_status_code(mac_vap, auth_rsp, auth_req, auth_rsp_len, &auth_rsp_handle) != HI_SUCCESS) {
        return auth_rsp_len;
    }
    /* ִ�гɹ��� ��ֱ�ӻ�ȡhmac vap�Լ�hmac user hmac_update_status_code_by_user���пմ��� */
    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(tx_ctl->us_tx_user_idx);
    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    /*  ��ʼ��������� */
    auth_rsp_handle.auth_rsp_param.is_wep_allowed = mac_is_wep_allowed(mac_vap);
    auth_rsp_handle.auth_rsp_param.user_asoc_state = hmac_user->base_user->user_asoc_state;

    /*  ����seq1����seq3 */
    puc_frame = (hi_u8 *)oal_netbuf_header(auth_rsp) + MAC_80211_FRAME_LEN; /* ��MAC HDR��֡����ʼλ�� */
    if (auth_rsp_handle.auth_rsp_fun != HI_NULL) {
        auth_proc_rst = auth_rsp_handle.auth_rsp_fun(&auth_rsp_handle.auth_rsp_param, &puc_frame[4], /* 4 Ԫ������ */
                                                     &hmac_user->base_user->user_asoc_state);
        /* ��� HMAC��TID��Ϣ */
        hmac_tid_clear(mac_vap, hmac_user);
    } else {
        auth_proc_rst = HMAC_AP_AUTH_BUTT;
        mac_user_set_asoc_state(hmac_user->base_user, MAC_USER_STATE_BUTT);
        puc_frame[4] = MAC_AUTH_SEQ_FAIL; /* 4 Ԫ������ */
    }
    oam_warning_log1(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_encap_auth_rsp::ul_auth_proc_rst:%d}", auth_proc_rst);

    /*  ���ݷ��ص�code���к������� */
    if (auth_proc_rst == HMAC_AP_AUTH_SEQ3_WEP_COMPLETE) {
        puc_chtxt = mac_get_auth_ch_text(oal_netbuf_header(auth_req));  /* seq3��ȡreq����ս�ַ��� */
    }
    puc_frame = (hi_u8 *)oal_netbuf_header(auth_rsp) + MAC_80211_FRAME_LEN; /* ȡ֡����ʼָ�� */
    auth_rsp_len = hmac_auth_rsp_handle_result(hmac_vap, tx_ctl, auth_proc_rst, puc_frame, puc_chtxt);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* dmac offload�ܹ��£�ͬ��user����״̬��Ϣ��dmac */
    if (hmac_config_user_asoc_state_syn(hmac_vap->base_vap, hmac_user->base_user) != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_AUTH, "{hmac_ap_rx_auth_req::user_asoc_state_syn failed.}");
    }
#endif
    return auth_rsp_len;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  : ��װmesh peering open֡
 �������  : 1. vapָ��2.hi_u8 *puc_data 3.mac_mesh_action_data_stru *st_action_data
 �� �� ֵ  :    ֡����
  1.��    ��   : 2019��2��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_encap_mesh_peering_open_frame(mac_vap_stru *mac_vap, hi_u8 *data,
                                          const mac_action_data_stru *action)
{
    hi_u8  ie_len = 0;
    hi_u8 *puc_frame_origin = data; /* ������ʼ��ַ�����ڼ��㳤�� */

    if (mac_vap->mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���� Frame Control field */
    mac_hdr_set_frame_control(data, WLAN_FC0_SUBTYPE_ACTION);

    /* ���� DA address1: STA MAC��ַ */
    /* ���� SA address2: dot11MACAddress */
    /* ���� DA address3::BSSID */
    if ((memcpy_s(data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN, action->puc_dst, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
                  mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN, action->puc_bssid, WLAN_MAC_ADDR_LEN) != EOK)) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_peering_open_frame::memcpy_s fail.}");
        return 0;
    }

    data += MAC_80211_FRAME_LEN;
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Mesh peering open Frame - Frame Body                     */
    /* --------------------------------------------------------------------- */
    /* |Category|action code | Capability Information | Supported Rates |    */
    /* --------------------------------------------------------------------- */
    /* |1             |1               |2                |3-10             | */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |Externed Surpported rates|RSN | HT Capabilities | Extended Capabilities */
    /* --------------------------------------------------------------------- */
    /* |3-257                    |4-256                 | */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* | RSN   | HT Capabilities | Extended Capabilities  | */
    /* --------------------------------------------------------------------- */
    /* |36-256 |3               |28               |3-8                     | */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* | MESH Element| MIC |Authenticated Mesh Peering Exchange| */
    /* --------------------------------------------------------------------- */
    /* |7-257  |X    |                                                       */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ����Category ��Action Code */
    *data = MAC_ACTION_CATEGORY_SELF_PROTECTED;
    *(data + 1) = MAC_SP_ACTION_MESH_PEERING_OPEN;
    data += 2; /* ����2 */

    /* ����Capability Info Field */
    mac_set_cap_info_ap((hi_void *)mac_vap, data);
    data += MAC_CAP_INFO_LEN;

    /* ���� Supported Rates IE */
    mac_set_supported_rates_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���� Extended Supported Rates IE */
    mac_set_exsup_rates_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ����RSN IE */
    mac_set_rsn_mesh_ie_authenticator((hi_void *)mac_vap, data, WLAN_FC0_SUBTYPE_PROBE_RSP, &ie_len);
    data += ie_len;

    /* ���� HT-Capabilities Information IE */
    mac_set_ht_capabilities_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���� HT-Operation Information IE */
    mac_set_ht_opern_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���wmm��Ϣ */
    mac_set_wmm_params_ie(mac_vap, data,
        mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented, &ie_len);
    data += ie_len;

    /* ���bss load��Ϣ */
    mac_set_bssload_ie(mac_vap, data, &ie_len);
    data += ie_len;

    /* ���� Extended Capabilities Information IE */
    mac_set_ext_capabilities_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ����Hisi-Mesh˽����Ϣ */
    mac_set_hisi_mesh_optimization_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���WPS��Ϣ */
    if (action->data_len > 0) {
        /* wpa��������action puc dataЯ��category��Action code���������ֽ�,���������ж��·���֡���ͣ�������� */
        /* Mesh peering open action frame �ֶ� */
        /* Bytes |1      |1     |...| */
        /* ie    |action category|action code|...| */
        if (memcpy_s(data, action->data_len - 2, action->puc_data + 2, action->data_len - 2) != EOK) { /* 2 ����ƫ�� */
            oam_error_log0(0, 0, "hmac_encap_mesh_peering_open_frame:: st_action_data->puc_data memcpy_s fail.");
            return HI_FAIL;
        }
        data += (action->data_len - 2); /* ��ȥ2 */
    }

    return (hi_u32)(data - puc_frame_origin);
}

/*****************************************************************************
 ��������  : ��װmesh peering confirm֡
 �������  : 1. vapָ��2.hmac_userָ��3.hi_u8 *puc_data 4. mac_mesh_action_data_stru *st_action_data
 �� �� ֵ  :֡����
 �޸���ʷ      :
  1.��    ��   : 2019��2��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_encap_mesh_peering_confirm_frame(mac_vap_stru *mac_vap, hi_u8 *data,
                                             const mac_action_data_stru *action_data)
{
    hi_u8 ie_len = 0;

    /* ������ʼ��ַ�����ڼ��㳤�� */
    hi_u8 *puc_frame_origin = data;

    if (mac_vap->mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���� Frame Control field */
    mac_hdr_set_frame_control(data, WLAN_FC0_SUBTYPE_ACTION);

    /* ���� DA address1: Զ�˽ڵ�MAC��ַ */
    /* ���� SA address2: dot11MACAddress */
    /* ���� DA address3::BSSID */
    if ((memcpy_s(data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN, action_data->puc_dst, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
            mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN, action_data->puc_bssid, WLAN_MAC_ADDR_LEN) != EOK)) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_peering_confirm_frame::memcpy_s fail.}");
        return 0;
    }
    data += MAC_80211_FRAME_LEN;
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Mesh peering confirm Frame - Frame Body                   */
    /* --------------------------------------------------------------------- */
    /* |Category|action code | Capability Information |AID| Supported Rates | */
    /* --------------------------------------------------------------------- */
    /* */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |Externed Surpported rates|RSN | HT Capabilities | Extended Capabilities */
    /* --------------------------------------------------------------------- */
    /* */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* | MESH Element| MIC |Authenticated Mesh Peering Exchange| */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    /* ����Category ��Action Code */
    *data = MAC_ACTION_CATEGORY_SELF_PROTECTED;
    *(data + 1) = MAC_SP_ACTION_MESH_PEERING_CONFIRM;
    data += 2; /* ����2 */

    /* ����Capability Info Field */
    mac_set_cap_info_ap((hi_void *)mac_vap, data);
    data += MAC_CAP_INFO_LEN;

    /* ����Mesh AID ��ֱ����wpa �·� */
    if (memcpy_s(data, MAC_AID_LEN, action_data->puc_data + 2, MAC_AID_LEN) != EOK) { /* 2 ���ڼ���ƫ�� */
        oam_error_log0(0, OAM_SF_CFG, "hmac_encap_mesh_peering_confirm_frame::st_action_data->puc_data memcpy_s fail.");
        return HI_FAIL;
    }
    data += MAC_AID_LEN;

    /* ���� Supported Rates IE */
    mac_set_supported_rates_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���� Extended Supported Rates IE */
    mac_set_exsup_rates_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ����RSN IE */
    mac_set_rsn_mesh_ie_authenticator((hi_void *)mac_vap, data, WLAN_FC0_SUBTYPE_PROBE_RSP, &ie_len);
    data += ie_len;

    /* ���� HT-Capabilities Information IE */
    mac_set_ht_capabilities_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���� HT-Operation Information IE */
    mac_set_ht_opern_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���wmm��Ϣ */
    mac_set_wmm_params_ie(mac_vap, data, mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented, &ie_len);
    data += ie_len;

    /* ���bss load��Ϣ */
    mac_set_bssload_ie(mac_vap, data, &ie_len);
    data += ie_len;

    /* ���� Extended Capabilities Information IE */
    mac_set_ext_capabilities_ie((hi_void *)mac_vap, data, &ie_len);
    data += ie_len;

    /* ���WPS��Ϣ */
    /* Mesh peering confirm action frame �ֶ� */
    /* Bytes |1       |1          |2|...| */
    /* ie    |action category|action code|aid|...| */
    if (action_data->data_len > 0) {
        if (memcpy_s(data, action_data->data_len - 4, action_data->puc_data + 4, /* 4 ���ڼ���ƫ�� */
                     action_data->data_len - 4) != EOK) { /* 4 ���ڼ���ƫ�� */
            oam_error_log0(0, 0, "hmac_encap_mesh_peering_confirm_frame::action_data->puc_data memcpy_s fail.");
            return HI_FAIL;
        }
        data += action_data->data_len - 4; /* 4 ���ڼ���ƫ�� */
    }

    return (hi_u32)(data - puc_frame_origin);
}

/*****************************************************************************
 ��������  : ��װmesh peering close֡
 �������  : 1. vapָ��2.hi_u8 *puc_data 3.hisi_action_data_stru *st_action_data
 �� �� ֵ  :    ֡����
  1.��    ��   : 2019��2��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_encap_mesh_peering_close_frame(const mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                           const mac_action_data_stru *action_data)
{
    hi_u8 *puc_frame_origin = HI_NULL;
    hi_u32 us_frame_len;

    /* ������ʼ��ַ�����ڼ��㳤�� */
    puc_frame_origin = puc_data;

    if (mac_vap->mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }
    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���� Frame Control field */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_ACTION);

    /* ���� DA address1: STA MAC��ַ */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_dst, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_peering_close_frame::memcpy_s fail.}");
        return 0;
    }
    /* ���� SA address2: dot11MACAddress */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
                 mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_peering_close_frame::memcpy_s fail.}");
        return 0;
    }
    /* ���� DA address3::BSSID */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_peering_close_frame::memcpy_s fail.}");
        return 0;
    }
    puc_data += MAC_80211_FRAME_LEN;
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Mesh peering close Frame - Frame Body                    */
    /* --------------------------------------------------------------------- */
    /* |Category|action code | Mesh Element | MIC Element |Authenticated Mesh Peering Exchange */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    /* ����Category ��Action Code */
    *puc_data = MAC_ACTION_CATEGORY_SELF_PROTECTED;
    *(puc_data + 1) = MAC_SP_ACTION_MESH_PEERING_CLOSE;
    puc_data += 2; /* ����2 */

    /* ���WPS��Ϣ */
    if (action_data->data_len > 0) {
        if (memcpy_s(puc_data, action_data->data_len - 2, action_data->puc_data + 2, /* 2 ���ڼ���ƫ�� */
                     action_data->data_len - 2) != EOK) { /* 2 ���ڼ���ƫ�� */
            oam_error_log0(0, OAM_SF_CFG, "hmac_encap_mesh_peering_close_frame:: puc_data memcpy_s fail.");
            return HI_FAIL;
        }
        puc_data += action_data->data_len - 2; /* 2 ���ڼ���ƫ�� */
    }

    us_frame_len = (hi_u32) (puc_data - puc_frame_origin);

    return us_frame_len;
}

/*****************************************************************************
 ��������  : ��װMESH_GROUP_KEY_INFORM֡
 �������  : 1. vapָ��2.hi_u8 *puc_data 3.hisi_action_data_stru *st_action_data
 �� �� ֵ  :    ֡����
  1.��    ��   : 2019��6��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_encap_mesh_group_key_inform_frame(const mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                              const mac_action_data_stru *action_data)
{
    hi_u8 *puc_frame_origin = HI_NULL;
    hi_u32 us_frame_len;

    /* ������ʼ��ַ�����ڼ��㳤�� */
    puc_frame_origin = puc_data;

    if (mac_vap->mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���� Frame Control field */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_ACTION);

    /* ���� DA address1: STA MAC��ַ */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_dst, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_group_key_inform_frame::memcpy_s fail.}");
        return 0;
    }
    /* ���� SA address2: dot11MACAddress */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
                 mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_group_key_inform_frame::memcpy_s fail.}");
        return 0;
    }
    /* ���� DA address3::BSSID */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
                 action_data->puc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_group_key_inform_frame::memcpy_s fail.}");
        return 0;
    }
    puc_data += MAC_80211_FRAME_LEN;
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Mesh GROUP KEY INFORM Frame - Frame Body                 */
    /* --------------------------------------------------------------------- */
    /* |Category|action code | MIC Element |Authenticated Mesh Peering Exchange */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    /* ����Category ��Action Code */
    *puc_data = MAC_ACTION_CATEGORY_SELF_PROTECTED;
    *(puc_data + 1) = MAC_SP_ACTION_MESH_GROUP_KEY_INFORM;
    puc_data += 2; /* ����2 */

    /* ���WPS��Ϣ */
    if (action_data->data_len > 0) {
        if (memcpy_s(puc_data, action_data->data_len - 2, action_data->puc_data + 2, /* 2 ���ڼ���ƫ�� */
                     action_data->data_len - 2) != EOK) { /* 2 ���ڼ���ƫ�� */
            oam_error_log0(0, OAM_SF_CFG, "hmac_encap_mesh_group_key_inform_frame:: puc_data memcpy_s fail.");
            return HI_FAIL;
        }
        puc_data += action_data->data_len - 2; /* 2 ���ڼ���ƫ�� */
    }

    us_frame_len = (hi_u32) (puc_data - puc_frame_origin);

    return us_frame_len;
}

/*****************************************************************************
 ��������  : ��װMESH_GROUP_KEY_ACK֡
 �������  : 1. vapָ��2.hi_u8 *puc_data 3.hisi_action_data_stru *st_action_data
 �� �� ֵ  :    ֡����
  1.��    ��   : 2019��6��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_encap_mesh_group_key_ack_frame(const mac_vap_stru *mac_vap, hi_u8 *puc_data,
                                           const mac_action_data_stru *action_data)
{
    hi_u8 *puc_frame_origin = HI_NULL;
    hi_u32 us_frame_len;

    /* ������ʼ��ַ�����ڼ��㳤�� */
    puc_frame_origin = puc_data;

    if (mac_vap->mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }
    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    /* ���� Frame Control field */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_ACTION);

    /* ���� DA address1: STA MAC��ַ */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN,
        action_data->puc_dst, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_group_key_ack_frame::memcpy_s fail.}");
        return 0;
    }
    /* ���� SA address2: dot11MACAddress */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
                 mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_group_key_ack_frame::memcpy_s fail.}");
        return 0;
    }
    /* ���� DA address3::BSSID */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
        action_data->puc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_mesh_group_key_ack_frame::memcpy_s fail.}");
        return 0;
    }
    puc_data += MAC_80211_FRAME_LEN;
    /****************************************************************************/
    /*                Set the contents of the frame body                        */
    /****************************************************************************/
    /****************************************************************************/
    /*              Mesh GROUP KEY ACK Frame - Frame Body                       */
    /* ---------------------------------------------------------------------    */
    /* |Category|action code | MIC Element |Authenticated Mesh Peering Exchange */
    /* ---------------------------------------------------------------------    */
    /* ---------------------------------------------------------------------    */
    /****************************************************************************/
    /* ����Category ��Action Code */
    *puc_data = MAC_ACTION_CATEGORY_SELF_PROTECTED;
    *(puc_data + 1) = MAC_SP_ACTION_MESH_GROUP_KEY_ACK;
    puc_data += 2; /* ����2 */

    /* ���WPS��Ϣ */
    if (action_data->data_len > 0) {
        if (memcpy_s(puc_data, action_data->data_len - 2, action_data->puc_data + 2, /* 2 ���ڼ���ƫ�� */
                     action_data->data_len - 2) != EOK) { /* 2 ���ڼ���ƫ�� */
            oam_error_log0(0, OAM_SF_CFG, "hmac_encap_mesh_group_key_ack_frame:: puc_data memcpy_s fail.");
            return HI_FAIL;
        }
        puc_data += action_data->data_len - 2; /* 2 ���ڼ���ƫ�� */
    }

    us_frame_len = (hi_u32) (puc_data - puc_frame_origin);

    return us_frame_len;
}
#endif
#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
