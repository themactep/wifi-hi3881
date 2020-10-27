/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HMAC layer STA mode SME file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hmac_sme_sta.h"
#include "mac_regdomain.h"
#include "hmac_main.h"
#include "hmac_fsm.h"
#include "hmac_mgmt_sta.h"
#include "hmac_device.h"
#include "hmac_scan.h"
#include "hmac_p2p.h"
#include "hmac_sme_sta.h"
#include "hcc_hmac_if.h"
#include "wal_customize.h"
#include "hmac_event.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
    g_handle_rsp_func_sta: ������sme����Ϣ
*****************************************************************************/
static hmac_sme_handle_rsp_func g_handle_rsp_func_sta[HMAC_SME_RSP_BUTT] = {
    hmac_handle_scan_rsp_sta,
    hmac_handle_join_rsp_sta,
    hmac_handle_auth_rsp_sta,
    hmac_handle_asoc_rsp_sta,
};

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : wpa_supplicant�·���ɨ������Ļص����������ڶ�ɨ�����ʱ�Խ���Ĵ���
 �������  :   *p_scan_record��ɨ���¼������ɨ�跢������Ϣ��ɨ����
 �޸���ʷ      :
  1.��    ��   : 2015��5��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_process_scan_complete_event(hi_void *scan_record)
{
    hmac_scan_record_stru *scan_record_value = (hmac_scan_record_stru *)scan_record;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hmac_scan_rsp_stru scan_rsp;

    /* ��ȡhmac vap */
    hmac_vap = hmac_vap_get_vap_stru(scan_record_value->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_process_scan_complete_event::pst_hmac_vap is null.");
        return;
    }

    /* �ϱ�ɨ�����ṹ���ʼ�� */
    if (memset_s(&scan_rsp, sizeof(scan_rsp), 0, sizeof(scan_rsp)) != EOK) {
        return;
    }

    scan_rsp.result_code = scan_record_value->scan_rsp_status;

    /* ɨ��������sme */
    hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_SCAN_RSP, (hi_u8 *)&scan_rsp);

    return;
}

static hi_u32 hmac_set_scan_req_ssid(mac_scan_req_stru *mac_scan_req, const mac_cfg80211_scan_param_stru *scan_param)
{
    hi_u8 loop;
    /* ����ϲ��·���ָ��ssid����ÿ��ɨ�跢�͵�probe req֡�ĸ���Ϊ�·���ssid���� */
    for (loop = 0; loop < scan_param->l_ssid_num; loop++) {
        if (loop >= WLAN_SCAN_REQ_MAX_BSS) {
            break;
        }

        if (scan_param->ssids[loop].auc_ssid[0] == '\0') {
            continue;
        }

        if (memcpy_s(mac_scan_req->ac_ssid[loop], sizeof(mac_scan_req->ac_ssid[loop]),
                     scan_param->ssids[loop].auc_ssid, scan_param->ssids[loop].ssid_len) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_set_can_req_ssid::fail to copy ssid to hmac.");
            return HI_FAIL;
        }
        mac_scan_req->ac_ssid[loop][scan_param->ssids[loop].ssid_len] = '\0';   /* ssidĩβ��'\0' */
    }
    mac_scan_req->max_send_probe_cnt_per_channel = loop;

    return HI_SUCCESS;
}

static hi_void hmac_set_scan_req_channel_param(const mac_vap_stru *mac_vap, mac_scan_req_stru *mac_scan_req,
    const mac_cfg80211_scan_param_stru *cfg80211_scan_param)
{
    hmac_device_stru     *hmac_dev = HI_NULL;
    hmac_scan_stru       *scan_mgmt = HI_NULL;
    hi_u8                loop;
    hi_u8                channel_number;
    hi_u8                channel_idx = 0;
    hi_u8                chan_num_2g = 0;
    hi_u32               ret;

    /* ����ɨ���ŵ� */
    /* ÿ�η���ɨ���ʱ���Ƚ���Ӧ���ŵ�map��0 */
    hmac_dev = hmac_get_device_stru();
    scan_mgmt = &(hmac_dev->scan_mgmt);
    scan_mgmt->scan_2g_ch_list_map = 0;

    for (loop = 0; loop < cfg80211_scan_param->num_channels_2_g; loop++) {
        channel_number = (hi_u8) cfg80211_scan_param->pul_channels_2_g[loop];

        /* �ж��ŵ��ǲ����ڹ������� */
        ret = mac_is_channel_num_valid(WLAN_BAND_2G, channel_number);
        if (ret == HI_SUCCESS) {
            ret = mac_get_channel_idx_from_num(WLAN_BAND_2G, channel_number, &channel_idx);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                    "{WLAN_BAND_2G::hmac_set_scan_req_channel_param::mac_get_channel_idx fail. channel_number: %u.}",
                                 channel_number);
            }

            mac_scan_req->ast_channel_list[chan_num_2g].band = WLAN_BAND_2G;
            mac_scan_req->ast_channel_list[chan_num_2g].chan_number = channel_number;
            mac_scan_req->ast_channel_list[chan_num_2g].idx = channel_idx;
            mac_scan_req->ast_channel_list[chan_num_2g].en_bandwidth = mac_vap->channel.en_bandwidth;
            /* �������ɨ���ŵ���Ӧ��bitλ��1 */
            scan_mgmt->scan_2g_ch_list_map |= (BIT0 << channel_number);

            mac_scan_req->channel_nums++;
            chan_num_2g++;
        }
    }

    /* �����ŵ�ɨ��ʱ�� */
    mac_scan_req->us_scan_time =
        (mac_scan_req->scan_type == WLAN_SCAN_TYPE_ACTIVE) ? WLAN_ACTIVE_SCAN_TIME : WLAN_PASSIVE_SCAN_TIME;
#ifdef _PRE_WLAN_FEATURE_MESH
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        /* ��ͨMeshɨ�� */
        mac_scan_req->us_scan_time = WLAN_ACTIVE_SCAN_TIME;
        mac_scan_req->max_scan_cnt_per_channel = FGSCAN_SCAN_CNT_PER_CHANNEL;
    }
#endif
}
/*****************************************************************************
 ��������  : �����ں��·���ɨ���������
 �޸���ʷ      :
  1.��    ��   : 2013��9��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_encap_scan_req(const mac_vap_stru *mac_vap, mac_scan_req_stru *mac_scan_req, hi_s8 *puc_param)
{
    mac_cfg80211_scan_param_stru *cfg80211_scan_param = HI_NULL;
#ifdef _PRE_WLAN_FEATURE_P2P
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru *mac_vap_temp = HI_NULL;
#endif
    hi_u8 scan_when_go_up = HI_FALSE;
    const hi_u8 *bcast_mac_addr = mac_get_mac_bcast_addr();

    cfg80211_scan_param = (mac_cfg80211_scan_param_stru *)puc_param;

    mac_scan_req->bss_type = WLAN_MIB_DESIRED_BSSTYPE_INFRA;
    mac_scan_req->scan_type = cfg80211_scan_param->scan_type;
    mac_scan_req->scan_func = MAC_SCAN_FUNC_BSS;               /* Ĭ��ɨ��bss */
    mac_scan_req->fn_cb = hmac_process_scan_complete_event;    /* ɨ����ɻص����� */
    mac_scan_req->max_scan_cnt_per_channel = 2; /* channel��ֵΪ2 */

#ifdef _PRE_WLAN_FEATURE_P2P
    /* p2p Go����ɨ��ʱ����ʹ��p2p device�豸���� */
    mac_dev = mac_res_get_dev();
    if (WLAN_P2P_DEV_MODE == mac_vap->p2p_mode) {
        if ((mac_device_find_up_p2p_go(mac_dev, &mac_vap_temp) == HI_SUCCESS) && (mac_vap_temp != HI_NULL)) {
            scan_when_go_up = HI_TRUE;
        }
    }
#endif /* _PRE_WLAN_FEATURE_P2P */

    if (scan_when_go_up == HI_TRUE || mac_vap->vap_state == MAC_VAP_STATE_UP ||
        mac_vap->vap_state == MAC_VAP_STATE_PAUSE ||
        (mac_vap->vap_state == MAC_VAP_STATE_STA_LISTEN && mac_vap->user_nums > 0)) {
        mac_scan_req->max_scan_cnt_per_channel = 1;
    }
    /* �����ָ���ŵ�����ɨ��ÿ���ŵ�ɨ���Σ�����Զ���dbac���� */
    if (mac_vap->vap_state == MAC_VAP_STATE_UP && cfg80211_scan_param->num_channels_2_g == 1) {
        mac_scan_req->max_scan_cnt_per_channel = FGSCAN_SCAN_CNT_PER_CHANNEL;
    }
    /* ����ssid ��ÿ�η���ɨ������֡�ĸ��� */
    if (hmac_set_scan_req_ssid(mac_scan_req, cfg80211_scan_param) != HI_SUCCESS) {
        return HI_FAIL;
    }

    /* ���ù㲥MAC��ַ */
    if (memcpy_s(mac_scan_req->auc_bssid[0], WLAN_MAC_ADDR_LEN, bcast_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_encap_scan_req::fail to set broadcast MAC address.");
        return HI_FAIL;
    }

    /* ����ɨ���ŵ������Ϣ */
    hmac_set_scan_req_channel_param(mac_vap, mac_scan_req, cfg80211_scan_param);

#ifdef _PRE_WLAN_FEATURE_P2P
    /* WLAN/P2P ����ʱ���ж��Ƿ�p2p0 ����ɨ�� */
    mac_scan_req->is_p2p0_scan = cfg80211_scan_param->is_p2p0_scan;
    if (cfg80211_scan_param->is_p2p0_scan) {
        mac_scan_req->bss_type = 0;
    }
#endif /* _PRE_WLAN_FEATURE_P2P */
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ׼����������
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_prepare_join_req(hmac_join_req_stru *join_req, const mac_bss_dscr_stru *bss_dscr)
{
    if (memset_s(join_req, sizeof(hmac_join_req_stru), 0, sizeof(hmac_join_req_stru)) != EOK) {
        return;
    }

    if (memcpy_s(&(join_req->bss_dscr), sizeof(mac_bss_dscr_stru), bss_dscr,
                 sizeof(mac_bss_dscr_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_prepare_join_req:: pst_bss_dscr memcpy_s fail.");
        return;
    }

    join_req->us_join_timeout = WLAN_JOIN_START_TIMEOUT;
    join_req->us_probe_delay = 0;   /* δʹ�� ��������ɾ�� */
}

/*****************************************************************************
 ��������  : ׼����֤����
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_prepare_auth_req(const mac_vap_stru *mac_vap, hi_u16 *auth_timeout)
{
    /* ����Զ���dbac�ĳ���,������֤��ʱʱ�� */
    *auth_timeout = (hi_u16)(mac_vap->mib_info->wlan_mib_sta_config.dot11_authentication_response_time_out << 1);
}

/*****************************************************************************
 ��������  : ׼����������
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_prepare_asoc_req(const mac_vap_stru *mac_vap, hi_u16 *us_assoc_timeout)
{
    /* ����Զ���dbac����,���ӹ���ʱ�� */
    *us_assoc_timeout = (hi_u16)mac_vap->mib_info->wlan_mib_sta_config.dot11_association_response_time_out;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ����Ƿ������������ɨ��
 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u8 hmac_is_sched_scan_allowed(const mac_vap_stru *mac_vap)
{
    hmac_device_stru      *hmac_dev = hmac_get_device_stru();
    mac_device_stru       *mac_dev = mac_res_get_dev();
    mac_vap_stru          *mac_vap_tmp = HI_NULL;

    /* ���vap��ģʽ����STA���򷵻أ���֧������ģʽ��vap�ĵ���ɨ�� */
    if (mac_vap->vap_mode != WLAN_VAP_MODE_BSS_STA) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_is_sched_scan_allowed::vap mode[%d] don't support sched scan.}",
                         mac_vap->vap_mode);

        hmac_dev->scan_mgmt.sched_scan_req = HI_NULL;
        hmac_dev->scan_mgmt.sched_scan_complete = HI_TRUE;
        return HI_FALSE;
    }

    /* ������ڵ�ǰdevice����up��vap������������ɨ�� */
    mac_device_find_up_vap(mac_dev, &mac_vap_tmp);
    if (mac_vap_tmp != HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_is_sched_scan_allowed::exist up vap, don't start sched scan.}");
        hmac_dev->scan_mgmt.sched_scan_req = HI_NULL;
        hmac_dev->scan_mgmt.sched_scan_complete = HI_TRUE;
        return HI_FALSE;
    }

    return HI_TRUE;
}

/*****************************************************************************
 ��������  : �����ں��·���������ɨ��
 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_start_sched_scan(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_pno_scan_stru    pno_scan_params;
    hi_u32               ret = HI_FAIL;
    hmac_device_stru    *hmac_dev = HI_NULL;

    hi_unref_param(us_len);
    /* �����Ϸ��Լ�� */
    if (oal_unlikely(mac_vap == HI_NULL) || oal_unlikely(puc_param == HI_NULL)) {
        oam_error_log2(0, OAM_SF_SCAN, "{hmac_start_sched_scan::input null %p %p.}",
                       (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �ϲ㴫���ǵ�ַ�������Ҫȡֵ��ȡ��������pnoɨ��������ڵĵ�ַ */
    mac_pno_scan_stru *cfg80211_pno_scan_params = (mac_pno_scan_stru *)(*(uintptr_t *)puc_param);

    /* ��ȡhmac vap */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_SCAN, "{hmac_start_sched_scan::pst_hmac_vap null.}");

        oal_mem_free(cfg80211_pno_scan_params);
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȡhmac device */
    hmac_dev = hmac_get_device_stru();
    /* �����ϲ��·���pnoɨ����� */
    if (memcpy_s(&pno_scan_params, sizeof(mac_pno_scan_stru), cfg80211_pno_scan_params,
        sizeof(mac_pno_scan_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_start_sched_scan:: pst_cfg80211_pno_scan_params memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ͷű����ڴ�ص��ڴ� */
    oal_mem_free(cfg80211_pno_scan_params);

    /* ��⵱ǰdevice�Ƿ������������ɨ�� */
    if (hmac_is_sched_scan_allowed(mac_vap) != HI_TRUE) {
        return HI_FAIL;
    }

    /* ����PNO����ɨ�����ʱ������н���ϱ������ϱ�ɨ�����Ļص����� */
    pno_scan_params.fn_cb = hmac_process_scan_complete_event;
    /* ���÷��͵�probe req֡��Դmac addr */
    pno_scan_params.is_random_mac_addr_scan = hmac_dev->scan_mgmt.is_random_mac_addr_scan;
    hmac_scan_set_sour_mac_addr_in_probe_req(hmac_vap, pno_scan_params.auc_sour_mac_addr, WLAN_MAC_ADDR_LEN,
                                             pno_scan_params.is_random_mac_addr_scan, HI_FALSE);

    /* ״̬������ */
    switch (hmac_vap->base_vap->vap_state) {
        case MAC_VAP_STATE_STA_FAKE_UP:
        case MAC_VAP_STATE_STA_SCAN_COMP:
            ret = hmac_scan_proc_sched_scan_req_event(hmac_vap, &pno_scan_params);
            break;
        default :
            break;
    }
    if (ret != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_start_sched_scan::process scan req fail[%d].}", ret);
        hmac_dev->scan_mgmt.sched_scan_req = HI_NULL;
        hmac_dev->scan_mgmt.sched_scan_complete = HI_TRUE;
    }

    return ret;
}

/*****************************************************************************
 ��������  : �����ں��·�����ֹͣPNO����ɨ��
 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_stop_sched_scan(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_u32 ret;

    /***************************************************************************
                         ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_STOP_SCHED_SCAN, us_len, puc_param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_CFG,
                         "{hmac_stop_sched_scan::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : �����ں��·���������ɨ��
 �޸���ʷ      :
  1.��    ��   : 2013��9��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_process_scan_req(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_scan_req_stru mac_scan_req = {0};
    mac_cfg80211_scan_param_stru *scan_param = HI_NULL;
    oal_app_ie_stru user_ie;

    hi_unref_param(us_len);

    if (oal_unlikely(puc_param == HI_NULL) || oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_process_scan_req::paramter is null, fail to scan.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_cfg80211_scan_param_pst_stru *cfg80211_scan_param_pst = (mac_cfg80211_scan_param_pst_stru *)puc_param;
    scan_param = cfg80211_scan_param_pst->mac_cfg80211_scan_param;
    if (oal_unlikely(scan_param == HI_NULL)) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���ں��·���ɨ��������µ�����ɨ������ṹ���� */
    if (hmac_encap_scan_req(mac_vap, &mac_scan_req, (hi_s8 *)scan_param) != HI_SUCCESS) {
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_P2P
    /* ����P2P/WPS IE ��Ϣ�� vap �ṹ����
     * BEGIN:DTS2015080801057 WLAN���͵� probe request ��Я��P2P IE
     */
    if (is_legacy_vap(mac_vap)) {
        hmac_p2p_del_ie((hi_u8 *)(scan_param->puc_ie), &(scan_param->ie_len));
    }

    /* P2P0 ɨ��ʱ��¼P2P listen channel */
    if (scan_param->is_p2p0_scan == HI_TRUE) {
        hmac_p2p_find_listen_channel(mac_vap, (hi_u16)(scan_param->ie_len), (hi_u8 *)(scan_param->puc_ie));
        mac_scan_req.p2p0_listen_channel = mac_vap->p2p_listen_channel;
    }

#endif
    user_ie.ie_len = scan_param->ie_len;

    if ((scan_param->puc_ie != HI_NULL) && (user_ie.ie_len != 0)) {
        if (memcpy_s(user_ie.auc_ie, WLAN_WPS_IE_MAX_SIZE, scan_param->puc_ie, user_ie.ie_len) != EOK) {
            oam_error_log0(0, OAM_SF_SCAN, "{hmac_process_scan_req::fail to copy scan ie to hmac.}");
            return HI_FAIL;
        }
    }
    user_ie.app_ie_type = OAL_APP_PROBE_REQ_IE;
    if (hmac_config_set_app_ie_to_vap(mac_vap, &user_ie, user_ie.app_ie_type) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_SCAN, "hmac_config_set_app_ie_to_vap return NON SUCCESS. ");
    }

    return hmac_fsm_handle_scan_req(mac_vap, &mac_scan_req);
}

/*****************************************************************************
 ��������  : �������
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_initiate_join(mac_vap_stru *mac_vap, mac_bss_dscr_stru *bss_dscr)
{
    hi_u32 ret = HI_SUCCESS;

    if (oal_unlikely((mac_vap == HI_NULL) || (bss_dscr == HI_NULL))) {
        oam_error_log2(0, OAM_SF_ASSOC, "{hmac_sta_initiate_join::nul%p %p}", (uintptr_t)mac_vap, (uintptr_t)bss_dscr);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_initiate_join::hmac_vap_get_vap_stru null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* �Ƿ������Mesh */
    hmac_vap->base_vap->is_conn_to_mesh = HI_FALSE;
    /* STAΪ11Bģʽʱ������Ϊ11B�������� */
    if (mac_vap->protocol == WLAN_LEGACY_11B_MODE) {
        hmac_vap->auc_supp_rates[0] = WLAN_11B_SUPPORT_RATE_1M;
        hmac_vap->auc_supp_rates[1] = WLAN_11B_SUPPORT_RATE_2M;
        hmac_vap->auc_supp_rates[2] = WLAN_11B_SUPPORT_RATE_5M;  /* 2 Ԫ������ */
        hmac_vap->auc_supp_rates[3] = WLAN_11B_SUPPORT_RATE_11M; /* 3 Ԫ������ */
        hmac_vap->rs_nrates = WLAN_11B_SUPPORT_RATE_NUM;
#ifdef _PRE_WLAN_FEATURE_MESH
    } else if (bss_dscr->is_hisi_mesh == HI_TRUE) { /* �Զ�ΪHisi-Meshʱ, ʹ�ñ�VAP�����ʼ� */
        mac_rateset_stru *rates_set = &(mac_vap->curr_sup_rates.rate);
        hmac_vap->rs_nrates = rates_set->rs_nrates;
        hmac_vap->base_vap->is_conn_to_mesh = HI_TRUE;
        /* �����ʿ�����VAP�ṹ���µ����ʼ��� */
        for (hi_u8 rate_index = 0; rate_index < rates_set->rs_nrates; rate_index++) {
            hmac_vap->auc_supp_rates[rate_index] = rates_set->ast_rs_rates[rate_index].mac_rate;
        }
        /* ����Mesh���� */
        hmac_set_retry_time_en(mac_vap, 30, MAC_CFG_RETRY_MGMT); /* ��ǰsta����Mesh����30ms�ش����� */
#endif
    } else {
        if (memcpy_s(hmac_vap->auc_supp_rates, WLAN_MAX_SUPP_RATES, bss_dscr->auc_supp_rates,
                     bss_dscr->num_supp_rates) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_sta_initiate_join:: auc_supp_rates memcpy_s fail.");
            return HI_FAIL;
        }
        hmac_vap->rs_nrates = bss_dscr->num_supp_rates;
    }

    hmac_join_req_stru *join_req = (hmac_join_req_stru *)oal_memalloc(sizeof(hmac_join_req_stru));
    if (join_req == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_sta_initiate_join:: failed alloc join_req}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_prepare_join_req(join_req, bss_dscr);

    if ((mac_vap->vap_state == MAC_VAP_STATE_STA_FAKE_UP) || (mac_vap->vap_state == MAC_VAP_STATE_STA_SCAN_COMP)) {
        ret = hmac_sta_wait_join(hmac_vap, join_req);
    }
    oal_free(join_req);
    return ret;
}

/*****************************************************************************
 ��������  : ������֤
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_initiate_auth(const mac_vap_stru *mac_vap)
{
    hi_u16 auth_timeout;
    hmac_vap_stru *hmac_vap = HI_NULL;

    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_sta_initiate_auth: pst_mac_vap is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_sta_initiate_auth: pst_hmac_vap is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_prepare_auth_req(mac_vap, &auth_timeout);

    /* ״̬������  */
    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_STA_JOIN_COMP:
            return hmac_sta_wait_auth(hmac_vap, auth_timeout);
        default :
            return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : �������
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_initiate_asoc(const mac_vap_stru *mac_vap)
{
    hi_u16 us_assoc_timeout;
    hmac_vap_stru *hmac_vap = HI_NULL;

    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{hmac_sta_initiate_asoc::pst_mac_vap null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ASSOC, "hmac_sta_initiate_asoc: pst_hmac_vap null!");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_prepare_asoc_req(mac_vap, &us_assoc_timeout);

    /* ״̬������  */
    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_STA_AUTH_COMP:
            return hmac_sta_wait_asoc(hmac_vap, us_assoc_timeout);
        default :
            return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : ����ɨ����
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_handle_scan_rsp_sta(hmac_vap_stru *hmac_vap, const hi_u8 *puc_msg)
{
    hmac_send_event_to_host(hmac_vap->base_vap, puc_msg,
        sizeof(hmac_scan_rsp_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_SCAN_COMP_STA);
    return;
}

/*****************************************************************************
 ��������  : ����ʧ��֪ͨDMAC
 �޸���ʷ      :
  1.��    ��   : 2014��11��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_send_connect_result_to_dmac_sta(const hmac_vap_stru *hmac_vap, hi_u32 result)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;

    /* ���¼���DMAC, �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(hi_u32));
    if (event_mem == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "event_mem null.");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;

    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_CONN_RESULT,
                       sizeof(hi_u32),
                       FRW_EVENT_PIPELINE_STAGE_1, hmac_vap->base_vap->vap_id);

    *((hi_u32 *)(event->auc_event_data)) = result;

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(hi_u32));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���������
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_handle_join_rsp_sta(hmac_vap_stru *hmac_vap, const hi_u8 *puc_msg)
{
    hmac_mgmt_status_enum_uint8 join_result_code = *puc_msg;
    hi_u32 ret;

    if (join_result_code == HMAC_MGMT_SUCCESS) {
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_handle_join_rsp_sta::join succ.}");

        /* ��ʼ��AUTH���� */
        hmac_vap->auth_cnt = 1;
        ret = hmac_sta_initiate_auth(hmac_vap->base_vap);
        if (ret != HI_SUCCESS) {
            hmac_handle_conn_fail(hmac_vap->base_vap);
        }
    } else {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                         "hmac_handle_join_rsp_sta::join fail[%d]", join_result_code);

        ret = hmac_send_connect_result_to_dmac_sta(hmac_vap, HI_FAIL);
        if (ret != HI_SUCCESS) {
            oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                "hmac_send_connect_result_to_dmac_sta return NON SUCCESS. ");
        }
    }
}

/*****************************************************************************
 ��������  : ���͹���ʧ�ܽ����wpa_supplicant
 �޸���ʷ      :
  1.��    ��   : 2015��3��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_report_connect_failed_result(hmac_vap_stru *hmac_vap, mac_status_code_enum_uint16 reason_code)
{
    hmac_asoc_rsp_stru asoc_rsp = {0};

    asoc_rsp.result_code = HMAC_MGMT_TIMEOUT;
    asoc_rsp.status_code = reason_code;
    /* ɨ�賬ʱ��Ҫ�ͷŶ�ӦHMAC VAP�µĹ�������buff */
    asoc_rsp.puc_asoc_req_ie_buff = hmac_vap->puc_asoc_req_ie_buff;

    hi_u32 ret = hmac_send_event_to_host(hmac_vap->base_vap, (const hi_u8*)(&asoc_rsp),
        sizeof(hmac_asoc_rsp_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_ASOC_COMP_STA);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_report_connect_failed_result:: hmac_send_event_to_host fail.");
        /* �ͷŹ�������֡�ڴ� */
        oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
    }

    hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
    return;
}

/*****************************************************************************
 ��������  : ������֤���
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_handle_auth_rsp_sta(hmac_vap_stru *hmac_vap, const hi_u8 *puc_msg)
{
    hmac_auth_rsp_stru *auth_rsp = (hmac_auth_rsp_stru *)puc_msg;
    hmac_user_stru *hmac_user = HI_NULL;
    hi_u32 ret;

    if (MAC_SUCCESSFUL_STATUSCODE == auth_rsp->us_status_code) {
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_handle_auth_rsp_sta::auth succ.}");

        /* ��ʼ��AOSC���� */
        hmac_vap->asoc_cnt = 1;
        ret = hmac_sta_initiate_asoc(hmac_vap->base_vap);
        if (ret != HI_SUCCESS) {
            hmac_handle_conn_fail(hmac_vap->base_vap);
        }
        return;
    }

    oam_warning_log2(0, 0, "hmac_handle_auth_rsp_sta::auth fail[%d],cnt[%d]", auth_rsp->us_status_code,
                     hmac_vap->auth_cnt);

    if ((MAC_UNSUPT_ALG == auth_rsp->us_status_code ||
         hmac_vap->auth_cnt >= MAX_AUTH_CNT) && (hmac_vap->auth_mode == WLAN_WITP_AUTH_AUTOMATIC)) {
        hmac_vap->auth_mode = WLAN_WITP_AUTH_SHARED_KEY;
        /* ��Ҫ��״̬������Ϊ */
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_JOIN_COMP);

        /* ����AUTH�Ĵ��� */
        hmac_vap->auth_cnt = 0;

        /* ���·���������� */
        ret = hmac_sta_initiate_auth(hmac_vap->base_vap);
        if (ret != HI_SUCCESS) {
            hmac_handle_conn_fail(hmac_vap->base_vap);
        }
        return;
    }

    if (hmac_vap->auth_cnt < MAX_AUTH_CNT) {
        /* ��Ҫ��״̬������Ϊ */
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_JOIN_COMP);

        /* ����AUTH�Ĵ��� */
        hmac_vap->auth_cnt++;

        /* ���·���������� */
        ret = hmac_sta_initiate_auth(hmac_vap->base_vap);
        if (ret != HI_SUCCESS) {
            hmac_handle_conn_fail(hmac_vap->base_vap);
        }
        return;
    }

    ret = hmac_send_connect_result_to_dmac_sta(hmac_vap, HI_FAIL);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "hmac_send_connect_result_to_dmac_sta returnON SUCC");
    }

    /* The MAC state is changed to fake up state. Further MLME     */
    /* requests are processed in this state.                       */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);

    /* ��ȡ�û�ָ�� */
    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(hmac_vap->base_vap->assoc_vap_id);
    if (hmac_user != HI_NULL) {
        /* ɾ����Ӧ�û� */
        hmac_user_del(hmac_vap->base_vap, hmac_user);
    }

    if (hmac_vap->base_vap->is_conn_to_mesh == HI_TRUE) {
        /* �ر�25ms�ش����� */
        hmac_set_retry_time_close(hmac_vap->base_vap);
    }
    /* �ϱ�����ʧ�ܵ�wpa_supplicant */
    hmac_report_connect_failed_result(hmac_vap, MAC_CHLNG_FAIL);
}

hi_u32 hmac_asoc_rsp_success_proc(hmac_vap_stru *hmac_vap, const hi_u8 *msg, hmac_asoc_rsp_stru *asoc_rsp)
{
    /* DTS2016102405092: asoc_rsp ֡����һ���ϱ��ϲ�,��ֹ֡�����ϱ�wal�ദ���hmac���ͷ� */
    hi_u8 *mgmt_data = (hi_u8 *)oal_memalloc(asoc_rsp->asoc_rsp_ie_len);
    if (mgmt_data == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_handle_asoc_rsp_sta::malloc null.}");
        /* ���ش��� */
        return HI_FAIL;
    }

    if ((asoc_rsp->puc_asoc_rsp_ie_buff != HI_NULL) &&
        (memcpy_s(mgmt_data, asoc_rsp->asoc_rsp_ie_len, asoc_rsp->puc_asoc_rsp_ie_buff,
            asoc_rsp->asoc_rsp_ie_len) != EOK)) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_handle_asoc_rsp_sta:: puc_asoc_rsp_ie_buff memcpy_s fail.");
        oal_free(mgmt_data);
        return HI_FAIL;
    }
    hi_u8 *puc_save = asoc_rsp->puc_asoc_rsp_ie_buff;
    asoc_rsp->puc_asoc_rsp_ie_buff = mgmt_data;

    hi_u32 ret = hmac_send_event_to_host(hmac_vap->base_vap, msg,
        sizeof(hmac_asoc_rsp_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_ASOC_COMP_STA);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_handle_asoc_rsp_sta:: puc_msg memcpy_s fail.");
        oal_free(mgmt_data);
        asoc_rsp->puc_asoc_rsp_ie_buff = puc_save;
        return HI_FAIL;
    }

    hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ������֤���
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_handle_asoc_rsp_sta(hmac_vap_stru *hmac_vap, const hi_u8 *msg)
{
    hmac_asoc_rsp_stru *asoc_rsp = (hmac_asoc_rsp_stru *)msg;

    if (msg == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_handle_asoc_rsp_sta::puc_msg fail!}");
        return;
    }

    /* end add */
    if (asoc_rsp->result_code == HMAC_MGMT_SUCCESS) {
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_handle_asoc_rsp_sta::asoc succ.}");

        if (hmac_asoc_rsp_success_proc(hmac_vap, msg, asoc_rsp) != HI_SUCCESS) {
            /* ��oal_mem_free�����п� */
            oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
            hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
            return;
        }
    } else {
        oam_warning_log2(hmac_vap->base_vap->vap_id, OAM_SF_AUTH,
            "{hmac_handle_asoc_rsp_sta::asoc fail=%d,assoc_cnt=%d}", asoc_rsp->result_code, hmac_vap->asoc_cnt);

        hi_u8 max_reassoc_count = MAX_ASOC_CNT;
#ifdef _PRE_WLAN_FEATURE_PMF
        max_reassoc_count = (asoc_rsp->status_code == MAC_REJECT_TEMP) ? MAX_ASOC_REJECT_CNT : MAX_ASOC_CNT;
#endif
        if (hmac_vap->asoc_cnt >= max_reassoc_count) {
            /* ��ȡ�û�ָ�� */
            hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(hmac_vap->base_vap->assoc_vap_id);
            if ((hmac_user != HI_NULL) && (hmac_user->base_user != HI_NULL)) {
                /* ����ȥ��֤֡��AP */
                hmac_mgmt_send_deauth_frame(hmac_vap->base_vap, hmac_user->base_user->user_mac_addr,
                    WLAN_MAC_ADDR_LEN, MAC_AUTH_NOT_VALID);

                /* ɾ����Ӧ�û� */
                hmac_user_del(hmac_vap->base_vap, hmac_user);
            } else {
                oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "asoc:pst_hmac_user NULL.");
            }

            /* ����״̬ΪFAKE UP */
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);

            /* ͬ��DMAC״̬ */
            if (hmac_send_connect_result_to_dmac_sta(hmac_vap, HI_FAIL) != HI_SUCCESS) {
                oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "hmac_send_connect_result_to_dmac_sta Err");
            }

            /* �ϱ�����ʧ�ܵ�wpa_supplicant */
            hmac_report_connect_failed_result(hmac_vap, asoc_rsp->status_code);
        } else {
            /* ��Ҫ��״̬������Ϊ */
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_AUTH_COMP);

            /* ����ASOC�Ĵ��� */
            hmac_vap->asoc_cnt++;

            /* ���·���������� */
            if (hmac_sta_initiate_asoc(hmac_vap->base_vap) != HI_SUCCESS) {
                /* ��oal_mem_free�����п� */
                oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
                hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
                hmac_handle_conn_fail(hmac_vap->base_vap);
            }
            return;
        }
    }

    if (hmac_vap->base_vap->is_conn_to_mesh == HI_TRUE) {
        /* �ر�25ms�ش����� */
        hmac_set_retry_time_close(hmac_vap->base_vap);
    }
}

/*****************************************************************************
 ��������  : ������״̬������ϱ���SME
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_send_rsp_to_sme_sta(hmac_vap_stru *hmac_vap, hmac_sme_rsp_enum_uint8 type, const hi_u8 *puc_msg)
{
    g_handle_rsp_func_sta[type] (hmac_vap, puc_msg);
}

/*****************************************************************************
 ��������  : ��lwip�ϱ�sta����/ȥ�����¼�
 ���������hmac_vap_stru *pst_hmac_vap
        hi_u8 *puc_addr������/ȥ������AP��ַ
        hi_u8 en_assoc��HI_TRUE���ϱ������¼���Hi_False���ϱ�ȥ�����¼�
 �޸���ʷ      :
  1.��    ��   : 2019��7��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_report_assoc_state_sta(const hmac_vap_stru *hmac_vap, const hi_u8 *mac_addr, hi_u8 assoc)
{
    /* �׼�������¼���WAL */
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(hmac_sta_report_assoc_info_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_report_assoc_state_sta::frw_event_alloc fail!}");
        return;
    }

    /* ��д�¼� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;

    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_HOST_CTX, HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_CONN_RESULT,
        sizeof(hmac_sta_report_assoc_info_stru), FRW_EVENT_PIPELINE_STAGE_0, hmac_vap->base_vap->vap_id);

    if (assoc == HI_TRUE) {
        /* ��ȡhmac device �ṹ */
        hmac_device_stru *hmac_dev = hmac_get_device_stru();
        /* ��ȡ����ɨ���bss����Ľṹ�� */
        hmac_bss_mgmt_stru *bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);
        /* ������ɾ����ǰ���� */
        oal_spin_lock(&(bss_mgmt->st_lock));

        hmac_scanned_bss_info *scanned_bss_info = hmac_scan_find_scanned_bss_by_bssid(bss_mgmt, mac_addr);
        if (scanned_bss_info == HI_NULL) {
            oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_CFG,
                             "{hmac_report_assoc_state_sta::find the bss failed by bssid:XX:XX:XX:%02X:%02X:%02X}",
                             mac_addr[3], mac_addr[4], mac_addr[5]); /* 3:4:5 Ԫ������ */
            /* ���� */
            oal_spin_unlock(&(bss_mgmt->st_lock));
            frw_event_free(event_mem);
            return;
        }
        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));

        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_report_assoc_state_sta::Asoc Report!}");

        hmac_sta_report_assoc_info_stru *sta_asoc = (hmac_sta_report_assoc_info_stru *)(event->auc_event_data);
        sta_asoc->is_assoc = HI_TRUE;
        sta_asoc->rssi = (hi_u8)oal_abs(scanned_bss_info->bss_dscr_info.rssi);
        sta_asoc->conn_to_mesh = scanned_bss_info->bss_dscr_info.is_hisi_mesh;
        if (memcpy_s(sta_asoc->auc_mac_addr, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_SCAN, "hmac_report_assoc_state_sta:: mem safe function err!");
            frw_event_free(event_mem);
            return;
        }
    }else {
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_report_assoc_state_sta::Disasoc Report!}");

        hmac_sta_report_assoc_info_stru *sta_asoc = (hmac_sta_report_assoc_info_stru *)(event->auc_event_data);
        sta_asoc->is_assoc = HI_FALSE;
        sta_asoc->rssi = WLAN_RSSI_DUMMY_MARKER;
        sta_asoc->conn_to_mesh = HI_FALSE;
        if (memcpy_s(sta_asoc->auc_mac_addr, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_SCAN, "hmac_report_assoc_state_sta:: mem safe function err!");
            frw_event_free(event_mem);
            return;
        }
    }

    /* �ַ��¼� */
    frw_event_dispatch_event(event_mem);
    /* end add */
    frw_event_free(event_mem);

    return;
}

hi_void hmac_handle_conn_fail(const mac_vap_stru *mac_vap)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;

    /* ���¼���DMAC, �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(hi_u32));
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_auth_fail_coex_handle::event_mem null.}");
        return;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_CONN_FAIL_SET_CHANNEL,
                       sizeof(hi_u32), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);
    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(hi_u32));
    frw_event_free(event_mem);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

