/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: STA side management surface processing.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_frame.h"
#include "wlan_mib.h"
#include "mac_ie.h"
#include "mac_regdomain.h"
#include "mac_user.h"
#include "mac_vap.h"
#include "mac_device.h"
#include "hmac_device.h"
#include "hmac_user.h"
#include "hmac_mgmt_sta.h"
#include "hmac_fsm.h"
#include "hmac_rx_data.h"
#include "hmac_chan_mgmt.h"
#include "hmac_mgmt_bss_comm.h"
#include "hmac_encap_frame_sta.h"
#include "hmac_sme_sta.h"
#include "hmac_scan.h"
#include "hmac_11i.h"
#include "hmac_config.h"
#include "hmac_ext_if.h"
#include "hmac_event.h"
#include "hmac_blockack.h"
#include "hcc_hmac_if.h"
#include "frw_timer.h"
#ifdef _PRE_WLAN_FEATURE_WAPI
#include "hmac_wapi.h"
#endif
#include "wal_customize.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : sta�ȴ�����֡��ʱ������
 �޸���ʷ      :
  1.��    ��   : 2013��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_mgmt_timeout_sta(hi_void *arg)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    hmac_mgmt_timeout_param_stru *timeout_param = HI_NULL;

    timeout_param = (hmac_mgmt_timeout_param_stru *)arg;
    hmac_vap = hmac_vap_get_vap_stru(timeout_param->vap_id);
    if ((hmac_vap == HI_NULL) || (hmac_vap->base_vap == HI_NULL)) {
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_timer_immediate_destroy_timer(&(hmac_vap->mgmt_timer));

    switch (hmac_vap->base_vap->vap_state) {
        case MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2:
        case MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4:
            return hmac_sta_auth_timeout(hmac_vap);
        case MAC_VAP_STATE_STA_WAIT_ASOC:
            return hmac_sta_wait_asoc_timeout(hmac_vap);
        default :
            return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : ��join֮ǰ����Э����صĲ���
 �޸���ʷ      :
  1.��    ��   : 2013��10��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_update_join_req_params_prot_sta(hmac_vap_stru *hmac_vap,
                                                    const hmac_join_req_stru *join_req)
{
    if (hmac_vap->base_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type ==
        WLAN_MIB_DESIRED_BSSTYPE_INFRA) {
#ifdef _PRE_WLAN_FEATURE_MESH
        if (join_req->bss_dscr.is_hisi_mesh == HI_TRUE) {
            hmac_vap->wmm_cap = HI_TRUE;
        } else {
            hmac_vap->wmm_cap = join_req->bss_dscr.wmm_cap;
            mac_vap_set_uapsd_cap(hmac_vap->base_vap, join_req->bss_dscr.uapsd_cap);
        }
#else
        hmac_vap->wmm_cap = join_req->bss_dscr.wmm_cap;
        mac_vap_set_uapsd_cap(hmac_vap->base_vap, join_req->bss_dscr.uapsd_cap);
#endif
    }
}

/*****************************************************************************
 ��������  : �ж��Ƿ�֧��ĳ������
 �޸���ʷ      :
  1.��    ��   : 2016��3��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_is_rate_support(const hi_u8 *puc_rates, hi_u8 rate_num, hi_u8 rate)
{
    hi_u8 rate_is_supp = HI_FALSE;
    hi_u8 loop;

    if (puc_rates == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_is_rate_support::puc_rates null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    for (loop = 0; loop < rate_num; loop++) {
        if ((puc_rates[loop] & 0x7F) == rate) {
            rate_is_supp = HI_TRUE;
            break;
        }
    }

    return rate_is_supp;
}

/*****************************************************************************
 ��������  : �Ƿ�֧��11g����
 �޸���ʷ      :
  1.��    ��   : 2016��3��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_is_support_11grate(const hi_u8 *puc_rates, hi_u8 rate_num)
{
    if (puc_rates == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_is_rate_support::puc_rates null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if ((HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x0C)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x12)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x18)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x24)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x30)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x48)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x60)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x6C))) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : �Ƿ�֧��11b����
 �޸���ʷ      :
  1.��    ��   : 2016��3��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_is_support_11brate(const hi_u8 *puc_rates, hi_u8 rate_num)
{
    if (puc_rates == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_is_support_11brate::puc_rates null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if ((HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x02)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x04)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x0B)) ||
        (HI_TRUE == hmac_is_rate_support(puc_rates, rate_num, 0x16))) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ��ȡ�û���Э��ģʽ
 �޸���ʷ      :
  1.��    ��   : 2014��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_get_user_protocol(mac_bss_dscr_stru *bss_dscr, wlan_protocol_enum_uint8 *protocol_mode)
{
    /* ��α��� */
    if (bss_dscr == HI_NULL || protocol_mode == HI_NULL) {
        oam_error_log2(0, OAM_SF_SCAN, "{hmac_sta_get_user_protocol::param null,%p %p.}",
                       (uintptr_t)bss_dscr, (uintptr_t)protocol_mode);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (bss_dscr->ht_capable == HI_TRUE) {
        *protocol_mode = WLAN_HT_MODE;
    } else {
        if (hmac_is_support_11grate(bss_dscr->auc_supp_rates, bss_dscr->num_supp_rates) == HI_TRUE) {
            *protocol_mode = WLAN_LEGACY_11G_MODE;
            if (hmac_is_support_11brate(bss_dscr->auc_supp_rates, bss_dscr->num_supp_rates) == HI_TRUE) {
                *protocol_mode = WLAN_MIXED_ONE_11G_MODE;
            }
        } else if (hmac_is_support_11brate(bss_dscr->auc_supp_rates, bss_dscr->num_supp_rates) == HI_TRUE) {
            *protocol_mode = WLAN_LEGACY_11B_MODE;
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_sta_get_user_protocol::get user protocol failed.}");
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}

hi_u8 hmac_sta_need_update_protocol(wlan_protocol_enum_uint8 vap_protocol, wlan_protocol_enum_uint8 user_protocol)
{
    if (((vap_protocol == WLAN_MIXED_ONE_11G_MODE) && (user_protocol == WLAN_LEGACY_11B_MODE)) ||
        ((vap_protocol == WLAN_HT_MODE) &&
               ((user_protocol == WLAN_LEGACY_11B_MODE) || (user_protocol == WLAN_MIXED_ONE_11G_MODE)))) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ���ݴ����ȡת����us�ķŴ���(ת��Ϊ��λ��)
 �޸���ʷ      :
  1.��    ��   : 2019��7��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_dbac_get_scale_by_bw(hi_u8 bandwidth)
{
    hi_u8 scale = 0;

    if (bandwidth == WLAN_BAND_WIDTH_5M) {
        scale = 2; /* 5M��4������Ӧλ����2 */
    } else if (bandwidth == WLAN_BAND_WIDTH_10M) {
        scale = 1; /* 10M��2������Ӧλ����1 */
    } else {
        scale = 0;
    }
    return scale;
}

/*****************************************************************************
 ��������  : ����join_request֡����sta�������ŵ������Ϣ
*****************************************************************************/
static hi_u32 hmac_sta_update_join_channel(mac_vap_stru *mac_vap, const hmac_join_req_stru *join_req)
{
    mac_device_stru *mac_dev = HI_NULL;
    hi_u8 bcn_scale;

    mac_dev = mac_res_get_dev();
    /* ����BSSID */
    mac_vap_set_bssid(mac_vap, join_req->bss_dscr.auc_bssid, WLAN_MAC_ADDR_LEN);
    /* ����mib���Ӧ��ssid */
    if (memcpy_s(mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid, WLAN_SSID_MAX_LEN,
                 join_req->bss_dscr.ac_ssid, WLAN_SSID_MAX_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_sta_update_join_channel:: ac_ssid memcpy_s fail.");
        return HI_FAIL;
    }
    mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid[WLAN_SSID_MAX_LEN - 1] = '\0';

    /* ���ݴ���ת��beacon����Ϊ��λTU */
    bcn_scale = hmac_dbac_get_scale_by_bw(mac_vap->channel.en_bandwidth);
    /* ����mib���Ӧ��dot11BeaconPeriodֵ */
    mac_vap->mib_info->wlan_mib_sta_config.dot11_beacon_period =
        ((hi_u32) (join_req->bss_dscr.us_beacon_period)) << bcn_scale;
    /* ����mib���Ӧ��ul_dot11CurrentChannelֵ */
    mac_vap_set_current_channel(mac_vap, join_req->bss_dscr.channel.band,
                                join_req->bss_dscr.channel.chan_number);

    /* ����Ƶ������20MHz�ŵ��ţ���APͨ�� DMAC�л��ŵ�ʱֱ�ӵ��� */
    if ((mac_vap->channel.en_bandwidth != WLAN_BAND_WIDTH_5M) &&
        (mac_vap->channel.en_bandwidth != WLAN_BAND_WIDTH_10M)) {  /* ���ڷ�խ��ʱ���� */
        mac_vap->channel.en_bandwidth =
            hmac_sta_get_band(mac_dev->bandwidth_cap, join_req->bss_dscr.channel_bandwidth);
    }
    mac_vap->channel.chan_number = join_req->bss_dscr.channel.chan_number;
    mac_vap->channel.band = join_req->bss_dscr.channel.band;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����join_request֡����sta������Э��ģʽ�����Ϣ
*****************************************************************************/
static hi_u32 hmac_sta_update_join_protocol(const hmac_vap_stru *hmac_vap, hmac_join_req_stru *join_req)
{
    mac_cfg_mode_param_stru cfg_mode = {0};
    mac_vap_stru *mac_vap = hmac_vap->base_vap;

    /* Mesh beacon֡�в������ʼ����޷���ȡ��ӦЭ��ģʽ�����Ĭ��MeshΪ11BGN���������STAЭ��ģʽ�ȹ���AP�ߵ����� */
    if (join_req->bss_dscr.is_hisi_mesh == HI_FALSE) {
        if (hmac_sta_get_user_protocol(&join_req->bss_dscr, &cfg_mode.protocol) != HI_SUCCESS) {
            oam_error_log0(0, OAM_SF_SCAN, "{hmac_sta_update_join_req_params::hmac_sta_get_user_protocol fail.}");
            return HI_FAIL;
        }
        /* STA��Э��ģʽ��Ҫ������AP�ߣ������mib���ж�Ӧ��������� */
        if (hmac_sta_need_update_protocol(mac_vap->protocol, cfg_mode.protocol) == HI_TRUE) {
            /* ����ǰ�Ƚ�STAģʽ�ָ�������ǰ����ֹ֮ǰ��������APʱģʽ���Ͳ��ָ� */
            mac_vap->protocol = hmac_vap->preset_para.protocol;
            mac_vap->mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented =
                join_req->bss_dscr.ht_capable;
            mac_vap->mib_info->phy_ht.dot11_ldpc_coding_option_implemented = (join_req->bss_dscr.ht_ldpc &&
                mac_vap->mib_info->phy_ht.dot11_ldpc_coding_option_activated);
            mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_implemented = (join_req->bss_dscr.ht_stbc &&
                mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_activated);

            /* ����2G AP����2ght40��ֹλΪ1ʱ����ѧϰAP��HT 40���� */
            mac_mib_set_forty_mhz_operation_implemented(mac_vap, HI_FALSE);
            if (!(mac_vap->channel.band == WLAN_BAND_2G && mac_vap->cap_flag.disable_2ght40) &&
                (join_req->bss_dscr.bw_cap != WLAN_BW_CAP_20M)) {
                mac_mib_set_forty_mhz_operation_implemented(mac_vap, HI_TRUE);
            }

            /* ����Ҫ����AP��Э��ģʽ����STA�����ʼ� */
            cfg_mode.band = join_req->bss_dscr.channel.band;
            cfg_mode.en_bandwidth = mac_vap->channel.en_bandwidth;
            cfg_mode.channel_idx = join_req->bss_dscr.channel.chan_number;
            if (hmac_config_sta_update_rates(mac_vap, &cfg_mode) != HI_SUCCESS) {
                oam_error_log0(0, OAM_SF_SCAN, "{hmac_sta_update_join_protocol::hmac_config_sta_update_rates fail.}");
                return HI_FAIL;
            }
        }
    }

    /* wapi ��Ҫ��Э�� */
    if (join_req->bss_dscr.wapi) {
        hmac_update_pcip_policy_prot_supplicant(mac_vap, WLAN_80211_CIPHER_SUITE_WAPI);
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_sta_update_join_protocol::wapi prot fall!}");
    }

    /* ����mib���Ӧ�ļ������ֵ */
    if (hmac_update_current_join_req_parms_11i(mac_vap, &join_req->bss_dscr.bss_sec_info) != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_sta_update_join_protocol::update security parameter failed.}");
        return HI_FAIL;
    }

    cfg_mode.protocol = mac_vap->protocol;
    cfg_mode.band = mac_vap->channel.band;
    cfg_mode.en_bandwidth = mac_vap->channel.en_bandwidth;
    cfg_mode.channel_idx = join_req->bss_dscr.channel.chan_number;

    return hmac_config_sta_update_rates(mac_vap, &cfg_mode);
}

/*****************************************************************************
 ��������  : ���͹��������¼���dmac
*****************************************************************************/
static hi_u32 hmac_sta_dispatch_join_req(const mac_vap_stru *mac_vap, const hmac_join_req_stru *join_req)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    dmac_ctx_join_req_set_reg_stru *reg_params = HI_NULL;

    /* ���¼���DMAC, �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(dmac_ctx_join_req_set_reg_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_sta_update_join_req_params::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_JOIN_SET_REG,
                       sizeof(dmac_ctx_join_req_set_reg_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    reg_params = (dmac_ctx_join_req_set_reg_stru *)event->auc_event_data;
    /* ������Ҫд��Ĵ�����BSSID��Ϣ */
    if (memcpy_s(reg_params->auc_bssid, WLAN_MAC_ADDR_LEN, join_req->bss_dscr.auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, 0, "{alg_autorate_init_rate_policy::copy bssid failed!}");
        return HI_FAIL;
    }

    /* ��д�ŵ������Ϣ */
    reg_params->current_channel.chan_number = mac_vap->channel.chan_number;
    reg_params->current_channel.band = mac_vap->channel.band;
    reg_params->current_channel.en_bandwidth = mac_vap->channel.en_bandwidth;
    reg_params->current_channel.idx = mac_vap->channel.idx;

    /* ����beaocn period��Ϣ */
    reg_params->us_beacon_period = (join_req->bss_dscr.us_beacon_period);
    /* ͬ��FortyMHzOperationImplemented */
    reg_params->dot11_forty_m_hz_operation_implemented = mac_mib_get_forty_mhz_operation_implemented(mac_vap);
    /* ����beacon filter�ر� */
    reg_params->beacon_filter = HI_FALSE;
    /* ����no frame filter�� */
    reg_params->non_frame_filter = HI_TRUE;
    /* �·�ssid */
    if (memcpy_s(reg_params->auc_ssid, WLAN_SSID_MAX_LEN, join_req->bss_dscr.ac_ssid, WLAN_SSID_MAX_LEN) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CFG, "hmac_sta_update_join_req_params:: ac_ssid memcpy_s fail.");
        return HI_FAIL;
    }
    reg_params->auc_ssid[WLAN_SSID_MAX_LEN - 1] = '\0';

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(dmac_ctx_join_req_set_reg_stru));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����join_request֡����mib��Ϣ����д��Ӧ�Ĵ���
 �������  : hmac_vap_stru      *pst_hmac_vap,
             hmac_join_req_stru *pst_join_req
 �޸���ʷ      :
  1.��    ��   : 2013��7��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

 2.��    ��   : 2014��4��7��
    ��    ��   : Hisilicon
   �޸�����   : ɾ����ӡ��־�����������
*****************************************************************************/
static hi_u32 hmac_sta_update_join_req_params(hmac_vap_stru *hmac_vap, hmac_join_req_stru *join_req)
{
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hi_u32 ret;
    mac_device_stru *mac_dev = HI_NULL;
    wlan_mib_ieee802dot11_stru *mib_info = mac_vap->mib_info;

    if (mib_info == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }
    mac_dev = mac_res_get_dev();
    /* ����ǰ����sta�Ƿ�֧��wmm����ˢ��mibֵ,��ֹ֮ǰ������֧��wmm��ap,mib�ָ������� */
    mib_info->wlan_mib_sta_config.dot11_qos_option_implemented = mac_dev->wmm;
    /* ����join_request֡����sta�������ŵ��ʹ��������Ϣ */
    if (hmac_sta_update_join_channel(mac_vap, join_req) != HI_SUCCESS) {
        return HI_FAIL;
    }
    /* ����join_request֡����sta������Э��ģʽ�����Ϣ */
    if (hmac_sta_update_join_protocol(hmac_vap, join_req) != HI_SUCCESS) {
        return HI_FAIL;
    }

    /* STA������20MHz���У����Ҫ�л���40 or 80MHz���У���Ҫ����һ������: */
    /* (1) �û�֧��40 or 80MHz���� */
    /* (2) AP֧��40 or 80MHz����(HT Supported Channel Width Set = 1 && VHT Supported Channel Width Set = 0) */
    /* (3) AP��40 or 80MHz����(SCO = SCA or SCB && VHT Channel Width = 1) */
    ret = mac_get_channel_idx_from_num(mac_vap->channel.band, mac_vap->channel.chan_number, &(mac_vap->channel.idx));
    if (ret != HI_SUCCESS) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_SCAN,
            "{hmac_sta_update_join_req_params::band and channel_num are not compatible.band[%d], channel_num[%d]}",
            mac_vap->channel.band, mac_vap->channel.chan_number);
        return ret;
    }

    /* ����Э�������Ϣ������WMM P2P 11I 20/40M�� */
    hmac_update_join_req_params_prot_sta(hmac_vap, join_req);
    /* �����Ż�����ͬƵ���µ�������һ�� */
    if (WLAN_BAND_2G == mac_vap->channel.band) {
        mac_mib_set_short_preamble_option_implemented(mac_vap, WLAN_LEGACY_11B_MIB_SHORT_PREAMBLE);
        mac_mib_set_spectrum_management_required(mac_vap, HI_FALSE);
    } else {
        mac_mib_set_short_preamble_option_implemented(mac_vap, WLAN_LEGACY_11B_MIB_LONG_PREAMBLE);
        mac_mib_set_spectrum_management_required(mac_vap, HI_TRUE);
    }

    if (0 == hmac_calc_up_vap_num(mac_dev)) {
        mac_dev->max_channel = mac_vap->channel.chan_number;
        mac_dev->max_band = mac_vap->channel.band;
        mac_dev->max_bandwidth = mac_vap->channel.en_bandwidth;
    }
    /* ���͹��������¼���dmac */
    return hmac_sta_dispatch_join_req(mac_vap, join_req);
}

/*****************************************************************************
 ��������  : ����SME���͹�����JOIN_REQ�������JOIN���̣���STA״̬����ΪWAIT_JOIN
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��4��7��
    ��    ��   : Hisilicon
    �޸�����   : ɾ���ȴ�beacon��tbtt�жϵĲ���
*****************************************************************************/
hi_u32 hmac_sta_wait_join(hmac_vap_stru *hmac_vap, hmac_join_req_stru *join_req)
{
#ifdef _PRE_WLAN_FEATURE_P2P
    /* 1102 P2PSTA���� todo ���²���ʧ�ܵĻ���Ҫ���ض����Ǽ����·�Join���� */
    if (hmac_p2p_check_can_enter_state(hmac_vap->base_vap, HMAC_FSM_INPUT_ASOC_REQ) != HI_SUCCESS) {
        /* ���ܽ������״̬�������豸æ */
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_join fail}\r\n");
        return HI_ERR_CODE_CONFIG_BUSY;
    }
#endif

    /* ����JOIN REG params ��MIB��MAC�Ĵ��� */
    hi_u32 ret = hmac_sta_update_join_req_params(hmac_vap, join_req);
    if (ret != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_join::params fail[%d]!}", ret);
        return ret;
    }
    oam_info_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_join::chn=%d bcnPeriod=%d DTIMPeriod=%d.}",
                  join_req->bss_dscr.channel.chan_number,
                  join_req->bss_dscr.us_beacon_period, join_req->bss_dscr.dtim_period);

    /* ��proxy staģʽʱ����Ҫ��dtim�������õ�dmac */
    /* ���¼���DMAC, �����¼��ڴ� */
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_ctx_set_dtim_tsf_reg_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_join::alloc null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;

    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_JOIN_DTIM_TSF_REG,
                       sizeof(dmac_ctx_set_dtim_tsf_reg_stru), FRW_EVENT_PIPELINE_STAGE_1, hmac_vap->base_vap->vap_id);

    dmac_ctx_set_dtim_tsf_reg_stru *set_dtim_tsf_reg_params = (dmac_ctx_set_dtim_tsf_reg_stru *)event->auc_event_data;

    /* ��Ap bssid��tsf REG ����ֵ�������¼�payload�� */
    set_dtim_tsf_reg_params->dtim_cnt = join_req->bss_dscr.dtim_cnt;
    set_dtim_tsf_reg_params->dtim_period = join_req->bss_dscr.dtim_period;
    set_dtim_tsf_reg_params->us_tsf_bit0 = BIT0;
    if (memcpy_s(set_dtim_tsf_reg_params->auc_bssid, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid,
                 WLAN_MAC_ADDR_LEN) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CFG, "hmac_sta_wait_join:: auc_bssid memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(dmac_ctx_set_dtim_tsf_reg_stru));
    frw_event_free(event_mem);

    hmac_mgmt_status_enum_uint8 join_result_code = HMAC_MGMT_SUCCESS;
    /* �л�STA״̬��JOIN_COMP */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_JOIN_COMP);

    /* ����JOIN�ɹ���Ϣ��SME */
    hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_JOIN_RSP, &join_result_code);

    oam_info_log4(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                  "{hmac_sta_wait_join::Join AP[XX:XX:XX:%02X:%02X:%02X] HT=%d VHT=%d HI_SUCCESS.}",
                  join_req->bss_dscr.auc_bssid[3], join_req->bss_dscr.auc_bssid[4], /* 3 4 Ԫ������ */
                  join_req->bss_dscr.auc_bssid[5], join_req->bss_dscr.ht_capable); /* 5 Ԫ������ */

    oam_info_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                  "{hmac_sta_wait_join::Join AP channel=%d bandwidth=%d Beacon Period=%d HI_SUCCESS.}",
                  join_req->bss_dscr.channel.chan_number,
                  hmac_vap->base_vap->channel.en_bandwidth, join_req->bss_dscr.us_beacon_period);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����sme������auth req���󡣽�״̬��ΪWAIT_AUTH_SEQ2 ���¼���dmac����
 �޸���ʷ      :
  1.��    ��   : 2013��6��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_wait_auth(hmac_vap_stru *hmac_vap, hi_u16 auth_timeout)
{
    /* ������֤֡�ռ� */
    oal_netbuf_stru *auth_frame = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);    /* align 4 */
    if (auth_frame == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta::puc_auth_frame null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(oal_netbuf_cb(auth_frame), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    if (memset_s((hi_u8 *)oal_netbuf_header(auth_frame), MAC_80211_FRAME_LEN, 0, MAC_80211_FRAME_LEN) != EOK) {
        oal_netbuf_free(auth_frame);
        return HI_FAIL;
    }

    /* ����֤����֡ */
    hi_u16 us_auth_len = hmac_mgmt_encap_auth_req(hmac_vap, (hi_u8 *)(oal_netbuf_header(auth_frame)));
    if (us_auth_len == 0) {
        /* ��֡ʧ�� */
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta:hmac_mgmt_encap_auth_req fail}");

        oal_netbuf_free(auth_frame);
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
        /* ��ϵͳ����reset MAC ֮��� */
        return HI_FAIL;
    }

    oal_netbuf_put(auth_frame, us_auth_len);
    hmac_user_stru *hmac_user_ap = (hmac_user_stru *)hmac_user_get_user_stru(hmac_vap->base_vap->assoc_vap_id);
    if ((hmac_user_ap == HI_NULL) || (hmac_user_ap->base_user == HI_NULL)) {
        oal_netbuf_free(auth_frame);
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta::pst_hmac_user_ap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* Ϊ��д����������׼������ */
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(auth_frame);        /* ��ȡcb�ṹ�� */
    tx_ctl->us_mpdu_len = us_auth_len;  /* dmac������Ҫ��mpdu���� */
    tx_ctl->us_tx_user_idx = hmac_user_ap->base_user->us_assoc_id;   /* ���������Ҫ��ȡuser�ṹ�� */
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(auth_frame);
    tx_ctl->mac_head_type = 1;

    /* �����WEP����Ҫ��ap��mac��ַд��lut */
    hi_u32 ret = hmac_init_security(hmac_vap->base_vap, hmac_user_ap->base_user->user_mac_addr, WLAN_MAC_ADDR_LEN);
    if (ret != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_auth::security failed[%d].}", ret);
    }

    /* ���¼���dmac����֡���� */
    ret = hmac_tx_mgmt_send_event(hmac_vap->base_vap, auth_frame, us_auth_len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(auth_frame);
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AUTH,
                         "{hmac_wait_auth_sta::hmac_tx_mgmt_send_event failed[%d].}", ret);
        return ret;
    }

    /* ����״̬ */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2);

    /* ������֤��ʱ��ʱ�� */
    hmac_vap->mgmt_timetout_param.state = MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2;
    hmac_vap->mgmt_timetout_param.user_index = (hi_u8)hmac_user_ap->base_user->us_assoc_id;
    hmac_vap->mgmt_timetout_param.vap_id = hmac_vap->base_vap->vap_id;
    frw_timer_create_timer(&hmac_vap->mgmt_timer, hmac_mgmt_timeout_sta, auth_timeout,
                           &hmac_vap->mgmt_timetout_param, HI_FALSE);

    return HI_SUCCESS;
}

hi_u32 hmac_sta_shared_key_auth_proc(hmac_vap_stru *hmac_vap, hi_u8 *mac_hdr)
{
    oal_netbuf_stru *auth_frame = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);    /* align 4 */
    if (auth_frame == HI_NULL) {
        /* ��λmac */
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta::pst_auth_frame null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ�� */
    memset_s(oal_netbuf_cb(auth_frame), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    hi_u16 auth_frame_len = hmac_mgmt_encap_auth_req_seq3(hmac_vap, (hi_u8*)oal_netbuf_header(auth_frame), mac_hdr);
    if (auth_frame_len == 0) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta::auth_frame_len is 0.}");
        oal_netbuf_free(auth_frame);
        return HI_FAIL;
    }
    oal_netbuf_put(auth_frame, auth_frame_len);

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru((hi_u16)hmac_vap->base_vap->assoc_vap_id);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oal_netbuf_free(auth_frame);
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta::pst_hmac_user_ap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д���ͺͷ��������Ҫ�Ĳ��� */
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(auth_frame);
    tx_ctl->us_mpdu_len         = auth_frame_len;                    /* ������Ҫ֡���� */
    tx_ctl->us_tx_user_idx      = hmac_user->base_user->us_assoc_id; /* �������Ҫ��ȡ�û� */
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header        = (mac_ieee80211_frame_stru *)oal_netbuf_header(auth_frame);
    tx_ctl->mac_head_type       = 1;

    /* ���¼���dmac���� */
    hi_u32 ret = hmac_tx_mgmt_send_event(hmac_vap->base_vap, auth_frame, auth_frame_len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(auth_frame);
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_wait_auth_sta::send_event Err=%d}", ret);
        return ret;
    }

    /* DTS2016092807661: �յ�seq = 2 ����֤֡��������������ȡ����ʱ�� */
    frw_timer_immediate_destroy_timer(&hmac_vap->mgmt_timer);

    /* ����״̬ΪMAC_VAP_STATE_STA_WAIT_AUTH_SEQ4����������ʱ�� */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4);

    frw_timer_create_timer(&hmac_vap->mgmt_timer, hmac_mgmt_timeout_sta, hmac_vap->mgmt_timer.timeout,
                           &hmac_vap->mgmt_timetout_param, HI_FALSE);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ������յ�seq num ����2 ����֤֡
 �޸���ʷ      :
  1.��    ��   : 2013��6��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_wait_auth_seq2_rx(hmac_vap_stru *hmac_vap, const dmac_wlan_crx_event_stru *crx_event)
{
    hmac_auth_rsp_stru auth_rsp = {0};

    /* ÿһ��MPDU�Ŀ�����Ϣ */
    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)crx_event->netbuf);
    hi_u8            *mac_hdr = (hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr;

    if ((mac_get_frame_sub_type(mac_hdr) != WLAN_FC0_SUBTYPE_AUTH) ||
        (mac_get_auth_seq_num(mac_hdr) != WLAN_AUTH_TRASACTION_NUM_TWO)) {
        return HI_SUCCESS;
    }

    /* AUTH alg CHECK */
    hi_u16 auth_alg = mac_get_auth_alg(mac_hdr);
    if ((hmac_vap->auth_mode != auth_alg) && (hmac_vap->auth_mode != WLAN_WITP_AUTH_AUTOMATIC)) {
        oam_warning_log2(hmac_vap->base_vap->vap_id, OAM_SF_AUTH,
            "{hmac_sta_wait_auth_seq2_rx::rcv unexpected auth alg[%d/%d].}", auth_alg, hmac_vap->auth_mode);
    }

    if (mac_get_auth_status(mac_hdr) != MAC_SUCCESSFUL_STATUSCODE) {
        /* DTS2016092807661: �յ�seq = 2 ����֤֡��������������ȡ����ʱ�� */
        frw_timer_immediate_destroy_timer(&hmac_vap->mgmt_timer);

        auth_rsp.us_status_code = mac_get_auth_status(mac_hdr);

        /* �ϱ���SME��֤�ɹ� */
        hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_AUTH_RSP, (hi_u8 *)&auth_rsp);
        return HI_SUCCESS;
    }

    if (auth_alg == WLAN_WITP_AUTH_OPEN_SYSTEM) {
        /* DTS2016092807661: �յ�seq = 2 ����֤֡��������������ȡ����ʱ�� */
        frw_timer_immediate_destroy_timer(&hmac_vap->mgmt_timer);

        /* ��״̬����ΪAUTH_COMP */
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_AUTH_COMP);
        auth_rsp.us_status_code = HMAC_MGMT_SUCCESS;

        /* �ϱ���SME��֤�ɹ� */
        hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_AUTH_RSP, (hi_u8 *)&auth_rsp);

        return HI_SUCCESS;
    } else if (auth_alg == WLAN_WITP_AUTH_SHARED_KEY) {
        /* ׼��seq����3����֤֡ */
        hi_u32 ret = hmac_sta_shared_key_auth_proc(hmac_vap, mac_hdr);
        return ret;
    } else {
        /* DTS2016092807661: �յ�seq = 2 ����֤֡��������������ȡ����ʱ�� */
        frw_timer_immediate_destroy_timer(&hmac_vap->mgmt_timer);

        /* ���յ�AP �ظ���auth response ��֧����֤�㷨��ǰ��֧�ֵ�����£�status code ȴ��SUCC,
           ��Ϊ��֤�ɹ������Ҽ����������� */
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AUTH,
                         "{hmac_sta_wait_auth_seq2_rx::auth_alg[%d]Err}", auth_alg);

        /* ��״̬����ΪAUTH_COMP */
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_AUTH_COMP);
        auth_rsp.us_status_code = HMAC_MGMT_SUCCESS;

        /* �ϱ���SME��֤�ɹ� */
        hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_AUTH_RSP, (hi_u8 *)&auth_rsp);

        return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : �����յ�seq = 4 ����֤֡
 �޸���ʷ      :
  1.��    ��   : 2013��6��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_wait_auth_seq4_rx(hmac_vap_stru *hmac_vap, const dmac_wlan_crx_event_stru *crx_event)
{
    hmac_rx_ctl_stru    *rx_ctrl = HI_NULL;
    hi_u8               *puc_mac_hdr = HI_NULL;
    hi_u16              us_auth_status;
    hmac_auth_rsp_stru  auth_rsp = {{0}, 0};

    /* ÿһ��MPDU�Ŀ�����Ϣ */
    rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)crx_event->netbuf);
    puc_mac_hdr = (hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr;

    if (WLAN_FC0_SUBTYPE_AUTH == mac_get_frame_sub_type(puc_mac_hdr)) {
        us_auth_status = mac_get_auth_status(puc_mac_hdr);
        if ((WLAN_AUTH_TRASACTION_NUM_FOUR == mac_get_auth_seq_num(puc_mac_hdr)) &&
            (us_auth_status == MAC_SUCCESSFUL_STATUSCODE)) {
            /* ���յ�seq = 4 ��״̬λΪsucc ȡ����ʱ�� */
            frw_timer_immediate_destroy_timer(&hmac_vap->mgmt_timer);

            auth_rsp.us_status_code = HMAC_MGMT_SUCCESS;

            /* ����sta״̬ΪMAC_VAP_STATE_STA_AUTH_COMP */
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_AUTH_COMP);
            oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_sta_wait_auth_seq4_rx::auth succ.}");
            /* ����֤����ϱ�SME */
            hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_AUTH_RSP, (hi_u8 *)&auth_rsp);
        } else {
            oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AUTH,
                             "{hmac_sta_wait_auth_seq4_rx::transaction num.status[%d]}", us_auth_status);
            /* �ȴ���ʱ����ʱ */
        }
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_sta_encap_asoc_req_frame(hmac_vap_stru *hmac_vap, oal_netbuf_stru *asoc_req_frame,
    hi_u32 *asoc_frame_len)
{
    /* ��֡ (Re)Assoc_req_Frame */
    hi_u32 asoc_frame_len_local = hmac_mgmt_encap_asoc_req_sta(hmac_vap, (hi_u8 *)(oal_netbuf_header(asoc_req_frame)));
    if (asoc_frame_len_local == 0) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_asoc::get asoc_frame_len fail.}");
        return HI_FAIL;
    }
    oal_netbuf_put(asoc_req_frame, asoc_frame_len_local);

    if (hmac_vap->puc_asoc_req_ie_buff != HI_NULL) {
        oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
        hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
    }

    if (oal_unlikely(asoc_frame_len_local < OAL_ASSOC_REQ_IE_OFFSET)) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_sta_wait_asoc::invalid ul_asoc_req_ie_len[%u].}", asoc_frame_len_local);
        return HI_FAIL;
    }
    *asoc_frame_len = asoc_frame_len_local;

    return HI_SUCCESS;
}

static hi_u32 hmac_sta_fill_asoc_req_ie_buff(hmac_vap_stru *hmac_vap, const oal_netbuf_stru *asoc_req_frame,
    hi_u32 asoc_frame_len)
{
    /* Should we change the ie buff from local mem to netbuf ?  */
    /* �˴�������ڴ棬ֻ���ϱ����ں˺��ͷ� */
    hmac_vap->us_asoc_req_ie_len = (hi_u16)((hmac_vap->reassoc_flag) ?
        (asoc_frame_len - OAL_ASSOC_REQ_IE_OFFSET - OAL_MAC_ADDR_LEN) : (asoc_frame_len - OAL_ASSOC_REQ_IE_OFFSET));
    hmac_vap->puc_asoc_req_ie_buff = oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, hmac_vap->us_asoc_req_ie_len);
    if (hmac_vap->puc_asoc_req_ie_buff == HI_NULL) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
            "{hmac_sta_fill_asoc_req_ie_buff::alloc %u bytes failed}", hmac_vap->us_asoc_req_ie_len);
        return HI_FAIL;
    }

    if (hmac_vap->reassoc_flag) {
        if (memcpy_s(hmac_vap->puc_asoc_req_ie_buff, hmac_vap->us_asoc_req_ie_len,
            oal_netbuf_header(asoc_req_frame) + OAL_ASSOC_REQ_IE_OFFSET + OAL_MAC_ADDR_LEN,
            hmac_vap->us_asoc_req_ie_len) != EOK) {
            oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
            hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
            oam_error_log0(0, OAM_SF_CFG, "hmac_sta_fill_asoc_req_ie_buff:: pst_asoc_req_frame memcpy_s fail.");
            return HI_FAIL;
        }
    } else {
        if (memcpy_s(hmac_vap->puc_asoc_req_ie_buff, hmac_vap->us_asoc_req_ie_len,
            oal_netbuf_header(asoc_req_frame) + OAL_ASSOC_REQ_IE_OFFSET, hmac_vap->us_asoc_req_ie_len) != EOK) {
            oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
            hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
            oam_error_log0(0, OAM_SF_CFG, "hmac_sta_fill_asoc_req_ie_buff:: pst_asoc_req_frame memcpy_s fail.");
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}

static hi_void hmac_sta_fill_tx_ctl_stru(oal_netbuf_stru *asoc_req_frame, hi_u32 asoc_frame_len,
    const hmac_user_stru *hmac_user_ap)
{
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(asoc_req_frame);

    tx_ctl->us_mpdu_len = (hi_u16) asoc_frame_len;
    tx_ctl->us_tx_user_idx = hmac_user_ap->base_user->us_assoc_id;
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(asoc_req_frame);
    tx_ctl->mac_head_type = 1;
}
/*****************************************************************************
 ��������  : ��AUTH_COMP״̬���յ�SME��������ASOC_REQ���󣬽�STA״̬����ΪWAIT_ASOC,
             ���¼���DMAC������Asoc_req_frame
 �޸���ʷ      :
  1.��    ��   : 2013��6��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_wait_asoc(hmac_vap_stru *hmac_vap, hi_u16 us_assoc_timeout)
{
    hi_u32 asoc_frame_len = 0;
    oal_netbuf_stru *asoc_req_frame = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);    /* align 4 */

    if (asoc_req_frame == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_asoc::pst_asoc_req_frame null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(oal_netbuf_cb(asoc_req_frame), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    /* ��mac header���� */
    if (memset_s((hi_u8 *)oal_netbuf_header(asoc_req_frame), MAC_80211_FRAME_LEN, 0, MAC_80211_FRAME_LEN) != EOK) {
        oal_netbuf_free(asoc_req_frame);
        return HI_FAIL;
    }

    /* ��֡ (Re)Assoc_req_Frame */
    if (hmac_sta_encap_asoc_req_frame(hmac_vap, asoc_req_frame, &asoc_frame_len) != HI_SUCCESS) {
        oal_netbuf_free(asoc_req_frame);
        return HI_FAIL;
    }

    /* ����hmac_vap->puc_asoc_req_ie_buff �ڴ棬ֻ���ϱ����ں˺��ͷ� */
    if (hmac_sta_fill_asoc_req_ie_buff(hmac_vap, asoc_req_frame, asoc_frame_len) != HI_SUCCESS) {
        oal_netbuf_free(asoc_req_frame);
        return HI_FAIL;
    }

    hmac_user_stru *hmac_user_ap = (hmac_user_stru *)hmac_user_get_user_stru(hmac_vap->base_vap->assoc_vap_id);
    if ((hmac_user_ap == HI_NULL) || (hmac_user_ap->base_user == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "{hmac_sta_wait_asoc::pst_hmac_user_ap null.}");
        oal_netbuf_free(asoc_req_frame);
        oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
        hmac_vap->puc_asoc_req_ie_buff = HI_NULL;
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ���tx_ctl ��Ϣ */
    hmac_sta_fill_tx_ctl_stru(asoc_req_frame, asoc_frame_len, hmac_user_ap);

    /* ���¼���DMAC����֡���� */
    hi_u32 ret = hmac_tx_mgmt_send_event(hmac_vap->base_vap, asoc_req_frame, (hi_u16) asoc_frame_len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(asoc_req_frame);
        oal_mem_free(hmac_vap->puc_asoc_req_ie_buff);
        hmac_vap->puc_asoc_req_ie_buff = HI_NULL;

        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                         "{hmac_sta_wait_asoc::hmac_tx_mgmt_send_event failed[%d].}", ret);
        return ret;
    }

    /* ����״̬ */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_WAIT_ASOC);

    /* ����������ʱ��ʱ��, Ϊ�Զ�ap����һ����ʱ���������ʱapû��asoc rsp��������ʱ���� */
    hmac_vap->mgmt_timetout_param.state = MAC_VAP_STATE_STA_WAIT_ASOC;
    hmac_vap->mgmt_timetout_param.user_index = (hi_u8)hmac_user_ap->base_user->us_assoc_id;
    hmac_vap->mgmt_timetout_param.vap_id = hmac_vap->base_vap->vap_id;

    frw_timer_create_timer(&(hmac_vap->mgmt_timer), hmac_mgmt_timeout_sta, us_assoc_timeout,
        &(hmac_vap->mgmt_timetout_param), HI_FALSE);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����STA������AP����QoS��ʱ��STAĬ�ϲ���VO���Է�������
 �޸���ʷ      :
  1.��    ��   : 2013��10��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_up_update_edca_params_machw(const hmac_vap_stru *hmac_vap, mac_wmm_set_param_type_enum_uint8 type)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    dmac_ctx_sta_asoc_set_edca_reg_stru asoc_set_edca_reg_param = { 0 };

    /* ���¼���dmacд�Ĵ��� */
    /* �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(dmac_ctx_sta_asoc_set_edca_reg_stru));
    if (event_mem == HI_NULL) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_sta_up_update_edca_params_machw::event_mem alloc null, size[%d].}",
                       sizeof(dmac_ctx_sta_asoc_set_edca_reg_stru));
        return HI_ERR_CODE_PTR_NULL;
    }

    asoc_set_edca_reg_param.vap_id = hmac_vap->base_vap->vap_id;
    asoc_set_edca_reg_param.set_param_type = type;

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_STA_SET_EDCA_REG,
                       sizeof(dmac_ctx_sta_asoc_set_edca_reg_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       hmac_vap->base_vap->vap_id);

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    if (type != MAC_WMM_SET_PARAM_TYPE_DEFAULT) {
        if (memcpy_s((hi_u8 *)&asoc_set_edca_reg_param.ast_wlan_mib_qap_edac,
            (sizeof(wlan_mib_dot11_qapedca_entry_stru) * WLAN_WME_AC_BUTT),
            (hi_u8 *)&hmac_vap->base_vap->mib_info->wlan_mib_qap_edac,
            (sizeof(wlan_mib_dot11_qapedca_entry_stru) * WLAN_WME_AC_BUTT)) != EOK) {
            frw_event_free(event_mem);
            oam_error_log0(0, OAM_SF_CFG, "hmac_sta_up_update_edca_params_machw:: st_wlan_mib_qap_edac memcpy_s fail.");
            return HI_FAIL;
        }
    }
#endif

    /* �������� */
    if (memcpy_s(frw_get_event_payload(event_mem), sizeof(dmac_ctx_sta_asoc_set_edca_reg_stru),
        (hi_u8 *)&asoc_set_edca_reg_param, sizeof(dmac_ctx_sta_asoc_set_edca_reg_stru)) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, 0, "hmac_sta_up_update_edca_params_machw:: st_asoc_set_edca_reg_param memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(dmac_ctx_sta_asoc_set_edca_reg_stru));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : STA����ÿһ��AC�Ĳ���
 �������  : pst_hmac_sta:����staģʽ��vap
             puc_payload :֡��
 �޸���ʷ      :
  1.��    ��   : 2013��10��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_sta_up_update_edca_params_mib(const hmac_vap_stru *hmac_vap, const hi_u8 *puc_payload)
{
    hi_u8 aifsn;
    hi_u8 aci;
    hi_u8 ecwmin;
    hi_u8 ecwmax;
    hi_u16 us_txop_limit;
    hi_u8 acm;
    /*        AC Parameters Record Format         */
    /* ------------------------------------------ */
    /* |     1     |       1       |      2     | */
    /* ------------------------------------------ */
    /* | ACI/AIFSN | ECWmin/ECWmax | TXOP Limit | */
    /* ------------------------------------------ */
    /************* ACI/AIFSN Field ***************/
    /*     ---------------------------------- */
    /* bit |   4   |  1  |  2  |    1     |   */
    /*     ---------------------------------- */
    /*     | AIFSN | ACM | ACI | Reserved |   */
    /*     ---------------------------------- */
    aifsn = puc_payload[0] & MAC_WMM_QOS_PARAM_AIFSN_MASK;
    acm = (puc_payload[0] & BIT4) ? HI_TRUE : HI_FALSE;
    aci = (puc_payload[0] >> MAC_WMM_QOS_PARAM_ACI_BIT_OFFSET) & MAC_WMM_QOS_PARAM_ACI_MASK;

    /* ECWmin/ECWmax Field */
    /*     ------------------- */
    /* bit |   4    |   4    | */
    /*     ------------------- */
    /*     | ECWmin | ECWmax | */
    /*     ------------------- */
    ecwmin = (puc_payload[1] & MAC_WMM_QOS_PARAM_ECWMIN_MASK);
    ecwmax = ((puc_payload[1] & MAC_WMM_QOS_PARAM_ECWMAX_MASK) >> MAC_WMM_QOS_PARAM_ECWMAX_BIT_OFFSET);

    /* ��mib���кͼĴ����ﱣ���TXOPֵ������usΪ��λ�ģ����Ǵ����ʱ������32usΪ
       ��λ���д���ģ�����ڽ�����ʱ����Ҫ����������ֵ����32
     */
    us_txop_limit = puc_payload[2] | /* 2 Ԫ������ */
        ((puc_payload[3] & MAC_WMM_QOS_PARAM_TXOPLIMIT_MASK) << MAC_WMM_QOS_PARAM_BIT_NUMS_OF_ONE_BYTE); /* 3Ԫ������ */
    us_txop_limit = (hi_u16) (us_txop_limit << MAC_WMM_QOS_PARAM_TXOPLIMIT_SAVE_TO_TRANS_TIMES);

    /* ������Ӧ��MIB����Ϣ */
    if (aci < WLAN_WME_AC_BUTT) {
        hmac_vap->base_vap->mib_info->wlan_mib_qap_edac[aci].dot11_qapedca_table_c_wmin = ecwmin;
        hmac_vap->base_vap->mib_info->wlan_mib_qap_edac[aci].dot11_qapedca_table_c_wmax = ecwmax;
        hmac_vap->base_vap->mib_info->wlan_mib_qap_edac[aci].dot11_qapedca_table_aifsn = aifsn;
        hmac_vap->base_vap->mib_info->wlan_mib_qap_edac[aci].dot11_qapedca_table_txop_limit =
            us_txop_limit;
        hmac_vap->base_vap->mib_info->wlan_mib_qap_edac[aci].dot11_qapedca_table_mandatory =
            acm;
    }
}

/*****************************************************************************
 ��������  : STA���յ�beacon֡���߹�����Ӧ֡���������EDCA�������漰��mibֵ
             �ͼĴ���
 �������  : puc_payload :֡��
             ul_msg_len  :֡����
             us_info_elem_offset :��ǰָ���֡��λ��
             pst_hmac_sta        :ָ��hmac_vap��ָ�룬vap��staģʽ
             uc_frame_sub_type   :֡�Ĵ�����
 �޸���ʷ      :
  1.��    ��   : 2013��10��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_sta_up_update_edca_params(const hmac_edca_params_info_stru *edca_params_info,
    const hmac_vap_stru *hmac_vap, hi_u8 frame_sub_type, const hmac_user_stru *hmac_user)
{
    hi_u8  param_set_cnt, edca_param_set, apsd;
    hi_u16 us_msg_offset = edca_params_info->us_info_elem_offset; /* ���֡���Ƿ���WMM��ϢԪ�� */
    mac_device_stru *mac_dev = (mac_device_stru *)mac_res_get_dev();

    /************************ WMM Parameter Element ***************************/
    /* ------------------------------------------------------------------------------ */
    /* | EID | LEN | OUI |OUI Type |OUI Subtype |Version |QoS Info |Resd |AC Params | */
    /* ------------------------------------------------------------------------------ */
    /* |  1  |  1  |  3  |    1    |     1      |    1   |    1    |  1  |    16    | */
    /* ------------------------------------------------------------------------------ */
    /******************* QoS Info field when sent from WMM AP *****************/
    /*        --------------------------------------------                    */
    /*          | Parameter Set Count | Reserved | U-APSD |                   */
    /*          --------------------------------------------                  */
    /*   bit    |        0~3          |   4~6    |   7    |                   */
    /*          --------------------------------------------                  */
    /**************************************************************************/
    while (us_msg_offset < edca_params_info->us_msg_len) {
        /* �жϵ�ǰ��ie�Ƿ���wmm ie��������ǣ����������һ��ie������ǣ�����WMM���� */
        if (HI_TRUE == mac_is_wmm_ie(&(edca_params_info->puc_payload[us_msg_offset]))) {
            /* ����wmm ie�Ƿ�Я��EDCA���� */
            edca_param_set = edca_params_info->puc_payload[us_msg_offset + MAC_OUISUBTYPE_WMM_PARAM_OFFSET];

            us_msg_offset += HMAC_WMM_QOS_PARAMS_HDR_LEN;
            param_set_cnt = edca_params_info->puc_payload[us_msg_offset] & 0x0F;

            /* ����յ�����beacon֡������param_set_countû�иı䣬˵��AP��WMM����û�б�
               ��STAҲ�������κθı䣬ֱ�ӷ��ؼ���.
             */
            if ((frame_sub_type == WLAN_FC0_SUBTYPE_BEACON) &&
                (param_set_cnt == hmac_vap->base_vap->wmm_params_update_count)) {
                return;
            }

            mac_dev->wmm = HI_TRUE;

            if (frame_sub_type == WLAN_FC0_SUBTYPE_BEACON) {
                /* ����QoS Info */
                mac_vap_set_wmm_params_update_count(hmac_vap->base_vap, param_set_cnt);
            }

            apsd = (edca_params_info->puc_payload[us_msg_offset] & BIT7) ? HI_TRUE : HI_FALSE;
            mac_user_set_apsd(hmac_user->base_user, apsd);

            us_msg_offset += HMAC_WMM_QOSINFO_AND_RESV_LEN;

            /* wmm ie�в�Я��edca���� ֱ�ӷ��� */
            if (edca_param_set != MAC_OUISUBTYPE_WMM_PARAM) {
                return;
            }

            /* ���ÿһ��AC������EDCA���� */
            for (hi_u8 ac_num_loop = 0; ac_num_loop < WLAN_WME_AC_BUTT; ac_num_loop++) {
                hmac_sta_up_update_edca_params_mib(hmac_vap, &(edca_params_info->puc_payload[us_msg_offset]));
                us_msg_offset += HMAC_WMM_AC_PARAMS_RECORD_LEN;
            }
            /* ����EDCA��ص�MAC�Ĵ��� */
            hmac_sta_up_update_edca_params_machw(hmac_vap, MAC_WMM_SET_PARAM_TYPE_UPDATE_EDCA);
            return;
        }

        us_msg_offset += (edca_params_info->puc_payload[us_msg_offset + 1] + MAC_IE_HDR_LEN);
    }

    if (frame_sub_type == WLAN_FC0_SUBTYPE_ASSOC_RSP) {
        /* ����STA������AP����QoS�ģ�STA��ȥʹ��EDCA�Ĵ�������Ĭ������VO���������� */
        hi_u32 ret = hmac_sta_up_update_edca_params_machw(hmac_vap, MAC_WMM_SET_PARAM_TYPE_DEFAULT);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                             "{hmac_sta_up_update_edca_params::hmac_sta_up_update_edca_params_machw failed[%d].}", ret);
        }
    }
}

/* DTS2015031908110 d00223710 2015-03-24 begin */
/*****************************************************************************
 ��������  : ��beacon HT IE״̬�仯�¸���mac user info��device
 �޸���ʷ      :
  1.��    ��   : 2015��03��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_sta_update_mac_user_info(const hmac_user_stru *hmac_user_ap, hi_u8 user_idx)
{
    mac_vap_stru *mac_vap = HI_NULL;
    mac_user_stru *mac_user_ap = HI_NULL;
    hi_u32 ret;

    if (hmac_user_ap == HI_NULL) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_sta_update_mac_user_info::param null.}");
        return;
    }

    mac_vap = mac_vap_get_vap_stru(hmac_user_ap->base_user->vap_id);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_RX, "{hmac_sta_update_mac_user_info::get mac_vap [vap_id:%d] null.}",
                       hmac_user_ap->base_user->vap_id);
        return;
    }

    mac_user_ap = hmac_user_ap->base_user;
    oam_warning_log3(mac_vap->vap_id, OAM_SF_RX,
                     "{hmac_sta_update_mac_user_info::user_idx:%d,en_avail_bandwidth:%d,en_cur_bandwidth:%d}",
                     user_idx, mac_user_ap->avail_bandwidth, mac_user_ap->cur_bandwidth);

    ret = hmac_config_user_info_syn(mac_vap, mac_user_ap);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_RX,
                       "{hmac_sta_update_mac_user_info::hmac_config_user_info_syn failed[%d].}", ret);
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    ret = hmac_config_user_rate_info_syn(mac_vap, mac_user_ap);
    if (ret != HI_SUCCESS) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_RX,
                       "{hmac_sta_wait_asoc_rx::hmac_syn_rate_info failed[%d].}", ret);
    }
#endif
    return;
}

/*****************************************************************************
 ��������  : ���ѱ����probe rsp��Ѱ��ָ��IE��һ��������asoc rsp��Ѱ��IEʧ��ʱ
             ����probe rsp����һ������
 �������  : pst_mac_vap : mac vap�ṹ��
             uc_eid: Ҫ���ҵ�EID
 �������  : puc_payload: probe rsp֡�壬��֡�ڵ�һ��IE��ͷ
             us_index:Ŀ��IE��payload�е����λ��
 �޸���ʷ      :
  1.��    ��   : 2016��5��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 *hmac_sta_find_ie_in_probe_rsp(const mac_vap_stru *mac_vap, hi_u8 eid, hi_u16 *pus_index)
{
    hmac_scanned_bss_info *scanned_bss_info = HI_NULL;
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;
    hmac_device_stru *hmac_dev = HI_NULL;
    mac_bss_dscr_stru *bss_dscr = HI_NULL;
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 *puc_payload = HI_NULL;
    hi_u8 us_offset;

    if (mac_vap == HI_NULL) {
        oam_warning_log0(0, OAM_SF_SCAN, "{find ie fail, pst_mac_vap is null.}");
        return HI_NULL;
    }

    /* ��ȡhmac device �ṹ */
    hmac_dev = hmac_get_device_stru();
    /* ��ȡ����ɨ���bss����Ľṹ�� */
    bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);

    oal_spin_lock(&(bss_mgmt->st_lock));

    scanned_bss_info = hmac_scan_find_scanned_bss_by_bssid(bss_mgmt, mac_vap->auc_bssid);
    if (scanned_bss_info == HI_NULL) {
        oam_warning_log3(mac_vap->vap_id, OAM_SF_CFG,
                         "{find the bss failed by bssid:XX:XX:XX:%02X:%02X:%02X}",
                         mac_vap->auc_bssid[3], mac_vap->auc_bssid[4], mac_vap->auc_bssid[5]); /* 3 4 5 Ԫ������ */

        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));
        return HI_NULL;
    }

    bss_dscr = &(scanned_bss_info->bss_dscr_info);
    /* ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));

    /* ��IE��ͷ��payload�����ع�������ʹ�� */
    us_offset = MAC_80211_FRAME_LEN + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /* �ɱ������÷���lin_t e416�澯���� */
    puc_payload = (hi_u8 *)(bss_dscr->auc_mgmt_buff + us_offset);
    if (bss_dscr->mgmt_len < us_offset) {
        return HI_NULL;
    }

    puc_ie = mac_find_ie(eid, puc_payload, (bss_dscr->mgmt_len - us_offset));
    if (puc_ie == HI_NULL) {
        return HI_NULL;
    }

    /* IE���ȳ���У�� */
    if (*(puc_ie + 1) == 0) {
        oam_warning_log1(0, OAM_SF_ANY, "{IE[%d] len in probe rsp is 0, find ie fail.}", eid);
        return HI_NULL;
    }

    *pus_index = (hi_u16) (puc_ie - puc_payload);

    oam_warning_log1(0, OAM_SF_ANY, "{found ie[%d] in probe rsp.}", eid);

    return puc_payload;
}

/*****************************************************************************
 ��������  : ��STAΪWAIT_ASOC״̬ʱ������ht cap IE���ֱ���asoc rsp��probe rsp
             �в���
 �޸���ʷ      :
  1.��    ��   : 2016��5��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_sta_check_ht_cap_ie(const mac_vap_stru *mac_sta,
                                 hi_u8 *puc_payload,
                                 mac_user_stru *mac_user_ap,
                                 hi_u16 *pus_amsdu_maxsize, hi_u16 us_payload_len)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 *puc_payload_for_ht_cap_chk = HI_NULL;
    hi_u16 us_ht_cap_index;
    hi_u16 us_ht_cap_info = 0;

    if ((mac_sta == HI_NULL) || (puc_payload == HI_NULL) || (mac_user_ap == HI_NULL)) {
        return;
    }

    puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_payload, us_payload_len);
    if (puc_ie == HI_NULL || puc_ie[1] < MAC_HT_CAP_LEN) {
        puc_payload_for_ht_cap_chk = hmac_sta_find_ie_in_probe_rsp(mac_sta, MAC_EID_HT_CAP, &us_ht_cap_index);
        if (puc_payload_for_ht_cap_chk == HI_NULL) {
            oam_warning_log0(0, OAM_SF_ANY, "{hmac_sta_check_ht_cap_ie::puc_payload_for_ht_cap_chk is null.}");
            return;
        }

        if (puc_payload_for_ht_cap_chk[us_ht_cap_index + 1] < MAC_HT_CAP_LEN) {
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_sta_check_ht_cap_ie::invalid ht cap len[%d].}",
                             puc_payload_for_ht_cap_chk[us_ht_cap_index + 1]);
            return;
        }
    } else {
        if (puc_ie < puc_payload) {
            return;
        }
        us_ht_cap_index = (hi_u16) (puc_ie - puc_payload);
        puc_payload_for_ht_cap_chk = puc_payload;
    }

    mac_user_set_ht_capable(mac_user_ap, HI_TRUE);
    /* ����Э��ֵ�������ԣ�������hmac_amsdu_init_user������� */
    mac_ie_proc_ht_sta(mac_sta, puc_payload_for_ht_cap_chk, &us_ht_cap_index, mac_user_ap, &us_ht_cap_info,
                       pus_amsdu_maxsize);

    /*  ���ⵥ��DTS2015012803927:֧��ht���������ǿռ������ʼ�Ϊ0��Ҫ�öԶ�APΪ��֧��ht�������Ӷ���11a����11g����AP */
    if ((mac_user_ap->ht_hdl.rx_mcs_bitmask[3] == 0) && (mac_user_ap->ht_hdl.rx_mcs_bitmask[2] == 0)
        && (mac_user_ap->ht_hdl.rx_mcs_bitmask[1] == 0)
        && (mac_user_ap->ht_hdl.rx_mcs_bitmask[0]) == 0) {
        oam_warning_log0(0, OAM_SF_ANY,
                         "{hmac_sta_check_ht_cap_ie::AP support ht capability but support none space_stream.}");
        /* �Զ�ht������Ϊ��֧�� */
        mac_user_set_ht_capable(mac_user_ap, HI_FALSE);
    }
}

/*****************************************************************************
 ��������  : ��STAΪWAIT_ASOC״̬ʱ������ext cap IE���ֱ���asoc rsp��probe rsp
             �в���
 �޸���ʷ      :
  1.��    ��   : 2016��5��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_sta_check_ext_cap_ie(const mac_vap_stru *mac_sta, hi_u8 *puc_payload, hi_u16 us_rx_len)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 *puc_payload_proc = HI_NULL;
    hi_u16 us_index;

    puc_ie = mac_find_ie(MAC_EID_EXT_CAPS, puc_payload, us_rx_len);
    if (puc_ie == HI_NULL || puc_ie[1] < MAC_XCAPS_LEN) {
        puc_payload_proc = hmac_sta_find_ie_in_probe_rsp(mac_sta, MAC_EID_EXT_CAPS, &us_index);
        if (puc_payload_proc == HI_NULL) {
            return;
        }

        if (puc_payload_proc[us_index + 1] < MAC_XCAPS_LEN) {
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_sta_check_ext_cap_ie::invalid ext cap len[%d].}",
                             puc_payload_proc[us_index + 1]);
            return;
        }
    } else {
        if (puc_ie < puc_payload) {
            return;
        }

        us_index = (hi_u16) (puc_ie - puc_payload);
    }
}

/*****************************************************************************
 ��������  : ��STAΪWAIT_ASOC״̬ʱ������OBSS IE���ֱ���asoc rsp��probe rsp
             �в���
 �޸���ʷ      :
  1.��    ��   : 2016��5��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_sta_check_obss_scan_ie(const mac_vap_stru *mac_sta, hi_u8 *puc_payload, hi_u16 us_rx_len)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 *puc_payload_proc = HI_NULL;
    hi_u16 us_index;
    hi_u32 ret;

    puc_ie = mac_find_ie(MAC_EID_OBSS_SCAN, puc_payload, us_rx_len);
    if (puc_ie == HI_NULL || puc_ie[1] < MAC_OBSS_SCAN_IE_LEN) {
        puc_payload_proc = hmac_sta_find_ie_in_probe_rsp(mac_sta, MAC_EID_OBSS_SCAN, &us_index);
        if (puc_payload_proc == HI_NULL) {
            return;
        }

        if (puc_payload_proc[us_index + 1] < MAC_OBSS_SCAN_IE_LEN) {
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_sta_check_obss_scan_ie::invalid obss scan len[%d].}",
                             puc_payload_proc[us_index + 1]);
            return;
        }
    } else {
        puc_payload_proc = puc_payload;
        if (puc_ie < puc_payload) {
            return;
        }

        us_index = (hi_u16) (puc_ie - puc_payload);
    }

    /* ���� obss scan IE */
    ret = hmac_ie_proc_obss_scan_ie(mac_sta, &puc_payload_proc[us_index]);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "hmac_ie_proc_obss_scan_ie return NON SUCCESS. ");
    }
}

/*****************************************************************************
 ��������  : ��STAΪWAIT_ASOC״̬ʱ������ht opern IE���ֱ���asoc rsp��probe rsp
             �в���
 �޸���ʷ      :
  1.��    ��   : 2016��5��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_check_ht_opern_ie(mac_vap_stru *mac_sta,
                                  mac_user_stru *mac_user_ap, hi_u8 *puc_payload, hi_u16 us_rx_len)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 *puc_payload_proc = HI_NULL;
    hi_u16 us_index;
    hi_u32 change = MAC_NO_CHANGE;

    puc_ie = mac_find_ie(MAC_EID_HT_OPERATION, puc_payload, us_rx_len);
    if (puc_ie == HI_NULL || puc_ie[1] < MAC_HT_OPERN_LEN) {
        puc_payload_proc = hmac_sta_find_ie_in_probe_rsp(mac_sta, MAC_EID_HT_OPERATION, &us_index);
        if (puc_payload_proc == HI_NULL) {
            return change;
        }

        if (puc_payload_proc[us_index + 1] < MAC_HT_OPERN_LEN) {
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_sta_check_ht_opern_ie::invalid ht cap len[%d].}",
                             puc_payload_proc[us_index + 1]);
            return change;
        }
    } else {
        puc_payload_proc = puc_payload;
        if (puc_ie < puc_payload) {
            return change;
        }

        us_index = (hi_u16) (puc_ie - puc_payload);
    }
    change |= mac_proc_ht_opern_ie(mac_sta, &puc_payload_proc[us_index], mac_user_ap);

    return change;
}

/*****************************************************************************
 ��������  : ��STAΪWAIT_ASOC״̬ʱ������asoc rsp ����reasoc rsp frame��������ز���
 �޸���ʷ      :
  1.��    ��   : 2013��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_ie_check_ht_sta(mac_vap_stru *mac_sta,
                            const hmac_check_ht_sta_info_stru *check_ht_sta_info,
                            mac_user_stru *mac_user_ap, hi_u16 *pus_amsdu_maxsize)
{
    hi_u32 change = MAC_NO_CHANGE;
    hi_u8 *puc_ie_payload_start = HI_NULL;
    hi_u16 us_ie_payload_len;

    if ((mac_sta == HI_NULL) || (check_ht_sta_info->puc_payload == HI_NULL) || (mac_user_ap == HI_NULL)) {
        return change;
    }

    /* ��ʼ��HT capΪFALSE������ʱ��ѱ�����������AP���� */
    mac_user_set_ht_capable(mac_user_ap, HI_FALSE);

    /* ����֧��11n�Ž��к����Ĵ��� */
    if (mac_mib_get_high_throughput_option_implemented(mac_sta) == HI_FALSE) {
        return change;
    }

    puc_ie_payload_start = check_ht_sta_info->puc_payload + check_ht_sta_info->us_offset;
    if (check_ht_sta_info->us_rx_len <= check_ht_sta_info->us_offset) {
        oam_warning_log2(0, OAM_SF_ANY, "{hmac_ie_check_ht_sta::rx_len[%d] less offset[%d].}",
                         check_ht_sta_info->us_rx_len, check_ht_sta_info->us_offset);
        return change;
    }
    us_ie_payload_len = check_ht_sta_info->us_rx_len - check_ht_sta_info->us_offset;

    hmac_sta_check_ht_cap_ie(mac_sta, puc_ie_payload_start, mac_user_ap, pus_amsdu_maxsize, us_ie_payload_len);

    hmac_sta_check_ext_cap_ie(mac_sta, puc_ie_payload_start, us_ie_payload_len);

    change = hmac_sta_check_ht_opern_ie(mac_sta, mac_user_ap, puc_ie_payload_start, us_ie_payload_len);

    return change;
}

/*****************************************************************************
 ��������  : ����Overlapping BSS Scan Parameters IE��������STA��ӦMIB��
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
             puc_payload: ָ��Overlapping BSS Scan Parameters IE��ָ��
 ���ú���  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2014��2��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_ie_proc_obss_scan_ie(const mac_vap_stru *mac_vap, const hi_u8 *puc_payload)
{
    hi_u16 us_trigger_scan_interval;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    wlan_mib_dot11_operation_entry_stru old_mib;
#endif
    if (oal_unlikely((mac_vap == HI_NULL) || (puc_payload == HI_NULL))) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_ie_proc_obss_scan_ie::param null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /********************Overlapping BSS Scan Parameters element******************
     |ElementID |Length |OBSS    |OBSS   |BSS Channel   |OBSS Scan  |OBSS Scan   |
     |          |       |Scan    |Scan   |Width Trigger |Passive    |Active Total|
     |          |       |Passive |Active |Scan Interval |Total Per  |Per         |
     |          |       |Dwell   |Dwell  |              |Channel    |Channel     |
     ----------------------------------------------------------------------------
     |1         |1      |2       |2      |2             |2          |2           |
     ----------------------------------------------------------------------------
     |BSS Width   |OBSS Scan|
     |Channel     |Activity |
     |Transition  |Threshold|
     |Delay Factor|         |
     ------------------------
     |2           |2        |
    ***************************************************************************/
    if (puc_payload[1] < MAC_OBSS_SCAN_IE_LEN) {
        oam_warning_log1(0, OAM_SF_SCAN, "{mac_ie_proc_obss_scan_ie::invalid obss scan ie len[%d].}", puc_payload[1]);
        return HI_FAIL;
    }

    us_trigger_scan_interval = hi_makeu16(puc_payload[6], puc_payload[7]); /* 6 7 Ԫ������ */
    if (us_trigger_scan_interval == 0) {
        return HI_ERR_CODE_INVALID_CONFIG;
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    if (memset_s(&old_mib, sizeof(wlan_mib_dot11_operation_entry_stru), 0,
                 sizeof(wlan_mib_dot11_operation_entry_stru)) != EOK) {
        return HI_FAIL;
    }
    if (memcpy_s(&old_mib, sizeof(old_mib), &mac_vap->mib_info->wlan_mib_operation,
                 sizeof(old_mib)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_ie_proc_obss_scan_ie:: hmac_ie_proc_obss_scan_ie memcpy_s fail.");
        return HI_FAIL;
    }
#endif
    mac_mib_set_obssscan_passive_dwell(mac_vap, hi_makeu16(puc_payload[2], puc_payload[3])); /* ����2,3,8 */
    mac_mib_set_obssscan_active_dwell(mac_vap, hi_makeu16(puc_payload[4], puc_payload[5]));  /* ����4,5,8 */
    /* obssɨ��������С300��,���600S, ��ʼ��Ĭ��Ϊ300�� */
    mac_mib_set_bsswidth_trigger_scan_interval(mac_vap,
        oal_min(oal_max(us_trigger_scan_interval, 300), 600)); /* min:max 300:600 */
    mac_mib_set_obssscan_passive_total_per_channel(mac_vap, hi_makeu16(puc_payload[8], puc_payload[9])); /* 8 9���� */
    mac_mib_set_obssscan_active_total_per_channel(mac_vap,
        hi_makeu16(puc_payload[10], puc_payload[11])); /* 10 11���� */
    mac_mib_set_bsswidth_channel_transition_delay_factor(mac_vap,
        hi_makeu16(puc_payload[12], puc_payload[13])); /* 12 13Ԫ������ */
    mac_mib_set_obssscan_activity_threshold(mac_vap, hi_makeu16(puc_payload[14], puc_payload[15])); /* 14 15���� */

    if (0 != memcmp(&old_mib, &mac_vap->mib_info->wlan_mib_operation, sizeof(old_mib))) {
        oam_info_log0(mac_vap->vap_id, OAM_SF_2040, "hmac_ie_proc_obss_scan_ie::sync obss mib to dmac");
        hmac_config_set_obss_scan_param(mac_vap);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����֡��legacy ���ʼ������µ�user�Ľṹ�����ʱ�����Ա��
 �޸���ʷ      :
  1.��    ��   : 2013��11��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_ie_proc_assoc_user_legacy_rate(hi_u8 *puc_payload,
                                                  hi_u16 us_offset,
                                                  hi_u16 us_rx_len, hmac_user_stru *hmac_user)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 num_rates = 0;
    hi_u8 num_ex_rates = 0;

    if (us_rx_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_RATES, puc_payload + us_offset, us_rx_len - us_offset);
        if (puc_ie != HI_NULL) {
            num_rates = puc_ie[1];

            if (num_rates > WLAN_MAX_SUPP_RATES || num_rates < MAC_MIN_XRATE_LEN) {
                oam_warning_log1(0, OAM_SF_ANY, "{hmac_ie_proc_assoc_user_legacy_rate:: invaild rates:%d}", num_rates);
                return HI_FAIL;
            }
            if (memcpy_s(hmac_user->op_rates.auc_rs_rates, num_rates, puc_ie + MAC_IE_HDR_LEN, num_rates)
                != EOK) {
                oam_error_log0(0, OAM_SF_CFG, "hmac_ie_proc_assoc_user_legacy_rate:: puc_ie memcpy_s fail.");
                return HI_FAIL;
            }
        }
        puc_ie = mac_find_ie(MAC_EID_XRATES, puc_payload + us_offset, us_rx_len - us_offset);
        if (puc_ie != HI_NULL) {
            num_ex_rates = puc_ie[1];

            if (num_ex_rates < MAC_MIN_XRATE_LEN) {
                oam_warning_log1(0, OAM_SF_ANY, "{hmac_ie_proc_assoc_user_legacy_rate:: invaild xrates:%d}",
                                 num_ex_rates);
                return HI_FAIL;
            }

            if (num_rates + num_ex_rates > WLAN_MAX_SUPP_RATES) {     /* ����֧�����ʸ��� */
                num_ex_rates = WLAN_MAX_SUPP_RATES - num_rates;
            }

            if (memcpy_s(&(hmac_user->op_rates.auc_rs_rates[num_rates]), WLAN_MAX_SUPP_RATES,
                         puc_ie + MAC_IE_HDR_LEN, num_ex_rates) != EOK) {
                oam_error_log0(0, OAM_SF_CFG, "hmac_ie_proc_assoc_user_legacy_rate:: puc_ie memcpy_s fail.");
                return HI_FAIL;
            }
        }
    }

    hmac_user->op_rates.rs_nrates = num_rates + num_ex_rates;

    return HI_SUCCESS;
}

hi_void hmac_sta_wait_asoc_rx_handle_for_pmf(hmac_vap_stru *hmac_vap, mac_status_code_enum_uint16 asoc_status)
{
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hmac_vap->pre_assoc_status = asoc_status;

    if (asoc_status == MAC_REJECT_TEMP) {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_association_response_time_out =
            WLAN_ASSOC_REJECT_TIMEOUT;
    } else {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_association_response_time_out =
            WLAN_ASSOC_TIMEOUT;
    }
}

hi_u32 hmac_sta_check_protocol_bandwidth(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user_ap,
                                         hmac_asoc_rsp_stru asoc_rsp)
{
    wlan_bw_cap_enum_uint8 bwcap;
    wlan_bw_cap_enum_uint8 bandwidth_cap;
    mac_vap_stru *mac_vap = hmac_vap->base_vap;

    /* ��ȡ�û���Э��ģʽ */
    hmac_set_user_protocol_mode(mac_vap, hmac_user_ap);
    /* ��Э��ģʽ���µ�STA */
    hi_u8 avail_mode = hmac_get_auc_avail_protocol_mode(mac_vap->protocol, hmac_user_ap->base_user->protocol_mode);
    /* STA��AP��Э��ģʽ�����ݣ�STAֱ��ȥ���� */
    if (avail_mode == WLAN_PROTOCOL_BUTT) {
        oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
            "{hmac_sta_check_protocol_bandwidth::no valid protocol:vap mode=%d, user mode=%d,user avail mode=%d.}",
            mac_vap->protocol,
            hmac_user_ap->base_user->protocol_mode,
            hmac_user_ap->base_user->avail_protocol_mode);

        asoc_rsp.result_code = HMAC_MGMT_REFUSED;
        asoc_rsp.status_code = MAC_UNSUP_RATE;

        /* ����������ֱ����Ϊmax,�������ٴι��� */
        hmac_vap->asoc_cnt = MAX_ASOC_CNT;

        /* ���͹��������SME */
        hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_ASOC_RSP, (hi_u8 *)&asoc_rsp);

        return HI_FAIL;
    }
    /* ��ȡ�û���VAPЭ��ģʽ���� */
    hmac_user_ap->base_user->avail_protocol_mode =
        hmac_get_auc_avail_protocol_mode(mac_vap->protocol, hmac_user_ap->base_user->protocol_mode);
    hmac_user_ap->base_user->cur_protocol_mode =
        hmac_user_ap->base_user->avail_protocol_mode;
    oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                     "{hmac_sta_check_protocol_bandwidth::user avail_protocol:%d,user cur_protocol:%d,vap protocol:%d}",
                     hmac_user_ap->base_user->avail_protocol_mode,
                     hmac_user_ap->base_user->cur_protocol_mode,
                     mac_vap->protocol);
    /* ��ȡ�û���VAP ��֧�ֵ�11a/b/g ���ʽ��� */
    hmac_vap_set_user_avail_rates(hmac_vap->base_vap, hmac_user_ap);

    /* ��ȡ�û���VAP������������ */
    /* ��ȡ�û��Ĵ������� */
    mac_user_get_ap_opern_bandwidth(hmac_user_ap->base_user, &bandwidth_cap);

    mac_vap_get_bandwidth_cap(mac_vap, &bwcap);
    bwcap = oal_min(bwcap, bandwidth_cap);
    mac_user_set_bandwidth_info(hmac_user_ap->base_user, bwcap, bwcap);

    oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                     "{hmac_sta_check_protocol_bandwidth::mac user[%d] en_bandwidth_cap:%d,en_avail_bandwidth:%d}",
                     hmac_user_ap->base_user->us_assoc_id,
                     bandwidth_cap, hmac_user_ap->base_user->avail_bandwidth);
    return HI_SUCCESS;
}

hi_void hmac_sta_wait_asoc_rx_complete_handle(hmac_vap_stru *hmac_vap, hi_u8 user_idx,
    const hmac_user_stru *hmac_user_ap, hmac_asoc_rsp_stru asoc_rsp, const hmac_rx_ctl_stru *rx_ctrl)
{
    hi_u32 rslt;
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    mac_user_stru *mac_user_ap = hmac_user_ap->base_user;

    hi_u8 *puc_mac_hdr = (hi_u8 *)(rx_ctrl->pul_mac_hdr_start_addr);
    hi_u16 us_msg_len = rx_ctrl->us_frame_len - rx_ctrl->mac_header_len;

    /* STA�л���UP״̬ */
    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_UP);
    /* ���û�(AP)�ڱ��ص�״̬��Ϣ����Ϊ�ѹ���״̬ */
    mac_user_set_asoc_state(hmac_user_ap->base_user, MAC_USER_STATE_ASSOC);

    /* dmac offload�ܹ��£�ͬ��STA USR��Ϣ��dmac */
    rslt = hmac_config_user_cap_syn(hmac_vap->base_vap, mac_user_ap);
    if (rslt != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_sta_wait_asoc_rx_complete_handle::hmac_config_usr_cap_syn failed[%d].}", rslt);
    }

    rslt = hmac_config_user_info_syn(hmac_vap->base_vap, mac_user_ap);
    if (rslt != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_sta_wait_asoc_rx_complete_handle::hmac_syn_vap_state failed[%d].}", rslt);
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    rslt = hmac_config_user_rate_info_syn(hmac_vap->base_vap, mac_user_ap);
    if (rslt != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_sta_wait_asoc_rx_complete_handle::hmac_syn_rate_info failed[%d].}", rslt);
    }
#endif

    /* user�Ѿ������ϣ����¼���DMAC����DMAC����û��㷨���� */
    hmac_user_add_notify_alg(hmac_vap->base_vap, user_idx);

       /* ׼����Ϣ���ϱ���APP */
    asoc_rsp.result_code = HMAC_MGMT_SUCCESS;
    asoc_rsp.status_code = MAC_SUCCESSFUL_STATUSCODE;

    /* ��¼������Ӧ֡�Ĳ������ݣ������ϱ����ں� */
    asoc_rsp.asoc_rsp_ie_len = us_msg_len - OAL_ASSOC_RSP_FIXED_OFFSET;   /* ��ȥMAC֡ͷ24�ֽں�FIXED����6�ֽ� */
    asoc_rsp.puc_asoc_rsp_ie_buff = puc_mac_hdr + OAL_ASSOC_RSP_IE_OFFSET;

    /* ��ȡAP��mac��ַ */
    mac_get_bssid(puc_mac_hdr, asoc_rsp.auc_addr_ap, WLAN_MAC_ADDR_LEN);

    /* ��ȡ��������֡��Ϣ */
    asoc_rsp.puc_asoc_req_ie_buff = hmac_vap->puc_asoc_req_ie_buff;
    asoc_rsp.asoc_req_ie_len = hmac_vap->us_asoc_req_ie_len;

    /* ��ȡ�ŵ�����Ƶ�� */
    hi_u16 us_freq = (hi_u16) oal_ieee80211_channel_to_frequency(mac_vap->channel.chan_number, mac_vap->channel.band);
    asoc_rsp.us_freq = us_freq;

    hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_ASOC_RSP, (hi_u8 *)(&asoc_rsp));
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* �ϱ���Lwip */
    hmac_report_assoc_state_sta(hmac_vap, asoc_rsp.auc_addr_ap, HI_TRUE);
#endif
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    /* dmac offload�ܹ��£�ͬ��STA USR��Ϣ��dmac */
    rslt = hmac_config_sta_vap_info_syn(hmac_vap->base_vap);
    if (rslt != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                       "{hmac_sta_wait_asoc_rx::hmac_syn_vap_state failed[%d].}", rslt);
    }
#endif
}

hi_void hmac_sta_wait_asoc_rx_complete_update_param(const hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user_ap,
                                                    const hmac_rx_ctl_stru *rx_ctrl, hi_u16 us_offset)
{
    hi_u8 *puc_mac_hdr = (hi_u8 *)(rx_ctrl->pul_mac_hdr_start_addr);
    hi_u8 *puc_payload = (hi_u8 *)(puc_mac_hdr) + rx_ctrl->mac_header_len;
    hi_u16 us_msg_len = rx_ctrl->us_frame_len - rx_ctrl->mac_header_len;
    hi_u8 frame_sub_type = mac_get_frame_sub_type(puc_mac_hdr);
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hmac_edca_params_info_stru  edca_params_info;
    hmac_check_ht_sta_info_stru check_ht_sta_info;
    /* sta���������edca parameters */
    edca_params_info.puc_payload = puc_payload;
    edca_params_info.us_msg_len = us_msg_len;
    edca_params_info.us_info_elem_offset = us_offset;
    hmac_sta_up_update_edca_params(&edca_params_info, hmac_vap, frame_sub_type,
                                   hmac_user_ap);

    /* ���¹����û��� QoS protocol table */
    hmac_mgmt_update_assoc_user_qos(puc_payload, us_msg_len, us_offset, hmac_user_ap);

    /* ���¹����û���legacy���ʼ��� */
    hi_u32 rslt = hmac_ie_proc_assoc_user_legacy_rate(puc_payload, us_offset, us_msg_len, hmac_user_ap);
    if (rslt != HI_SUCCESS) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC, "hmac_ie_proc_assoc_user_legacy_rate fail");
    }

    /* ���� HT ����  */
    check_ht_sta_info.puc_payload = puc_payload;
    check_ht_sta_info.us_offset = us_offset;
    check_ht_sta_info.us_rx_len = us_msg_len;
    hi_u32 change = hmac_ie_check_ht_sta(hmac_vap->base_vap, &check_ht_sta_info,
        hmac_user_ap->base_user, &hmac_user_ap->us_amsdu_maxsize);
    if (MAC_BW_CHANGE & change) {
        oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_ASSOC,
                         "{hmac_sta_wait_asoc_rx::change BW. ul_change[0x%x], uc_channel[%d], en_bandwidth[%d].}",
                         change, mac_vap->channel.chan_number, mac_vap->channel.en_bandwidth);
        hmac_chan_sync(mac_vap,
                       mac_vap->channel.chan_number, mac_vap->channel.en_bandwidth, HI_TRUE);
    }
}

/*****************************************************************************
 ��������  : ��WAIT_ASOC״̬�½��յ�Asoc_rsp_frame�Ĵ�����
 �޸���ʷ      :
  1.��    ��   : 2013��6��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������: �����ھۣ��������� */
hi_u32 hmac_sta_wait_asoc_rx(hmac_vap_stru *hmac_vap, const dmac_wlan_crx_event_stru *crx_event)
{
    hmac_asoc_rsp_stru          asoc_rsp;
    hi_u8                       sa_mac_addr[WLAN_MAC_ADDR_LEN] = { 0 };
    hi_u8                       user_idx = 0;
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)crx_event->netbuf);
    hi_u8 *puc_mac_hdr = (hi_u8 *)(rx_ctrl->pul_mac_hdr_start_addr);
    hi_u8 *puc_payload = (hi_u8 *)(puc_mac_hdr) + rx_ctrl->mac_header_len;
    hi_u16 us_msg_len = rx_ctrl->us_frame_len - rx_ctrl->mac_header_len;    /* ��Ϣ�ܳ���,������FCS */

    hi_u16 us_offset = 0;
    hi_u8 frame_sub_type = mac_get_frame_sub_type(puc_mac_hdr);

    if (memset_s(&asoc_rsp, sizeof(hmac_asoc_rsp_stru), 0, sizeof(hmac_asoc_rsp_stru)) != EOK) {
        return HI_FAIL;
    }

    /* ���ó�ʼ����״̬Ϊ�ɹ� */
    asoc_rsp.result_code = HMAC_MGMT_SUCCESS;
    switch (frame_sub_type) {
        case WLAN_FC0_SUBTYPE_ASSOC_RSP:
        case WLAN_FC0_SUBTYPE_REASSOC_RSP:
            break;
        default:
            /* do nothing,wait for time out */
            return HI_SUCCESS;
    }

    us_offset += MAC_CAP_INFO_LEN;

    mac_status_code_enum_uint16 asoc_status = mac_get_asoc_status(puc_payload);

    us_offset += MAC_STATUS_CODE_LEN;

#ifdef _PRE_WLAN_FEATURE_PMF
    hmac_sta_wait_asoc_rx_handle_for_pmf(hmac_vap, asoc_status);
#endif

    if ((asoc_status != MAC_SUCCESSFUL_STATUSCODE) || (us_msg_len < OAL_ASSOC_RSP_FIXED_OFFSET)) {
        oam_warning_log2(0, 0, "{hmac_sta_wait_asoc_rx fail:: asoc_status[%d], msg_len[%d].}", asoc_status, us_msg_len);
        return HI_FAIL;
    }

    /* ��ȡSA ��ַ */
    mac_get_address2(puc_mac_hdr, WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN);

    /* ����SA �ص��ҵ���ӦAP USER�ṹ */
    hi_u32 rslt = mac_vap_find_user_by_macaddr(hmac_vap->base_vap, sa_mac_addr, WLAN_MAC_ADDR_LEN, &user_idx);
    if (rslt != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hmac_sta_wait_asoc_rx:: mac_vap_find_user_by_macaddr failed[%d].}", rslt);

        return rslt;
    }

    /* ��ȡSTA������AP���û�ָ�� */
    hmac_user_stru *hmac_user_ap = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
    if ((hmac_user_ap == HI_NULL) || (hmac_user_ap->base_user == HI_NULL)) {
        return HI_FAIL;
    }

    /* ȡ����ʱ�� */
    frw_timer_immediate_destroy_timer(&(hmac_vap->mgmt_timer));

    /* ���¹���ID */
    hi_u16 us_aid = mac_get_asoc_id(puc_payload);
    if ((us_aid > 0) && (us_aid <= 2007)) { /* idС��2007 */
        mac_vap_set_aid(hmac_vap->base_vap, us_aid);
    } else {
        oam_warning_log1(0, 0, "{hmac_sta_wait_asoc_rx::invalid us_sta_aid[%d].}", us_aid);
    }
    us_offset += MAC_AID_LEN;

    /* ��ʼ����ȫ�˿ڹ��˲��� */
#if defined (_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    rslt = hmac_init_user_security_port(hmac_vap->base_vap, hmac_user_ap->base_user);
    if (rslt != HI_SUCCESS) {
        oam_error_log1(0, 0, "{hmac_sta_wait_asoc_rx::hmac_init_user_security_port failed[%d].}", rslt);
    }
#endif

#ifdef _PRE_WLAN_FEATURE_PMF
    /* STAģʽ�µ�pmf������Դ��WPA_supplicant��ֻ������pmf�Ͳ�����pmf�������� */
    mac_user_set_pmf_active(hmac_user_ap->base_user, mac_vap->user_pmf_cap);
#endif

    hmac_sta_wait_asoc_rx_complete_update_param(hmac_vap, hmac_user_ap, rx_ctrl, us_offset);

    rslt = hmac_sta_check_protocol_bandwidth(hmac_vap, hmac_user_ap, asoc_rsp);
    if (rslt != HI_SUCCESS) {
        return HI_SUCCESS;
    }

    /* ��ȡ�û���VAP�ռ������� */
    rslt = hmac_user_set_avail_num_space_stream(hmac_user_ap->base_user, WLAN_SINGLE_NSS);
    if (rslt != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hmac_sta_wait_asoc_rx::mac_user_set_avail_num_space_stream failed[%d].}", rslt);
    }
#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY

    /* ����Operating Mode Notification ��ϢԪ�� */
    rslt = hmac_check_opmode_notify(hmac_vap, puc_mac_hdr, puc_payload, us_offset, us_msg_len, hmac_user_ap);
    if (rslt != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hmac_sta_wait_asoc_rx::hmac_check_opmode_notify failed[%d].}", rslt);
    }
#endif

    hmac_sta_wait_asoc_rx_complete_handle(hmac_vap, user_idx, hmac_user_ap, asoc_rsp, rx_ctrl);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��֤��ʱ����
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_auth_timeout(hmac_vap_stru *hmac_vap)
{
    hmac_auth_rsp_stru auth_rsp = {{0, }, 0};

    /* and send it to the host.                                          */
    auth_rsp.us_status_code = HMAC_MGMT_TIMEOUT;

    /* Send the response to host now. */
    hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_AUTH_RSP, (hi_u8 *)&auth_rsp);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ݳ�ʼ����dev����������bss�Ĵ�������������ǰ��Ҫʹ�õĴ���
 �������  :    en_dev_cap, en_bss_cap
 �� �� ֵ  : hi_u32
 �޸���ʷ      :
  1.��    ��   : 2015��2��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
wlan_channel_bandwidth_enum_uint8 hmac_sta_get_band(wlan_bw_cap_enum_uint8 dev_cap,
                                                    wlan_channel_bandwidth_enum_uint8 bss_cap)
{
    wlan_channel_bandwidth_enum_uint8 band;

    band = WLAN_BAND_WIDTH_20M;

    if ((dev_cap == WLAN_BW_CAP_80M) && (bss_cap >= WLAN_BAND_WIDTH_80PLUSPLUS)) {
        /* ���AP��STAUT��֧��80M��������ΪAPһ�� */
        band = bss_cap;
        return band;
    }

    switch (bss_cap) {
        case WLAN_BAND_WIDTH_40PLUS:
        case WLAN_BAND_WIDTH_80PLUSPLUS:
        case WLAN_BAND_WIDTH_80PLUSMINUS:
            if (WLAN_BW_CAP_40M <= dev_cap) {
                band = WLAN_BAND_WIDTH_40PLUS;
            }
            break;

        case WLAN_BAND_WIDTH_40MINUS:
        case WLAN_BAND_WIDTH_80MINUSPLUS:
        case WLAN_BAND_WIDTH_80MINUSMINUS:
            if (WLAN_BW_CAP_40M <= dev_cap) {
                band = WLAN_BAND_WIDTH_40MINUS;
            }
            break;

        default:
            band = WLAN_BAND_WIDTH_20M;
            break;
    }

    return band;
}

/*****************************************************************************
 ��������  : ������ʱ������
 �������  : hmac_vap_stru *pst_hmac_sta, hi_void *p_param
 �޸���ʷ      :
  1.��    ��   : 2013��7��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_wait_asoc_timeout(hmac_vap_stru *hmac_vap)
{
    hmac_asoc_rsp_stru asoc_rsp = { 0 };

    /* ��д������� */
    asoc_rsp.result_code = HMAC_MGMT_TIMEOUT;

    /* ������ʱʧ��,ԭ�����ϱ�wpa_supplicant */
#ifdef _PRE_WLAN_FEATURE_PMF
    if (hmac_vap->pre_assoc_status == MAC_REJECT_TEMP) {
        asoc_rsp.status_code = MAC_REJECT_TEMP;
    } else {
        asoc_rsp.status_code = MAC_AUTH_TIMEOUT;
    }
#else
    asoc_rsp.status_code = MAC_AUTH_TIMEOUT;
#endif
    /* ���͹��������SME */
    hmac_send_rsp_to_sme_sta(hmac_vap, HMAC_SME_ASOC_RSP, (hi_u8 *)&asoc_rsp);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ϱ��ں�sta�Ѿ���ĳ��apȥ����
 �޸���ʷ      :
  1.��    ��   : 2013��9��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_sta_disassoc_rsp(const hmac_vap_stru *hmac_vap, hi_u16 us_disasoc_reason_code,
                              hi_u16 us_dmac_reason_code)
{
    hi_u32 reason_code = ((us_disasoc_reason_code & 0x0000ffff) |
        ((us_dmac_reason_code << 16) & 0xffff0000));    /* 16 ��λbit������2�ֽں͵�2�ֽڴ� */
    hmac_send_event_to_host(hmac_vap->base_vap, (const hi_u8*)(&reason_code),
        sizeof(hi_u32), HMAC_HOST_CTX_EVENT_SUB_TYPE_DISASOC_COMP_STA);

    const hi_u8        *bcast_mac_addr = mac_get_mac_bcast_addr();
    /* �ϱ���Lwip */
    hmac_report_assoc_state_sta(hmac_vap, (hi_u8 *)bcast_mac_addr, HI_FALSE);
    return;
}

/*****************************************************************************
��������  : �������ȥ��֤֡
�޸���ʷ      :
1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
�޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_sta_rx_deauth_req(hmac_vap_stru *hmac_vap, hi_u8 *mac_hdr, hi_u8 protected)
{
    hi_u8  auc_bssid[WLAN_MAC_ADDR_LEN] = {0}; /* Ԫ�ظ���Ϊ6 */
    hi_u8  user_idx    = 0xff;
    hi_u8 *da_mac_addr = HI_NULL;
    hi_u8 *sa_mac_addr = HI_NULL;

    /* ���ӽ��յ�ȥ��֤֡����ȥ����֡ʱ��ά����Ϣ */
    mac_rx_get_sa((mac_ieee80211_frame_stru *)mac_hdr, &sa_mac_addr);
    oam_warning_log4(hmac_vap->base_vap->vap_id, OAM_SF_AUTH,
        "{hmac_sta_rx_deauth_req::Because of err_code[%d], received deauth/disassoc frame, sa xx:xx:xx:%2x:%2x:%2x.}",
        *((hi_u16 *)(mac_hdr + MAC_80211_FRAME_LEN)), sa_mac_addr[3], sa_mac_addr[4], sa_mac_addr[5]); /* 3 4 5 */

    mac_get_address2(mac_hdr, WLAN_MAC_ADDR_LEN, auc_bssid, WLAN_MAC_ADDR_LEN);

    hi_u32 ret = mac_vap_find_user_by_macaddr(hmac_vap->base_vap, auc_bssid, WLAN_MAC_ADDR_LEN, &user_idx);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_sta_rx_deauth_req::find user failed=%d}", ret);
        return ret;
    }

    hmac_user_stru *hmac_user_vap = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
    if ((hmac_user_vap == HI_NULL) || (hmac_user_vap->base_user == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_sta_rx_deauth_req::pst_hmac_user_vap null.}");

        /* û�в鵽��Ӧ��USER,����ȥ��֤��Ϣ */
        hmac_mgmt_send_deauth_frame(hmac_vap->base_vap, auc_bssid, WLAN_MAC_ADDR_LEN, MAC_NOT_AUTHED);

        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);

        /* �ϱ��ں�sta�Ѿ���ĳ��apȥ���� */
        hmac_sta_disassoc_rsp(hmac_vap, *((hi_u16 *)(mac_hdr + MAC_80211_FRAME_LEN)), DMAC_DISASOC_MISC_WOW_RX_DEAUTH);
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_PMF
    /* ����Ƿ���Ҫ����SA query request */
    if ((hmac_user_vap->base_user->user_asoc_state == MAC_USER_STATE_ASSOC) &&
        (hmac_pmf_check_err_code(hmac_user_vap->base_user, protected, mac_hdr) == HI_SUCCESS)) {
        /* �ڹ���״̬���յ�δ���ܵ�ReasonCode 6/7��Ҫ����SA Query���� */
        ret = hmac_start_sa_query(hmac_vap->base_vap, hmac_user_vap, hmac_user_vap->base_user->cap_info.pmf_active);
        if (ret != HI_SUCCESS) {
            return HI_ERR_CODE_PMF_SA_QUERY_START_FAIL;
        }

        return HI_SUCCESS;
    }
#endif

    /* ������û��Ĺ���֡�������Բ�һ�£������ñ��� */
    mac_rx_get_da((mac_ieee80211_frame_stru *)mac_hdr, &da_mac_addr);
    if ((ether_is_multicast(da_mac_addr) != HI_TRUE) && (protected != hmac_user_vap->base_user->cap_info.pmf_active)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_sta_rx_deauth_req::PMF check failed.}");

        return HI_FAIL;
    }

    hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);

    /* �ϱ�system error ��λ mac */
    /* ɾ��user */
    if (hmac_user_del(hmac_vap->base_vap, hmac_user_vap) != HI_SUCCESS) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AUTH, "{hmac_sta_rx_deauth_req::hmac_user_del failed.}");

        /* �ϱ��ں�sta�Ѿ���ĳ��apȥ���� */
        hmac_sta_disassoc_rsp(hmac_vap, *((hi_u16 *)(mac_hdr + MAC_80211_FRAME_LEN)), DMAC_DISASOC_MISC_WOW_RX_DEAUTH);
        return HI_FAIL;
    }

    /* �ϱ��ں�sta�Ѿ���ĳ��apȥ���� */
    hmac_sta_disassoc_rsp(hmac_vap, *((hi_u16*)(mac_hdr + MAC_80211_FRAME_LEN)), DMAC_DISASOC_MISC_WOW_RX_DEAUTH);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : STA�յ�Beacon֡�󣬴���HT�����ϢԪ��
 �������  : pst_mac_vap    : MAC VAP�ṹ��ָ�룬ָ��STA
             puc_payload    : ָ��Beacon֡���ָ��
             us_frame_len   : Beacon֡��ĳ���(������֡ͷ)
             us_frame_offset: Beacon֡�е�һ��IE���֡���ַ��ƫ��
 �������  : pst_mac_user   : MAC USER�ṹ��ָ�룬ָ��AP
 �� �� ֵ  : hi_u8:�����Ϣ�Ƿ��иı䣬�Ƿ���Ҫͬ��?
 �޸���ʷ      :
  1.��    ��   : 2014��3��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_sta_up_update_ht_params(mac_vap_stru *mac_vap, const hi_u8 *puc_payload,
                                           hi_u16 us_frame_len, hi_u16 us_frame_offset,
                                           mac_user_stru *mac_user)
{
    hi_u16 us_index = us_frame_offset;
    mac_user_ht_hdl_stru ht_hdl;
    hi_u32 change = MAC_NO_CHANGE;

    if (memset_s(&ht_hdl, sizeof(mac_user_ht_hdl_stru), 0, sizeof(mac_user_ht_hdl_stru)) != EOK) {
        return HI_FAIL;
    }
    mac_user_get_ht_hdl(mac_user, &ht_hdl);

    while (us_index < us_frame_len) {
        if (puc_payload[us_index] == MAC_EID_HT_OPERATION) {
            change |= mac_proc_ht_opern_ie(mac_vap, &puc_payload[us_index], mac_user);
        }
        us_index += puc_payload[us_index + 1] + MAC_IE_HDR_LEN;
    }

    if (memcmp((hi_u8 *)(&ht_hdl), (hi_u8 *)(&mac_user->ht_hdl), sizeof(mac_user_ht_hdl_stru)) != 0) {
        return (change | MAC_HT_CHANGE);
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : sta up״̬����beacon֡����
 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_sta_up_rx_beacon(const hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf)
{
    hi_u8 sa_mac_addr[WLAN_MAC_ADDR_LEN] = { 0 };
    hi_u8 user_idx = 0;

    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    mac_ieee80211_frame_stru *mac_hdr = (mac_ieee80211_frame_stru *)(rx_ctrl->pul_mac_hdr_start_addr);
    hi_u8 *frame_body = (hi_u8 *)mac_hdr + rx_ctrl->mac_header_len;
    hi_u16 frame_len = rx_ctrl->us_frame_len - rx_ctrl->mac_header_len;  /* ֡�峤�� */

    hi_u16 frame_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    hi_u8 frame_sub_type = mac_get_frame_sub_type((hi_u8 *)mac_hdr);

    /* ��������bss��Beacon�������� */
    if (oal_compare_mac_addr(hmac_vap->base_vap->auc_bssid, mac_hdr->auc_address3, WLAN_MAC_ADDR_LEN) != 0) {
        return HI_SUCCESS;
    }

    /* ��ȡ����֡��Դ��ַSA */
    mac_get_address2((hi_u8 *)mac_hdr, WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN);

    /* ����SA �ص��ҵ���ӦAP USER�ṹ */
    if (mac_vap_find_user_by_macaddr(hmac_vap->base_vap, sa_mac_addr, WLAN_MAC_ADDR_LEN, &user_idx) != HI_SUCCESS) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_sta_up_rx_beacon:mac_vap_find failed}");
        return HI_FAIL;
    }
    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_sta_up_rx_beacon::pst_hmac_user null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ����HT �����ϢԪ�� */
    hi_u32 change_flag = MAC_NO_CHANGE | hmac_sta_up_update_ht_params(hmac_vap->base_vap, frame_body, frame_len,
        frame_offset, hmac_user->base_user);

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
    /* ����Operating Mode Notification ��ϢԪ�� */
    if (hmac_check_opmode_notify(hmac_vap, (hi_u8 *)mac_hdr, frame_body, frame_offset, frame_len, hmac_user)
        != HI_SUCCESS) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_sta_up_rx_beacon::hmac_check failed.}");
    }
#endif
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    if (((MAC_HT_CHANGE & change_flag) || (MAC_VHT_CHANGE & change_flag)) &&
        (hmac_config_user_rate_info_syn(hmac_vap->base_vap, hmac_user->base_user) != HI_SUCCESS)) {
            oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_sta_up_rx_beacon::user_rate failed.}");
    }
#endif
    if (MAC_BW_CHANGE & change_flag) {
        hmac_sta_update_mac_user_info(hmac_user, user_idx);

        oam_warning_log3(0, OAM_SF_ASSOC, "{hmac_sta_up_rx_beacon::change BW.change[0x%x],channel[%d],bandwidth[%d].}",
            change_flag, hmac_vap->base_vap->channel.chan_number, hmac_vap->base_vap->channel.en_bandwidth);
        hmac_chan_sync(hmac_vap->base_vap, hmac_vap->base_vap->channel.chan_number,
            hmac_vap->base_vap->channel.en_bandwidth, HI_TRUE);
    }

    /* ����edca���� */
    hmac_edca_params_info_stru edca_params_info = {frame_body, frame_len, frame_offset};
    hmac_sta_up_update_edca_params(&edca_params_info, hmac_vap, frame_sub_type, hmac_user);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : STA up״̬����Channel Switch Announcement֡����
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
             pst_netbuf : ����Channel Switch Announcement֡��netbuf
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_sta_up_rx_ch_switch(mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf)
{
    hmac_rx_ctl_stru *rx_ctrl = HI_NULL;
    hi_u16 us_index;
    hi_u8 *puc_data = HI_NULL;
    hi_u16 us_framebody_len;

    if (HI_FALSE == mac_mib_get_spectrum_management_implemented(mac_vap)) {
        oam_info_log0(mac_vap->vap_id, OAM_SF_BA,
                      "{hmac_sta_up_rx_ch_switch::Ignoring Spectrum Management frames.}");
        return;
    }

    rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    us_framebody_len = rx_ctrl->us_frame_len - rx_ctrl->mac_header_len;

    /* ��ȡ֡��ָ�� */
    puc_data = (hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr + rx_ctrl->mac_header_len;

    us_index = MAC_ACTION_OFFSET_ACTION + 1;

    while (us_index < us_framebody_len) {
        if (puc_data[us_index] == MAC_EID_CHANSWITCHANN) {
            hmac_ie_proc_ch_switch_ie(mac_vap, &puc_data[us_index], MAC_EID_CHANSWITCHANN);
        } else if (puc_data[us_index] == MAC_EID_SEC_CH_OFFSET) {
            if (puc_data[us_index + 1] < MAC_SEC_CH_OFFSET_IE_LEN) {
                oam_warning_log1(0, OAM_SF_ANY, "{dmac_sta_up_rx_ch_switch::invalid sec chan offset ie len[%d]}",
                                 puc_data[us_index + 1]);
                us_index += MAC_IE_HDR_LEN + puc_data[us_index + 1];
                continue;
            }
            /* ���ͨ�������ı��ˣ�����Ҫ���ŵ�ô? */
            mac_vap->ch_switch_info.new_bandwidth =
                mac_get_bandwidth_from_sco(puc_data[us_index + MAC_IE_HDR_LEN]);
            oam_warning_log1(0, OAM_SF_ANY, "{hmac_sta_up_rx_sca:new_bw[%d]}", mac_vap->ch_switch_info.new_bandwidth);
        }
        us_index += MAC_IE_HDR_LEN + puc_data[us_index + 1];
    }
}

/*****************************************************************************
 ��������  : STA up״̬����Extended Channel Switch Announcement֡����
 �������  : pst_mac_vap: MAC VAP�ṹ��ָ��
             pst_netbuf : ����Extended Channel Switch Announcement֡��netbuf
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_sta_up_rx_ext_ch_switch(mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf)
{
    hmac_rx_ctl_stru *rx_ctrl = HI_NULL;
    hi_u8 *puc_data = HI_NULL;

    if (HI_FALSE == mac_mib_get_spectrum_management_implemented(mac_vap)) {
        oam_info_log0(mac_vap->vap_id, OAM_SF_BA,
                      "{hmac_sta_up_rx_ext_ch_switch::Ignoring Spectrum Management frames.}");
        return;
    }

    rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    /* ��ȡ֡��ָ�� */
    puc_data = (hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr + rx_ctrl->mac_header_len;

    hmac_ie_proc_ch_switch_ie(mac_vap, puc_data, MAC_EID_EXTCHANSWITCHANN);
}

/*****************************************************************************
 ��������  : STA��UP״̬�µĽ���ACTION֡����
 �������  : pst_hmac_vap: HMAC VAP�ṹ��ָ��
             pst_netbuf  : Action֡���ڵ�netbuf
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_sta_up_rx_action(hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf, hi_u8 is_protected)
{
    hmac_user_stru   *hmac_user = HI_NULL;
    hmac_rx_ctl_stru *rx_ctrl   = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);

    /* ��ȡ֡ͷ��Ϣ */
    mac_ieee80211_frame_stru *frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;
#ifdef _PRE_WLAN_FEATURE_P2P
    /* P2P0�豸�����ܵ�actionȫ���ϱ� */
    hi_u8 *puc_p2p0_mac_addr = hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_p2p0_dot11_station_id;
    if (oal_compare_mac_addr(frame_hdr->auc_address1, puc_p2p0_mac_addr, WLAN_MAC_ADDR_LEN) == 0) {
        hmac_rx_mgmt_send_to_host(hmac_vap, netbuf);
    }
#endif

    /* ��ȡ���Ͷ˵��û�ָ�� */
    hmac_user = mac_vap_get_hmac_user_by_addr(hmac_vap->base_vap, frame_hdr->auc_address2, WLAN_MAC_ADDR_LEN);
    if (hmac_user == HI_NULL) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_sta_up_rx_action::mac_vap_find_user failed.}");
        return;
    }

    /* ��ȡ֡��ָ�� */
    hi_u8 *puc_data = (hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr + rx_ctrl->mac_header_len;

    /* Category */
    if (puc_data[MAC_ACTION_OFFSET_CATEGORY] == MAC_ACTION_CATEGORY_BA) {
        hmac_mgmt_rx_action_ba(hmac_vap, hmac_user, puc_data);
    } else if (puc_data[MAC_ACTION_OFFSET_CATEGORY] == MAC_ACTION_CATEGORY_SPECMGMT) {
        if (puc_data[MAC_ACTION_OFFSET_ACTION] == MAC_SPEC_CH_SWITCH_ANNOUNCE) {
            hmac_sta_up_rx_ch_switch(hmac_vap->base_vap, netbuf);
        }
    } else if (puc_data[MAC_ACTION_OFFSET_CATEGORY] == MAC_ACTION_CATEGORY_PUBLIC) {
        if (puc_data[MAC_ACTION_OFFSET_ACTION] == MAC_PUB_EX_CH_SWITCH_ANNOUNCE) {
            hmac_sta_up_rx_ext_ch_switch(hmac_vap->base_vap, netbuf);
#ifdef _PRE_WLAN_FEATURE_P2P
        } else if (puc_data[MAC_ACTION_OFFSET_ACTION] == MAC_PUB_VENDOR_SPECIFIC) {
            /* ����OUI-OUI typeֵΪ 50 6F 9A - 09 (WFA P2P v1.0)  */
            /* ����hmac_rx_mgmt_send_to_host�ӿ��ϱ� */
            if (mac_ie_check_p2p_action(puc_data + MAC_ACTION_OFFSET_ACTION) == HI_TRUE) {
                hmac_rx_mgmt_send_to_host(hmac_vap, netbuf);
            }
#endif
        }
#ifdef _PRE_WLAN_FEATURE_PMF
    } else if (puc_data[MAC_ACTION_OFFSET_CATEGORY] == MAC_ACTION_CATEGORY_SA_QUERY) {
        if (puc_data[MAC_ACTION_OFFSET_ACTION] == MAC_SA_QUERY_ACTION_REQUEST) {
            hmac_rx_sa_query_req(hmac_vap, netbuf, is_protected);
        } else if (puc_data[MAC_ACTION_OFFSET_ACTION] == MAC_SA_QUERY_ACTION_RESPONSE) {
            hmac_rx_sa_query_rsp(hmac_vap, netbuf, is_protected);
        }
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    } else if (puc_data[MAC_ACTION_OFFSET_CATEGORY] == MAC_ACTION_CATEGORY_VENDOR) {
            /* ����OUI-OUI typeֵΪ 50 6F 9A - 09 (WFA P2P v1.0)  */
            /* ����hmac_rx_mgmt_send_to_host�ӿ��ϱ� */
            if (HI_TRUE == mac_ie_check_p2p_action(puc_data + MAC_ACTION_OFFSET_CATEGORY)) {
                hmac_rx_mgmt_send_to_host(hmac_vap, netbuf);
            }
#endif
    }
}

/*****************************************************************************
 ��������  : AP��UP״̬�µĽ��չ���֡����
 �޸���ʷ      :
  1.��    ��   : 2013��6��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sta_up_rx_mgmt(hmac_vap_stru *hmac_vap, const dmac_wlan_crx_event_stru *crx_event)
{
    hmac_rx_ctl_stru    *rx_ctrl = HI_NULL;
    hi_u8               *puc_mac_hdr = HI_NULL;
    hi_u8               mgmt_frm_type;
    hi_u8               is_protected;
    if (crx_event == HI_NULL || crx_event->netbuf == HI_NULL) {
        oam_error_log0(0, OAM_SF_AUTH, "{hmac_sta_up_rx_mgmt::crx_event/crx_event->netbuf  is NULL}");
        return HI_ERR_CODE_PTR_NULL;
    }

    rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)crx_event->netbuf);

    puc_mac_hdr = (hi_u8 *)(rx_ctrl->pul_mac_hdr_start_addr);
    if (puc_mac_hdr == HI_NULL) {
        oam_error_log0(0, OAM_SF_AUTH, "{hmac_sta_up_rx_mgmt::puc_mac_hdr is NULL}");
        return HI_ERR_CODE_PTR_NULL;
    }

    is_protected = mac_get_protectedframe(puc_mac_hdr);

    /* Bar frame proc here */
    if (WLAN_FC0_TYPE_CTL == mac_get_frame_type(puc_mac_hdr)) {
        mgmt_frm_type = mac_get_frame_sub_type(puc_mac_hdr);
        if ((mgmt_frm_type >> 4) == WLAN_BLOCKACK_REQ) { /* ����4λ */
            hmac_up_rx_bar(hmac_vap, rx_ctrl);
        }
    }

    /* AP��UP״̬�� ���յ��ĸ��ֹ���֡���� */
    mgmt_frm_type = mac_get_frame_sub_type(puc_mac_hdr);

    switch (mgmt_frm_type) {
        case WLAN_FC0_SUBTYPE_DEAUTH:
        case WLAN_FC0_SUBTYPE_DISASSOC:
            hmac_sta_rx_deauth_req(hmac_vap, puc_mac_hdr, is_protected);
            break;

        case WLAN_FC0_SUBTYPE_BEACON:
            hmac_sta_up_rx_beacon(hmac_vap, (oal_netbuf_stru *)crx_event->netbuf);
            break;

        case WLAN_FC0_SUBTYPE_ACTION:
            hmac_sta_up_rx_action(hmac_vap, (oal_netbuf_stru *)crx_event->netbuf, is_protected);
            break;
        default:
            break;
        }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����25ms�ش�����
 �޸���ʷ      :
  1.��    ��   : 2019��9��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_set_retry_time_en(const mac_vap_stru *mac_vap, hi_u8 retry_time, hi_u8 retry_frame_type)
{
    mac_cfg_retry_param_stru set_retry_first;
    mac_cfg_retry_param_stru set_retry_second;
    hi_u32 ret;

    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_TX, "{hmac_set_retry_time_en::mac vap is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����ǰ�ش�������0 */
    set_retry_first.limit = 0;
    set_retry_first.type = retry_frame_type;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RETRY_LIMIT, sizeof(mac_cfg_retry_param_stru),
                                 (hi_u8 *)&set_retry_first);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_set_retry_time_en::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    /* ʹ��ʱ���ش����� */
    set_retry_second.limit = retry_time;
    set_retry_second.type = MAC_CFG_RETRY_TIMEOUT;

    /***************************************************************************
            ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RETRY_LIMIT, sizeof(mac_cfg_retry_param_stru),
                                 (hi_u8 *)&set_retry_second);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_set_retry_time_en::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ر�25ms�ش�����
 �޸���ʷ      :
  1.��    ��   : 2019��9��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_set_retry_time_close(const mac_vap_stru *mac_vap)
{
    mac_cfg_retry_param_stru set_retry_first;
    mac_cfg_retry_param_stru set_retry_second;
    mac_cfg_retry_param_stru set_retry_third;
    hi_u32 ret;

    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_TX, "{hmac_set_retry_time_close::mac vap is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �ָ�����֡�ش����� */
    set_retry_first.limit = 5; /* DMAC_MAX_SW_RETRIES: 5 */
    set_retry_first.type = MAC_CFG_RETRY_DATA;

    /***************************************************************************
        ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RETRY_LIMIT, sizeof(mac_cfg_retry_param_stru),
                                 (hi_u8 *)&set_retry_first);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_set_retry_time_close::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    /* �ָ�����֡�ش����� */
    set_retry_second.limit = DMAC_MGMT_MAX_SW_RETRIES;
    set_retry_second.type = MAC_CFG_RETRY_MGMT;

    /***************************************************************************
            ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RETRY_LIMIT, sizeof(mac_cfg_retry_param_stru),
                                 (hi_u8 *)&set_retry_second);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_set_retry_time_close::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    /* �ر�ʱ���ش����� */
    set_retry_third.limit = 0;
    set_retry_third.type = MAC_CFG_RETRY_TIMEOUT;

    /***************************************************************************
            ���¼���DMAC��, ͬ��DMAC����
    ***************************************************************************/
    ret = hmac_config_send_event(mac_vap, WLAN_CFGID_SET_RETRY_LIMIT, sizeof(mac_cfg_retry_param_stru),
                                 (hi_u8 *)&set_retry_third);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_UM,
                         "{hmac_set_retry_time_close::hmac_config_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
