/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Source file corresponding to the structure definition of the frame.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oam_ext_if.h"
#include "mac_frame.h"
#include "mac_vap.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "mac_regdomain.h"
#include "mac_data.h"
#include "frw_main.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  ȫ�ֱ�������
*****************************************************************************/
#define __WIFI_ROM_SECTION__        /* ����ROM����ʼλ�� */
/*****************************************************************************
  ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ����ָ����IE
 �������  : [1]eid
             [2]puc_ies
             [3]l_len
 �� �� ֵ  : const hi_u8 *
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 *mac_find_ie(hi_u8 eid, hi_u8 *puc_ies, hi_u32 l_len)
{
    if (puc_ies == HI_NULL) {
        return HI_NULL;
    }
    while (l_len > MAC_IE_HDR_LEN && puc_ies[0] != eid) {
        if (l_len < (hi_u32)(puc_ies[1] + MAC_IE_HDR_LEN)) {
            break;
        }
        l_len   -= puc_ies[1] + MAC_IE_HDR_LEN;
        puc_ies += puc_ies[1] + MAC_IE_HDR_LEN;
    }
    if ((l_len < MAC_IE_HDR_LEN) || (l_len < (hi_u32)(MAC_IE_HDR_LEN + puc_ies[1]))
        || ((l_len == MAC_IE_HDR_LEN) && (puc_ies[0] != eid))) {
        return HI_NULL;
    }
    return puc_ies;
}

/*****************************************************************************
 ��������  : ���ҳ����Զ��� IE
 �������  : [1]oui
             [2]oui_type
             [3]puc_ies
             [4]l_len
 �� �� ֵ  : const hi_u8 * ժ��linux �ں�
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 *mac_find_vendor_ie(hi_u32 oui, hi_u8 oui_type, hi_u8 *puc_ies, hi_s32 l_len)
{
    mac_ieee80211_vendor_ie_stru *ie = HI_NULL;
    hi_u8 *puc_pos = HI_NULL;
    hi_u8 *puc_end = HI_NULL;
    hi_u32 ie_oui;

    if (puc_ies == HI_NULL) {
        return HI_NULL;
    }
    puc_pos = puc_ies;
    puc_end = puc_ies + l_len;
    while (puc_pos < puc_end) {
        puc_pos = mac_find_ie(MAC_EID_VENDOR, puc_pos, (hi_u32)(puc_end - puc_pos));
        if (puc_pos == HI_NULL) {
            return HI_NULL;
        }
        ie = (mac_ieee80211_vendor_ie_stru *)puc_pos;
        if (ie->len >= (sizeof(mac_ieee80211_vendor_ie_stru) - MAC_IE_HDR_LEN)) {
            ie_oui = (ie->auc_oui[0] << 16) |           /* auc_oui[0]�������16bit */
                (ie->auc_oui[1] << 8) | ie->auc_oui[2]; /* auc_oui[1]���ڴθ�8bit��auc_oui[2]�������8bit */
            if ((ie_oui == oui) && (ie->oui_type == oui_type)) {
                return puc_pos;
            }
        }
        puc_pos += 2 + ie->len; /* ÿ��ѭ��ƫ��(2 + ie->len)byte */
    }
    return HI_NULL;
}

/*****************************************************************************
 ��������  : ��Ϊapʱ������mibֵ������cap info
 �������  : pst_vap      : ָ��vap
             puc_cap_info : ָ��洢����λ��Ϣ��buffer
 �޸���ʷ      :
  1.��    ��   : 2013��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_cap_info_ap(hi_void *vap, hi_u8 *puc_cap_info)
{
    mac_cap_info_stru  *cap_info = (mac_cap_info_stru *)puc_cap_info;
    mac_vap_stru       *mac_vap  = (mac_vap_stru *)vap;

    wlan_mib_ieee802dot11_stru *mib = mac_vap->mib_info;
    /**************************************************************************
         -------------------------------------------------------------------
         |B0 |B1  |B2        |B3    |B4     |B5      |B6  |B7     |B8      |
         -------------------------------------------------------------------
         |ESS|IBSS|CFPollable|CFPReq|Privacy|Preamble|PBCC|Agility|SpecMgmt|
         -------------------------------------------------------------------
         |B9 |B10      |B11 |B12     |B13      |B14        |B15            |
         -------------------------------------------------------------------
         |QoS|ShortSlot|APSD|RM      |DSSS-OFDM|Delayed BA |Immediate BA   |
         -------------------------------------------------------------------
    ***************************************************************************/
    /* ��ʼ���� */
    puc_cap_info[0] = 0;
    puc_cap_info[1] = 0;

    if (WLAN_MIB_DESIRED_BSSTYPE_INDEPENDENT == mib->wlan_mib_sta_config.dot11_desired_bss_type) {
        cap_info->ibss = 1;
    } else if (WLAN_MIB_DESIRED_BSSTYPE_INFRA == mib->wlan_mib_sta_config.dot11_desired_bss_type) {
        cap_info->ess = 1;
    }

    /* The Privacy bit is set if WEP is enabled */
    cap_info->privacy = mib->wlan_mib_privacy.dot11_privacy_invoked;
    /* preamble */
    cap_info->short_preamble = mac_mib_get_short_preamble_option_implemented(mac_vap);
    /* packet binary convolutional code (PBCC) modulation */
    cap_info->pbcc = mib->phy_hrdsss.dot11_pbcc_option_implemented;
    /* Channel Agility */
    cap_info->channel_agility = mib->phy_hrdsss.dot11_channel_agility_present;
    /* Spectrum Management */
    cap_info->spectrum_mgmt = mib->wlan_mib_sta_config.dot11_spectrum_management_required;
    /* QoS subfield */
    cap_info->qos = mib->wlan_mib_sta_config.dot11_qos_option_implemented;
    /* short slot */
    cap_info->short_slot_time = 1;
    /* APSD */
    cap_info->apsd = mib->wlan_mib_sta_config.dot11_apsd_option_implemented;
    /* Radio Measurement */
    cap_info->radio_measurement = mib->wlan_mib_sta_config.dot11_radio_measurement_activated;
    /* DSSS-OFDM */
    cap_info->dsss_ofdm = HI_FALSE;
    /* Delayed BA */
    cap_info->delayed_block_ack = mib->wlan_mib_sta_config.dot11_delayed_block_ack_option_implemented;
    /* Immediate Block Ack �ο�STA��AP��ˣ�������һֱΪ0,ʵ��ͨ��addbaЭ�̡��˴��޸�Ϊ���һ�¡�mibֵ���޸� */
    cap_info->immediate_block_ack = 0;
}

WIFI_ROM_RODATA const hi_char g_dmac_p2p_wildcard_ssid[MAC_P2P_WILDCARD_SSID] = "DIRECT-";
/*****************************************************************************
 ��������  : ����ssid ie
 �������  : pst_vap: ָ��vap
             puc_buffer : ָ��buffer
 �������  : puc_ie_len : element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u16 mac_set_ssid_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len, hi_u16 us_frm_type)
{
    hi_u8    *puc_ssid = HI_NULL;
    hi_u8     ssid_len;
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;

    /***************************************************************************
                    ----------------------------
                    |Element ID | Length | SSID|
                    ----------------------------
           Octets:  |1          | 1      | 0~32|
                    ----------------------------
    ***************************************************************************/
    /***************************************************************************
      A SSID  field  of length 0 is  used  within Probe
      Request management frames to indicate the wildcard SSID.
    ***************************************************************************/
    *puc_buffer = MAC_EID_SSID;

    /* ֻ��beacon������ssid */
    if ((mac_vap->cap_flag.hide_ssid) && (WLAN_FC0_SUBTYPE_BEACON == us_frm_type)) {
        /* ssid len */
        *(puc_buffer + 1) = 0;
        *puc_ie_len = MAC_IE_HDR_LEN;
        return 0;
    }

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA && mac_vap->p2p_mode == WLAN_P2P_DEV_MODE) {
        ssid_len = (hi_u8)sizeof(g_dmac_p2p_wildcard_ssid) - 1;    /* ������'\0' */
        *(puc_buffer + 1) = ssid_len;

        if (memcpy_s(puc_buffer + MAC_IE_HDR_LEN, ssid_len, g_dmac_p2p_wildcard_ssid, ssid_len) != EOK) {
            oam_error_log0(0, OAM_SF_P2P, "{mac_set_ssid_ie::mem safe func err!}");
            /* ssid len */
            *(puc_buffer + 1) = 0;
            *puc_ie_len = MAC_IE_HDR_LEN;
            return 0;
        }
    } else {
        puc_ssid = mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid;
        ssid_len = (hi_u8)strlen((hi_char *)puc_ssid);   /* ������'\0' */
        *(puc_buffer + 1) = ssid_len;
        if (memcpy_s(puc_buffer + MAC_IE_HDR_LEN, ssid_len, puc_ssid, ssid_len) != EOK) {
            oam_error_log0(0, 0, "{mac_set_ssid_ie::mem safe func err!}");
            /* ssid len */
            *(puc_buffer + 1) = 0;
            *puc_ie_len = MAC_IE_HDR_LEN;
            return 0;
        }
    }
    *puc_ie_len = ssid_len + MAC_IE_HDR_LEN;
    return ssid_len;
}

/*****************************************************************************
 ��������  : �������ʼ�
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_supported_rates_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru     *mac_vap   = (mac_vap_stru *)vap;
    mac_rateset_stru *rates_set = HI_NULL;
    hi_u8         nrates;
    hi_u8         idx;

    rates_set = &(mac_vap->curr_sup_rates.rate);
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
    nrates = rates_set->rs_nrates;
    if (nrates > MAC_MAX_SUPRATES) {
        nrates = MAC_MAX_SUPRATES;
    }
    for (idx = 0; idx < nrates; idx++) {
        puc_buffer[MAC_IE_HDR_LEN + idx] = rates_set->ast_rs_rates[idx].mac_rate;
    }
    puc_buffer[1] = nrates;
    *puc_ie_len = MAC_IE_HDR_LEN + nrates;
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
/*****************************************************************************
 ��������  : Mesh���ظ���Mesh�ڵ��rsn��Ϣ
 �������  : pst_vap   : ָ��vap
             puc_buffer: ָ��buffer
             hi_u16 us_frm_type
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2019��1��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_rsn_mesh_cap(mac_rsn_cap_stru *rsn_cap, const mac_vap_stru *mac_vap)
{
    rsn_cap->mfpr        = mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpr;
    rsn_cap->mfpc        = mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpc;
    rsn_cap->pre_auth    =
        mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_preauthentication_activated;
    rsn_cap->no_pairwise = 0;
    rsn_cap->ptska_relay_counter =
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_number_of_ptksa_replay_counters_implemented;
    rsn_cap->gtska_relay_counter =
        mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_number_of_gtksa_replay_counters_implemented;
}

WIFI_ROM_TEXT static hi_void mac_set_rsn_group_cipher_suite_field(const mac_vap_stru *mac_vap,
    hi_u8 *puc_buffer, hi_u16 us_frm_type, hi_u8 *puc_ie_len)
{
    hi_u8               auc_oui[MAC_OUI_LEN];
    hi_u8               index = 0;

    if (us_frm_type == WLAN_FC0_SUBTYPE_PROBE_RSP) {
        index = MAC_IE_HDR_LEN;
        /* ����RSN ie��EID */
        puc_buffer[0] = MAC_EID_RSN;
    } else if (us_frm_type == WLAN_FC0_SUBTYPE_BEACON) {
        index = MAC_IE_VENDOR_SPEC_MESH_HDR_LEN;
        puc_buffer[0] = MAC_EID_VENDOR;
        auc_oui[0] = (hi_u8)MAC_WLAN_OUI_HUAWEI0;
        auc_oui[1] = (hi_u8)MAC_WLAN_OUI_HUAWEI1;
        auc_oui[2] = (hi_u8)MAC_WLAN_OUI_HUAWEI2; /* auc_oui[2]��ֵΪMAC_WLAN_OUI_HUAWEI2 */
        if (memcpy_s(&puc_buffer[2], MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) { /* puc_buffer[2]��ֵ */
            return;
        }
        puc_buffer[5] = MAC_OUITYPE_MESH; /* puc_buffer[5]��ֵΪMAC_OUITYPE_MESH */
        puc_buffer[6] = MAC_OUISUBTYPE_MESH_HISI_RSN; /* puc_buffer[6]��ֵΪMAC_OUISUBTYPE_MESH_HISI_RSN */
    }
    auc_oui[0] = (hi_u8)MAC_WLAN_OUI_RSN0;
    auc_oui[1] = (hi_u8)MAC_WLAN_OUI_RSN1;
    auc_oui[2] = (hi_u8)MAC_WLAN_OUI_RSN2; /* auc_oui[2]��ֵΪMAC_WLAN_OUI_RSN2 */
    /* ����version�ֶ� */
    puc_buffer[index++] = MAC_RSN_IE_VERSION;
    puc_buffer[index++] = 0;

    /* ����Group Cipher Suite */
    /*************************************************************************/
    /*                  Group Cipher Suite                                   */
    /* --------------------------------------------------------------------- */
    /*                  | OUI | Suite type |                                 */
    /* --------------------------------------------------------------------- */
    /*          Octets: |  3  |     1      |                                 */
    /* --------------------------------------------------------------------- */
    /*************************************************************************/
    if (memcpy_s(&puc_buffer[index], MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) {
        return;
    }
    index += MAC_OUI_LEN;
    puc_buffer[index++] = mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher;
    /* ���óɶԼ����׼����� */
    puc_buffer[index++] = 1;
    puc_buffer[index++] = 0;
    if (memcpy_s(&puc_buffer[index], MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) {
        return;
    }
    index += MAC_OUI_LEN;
    puc_buffer[index++] = WLAN_80211_CIPHER_SUITE_CCMP; /* Mesh ��ֻʹ��CCMP-128 ,�ݲ��������� */
    /* ������֤�׼��� (Mesh��ֻ֧��SAE) */
    puc_buffer[index++] = 1;
    puc_buffer[index++] = 0;
    /* ����MIB ֵ��������֤�׼����� */
    if (memcpy_s(&puc_buffer[index], MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) {
        return;
    }
    index += MAC_OUI_LEN;
    puc_buffer[index++] = WLAN_AUTH_SUITE_SAE_SHA256; /* MESH ��ֻ֧��SAE */

    *puc_ie_len = index;
}

WIFI_ROM_TEXT hi_void mac_set_rsn_mesh_ie_authenticator(hi_void *vap, hi_u8 *puc_buffer,
                                                        hi_u16 us_frm_type, hi_u8 *puc_ie_len)
{
    mac_vap_stru        *mac_vap = (mac_vap_stru *)vap;
    mac_rsn_cap_stru    *rsn_cap = HI_NULL;
    hi_u8               index = 0;
    hi_u8               ie_len = 0;

    if (mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated != HI_TRUE) {
        *puc_ie_len = 0;
        return;
    }
    if (mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_security_activated != HI_TRUE) {
        *puc_ie_len = 0;
        return;
    }
    if (mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol
        != MAC_MIB_AUTH_PROTOCOL_SAE) {
        *puc_ie_len = 0;
        return;
    }
    /*************************************************************************/
    /*                  RSN Element Format              */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length | Version | Group Cipher Suite | Pairwise Cipher */
    /* --------------------------------------------------------------------- */
    /* | 1         | 1      | 2       |      4             |     2           */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Suite | Pairwise Cipher Suite List | AKM Suite Count | AKM Suite List */
    /* --------------------------------------------------------------------- */
    /*       | 4-m                        |     2          | 4-n             */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |RSN Capabilities|PMKID Count|PMKID List|Group Management Cipher Suite */
    /* --------------------------------------------------------------------- */
    /* |    2           |    2      |16 -s     |         4                 | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    mac_set_rsn_group_cipher_suite_field(mac_vap, &puc_buffer[index], us_frm_type, &ie_len);
    index  += ie_len;
    /* ���� RSN Capabilities�ֶ� */
    /*************************************************************************/
    /* --------------------------------------------------------------------- */
    /* | B15 - B6  |  B5 - B4      | B3 - B2     |       B1    |     B0    | */
    /* --------------------------------------------------------------------- */
    /* | Reserved  |  GTSKA Replay | PTSKA Replay| No Pairwise | Pre - Auth| */
    /* |           |    Counter    |   Counter   |             |           | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ����RSN Capabilities ֵ������Pre_Auth, no_pairwise */
    /* Replay counters (PTKSA and GTKSA)                    */
    rsn_cap = (mac_rsn_cap_stru *)(puc_buffer + index);
    if (memset_s(rsn_cap, sizeof(mac_rsn_cap_stru), 0, sizeof(mac_rsn_cap_stru)) != EOK) {
        return;
    }
    index += MAC_RSN_CAP_LEN;

    mac_set_rsn_mesh_cap(rsn_cap, mac_vap);

    /* ����RSN element�ĳ��� */
    puc_buffer[1] = index - MAC_IE_HDR_LEN;

    *puc_ie_len = index;
}

/*****************************************************************************
 ��������  : ����mesh�Զ��� IE(��ȷ��subtype)
 �������  : [1]oui_sub_type,
             [2]puc_ies,
             [3]l_len
 �� �� ֵ  : hi_u8 *
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 *mac_find_mesh_vendor_ie(hi_u8 oui_sub_type, hi_u8 *puc_ies, hi_u32 l_len)
{
    mac_ieee80211_vendor_ie_stru *ie = HI_NULL;
    hi_u8 *puc_pos = HI_NULL;
    hi_u8 *puc_end = HI_NULL;
    hi_u32 ie_oui;

    puc_pos = puc_ies;
    puc_end = puc_ies + l_len;
    while (puc_pos < puc_end) {
        puc_pos = mac_find_ie(MAC_EID_VENDOR, puc_pos, (hi_u32)(puc_end - puc_pos));
        if (puc_pos == HI_NULL) {
            return HI_NULL;
        }
        ie = (mac_ieee80211_vendor_ie_stru *)puc_pos;
        if (ie->len > (sizeof(mac_ieee80211_vendor_ie_stru) - MAC_IE_HDR_LEN)) {
            ie_oui = (ie->auc_oui[0] << 16) |          /* auc_oui[0]�������16bit */
                (ie->auc_oui[1] << 8) | ie->auc_oui[2]; /* auc_oui[1]���ڴθ�8bit��auc_oui[2]�������8bit */
            if ((ie_oui == MAC_WLAN_OUI_HUAWEI) && (ie->oui_type == MAC_OUITYPE_MESH)
                && (puc_pos[MAC_IE_VENDOR_SPEC_MESH_SUBTYPE_POS] == oui_sub_type)) {
                return puc_pos;
            }
        }
        puc_pos += 2 + ie->len; /* ÿ��ƫ��(2 + ie->len) byte */
    }
    return HI_NULL;
}

/*****************************************************************************
 ��������  : ����ʱ���˽���ֶΣ��жϰ��ķ��Ͷ��Ƿ�ΪMesh VAP
 �������  :
             [1]puc_buffer
             [2]puc_ie_len
 �� �� ֵ  : hi_u8
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_check_is_mesh_vap(hi_u8 *puc_buffer, hi_u8 puc_ie_len)
{
    hi_u8 *hisi_beacon_ie = HI_NULL;
    hi_u8 *hisi_prb_rsp_ie = HI_NULL;

    hisi_beacon_ie = mac_find_mesh_vendor_ie(MAC_OUISUBTYPE_MESH_HISI_BEACON, puc_buffer, puc_ie_len);
    hisi_prb_rsp_ie = mac_find_mesh_vendor_ie(MAC_OUISUBTYPE_MESH_HISI_RSP, puc_buffer, puc_ie_len);
    if ((hisi_beacon_ie == HI_NULL) && (hisi_prb_rsp_ie == HI_NULL)) {
        return HI_FALSE;
    }
    return HI_TRUE;
}

/*****************************************************************************
 ��������  : ��ȡbeacon֡�е�meshid(˽���ֶ���)
 �������  : puc_beacon_body:Beacon or probe rsp֡��
                            hi_s32 l_frame_body_len:֡�峤��
 �������  : puc_meshid_len:meshid����
 �� �� ֵ  : ָ��meshid
 �޸���ʷ      :
  1.��    ��   : 2019��4��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
WIFI_ROM_TEXT hi_u8* mac_get_meshid(hi_u8 *puc_beacon_body, hi_s32 l_frame_body_len, hi_u8 *puc_meshid_len)
{
    const hi_u8 *puc_meshid_ie = HI_NULL;
    hi_u16 us_offset =  MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* --------------------------------------------------------------------- */
    /* |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   | */
    /* --------------------------------------------------------------------- */
    /* |8         |2         |2       |2-34 |3-10     |3        |4-256     | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /***************************************************************************
         Vendor Spec |Length| OUI|TYPE|SUBTYPE|MESHID LEN|MESHID|
           1                |1        |3    |1     |1           |  1               |Var       |
    ***************************************************************************/
    /* meshid�ĳ��ȳ�ʼ��ֵΪ0 */
    *puc_meshid_len = 0;

    /* ���beacon֡����probe rsp֡�ĳ��ȵĺϷ��� */
    if (l_frame_body_len <= us_offset) {
        oam_warning_log0(0, OAM_SF_ANY, "{mac_get_meshid:: the length of beacon/probe rsp frame body is invalid.}");
        return HI_NULL;
    }

    puc_meshid_ie = mac_find_mesh_vendor_ie(MAC_OUISUBTYPE_MESH_HISI_MESHID,
        (puc_beacon_body + us_offset), (hi_u32)(l_frame_body_len - us_offset));
    /* ����meshid��ie */
    if ((puc_meshid_ie != HI_NULL) && (puc_meshid_ie[MAC_MESH_MESHID_LEN_POS] < WLAN_MESHID_MAX_LEN)) {
        /* ��ȡssid ie�ĳ��� */
        *puc_meshid_len = puc_meshid_ie[MAC_MESH_MESHID_LEN_POS];

        return (hi_u8 *)(puc_meshid_ie + MAC_MESH_MESHID_OFFSET);
    }

    return HI_NULL;
}

/*****************************************************************************
 ��������  : ��ȡbeacon֡�е�beacon priority�ֶΣ��ϱ�new peer candidateʱʹ��(˽���ֶ���)
 �������  : puc_beacon_body:Beacon or probe rsp֡��
                            hi_s32 l_frame_body_len:֡�峤��
 �� �� ֵ  : uc_bcn_prio:beacon priority
 �޸���ʷ      :
  1.��    ��   : 2019��5��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_get_hisi_beacon_prio(hi_u8 *puc_beacon_body, hi_s32 l_frame_body_len)
{
    hi_u8 bcn_prio = 0;
    hi_u8 *puc_bcn_prio_ie = HI_NULL;
    hi_u16 us_offset =  MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* --------------------------------------------------------------------- */
    /* |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   | */
    /* --------------------------------------------------------------------- */
    /* |8         |2         |2       |2-34 |3-10     |3        |4-256     | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /***************************************************************************
         Vendor Spec |Length| OUI|TYPE|SUBTYPE|Beacon Priority|
           1                |1        |3    |1     |1            |  1                  |
    ***************************************************************************/
    /* ���beacon֡����probe rsp֡�ĳ��ȵĺϷ��� */
    if (l_frame_body_len <= us_offset) {
        oam_warning_log0(0, OAM_SF_ANY,
            "{mac_get_hisi_mesh_optimization_ie:: the length of beacon/probe rsp frame body is invalid.}");
        return 0;
    }

    puc_bcn_prio_ie = mac_find_mesh_vendor_ie(MAC_OUISUBTYPE_MESH_HISI_OPTIMIZATION,
        (puc_beacon_body + us_offset), (hi_u32)(l_frame_body_len - us_offset));
    /* ����beacon prio��ie */
    if (puc_bcn_prio_ie != HI_NULL) {
        /* ��ȡbeacon prio */
        bcn_prio = puc_bcn_prio_ie[MAC_MESH_HISI_BEACON_PRIO_POS];
    }

    return bcn_prio;
}

/*****************************************************************************
 ��������  : ��ȡbeacon֡�е�is mbr��ʶ�ֶΣ��ϱ�new peer candidateʱʹ��(˽���ֶ���)
 �������  : puc_beacon_body:Beacon or probe rsp֡��
                            hi_s32 l_frame_body_len:֡�峤��
 �� �� ֵ  : hi_u8 en_is_mbr
 �޸���ʷ      :
  1.��    ��   : 2019��6��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_get_hisi_en_is_mbr(hi_u8 *puc_beacon_body, hi_s32 l_frame_body_len)
{
    hi_u8 is_mbr = 0;
    hi_u8 *puc_hisi_optimization_ie = HI_NULL;
    hi_u16 us_offset =  MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* --------------------------------------------------------------------- */
    /* |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   | */
    /* --------------------------------------------------------------------- */
    /* |8         |2         |2       |2-34 |3-10     |3        |4-256     | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /***************************************************************************
         Vendor Spec |Length| OUI|TYPE|SUBTYPE|Beacon Priority|
           1                |1        |3    |1     |1            |  1                  |
    ***************************************************************************/
    /* ���beacon֡����probe rsp֡�ĳ��ȵĺϷ��� */
    if (l_frame_body_len <= us_offset) {
        oam_warning_log0(0, OAM_SF_ANY,
            "{mac_get_hisi_en_is_mbr:: the length of beacon/probe rsp frame body is invalid.}");
        return 0;
    }

    puc_hisi_optimization_ie = mac_find_mesh_vendor_ie(MAC_OUISUBTYPE_MESH_HISI_OPTIMIZATION,
        (puc_beacon_body + us_offset), (hi_u32)(l_frame_body_len - us_offset));
    /* ����beacon prio��ie */
    if (puc_hisi_optimization_ie != HI_NULL) {
        /* ��ȡbeacon prio */
        is_mbr = puc_hisi_optimization_ie[MAC_MESH_HISI_IS_MBR_POS];
    }

    return is_mbr;
}

/*****************************************************************************
 ��������  : ��ȡbeacon֡�е�Accept sta��ʶ�ֶΣ��ϱ�new peer candidateʱʹ��(˽���ֶ���)
 �������  : puc_beacon_body:Beacon or probe rsp֡��
                            hi_s32 l_frame_body_len:֡�峤��
 �� �� ֵ  : hi_u8 accept_sta
 �޸���ʷ      :
  1.��    ��   : 2019��6��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_get_hisi_accept_sta(hi_u8 *puc_beacon_body, hi_s32 l_frame_body_len)
{
    hi_u8 accept_sta = 0;
    hi_u8 *puc_hisi_optimization_ie = HI_NULL;
    hi_u16 us_offset =  MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* --------------------------------------------------------------------- */
    /* |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   | */
    /* --------------------------------------------------------------------- */
    /* |8         |2         |2       |2-34 |3-10     |3        |4-256     | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /***************************************************************************
         Vendor Spec |Length| OUI|TYPE|SUBTYPE|Beacon Priority|
           1                |1        |3    |1     |1            |  1                  |
    ***************************************************************************/
    /* ���beacon֡����probe rsp֡�ĳ��ȵĺϷ��� */
    if (l_frame_body_len <= us_offset) {
        oam_warning_log0(0, OAM_SF_ANY,
            "{mac_get_hisi_accept_sta:: the length of beacon/probe rsp frame body is invalid.}");
        return 0;
    }

    puc_hisi_optimization_ie = mac_find_mesh_vendor_ie(MAC_OUISUBTYPE_MESH_HISI_OPTIMIZATION,
        (puc_beacon_body + us_offset), (hi_u32)(l_frame_body_len - us_offset));
    /* ����beacon prio��ie */
    if (puc_hisi_optimization_ie != HI_NULL) {
        /* ��ȡbeacon prio */
        accept_sta = puc_hisi_optimization_ie[MAC_MESH_HISI_ACCEPT_STA_POS];
    }

    return accept_sta;
}

#endif

#ifdef _PRE_WLAN_FEATURE_STA_UAPSD
/*****************************************************************************
 ��������  : ����sta qos info�ֶ�
 �������  : pst_mac_vap: ָ��vap
             puc_buffer : ָ��buffer
 �޸���ʷ      :
  1.��    ��   : 2015��2��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_qos_info_wmm_sta(const mac_vap_stru *mac_vap, hi_u8 *puc_buffer)
{
    hi_u8                   qos_info = 0;
    hi_u8                   max_sp_bits;
    hi_u8                   max_sp_length;
    /* QoS Information field                                          */
    /* -------------------------------------------------------------- */
    /* | B0    | B1    | B2    | B3    | B4      | B5:B6 | B7       | */
    /* -------------------------------------------------------------- */
    /* | AC_VO | AC_VI | AC_BK | AC_BE |         | Max SP|          | */
    /* | U-APSD| U-APSD| U-APSD| U-APSD| Reserved| Length| Reserved | */
    /* | Flag  | Flag  | Flag  | Flag  |         |       |          | */
    /* -------------------------------------------------------------- */
    /* Set the UAPSD configuration information in the QoS info field if the  */
    /* BSS type is Infrastructure and the AP supports UAPSD.                 */
    if (mac_vap->uapsd_cap) {
        max_sp_length  = mac_vap->sta_uapsd_cfg.max_sp_len;
        qos_info = mac_vap->sta_uapsd_cfg.trigger_map;
        if (max_sp_length <= 6) { /* sp��󳤶�Ϊ6 byte */
            max_sp_bits = max_sp_length >> 1;
            qos_info |= ((max_sp_bits & 0x03) << 5); /* sp bit����qos_info�ĵ�5bit��ʼ�洢 */
        }
    }
    puc_buffer[0] = qos_info;
}
#endif

/*****************************************************************************
 ��������  : ����qos info�ֶ�
 �������  : pst_mac_vap: ָ��vap
             puc_buffer : ָ��buffer
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_qos_info_field(const mac_vap_stru *mac_vap, hi_u8 *puc_buffer)
{
    mac_qos_info_stru *qos_info = (mac_qos_info_stru *)puc_buffer;

    /* QoS Information field  (AP MODE)            */
    /* ------------------------------------------- */
    /* | B0:B3               | B4:B6    | B7     | */
    /* ------------------------------------------- */
    /* | Parameter Set Count | Reserved | U-APSD | */
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
        || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
    ) {
        qos_info->params_count = mac_vap->wmm_params_update_count;
        qos_info->uapsd        = mac_vap->cap_flag.uapsd;
        qos_info->bit_resv         = 0;
    }

    /* QoS Information field  (STA MODE)           */
    /* ---------------------------------------------------------------------------------------------------------- */
    /* | B0              | B1              | B2              | B3              | B4      |B5   B6      | B7     | */
    /* ---------------------------------------------------------------------------------------------------------- */
    /* |AC_VO U-APSD Flag|AC_VI U-APSD Flag|AC_BK U-APSD Flag|AC_BE U-APSD Flag|Reserved |Max SP Length|Reserved| */
    /* ---------------------------------------------------------------------------------------------------------- */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
#ifdef _PRE_WLAN_FEATURE_STA_UAPSD
        mac_set_qos_info_wmm_sta(mac_vap, puc_buffer);
#else
        puc_buffer[0] = 0;
        puc_buffer[0] |= 0x0;
#endif
    }
}

/*****************************************************************************
 ��������  : ����һ��ac�Ĳ���
 �������  : pst_mac_vap: ָ��vap
             puc_buffer : ָ��buffer
             en_ac      : AC����
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_wmm_ac_params(const mac_vap_stru *mac_vap, hi_u8 *puc_buffer, hi_u8 ac)
{
    mac_wmm_ac_params_stru *ac_params = (mac_wmm_ac_params_stru *)puc_buffer;

    /* AC_** Parameter Record field               */
    /* ------------------------------------------ */
    /* | Byte 1    | Byte 2        | Byte 3:4   | */
    /* ------------------------------------------ */
    /* | ACI/AIFSN | ECWmin/ECWmax | TXOP Limit | */
    /* ------------------------------------------ */
    /* ACI/AIFSN Field                    */
    /* ---------------------------------- */
    /* | B0:B3 | B4  | B5:B6 | B7       | */
    /* ---------------------------------- */
    /* | AIFSN | ACM | ACI   | Reserved | */
    /* ---------------------------------- */
    /* AIFSN */
    ac_params->aifsn = mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_aifsn;
    /* ACM */
    ac_params->acm = mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_mandatory;
    /* ACI */
    ac_params->aci = ac;
    ac_params->bit_resv = 0;

    /* ECWmin/ECWmax Field */
    /* ------------------- */
    /* | B0:B3  | B4:B7  | */
    /* ------------------- */
    /* | ECWmin | ECWmax | */
    /* ------------------- */
    /* ECWmin */
    ac_params->ecwmin = mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_c_wmin;
    /* ECWmax */
    ac_params->ecwmax = mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_c_wmax;
    /* TXOP Limit. The value saved in MIB is in usec while the value to be   */
    /* set in this element should be in multiple of 32us                     */
    ac_params->us_txop =
        (hi_u16)((mac_vap->mib_info->ast_wlan_mib_edca[ac].dot11_edca_table_txop_limit) >> 5); /* ����5bit��ȡtxop */
}

/*****************************************************************************
 ��������  : ����wmm��ϢԪ��
 �������  : pst_vap   : ָ��vap
             puc_buffer: ָ��buffer
             en_is_qos : �Ƿ�֧��QOS�������BEACON/Probe Req/Probe Rsp/ASSOC Req֡����ȡAP/STA�����QOS������
             ���ASSOC RSP������Ҫ���ݶԷ�STA��QOS���������ж��Ƿ��WMM IE��
 �������  : puc_ie_len: ie���ܳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_wmm_params_ie(hi_void *vap,
                                            hi_u8 *puc_buffer, hi_u8 is_qos, hi_u8 *puc_ie_len)
{
    hi_u8     index;
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    hi_u8     auc_oui[MAC_OUI_LEN] = {(hi_u8)MAC_WLAN_OUI_MICRO0,
                                      (hi_u8)MAC_WLAN_OUI_MICRO1, (hi_u8)MAC_WLAN_OUI_MICRO2};

    if (!is_qos) {
        *puc_ie_len = 0;
        return;
    }
    /* WMM Parameter Element Format                                          */
    /* --------------------------------------------------------------------- */
    /* | 3Byte | 1        | 1           | 1             | 1        | 1     | */
    /* --------------------------------------------------------------------- */
    /* | OUI   | OUI Type | OUI Subtype | Version field | QoS Info | Resvd | */
    /* --------------------------------------------------------------------- */
    /* | 4              | 4              | 4              | 4              | */
    /* --------------------------------------------------------------------- */
    /* | AC_BE ParamRec | AC_BK ParamRec | AC_VI ParamRec | AC_VO ParamRec | */
    /* --------------------------------------------------------------------- */
    puc_buffer[0] = MAC_EID_WMM;
    puc_buffer[1] = MAC_WMM_PARAM_LEN;
    index = MAC_IE_HDR_LEN;
    /* OUI */
    if (memcpy_s(&puc_buffer[index], MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) {
        return;
    }
    index += MAC_OUI_LEN;
    /* OUI Type */
    puc_buffer[index++] = MAC_OUITYPE_WMM;
    /* OUI Subtype */
    puc_buffer[index++] = MAC_OUISUBTYPE_WMM_PARAM;
    /* Version field */
    puc_buffer[index++] = MAC_OUI_WMM_VERSION;
    /* QoS Information Field */
    mac_set_qos_info_field(mac_vap, &puc_buffer[index]);
    index += MAC_QOS_INFO_LEN;
    /* Reserved */
    puc_buffer[index++] = 0;
    /* Set the AC_BE, AC_BK, AC_VI, AC_VO Parameter Record fields */
    mac_set_wmm_ac_params(mac_vap, &puc_buffer[index], WLAN_WME_AC_BE);
    index += MAC_AC_PARAM_LEN;
    mac_set_wmm_ac_params(mac_vap, &puc_buffer[index], WLAN_WME_AC_BK);
    index += MAC_AC_PARAM_LEN;
    mac_set_wmm_ac_params(mac_vap, &puc_buffer[index], WLAN_WME_AC_VI);
    index += MAC_AC_PARAM_LEN;
    mac_set_wmm_ac_params(mac_vap, &puc_buffer[index], WLAN_WME_AC_VO);
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_WMM_PARAM_LEN;
}

/*****************************************************************************
 ��������  : ���extended supported rates��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_exsup_rates_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru     *mac_vap   = (mac_vap_stru *)vap;
    mac_rateset_stru *rates_set = HI_NULL;
    hi_u8         nrates;
    hi_u8         idx;

    rates_set = &(mac_vap->curr_sup_rates.rate);
    /***************************************************************************
                   -----------------------------------------------
                   |ElementID | Length | Extended Supported Rates|
                   -----------------------------------------------
       Octets:     |1         | 1      | 1-255                   |
                   -----------------------------------------------
    ***************************************************************************/
    if (rates_set->rs_nrates <= MAC_MAX_SUPRATES) {
        *puc_ie_len = 0;
        return;
    }
    puc_buffer[0] = MAC_EID_XRATES;
    nrates     = rates_set->rs_nrates - MAC_MAX_SUPRATES;
    puc_buffer[1] = nrates;
    for (idx = 0; idx < nrates; idx++) {
        puc_buffer[MAC_IE_HDR_LEN + idx] = rates_set->ast_rs_rates[idx + MAC_MAX_SUPRATES].mac_rate;
    }
    *puc_ie_len = MAC_IE_HDR_LEN + nrates;
}

/*****************************************************************************
 ��������  : ��дht capabilities info��
 �������  : pst_vap :ָ��vap
             puc_buffer :ָ��buffer
 �޸���ʷ      :
  1.��    ��   : 2013��4��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_ht_capinfo_field(hi_void *vap, hi_u8 *puc_buffer)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    mac_frame_ht_cap_stru *ht_capinfo = (mac_frame_ht_cap_stru *)puc_buffer;
    /*********************** HT Capabilities Info field*************************
    ----------------------------------------------------------------------------
     |-------------------------------------------------------------------|
     | LDPC   | Supp    | SM    | Green- | Short  | Short  |  Tx  |  Rx  |
     | Coding | Channel | Power | field  | GI for | GI for | STBC | STBC |
     | Cap    | Wth Set | Save  |        | 20 MHz | 40 MHz |      |      |
     |-------------------------------------------------------------------|
     |   B0   |    B1   |B2   B3|   B4   |   B5   |    B6  |  B7  |B8  B9|
     |-------------------------------------------------------------------|
     |-------------------------------------------------------------------|
     |    HT     |  Max   | DSS/CCK | Reserved | 40 MHz     | L-SIG TXOP |
     |  Delayed  | AMSDU  | Mode in |          | Intolerant | Protection |
     | Block-Ack | Length | 40MHz   |          |            | Support    |
     |-------------------------------------------------------------------|
     |    B10    |   B11  |   B12   |   B13    |    B14     |    B15     |
     |-------------------------------------------------------------------|
    ***************************************************************************/
    /* ��ʼ��0 */
    puc_buffer[0] = 0;
    puc_buffer[1] = 0;
    ht_capinfo->ldpc_coding_cap = mac_vap->mib_info->phy_ht.dot11_ldpc_coding_option_implemented;
    /* ������֧�ֵ��ŵ���ȼ�"��0:��20MHz����; 1:20MHz��40MHz���� */
    ht_capinfo->supported_channel_width = mac_mib_get_forty_mhz_operation_implemented(mac_vap);
    ht_capinfo->sm_power_save = MAC_SMPS_MIMO_MODE;
    ht_capinfo->ht_green_field = 0;
    ht_capinfo->short_gi_20mhz = mac_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented;
    ht_capinfo->short_gi_40mhz = mac_mib_get_shortgi_option_in_forty_implemented(mac_vap);
    ht_capinfo->tx_stbc = mac_vap->mib_info->phy_ht.dot11_tx_stbc_option_implemented;
    ht_capinfo->rx_stbc =
        (HI_TRUE == mac_vap->mib_info->phy_ht.dot11_rx_stbc_option_implemented) ? 1 : 0;
    ht_capinfo->ht_delayed_block_ack =
        mac_vap->mib_info->wlan_mib_sta_config.dot11_delayed_block_ack_option_implemented;
    ht_capinfo->max_amsdu_length = 0;   /* 0��ʾ���amsdu����Ϊ3839bytes */
    /* 1131Hֻ֧��2.4g 20M ����ΪĬ��ֵ */
    ht_capinfo->dsss_cck_mode_40mhz = 0;
    ht_capinfo->forty_mhz_intolerant = mac_mib_get_forty_mhz_intolerant(mac_vap);
    ht_capinfo->lsig_txop_protection = HI_TRUE;
}

/*****************************************************************************
 ��������  : ���ht a-mpdu parameters����Ϣ
 �������  : pst_vap :ָ��vap
             puc_buffer :ָ��buffer
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_ampdu_params_field(hi_u8 *puc_buffer)
{
    mac_ampdu_params_stru *ampdu_params  = (mac_ampdu_params_stru *)puc_buffer;

     /******************** AMPDU Parameters Field ******************************
      |-----------------------------------------------------------------------|
      | Maximum AMPDU Length Exponent | Minimum MPDU Start Spacing | Reserved |
      |-----------------------------------------------------------------------|
      | B0                         B1 | B2                      B4 | B5     B7|
      |-----------------------------------------------------------------------|
     **************************************************************************/
    /* ��ʼ��0 */
    puc_buffer[0] = 0;
    if (frw_get_offload_mode()) {
        ampdu_params->max_ampdu_len_exponent = 2; /* IPC �����յ�ampdu���� 32k=(2^(13+2))-1 */
    } else {
        /* IOT 31H����PACKET B��С,�����յ�ampdu���� 8k=(2^(13))-1 */
        ampdu_params->max_ampdu_len_exponent = 0;
    }
    ampdu_params->min_mpdu_start_spacing = 5; /* AMPDU������mpdu����С���,ȡֵ5(= 4ms) */
}

/*****************************************************************************
 ��������  : ���supported mcs set����Ϣ
 �������  : pst_vap :ָ��vap
             puc_buffer :ָ��buffer
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_sup_mcs_set_field(hi_void *vap, hi_u8 *puc_buffer)
{
    mac_vap_stru *mac_vap              = (mac_vap_stru *)vap;
    mac_sup_mcs_set_stru *sup_mcs_set  = (mac_sup_mcs_set_stru *)puc_buffer;

    /************************* Supported MCS Set Field **********************
    |-------------------------------------------------------------------|
    | Rx MCS Bitmask | Reserved | Rx Highest    | Reserved |  Tx MCS    |
    |                |          | Supp Data Rate|          |Set Defined |
    |-------------------------------------------------------------------|
    | B0         B76 | B77  B79 | B80       B89 | B90  B95 |    B96     |
    |-------------------------------------------------------------------|
    | Tx Rx MCS Set  | Tx Max Number     |   Tx Unequal     | Reserved  |
    |  Not Equal     | Spat Stream Supp  | Modulation Supp  |           |
    |-------------------------------------------------------------------|
    |      B97       | B98           B99 |       B100       | B101 B127 |
    |-------------------------------------------------------------------|
    *************************************************************************/
    /* ��ʼ���� */
    if (memset_s(puc_buffer, sizeof(mac_sup_mcs_set_stru), 0, sizeof(mac_sup_mcs_set_stru)) != EOK) {
        return;
    }
    if (memcpy_s(sup_mcs_set->auc_rx_mcs, sizeof(sup_mcs_set->auc_rx_mcs),
                 mac_vap->mib_info->supported_mcsrx.auc_dot11_supported_mcs_rx_value,
                 WLAN_HT_MCS_BITMASK_LEN) != EOK) {
        return;
    }
    sup_mcs_set->rx_highest_rate = MAC_MAX_RATE_SINGLE_NSS_20M_11N;
    sup_mcs_set->tx_mcs_set_def = 1;
    /* reserveλ��0 */
    sup_mcs_set->resv1 = 0;
    sup_mcs_set->resv2 = 0;
}

/*****************************************************************************
 �� �� ��  : mac_set_ht_extcap_field
 ��������  : ���ht extended capabilities field��Ϣ
 �������  : pst_vap :ָ��vap
             puc_buffer :ָ��buffer
 �޸���ʷ      :
  1.��    ��   : 2013��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT static hi_void mac_set_ht_extcap_field(hi_u8 *puc_buffer)
{
    mac_ext_cap_stru *ext_cap  = (mac_ext_cap_stru *)puc_buffer;

    /***************** HT Extended Capabilities Field **********************
      |-----------------------------------------------------------------|
      | PCO | PCO Trans | Reserved | MCS  |  +HTC   |  RD    | Reserved |
      |     |   Time    |          | Fdbk | Support | Resp   |          |
      |-----------------------------------------------------------------|
      | B0  | B1     B2 | B3    B7 | B8 B9|   B10   |  B11   | B12  B15 |
      |-----------------------------------------------------------------|
    ***********************************************************************/
    /* ��ʼ��0 */
    puc_buffer[0] = 0;
    puc_buffer[1] = 0;
    ext_cap->mcs_fdbk = (hi_u16)WLAN_MIB_MCS_FEEDBACK_OPT_IMPLT_NONE;
    ext_cap->htc_sup = HI_FALSE;
    ext_cap->rd_resp = HI_FALSE;
}


/*****************************************************************************
 ��������  : ���ht capabilities��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_ht_capabilities_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru *mac_vap        = (mac_vap_stru *)vap;

    if (!mac_vap->mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented) {
        *puc_ie_len = 0;
        return;
    }
    /***************************************************************************
    -------------------------------------------------------------------------
    |EID |Length |HT Capa. Info |A-MPDU Parameters |Supported MCS Set|
    -------------------------------------------------------------------------
    |1   |1      |2             |1                 |16               |
    -------------------------------------------------------------------------
    |HT Extended Cap. |Transmit Beamforming Cap. |ASEL Cap.          |
    -------------------------------------------------------------------------
    |2                |4                         |1                  |
    -------------------------------------------------------------------------
    ***************************************************************************/
    *puc_buffer       = MAC_EID_HT_CAP;
    *(puc_buffer + 1) = MAC_HT_CAP_LEN;
    puc_buffer += MAC_IE_HDR_LEN;
    /* ���ht capabilities information����Ϣ */
    mac_set_ht_capinfo_field(vap, puc_buffer);
    puc_buffer += MAC_HT_CAPINFO_LEN;
    /* ���A-MPDU parameters����Ϣ */
    mac_set_ampdu_params_field(puc_buffer);
    puc_buffer += MAC_HT_AMPDU_PARAMS_LEN;
    /* ���supported MCS set����Ϣ */
    mac_set_sup_mcs_set_field(vap, puc_buffer);
    puc_buffer += MAC_HT_SUP_MCS_SET_LEN;
    /* ���ht extended capabilities����Ϣ */
    mac_set_ht_extcap_field(puc_buffer);
    puc_buffer += MAC_HT_EXT_CAP_LEN;
    /* ��� transmit beamforming capabilities����Ϣ */
    mac_set_txbf_cap_field(puc_buffer);
    puc_buffer += MAC_HT_TXBF_CAP_LEN;
    /* ���asel(antenna selection) capabilities����Ϣ */
    mac_set_asel_cap_field(puc_buffer);
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_HT_CAP_LEN;
}

/*****************************************************************************
 ��������  : ���ht operation��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_ht_opern_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru        *mac_vap     = (mac_vap_stru *)vap;
    mac_ht_opern_stru   *ht_opern = HI_NULL;
    hi_u8           obss_non_ht = 0;

    if (!mac_mib_get_high_throughput_option_implemented(mac_vap)) {
        *puc_ie_len = 0;
        return;
    }
    /***************************************************************************
      ----------------------------------------------------------------------
      |EID |Length |PrimaryChannel |HT Operation Information |Basic MCS Set|
      ----------------------------------------------------------------------
      |1   |1      |1              |5                        |16           |
      ----------------------------------------------------------------------
    ***************************************************************************/
    /************************ HT Information Field ****************************
     |--------------------------------------------------------------------|
     | Primary | Seconday  | STA Ch | RIFS |           reserved           |
     | Channel | Ch Offset | Width  | Mode |                              |
     |--------------------------------------------------------------------|
     |    1    | B0     B1 |   B2   |  B3  |    B4                     B7 |
     |--------------------------------------------------------------------|
     |----------------------------------------------------------------|
     |     HT     | Non-GF STAs | resv      | OBSS Non-HT  | Reserved |
     | Protection |   Present   |           | STAs Present |          |
     |----------------------------------------------------------------|
     | B0     B1  |     B2      |    B3     |     B4       | B5   B15 |
     |----------------------------------------------------------------|
     |-------------------------------------------------------------|
     | Reserved |  Dual  |  Dual CTS  | Seconday | LSIG TXOP Protn |
     |          | Beacon | Protection |  Beacon  | Full Support    |
     |-------------------------------------------------------------|
     | B0    B5 |   B6   |     B7     |     B8   |       B9        |
     |-------------------------------------------------------------|
     |---------------------------------------|
     |  PCO   |  PCO  | Reserved | Basic MCS |
     | Active | Phase |          |    Set    |
     |---------------------------------------|
     |  B10   |  B11  | B12  B15 |    16     |
     |---------------------------------------|
    **************************************************************************/
    *puc_buffer = MAC_EID_HT_OPERATION;
    *(puc_buffer + 1) = MAC_HT_OPERN_LEN;
    ht_opern = (mac_ht_opern_stru *)(puc_buffer + MAC_IE_HDR_LEN);
    /* ���ŵ���� */
    ht_opern->primary_channel = mac_vap->channel.chan_number;
    ht_opern->secondary_chan_offset = MAC_SCN;
    /* ����"STA�ŵ����"����BSS�����ŵ���� >= 40MHzʱ����Ҫ����field����Ϊ1 */
    ht_opern->sta_chan_width = (mac_vap->channel.en_bandwidth > WLAN_BAND_WIDTH_20M) ? 1 : 0;
    /* ָʾ�����������Ƿ�����ʹ�ü�С��֡��� */
    ht_opern->rifs_mode = mac_mib_get_rifs_mode(mac_vap);
    /* B4-B7���� */
    ht_opern->resv1 = 0;
    /* ָʾht����ı���Ҫ�� */
    ht_opern->ht_protection = mac_mib_get_ht_protection(mac_vap);
    /* Non-GF STAs */
    ht_opern->nongf_sta_present = mac_mib_get_non_gfentities_present(mac_vap);
    /* B3 resv */
    ht_opern->resv2 = 0;
    /* B4  obss_nonht_sta_present */
    if ((mac_vap->protection.obss_non_ht_present != 0) ||
         (mac_vap->protection.sta_non_ht_num != 0)) {
        obss_non_ht = 1;
    }
    ht_opern->obss_nonht_sta_present = obss_non_ht;
    /* B5-B15 ���� */
    ht_opern->resv3 = 0;
    ht_opern->resv4 = 0;
    /* B0-B5 ���� */
    ht_opern->resv5 = 0;
    /* B6  dual_beacon */
    ht_opern->dual_beacon = 0;
    /* Dual CTS protection */
    ht_opern->dual_cts_protection = 0;
    /* secondary_beacon: Set to 0 in a primary beacon */
    ht_opern->secondary_beacon = 0;
    /* BSS support L-SIG TXOP Protection */
    ht_opern->lsig_txop_protection_full_support = mac_mib_get_lsig_txop_full_protection_activated(mac_vap);
    /* PCO active */
    ht_opern->pco_active = 0;
    /* PCO phase */
    ht_opern->pco_phase = 0;
    /* B12-B15  ���� */
    ht_opern->resv6 = 0;
    /* Basic MCS Set: set all bit zero,Indicates the MCS values that are supported by all HT STAs in the BSS. */
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(ht_opern->auc_basic_mcs_set, MAC_HT_BASIC_MCS_SET_LEN, 0, MAC_HT_BASIC_MCS_SET_LEN);
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_HT_OPERN_LEN;
}

/*****************************************************************************
 ��������  : ���extended capabilities element��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_ext_capabilities_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru            *mac_vap = (mac_vap_stru *)vap;
    mac_ext_cap_ie_stru     *ext_cap = HI_NULL;

    if (!mac_mib_get_high_throughput_option_implemented(mac_vap)) {
        *puc_ie_len = 0;
        return;
    }
    /***************************************************************************
                         ----------------------------------
                         |Element ID |Length |Capabilities|
                         ----------------------------------
          Octets:        |1          |1      |n           |
                         ----------------------------------
    ------------------------------------------------------------------------------------------
    |  B0       | B1 | B2             | B3   | B4   |  B5  |  B6    |  B7   | ...|  B38    |   B39      |
    ----------------------------------------------------------------------------
    |20/40 coex |resv|extended channel| resv | PSMP | resv | S-PSMP | Event |    |TDLS Pro-  TDLS Channel
                                                                                             Switching
    |mgmt supp  |    |switching       |      |      |      |        |       | ...| hibited | Prohibited |
    --------------------------------------------------------------------------------------------
    ***************************************************************************/
    puc_buffer[0] = MAC_EID_EXT_CAPS;
    puc_buffer[1] = MAC_XCAPS_EX_LEN;
    /* ��ʼ���� */
    if (memset_s(puc_buffer + MAC_IE_HDR_LEN, sizeof(mac_ext_cap_ie_stru), 0, sizeof(mac_ext_cap_ie_stru)) != EOK) {
        return;
    }
    ext_cap = (mac_ext_cap_ie_stru *)(puc_buffer + MAC_IE_HDR_LEN);
    /* ����20/40 BSS Coexistence Management Support fieid */
    if ((HI_TRUE == mac_mib_get_2040bss_coexistence_management_support(mac_vap)) &&
        (WLAN_BAND_2G == mac_vap->channel.band)) {
        ext_cap->coexistence_mgmt = 1;
    }
    /* ����TDLS prohibited */
    ext_cap->tdls_prhibited =  mac_vap->cap_flag.tdls_prohibited;
    /* ����TDLS channel switch prohibited */
    ext_cap->tdls_channel_switch_prhibited = mac_vap->cap_flag.tdls_channel_switch_prohibited;
#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
    /* �����11ac վ�� ����OPMODE NOTIFY��־ */
    if (mac_mib_get_VHTOptionImplemented(mac_vap)) {
        ext_cap->operating_mode_notification = mac_mib_get_operating_mode_notification_implemented(mac_vap);
    }
#endif
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_XCAPS_EX_LEN;
}

/*****************************************************************************
 ��������  : ��ȡbeacon֡�е�ssid
 �������  : puc_beacon_body,               Beacon or probe rsp֡��
             hi_s32 l_frame_body_len,    ֡�峤��
 �������  : puc_ssid_len,                  ssid ����
 �� �� ֵ  : ָ��ssid
 �޸���ʷ      :
  1.��    ��   : 2013��6��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8* mac_get_ssid(hi_u8 *puc_beacon_body, hi_s32 l_frame_body_len, hi_u8 *puc_ssid_len)
{
    const hi_u8   *puc_ssid_ie = HI_NULL;
    hi_u16         us_offset =  MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* --------------------------------------------------------------------- */
    /* |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   | */
    /* --------------------------------------------------------------------- */
    /* |8         |2         |2       |2-34 |3-10     |3        |4-256     | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /***************************************************************************
                    ----------------------------
                    |Element ID | Length | SSID|
                    ----------------------------
           Octets:  |1          | 1      | 0~32|
                    ----------------------------
    ***************************************************************************/
    /* ssid�ĳ��ȳ�ʼ��ֵΪ0 */
    *puc_ssid_len = 0;
    /* ���beacon֡����probe rsp֡�ĳ��ȵĺϷ��� */
    if (l_frame_body_len <= us_offset) {
        oam_warning_log0(0, OAM_SF_ANY, "{mac_get_ssid:: the length of beacon/probe rsp frame body is invalid.}");
        return HI_NULL;
    }
    /* ����ssid��ie */
    puc_ssid_ie = mac_find_ie(MAC_EID_SSID, (puc_beacon_body + us_offset), (hi_u32)(l_frame_body_len - us_offset));
    if ((puc_ssid_ie != HI_NULL) && (puc_ssid_ie[1] < WLAN_SSID_MAX_LEN)) {
        /* ��ȡssid ie�ĳ��� */
        *puc_ssid_len = puc_ssid_ie[1];
        return (hi_u8 *)(puc_ssid_ie + MAC_IE_HDR_LEN);
    }
    return HI_NULL;
}

/*****************************************************************************
 ��������  : ����û�̬�·�����ϢԪ�ص�����֡��
 �������  : [1]vap
             [2]puc_buffer
             [3]puc_ie_len
             [4]type
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_add_app_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u16 *pus_ie_len,
                                     en_app_ie_type_uint8 type)
{
    mac_vap_stru    *mac_vap = HI_NULL;
    hi_u8           *puc_app_ie = HI_NULL;
    hi_u32           app_ie_len;

    mac_vap   = (mac_vap_stru *)vap;
    puc_app_ie    = mac_vap->ast_app_ie[type].puc_ie;
    app_ie_len = mac_vap->ast_app_ie[type].ie_len;
    if (app_ie_len == 0) {
        *pus_ie_len = 0;
        return;
    } else {
        if (memcpy_s(puc_buffer, app_ie_len, puc_app_ie, app_ie_len) != EOK) {
            return;
        }
        *pus_ie_len = (hi_u16)app_ie_len;
    }
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
/*****************************************************************************
 ��������  : ����mesh ssid ie
 �������  : pst_vap: ָ��vap
             puc_buffer : ָ��buffer
 �������  : puc_ie_len : element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2019��1��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_mesh_ssid_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len,
                                           hi_u8 is_mesh_req)
{
    hi_u8     ssid_len;
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;

    /***************************************************************************
                    ----------------------------
                    |Element ID | Length | SSID|
                    ----------------------------
           Octets:  |1          | 1      | 0~32|
                    ----------------------------
    ***************************************************************************/
    /* Mesh��Probe req�ڵ���Ϊ��Mesh �ڵ㣬�ظ��ǿ�SSID����ΪMesh�ڵ㣬�ظ���SSID */
    if (is_mesh_req == HI_TRUE) {
        /* ssid ie */
        *puc_buffer = MAC_EID_SSID;
        /* ssid len */
        *(puc_buffer + 1) = 0;
        *puc_ie_len = MAC_IE_HDR_LEN;
        return;
    } else {
        hi_u8 *puc_ssid = HI_NULL;
        *puc_buffer = MAC_EID_SSID;
        puc_ssid = mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_desired_ssid;
        ssid_len = (hi_u8)strlen((hi_char *)puc_ssid);   /* ������'\0' */
        *(puc_buffer + 1) = ssid_len;
        if (memcpy_s(puc_buffer + MAC_IE_HDR_LEN, ssid_len, puc_ssid, ssid_len) != EOK) {
            return;
        }
        *puc_ie_len = ssid_len + MAC_IE_HDR_LEN;
        return;
    }
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM

/*****************************************************************************
 ��������  : ���mesh��ص�Vendor Specific IE�ֶ���ͷ����Ϣ
 �������  : [1]puc_buffer
 �������  : [1]puc_len
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_mesh_vendor_ie_hdr(hi_u8 *puc_buffer, hi_u8 *puc_len)
{
    mac_ieee80211_vendor_ie_stru *vendor_ie = HI_NULL;
    hi_u8  auc_oui[MAC_OUI_LEN] = {(hi_u8)MAC_WLAN_OUI_HUAWEI0, (hi_u8)MAC_WLAN_OUI_HUAWEI1,
                                   (hi_u8)MAC_WLAN_OUI_HUAWEI2};

    vendor_ie = (mac_ieee80211_vendor_ie_stru *)puc_buffer;
    vendor_ie->element_id = MAC_EID_VENDOR;
    vendor_ie->len = sizeof(mac_ieee80211_vendor_ie_stru) - MAC_IE_HDR_LEN;
    if (memcpy_s(vendor_ie->auc_oui, MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) {
        puc_len = 0;
        return;
    }
    vendor_ie->oui_type = MAC_OUITYPE_MESH;
    *puc_len = sizeof(mac_ieee80211_vendor_ie_stru);
}

#endif

/*****************************************************************************
 ��������  : ���meshid�ֶ�(Hi1131Hmesh ����meshidЯ����˽���ֶ�)
 �������  : [1]vap
             [2]puc_buffer
 �������  : [3]puc_ie_len
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_meshid_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    hi_u8 mesh_vendor_ie_hdr_len = 0;
    hi_u8 meshid_len;

    meshid_len = (hi_u8)strlen((const hi_char *)mac_vap->mib_info->wlan_mib_mesh_sta_cfg.auc_dot11_mesh_id);

    /* Vendor Spec |Length| OUI|TYPE|SUBTYPE|MESHID LEN|MESHID|
           1                |1        |3    |1     |1           |  1               |Var       | */
    mac_set_mesh_vendor_ie_hdr(puc_buffer, &mesh_vendor_ie_hdr_len);
    *(puc_buffer + mesh_vendor_ie_hdr_len) = MAC_OUISUBTYPE_MESH_HISI_MESHID;
    *(puc_buffer + mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN) = meshid_len;
    if (memcpy_s(puc_buffer + mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN + 1, meshid_len,
                 mac_vap->mib_info->wlan_mib_mesh_sta_cfg.auc_dot11_mesh_id, meshid_len) != EOK) {
        return;
    }

    /* ����Element ���� */
    *(puc_buffer + 1) += MAC_OUISUBTYPE_LEN + 1 + meshid_len;
    *(puc_ie_len) = mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN + 1 + meshid_len;

    return;
}

/*****************************************************************************
 ��������  : ���Mesh Formation Info����Ϣ
 �������  : [1]vap
             [2]puc_buffer
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_mesh_formation_info_field(hi_void *vap, hi_u8 *puc_buffer)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    mesh_formation_info_stru *mesh_formation_info = (mesh_formation_info_stru *)puc_buffer;
    /************ mesh formation info field******************
    --------------------------------------------------
    |Connected to Mesh Gate |Number of Peerings|Connected to AS|
    --------------------------------------------------
    |BIT0                                |BIT1-BIT6             |BIT7                   |
    --------------------------------------------------
    **************************************************/
    /* ��ʼ���� */
    if (memset_s(puc_buffer, sizeof(mesh_formation_info_stru), 0, sizeof(mesh_formation_info_stru)) != EOK) {
        return;
    }
    mesh_formation_info->connected_to_mesh_gate = 0;
    mesh_formation_info->number_of_peerings = mac_vap->user_nums;
    mesh_formation_info->connected_to_as = 0;
}

/*****************************************************************************
 ��������  : ���Mesh Capability����Ϣ
 �������  : [1]vap
             [2]puc_buffer
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_mesh_capability_field(hi_void *vap, hi_u8 *puc_buffer)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    mesh_capability_stru *mesh_capability = (mesh_capability_stru *)puc_buffer;
    /************ mesh capability field*********************************
    -------------------------------------------------------------
    |Accepting Additional Mesh Peering|MCCA Supported|MCCA Enabled|Forwarding|
    -------------------------------------------------------------
    |BIT0                                           |BIT1                   |BIT2              |BIT3          |
    -------------------------------------------------------------
    |MBCA Enabled|TBTT Adjusting|Mesh Power Save Level|Reserved|
    |BIT4               |BIT5               |BIT6                           |BIT7         |
    -------------------------------------------------------------
    **************************************************************/
    /* ��ʼ���� */
    if (memset_s(mesh_capability, sizeof(mesh_capability_stru), 0, sizeof(mesh_capability_stru)) != EOK) {
        return;
    }
    mesh_capability->accepting_add_mesh_peerings =
        mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_accepting_additional_peerings;
    mesh_capability->mbca_enabled = mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mbca_activated;
    mesh_capability->tbtt_adjusting = mac_vap->mesh_tbtt_adjusting;
}

/*****************************************************************************
 ��������  : ���mesh configuration�ֶ�
 �������  : [1]vap
             [2]puc_buffer
 �������  : [1]puc_ie_len
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_mesh_configuration_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;

    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        *puc_ie_len = 0;
        return;
    }

    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_mesh_activated != HI_TRUE) {
        *puc_ie_len = 0;
        return;
    }

    /*********************** Mesh Configuration Element*************************
    -------------------------------------------------------------------------
    |EID |Length |Active Path Selection Protocol Id |Active Path Selection Metric Id |Congestion Control Mode Id|
    -------------------------------------------------------------------------
    |1   |1      |1                                 |1                               |1                         |
    -------------------------------------------------------------------------
    |Sync Method ID |Auth Protocol ID |Mesh Formation Info|Mesh Capability|
    -------------------------------------------------------------------------
    |1              |1                |1                  |1              |
    -------------------------------------------------------------------------
    ***************************************************************************/
    *puc_buffer = MAC_EID_MESH_CONF;
    *(puc_buffer + 1) = MAC_MESH_CONF_LEN;

    puc_buffer += MAC_IE_HDR_LEN;

    /* ���Active Path Selection Protocol Id����Ϣ */
    *puc_buffer = MAC_MIB_MESH_VENDOR_SPECIFIC;    /* Vendor Specific */
    /* ���Active Path Selection Metric Id����Ϣ */
    *(puc_buffer + 1) = MAC_MIB_MESH_VENDOR_SPECIFIC;    /* Vendor Specific: byte 1 */
    /* ���Congestion Control Mode Id����Ϣ */
    *(puc_buffer + 2) = 0;    /* Not activated: byte 2 */
    /* ���Sync Method ID����Ϣ */
    *(puc_buffer + 3) = MAC_MIB_MESH_VENDOR_SPECIFIC;    /* Neighbor offset synchronization Method: byte 3 */
    /* ���Auth Protocol ID����Ϣ */
    *(puc_buffer + 4) =    /* SAE(1): byte 4 */
        mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol;
    puc_buffer += 5; /* Active Path Selection Protocol Id�򳤶�Ϊ5 byte */

    /* ���Mesh Formation Info����Ϣ */
    mac_set_mesh_formation_info_field(vap, puc_buffer);
    puc_buffer += MAC_MESH_FORMATION_LEN;
    /* ���Mesh Capability Field ����Ϣ */
    mac_set_mesh_capability_field(vap, puc_buffer);
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_MESH_CONF_LEN;

    return;
}

/*****************************************************************************
 ��������  : ���HISI Mesh Optimization����Ϣ
 �������  : [1]pst_vap
             [2]puc_buffer
 �������  : [1]puc_ie_len
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_hisi_mesh_optimization_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    hi_u8 mesh_vendor_ie_hdr_len = 0;
    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        *puc_ie_len = 0;
        return;
    }
    /* Mesh Optimization: Node Priority, En is MBR, Mesh Accept Sta */
    mac_set_mesh_vendor_ie_hdr(puc_buffer, &mesh_vendor_ie_hdr_len);
    *(puc_buffer + mesh_vendor_ie_hdr_len) = MAC_OUISUBTYPE_MESH_HISI_OPTIMIZATION;
    *(puc_buffer + mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN) = mac_vap->priority;
    *(puc_buffer + mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN + 1) = mac_vap->is_mbr;
    *(puc_buffer + mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN + 2) = /* accept_sta��־,��IEͷ����Ϣ���byte(1+2)λ��д */
        mac_vap->mesh_accept_sta;

    /* ����Element ���� */
    *(puc_buffer + 1) += MAC_MESH_HISI_OPTIMIZATION_LEN + MAC_OUISUBTYPE_LEN;
    *(puc_ie_len) = mesh_vendor_ie_hdr_len + MAC_OUISUBTYPE_LEN + MAC_MESH_HISI_OPTIMIZATION_LEN;
    return;
}

/*****************************************************************************
 ��������  : ���HISI Mesh Vendor�ֶ�(Subtype)
 �������  : [1]puc_buffer
             [2]subtype
 �������  : [1]puc_ie_len
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_mesh_vendor_subtype(hi_u8 *puc_buffer,
                                                  hi_u8 subtype,
                                                  hi_u8 *puc_ie_len)
{
    hi_u8 mesh_vendor_ie_hdr_len = 0;

    mac_set_mesh_vendor_ie_hdr(puc_buffer, &mesh_vendor_ie_hdr_len);
    *(puc_buffer + mesh_vendor_ie_hdr_len) = subtype;
    mesh_vendor_ie_hdr_len += MAC_OUISUBTYPE_LEN;
    *(puc_ie_len) = mesh_vendor_ie_hdr_len;
    /* ����IE ���� */
    *(puc_buffer + 1) += MAC_OUISUBTYPE_LEN;
}
#endif

/*****************************************************************************
 ��������  : ���DS������
 �������  : [1]vap
             [2]us_frm_type
             [3]puc_buffer
 �������  : [1]puc_ie_len
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_dsss_params(hi_void *vap, hi_u16 us_frm_type,
                                          hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru    *mac_vap     = (mac_vap_stru *)vap;
    hi_u8            chan_num;
    mac_device_stru *mac_dev = HI_NULL;
#ifndef _PRE_WLAN_FEATURE_MESH_ROM
    hi_unref_param(us_frm_type);
#endif
    /***************************************************************************
                        ----------------------------------------
                        | Element ID  | Length |Current Channel|
                        ----------------------------------------
              Octets:   | 1           | 1      | 1             |
                        ----------------------------------------
    The DSSS Parameter Set element contains information to allow channel number identification for STAs.
    ***************************************************************************/
    mac_dev = mac_res_get_dev();
    chan_num = mac_vap->channel.chan_number;
    if ((is_sta(mac_vap)
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
        || ((mac_vap->vap_mode == WLAN_VAP_MODE_MESH) &&
        (us_frm_type == WLAN_FC0_SUBTYPE_PROBE_REQ))
#endif
        ) && (mac_dev->curr_scan_state == MAC_SCAN_STATE_RUNNING)) {
        chan_num = mac_dev->scan_params.ast_channel_list[mac_dev->scan_chan_idx].chan_number;
    }
    puc_buffer[0] = MAC_EID_DSPARMS;
    puc_buffer[1] = MAC_DSPARMS_LEN;
    puc_buffer[2] = chan_num; /* DS������ byte 2 ָʾΪ�ŵ����� */
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_DSPARMS_LEN;
}

/*****************************************************************************
 ��������  : ���Country��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_country_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru                *mac_vap = (mac_vap_stru *)vap;
    mac_regdomain_info_stru     *rd_info = HI_NULL;
    hi_u8                    band;
    hi_u8                    index;
    hi_u8                    len = 0;

    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_multi_domain_capability_activated != HI_TRUE
        && mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_required != HI_TRUE
        && mac_vap->mib_info->wlan_mib_sta_config.dot11_radio_measurement_activated != HI_TRUE) {
        /* û��ʹ�ܹ�����ie */
        *puc_ie_len = 0;
        return;
    }
    /***************************************************************************
                               |....These three fields are repeated...|
    -------------------------------------------------------------------------------
    |EID | Len | CountryString | First Channel |Number of |Maximum    | Pad       |
    |    |     |               |   Number/     |Channels/ |Transmit   |(if needed)|
    |    |     |               |   Operating   | Operating|Power Level|           |
    |    |     |               |   Extension   | Class    |/Coverage  |           |
    |    |     |               |   Identifier  |          |Class      |           |
    -------------------------------------------------------------------------------
    |1   |1    |3              |1              |1         |1          |0 or 1     |
    -------------------------------------------------------------------------------
    ***************************************************************************/
    /* ��ȡ��������Ϣ */
    rd_info = mac_get_regdomain_info();
    /* ��ȡ��ǰ����Ƶ�� */
    band = mac_vap->channel.band;
    /* ��дEID, ��������� */
    puc_buffer[0] = MAC_EID_COUNTRY;
    /* ��ʼ����дbuffer��λ�� */
    index = MAC_IE_HDR_LEN;
    /* ������ */
    puc_buffer[index++] = (hi_u8)(rd_info->ac_country[0]);
    puc_buffer[index++] = (hi_u8)(rd_info->ac_country[1]);
    puc_buffer[index++] = ' ';     /* 0��ʾ��������涨��ͬ */
    if (WLAN_BAND_2G == band) {
        mac_set_country_ie_2g(rd_info, &(puc_buffer[index]), &len);
    }

    if (len == 0) {
        /* �޹��������� */
        *puc_ie_len = 0;
        return;
    }
    index += len;
    /* ����ܳ���Ϊ��������1�ֽ�pad */
    if (index & BIT0) {
        puc_buffer[index] = 0;
        index += 1;
    }
    /* ������ϢԪ�س��� */
    puc_buffer[1] = index - MAC_IE_HDR_LEN;
    *puc_ie_len = index;
}

/*****************************************************************************
 ��������  : ���power constraint��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_pwrconstraint_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;

    /***************************************************************************
                   -------------------------------------------
                   |ElementID | Length | LocalPowerConstraint|
                   -------------------------------------------
       Octets:     |1         | 1      | 1                   |
                   -------------------------------------------

    ����վ�����������������书�ʣ�����ϢԪ�ؼ�¼�涨���ֵ
    ��ȥʵ��ʹ��ʱ�����ֵ
    ***************************************************************************/
    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_required == HI_FALSE) {
        *puc_ie_len = 0;
        return;
    }
    *puc_buffer       = MAC_EID_PWRCNSTR;
    *(puc_buffer + 1) = MAC_PWR_CONSTRAINT_LEN;
    /* Note that this field is always set to 0 currently. Ideally            */
    /* this field can be updated by having an algorithm to decide transmit   */
    /* power to be used in the BSS by the AP.                                */
    *(puc_buffer + MAC_IE_HDR_LEN) = 0;
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_PWR_CONSTRAINT_LEN;
}

/*****************************************************************************
 ��������  : ���quiet��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
             uc_qcount  : Quiet Count
             uc_qperiod : Quiet Period
             us_qdur    : Quiet Duration
             us_qoffset : Quiet Offset
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_quiet_ie(hi_void *vap, hi_u8 *puc_buffer,
    const mac_set_quiet_ie_info_stru *mac_set_quiet_ie_info, hi_u8 *puc_ie_len)
{
    mac_quiet_ie_stru *quiet   = HI_NULL;
    mac_vap_stru      *mac_vap = (mac_vap_stru *)vap;
    if ((mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_required != HI_TRUE)
        && (mac_vap->mib_info->wlan_mib_sta_config.dot11_radio_measurement_activated != HI_TRUE)) {
        *puc_ie_len = 0;
        return;
    }
    /***************************************************************************
    -----------------------------------------------------------------------------
    |ElementID | Length | QuietCount | QuietPeriod | QuietDuration | QuietOffset|
    -----------------------------------------------------------------------------
    |1         | 1      | 1          | 1           | 2             | 2          |
    -----------------------------------------------------------------------------
    ***************************************************************************/
    if (mac_set_quiet_ie_info->us_qduration == 0 || mac_set_quiet_ie_info->qcount == 0) {
        *puc_ie_len = 0;
        return;
    }
    *puc_buffer = MAC_EID_QUIET;
    *(puc_buffer + 1) = MAC_QUIET_IE_LEN;
    quiet = (mac_quiet_ie_stru *)(puc_buffer + MAC_IE_HDR_LEN);
    quiet->quiet_count    = mac_set_quiet_ie_info->qcount;
    quiet->quiet_period   = mac_set_quiet_ie_info->qperiod;
    quiet->quiet_duration = oal_byteorder_to_le16(mac_set_quiet_ie_info->us_qduration);
    quiet->quiet_offset   = oal_byteorder_to_le16(mac_set_quiet_ie_info->us_qoffset);
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_QUIET_IE_LEN;
}

/*****************************************************************************
 ��������  : ���tpc report��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_tpc_report_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru *mac_vap = (mac_vap_stru *)vap;
    /***************************************************************************
                -------------------------------------------------
                |ElementID  |Length  |TransmitPower  |LinkMargin|
                -------------------------------------------------
       Octets:  |1          |1       |1              |1         |
                -------------------------------------------------

    TransimitPower, ��֡�Ĵ��͹��ʣ���dBmΪ��λ
    ***************************************************************************/
    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_required == HI_FALSE
        && mac_vap->mib_info->wlan_mib_sta_config.dot11_radio_measurement_activated == HI_FALSE) {
        *puc_ie_len = 0;
        return;
    }
    *puc_buffer       = MAC_EID_TPCREP;
    *(puc_buffer + 1) = MAC_TPCREP_IE_LEN;
    *(puc_buffer + 2) = mac_vap->tx_power; /* tpc report byte 2 �洢tx_power */
    *(puc_buffer + 3) = 0;                 /* tpc report byte 3 �ֶι���֡�в��� */
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_TPCREP_IE_LEN;
}

/*****************************************************************************
 ��������  : ���Quiet��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_erp_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru         *mac_vap    = (mac_vap_stru *)vap;
    mac_erp_params_stru  *erp_params = HI_NULL;
    /***************************************************************************
    --------------------------------------------------------------------------
    |EID  |Len  |NonERP_Present|Use_Protection|Barker_Preamble_Mode|Reserved|
    --------------------------------------------------------------------------
    |B0-B7|B0-B7|B0            |B1            |B2                  |B3-B7   |
    --------------------------------------------------------------------------
    ***************************************************************************/
    if (WLAN_LEGACY_11B_MODE == mac_vap->protocol) {
        *puc_ie_len = 0;
        return;     /* 5GƵ�κ�11bЭ��ģʽ û��erp��Ϣ */
    }
    *puc_buffer       = MAC_EID_ERP;
    *(puc_buffer + 1) = MAC_ERP_IE_LEN;
    *(puc_buffer + 2) = 0;  /* Quiet��Ϣbyte 2 ��ʼ��0 */
    erp_params = (mac_erp_params_stru *)(puc_buffer + MAC_IE_HDR_LEN);
    /* �������non erpվ����ap������ ����obss�д���non erpվ�� */
    if ((mac_vap->protection.sta_non_erp_num != 0) || (mac_vap->protection.obss_non_erp_present)) {
        erp_params->non_erp = 1;
    }
    /* ���ap�Ѿ�����erp���� */
    if (mac_vap->protection.protection_mode == WLAN_PROT_ERP) {
        erp_params->use_protection = 1;
    }
    /* ������ڲ�֧��short preamble��վ����ap������ ����ap����֧��short preamble */
    if ((mac_vap->protection.sta_no_short_preamble_num != 0)
        || (mac_mib_get_short_preamble_option_implemented(mac_vap) == HI_FALSE)) {
        erp_params->preamble_mode = 1;
    }
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_ERP_IE_LEN;
}

/*****************************************************************************
 ��������  : ���bss load��Ϣ
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_set_bssload_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_bss_load_stru  *bss_load = HI_NULL;
    mac_vap_stru       *mac_vap  = (mac_vap_stru *)vap;
    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented == HI_FALSE ||
        mac_vap->mib_info->wlan_mib_sta_config.dot11_qbss_load_implemented == HI_FALSE) {
        *puc_ie_len = 0;
        return;
    }
    /***************************************************************************
    ------------------------------------------------------------------------
    |EID |Len |StationCount |ChannelUtilization |AvailableAdmissionCapacity|
    ------------------------------------------------------------------------
    |1   |1   |2            |1                  |2                         |
    ------------------------------------------------------------------------
    ***************************************************************************/
    puc_buffer[0] = MAC_EID_QBSS_LOAD;
    puc_buffer[1] = MAC_BSS_LOAD_IE_LEN;
    bss_load = (mac_bss_load_stru *)(puc_buffer + MAC_IE_HDR_LEN);
    bss_load->us_sta_count = oal_byteorder_to_le16(mac_vap->user_nums);
    bss_load->chan_utilization = 0;
    bss_load->us_aac = 0;
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_BSS_LOAD_IE_LEN;
}

/*****************************************************************************
 ��������  : ����û�̬�·�����ϢԪ�ص�����֡��
 �������  : [1]vap
             [2]puc_buffer
             [3]puc_ie_len
             [4]type
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_add_wps_ie(hi_void *vap, hi_u8 *puc_buffer, hi_u16 *pus_ie_len,
                                     en_app_ie_type_uint8 type)
{
    mac_vap_stru    *mac_vap = HI_NULL;
    hi_u8           *puc_app_ie  = HI_NULL;
    hi_u8           *puc_wps_ie  = HI_NULL;
    hi_u32          app_ie_len;

    mac_vap   = (mac_vap_stru *)vap;
    puc_app_ie    = mac_vap->ast_app_ie[type].puc_ie;
    app_ie_len = mac_vap->ast_app_ie[type].ie_len;

    if (app_ie_len == 0) {
        *pus_ie_len = 0;
        return;
    }
    puc_wps_ie =
        mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_WLAN_OUI_TYPE_MICROSOFT_WPS, puc_app_ie, (hi_s32)app_ie_len);
    if ((puc_wps_ie == HI_NULL) || (puc_wps_ie[1] < MAC_MIN_WPS_IE_LEN)) {
        *pus_ie_len = 0;
        return;
    }
    /* ��WPS ie ��Ϣ������buffer �� */
    if (memcpy_s(puc_buffer, puc_wps_ie[1] + MAC_IE_HDR_LEN, puc_wps_ie, puc_wps_ie[1] + MAC_IE_HDR_LEN) != EOK) {
        oam_warning_log0(0, 0, "{mac_add_wps_ie::memcpy_s fail!}");
        *pus_ie_len = 0;
        return;
    }

    *pus_ie_len = puc_wps_ie[1] + MAC_IE_HDR_LEN;
}

/*****************************************************************************
 ��������  : ��װ����
 �������  : header��80211ͷ��ָ��
             us_fc frame control����
             puc_da: Ŀ��mac��ַ
             puc_sa: Դmac��ַ
*****************************************************************************/
WIFI_ROM_TEXT hi_void mac_null_data_encap(hi_u8* header, hi_u16 us_fc, const hi_u8 *da_mac_addr,
    const hi_u8 *sa_mac_addr)
{
    mac_hdr_set_frame_control(header, us_fc);
    /* ����ADDR1ΪDA|BSSID */
    if (memcpy_s((header + WLAN_HDR_ADDR1_OFFSET), WLAN_MAC_ADDR_LEN, da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_warning_log0(0, 0, "{mac_null_data_encap::memcpy_s fail!}");
        return;
    }
    /* ����ADDR2ΪBSSID|SA */
    if (memcpy_s((header + WLAN_HDR_ADDR2_OFFSET), WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_warning_log0(0, 0, "{mac_null_data_encap::memcpy_s fail!}");
        return;
    }
    if ((us_fc & WLAN_FRAME_FROME_AP) && !(us_fc & WLAN_FRAME_TO_AP)) {
        /* ����ADDR3ΪSA */
        if (memcpy_s((header + WLAN_HDR_ADDR3_OFFSET), WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_warning_log0(0, 0, "{mac_null_data_encap::memcpy_s fail!}");
            return;
        }
    } else if (!(us_fc & WLAN_FRAME_FROME_AP) && (us_fc & WLAN_FRAME_TO_AP)) {
        /* ����ADDR3ΪDA */
        if (memcpy_s((header + WLAN_HDR_ADDR3_OFFSET), WLAN_MAC_ADDR_LEN, da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_warning_log0(0, 0, "{mac_null_data_encap::memcpy_s fail!}");
            return;
        }
    }
    /* NULL֡����������DSλ ������ */
}

/*****************************************************************************
 ��������  : ��װaction֡ͷ
 �������  : header��80211ͷ��ָ��
             puc_da: Ŀ��mac��ַ
             puc_sa: Դmac��ַ
 �޸���ʷ      :
  1.��    ��   : 2019��03��08��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_prepare_action_frame_head(hi_u8* puc_header, const hi_u8 *da_mac_addr,
    const hi_u8 *sa_mac_addr)
{
    /* ֡�����ֶ�ȫΪ0������type��subtype */
    mac_hdr_set_frame_control(puc_header, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT | WLAN_FC0_SUBTYPE_ACTION);
    /* ���÷�Ƭ���Ϊ0 */
    mac_hdr_set_fragment_number(puc_header, 0);
    /* ���õ�ַ1��һ���ǹ㲥��ַ */
    if (memcpy_s(puc_header + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN, da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{mac_prepare_action_frame_head::mem safe func err!}");
        return HI_FAIL;
    }
    /* ���õ�ַ2Ϊ�Լ���MAC��ַ */
    if (memcpy_s(puc_header + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{mac_prepare_action_frame_head::mem safe func err!}");
        return HI_FAIL;
    }
    /* ��ַ3��ΪVAP�Լ���MAC��ַ */
    if (memcpy_s(puc_header + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{mac_prepare_action_frame_head::mem safe func err!}");
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��װaction֡��
 �޸���ʷ      :
  1.��    ��   : 2019��03��08��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_prepare_action_frame_body(hi_u8* puc_body, hi_u8 body_len, hi_u8 category,
                                                  const hi_u8 *puc_elements, hi_u8 element_len)
{
    if (body_len < (WLAN_ACTION_BODY_ELEMENT_OFFSET + element_len)) {
        return HI_FALSE;
    }

    /* category :127,��ʾ�ǳ����Զ���֡ */
    puc_body[WLAN_ACTION_BODY_CATEGORY_OFFSET] = category;
    /* ��ʼ��vendor OUI */
    puc_body[MAC_ACTION_OUI_POS]     = MAC_WLAN_OUI_HUAWEI0;
    puc_body[MAC_ACTION_OUI_POS + 1] = MAC_WLAN_OUI_HUAWEI1; /* vendor OUI byte(1+1)���� */
    puc_body[MAC_ACTION_OUI_POS + 2] = MAC_WLAN_OUI_HUAWEI2; /* vendor OUI byte(1+2)���� */
    /* ����action���ͺ������� */
    puc_body[MAC_ACTION_VENDOR_TYPE_POS] = MAC_OUITYPE_DBAC;
    puc_body[MAC_ACTION_VENDOR_SUBTYPE_POS] = MAC_OUISUBTYPE_DBAC_NOA;
    /* ����IE�ֶ� */
    if (0 != memcpy_s(puc_body + WLAN_ACTION_BODY_ELEMENT_OFFSET, body_len, puc_elements, element_len)) {
        return HI_FALSE;
    }

    return HI_TRUE;
}

/* ����ROM�ν���λ�� ����ROM���������SECTION�� */
#undef __WIFI_ROM_SECTION__

/*****************************************************************************
 ��������  : STA���ݹ����û���������Ϣ�����ù�������֡�е�cap info
 �������  : pst_vap      : ָ��vap
             puc_cap_info : ָ��洢����λ��Ϣ��buffer
 �޸���ʷ      :
  1.��    ��   : 2015��9��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void  mac_set_cap_info_sta(hi_void *vap, hi_u8 *puc_cap_info)
{
    mac_cap_info_stru   *cap_info = (mac_cap_info_stru *)puc_cap_info;
    mac_vap_stru        *mac_vap  = (mac_vap_stru *)vap;

    /**************************************************************************
         -------------------------------------------------------------------
         |B0 |B1  |B2        |B3    |B4     |B5      |B6  |B7     |B8      |
         -------------------------------------------------------------------
         |ESS|IBSS|CFPollable|CFPReq|Privacy|Preamble|PBCC|Agility|SpecMgmt|
         -------------------------------------------------------------------
         |B9 |B10      |B11 |B12     |B13      |B14        |B15            |
         -------------------------------------------------------------------
         |QoS|ShortSlot|APSD|RM      |DSSS-OFDM|Delayed BA |Immediate BA   |
         -------------------------------------------------------------------
    ***************************************************************************/
    /* ѧϰ�Զ˵�������Ϣ */
    if (memcpy_s(puc_cap_info, sizeof(mac_cap_info_stru), (hi_u8 *)(&mac_vap->us_assoc_user_cap_info),
                 sizeof(mac_cap_info_stru)) != EOK) {
        return;
    }
    /* ��������λ��ѧϰ������Ĭ��ֵ */
    cap_info->ibss              = 0;
    cap_info->cf_pollable       = 0;
    cap_info->cf_poll_request   = 0;
    cap_info->radio_measurement =
        mac_vap->mib_info->wlan_mib_sta_config.dot11_radio_measurement_activated;
}

#ifdef _PRE_WLAN_FEATURE_PMF
/*****************************************************************************
 ��������  : ����Timeout_Interval��ϢԪ��
 �������  : pst_mac_vap   : ָ��vap
             puc_buffer: ָ��buffer
             ul_type: Timeout_Interval������
             puc_sta_addr: ap���ʹ�Timeout_Interval��assoc rsp֡�е�DA
             puc_ie_len: ie���ܳ���
             pst_sa_query_info :��ASSOCIATION_COMEBACK_TIMEʱ��Ҫ��
 �޸���ʷ      :
  1.��    ��   : 2014��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_set_timeout_interval_ie(hi_u8 *puc_buffer, hi_u8 *puc_ie_len, hi_u32 type, hi_u32 timeout)
{
    mac_timeout_interval_type_enum tie_type;

    tie_type = (mac_timeout_interval_type_enum)type;
    *puc_ie_len = 0;
    /* �ж��Ƿ���Ҫ����timeout_interval IE */
    if (tie_type >= MAC_TIE_BUTT) {
        return;
    }
    /* Timeout Interval Parameter Element Format
    -----------------------------------------------------------------------
    |ElementID | Length | Timeout Interval Type| Timeout Interval Value  |
    -----------------------------------------------------------------------
    |1         | 1      | 1                    |  4                      |
    -----------------------------------------------------------------------*/
    puc_buffer[0] = MAC_EID_TIMEOUT_INTERVAL;
    puc_buffer[1] = MAC_TIMEOUT_INTERVAL_INFO_LEN;
    puc_buffer[2] = tie_type; /* Timeout_Interval byte2 Ϊtie_type */
    /* ����Timeout Interval Value */
    puc_buffer[3] = timeout & 0x000000FF;       /* Timeout_Interval byte3 Ϊtimeout���8byte */
    puc_buffer[4] = (timeout & 0x0000FF00)>>8;  /* Timeout_Interval byte4 Ϊtimeout��bit8 ~ 15 */
    puc_buffer[5] = (timeout & 0x00FF0000)>>16; /* Timeout_Interval byte5 Ϊtimeout��bit16 ~ 23 */
    puc_buffer[6] = (timeout & 0xFF000000)>>24; /* Timeout_Interval byte6 Ϊtimeout��bit24 ~ 31 */
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_TIMEOUT_INTERVAL_INFO_LEN;
}
#endif /* #ifdef HI_ON_FLASH */

/*****************************************************************************
 ��������  : ��RSN ie�л�ȡpmf������Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��2��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
wlan_pmf_cap_status_uint8 mac_get_pmf_cap(hi_u8 *puc_ie, hi_u32 ie_len)
{
    hi_u8  *puc_rsn_ie = HI_NULL;
    hi_u16  us_rsn_cap;

    if (oal_unlikely(puc_ie == HI_NULL)) {
        return MAC_PMF_DISABLED;
    }

    /* ����RSN��ϢԪ��,���û��RSN��ϢԪ��,���ղ�֧�ִ��� */
    puc_rsn_ie = mac_find_ie(MAC_EID_RSN, puc_ie, ie_len);
    /* ����RSN��ϢԪ��, �ж�RSN�����Ƿ�ƥ�� */
    us_rsn_cap = mac_get_rsn_capability(puc_rsn_ie);
    if ((us_rsn_cap & BIT6) && (us_rsn_cap & BIT7)) {
        return MAC_PME_REQUIRED;
    }
    if (us_rsn_cap & BIT7) {
        return MAC_PMF_ENABLED;
    }
    return MAC_PMF_DISABLED;
}

/*****************************************************************************
 ��������  : ��beacon֡�л��beacon period
 �޸���ʷ      :
  1.��    ��   : 2013��6��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 mac_get_beacon_period(const hi_u8 *puc_beacon_body)
{
    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* --------------------------------------------------------------------- */
    /* |Timestamp |BeaconInt |CapInfo |SSID |SupRates |DSParSet |TIM elm   | */
    /* --------------------------------------------------------------------- */
    /* |8         |2         |2       |2-34 |3-10     |3        |4-256     | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    return *((hi_u16 *)(puc_beacon_body + MAC_TIME_STAMP_LEN));
}

/*****************************************************************************
 ��������  : ��ȡdtim periodֵ
 �޸���ʷ      :
  1.��    ��   : 2013��10��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_get_dtim_period(hi_u8 *puc_frame_body, hi_u16 us_frame_body_len)
{
    hi_u8   *puc_ie = HI_NULL;
    hi_u16   us_offset;

    us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    if (us_frame_body_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_TIM, puc_frame_body + us_offset, us_frame_body_len - us_offset);
        if ((puc_ie != HI_NULL) && (puc_ie[1] >= MAC_MIN_TIM_LEN)) {
            return puc_ie[3]; /* byte 3 Ϊdtim periodֵ */
        }
    }
    return 0;
}

/*****************************************************************************
 ��������  : ��ȡdtim cntֵ
 �޸���ʷ      :
  1.��    ��   : 2013��10��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_get_dtim_cnt(hi_u8 *puc_frame_body, hi_u16 us_frame_body_len)
{
    hi_u8   *puc_ie = HI_NULL;
    hi_u16   us_offset;

    us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    if (us_frame_body_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_TIM, puc_frame_body + us_offset, us_frame_body_len - us_offset);
        if ((puc_ie != HI_NULL) && (puc_ie[1] >= MAC_MIN_TIM_LEN)) {
            return puc_ie[2]; /* byte 2 Ϊdtim cntֵ */
        }
    }
    return 0;
}

/*****************************************************************************
 ��������  : �ӹ���֡�л�ȡwmm ie
 �޸���ʷ      :
  1.��    ��   : 2013��6��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8* mac_get_wmm_ie(hi_u8 *puc_beacon_body, hi_u16 us_frame_len, hi_u16 us_offset)
{
    hi_u16 us_index = us_offset;

    /* Ѱ��TIM��ϢԪ�� */
    while (us_index < us_frame_len) {
        if (mac_is_wmm_ie(puc_beacon_body + us_index)) {
            return(&puc_beacon_body[us_index]);
        } else {
            us_index += (MAC_IE_HDR_LEN + puc_beacon_body[us_index + 1]);
        }
    }
    return HI_NULL;
}

/*****************************************************************************
 ��������  : ����rsn_ie��ȡrsn����
 �������  : [1]puc_rsn_ie
 �� �� ֵ  : ��
******************************************************************************/
hi_u16 mac_get_rsn_capability(const hi_u8 *puc_rsn_ie)
{
    hi_u16  us_pairwise_count;
    hi_u16  us_akm_count;
    hi_u16  us_rsn_capability;
    hi_u16  us_index               = 0;

    if (puc_rsn_ie == HI_NULL) {
        return 0;
    }
    /*************************************************************************/
    /*                  RSN Element Format                                   */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length | Version | Group Cipher Suite | Pairwise Cipher */
    /* --------------------------------------------------------------------- */
    /* |     1     |    1   |    2    |         4          |       2         */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Suite Count| Pairwise Cipher Suite List | AKM Suite Count | AKM Suite List */
    /* --------------------------------------------------------------------- */
    /*            |         4*m                |     2           |   4*n     */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |RSN Capabilities|PMKID Count|PMKID List|Group Management Cipher Suite */
    /* --------------------------------------------------------------------- */
    /* |        2       |    2      |   16 *s  |               4           | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    if (puc_rsn_ie[1] < MAC_MIN_RSN_LEN) {
        oam_warning_log1(0, OAM_SF_WPA, "{hmac_get_rsn_capability::invalid rsn ie len[%d].}", puc_rsn_ie[1]);
        return 0;
    }
    us_index += 8; /* ƫ��8 byte����ȡpairwise_count */
    us_pairwise_count = hi_makeu16(puc_rsn_ie[us_index], puc_rsn_ie[us_index + 1]);
    if (us_pairwise_count > MAC_PAIRWISE_CIPHER_SUITES_NUM) {
        oam_warning_log1(0, OAM_SF_WPA, "{hmac_get_rsn_capability::invalid us_pairwise_count[%d].}", us_pairwise_count);
        return 0;
    }
    us_index += 2 + 4 * (hi_u8)us_pairwise_count; /* ��ƫ��(2 + 4 * pairwise_count) byte����ȡakm_count */
    us_akm_count = hi_makeu16(puc_rsn_ie[us_index], puc_rsn_ie[us_index + 1]);
    if (us_akm_count > MAC_AUTHENTICATION_SUITE_NUM) {
        oam_warning_log1(0, OAM_SF_WPA, "{hmac_get_rsn_capability::invalid us_akm_count[%d].}", us_akm_count);
        return 0;
    }
    us_index += 2 + 4 * (hi_u8)us_akm_count; /* ��ƫ��(2 + 4 * akm_count) byte����ȡrsn_capability */
    us_rsn_capability = hi_makeu16(puc_rsn_ie[us_index], puc_rsn_ie[us_index + 1]);
    return us_rsn_capability;
}

/*****************************************************************************
 ��������  : ����power capability��ϢԪ��
 �������  : mac_vap_stru *pst_vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len
 �޸���ʷ      :
  1.��    ��   : 2013��6��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_set_power_cap_ie(hi_u8 *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_vap_stru            *mac_vap        = (mac_vap_stru *)vap;
    mac_regclass_info_stru  *regclass_info  = HI_NULL;

    /********************************************************************************************
            ------------------------------------------------------------------------------------
            |ElementID | Length | MinimumTransmitPowerCapability| MaximumTransmitPowerCapability|
            ------------------------------------------------------------------------------------
    Octets: |1         | 1      | 1                             | 1                             |
            -------------------------------------------------------------------------------------

    *********************************************************************************************/
    *puc_buffer       = MAC_EID_PWRCAP;
    *(puc_buffer + 1) = MAC_PWR_CAP_LEN;
    /* �ɹ���ȡ��������Ϣ����ݹ������TPC����������С���书�ʣ�����Ĭ��Ϊ0 */
    regclass_info = mac_get_channel_num_rc_info(mac_vap->channel.band, mac_vap->channel.chan_number);
    if (regclass_info != HI_NULL) {
        *(puc_buffer + 2) = /* puc_buffer��2 byte ��ʾ����书�� */
            (hi_u8)((mac_vap->channel.band == WLAN_BAND_2G) ? 4 : 3); /* 2G����������书��Ϊ4������Ϊ3 */
        *(puc_buffer + 3) = /* puc_buffer��3 byte ��ʾ��С���书�� */
            oal_min(regclass_info->max_reg_tx_pwr, regclass_info->max_tx_pwr);
    } else {
        *(puc_buffer + 2) = 0; /* δ��ȡ��������Ϣ, ��puc_buffer��2 byte(����书��)��Ϊ0 */
        *(puc_buffer + 3) = 0; /* δ��ȡ��������Ϣ, ��puc_buffer��3 byte(��С���书��)��Ϊ0 */
    }
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_PWR_CAP_LEN;
}

/*****************************************************************************
 ��������  : ����֧���ŵ���ϢԪ��
 �������  : [1]vap,
             [2]puc_buffer
             [3]puc_ie_len
 �� �� ֵ  : ��
*****************************************************************************/
hi_void mac_set_supported_channel_ie(hi_u8 *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    hi_u8            channel_max_num;
    hi_u8            channel_idx;
    hi_u8            us_channel_ie_len = 0;
    hi_u8           *puc_ie_len_buffer = 0;
    mac_vap_stru        *mac_vap       = (mac_vap_stru *)vap;
    hi_u8            channel_idx_cnt = 0;
    if (mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_required == HI_FALSE
        || mac_vap->mib_info->wlan_mib_sta_config.dot11_extended_channel_switch_activated == HI_TRUE) {
        *puc_ie_len = 0;
        return;
    }

    /********************************************************************************************
            ���Ȳ������ŵ������ŵ����ɶԳ���
            ------------------------------------------------------------------------------------
            |ElementID | Length | Fisrt Channel Number| Number of Channels|
            ------------------------------------------------------------------------------------
    Octets: |1         | 1      | 1                   | 1                 |
            -------------------------------------------------------------------------------------

    *********************************************************************************************/
    /* ����֧�ֵ�Ƶ�λ�ȡ����ŵ����� */
    if (WLAN_BAND_2G == mac_vap->channel.band) {
        channel_max_num = (hi_u8)MAC_CHANNEL_FREQ_2_BUTT;
    } else {
        *puc_ie_len = 0;
        return;
    }

    *puc_buffer = MAC_EID_SUPPCHAN;
    puc_buffer++;
    puc_ie_len_buffer = puc_buffer;
    /* ��д�ŵ���Ϣ */
    for (channel_idx = 0; channel_idx < channel_max_num; channel_idx++) {
        /* �޸Ĺ�����ṹ�����Ҫ���Ӹ��Ƿ�֧���źŵ��ж� */
        if (mac_is_channel_idx_valid(mac_vap->channel.band, channel_idx, HI_NULL) == HI_SUCCESS) {
            channel_idx_cnt++;
            /* uc_channel_idx_cntΪ1��ʱ���ʾ�ǵ�һ�������ŵ�����Ҫд��Fisrt Channel Number */
            if (channel_idx_cnt == 1) {
                puc_buffer++;
                mac_get_channel_num_from_idx(mac_vap->channel.band, channel_idx, puc_buffer);
            } else if ((channel_max_num - 1) == channel_idx) {
                /* ��Number of Channelsд��֡���� */
                puc_buffer++;
               *puc_buffer = channel_idx_cnt;
                us_channel_ie_len += 2; /* �ŵ�IE����ÿ������2 byte */
            }
        } else {
            /* uc_channel_idx_cnt��Ϊ0��ʱ���ʾ֮ǰ�п����ŵ�����Ҫ�������ŵ��ĳ���д��֡���� */
            if (channel_idx_cnt != 0) {
                /* ��Number of Channelsд��֡���� */
                puc_buffer++;
               *puc_buffer = channel_idx_cnt;
                us_channel_ie_len += 2; /* �ŵ�IE����ÿ������2 byte */
            }
            /* ��Number of Channelsͳ������ */
            channel_idx_cnt = 0;
        }
    }
    *puc_ie_len_buffer = us_channel_ie_len;
    *puc_ie_len = us_channel_ie_len + MAC_IE_HDR_LEN;
}

/*****************************************************************************
 ��������  : ����WMM info element
 �������  : mac_vap_stru  *pst_vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2013��10��23��
    ��    ��   : Hisilicon
    �޸�����   : �޸ĺ��������������
*****************************************************************************/
hi_void mac_set_wmm_ie_sta(hi_u8 *vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    hi_u8     index;
    mac_vap_stru  *mac_vap  = (mac_vap_stru *)vap;
    hi_u8     auc_oui[MAC_OUI_LEN] = {(hi_u8)MAC_WLAN_OUI_MICRO0,
                                      (hi_u8)MAC_WLAN_OUI_MICRO1, (hi_u8)MAC_WLAN_OUI_MICRO2};

    /* WMM Information Element Format                                */
    /* ------------------------------------------------------------- */
    /* | 3     | 1        | 1           | 1             | 1        | */
    /* ------------------------------------------------------------- */
    /* | OUI   | OUI Type | OUI Subtype | Version field | QoS Info | */
    /* ------------------------------------------------------------- */
    /* �ж�STA�Ƿ�֧��WMM */
    if (!mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented) {
        *puc_ie_len = 0;
        return;
    }

    puc_buffer[0]        = MAC_EID_WMM;
    puc_buffer[1]        = MAC_WMM_INFO_LEN;
    index             = MAC_IE_HDR_LEN;
    /* OUI */
    if (memcpy_s(&puc_buffer[index], MAC_OUI_LEN, auc_oui, MAC_OUI_LEN) != EOK) {
        return;
    }
    index += MAC_OUI_LEN;
    /* OUI Type */
    puc_buffer[index++] = MAC_OUITYPE_WMM;
    /* OUI Subtype */
    puc_buffer[index++] = MAC_OUISUBTYPE_WMM_INFO;
    /* Version field */
    puc_buffer[index++] = MAC_OUI_WMM_VERSION;
    /* QoS Information Field */
    mac_set_qos_info_field(mac_vap, &puc_buffer[index]);
    index += MAC_QOS_INFO_LEN;
    /* Reserved */
    puc_buffer[index++] = 0;
    *puc_ie_len = MAC_IE_HDR_LEN + MAC_WMM_INFO_LEN;
}

/*****************************************************************************
 ��������  : ����listen interval��ϢԪ��
 �������  : mac_vap_stru *pst_vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_set_listen_interval_ie(hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    puc_buffer[0] = 0x03;
    puc_buffer[1] = 0x00;
    *puc_ie_len   = MAC_LIS_INTERVAL_IE_LEN;
}

/*****************************************************************************
 ��������  : ����״̬����ϢԪ��
 �� �� ֵ  : hi_void
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_set_status_code_ie(hi_u8 *puc_buffer, mac_status_code_enum_uint16 status_code)
{
    puc_buffer[0] = (hi_u8)(status_code & 0x00FF);
    puc_buffer[1] = (hi_u8)((status_code & 0xFF00) >> 8); /* ״̬����ϢԪ��byte 1,��ֵΪstatus_code��8 byte */
}

/*****************************************************************************
 ��������  : ����AID��ɨ��ID����ϢԪ��
 �������  : hi_u8 *puc_buffer, hi_u16 uc_status_code
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_set_aid_ie(hi_u8 *puc_buffer, hi_u16 aid)
{
    /* The 2 MSB bits of Association ID is set to 1 as required by the standard. */
    aid |= 0xC000;
    puc_buffer[0] = (aid & 0x00FF);
    puc_buffer[1] = (aid & 0xFF00) >> 8; /* ɨ��ID��ϢԪ��byte 1,��ֵΪaid��8 byte */
}

/*****************************************************************************
 �� �� ��  : mac_get_bss_type
 ��������  : ��ȡBSS������
 �޸���ʷ      :
  1.��    ��   : 2013��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_get_bss_type(hi_u16 us_cap_info)
{
    mac_cap_info_stru *cap_info = (mac_cap_info_stru *)&us_cap_info;

    if (cap_info->ess != 0) {
        return (hi_u8)WLAN_MIB_DESIRED_BSSTYPE_INFRA;
    }
    if (cap_info->ibss != 0) {
        return (hi_u8)WLAN_MIB_DESIRED_BSSTYPE_INDEPENDENT;
    }
    return (hi_u8)WLAN_MIB_DESIRED_BSSTYPE_ANY;
}

/*****************************************************************************
 ��������  : ���CAP INFO��privacy �Ƿ����
 �޸���ʷ      :
  1.��    ��   : 2013��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_check_mac_privacy(hi_u16 us_cap_info, hi_u8 *vap)
{
    mac_vap_stru       *mac_vap = HI_NULL;
    mac_cap_info_stru  *cap_info = (mac_cap_info_stru *)&us_cap_info;

    mac_vap = (mac_vap_stru *)vap;
    if (mac_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked) {
        /* ��VAP��Privacy invoked������VAPû�� */
        if (cap_info->privacy == 0) {
            return HI_FALSE;
        }
    }
    /* ���Ǽ����ԣ���vap��֧�ּ���ʱ��������û������� */
    return HI_TRUE;
}

/*****************************************************************************
 ��������  : ����LLC SNAP, TX�����ϵ���
 �������  : pst_buf netbuf�ṹ�� us_ether_type ��̫������
*****************************************************************************/
hi_void mac_set_snap(oal_netbuf_stru *netbuf, hi_u16 us_ether_type, hi_u8 offset)
{
    mac_llc_snap_stru *llc = HI_NULL;
    hi_u16         use_btep1;
    hi_u16         use_btep2;

    /* LLC */
    llc = (mac_llc_snap_stru *)(oal_netbuf_data(netbuf) + offset);
    llc->llc_dsap      = SNAP_LLC_LSAP;
    llc->llc_ssap      = SNAP_LLC_LSAP;
    llc->control       = LLC_UI;

    use_btep1              = hi_swap_byteorder_16(ETHER_TYPE_AARP);
    use_btep2              = hi_swap_byteorder_16(ETHER_TYPE_IPX);
    if (oal_unlikely((use_btep1 == us_ether_type) || (use_btep2 == us_ether_type))) {
        llc->auc_org_code[0] = SNAP_BTEP_ORGCODE_0; /* org_code[0]:0x0 */
        llc->auc_org_code[1] = SNAP_BTEP_ORGCODE_1; /* org_code[1]:0x0 */
        llc->auc_org_code[2] = SNAP_BTEP_ORGCODE_2; /* org_code[2]:0xf8 */
    } else {
        llc->auc_org_code[0]  = SNAP_RFC1042_ORGCODE_0;  /* org_code[0]:0x0 */
        llc->auc_org_code[1]  = SNAP_RFC1042_ORGCODE_1;  /* org_code[1]:0x0 */
        llc->auc_org_code[2]  = SNAP_RFC1042_ORGCODE_2;  /* org_code[2]:0x0 */
    }
    llc->us_ether_type = us_ether_type;
    oal_netbuf_pull(netbuf, offset);
}

/*****************************************************************************
 ��������  : ��ȡmacͷ�е�qos ctrl�ֶ�
*****************************************************************************/
hi_void mac_get_qos_ctrl(const hi_u8 *puc_mac_hdr, hi_u8 *puc_qos_ctrl)
{
    if (!mac_is_4addr(puc_mac_hdr)) {
        if (memcpy_s(puc_qos_ctrl, MAC_QOS_CTL_LEN, puc_mac_hdr + MAC_QOS_CTRL_FIELD_OFFSET, MAC_QOS_CTL_LEN) != EOK) {
            oam_error_log0(0, 0, "{mac_get_qos_ctrl::memcpy_s fail.}");
            return;
        }
        return;
    }
    if (memcpy_s(puc_qos_ctrl, MAC_QOS_CTL_LEN, puc_mac_hdr + MAC_QOS_CTRL_FIELD_OFFSET_4ADDR,
        MAC_QOS_CTL_LEN) != EOK) {
        oam_error_log0(0, 0, "{mac_get_qos_ctrl::memcpy_s fail.}");
        return;
    }
}

/*****************************************************************************
 ��������  : ��䳧���Զ���ie
 �������  : pst_vap: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2014��6��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��11��18��
    ��    ��   : Hisilicon
    �޸�����   : ����2.4G 11ac˽����ǿOUI��Type
*****************************************************************************/
hi_void mac_set_vendor_hisi_ie(hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
{
    mac_ieee80211_vendor_ie_stru *vendor_ie;

    vendor_ie = (mac_ieee80211_vendor_ie_stru *)puc_buffer;
    vendor_ie->element_id = MAC_EID_VENDOR;
    vendor_ie->len = sizeof(mac_ieee80211_vendor_ie_stru) - MAC_IE_HDR_LEN;

    /* ��ֵ����a��˾��д */
    vendor_ie->oui_type = MAC_EID_VHT_TYPE;
    vendor_ie->auc_oui[0] = (hi_u8)((MAC_HUAWEI_VENDER_IE >> 16) & 0xff); /* oui[0]�����HW IE�����16 bit��ȡ */
    vendor_ie->auc_oui[1] = (hi_u8)((MAC_HUAWEI_VENDER_IE >> 8) & 0xff);  /* oui[1]�����HW IE�ε�8 bit��ȡ */
    vendor_ie->auc_oui[2] = (hi_u8)((MAC_HUAWEI_VENDER_IE) & 0xff);       /* oui[2]�����HW IE���8 bit��ȡ */
    *puc_ie_len = sizeof(mac_ieee80211_vendor_ie_stru);
}


/*****************************************************************************
 ��������  : �ж��Ƿ��ǳ����Զ���Action����
 �޸���ʷ      :
  1.��    ��   : 2019��4��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 mac_check_is_vendor_action(hi_u32 oui, const hi_u8 *puc_ies, hi_u16 us_len)
{
    hi_u32 ie_oui;

    if (us_len < 4) { /* puc_ies��С��С��4�ֽ� */
        return HI_FALSE;
    }

    ie_oui = (puc_ies[1] << 16) | (puc_ies[2] << 8) | puc_ies[3]; /* ��OUI����,byte 1�ڸ�16bit,byte 2��bit8~15,byte 3 */
    if (ie_oui == oui) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : �ж��Ƿ��ǳ����Զ���Action����֡
 �������  : [1]oui
             [2]oui_type
             [3]puc_ies
             [4]l_len
 �� �� ֵ  : hi_u8 *����ָ�룬HI_NULL��ʾû���ҵ���Ӧvendor actionλ��
*****************************************************************************/
hi_u8 mac_find_vendor_action(hi_u32 oui, hi_u8 oui_type, const hi_u8 *puc_ies, hi_s32 l_len)
{
    hi_u32 ie_oui;
    hi_u8  type;

    if ((puc_ies == HI_NULL) || (l_len <= MAC_ACTION_VENDOR_TYPE_POS)) {
        return HI_FALSE;
    }

    if (puc_ies[0] != MAC_ACTION_CATEGORY_VENDOR) {
        return HI_FALSE;
    }

    type = puc_ies[MAC_ACTION_VENDOR_TYPE_POS];
    ie_oui = (puc_ies[1] << 16) | (puc_ies[2] << 8) | puc_ies[3]; /* 16:����λ����2:����λ����8:����λ����3:����λ�� */
    if ((ie_oui == oui) && (type == oui_type)) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 * ��������  : ���ù���֡ͷ
 * �������  : mac_header MAC ͷָ�룬frame_type : Frame Control��
 *                           addr1��addr2��addr3: mac addrsss
*****************************************************************************/
WIFI_ROM_TEXT hi_u16 mac_set_mgmt_frame_header(hi_u8 *mac_header, hi_u16 frame_type,
                                               const hi_u8 *addr1, const hi_u8 *addr2, const hi_u8 *addr3)
{
    /*************************************************************************/
    /*                        Management Frame Format                        */
    /* --------------------------------------------------------------------  */
    /* |Frame Control|Duration|DA|SA|BSSID|Sequence Control|Frame Body|FCS|  */
    /* --------------------------------------------------------------------  */
    /* | 2           |2       |6 |6 |6    |2               |0 - 2312  |4  |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    mac_hdr_set_frame_control(mac_header, frame_type);

    /* ����durationΪ0����Ӳ���� */
    mac_hdr_set_duration(mac_header, frame_type, 0);

    /* ���õ�ַ1, 2, 3  */
    if (mac_hdr_set_mac_addrsss(mac_header, addr1, addr2, addr3) == 0) {
        return 0;
    }

    /* ���÷�Ƭ���, ����֡Ϊ0 */
    mac_hdr_set_fragment_number(mac_header, 0);

    return MAC_80211_FRAME_LEN;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

