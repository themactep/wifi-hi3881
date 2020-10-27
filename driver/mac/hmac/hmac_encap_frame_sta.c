/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: STA mode framing, HMAC layer STA-specific frame framing file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_vap.h"
#include "wlan_mib.h"
#include "mac_frame.h"
#include "hmac_encap_frame_sta.h"
#include "hmac_user.h"
#include "hmac_tx_data.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �������ʼ�
 �������  : pst_hmac_sta: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��6��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_set_supported_rates_ie_asoc_req(const hmac_vap_stru *hmac_vap, hi_u8 *puc_buffer,
                                             hi_u8 *puc_ie_len)
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

    nrates = hmac_vap->rs_nrates;

    if (nrates > MAC_MAX_SUPRATES) {
        nrates = MAC_MAX_SUPRATES;
    }

    for (idx = 0; idx < nrates; idx++) {
        puc_buffer[MAC_IE_HDR_LEN + idx] = hmac_vap->auc_supp_rates[idx];
    }

    puc_buffer[1] = nrates;

    *puc_ie_len = MAC_IE_HDR_LEN + nrates;
}

/*****************************************************************************
 ��������  : ���extended supported rates��Ϣ
 �������  : pst_hmac_sta: ָ��vap
             puc_buffer: ָ��buffer
 �������  : puc_ie_len: element�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��6��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_set_exsup_rates_ie_asoc_req(const hmac_vap_stru *hmac_vap, hi_u8 *puc_buffer, hi_u8 *puc_ie_len)
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
    if (hmac_vap->rs_nrates <= MAC_MAX_SUPRATES) {
        *puc_ie_len = 0;
        return;
    }

    puc_buffer[0] = MAC_EID_XRATES;
    nrates = hmac_vap->rs_nrates - MAC_MAX_SUPRATES;
    puc_buffer[1] = nrates;

    for (idx = 0; idx < nrates; idx++) {
        puc_buffer[MAC_IE_HDR_LEN + idx] = hmac_vap->auc_supp_rates[idx + MAC_MAX_SUPRATES];
    }

    *puc_ie_len = MAC_IE_HDR_LEN + nrates;
}

/*****************************************************************************
 ��������  : ��֡(Re)assoc
 �޸���ʷ      :
  1.��    ��   : 2013��6��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_encap_asoc_req_sta(const hmac_vap_stru *hmac_vap, hi_u8 *puc_req_frame)
{
    hi_u16  us_app_ie_len = 0;
    hi_u8   ie_len = 0;
    hi_u8  *puc_req_frame_origin = puc_req_frame; /* ������ʼ��ַ��������㳤�� */
    hi_u8  *bssid = hmac_vap->base_vap->auc_bssid;

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
    /* �ж��Ƿ�Ϊreassoc���� */
    mac_hdr_set_frame_control(puc_req_frame, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT |
        ((hmac_vap->reassoc_flag == HI_TRUE) ? WLAN_FC0_SUBTYPE_REASSOC_REQ : WLAN_FC0_SUBTYPE_ASSOC_REQ));

    /* ���� DA address1: AP MAC��ַ (BSSID) */
    /* ���� SA address2: dot11MACAddress */
    /* ���� DA address3: AP MAC��ַ (BSSID) */
    if ((memcpy_s(puc_req_frame + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN, bssid, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(puc_req_frame + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
            hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(puc_req_frame + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN, bssid, WLAN_MAC_ADDR_LEN) != EOK)) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_asoc_req_sta::memcpy_s fail.}");
        return 0;
    }

    puc_req_frame += MAC_80211_FRAME_LEN;

    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Association Request Frame - Frame Body                   */
    /* --------------------------------------------------------------------- */
    /* | Capability Information | Listen Interval | SSID | Supported Rates | */
    /* --------------------------------------------------------------------- */
    /* |2                       |2                |2-34  |3-10             | */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |Externed Surpported rates| Power Capability | Supported Channels   | */
    /* --------------------------------------------------------------------- */
    /* |3-257                    |4                 |4-256                 | */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* | RSN   | QoS Capability | HT Capabilities | Extended Capabilities  | */
    /* --------------------------------------------------------------------- */
    /* |36-256 |3               |28               |3-8                     | */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* | WPS   | P2P |                                                       */
    /* --------------------------------------------------------------------- */
    /* |7-257  |X    |                                                       */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    mac_set_cap_info_sta((hi_void *)hmac_vap->base_vap, puc_req_frame);
    puc_req_frame += MAC_CAP_INFO_LEN;

    /* ���� Listen Interval IE */
    mac_set_listen_interval_ie(puc_req_frame, &ie_len);
    puc_req_frame += ie_len;

    /* Ressoc��֡����Current AP address */
    if (hmac_vap->reassoc_flag) {
        if (memcpy_s(puc_req_frame, WLAN_MAC_ADDR_LEN,  hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
            return 0;
        }
        puc_req_frame += OAL_MAC_ADDR_LEN;
    }
    /* ���� SSID IE */
    mac_set_ssid_ie((hi_void *)hmac_vap->base_vap, puc_req_frame, &ie_len, WLAN_FC0_SUBTYPE_ASSOC_REQ);
    puc_req_frame += ie_len;

    /* ���� Supported Rates IE */
    hmac_set_supported_rates_ie_asoc_req(hmac_vap, puc_req_frame, &ie_len);
    puc_req_frame += ie_len;

    /* ���� Extended Supported Rates IE */
    hmac_set_exsup_rates_ie_asoc_req(hmac_vap, puc_req_frame, &ie_len);
    puc_req_frame += ie_len;
    /* ���� Power Capability IE */
    mac_set_power_cap_ie((hi_void *)hmac_vap->base_vap, puc_req_frame, &ie_len);
    puc_req_frame += ie_len;

    /* ���� Supported channel IE */
    mac_set_supported_channel_ie((hi_void *)hmac_vap->base_vap, puc_req_frame, &ie_len);
    puc_req_frame += ie_len;

    /* ���WMM element */
    if (hmac_vap->wmm_cap == HI_TRUE) {
        mac_set_wmm_ie_sta((hi_void *)hmac_vap->base_vap, puc_req_frame, &ie_len);
        puc_req_frame += ie_len;
    }

    /* ���� HT Capability IE  */
    mac_set_ht_capabilities_ie((hi_void *)hmac_vap->base_vap, puc_req_frame, &ie_len);
    puc_req_frame += ie_len;

    /* ���� Extended Capability IE */
    mac_set_ext_capabilities_ie((hi_void *)hmac_vap->base_vap, puc_req_frame, &ie_len);
    puc_req_frame += ie_len;

    /* ���P2P/WPS IE ��Ϣ */
    mac_add_app_ie(hmac_vap->base_vap, puc_req_frame, &us_app_ie_len, OAL_APP_ASSOC_REQ_IE);
    /* DTS2015021504247 P2P���� ������͵Ĺ�������û��P2P WPS IE��Ϣ */
    puc_req_frame += us_app_ie_len;

    return (hi_u32)(puc_req_frame - puc_req_frame_origin);
}

/*****************************************************************************
 ��������  : ��seq = 1 ��auth req֡
 �޸���ʷ      :
  1.��    ��   : 2013��6��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_mgmt_encap_auth_req(const hmac_vap_stru *hmac_vap, hi_u8 *puc_mgmt_frame)
{
    hi_u8 user_index = 0;

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
    mac_hdr_set_frame_control(puc_mgmt_frame, WLAN_FC0_SUBTYPE_AUTH);

    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_mgmt_frame)->auc_address1, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_auth_req::mem safe function err!}");
        return 0;
    }
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_mgmt_frame)->auc_address2, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_auth_req::mem safe function err!}");
        return 0;
    }
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_mgmt_frame)->auc_address3, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_auth_req::mem safe function err!}");
        return 0;
    }
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Authentication Frame (Sequence 1) - Frame Body           */
    /* --------------------------------------------------------------------  */
    /* |Auth Algorithm Number|Auth Transaction Sequence Number|Status Code|  */
    /* --------------------------------------------------------------------  */
    /* | 2                   |2                               |2          |  */
    /* --------------------------------------------------------------------  */
    /*                                                                       */
    /*************************************************************************/
    if (hmac_vap->base_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked == HI_FALSE) {
        /* Open System */
        puc_mgmt_frame[MAC_80211_FRAME_LEN] = 0x00;
        puc_mgmt_frame[MAC_80211_FRAME_LEN + 1] = 0x00;
    } else {
        hi_u16 us_auth_type = (hi_u16)hmac_vap->auth_mode;

        if (us_auth_type == WLAN_WITP_AUTH_SHARED_KEY) {
            oam_info_log0(0, OAM_SF_ASSOC, "{hmac_mgmt_encap_auth_req::WLAN_WITP_AUTH_SHARED_KEY.}");
            us_auth_type = WLAN_WITP_AUTH_SHARED_KEY;
        } else {
            oam_info_log0(0, OAM_SF_ASSOC, "{hmac_mgmt_encap_auth_req::WLAN_WITP_AUTH_OPEN_SYSTEM.}");
            us_auth_type = WLAN_WITP_AUTH_OPEN_SYSTEM;
        }

        puc_mgmt_frame[MAC_80211_FRAME_LEN] = (us_auth_type & 0xFF);
        puc_mgmt_frame[MAC_80211_FRAME_LEN + 1] = ((us_auth_type & 0xFF00) >> 8); /* ����8λ */
    }

    /* ���� Authentication Transaction Sequence Number Ϊ 1 */
    puc_mgmt_frame[MAC_80211_FRAME_LEN + 2] = 0x01; /* λ������Ϊ2 */
    puc_mgmt_frame[MAC_80211_FRAME_LEN + 3] = 0x00; /* λ������Ϊ3 */
    /* ���� Status Code Ϊ0. �����������ֶ�û�� . */
    puc_mgmt_frame[MAC_80211_FRAME_LEN + 4] = 0x00; /* λ������Ϊ4 */
    puc_mgmt_frame[MAC_80211_FRAME_LEN + 5] = 0x00; /* λ������Ϊ5 */
    /* ���� ��֤֡�ĳ��� */
    hi_u16 us_auth_req_len = MAC_80211_FRAME_LEN + MAC_AUTH_ALG_LEN + MAC_AUTH_TRANS_SEQ_NUM_LEN + MAC_STATUS_CODE_LEN;

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(hmac_vap->base_vap->assoc_vap_id);
    if (hmac_user == HI_NULL) {
        oam_info_log0(0, OAM_SF_ASSOC, "{hmac_mgmt_encap_auth_req::no present ap, alloc new ap.}");
        hi_u32 ret = hmac_user_add(hmac_vap->base_vap, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN, &user_index);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ASSOC, "{hmac_mgmt_encap_auth_req::hmac_user_add failed[%d].}", ret);
            us_auth_req_len = 0;
        }
    }

    return us_auth_req_len;
}

/*****************************************************************************
 ��������  : Ϊshared key׼��seq = 3 ����֤֡
 �޸���ʷ      :
  1.��    ��   : 2013��6��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_mgmt_encap_auth_req_seq3(const hmac_vap_stru *hmac_vap, hi_u8 *puc_mgmt_frame, hi_u8 *puc_mac_hrd)
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
    /*************************************************************************/
    /*                Set the fields in the frame header                     */
    /*************************************************************************/
    mac_hdr_set_frame_control(puc_mgmt_frame, WLAN_FC0_SUBTYPE_AUTH);

    /* ��֡�����ֶ���1 */
    mac_set_wep(puc_mgmt_frame, 1);

    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_mgmt_frame)->auc_address1, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_mgmt_encap_auth_req_seq3::mem safe function err!}");
        return 0;
    }
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_mgmt_frame)->auc_address2, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_mgmt_encap_auth_req_seq3::mem safe function err!}");
        return 0;
    }
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_mgmt_frame)->auc_address3, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "{hmac_mgmt_encap_auth_req_seq3::mem safe function err!}");
        return 0;
    }

    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*              Authentication Frame (Sequence 3) - Frame Body           */
    /* --------------------------------------------------------------------- */
    /* |Auth Algo Number|Auth Trans Seq Number|Status Code| Challenge Text | */
    /* --------------------------------------------------------------------- */
    /* | 2              |2                    |2          | 3 - 256        | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ��ȡ��֤֡payload */
    hi_u16 us_index = MAC_80211_FRAME_LEN;
    hi_u8 *puc_data = (hi_u8 *)(puc_mgmt_frame + us_index);

    /* ���� ��֤֡�ĳ��� */
    hi_u16 us_auth_req_len = MAC_80211_FRAME_LEN + MAC_AUTH_ALG_LEN + MAC_AUTH_TRANS_SEQ_NUM_LEN + MAC_STATUS_CODE_LEN;

    /* In case of no failure, the frame must be WEP encrypted.
     * 4 bytes must be left for the IV in that case. These
     * fields will then be reinitialized, using the correct
     * index, with offset for IV field. Authentication
     * Algorithm Number */
    puc_data[0] = WLAN_WITP_AUTH_SHARED_KEY;
    puc_data[1] = 0x00;

    /* Authentication Transaction Sequence Number */
    puc_data[2] = 0x03;   /*  2 ��3λ */
    puc_data[3] = 0x00;  /* 3 ��4λ */

    /* If WEP subfield in the  incoming  authentication frame
     * is 1,  respond with  'challenge text failure' status,
     * since the STA does not expect an encrypted frame in
     * this state.                                     */
    if (mac_is_protectedframe(puc_mac_hrd)) {
        puc_data[4] = MAC_CHLNG_FAIL; /* 4 ��5λ */
        puc_data[5] = 0x00; /* 5 ��6λ */
    } else if (HI_FALSE == mac_is_wep_enabled(hmac_vap->base_vap)) {
        /* If the STA does not support WEP, respond with
         * 'unsupported algo' status, since WEP is necessary
         * for Shared Key Authentication.         */
        puc_data[4] = MAC_UNSUPT_ALG; /* 4 ��5λ */
        puc_data[5] = 0x00; /* 5 ��6λ */
    } else if (mac_mib_get_wep_default_keysize(hmac_vap->base_vap) == 0) {
        /* If the default WEP key is NULL, respond with
         * 'challenge text failure' status, since a NULL
         * key value cannot be used for WEP operations.     */
        puc_data[4] = MAC_CHLNG_FAIL; /* 4 ��5λ */
        puc_data[5] = 0x00; /* 5 ��6λ */
    } else {
        /* If there is a mapping in dot11WEPKeyMappings
         * matching the address of the AP, and the corresponding
         * key is NULL respond with 'challenge text failure' status.
         * This is currently not being used.               */
        /* No error condition detected */
        puc_data[4] = MAC_SUCCESSFUL_STATUSCODE; /* 4 ��5λ */
        puc_data[5] = 0x00; /* 5 ��6λ */

        /* Extract 'Challenge Text' and its 'length' from the incoming       */
        /* authentication frame                                              */
        hi_u8  ch_text_len = puc_mac_hrd[MAC_80211_FRAME_LEN + 7]; /* λ����7 */
        hi_u8 *puc_ch_text = (hi_u8 *)(&puc_mac_hrd[MAC_80211_FRAME_LEN + 8]); /* λ����8 */

        /* Challenge Text Element                  */
        /* --------------------------------------- */
        /* |Element ID | Length | Challenge Text | */
        /* --------------------------------------- */
        /* | 1         |1       |1 - 253         | */
        /* --------------------------------------- */
        puc_mgmt_frame[us_index + 6] = MAC_EID_CHALLENGE; /* λ����6 */
        puc_mgmt_frame[us_index + 7] = ch_text_len; /* λ����7 */
        if (memcpy_s(&puc_mgmt_frame[us_index + 8], ch_text_len, puc_ch_text, ch_text_len) != EOK) { /* λ����8 */
            /* ROM����ֹ���� */
            oam_error_log0(0, OAM_SF_CFG, "hmac_mgmt_encap_auth_req_seq3:: puc_ch_text memcpy_s fail.");
            return 0;
        }

        /* Add the challenge text element length to the authentication       */
        /* request frame length. The IV, ICV element lengths will be added   */
        /* after encryption.                                                 */
        us_auth_req_len += (ch_text_len + MAC_IE_HDR_LEN);
    }

    return us_auth_req_len;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
