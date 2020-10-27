/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: AP mode and STA mode shared frame framing file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hmac_encap_frame.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
��������  : ��sa query ����֡
�������  : pst_mac_vap :mac vap�ṹ��
            puc_data    :netbuf dataָ��
            puc_da      :Ŀ���û���mac��ַ
            trans_id    :sa query ie,���ڱ��response��request�Ƿ�һ��
�� �� ֵ  : ֡ͷ+֡��ĳ���
�޸���ʷ      :
 1.��    ��   : 2014��4��19��
   ��    ��   : Hisilicon
   �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_encap_sa_query_req(const mac_vap_stru *mac_vap, hi_u8 *puc_data, const hi_u8 *da_mac_addr,
                               hi_u16 us_trans_id)
{
    hi_u16 us_len;

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
    /* All the fields of the Frame Control Field are set to zero. Only the   */
    /* Type/Subtype field is set.                                            */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_ACTION);
    /*  Set DA  */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address1, WLAN_MAC_ADDR_LEN,
        da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }
    /*  Set SA  */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address2, WLAN_MAC_ADDR_LEN,
        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }
    /*  Set SSID  */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address3, WLAN_MAC_ADDR_LEN,
        mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*                  SA Query Frame - Frame Body                          */
    /* --------------------------------------------------------------------- */
    /* |   Category   |SA Query Action |  Transaction Identifier           | */
    /* --------------------------------------------------------------------- */
    /* |1             |1               |2 Byte                             | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    puc_data[MAC_80211_FRAME_LEN] = MAC_ACTION_CATEGORY_SA_QUERY;
    puc_data[MAC_80211_FRAME_LEN + 1] = MAC_SA_QUERY_ACTION_REQUEST; /* 1:ƫ��1 */
    puc_data[MAC_80211_FRAME_LEN + 2] = (us_trans_id & 0x00FF); /* 2:ƫ��2 */
    puc_data[MAC_80211_FRAME_LEN + 3] = (us_trans_id & 0xFF00) >> 8; /* 3:ƫ��1��8:�����ƶ�8λ */

    us_len = MAC_80211_FRAME_LEN + MAC_SA_QUERY_LEN;
    return us_len;
}

/*****************************************************************************
��������  : ��sa query ����֡
�������  : pst_hdr:sa query request frame
            puc_data:sa query response frame
�� �� ֵ  : ֡ͷ+֡��ĳ���
�޸���ʷ      :
 1.��    ��   : 2014��4��19��
   ��    ��   : Hisilicon
   �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_encap_sa_query_rsp(const mac_vap_stru *mac_vap, const hi_u8 *hdr, hi_u8 *puc_data)
{
    hi_u16 us_len;

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
    /* All the fields of the Frame Control Field are set to zero. Only the   */
    /* Type/Subtype field is set.                                            */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_ACTION);
    /* Set DA  */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address1, WLAN_MAC_ADDR_LEN,
        ((mac_ieee80211_frame_stru *)hdr)->auc_address2, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_sa_query_rsp::mem safe function err!}");
        return 0;
    }
    /*  Set SA  */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address2, WLAN_MAC_ADDR_LEN,
        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_sa_query_rsp::mem safe function err!}");
        return 0;
    }
    /*  Set SSID  */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address3, WLAN_MAC_ADDR_LEN,
        mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_encap_sa_query_rsp::mem safe function err!}");
        return 0;
    }
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*                  SA Query Frame - Frame Body                          */
    /* --------------------------------------------------------------------- */
    /* |   Category   |SA Query Action |  Transaction Identifier           | */
    /* --------------------------------------------------------------------- */
    /* |1             |1               |2 Byte                             | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    puc_data[MAC_80211_FRAME_LEN] = hdr[MAC_80211_FRAME_LEN];
    puc_data[MAC_80211_FRAME_LEN + 1] = MAC_SA_QUERY_ACTION_RESPONSE; /* 1:ƫ��1 */
    puc_data[MAC_80211_FRAME_LEN + 2] = hdr[MAC_80211_FRAME_LEN + 2]; /* 2:ƫ��2 */
    puc_data[MAC_80211_FRAME_LEN + 3] = hdr[MAC_80211_FRAME_LEN + 3]; /* 3:ƫ��3 */

    us_len = MAC_80211_FRAME_LEN + MAC_SA_QUERY_LEN;
    return us_len;
}

/*****************************************************************************
 ��������  : ��ȥ��֤֡
*****************************************************************************/
hi_u16 hmac_mgmt_encap_deauth(const mac_vap_stru *mac_vap, hi_u8 *puc_data, const hi_u8 *da_mac_addr, hi_u16 err_code)
{
    hi_u8 auc_bssid[WLAN_MAC_ADDR_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    mac_ieee80211_frame_stru *mac_hdr = (mac_ieee80211_frame_stru *)puc_data;

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
    /* All the fields of the Frame Control Field are set to zero. Only the   */
    /* Type/Subtype field is set.                                            */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_DEAUTH);
    /* Set DA to address of unauthenticated STA */
    if (memcpy_s(mac_hdr->auc_address1, WLAN_MAC_ADDR_LEN, da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }
#ifdef _PRE_WLAN_FEATURE_P2P
    if (err_code & MAC_SEND_TWO_DEAUTH_FLAG) {
        mac_vap_stru *up_vap1 = HI_NULL;
        mac_vap_stru *up_vap2 = HI_NULL;
        err_code = err_code & ~MAC_SEND_TWO_DEAUTH_FLAG;

        mac_device_stru *mac_dev = mac_res_get_dev();
        if (mac_device_find_2up_vap(mac_dev, &up_vap1, &up_vap2) == HI_SUCCESS) {
            /* ��ȡ����һ��VAP����֡ʱ�޸ĵ�ַ2Ϊ����1��VAP��MAC��ַ */
            up_vap2 = (mac_vap->vap_id != up_vap1->vap_id) ? up_vap1 : up_vap2;
            if (up_vap2->mib_info == HI_NULL) {
                return 0;
            }
            if ((memcpy_s(mac_hdr->auc_address2, WLAN_MAC_ADDR_LEN,
                up_vap2->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) ||
                (memcpy_s(mac_hdr->auc_address3, WLAN_MAC_ADDR_LEN, up_vap2->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK)) {
                return 0;
            }
        }
    } else {
#endif
        if (mac_vap->mib_info == HI_NULL) {
            return 0;
        }
        /* SA is the dot11MACAddress */
        if (memcpy_s(mac_hdr->auc_address2, WLAN_MAC_ADDR_LEN,
            mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
            return 0;
        }
        /*
         * ���50������,����дBSSID���BSSID����ȫ0�Ƚ�
         * STA����FAKE_UP״̬��mac vap��bssidΪȫ0��deauth֡�Զ˲�����,��Ϊ��дda��
         */
        if (memcpy_s(mac_hdr->auc_address3, WLAN_MAC_ADDR_LEN, mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
            return 0;
        }
        if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) &&
            (memcmp(mac_vap->auc_bssid, auc_bssid, WLAN_MAC_ADDR_LEN) == 0)) {
            if (memcpy_s(mac_hdr->auc_address3, WLAN_MAC_ADDR_LEN, da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
                return 0;
            }
        }
#ifdef _PRE_WLAN_FEATURE_P2P
    }
#endif
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*                  Deauthentication Frame - Frame Body                  */
    /* --------------------------------------------------------------------- */
    /* |                           Reason Code                             | */
    /* --------------------------------------------------------------------- */
    /* |2 Byte                                                             | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* Set Reason Code to 'Class2 error' */
    puc_data[MAC_80211_FRAME_LEN] = (err_code & 0x00FF);
    puc_data[MAC_80211_FRAME_LEN + 1] = (err_code & 0xFF00) >> 8; /* 1:ƫ��1��8:����λ��8 */

    return (MAC_80211_FRAME_LEN + WLAN_REASON_CODE_LEN);
}

/*****************************************************************************
 ��������  : ��ȥ����֡
 �������  : vapָ��,DA,ErrCode
 �������  : ֡������
 �� �� ֵ  : ֡����
 �޸���ʷ      :
  1.��    ��   : 2013��12��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_mgmt_encap_disassoc(const mac_vap_stru *mac_vap, hi_u8 *puc_data, const hi_u8 *da_mac_addr,
                                hi_u16 us_err_code)
{
    hi_u16 us_disassoc_len = 0;

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
    /*                            ����֡ͷ                                   */
    /*************************************************************************/
    /* ����subtype   */
    mac_hdr_set_frame_control(puc_data, WLAN_FC0_SUBTYPE_DISASSOC);

    if (mac_vap->mib_info == HI_NULL) {
        us_disassoc_len = 0;
        oam_error_log0(mac_vap->vap_id, OAM_SF_AUTH, "hmac_mgmt_encap_disassoc: pst_mac_vap mib ptr null.");
        return us_disassoc_len;
    }
    /* ����DA */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address1, WLAN_MAC_ADDR_LEN,
        da_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }
    /* ����SA */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address2, WLAN_MAC_ADDR_LEN,
        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    /* Mesh ��ֱ����䱾�豸mac ��ַ�����ж� */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address3, WLAN_MAC_ADDR_LEN,
            mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
            return 0;
        }
    } else {
        /* ����bssid */
        if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address3, WLAN_MAC_ADDR_LEN,
            mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP ?
            mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id : mac_vap->auc_bssid,
            WLAN_MAC_ADDR_LEN) != EOK) {
            return 0;
        }
    }
#else
    /* ����bssid */
    if (memcpy_s(((mac_ieee80211_frame_stru *)puc_data)->auc_address3, WLAN_MAC_ADDR_LEN,
        mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP ?
        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id : mac_vap->auc_bssid,
        WLAN_MAC_ADDR_LEN) != EOK) {
        return 0;
    }
#endif

    /*************************************************************************/
    /*                  Disassociation ֡ - ֡��                  */
    /* --------------------------------------------------------------------- */
    /* |                           Reason Code                             | */
    /* --------------------------------------------------------------------- */
    /* |2 Byte                                                             | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ����reason code */
    puc_data[MAC_80211_FRAME_LEN] = (us_err_code & 0x00FF);
    puc_data[MAC_80211_FRAME_LEN + 1] = (us_err_code & 0xFF00) >> 8; /* 1:ƫ��1��8:����λ��8 */

    us_disassoc_len = MAC_80211_FRAME_LEN + WLAN_REASON_CODE_LEN;

    return us_disassoc_len;
}

/*****************************************************************************
 ��������  : ��鵱ǰSTA�Ƿ�֧��AP�Ļ�������
 �޸���ʷ      :
  1.��    ��   : 2013��7��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_check_sta_base_rate(hi_u8 *user, mac_status_code_enum_uint16 *pen_status_code)
{
    hi_u8 num_basic_rates;
    hi_u8 loop;
    hi_u8 index;
    hi_u8 found;
    hi_u8 num_rates;
    hi_u8 ap_base_rate;
    mac_vap_stru *mac_vap = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;

    hmac_user = (hmac_user_stru *)user;

    /* ��ȡVAP */
    mac_vap = mac_vap_get_vap_stru(hmac_user->base_user->vap_id);
    if (mac_vap == HI_NULL) {
        return;
    }

    num_basic_rates = mac_vap->curr_sup_rates.br_rate_num;
    num_rates = hmac_user->op_rates.rs_nrates;

    for (loop = 0; loop < num_basic_rates; loop++) {
        found = HI_FALSE;
        ap_base_rate = mac_vap_get_curr_baserate(mac_vap, loop);

        for (index = 0; index < num_rates; index++) {
            if ((hmac_user->op_rates.auc_rs_rates[index] & 0x7F) == (ap_base_rate & 0x7F)) {
                found = HI_TRUE;
                break;
            }
        }

        /* ��֧��ĳ�������ʣ�����false  */
        if (found == HI_FALSE) {
            *pen_status_code = MAC_UNSUP_RATE;
            return;
        }
    }
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
