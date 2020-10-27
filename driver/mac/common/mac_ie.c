/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: mac_ie.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include "mac_ie.h"
#include "mac_frame.h"
#include "mac_device.h"
#include "dmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ����ʵ��
*****************************************************************************/
#define __WIFI_ROM_SECTION__        /* ����ROM����ʼλ�� */

/*****************************************************************************
 ��������  : ����VAP mibֵ
 �������  : [1]mac_vap
             [2]us_len
             [3]puc_param
 �� �� ֵ  : ��
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_config_set_mib(const mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    mac_cfg_set_mib_stru *set_mib = (mac_cfg_set_mib_stru *)puc_param;

    hi_unref_param(us_len);

    if (set_mib->mib_idx == WLAN_MIB_INDEX_SPEC_MGMT_IMPLEMENT) {
        mac_mib_set_spectrum_management_implemented(mac_vap, (hi_u8)(set_mib->mib_value));
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_FORTY_MHZ_OPERN_IMPLEMENT) {
        mac_mib_set_forty_mhz_operation_implemented(mac_vap, (hi_u8)(set_mib->mib_value));
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_2040_COEXT_MGMT_SUPPORT) {
        mac_mib_set_2040bss_coexistence_management_support(mac_vap, (hi_u8)(set_mib->mib_value));
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_FORTY_MHZ_INTOL) {
        mac_mib_set_forty_mhz_intolerant(mac_vap, (hi_u8)(set_mib->mib_value));
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_TRIGGER_INTERVAL) {
        mac_mib_set_bsswidth_trigger_scan_interval(mac_vap, set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_TRANSITION_DELAY_FACTOR) {
        mac_mib_set_bsswidth_channel_transition_delay_factor(mac_vap, set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_PASSIVE_DWELL) {
        mac_mib_set_obssscan_passive_dwell(mac_vap, set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_ACTIVE_DWELL) {
        mac_mib_set_obssscan_active_dwell(mac_vap, set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_PASSIVE_TOTAL_PER_CHANNEL) {
        mac_mib_set_obssscan_passive_total_per_channel(mac_vap, set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_ACTIVE_TOTAL_PER_CHANNEL) {
        mac_mib_set_obssscan_active_total_per_channel(mac_vap, set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_OBSSSCAN_ACTIVITY_THRESHOLD) {
        mac_mib_set_obssscan_activity_threshold(mac_vap, set_mib->mib_value);
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_MESH_ACCEPTING_PEER) {
        mac_mib_set_accepting_peer(mac_vap, (hi_u8)set_mib->mib_value);
    } else if (set_mib->mib_idx == WLAN_MIB_INDEX_MESH_SECURITY_ACTIVATED) {
        mac_mib_set_mesh_security(mac_vap, (hi_u8)set_mib->mib_value);
#endif
    } else {
        oam_error_log1(mac_vap->vap_id, OAM_SF_CFG, "{hmac_config_set_mib::invalid ul_mib_idx[%d].}",
            set_mib->mib_idx);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����HT Operation IE
 �������  : pst_mac_vap : MAC VAP�ṹ��ָ�룬ָ��STA
             puc_payload : ָ��HT Operation IE��ָ��
             pst_mac_user: MAC VAP�ṹ��ָ�룬ָ��AP
 �޸���ʷ      :
  1.��    ��   : 2014��3��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_proc_ht_opern_ie(mac_vap_stru *mac_vap, const hi_u8 *puc_payload, mac_user_stru *mac_user)
{
    mac_ht_opern_stru *ht_opern = HI_NULL;
    mac_user_ht_hdl_stru ht_hdl;
    wlan_bw_cap_enum_uint8 bwcap_vap;
    hi_u32 change = MAC_NO_CHANGE;

    if (oal_unlikely((mac_vap == HI_NULL) || (puc_payload == HI_NULL) || (mac_user == HI_NULL))) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_ie_proc_ht_opern_ie::param null.}");
        return change;
    }

    if (puc_payload[1] < 6) { /* ����У�飬�˴����õ�ǰ6�ֽڣ�����Basic MCS Setδ�漰 */
        oam_warning_log1(0, OAM_SF_ANY, "{mac_proc_ht_opern_ie::invalid ht opern ie len[%d].}", puc_payload[1]);
        return change;
    }
    mac_user_get_ht_hdl(mac_user, &ht_hdl);

    /************************ HT Operation Element *************************************
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
    ht_opern = (mac_ht_opern_stru *)(&puc_payload[MAC_IE_HDR_LEN]);

    /* ��ȡHT Operation IE�е�"STA Channel Width" */
    mac_user_set_bandwidth_info(mac_user, ht_opern->sta_chan_width, mac_user->cur_bandwidth);

    /* ��ȡHT Operation IE�е�"Secondary Channel Offset" */
    ht_hdl.secondary_chan_offset = ht_opern->secondary_chan_offset;

    /* Ϊ�˷�ֹ5G���û�����20M��������80M���ݵ��������5G����¸ñ������л� */
    if ((mac_user->avail_bandwidth == 0) && (mac_vap->channel.band == WLAN_BAND_2G)) {
        ht_hdl.secondary_chan_offset = MAC_SCN;
    }

    /* �û���VAP��������ȡ���� */
    mac_vap_get_bandwidth_cap(mac_vap, &bwcap_vap);
    bwcap_vap = oal_min(mac_user->bandwidth_cap, bwcap_vap);
    bwcap_vap = oal_min(mac_user->avail_bandwidth, bwcap_vap);
    mac_user_set_bandwidth_info(mac_user, bwcap_vap, bwcap_vap);

    /* ������� */
    ht_hdl.rifs_mode = ht_opern->rifs_mode;      /* ������������дʱ����Ҫ��ֵ */
    ht_hdl.ht_protection = ht_opern->ht_protection;
    ht_hdl.nongf_sta_present = ht_opern->nongf_sta_present;
    ht_hdl.obss_nonht_sta_present = ht_opern->obss_nonht_sta_present;
    ht_hdl.lsig_txop_protection_full_support = ht_opern->lsig_txop_protection_full_support;

    mac_user_set_ht_hdl(mac_user, &ht_hdl);

    return change;
}

/*****************************************************************************
 ��������  : ������20M�ŵ�ƫ��IE
 �޸���ʷ      :
  1.��    ��   : 2013��12��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
WIFI_ROM_TEXT hi_u32 mac_set_second_channel_offset_ie(wlan_channel_bandwidth_enum_uint8 bw, hi_u8 *pauc_buffer,
    hi_u8 *puc_output_len)
{
    /* Ĭ�����Ϊ�� */
    *pauc_buffer    = '\0';
    *puc_output_len = 0;

    /* 11n ����Secondary Channel Offset Element */
    /******************************************************************/
    /* -------------------------------------------------------------- */
    /* |Ele. ID |Length |Secondary channel offset |                   */
    /* -------------------------------------------------------------- */
    /* |1       |1      |1                        |                   */
    /*                                                                */
    /******************************************************************/
    pauc_buffer[0] = 62; /* �̶�����Ϊ62 */
    pauc_buffer[1] = 1;
    switch (bw) {
        case WLAN_BAND_WIDTH_20M:
            pauc_buffer[2] = 0;  /* no secondary channel(pauc_buffer[2]) */
            break;
        case WLAN_BAND_WIDTH_5M:
            pauc_buffer[2] = MAC_BW_5M;  /* pauc_buffer[2] : �Զ��壬խ��5M */
            break;
        case WLAN_BAND_WIDTH_10M:
            pauc_buffer[2] = MAC_BW_10M;  /* pauc_buffer[2] : �Զ��壬խ��10M */
            break;
        default:
            oam_error_log1(0, OAM_SF_SCAN, "{mac_set_second_channel_offset_ie::invalid bandwidth[%d].}", bw);
            return HI_FAIL;
    }
    *puc_output_len = 3; /* output_len�̶���ֵΪ3 */
    return HI_SUCCESS;
}

/* ����ROM�ν���λ�� ����ROM���������SECTION�� */
#undef __WIFI_ROM_SECTION__

/*****************************************************************************
 ��������  : ����ht cap ie�е� supported channel width
 �������  : pst_mac_user_sta           : user�ṹ��ָ��
             pst_mac_vap                : vap�ṹ��ָ��
             uc_supported_channel_width : �Ƿ�֧��40Mhz����  0: ��֧�֣� 1: ֧��
             en_prev_asoc_ht            : user֮ǰ�Ƿ���htվ����ݹ�����ap  0: ֮ǰδ������ 1: ֮ǰ������
 �� �� ֵ  :�û��й��������st_ht_hdl.bit_supported_channel_width��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_ie_proc_ht_supported_channel_width(const mac_user_stru *mac_user_sta,
    mac_vap_stru *mac_vap, hi_u8 supported_channel_width, hi_bool prev_asoc_ht)
{
    /* ��֧��20/40MhzƵ�� */
    if (supported_channel_width == 0) {
        /*  ���STA֮ǰû����ΪHTվ����AP������ ����STA֮ǰ�Ѿ���Ϊ֧��20/40MhzƵ���HTվ����AP���� */
        if ((prev_asoc_ht == HI_FALSE) ||
            (mac_user_sta->ht_hdl.ht_capinfo.supported_channel_width == HI_TRUE)) {
            mac_vap->protection.sta_20_m_only_num++;
        }
        return HI_FALSE;
    } else { /* ֧��20/40MhzƵ�� */
        /*  ���STA֮ǰ�Ѿ���Ϊ��֧��20/40MhzƵ���HTվ����AP���� */
        if ((prev_asoc_ht == HI_TRUE) &&
            (mac_user_sta->ht_hdl.ht_capinfo.supported_channel_width == HI_FALSE)) {
            mac_vap->protection.sta_20_m_only_num--;
        }
        return HI_TRUE;
    }
}

/*****************************************************************************
 ��������  : ����ht cap ie�е� ht green field  BIT4
 �������  : pst_mac_user_sta  : user�ṹ��ָ��
             pst_mac_vap       : vap�ṹ��ָ��
             uc_ht_green_field : �Ƿ�֧��gf�� 0: ��֧�֣� 1: ֧��
             en_prev_asoc_ht   : user֮ǰ�Ƿ���htվ����ݹ�����ap  0: ֮ǰδ������ 1: ֮ǰ������
 �� �� ֵ  :�û����������st_ht_hdl.bit_ht_green_field��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��12��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_ie_proc_ht_green_field(const mac_user_stru *mac_user_sta, mac_vap_stru *mac_vap,
                                 hi_u8 ht_green_field, hi_bool prev_asoc_ht)
{
    /* ��֧��Greenfield */
    if (ht_green_field == 0) {
        /*  ���STA֮ǰû����ΪHTվ����AP������ ����STA֮ǰ�Ѿ���Ϊ֧��GF��HTվ����AP���� */
        if ((prev_asoc_ht == HI_FALSE) || (mac_user_sta->ht_hdl.ht_capinfo.ht_green_field == HI_TRUE)) {
            mac_vap->protection.sta_non_gf_num++;
        }
        return HI_FALSE;
    } else { /* ֧��Greenfield */
        /*  ���STA֮ǰ�Ѿ���Ϊ��֧��GF��HTվ����AP���� */
        if ((prev_asoc_ht == HI_TRUE) && (mac_user_sta->ht_hdl.ht_capinfo.ht_green_field == HI_FALSE)) {
            mac_vap->protection.sta_non_gf_num--;
        }
        return HI_TRUE;
    }
}

/*****************************************************************************
 �� �� ��  : mac_ie_proc_lsig_txop_protection_support
 ��������  : ����ht cap ie�е� lsig_txop_protection_support
 �������  : pst_mac_user_sta                : user�ṹ��ָ��
             pst_mac_vap                     : vap�ṹ��ָ��
             uc_lsig_txop_protection_support : �Ƿ�֧��lsig txop������ 0: ��֧�֣� 1: ֧��
             en_prev_asoc_ht                 : user֮ǰ�Ƿ���htվ����ݹ�����ap  0: ֮ǰδ������ 1: ֮ǰ������
 �� �� ֵ  :�û����������st_ht_hdl.bit_lsig_txop_protection��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2014��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_ie_proc_lsig_txop_protection_support(const mac_user_stru *mac_user_sta,
    mac_vap_stru *mac_vap, hi_u8 lsig_txop_protection_support, hi_bool prev_asoc_ht)
{
    /* ��֧��L-sig txop protection */
    if (lsig_txop_protection_support == 0) {
        /*  ���STA֮ǰû����ΪHTվ����AP������ ����STA֮ǰ�Ѿ���Ϊ֧��Lsig txop protection��HTվ����AP���� */
        if ((prev_asoc_ht == HI_FALSE) ||
            (mac_user_sta->ht_hdl.ht_capinfo.lsig_txop_protection == HI_TRUE)) {
            mac_vap->protection.sta_no_lsig_txop_num++;
        }
        return HI_FALSE;
    } else { /* ֧��L-sig txop protection */
        /*  ���STA֮ǰ�Ѿ���Ϊ��֧��Lsig txop protection��HTվ����AP���� */
        if ((prev_asoc_ht == HI_TRUE) &&
            (mac_user_sta->ht_hdl.ht_capinfo.lsig_txop_protection == HI_FALSE)) {
            mac_vap->protection.sta_no_lsig_txop_num--;
        }
        return HI_TRUE;
    }
}

/*****************************************************************************
  *  �� �� ��  :   mac_ie_txbf_set_ht_hdl
 *  ��������  : ����txbf feild�ṹ��
 *  �������  :
 *  �������  :
 *  �� �� ֵ  : hi_void
*****************************************************************************/
hi_void  mac_ie_txbf_set_ht_hdl(mac_user_ht_hdl_stru *ht_hdl, hi_u32 info_elem)
{
    hi_u32  tmp_txbf_elem = info_elem;

    ht_hdl->imbf_receive_cap                = (tmp_txbf_elem & BIT0);
    ht_hdl->receive_staggered_sounding_cap  = ((tmp_txbf_elem & BIT1) >> 1);
    ht_hdl->transmit_staggered_sounding_cap = ((tmp_txbf_elem & BIT2) >> 2); /* ����2 bit��ȡtransmit sounding_cap */
    ht_hdl->receive_ndp_cap                 = ((tmp_txbf_elem & BIT3) >> 3); /* ����3 bit��ȡreceive_ndp_cap */
    ht_hdl->transmit_ndp_cap                = ((tmp_txbf_elem & BIT4) >> 4); /* ����4 bit��ȡtransmit_ndp_cap */
    ht_hdl->imbf_cap                        = ((tmp_txbf_elem & BIT5) >> 5); /* ����5 bit��ȡimbf_cap */
    ht_hdl->calibration                     = ((tmp_txbf_elem & 0x000000C0) >> 6);  /* ����6 bit��ȡcalibration */
    ht_hdl->exp_csi_txbf_cap                = ((tmp_txbf_elem & BIT8) >> 8);   /* ����8 bit��ȡexp_csi_txbf_cap */
    ht_hdl->exp_noncomp_txbf_cap            = ((tmp_txbf_elem & BIT9) >> 9);   /* ����9 bit��ȡexp_noncomp_txbf_cap */
    ht_hdl->exp_comp_txbf_cap               = ((tmp_txbf_elem & BIT10) >> 10); /* ����10 bit��ȡexp_comp_txbf_cap */
    ht_hdl->exp_csi_feedback                = ((tmp_txbf_elem & 0x00001800) >> 11); /* ����11 bit��ȡexp_csi_feedback */
    ht_hdl->exp_noncomp_feedback            = ((tmp_txbf_elem & 0x00006000) >> 13); /* ����13 bit��ȡnoncomp_feedback */

    ht_hdl->exp_comp_feedback               = ((tmp_txbf_elem & 0x0001C000) >> 15); /* ����15 bit��ȡcomp_feedback */
    ht_hdl->min_grouping                    = ((tmp_txbf_elem & 0x00060000) >> 17); /* ����17 bit��ȡmin_grouping */
    ht_hdl->csi_bfer_ant_number             = ((tmp_txbf_elem & 0x001C0000) >> 19); /* ����19 bit��ȡbfer_ant_number */
    ht_hdl->noncomp_bfer_ant_number         = ((tmp_txbf_elem & 0x00600000) >> 21); /* ����21 bit��ȡbfer_ant_number */
    ht_hdl->comp_bfer_ant_number            = ((tmp_txbf_elem & 0x01C00000) >> 23); /* ����23 bit��ȡbfer_ant_number */
    ht_hdl->csi_bfee_max_rows               = ((tmp_txbf_elem & 0x06000000) >> 25); /* ����25 bit��ȡbfee_max_rows */
    ht_hdl->channel_est_cap                 = ((tmp_txbf_elem & 0x18000000) >> 27); /* ����27 bit��ȡchannel_est_cap */
}

/*****************************************************************************
 ��������  : ����asoc rsp frame֡�е�HT cap IE
 �޸���ʷ      :
  1.��    ��   : 2013��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_ie_proc_ht_sta(const mac_vap_stru *mac_vap, const hi_u8 *puc_payload, const hi_u16 *pus_index,
    mac_user_stru *mac_user_ap, hi_u16 *pus_ht_cap_info, hi_u16 *pus_amsdu_max)
{
    hi_u16                us_offset = *pus_index;
    mac_user_stru        *mac_user = mac_user_ap;
    mac_user_ht_hdl_stru  ht_hdl_value;
    mac_user_ht_hdl_stru *ht_hdl = &ht_hdl_value;

    mac_user_get_ht_hdl(mac_user, ht_hdl);
    /* ���� HT Capability Element �� AP����ʾ������HT capable. */
    ht_hdl->ht_capable = HI_TRUE;
    us_offset += MAC_IE_HDR_LEN;
    /********************************************/
    /*     ���� HT Capabilities Info Field      */
    /********************************************/
    *pus_ht_cap_info = hi_makeu16(puc_payload[us_offset], puc_payload[us_offset + 1]);
    /* ���STA��֧�ֵ�LDPC�������� B0��0:��֧�֣�1:֧�� */
    ht_hdl->ht_capinfo.ldpc_coding_cap = (*pus_ht_cap_info & BIT0);
    /* ��ȡAP��֧�ֵĴ�������  */
    ht_hdl->ht_capinfo.supported_channel_width = ((*pus_ht_cap_info & BIT1) >> 1);
    /* ���ռ临�ý���ģʽ B2~B3 */
    hi_u8 smps = (*pus_ht_cap_info & (BIT2 | BIT3));
    ht_hdl->ht_capinfo.sm_power_save = mac_ie_proc_sm_power_save_field(smps);

    ht_hdl->ht_capinfo.ht_green_field = ((*pus_ht_cap_info & BIT4) >> 4); /* ��ȡAP֧��Greenfield���,����4bit */

    ht_hdl->ht_capinfo.short_gi_20mhz = ((*pus_ht_cap_info & BIT5) >> 5); /* ��ȡAP֧��20MHz Short-GI���,����5bit */

    ht_hdl->ht_capinfo.short_gi_40mhz = ((*pus_ht_cap_info & BIT6) >> 6); /* ��ȡAP֧��40MHz Short-GI���,����6bit */

    ht_hdl->ht_capinfo.rx_stbc = (hi_u8)((*pus_ht_cap_info & 0x30) >> 4); /* ��ȡAP֧��STBC PPDU���,����4bit */
    /* ��ȡAP֧�����A-MSDU������� */
    *pus_amsdu_max = ((*pus_ht_cap_info & BIT11) == 0) ?
        WLAN_MIB_MAX_AMSDU_LENGTH_SHORT : WLAN_MIB_MAX_AMSDU_LENGTH_LONG;

    ht_hdl->ht_capinfo.dsss_cck_mode_40mhz = ((*pus_ht_cap_info & BIT12) >> 12); /* 12:��ȡ40M��DSSS/CCK��֧����� */

    ht_hdl->ht_capinfo.lsig_txop_protection = ((*pus_ht_cap_info & BIT15) >> 15); /* 15:��ȡL-SIG TXOP ������֧����� */
    us_offset += MAC_HT_CAPINFO_LEN;

    /********************************************/
    /*     ���� A-MPDU Parameters Field         */
    /********************************************/
    /* ��ȡ Maximum Rx A-MPDU factor (B1 - B0) */
    ht_hdl->max_rx_ampdu_factor = (puc_payload[us_offset] & 0x03);

    ht_hdl->min_mpdu_start_spacing = (puc_payload[us_offset] >> 2) & 0x07; /* ��ȡ Minmum Rx A-MPDU factor (B3 - B2) */
    us_offset += MAC_HT_AMPDU_PARAMS_LEN;

    /********************************************/
    /*     ���� Supported MCS Set Field         */
    /********************************************/
    for (hi_u8 mcs_bmp_index = 0; mcs_bmp_index < WLAN_HT_MCS_BITMASK_LEN; mcs_bmp_index++) {
        ht_hdl->rx_mcs_bitmask[mcs_bmp_index] =
            (mac_vap->mib_info->supported_mcstx.auc_dot11_supported_mcs_tx_value[mcs_bmp_index]) &
            (*(hi_u8 *)(puc_payload + us_offset + mcs_bmp_index));
    }
    ht_hdl->rx_mcs_bitmask[WLAN_HT_MCS_BITMASK_LEN - 1] &= 0x1F;
    us_offset += MAC_HT_SUP_MCS_SET_LEN;

    /********************************************/
    /* ���� HT Extended Capabilities Info Field */
    /********************************************/
    *pus_ht_cap_info = hi_makeu16(puc_payload[us_offset], puc_payload[us_offset + 1]);
    /* ��ȡ HTC support Information */
    if ((*pus_ht_cap_info & BIT10) != 0) {
        ht_hdl->htc_support = 1;
    }
    us_offset += MAC_HT_EXT_CAP_LEN;

    /********************************************/
    /*  ���� Tx Beamforming Field               */
    /********************************************/
    hi_u16 us_tmp_info_elem = hi_makeu16(puc_payload[us_offset], puc_payload[us_offset + 1]);
    hi_u16 us_tmp_txbf_low  = hi_makeu16(puc_payload[us_offset + 2], puc_payload[us_offset + 3]); /* 2/3:ƫ�� */
    hi_u32 tmp_txbf_elem    = hi_makeu32(us_tmp_info_elem, us_tmp_txbf_low);

    mac_ie_txbf_set_ht_hdl(ht_hdl, tmp_txbf_elem);

    mac_user_set_ht_hdl(mac_user, ht_hdl);
}

/*****************************************************************************
 ��������  : ���action֡�ǲ���p2p֡
 �޸���ʷ      :
  1.��    ��   : 2014��12��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_ie_check_p2p_action(const hi_u8 *puc_payload)
{
    /* �ҵ�WFA OUI */
    hi_u8 auc_oui[MAC_OUI_LEN] = {(hi_u8)MAC_WLAN_OUI_P2P0, (hi_u8)MAC_WLAN_OUI_P2P1, (hi_u8)MAC_WLAN_OUI_P2P2};

    if ((0 == memcmp(puc_payload, auc_oui, MAC_OUI_LEN)) &&
        (MAC_OUITYPE_P2P == puc_payload[MAC_OUI_LEN])) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ����ht cap ie�е� sm power save field B2~B3
 �������  : pst_mac_user_sta --�û��ṹ��ָ�룬uc_smps--�û�smpsģʽ
 �� �� ֵ  : �û���Ϣ��st_ht_hdl.bit_sm_power_save����Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��12��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
wlan_mib_mimo_power_save_enum_uint8 mac_ie_proc_sm_power_save_field(hi_u8 smps)
{
    if (smps == MAC_SMPS_STATIC_MODE) {
        return WLAN_MIB_MIMO_POWER_SAVE_STATIC;
    } else if (smps == MAC_SMPS_DYNAMIC_MODE) {
        return WLAN_MIB_MIMO_POWER_SAVE_DYNAMIC;
    } else {
        return WLAN_MIB_MIMO_POWER_SAVE_MIMO;
    }
}

/*****************************************************************************
 ��������  : ��֡���н���ie�е�chan��Ϣ������HT operation IE����chan��Ϣ������ҵ��ͷ��أ����Ҳ�����
             ����DSSS Param set ie��Ѱ��
 �޸���ʷ      :
  1.��    ��   : 2014��2��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 mac_ie_get_chan_num(hi_u8 *puc_frame_body, hi_u16 us_frame_len, hi_u16 us_offset, hi_u8 curr_chan)
{
    hi_u8   chan_num = 0;
    hi_u8  *puc_ie_start_addr = HI_NULL;

    if (us_frame_len > us_offset) {
        /* ��DSSS Param set ie�н���chan num */
        puc_ie_start_addr = mac_find_ie(MAC_EID_DSPARMS, puc_frame_body + us_offset, us_frame_len - us_offset);
        if ((puc_ie_start_addr != HI_NULL) && (puc_ie_start_addr[1] == MAC_DSPARMS_LEN)) {
            chan_num = puc_ie_start_addr[2]; /* ��ie_start_addr��2 byte��ȡ�ŵ��� */
            if (mac_is_channel_num_valid(mac_get_band_by_channel_num(chan_num), chan_num) == HI_SUCCESS) {
                return chan_num;
            }
        }
        /* ��HT operation ie�н��� chan num */
        puc_ie_start_addr = mac_find_ie(MAC_EID_HT_OPERATION, puc_frame_body + us_offset, us_frame_len - us_offset);
        if ((puc_ie_start_addr != HI_NULL) && (puc_ie_start_addr[1] >= 1)) {
            chan_num = puc_ie_start_addr[2]; /* ��ie_start_addr��2 byte��ȡ�ŵ��� */
            if (mac_is_channel_num_valid(mac_get_band_by_channel_num(chan_num), chan_num) == HI_SUCCESS) {
                return  chan_num;
            }
        }
    }
    chan_num = curr_chan;
    return chan_num;
}

/*****************************************************************************
 ��������  : ����"����ģʽ"��ȡ��Ӧ��"���ŵ�ƫ����"
 �������  : en_bandwidth: ����ģʽ
 �� �� ֵ  : ���ŵ�ƫ����
*****************************************************************************/
WIFI_ROM_TEXT mac_sec_ch_off_enum_uint8 mac_get_sco_from_bandwidth(wlan_channel_bandwidth_enum_uint8 bandwidth)
{
    switch (bandwidth) {
        case WLAN_BAND_WIDTH_40PLUS:
        case WLAN_BAND_WIDTH_80PLUSPLUS:
        case WLAN_BAND_WIDTH_80PLUSMINUS:
            return MAC_SCA;
        case WLAN_BAND_WIDTH_40MINUS:
        case WLAN_BAND_WIDTH_80MINUSPLUS:
        case WLAN_BAND_WIDTH_80MINUSMINUS:
            return MAC_SCB;
        default:
            return MAC_SCN;
    }
}

/*****************************************************************************
 ��������  : �����ŵ�����Ƶ���ȡ��Ӧ��"����ģʽ"
 �������  : uc_channel         : �ŵ���
             uc_chan_center_freq: �ŵ�����Ƶ��
 �޸���ʷ      :
  1.��    ��   : 2014��2��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
wlan_channel_bandwidth_enum_uint8 mac_get_bandwith_from_center_freq_seg0(hi_u8 channel, hi_u8 chan_center_freq)
{
    switch (chan_center_freq - channel) {
        case 6: /* 6: ��20�ŵ�+1, ��40�ŵ�+1 ���� */
            /***********************************************************************
            | ��20 | ��20 | ��40       |
                          |
                          |����Ƶ���������20ƫ6���ŵ�
            ************************************************************************/
            return WLAN_BAND_WIDTH_80PLUSPLUS;
        case -2: /* -2: ��20�ŵ�+1, ��40�ŵ�-1 ���� */
            /***********************************************************************
            | ��40        | ��20 | ��20 |
                          |
                          |����Ƶ���������20ƫ-2���ŵ�
            ************************************************************************/
            return WLAN_BAND_WIDTH_80PLUSMINUS;
        case 2: /* 2: ��20�ŵ�-1, ��40�ŵ�+1 ���� */
            /***********************************************************************
            | ��20 | ��20 | ��40       |
                          |
                          |����Ƶ���������20ƫ2���ŵ�
            ************************************************************************/
            return  WLAN_BAND_WIDTH_80MINUSPLUS;
        case -6: /* -6: ��20�ŵ�-1, ��40�ŵ�-1 ���� */
            /***********************************************************************
            | ��40        | ��20 | ��20 |
                          |
                          |����Ƶ���������20ƫ-6���ŵ�
            ************************************************************************/
            return WLAN_BAND_WIDTH_80MINUSMINUS;
        default:
            return 0;
    }
}

/*****************************************************************************
 ��������  : ����"���ŵ�ƫ����"��ȡ��Ӧ�Ĵ���ģʽ
 �������  : en_sec_chan_offset: ���ŵ�ƫ����
 �� �� ֵ  : ����ģʽ
*****************************************************************************/
wlan_channel_bandwidth_enum_uint8 mac_get_bandwidth_from_sco(mac_sec_ch_off_enum_uint8 sec_chan_offset)
{
    switch (sec_chan_offset) {
        case MAC_SCA:   /* Secondary Channel Above */
            return WLAN_BAND_WIDTH_40PLUS;
        case MAC_SCB:   /* Secondary Channel Below */
            return WLAN_BAND_WIDTH_40MINUS;
        case MAC_BW_5M:
            return WLAN_BAND_WIDTH_5M;
        case MAC_BW_10M:
            return WLAN_BAND_WIDTH_10M;
        default:        /* No Secondary Channel    */
            return WLAN_BAND_WIDTH_20M;
    }
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
