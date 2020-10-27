/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Source file implemented by the management frame interface common to the AP and the STA
                under the HMAC module.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_vap.h"
#include "mac_ie.h"
#include "mac_frame.h"
#include "hmac_mgmt_bss_comm.h"
#include "mac_resource.h"
#include "hmac_device.h"
#include "hmac_fsm.h"
#include "hmac_encap_frame.h"
#include "hmac_mgmt_ap.h"
#include "hmac_mgmt_sta.h"
#include "hmac_blockack.h"
#include "hmac_event.h"
#include "frw_timer.h"
#ifdef _PRE_WLAN_FEATURE_BTCOEX
#include "dmac_btcoex.h"
#endif
#include "hcc_hmac_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
hi_u8 g_auc_avail_protocol_mode[WLAN_PROTOCOL_BUTT][WLAN_PROTOCOL_BUTT] = {
    {WLAN_LEGACY_11A_MODE, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT,
     WLAN_LEGACY_11A_MODE, WLAN_LEGACY_11A_MODE, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT},

    {WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11B_MODE,
     WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11B_MODE, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT},

    {WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11G_MODE, WLAN_LEGACY_11G_MODE, WLAN_LEGACY_11G_MODE,
     WLAN_LEGACY_11G_MODE, WLAN_LEGACY_11G_MODE, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11G_MODE},

    {WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11G_MODE, WLAN_MIXED_ONE_11G_MODE, WLAN_MIXED_ONE_11G_MODE,
     WLAN_MIXED_ONE_11G_MODE, WLAN_MIXED_ONE_11G_MODE, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11G_MODE},

    {WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11G_MODE, WLAN_MIXED_ONE_11G_MODE, WLAN_MIXED_TWO_11G_MODE,
     WLAN_MIXED_ONE_11G_MODE, WLAN_MIXED_ONE_11G_MODE, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11G_MODE},

    {WLAN_LEGACY_11A_MODE, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11G_MODE, WLAN_MIXED_ONE_11G_MODE, WLAN_MIXED_ONE_11G_MODE,
     WLAN_HT_MODE, WLAN_HT_MODE, WLAN_HT_ONLY_MODE, WLAN_PROTOCOL_BUTT, WLAN_HT_11G_MODE},

    {WLAN_LEGACY_11A_MODE, WLAN_LEGACY_11B_MODE, WLAN_LEGACY_11G_MODE, WLAN_MIXED_ONE_11G_MODE, WLAN_MIXED_ONE_11G_MODE,
     WLAN_HT_MODE, WLAN_VHT_MODE, WLAN_HT_ONLY_MODE, WLAN_VHT_ONLY_MODE, WLAN_PROTOCOL_BUTT},

    {WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT,
     WLAN_HT_ONLY_MODE, WLAN_HT_ONLY_MODE, WLAN_HT_ONLY_MODE, WLAN_HT_ONLY_MODE, WLAN_HT_ONLY_MODE},

    {WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT,
     WLAN_PROTOCOL_BUTT, WLAN_VHT_ONLY_MODE, WLAN_PROTOCOL_BUTT, WLAN_VHT_ONLY_MODE, WLAN_PROTOCOL_BUTT},

    {WLAN_PROTOCOL_BUTT, WLAN_PROTOCOL_BUTT, WLAN_LEGACY_11G_MODE, WLAN_LEGACY_11G_MODE, WLAN_LEGACY_11G_MODE,
     WLAN_HT_11G_MODE, WLAN_PROTOCOL_BUTT, WLAN_HT_ONLY_MODE, WLAN_PROTOCOL_BUTT, WLAN_HT_11G_MODE},
};

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
hi_u8 hmac_get_auc_avail_protocol_mode(wlan_protocol_enum_uint8 vap_protocol, wlan_protocol_enum_uint8 user_protocol)
{
    return g_auc_avail_protocol_mode[vap_protocol][user_protocol];
}

#ifdef _PRE_WLAN_FEATURE_AMPDU_VAP
/*****************************************************************************
 ��������  : VAP�� rx BA�Ự����1
 �޸���ʷ      :
  1.��    ��   : 2015��3��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_ba_session_decr(hmac_vap_stru *hmac_vap)
{
    if (hmac_vap->rx_ba_session_num == 0) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_BA,
                         "{hmac_rx_ba_session_decr:: rx_session already zero.}");
        return;
    }
    hmac_vap->rx_ba_session_num--;
}

/*****************************************************************************
 ��������  : VAP�� tx BA�Ự����1
 �޸���ʷ      :
  1.��    ��   : 2015��3��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_tx_ba_session_decr(hmac_vap_stru *hmac_vap)
{
    if (hmac_vap->tx_ba_session_num == 0) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_BA,
                         "{hmac_tx_ba_session_decr:: tx_session already zero.}");
        return;
    }
    hmac_vap->tx_ba_session_num--;
}
#else
/*****************************************************************************
 ��������  : device�� rx BA�Ự����1
 �޸���ʷ      :
  1.��    ��   : 2015��3��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_ba_session_decr(hmac_device_stru *hmac_dev)
{
    if (hmac_dev->rx_ba_session_num == 0) {
        oam_warning_log0(0, OAM_SF_BA, "{hmac_rx_ba_session_decr:: rx_session already zero.}");
        return;
    }
    hmac_dev->rx_ba_session_num--;
}

/*****************************************************************************
 ��������  : device�� tx BA�Ự����1
 �޸���ʷ      :
  1.��    ��   : 2015��3��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_tx_ba_session_decr(hmac_device_stru *hmac_dev)
{
    if (hmac_dev->tx_ba_session_num == 0) {
        oam_warning_log0(0, OAM_SF_BA, "{hmac_tx_ba_session_decr::tx_session already zero.}");
        return;
    }
    hmac_dev->tx_ba_session_num--;
}
#endif
/*****************************************************************************
 ��������  : ��װADDBA_REQ֡
 �޸���ʷ      :
  1.��    ��   : 2013��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_mgmt_encap_addba_req(hmac_vap_stru *hmac_vap, hi_u8 *puc_data, dmac_ba_tx_stru *tx_ba, hi_u8 tid)
{
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
#endif
    if ((hmac_vap == HI_NULL) || (puc_data == HI_NULL) || (tx_ba == HI_NULL)) {
        oam_error_log3(0, OAM_SF_BA, "{hmac_mgmt_encap_addba_req::null param.vap:%p data:%p ba:%p}",
                       (uintptr_t)hmac_vap, (uintptr_t)puc_data, (uintptr_t)tx_ba);
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
    /* Frame Control Field ��ֻ��Ҫ����Type/Subtypeֵ����������Ϊ0 */
    mac_hdr_set_frame_control(puc_data, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT | WLAN_FC0_SUBTYPE_ACTION);

    /* DA is address of STA requesting association */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN, tx_ba->puc_dst_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_addba_req::memcpy_s fail.}");
        return 0;
    }
    /* SA��ֵΪdot11MACAddress��ֵ */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_addba_req::memcpy_s fail.}");
        return 0;
    }
    /* Set BSSID */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid,
        WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_addba_req::memcpy_s fail.}");
        return 0;
    }
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /* ������ָ��frame body��ʼλ�� */
    hi_u16 us_index = MAC_80211_FRAME_LEN;

    /* ����Category */
    puc_data[us_index++] = MAC_ACTION_CATEGORY_BA;

    /* ����Action */
    puc_data[us_index++] = MAC_BA_ACTION_ADDBA_REQ;

    /* ����Dialog Token */
    puc_data[us_index++] = tx_ba->dialog_token;

    /*
       ����Block Ack Parameter set field
       bit0 - AMSDU Allowed
       bit1 - Immediate or Delayed block ack
       bit2-bit5 - TID
       bit6-bit15 -  Buffer size
     */
    hi_u16 us_ba_param = tx_ba->amsdu_supp;     /* bit0 */
    us_ba_param |= (tx_ba->ba_policy << 1);      /* bit1 */
    us_ba_param |= (tid << 2);       /* bit2 */
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    /* ��������򿪣����ҵ�ǰ��������ʹ�ã��̶�����ba_sizeΪ1�������ǰ����û��ʹ�ã���ʹ��Ĭ��ba_size */
    if (hmac_dev->d2h_btcoex_delba.ba_size == 1) {
        us_ba_param |= (hi_u16)(hmac_dev->d2h_btcoex_delba.ba_size << 6);   /* BIT6 */
    } else {
        us_ba_param |= (hi_u16)(tx_ba->us_baw_size << 6);   /* BIT6 */
    }
#else
    us_ba_param |= (hi_u16)(tx_ba->us_baw_size << 6);   /* bit6 */
#endif

    puc_data[us_index++] = (hi_u8) (us_ba_param & 0xFF);
    puc_data[us_index++] = (hi_u8) ((us_ba_param >> 8) & 0xFF); /* ����8λ */

    /* ����BlockAck timeout */
    puc_data[us_index++] = (hi_u8) (tx_ba->us_ba_timeout & 0xFF);
    puc_data[us_index++] = (hi_u8) ((tx_ba->us_ba_timeout >> 8) & 0xFF); /* ����8λ */

    /*
       Block ack starting sequence number�ֶ���Ӳ������
       bit0-bit3 fragmentnumber
       bit4-bit15: sequence number
     */
    /* us_buf_seq�˴��ݲ���д����dmac��Ჹ����д */
    puc_data[us_index++] = 0;
    puc_data[us_index++] = 0;

    /* ���ص�֡�����в�����FCS */
    return us_index;
}

/*****************************************************************************
 ��������  : ��װADDBA_RSP֡
 �޸���ʷ      :
  1.��    ��   : 2013��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_mgmt_encap_addba_rsp(hmac_vap_stru *vap, hi_u8 *data, hmac_ba_rx_stru *addba_rsp, hi_u8 tid, hi_u8 status)
{
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
#endif

    if ((vap == HI_NULL) || (data == HI_NULL) || (addba_rsp == HI_NULL)) {
        oam_error_log3(0, OAM_SF_BA, "{hmac_mgmt_encap_addba_req::null param.vap:%p data:%p rsp:%p}",
                       (uintptr_t)vap, (uintptr_t)data, (uintptr_t)addba_rsp);
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
    mac_hdr_set_frame_control(data, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT | WLAN_FC0_SUBTYPE_ACTION);
    /* DA is address of STA requesting association */
    if (memcpy_s(data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN,
        addba_rsp->puc_transmit_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_addba_rsp::memcpy_s fail.}");
        return 0;
    }
    /* SA is the dot11MACAddress */
    if (memcpy_s(data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
        vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_addba_rsp::memcpy_s fail.}");
        return 0;
    }
    /* Set BSSID */
    if (memcpy_s(data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
        vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_addba_rsp::memcpy_s fail.}");
        return 0;
    }
    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*             ADDBA Response Frame - Frame Body                         */
    /*    ---------------------------------------------------------------    */
    /*    | Category | Action | Dialog | Status  | Parameters | Timeout |    */
    /*    ---------------------------------------------------------------    */
    /*    | 1        | 1      | 1      | 2       | 2          | 2       |    */
    /*    ---------------------------------------------------------------    */
    /*                                                                       */
    /*************************************************************************/
    /* Initialize index and the frame data pointer */
    hi_u16 us_index = MAC_80211_FRAME_LEN;

    /* Action Category���� */
    data[us_index++] = MAC_ACTION_CATEGORY_BA;

    /* �ض�Action�����µ�action��֡���� */
    data[us_index++] = MAC_BA_ACTION_ADDBA_RSP;

    /* Dialog Token�����ã���Ҫ��req��copy���� */
    data[us_index++] = addba_rsp->dialog_token;

    /* ״̬������ */
    data[us_index++] = status;
    data[us_index++] = 0;

    /* Block Ack Parameter���� */
    /* B0 - AMSDU Support, B1- Immediate or Delayed block ack */
    /* B2-B5 : TID, B6-B15: Buffer size */
    hi_u16 us_ba_param = addba_rsp->amsdu_supp; /* BIT0 */
    us_ba_param |= (addba_rsp->ba_policy << 1);  /* BIT1 */
    us_ba_param |= (tid << 2);       /* BIT2 */
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    /* ��������򿪣����ҵ�ǰ��������ʹ�ã��̶�����ba_sizeΪ1�������ǰ����û��ʹ�ã���ʹ��Ĭ��ba_size */
    if (hmac_dev->d2h_btcoex_delba.ba_size == 1) {
        us_ba_param |= (hi_u16) (hmac_dev->d2h_btcoex_delba.ba_size << 6); /* BIT6 */
    } else {
        us_ba_param |= (hi_u16) (addba_rsp->us_baw_size << 6);  /* BIT6 */
    }
#else
    us_ba_param |= (hi_u16) (addba_rsp->us_baw_size << 6);      /* BIT6 */
#endif

    data[us_index++] = (hi_u8) (us_ba_param & 0xFF);
    data[us_index++] = (hi_u8) ((us_ba_param >> 8) & 0xFF); /* ����8λ */

    /* BlockAck timeoutֵ����DTS2015111901526 ���timeout���������� */
    data[us_index++] = 0x00;
    data[us_index++] = 0x00;

    /* ���ص�֡�����в�����FCS */
    return us_index;
}

/*****************************************************************************
 ��������  : ��װDELBA֡
 �޸���ʷ      :
  1.��    ��   : 2013��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u16 hmac_mgmt_encap_delba(hmac_vap_stru *hmac_vap,
                             hi_u8 *puc_data,
                             const mac_action_mgmt_args_stru *action_args)
{
    hi_u16 us_index;
    hi_u8  tid    = (hi_u8)action_args->arg1;
    hi_u8  reason = (hi_u8)action_args->arg3;
    mac_delba_initiator_enum_uint8 initiator = (hi_u8) action_args->arg2;

    if ((hmac_vap == HI_NULL) || (puc_data == HI_NULL) || (action_args->puc_arg5 == HI_NULL)) {
        oam_error_log3(0, OAM_SF_BA, "{hmac_mgmt_encap_delba::null param, %p %p %p.}",
                       (uintptr_t)hmac_vap, (uintptr_t)puc_data, (uintptr_t)(action_args->puc_arg5));
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
    mac_hdr_set_frame_control(puc_data, WLAN_PROTOCOL_VERSION | WLAN_FC0_TYPE_MGT | WLAN_FC0_SUBTYPE_ACTION);

    /* duration */
    puc_data[WLAN_HDR_DUR_OFFSET] = 0;
    puc_data[WLAN_HDR_DUR_OFFSET + 1] = 0;
    /* DA is address of STA requesting association */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR1_OFFSET, WLAN_MAC_ADDR_LEN, action_args->puc_arg5, WLAN_MAC_ADDR_LEN) !=
        EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_delba::memcpy_s fail.}");
        return 0;
    }
    /* SA is the dot11MACAddress */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR2_OFFSET, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_delba::memcpy_s fail.}");
        return 0;
    }
    /* Set BSSID */
    if (memcpy_s(puc_data + WLAN_HDR_ADDR3_OFFSET, WLAN_MAC_ADDR_LEN,
        hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_mgmt_encap_delba::memcpy_s fail.}");
        return 0;
    }

    /* seq control */
    puc_data[WLAN_HDR_FRAG_OFFSET] = 0;
    puc_data[WLAN_HDR_FRAG_OFFSET + 1] = 0;

    /*************************************************************************/
    /*                Set the contents of the frame body                     */
    /*************************************************************************/
    /*************************************************************************/
    /*             DELBA Response Frame - Frame Body                         */
    /*        -------------------------------------------------              */
    /*        | Category | Action |  Parameters | Reason code |              */
    /*        -------------------------------------------------              */
    /*        | 1        | 1      |       2     | 2           |              */
    /*        -------------------------------------------------              */
    /*                          Parameters                                   */
    /*                  -------------------------------                      */
    /*                  | Reserved | Initiator |  TID  |                     */
    /*                  -------------------------------                      */
    /*             bit  |    11    |    1      |  4    |                     */
    /*                  --------------------------------                     */
    /*************************************************************************/
    /* Initialize index and the frame data pointer */
    us_index = MAC_80211_FRAME_LEN;

    /* Category */
    puc_data[us_index++] = MAC_ACTION_CATEGORY_BA;

    /* Action */
    puc_data[us_index++] = MAC_BA_ACTION_DELBA;

    /* DELBA parameter set */
    /* B0 - B10 -reserved */
    /* B11 - initiator */
    /* B12-B15 - TID */
    puc_data[us_index++] = 0;
    puc_data[us_index] = (hi_u8) (initiator << 3); /* ����3λ */
    puc_data[us_index++] |= (hi_u8) (tid << 4); /* ����4λ */

    /* Reason field */
    /* Reason can be either of END_BA, QSTA_LEAVING, UNKNOWN_BA */
    puc_data[us_index++] = reason;
    puc_data[us_index++] = 0;

    /* ���ص�֡�����в�����FCS */
    return us_index;
}

hi_u32 hmac_mgmt_set_addba_req(hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user, dmac_ba_tx_stru *tx_ba,
    oal_netbuf_stru *addba_req, const hmac_addba_req_info *addba_info)
{
    mac_vap_stru     *mac_vap = hmac_vap->base_vap;
    hmac_tx_ctl_stru *tx_ctl  = (hmac_tx_ctl_stru *)oal_netbuf_cb(addba_req);

    dmac_ctx_action_event_stru wlan_ctx_action = {0};

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ�� */
    memset_s(oal_netbuf_cb(addba_req), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    /* ���÷�װ����֡�ӿ� */
    hi_u16 us_frame_len = hmac_mgmt_encap_addba_req(hmac_vap, oal_netbuf_data(addba_req), tx_ba, addba_info->tidno);
    if (us_frame_len == 0) {
        oam_error_log0(0, OAM_SF_BA, "{hmac_mgmt_tx_addba_req::frame len is 0.}");
        oal_netbuf_free(addba_req);
        return HI_FAIL;
    }

    /* ��ֵҪ����Dmac����Ϣ */
    wlan_ctx_action.us_frame_len    = us_frame_len;
    wlan_ctx_action.hdr_len         = MAC_80211_FRAME_LEN;
    wlan_ctx_action.action_category = MAC_ACTION_CATEGORY_BA;
    wlan_ctx_action.action          = MAC_BA_ACTION_ADDBA_REQ;
    wlan_ctx_action.user_idx        = hmac_user->base_user->us_assoc_id;
    wlan_ctx_action.tidno           = addba_info->tidno;
    wlan_ctx_action.dialog_token    = tx_ba->dialog_token;
    wlan_ctx_action.ba_policy       = tx_ba->ba_policy;
    wlan_ctx_action.us_baw_size     = tx_ba->us_baw_size;
    wlan_ctx_action.us_ba_timeout   = tx_ba->us_ba_timeout;

    if (memcpy_s((hi_u8 *)(oal_netbuf_data(addba_req) + us_frame_len), sizeof(dmac_ctx_action_event_stru),
                 (hi_u8 *)&wlan_ctx_action, sizeof(dmac_ctx_action_event_stru)) != EOK) {
        oal_netbuf_free(addba_req);
        oam_error_log0(0, OAM_SF_CFG, "hmac_mgmt_tx_addba_req:: st_wlan_ctx_action memcpy_s fail.");
        return HI_FAIL;
    }
    oal_netbuf_put(addba_req, (us_frame_len + sizeof(dmac_ctx_action_event_stru)));

    tx_ctl->us_mpdu_len         = us_frame_len + sizeof(dmac_ctx_action_event_stru);
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header        = (mac_ieee80211_frame_stru *)oal_netbuf_header(addba_req);
    tx_ctl->mac_head_type       = 1;

    mac_vap_set_cb_tx_user_idx(mac_vap, tx_ctl, hmac_user->base_user->user_mac_addr);

    *(addba_info->frame_len) = us_frame_len;

    return HI_SUCCESS;
}

hi_u32 hmac_mgmt_send_addba_event(const mac_vap_stru *mac_vap, oal_netbuf_stru *addba_req, hi_u16 us_frame_len)
{
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_req::event_mem null.}");
        oal_netbuf_free(addba_req);
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_ACTION,
                       sizeof(dmac_tx_event_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    dmac_tx_event_stru *tx_event = (dmac_tx_event_stru *)(event->auc_event_data);
    tx_event->netbuf       = addba_req;
    tx_event->us_frame_len = us_frame_len + sizeof(dmac_ctx_action_event_stru);

    hi_u32 ret = hcc_hmac_tx_data_event(event_mem, addba_req, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(addba_req);
        oam_error_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_req::frw_event_dispatch_event Err[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }

    frw_event_free(event_mem);

    return HI_SUCCESS;
}

hi_u32 hmac_mgmt_set_ba_tx_info(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, const mac_vap_stru *mac_vap,
    const dmac_ba_tx_stru *tx_ba, hi_u8 tidno)
{
    hi_unref_param(hmac_vap);

    if (hmac_user->ast_tid_info[tidno].ba_tx_info != HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_req:tid[%d] already set up}", tidno);
        hmac_ba_reset_tx_handle(&hmac_user->ast_tid_info[tidno].ba_tx_info);
    }

    hmac_user->ast_tid_info[tidno].ba_tx_info = (hmac_ba_tx_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL,
                                                                                 (hi_u16) sizeof(hmac_ba_tx_stru));
    if (hmac_user->ast_tid_info[tidno].ba_tx_info == HI_NULL) {
        oam_error_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_req::mem alloc failed.tid[%d]}", tidno);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (memset_s(hmac_user->ast_tid_info[tidno].ba_tx_info, sizeof(hmac_ba_tx_stru),
        0, sizeof(hmac_ba_tx_stru)) != EOK) {
        oal_mem_free(hmac_user->ast_tid_info[tidno].ba_tx_info);
        hmac_user->ast_tid_info[tidno].ba_tx_info = HI_NULL;
        oam_error_log0(0, OAM_SF_CFG, "hmac_mgmt_tx_addba_req:: ba_tx_info memset_s fail.");
        return HI_FAIL;
    }

    hmac_ba_tx_stru *tx_ba_stru = hmac_user->ast_tid_info[tidno].ba_tx_info;
    /* ���¶�Ӧ��TID��Ϣ */
    tx_ba_stru->ba_status    = DMAC_BA_INPROGRESS;
    tx_ba_stru->dialog_token = tx_ba->dialog_token;
    /* ��ʼ����ʱ��ʱ����Դ */
    tx_ba_stru->alarm_data.ba               = tx_ba_stru;
    tx_ba_stru->alarm_data.mac_user_idx     = (hi_u8)hmac_user->base_user->us_assoc_id;
    tx_ba_stru->alarm_data.vap_id           = mac_vap->vap_id;
    tx_ba_stru->alarm_data.tid              = tidno;
    tx_ba_stru->alarm_data.us_timeout_times = 0;
    tx_ba_stru->alarm_data.direction        = MAC_ORIGINATOR_DELBA;

#ifdef _PRE_WLAN_FEATURE_AMPDU_VAP
    hmac_vap->tx_ba_session_num++;
#else
    /* ��ȡdevice�ṹ */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    hmac_dev->tx_ba_session_num++;
#endif

    /* ����ADDBA��ʱ��ʱ�� */
    frw_timer_create_timer(&(hmac_user->ast_tid_info[tidno].ba_tx_info->addba_timer), hmac_mgmt_tx_addba_timeout,
                           WLAN_ADDBA_TIMEOUT, &(hmac_user->ast_tid_info[tidno].ba_tx_info->alarm_data), HI_FALSE);

    return HI_SUCCESS;
}

hi_u32 hmac_mgmt_tx_addba_rsp_send_event(hmac_ba_rx_stru *ba_rx_info, const mac_vap_stru *mac_vap,
    oal_netbuf_stru *addba_rsp, hmac_tx_ctl_stru *tx_ctl, hi_u16 us_frame_len)
{
    tx_ctl->us_mpdu_len         = us_frame_len + sizeof(dmac_ctx_action_event_stru);
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header        = (mac_ieee80211_frame_stru *)oal_netbuf_header(addba_rsp);
    tx_ctl->mac_head_type       = 1;

    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_rsp::event_mem mem alloc failed.}");
        oal_netbuf_free(addba_rsp);
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_ACTION,
                       sizeof(dmac_tx_event_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    /* ��д�¼�payload */
    dmac_tx_event_stru *tx_event = (dmac_tx_event_stru *)(event->auc_event_data);
    tx_event->netbuf       = addba_rsp;
    tx_event->us_frame_len = us_frame_len + sizeof(dmac_ctx_action_event_stru);

    hi_u32 ret = hcc_hmac_tx_data_event(event_mem, addba_rsp, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(addba_rsp);
        oam_error_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_rsp::hcc_hmac_tx_data_event Err=%d}", ret);
    } else {
        ba_rx_info->ba_status = DMAC_BA_COMPLETE;
    }

    frw_event_free(event_mem);

    return ret;
}

/*****************************************************************************
 ��������  : ����ADDBA_REQ֡
 �޸���ʷ      :
  1.��    ��   : 2013��4��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_tx_addba_req(hmac_vap_stru *hmac_vap,
                              hmac_user_stru *hmac_user, const mac_action_mgmt_args_stru *action_args)
{
    dmac_ba_tx_stru      tx_ba = {0};
    hmac_addba_req_info  addba_req_info = {0};
    mac_vap_stru        *mac_vap = hmac_vap->base_vap;

    hi_u16 us_frame_len = 0;
    hi_u8  tidno        = (hi_u8)(action_args->arg1);

    /* ȷ��vap���ڹ���״̬ */
    if (mac_vap->vap_state == MAC_VAP_STATE_BUTT) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_req::vap state[%d]Err}", mac_vap->vap_state);
        return HI_FAIL;
    }

    /* ����ADDBA_REQ����֡�ڴ� */
    oal_netbuf_stru *addba_req = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4); /* align 4 */
    if (addba_req == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_req::pst_addba_req null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    oal_netbuf_prev(addba_req) = HI_NULL;
    oal_netbuf_next(addba_req) = HI_NULL;

    hmac_vap->ba_dialog_token++;

    tx_ba.dialog_token  = hmac_vap->ba_dialog_token;        /* ��֤ba�Ự�����ܹ����� */
    tx_ba.us_baw_size   = (hi_u8)(action_args->arg2);
    tx_ba.ba_policy     = (hi_u8)(action_args->arg3);
    tx_ba.us_ba_timeout = (hi_u16)(action_args->arg4);
    tx_ba.puc_dst_addr  = hmac_user->base_user->user_mac_addr;
    tx_ba.amsdu_supp    = (hi_u8)hmac_vap->amsdu_ampdu_active; /* ���˶�AMPDU+AMSDU��֧�� */

    /* �����~���������ʽ�еı������޷�����,�󱨸澯,lin_t e502�澯���� */
    if (tx_ba.amsdu_supp == HI_FALSE) {
        hmac_user_set_amsdu_not_support(hmac_user, tidno);
    } else {
        /* lin_t +e502 */
        hmac_user_set_amsdu_support(hmac_user, tidno);
    }

    addba_req_info.tidno = tidno;
    addba_req_info.frame_len = &us_frame_len;
    hi_u32 ret = hmac_mgmt_set_addba_req(hmac_vap, hmac_user, &tx_ba, addba_req, &addba_req_info);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = hmac_mgmt_send_addba_event(mac_vap, addba_req, us_frame_len);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = hmac_mgmt_set_ba_tx_info(hmac_vap, hmac_user, mac_vap, &tx_ba, tidno);
    return ret;
}

/*****************************************************************************
 ��������  :����ADDBA_RSP֡
 �޸���ʷ      :
  1.��    ��   : 2014��11��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_tx_addba_rsp(hmac_vap_stru *hmac_vap,
                              const hmac_user_stru *hmac_user,
                              hmac_ba_rx_stru *ba_rx_info, hi_u8 tid, hi_u8 status)
{
    dmac_ctx_action_event_stru wlan_ctx_action = {0};
    mac_vap_stru *mac_vap = hmac_vap->base_vap;

    if (mac_vap->vap_state == MAC_VAP_STATE_BUTT) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_rsp:VapDown/Del,stat%d}", mac_vap->vap_state);
        return HI_FAIL;
    }

    /* ����ADDBA_RSP����֡�ڴ� */
    oal_netbuf_stru *addba_rsp = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4); /* align 4 */
    if (addba_rsp == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_addba_rsp::addba_rsp mem alloc failed}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ�� */
    memset_s(oal_netbuf_cb(addba_rsp), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    oal_netbuf_prev(addba_rsp) = HI_NULL;
    oal_netbuf_next(addba_rsp) = HI_NULL;

    /* ��дnetbuf��cb�ֶΣ������͹���֡�ͷ�����ɽӿ�ʹ�� */
    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(addba_rsp);
    tx_ctl->us_tx_user_idx = hmac_user->base_user->us_assoc_id;
    tx_ctl->tid            = tid;
    tx_ctl->is_amsdu       = HI_FALSE;

    hi_u16 us_frame_len = hmac_mgmt_encap_addba_rsp(hmac_vap, oal_netbuf_data(addba_rsp), ba_rx_info, tid, status);
    if (us_frame_len == 0) {
        oal_netbuf_free(addba_rsp);
        return HI_FAIL;
    }

    wlan_ctx_action.action_category = MAC_ACTION_CATEGORY_BA;
    wlan_ctx_action.action          = MAC_BA_ACTION_ADDBA_RSP;
    wlan_ctx_action.hdr_len         = MAC_80211_FRAME_LEN;
    wlan_ctx_action.us_baw_size     = ba_rx_info->us_baw_size;
    wlan_ctx_action.us_frame_len    = us_frame_len;
    wlan_ctx_action.user_idx        = hmac_user->base_user->us_assoc_id;
    wlan_ctx_action.tidno           = tid;
    wlan_ctx_action.stauts          = status;
    wlan_ctx_action.us_ba_timeout   = ba_rx_info->us_ba_timeout;
    wlan_ctx_action.back_var        = ba_rx_info->back_var;
    wlan_ctx_action.lut_index       = ba_rx_info->lut_index;
    wlan_ctx_action.us_baw_start    = ba_rx_info->us_baw_start;
    wlan_ctx_action.ba_policy       = ba_rx_info->ba_policy;

    if (memcpy_s((hi_u8 *)(oal_netbuf_data(addba_rsp) + us_frame_len), sizeof(dmac_ctx_action_event_stru),
                 (hi_u8 *)&wlan_ctx_action, sizeof(dmac_ctx_action_event_stru)) != EOK) {
        oal_netbuf_free(addba_rsp);
        oam_error_log0(0, OAM_SF_CFG, "hmac_mgmt_tx_addba_rsp:: st_wlan_ctx_action memcpy_s fail.");
        return HI_FAIL;
    }

    oal_netbuf_put(addba_rsp, (us_frame_len + sizeof(dmac_ctx_action_event_stru)));

    hi_u32 ret = hmac_mgmt_tx_addba_rsp_send_event(ba_rx_info, mac_vap, addba_rsp, tx_ctl, us_frame_len);
    return ret;
}

hi_u32 hmac_mgmt_tx_delba_send_event(hmac_user_stru *hmac_user, const mac_action_mgmt_args_stru *action_args,
    mac_vap_stru *mac_vap, oal_netbuf_stru *delba, hi_u16 us_frame_len)
{
    hi_u8 tidno = (hi_u8)(action_args->arg1);
    mac_delba_initiator_enum_uint8 initiator = (mac_delba_initiator_enum_uint8)(action_args->arg2);

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(delba);

    tx_ctl->us_mpdu_len         = us_frame_len + sizeof(dmac_ctx_action_event_stru);
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header        = (mac_ieee80211_frame_stru *)oal_netbuf_header(delba);
    tx_ctl->mac_head_type       = 1;

    mac_vap_set_cb_tx_user_idx(mac_vap, tx_ctl, hmac_user->base_user->user_mac_addr);

    /* ���¼�����DMACģ�鷢�� */
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba::event_mem null.}");
        /* �ͷŹ���֡�ڴ浽netbuf�ڴ�� */
        oal_netbuf_free(delba);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����¼�ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_ACTION,
                       sizeof(dmac_tx_event_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    /* ��д�¼�payload */
    dmac_tx_event_stru *tx_event = (dmac_tx_event_stru *)(event->auc_event_data);
    tx_event->netbuf       = delba;
    tx_event->us_frame_len = us_frame_len + sizeof(dmac_ctx_action_event_stru);

    /* �ַ� */
    hi_u32 ret = hcc_hmac_tx_data_event(event_mem, delba, HI_TRUE);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(delba);
        oam_error_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba::frw_event_dispatch_event failed[%d].}", ret);
        frw_event_free(event_mem);
        return ret;
    }

    frw_event_free(event_mem);

    if (initiator == MAC_RECIPIENT_DELBA) {
        hmac_ba_reset_rx_handle(&hmac_user->ast_tid_info[tidno].ba_rx_info, tidno);
    } else {
        hmac_ba_reset_tx_handle(&hmac_user->ast_tid_info[tidno].ba_tx_info);

        /* ��ԭ����AMPDU��AMSDU��֧����� */
        hmac_user_set_amsdu_support(hmac_user, tidno);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����DELBA����ӿ�
 �޸���ʷ      :
  1.��    ��   : 2013��4��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_tx_delba(hmac_vap_stru *hmac_vap,
                          hmac_user_stru *hmac_user, const mac_action_mgmt_args_stru *action_args)
{
    dmac_ctx_action_event_stru wlan_ctx_action = {0};
    mac_vap_stru *mac_vap = hmac_vap->base_vap;

    /* ��ȷ��vap���ڹ���״̬ */
    if (mac_vap->vap_state == MAC_VAP_STATE_BUTT) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba::vap_state[%d]Err}", mac_vap->vap_state);
        return HI_FAIL;
    }

    mac_delba_initiator_enum_uint8 initiator = (mac_delba_initiator_enum_uint8)(action_args->arg2);
    hi_u8 tidno = (hi_u8)(action_args->arg1);
    if (tidno >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba: tid=[%d] invalid tid num!.}", tidno);
        return HI_FAIL;
    }

    /* ˯�߻��Ѻ�dmacɾ��delbaʧ��,�ٴ�ɾ��ʱ���޷����͡��轫������ȥ���� */
    if ((initiator == MAC_ORIGINATOR_DELBA) && (hmac_user->ast_tid_info[tidno].ba_tx_info == HI_NULL)) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba:tid=%d ba_tx_info null}", action_args->arg1);
    }

    /* ����DEL_BA����֡�ڴ� */
    oal_netbuf_stru *delba = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4); /* align 4 */
    if (delba == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_tx_delba::pst_delba null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ�� */
    memset_s(oal_netbuf_cb(delba), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    oal_netbuf_prev(delba) = HI_NULL;
    oal_netbuf_next(delba) = HI_NULL;

    /* ���÷�װ����֡�ӿ� */
    hi_u16 us_frame_len = hmac_mgmt_encap_delba(hmac_vap, (hi_u8 *)oal_netbuf_header(delba), action_args);
    if (us_frame_len == 0) {
        oal_netbuf_free(delba);
        return HI_FAIL;
    }

    wlan_ctx_action.us_frame_len    = us_frame_len;
    wlan_ctx_action.hdr_len         = MAC_80211_FRAME_LEN;
    wlan_ctx_action.action_category = MAC_ACTION_CATEGORY_BA;
    wlan_ctx_action.action          = MAC_BA_ACTION_DELBA;
    wlan_ctx_action.user_idx        = (hi_u8)hmac_user->base_user->us_assoc_id;
    wlan_ctx_action.tidno           = tidno;
    wlan_ctx_action.initiator       = initiator;

    if (memcpy_s((hi_u8 *)(oal_netbuf_data(delba) + us_frame_len), sizeof(dmac_ctx_action_event_stru),
                 (hi_u8 *)&wlan_ctx_action, sizeof(dmac_ctx_action_event_stru)) != EOK) {
        oal_netbuf_free(delba);
        oam_error_log0(0, OAM_SF_CFG, "hmac_mgmt_tx_delba:: st_wlan_ctx_action memcpy_s fail.");
        return HI_FAIL;
    }
    oal_netbuf_put(delba, (us_frame_len + sizeof(dmac_ctx_action_event_stru)));

    hi_u32 ret = hmac_mgmt_tx_delba_send_event(hmac_user, action_args, mac_vap, delba, us_frame_len);
    return ret;
}

/*****************************************************************************
��������  : �ӿտڽ���BA���֡�Ĵ�����
�޸���ʷ      :
1.��    ��   : 2013��4��14��
    ��    ��   : Hisilicon
  �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_mgmt_rx_action_ba(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, const hi_u8 *puc_data)
{
    switch (puc_data[MAC_ACTION_OFFSET_ACTION]) {
        case MAC_BA_ACTION_ADDBA_REQ:
            hmac_mgmt_rx_addba_req(hmac_vap, hmac_user, puc_data);
            break;

        case MAC_BA_ACTION_ADDBA_RSP:
            hmac_mgmt_rx_addba_rsp(hmac_vap, hmac_user, puc_data);
            break;

        case MAC_BA_ACTION_DELBA:
            hmac_mgmt_rx_delba(hmac_vap, hmac_user, puc_data);
            break;

        default:
            break;
    }
}

static hi_void hmac_mgmt_rx_addba_req_init(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
    const hi_u8 *puc_payload, hmac_ba_rx_stru *ba_rx_stru, hi_u8 tid)
{
    hi_u16 aus_rx_timeout[WLAN_WME_AC_BUTT] = {HMAC_BA_RX_BE_TIMEOUT, HMAC_BA_RX_BK_TIMEOUT,
                                               HMAC_BA_RX_VI_TIMEOUT, HMAC_BA_RX_VO_TIMEOUT};

    /* �ڴ�����0 ��0������ʡȥ */
    /* ba_status��DMAC_BA_INIT */
    ba_rx_stru->dialog_token = puc_payload[2]; /* 2 Ԫ������ */

    /* ��ʼ��reorder���� */
    for (hi_u8 reorder_index = 0; reorder_index < WLAN_AMPDU_RX_BUFFER_SIZE; reorder_index++) {
        /* in_use seq_num num_buf��0 */
        oal_netbuf_list_head_init(&(ba_rx_stru->ast_re_order_list[reorder_index].netbuf_head));
    }

    /* ��ʼ�����մ��� */
    ba_rx_stru->us_baw_start = (puc_payload[7] >> 4) | (puc_payload[8] << 4); /* 7 8 Ԫ������ 4 �ƶ�λ�� */
    ba_rx_stru->us_baw_size = (puc_payload[3] & 0xC0) >> 6; /* 3 Ԫ������ ����6λ */
    ba_rx_stru->us_baw_size |= (puc_payload[4] << 2); /* 4 Ԫ������ ����2λ */
    if ((ba_rx_stru->us_baw_size == 0) || (ba_rx_stru->us_baw_size > WLAN_AMPDU_RX_BUFFER_SIZE)) {
        ba_rx_stru->us_baw_size = WLAN_AMPDU_RX_BUFFER_SIZE;
    }

    /* DTS2016010902690 ���goldenap�¹̼��汾���������� */
    if (ba_rx_stru->us_baw_size == 1) {
        ba_rx_stru->us_baw_size = WLAN_AMPDU_RX_BUFFER_SIZE;
    }

    ba_rx_stru->us_baw_end = dmac_ba_seq_add(ba_rx_stru->us_baw_start, (ba_rx_stru->us_baw_size - 1));
    ba_rx_stru->us_baw_tail = dmac_ba_seqno_sub(ba_rx_stru->us_baw_start, 1);
    ba_rx_stru->us_baw_head = dmac_ba_seqno_sub(ba_rx_stru->us_baw_start, HMAC_BA_BMP_SIZE);
    /* mpdu_cnt��0 */
    ba_rx_stru->is_ba = HI_TRUE;        /* Ba session is processing */
    /* ��ʼ����ʱ����Դ */
    ba_rx_stru->alarm_data.ba = ba_rx_stru;
    ba_rx_stru->alarm_data.vap_id = hmac_vap->base_vap->vap_id;
    ba_rx_stru->alarm_data.tid = tid;   /* �������timeout_times timer_triggered��0 */
    /* Ba�Ự������ʼ�� */
    ba_rx_stru->us_ba_timeout = puc_payload[5] | (puc_payload[6] << 8); /* 5 6 Ԫ������ ����8λ */
    ba_rx_stru->amsdu_supp = hmac_vap->amsdu_ampdu_active;
    ba_rx_stru->back_var = MAC_BACK_COMPRESSED;
    ba_rx_stru->puc_transmit_addr = hmac_user->base_user->user_mac_addr;
    ba_rx_stru->ba_policy = (puc_payload[3] & 0x02) >> 1; /* 3  Ԫ������ */

    frw_timer_create_timer(&(ba_rx_stru->ba_timer), hmac_ba_timeout_fn,
        aus_rx_timeout[wlan_wme_tid_to_ac(tid)], &(ba_rx_stru->alarm_data), HI_FALSE);
}

/*****************************************************************************
 ��������  : �ӿտڽ���ADDBA_REQ֡�Ĵ�����
 �޸���ʷ      :
  1.��    ��   : 2013��4��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

  2.��    ��   : 2014��12��3��
    ��    ��   : Hisilicon
    �޸�����   : ��Reorder���������Ϣ��ֲHmac
*****************************************************************************/
hi_u32 hmac_mgmt_rx_addba_req(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, const hi_u8 *puc_payload)
{
    hmac_device_stru *hmac_dev = hmac_get_device_stru();

    if (puc_payload == HI_NULL) {
        oam_error_log0(0, OAM_SF_BA, "{hmac_mgmt_rx_addba_req::addba req receive failed, null param.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_stru *mac_vap = hmac_vap->base_vap;

    /* 11n���������ſɽ���ampdu */
    if ((!(mac_vap->protocol >= WLAN_HT_MODE)) || (!(hmac_user->base_user->protocol_mode >= WLAN_HT_MODE))) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_req::protocol mode=%d,user protocol mode=%d}",
            mac_vap->protocol, hmac_user->base_user->protocol_mode);
        return HI_SUCCESS;
    }

    /******************************************************************/
    /*       ADDBA Request Frame - Frame Body                         */
    /* --------------------------------------------------------------- */
    /* | Category | Action | Dialog | Parameters | Timeout | SSN     | */
    /* --------------------------------------------------------------- */
    /* | 1        | 1      | 1      | 2          | 2       | 2       | */
    /* --------------------------------------------------------------- */
    /*                                                                */
    /******************************************************************/
    hi_u8 tid = (puc_payload[3] & 0x3C) >> 2; /* 3 Ԫ������ ����2λ */
    if (tid >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_req::addba req receive failed, tid %d}", tid);
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }

    if (hmac_user->ast_tid_info[tid].ba_rx_info != HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_req::addba req received, but tid [%d]}", tid);
        /* DTS2015042207613 addba rsp����ʧ��,�ٴ��ܵ�addba req���½���BA */
        hmac_ba_reset_rx_handle(&hmac_user->ast_tid_info[tid].ba_rx_info, tid);
    }

    hmac_user->ast_tid_info[tid].ba_rx_info =
        (hmac_ba_rx_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, (hi_u16) sizeof(hmac_ba_rx_stru));
    if (hmac_user->ast_tid_info[tid].ba_rx_info == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_req: ba_rx_hdl mem alloc fail.tid %d}", tid);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_ba_rx_stru *ba_rx_stru = hmac_user->ast_tid_info[tid].ba_rx_info;
    if (memset_s(ba_rx_stru, sizeof(hmac_ba_rx_stru), 0, sizeof(hmac_ba_rx_stru)) != EOK) {    /* �ڴ���0 */
        return HI_FAIL;
    }

    oal_spin_lock_init(&ba_rx_stru->st_ba_lock);
    hmac_mgmt_rx_addba_req_init(hmac_vap, hmac_user, puc_payload, ba_rx_stru, tid);

#ifdef _PRE_WLAN_FEATURE_AMPDU_VAP
    hmac_vap->rx_ba_session_num++;
#else
    hmac_dev->rx_ba_session_num++;
#endif

    /* �жϽ����ܷ�ɹ� */
    hi_u8 status = hmac_mgmt_check_set_rx_ba_ok(hmac_vap, ba_rx_stru, hmac_dev);
    if (status == MAC_SUCCESSFUL_STATUSCODE) {
        hmac_user->ast_tid_info[tid].ba_rx_info->ba_status = DMAC_BA_INPROGRESS;
    }

    hi_u32 ret = hmac_mgmt_tx_addba_rsp(hmac_vap, hmac_user, ba_rx_stru, tid, status);

    oam_warning_log4(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_req:tid %d,status %d,baw_start %d,baw_size %d}\n",
        tid, status, ba_rx_stru->us_baw_start, ba_rx_stru->us_baw_size);

    if ((status != MAC_SUCCESSFUL_STATUSCODE) || (ret != HI_SUCCESS)) {
        /* DTS2015042809320 Hi110x bug fix zengjun /00185449 2015/05/08 begin */
        /* pst_hmac_user->ast_tid_info[uc_tid].pst_ba_rx_info�޸�Ϊ�ں������ÿգ�������
           ����һ�� */
        hmac_ba_reset_rx_handle(&hmac_user->ast_tid_info[tid].ba_rx_info, tid);
        /* DTS2015042809320 Hi110x bug fix zengjun /00185449 2014/05/08 end */
    }

    return HI_SUCCESS;
}

hi_u32 hmac_mgmt_rx_addba_rsp_send_event(const hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user,
    const hi_u8 *puc_payload, hmac_tid_stru *tid, hi_u8 tidno)
{
    mac_vap_stru       *mac_vap   = hmac_vap->base_vap;
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_ctx_action_event_stru));

    if (event_mem == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_rsp::event_mem null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����¼�ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_BA_SYNC,
                       sizeof(dmac_ctx_action_event_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    /* ��ȡ֡����Ϣ������DMAC��ͬ������д�¼�payload */
    dmac_ctx_action_event_stru *rx_addba_rsp_event = (dmac_ctx_action_event_stru *)(event->auc_event_data);
    rx_addba_rsp_event->action_category = MAC_ACTION_CATEGORY_BA;
    rx_addba_rsp_event->action          = MAC_BA_ACTION_ADDBA_RSP;
    rx_addba_rsp_event->user_idx        = (hi_u8)hmac_user->base_user->us_assoc_id;
    rx_addba_rsp_event->stauts          = puc_payload[3]; /* 3 Ԫ������ */
    rx_addba_rsp_event->tidno           = tidno;
    rx_addba_rsp_event->dialog_token    = puc_payload[2]; /* 2 Ԫ������ */

    if (rx_addba_rsp_event->stauts != MAC_SUCCESSFUL_STATUSCODE) {
        /* ����HMACģ����Ϣ */
        hmac_ba_reset_tx_handle(&tid->ba_tx_info);
    } else {
        /* ֻ��״̬Ϊ�ɹ�ʱ�����б�Ҫ����Щ��Ϣ���ݸ�dmac */
        rx_addba_rsp_event->ba_policy     = ((puc_payload[5] & 0x02) >> 1); /* 5 Ԫ������ */
        rx_addba_rsp_event->us_ba_timeout = puc_payload[7] | (puc_payload[8] << 8); /* 7 8 Ԫ������ ����8λ */
        rx_addba_rsp_event->amsdu_supp    = puc_payload[5] & BIT0; /* 5 Ԫ������ */

        hi_u16 us_baw_size  = (hi_u16) (((puc_payload[5] & 0xC0) >> 6) | (puc_payload[6] << 2)); /* 5 6 ���� ����2λ */
        hi_u8  ampdu_max_num = (hi_u8) us_baw_size / WLAN_AMPDU_TX_SCHD_STRATEGY;

        rx_addba_rsp_event->ampdu_max_num = oal_max(ampdu_max_num, 1);
        rx_addba_rsp_event->us_baw_size   = us_baw_size;

        /* ����hmacģ���Ӧ��BA�������Ϣ */
        tid->ba_tx_info->ba_status = DMAC_BA_COMPLETE;
        tid->tx_ba_attemps = 0;
        if (rx_addba_rsp_event->amsdu_supp && hmac_vap->amsdu_ampdu_active) {
            hmac_user_set_amsdu_support(hmac_user, tidno);
        } else {
            /* ����꺯���а�����~���������ʽ�����б��������޷�����,�󱨸澯��lin_t e502�澯���� */
            hmac_user_set_amsdu_not_support(hmac_user, tidno);
        }
    }

    hcc_hmac_tx_control_event(event_mem, sizeof(dmac_ctx_action_event_stru));

    /* �ͷ��¼��ڴ� */
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ӿտڽ���ADDBA_RSP֡�Ĵ�����
 �޸���ʷ      :
  1.��    ��   : 2013��4��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_rx_addba_rsp(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, const hi_u8 *puc_payload)
{
    mac_action_mgmt_args_stru action_args;

    if ((hmac_vap == HI_NULL) || (hmac_user == HI_NULL) || (puc_payload == HI_NULL)) {
        oam_error_log3(0, OAM_SF_BA, "{hmac_mgmt_rx_addba_rsp::null param, %p %p %p.}", (uintptr_t)hmac_vap,
                       (uintptr_t)hmac_user, (uintptr_t)puc_payload);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hi_unref_param(mac_vap);
    /******************************************************************/
    /*       ADDBA Response Frame - Frame Body                        */
    /* --------------------------------------------------------------- */
    /* | Category | Action | Dialog | Status  | Parameters | Timeout | */
    /* --------------------------------------------------------------- */
    /* | 1        | 1      | 1      | 2       | 2          | 2       | */
    /* --------------------------------------------------------------- */
    /*                                                                */
    /******************************************************************/
    hi_u8 tidno = (puc_payload[5] & 0x3C) >> 2; /* 5: Ԫ���±� 2: ������λ */
    /* Э��֧��tidΪ0~15,02ֻ֧��tid0~7 */
    if (tidno >= WLAN_TID_MAX_NUM) {
        /* ����tid > 7��respֱ�Ӻ��� */
        oam_warning_log3(mac_vap->vap_id, OAM_SF_BA,
            "{hmac_mgmt_rx_addba_rsp::addba rsp tid[%d]} token[%d] state[%d]", tidno, puc_payload[2], /* 2 Ԫ������ */
            puc_payload[3]); /* 3 Ԫ������ */
        return HI_SUCCESS;
    }

    hmac_tid_stru *tid = &(hmac_user->ast_tid_info[tidno]);
    hi_u8 dialog_token = puc_payload[2]; /* 2 Ԫ������ */

    if (tid->ba_tx_info == HI_NULL) {
        /* ����DELBA֡ */
        action_args.category = MAC_ACTION_CATEGORY_BA;
        action_args.action = MAC_BA_ACTION_DELBA;
        action_args.arg1 = tidno;      /* ������֡��Ӧ��TID�� */
        action_args.arg2 = MAC_ORIGINATOR_DELBA;  /* DELBA�У�����ɾ��BA�Ự�ķ���� */
        action_args.arg3 = MAC_UNSPEC_QOS_REASON; /* DELBA�д���ɾ��reason */
        action_args.puc_arg5 = hmac_user->base_user->user_mac_addr;   /* DELBA�д���Ŀ�ĵ�ַ */

        if (hmac_mgmt_tx_delba(hmac_vap, hmac_user, &action_args) != HI_SUCCESS) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_BA, "hmac_mgmt_tx_delba return NON SUCCESS. ");
        }

        oam_warning_log1(mac_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_addba_rsp::tx ba info null.tid[%d]}", tidno);
        return HI_SUCCESS;
    }

    if ((tid->ba_tx_info->ba_status == DMAC_BA_COMPLETE) || (dialog_token != tid->ba_tx_info->dialog_token)) {
        oam_warning_log4(mac_vap->vap_id, OAM_SF_BA,
            "{hmac_mgmt_rx_addba_rsp::status ialog_token wrong.tid %d, status %d, rsp dialog %d, req dialog %d}",
            tidno, tid->ba_tx_info->ba_status, dialog_token, tid->ba_tx_info->dialog_token);
        return HI_SUCCESS;
    }
    /* ֹͣ��ʱ�� */
    frw_timer_immediate_destroy_timer(&(tid->ba_tx_info->addba_timer));

    /* ���¼���DMAC���� */
    hi_u32 ret = hmac_mgmt_rx_addba_rsp_send_event(hmac_vap, hmac_user, puc_payload, tid, tidno);
    return ret;
}

/*****************************************************************************
 ��������  : �ӿտڽ���DEL_BA֡�Ĵ�����
 �޸���ʷ      :
  1.��    ��   : 2013��4��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_rx_delba(const hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, const hi_u8 *puc_payload)
{
    if (oal_unlikely(puc_payload == HI_NULL)) {
        oam_error_log1(0, OAM_SF_BA, "{hmac_mgmt_rx_delba::null param, %p.}", (uintptr_t)puc_payload);
        return HI_ERR_CODE_PTR_NULL;
    }

    /************************************************/
    /*       DELBA Response Frame - Frame Body      */
    /* -------------------------------------------- */
    /* | Category | Action | Parameters | Reason  | */
    /* -------------------------------------------- */
    /* | 1        | 1      | 2          | 2       | */
    /* -------------------------------------------- */
    /*                                              */
    /************************************************/
    hi_u8 tid_value = (puc_payload[3] & 0xF0) >> 4; /* 3 Ԫ������ ����4λ */
    hi_u8 initiator = (puc_payload[3] & 0x08) >> 3; /* 3 Ԫ������ ����3λ */
    hi_u16 us_reason = (puc_payload[4] & 0xFF) | ((puc_payload[5] << 8) & 0xFF00); /* 4 5 Ԫ������ ����8λ */

    /* tid��������������Խ�� */
    if (tid_value >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(0, OAM_SF_BA, "{hmac_mgmt_rx_delba::delba receive failed, tid %d overflow.}", tid_value);
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }

    hmac_tid_stru *tid = &(hmac_user->ast_tid_info[tid_value]);
    hi_unref_param(us_reason);    /* ���ڽ���ر�ά���ı���澯���� */
    oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_BA,
                     "{hmac_mgmt_rx_delba::receive delba from peer sta, tid[%d], uc_initiator[%d], reason[%d].}",
                     tid_value, initiator, us_reason);
    /* ����BA���ͻỰ */
    if (initiator == MAC_RECIPIENT_DELBA) {
        if (tid->ba_tx_info == HI_NULL) {
            return HI_SUCCESS;
        }
        tid->ba_flag = 0;
        /* ��ԭ����AMPDU��AMSDU��֧����� */
        hmac_user_set_amsdu_support(hmac_user, tid_value);
        hmac_ba_reset_tx_handle(&tid->ba_tx_info);
    } else {                    /* ����BA���ջỰ */
        if (tid->ba_rx_info == HI_NULL) {
            return HI_SUCCESS;
        }
        hmac_ba_reset_rx_handle(&tid->ba_rx_info, tid_value);
    }

    /* ���¼���DMAC���� */
    /* �����¼����ص��ڴ�ָ�� */
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_ctx_action_event_stru));
    if ((event_mem == HI_NULL) || (event_mem->puc_data == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_BA, "{hmac_mgmt_rx_delba::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����¼�ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_BA_SYNC,
        sizeof(dmac_ctx_action_event_stru), FRW_EVENT_PIPELINE_STAGE_1, hmac_vap->base_vap->vap_id);

    /* ��д�¼�payload */
    dmac_ctx_action_event_stru *wlan_crx_action = (dmac_ctx_action_event_stru *)(event->auc_event_data);
    wlan_crx_action->action_category = MAC_ACTION_CATEGORY_BA;
    wlan_crx_action->action = MAC_BA_ACTION_DELBA;
    wlan_crx_action->user_idx = (hi_u8)hmac_user->base_user->us_assoc_id;
    wlan_crx_action->tidno = tid_value;
    wlan_crx_action->initiator = initiator;
    hcc_hmac_tx_control_event(event_mem, sizeof(dmac_ctx_action_event_stru));
    /* �ͷ��¼��ڴ� */
    frw_event_free(event_mem);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ADDBA req֡��ʱ����
 �޸���ʷ      :
  1.��    ��   : 2013��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_tx_addba_timeout(hi_void *arg)
{
    hmac_vap_stru *hmac_vap = HI_NULL;      /* vapָ�� */
    hi_u8 *da_mac_addr = HI_NULL;          /* �����û�Ŀ�ĵ�ַ��ָ�� */
    hmac_user_stru *hmac_user = HI_NULL;
    mac_action_mgmt_args_stru action_args;
    dmac_ba_alarm_stru *alarm_data = HI_NULL;
    hi_u32 ret;

    if (arg == HI_NULL) {
        oam_error_log0(0, OAM_SF_BA, "{hmac_mgmt_tx_addba_timeout::p_arg null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    alarm_data = (dmac_ba_alarm_stru *)arg;
    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(alarm_data->mac_user_idx);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_error_log0(0, OAM_SF_BA, "{hmac_mgmt_tx_addba_timeout::pst_hmac_user null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    da_mac_addr = hmac_user->base_user->user_mac_addr;

    hmac_vap = hmac_vap_get_vap_stru(alarm_data->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(hmac_user->base_user->vap_id, OAM_SF_BA,
                       "{hmac_mgmt_tx_addba_timeout::pst_hmac_user null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����DELBA֡ */
    action_args.category = MAC_ACTION_CATEGORY_BA;
    action_args.action = MAC_BA_ACTION_DELBA;
    action_args.arg1 = alarm_data->tid;    /* ������֡��Ӧ��TID�� */
    action_args.arg2 = MAC_ORIGINATOR_DELBA;      /* DELBA�У�����ɾ��BA�Ự�ķ���� */
    action_args.arg3 = MAC_QSTA_TIMEOUT;  /* DELBA�д���ɾ��reason */
    action_args.puc_arg5 = da_mac_addr;   /* DELBA�д���Ŀ�ĵ�ַ */

    ret = hmac_mgmt_tx_delba(hmac_vap, hmac_user, &action_args);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(hmac_user->base_user->vap_id, OAM_SF_BA, "hmac_mgmt_tx_delba return NON SUCCESS. ");
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��������AMPDU����Ҫ�Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_tx_ampdu_start(hmac_vap_stru *hmac_vap,
                                hmac_user_stru *hmac_user, mac_priv_req_args_stru *priv_req)
{
    frw_event_mem_stru *event_mem = HI_NULL;  /* �����¼����ص��ڴ�ָ�� */
    frw_event_stru *event = HI_NULL;
    mac_priv_req_args_stru *rx_ampdu_start_event = HI_NULL;
    hi_u8 tidno;
    hmac_tid_stru *tid = HI_NULL;
    hi_u32 ret;

    if ((hmac_vap == HI_NULL) || (hmac_user == HI_NULL) || (priv_req == HI_NULL)) {
        oam_error_log3(0, OAM_SF_AMPDU, "{hmac_mgmt_tx_ampdu_start::param null, %p %p %p.}", (uintptr_t)hmac_vap,
                       (uintptr_t)hmac_user, (uintptr_t)priv_req);
        return HI_ERR_CODE_PTR_NULL;
    }

    tidno = priv_req->arg1;
    tid = &(hmac_user->ast_tid_info[tidno]);

    /* AMPDUΪNORMAL ACKʱ����Ӧ��BA�Ựû�н������򷵻� */
    if (priv_req->arg3 == WLAN_TX_NORMAL_ACK) {
        if (tid->ba_tx_info == HI_NULL) {
            return HI_SUCCESS;
        }
    }

    /* ���¼���DMAC���� */
    event_mem = frw_event_alloc(sizeof(mac_priv_req_args_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU,
                       "{hmac_mgmt_tx_ampdu_start::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����¼�ָ�� */
    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_PRIV_REQ,
                       sizeof(mac_priv_req_args_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       hmac_vap->base_vap->vap_id);

    /* ��ȡ����AMPDU�Ĳ�������dmac�������� */
    rx_ampdu_start_event = (mac_priv_req_args_stru *)(event->auc_event_data);
    rx_ampdu_start_event->type = MAC_A_MPDU_START;
    rx_ampdu_start_event->arg1 = priv_req->arg1;
    rx_ampdu_start_event->arg2 = priv_req->arg2;
    rx_ampdu_start_event->arg3 = priv_req->arg3;
    rx_ampdu_start_event->user_idx = (hi_u8)hmac_user->base_user->us_assoc_id;       /* ���������Դ�ص����� */

    /* �ַ� */
    ret = hcc_hmac_tx_control_event(event_mem, sizeof(mac_priv_req_args_stru));

    /* �ͷ��¼��ڴ� */
    frw_event_free(event_mem);

    return ret;
}

/*****************************************************************************
 ��������  : ���ùر�AMPDU
 �޸���ʷ      :
  1.��    ��   : 2013��6��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_tx_ampdu_end(hmac_vap_stru *hmac_vap,
                              hmac_user_stru *hmac_user, mac_priv_req_args_stru *priv_req)
{
    frw_event_mem_stru *event_mem = HI_NULL;  /* �����¼����ص��ڴ�ָ�� */
    frw_event_stru *event = HI_NULL;
    mac_priv_req_args_stru *rx_ampdu_end_event = HI_NULL;
    hi_u32 ret;

    if ((hmac_vap == HI_NULL) || (hmac_user == HI_NULL) || (priv_req == HI_NULL)) {
        oam_error_log3(0, OAM_SF_AMPDU, "{hmac_mgmt_tx_ampdu_end::param null, %p %p %p.}",
                       (uintptr_t)hmac_vap, (uintptr_t)hmac_user, (uintptr_t)priv_req);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���¼���DMAC���� */
    event_mem = frw_event_alloc(sizeof(mac_priv_req_args_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU,
                       "{hmac_mgmt_tx_ampdu_end::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����¼�ָ�� */
    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_PRIV_REQ,
                       sizeof(mac_priv_req_args_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       hmac_vap->base_vap->vap_id);

    /* ��ȡ����AMPDU�Ĳ�������dmac�������� */
    rx_ampdu_end_event = (mac_priv_req_args_stru *)(event->auc_event_data);
    rx_ampdu_end_event->type = MAC_A_MPDU_END;   /* ���� */
    rx_ampdu_end_event->arg1 = priv_req->arg1;    /* tid no */
    rx_ampdu_end_event->user_idx = (hi_u8)hmac_user->base_user->us_assoc_id; /* ���������Դ�ص����� */

    /* �ַ� */
    ret = hcc_hmac_tx_control_event(event_mem, sizeof(mac_priv_req_args_stru));

    /* �ͷ��¼��ڴ� */
    frw_event_free(event_mem);

    return ret;
}

/*****************************************************************************
 ��������  : ���͹���֡���¼�
 �޸���ʷ      :
  1.��    ��   : 2013��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_tx_mgmt_send_event(const mac_vap_stru *mac_vap, oal_netbuf_stru *mgmt_frame, hi_u32 us_frame_len)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u32 return_code;
    dmac_tx_event_stru *ctx_stru = HI_NULL;

    /* ���¼���DMAC,��DMAC�������VAP���� */
    event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_SCAN, "{hmac_tx_mgmt_send_event::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_MGMT,
                       sizeof(dmac_tx_event_stru),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       mac_vap->vap_id);

    ctx_stru                = (dmac_tx_event_stru *)event->auc_event_data;
    ctx_stru->netbuf        = mgmt_frame;
    ctx_stru->us_frame_len  = us_frame_len;

    return_code = hcc_hmac_tx_data_event(event_mem, mgmt_frame, HI_TRUE);
    if (return_code != HI_SUCCESS) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_tx_mgmt_send_event::frw_event_dispatch_event failed[%d].}", return_code);
        frw_event_free(event_mem);
        return return_code;
    }

    /* �ͷ��¼� */
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �յ���֤���� ��������ʱ �����û��Ľ���״̬
 �޸���ʷ      :
  1.��    ��   : 2014��5��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��1��26��
    ��    ��   : Hisilicon
    �޸�����   : ����keepalive����
*****************************************************************************/
hi_u32 hmac_mgmt_reset_psm(const mac_vap_stru *mac_vap, hi_u8 user_id)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hi_u8  *puc_user_id = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;

    /* ������ֱ�������õ�һЩ����������Ҫ�ٴ�ͬ�� */
    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_id);
    if (oal_unlikely(mac_vap == HI_NULL || hmac_user == HI_NULL)) {
        oam_error_log2(0, OAM_SF_PWR,
            "{hmac_mgmt_reset_psm::mac_vap/hmac_user null! mac_vap=%p, hmac_user=%p}",
            (uintptr_t)mac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    event_mem = frw_event_alloc(sizeof(hi_u8));
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_PWR, "{hmac_mgmt_reset_psm::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_RESET_PSM,
                       sizeof(hi_u16),
                       FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

    puc_user_id = event->auc_event_data;
    *puc_user_id = user_id;
    hcc_hmac_tx_control_event(event_mem, sizeof(hi_u16));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
/*****************************************************************************
 ��������  : ���Operating Mode�ֶβ����Ƿ����
 �������  : pst_mac_user: MAC USER�ṹ��ָ��
             puc_payload : ָ��Operating Mode Notification IE��ָ��
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2014��6��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_ie_check_proc_opmode_param(mac_user_stru *mac_user,
                                              mac_opmode_notify_stru *opmode_notify)
{
    /* USER���޶������ռ������������������ */
    if ((mac_user->bandwidth_cap < opmode_notify->channel_width)
        || (mac_user->num_spatial_stream < opmode_notify->rx_nss)) {
        oam_warning_log4(mac_user->vap_id, OAM_SF_ANY,
            "{hmac_ie_check_proc_opmode_param:: cap over limit! bw_cap=[%d], op_bw=[%d],user_nss=[%d], op_nss=[%d]!}",
            mac_user->bandwidth_cap, opmode_notify->channel_width,
            mac_user->num_spatial_stream, opmode_notify->rx_nss);
        return HI_FAIL;
    }

    /* Nss TypeֵΪ1�����ʾbeamforming Rx Nss���ܳ���������ֵ */
    if (opmode_notify->rx_nss_type == 1) {
        if (mac_user->vht_hdl.vht_cap_info.num_bf_ant_supported < opmode_notify->rx_nss) {
            oam_warning_log2(mac_user->vap_id, OAM_SF_ANY,
                "{hmac_ie_check_proc_opmode_param::rx_nss over limit!ant_supported = [%d], rx_nss = [%d]!}",
                mac_user->vht_hdl.vht_cap_info.num_bf_ant_supported, opmode_notify->rx_nss);
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����Operating Mode�ֶ�
 �������  : pst_mac_user: MAC USER�ṹ��ָ��
             puc_payload : ָ��Operating Mode Notification IE��ָ��
 �� �� ֵ  : HI_SUCCESS������������
 �޸���ʷ      :
  1.��    ��   : 2014��6��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_ie_proc_opmode_field(mac_vap_stru *mac_vap, mac_user_stru *mac_user,
                                 mac_opmode_notify_stru *opmode_notify, hi_u8 mgmt_frm_type)
{
    wlan_bw_cap_enum_uint8 bwcap_vap = 0;    /* vap����������� */
    wlan_bw_cap_enum_uint8 avail_bw;         /* vap����������� */

    if (oal_unlikely((mac_user == HI_NULL) || (opmode_notify == HI_NULL) ||
        (mac_vap == HI_NULL))) {
        oam_error_log3(0, OAM_SF_ANY,
            "{hmac_ie_proc_opmode_field::pst_mac_user = [%x], pst_opmode_notify = [%x], pst_mac_vap = [%x]!}\r\n",
            mac_user, opmode_notify, mac_vap);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (HI_FAIL == hmac_ie_check_proc_opmode_param(mac_user, opmode_notify)) {
        oam_warning_log0(mac_user->vap_id, OAM_SF_ANY,
                         "{hmac_ie_proc_opmode_field::hmac_ie_check_proc_opmode_param return fail!}\r\n");
        return HI_FAIL;
    }

    /* �ж�Rx Nss Type�Ƿ�Ϊbeamformingģʽ */
    if (opmode_notify->rx_nss_type == 1) {
        oam_info_log0(mac_vap->vap_id, OAM_SF_ANY,
                      "{hmac_ie_proc_opmode_field::pst_opmode_notify->bit_rx_nss_type == 1!}\r\n");

        /* �ж�Rx Nss�Ƿ���user֮ǰʹ��Rx Nss��ͬ */
        if (opmode_notify->rx_nss != mac_user->avail_bf_num_spatial_stream) {
            mac_user_avail_bf_num_spatial_stream(mac_user, opmode_notify->rx_nss);
        }

        return HI_SUCCESS;
    }

    /* �ж�Rx Nss�Ƿ���user֮ǰʹ��Rx Nss��ͬ */
    if (opmode_notify->rx_nss != mac_user->avail_num_spatial_stream) {
        oam_info_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{hmac_ie_proc_opmode_field::opmode rx_nss = [%x], mac_user avail_num_spatial_stream = [%x]!}",
            opmode_notify->rx_nss, mac_user->avail_num_spatial_stream);
        /* ��AP������ȡ���� */
        mac_user_set_avail_num_spatial_stream(mac_user, oal_min(mac_vap->vap_rx_nss, opmode_notify->rx_nss));

        oam_info_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{hmac_ie_proc_opmode_field::change nss. mac_vap rx_nss=[%x], mac_user avail_num_spatial_stream=[%x]!}",
            mac_vap->vap_rx_nss, mac_user->avail_num_spatial_stream);
    }

    /* �ж�channel_width�Ƿ���user֮ǰʹ��channel_width��ͬ */
    if (opmode_notify->channel_width != mac_user->avail_bandwidth) {
        oam_info_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{hmac_ie_proc_opmode_field:: opmode channel_width = [%x], mac_user avail_bandwidth = [%x]!}",
            opmode_notify->channel_width, mac_user->avail_bandwidth);

        /* ��ȡvap�����������û����������Ľ��� */
        mac_vap_get_bandwidth_cap(mac_vap, &bwcap_vap);

        avail_bw = oal_min(bwcap_vap, opmode_notify->channel_width);
        mac_user_set_bandwidth_info(mac_user, avail_bw, avail_bw);

        oam_info_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{hmac_ie_proc_opmode_field::change bandwidth. bwcap_vap = [%x], mac_user avail_bandwidth = [%x]!}",
            bwcap_vap, mac_user->avail_bandwidth);
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_PMF
/*****************************************************************************
 ��������  : ��ʼSA Query timer1��ʱɾ��user
 �������  : pst_mac_vap:�Ҵ�user��vap
             puc_addr:��Ҫɾ����user mac��ַ
 �� �� ֵ  : HI_SUCCESS:ɾ���û��ɹ�
 �޸���ʷ      :
  1.��    ��   : 2014��4��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_sa_query_del_user(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user)
{
    wlan_vap_mode_enum_uint8 vap_mode;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u32 ret;
    mac_sa_query_stru *sa_query_info = HI_NULL;

    if ((mac_vap == HI_NULL) || (hmac_user == HI_NULL)) {
        oam_error_log2(0, OAM_SF_PMF, "{hmac_sa_query_del_user::param null, %p %p.}",
                       (uintptr_t)mac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_PMF, "{hmac_sa_query_del_user::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* pending SA Query requests ���������� & sa query���̿�ʼʱ������ */
    sa_query_info = &hmac_user->sa_query_info;
    sa_query_info->us_sa_query_count = 0;
    sa_query_info->sa_query_start_time = 0;

    /* �޸� state & ɾ�� user */
    vap_mode = mac_vap->vap_mode;
    switch (vap_mode) {
#ifdef _PRE_WLAN_FEATURE_MESH
        case WLAN_VAP_MODE_MESH:
#endif
        case WLAN_VAP_MODE_BSS_AP:
        {
            /* ���¼��ϱ��ںˣ��Ѿ�ȥ����ĳ��STA */
            hmac_handle_disconnect_rsp_ap(hmac_vap, hmac_user);
        }
            break;

        case WLAN_VAP_MODE_BSS_STA:
        {
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);

            /* �ϱ��ں�sta�Ѿ���ĳ��apȥ���� */
            /* hmac_sa_query_del_user, dmac_reason_code is 7 */
            hmac_sta_disassoc_rsp(hmac_vap, HMAC_REPORT_ACTION, DMAC_DISASOC_SA_QUERY_DEL_USER);
        }
            break;
        default:
            break;
    }

    /* ɾ��user */
    ret = hmac_user_del(hmac_vap->base_vap, hmac_user);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_PMF, "{hmac_sa_query_del_user::hmac_user_del failed[%d].}",
                       ret);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : hmac_start_sa_query���¼�������û������timer�Ĺ���
 �������  : pst_mac_vap:����SA��ѯ��mac vap�ṹ��
             puc_da:Ŀ��user��mac ��ַ
             en_is_protected:SA Query֡�ļ��ܱ�־λ
 �޸���ʷ      :
  1.��    ��   : 2014��4��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
 *****************************************************************************/
static hi_u32 hmac_send_sa_query_req(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user,
                                     hi_u8 is_protected, hi_u16 us_init_trans_id)
{
    if ((mac_vap == HI_NULL) || (hmac_user == HI_NULL)) {
        oam_error_log2(0, OAM_SF_PMF, "{hmac_send_sa_query_req::param null, %p %p.}",
                       (uintptr_t)mac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����SA Query ֡�ռ� */
    oal_netbuf_stru *sa_query = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);   /* align 4 */
    if (sa_query == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_PMF, "{hmac_send_sa_query_req::pst_sa_query null.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* ���� trans id */
    hmac_user->sa_query_info.us_sa_query_trans_id = us_init_trans_id + 1;
    /* ����sa query request������ */
    hmac_user->sa_query_info.us_sa_query_count += 1;
    /* ��װSA Query request֡ */
    if (memset_s(oal_netbuf_cb(sa_query), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_PMF, "{hmac_send_sa_query_req::memset_s fail.}");
        oal_netbuf_free(sa_query);
        return HI_FAIL;
    }
    hi_u16 sa_query_len = hmac_encap_sa_query_req(mac_vap, (hi_u8 *)oal_netbuf_header(sa_query),
                                                  hmac_user->base_user->user_mac_addr,
                                                  hmac_user->sa_query_info.us_sa_query_trans_id);
    if (sa_query_len == 0) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_PMF, "{hmac_send_sa_query_req::sa query len is 0.}");
        oal_netbuf_free(sa_query);
        return HI_FAIL;
    }
    /* ��������֡���� */
    if (is_protected == HI_TRUE) {
        mac_set_protectedframe((hi_u8 *)oal_netbuf_header(sa_query));
    }

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(sa_query); /* ��ȡcb�ṹ�� */
    tx_ctl->us_mpdu_len = sa_query_len;  /* dmac������Ҫ��mpdu���� */
    tx_ctl->us_tx_user_idx = MAC_INVALID_USER_ID;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(sa_query);
    tx_ctl->mac_head_type = 1;
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    oal_netbuf_put(sa_query, sa_query_len);

    /* Buffer this frame in the Memory Queue for transmission */
    hi_u32 ret = hmac_tx_mgmt_send_event(mac_vap, sa_query, sa_query_len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(sa_query);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_PMF,
                         "{hmac_send_sa_query_req::hmac_tx_mgmt_send_event failed[%d].}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ж��Ƿ���յ���ȥ����ȥ��֤֡����PMF���ԵĴ���
 �� �� ֵ  : HI_SUCCESS: �������PMF���ԵĴ���(�翪��sa query����)
 �޸���ʷ      :
  1.��    ��   : 2014��6��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_pmf_check_err_code(const mac_user_stru *user_base_info, hi_u8 is_protected,
                               const hi_u8 *puc_mac_hdr)
{
    hi_u8 aim_err_code;
    hi_u16 us_err_code;

    us_err_code = hi_makeu16(puc_mac_hdr[MAC_80211_FRAME_LEN], puc_mac_hdr[MAC_80211_FRAME_LEN + 1]);
    aim_err_code = ((MAC_NOT_AUTHED == us_err_code) || (MAC_NOT_ASSOCED == us_err_code)) ? HI_TRUE : HI_FALSE;

    if ((user_base_info->cap_info.pmf_active == HI_TRUE) &&
        (aim_err_code == HI_TRUE) && (is_protected == HI_FALSE)) {
        return HI_SUCCESS;
    }

    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ��ʼSA Query timer2��ʱ����
 �������  : p_arg:timer2��ʱ������νṹ��
 �� �� ֵ  : HI_SUCCESS:��ʱ����ɹ�
 �޸���ʷ      :
  1.��    ��   : 2014��4��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_sa_query_interval_timeout(hi_void *arg)
{
    hmac_interval_timer_stru *interval_timer_arg = HI_NULL;
    hi_u32 relt;

    if (arg == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_sa_query_interval_timeout::p_arg null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    interval_timer_arg = (hmac_interval_timer_stru *)arg;

    if ((interval_timer_arg->hmac_user == HI_NULL) ||
        (interval_timer_arg->hmac_user->base_user->user_asoc_state != MAC_USER_STATE_ASSOC)) {
        oam_error_log0(interval_timer_arg->mac_vap->vap_id, OAM_SF_ANY,
                       "{hmac_sa_query_interval_timeout::invalid param.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �ж��Ƿ�ʱ */
    if (interval_timer_arg->hmac_user->sa_query_info.us_sa_query_count >= 3) { /* 3 �߽� */
        relt = hmac_sa_query_del_user(interval_timer_arg->mac_vap, interval_timer_arg->hmac_user);
        if (relt != HI_SUCCESS) {
            oam_error_log1(interval_timer_arg->mac_vap->vap_id, OAM_SF_ANY,
                           "{hmac_sa_query_interval_timeout::hmac_sa_query_del_user failed[%d].}", relt);
            return HI_ERR_CODE_PMF_SA_QUERY_DEL_USER_FAIL;
        }
        return HI_SUCCESS;
    }

    /* ѭ������sa query request */
    relt = hmac_send_sa_query_req(interval_timer_arg->mac_vap, interval_timer_arg->hmac_user,
                                  interval_timer_arg->is_protected, interval_timer_arg->us_trans_id);
    if (relt != HI_SUCCESS) {
        oam_error_log1(interval_timer_arg->mac_vap->vap_id, OAM_SF_ANY,
                       "{hmac_sa_query_interval_timeout::hmac_send_sa_query_req failed[%d].}", relt);
        return HI_ERR_CODE_PMF_SA_QUERY_REQ_SEND_FAIL;
    }

    hi_u16 timeout = (hi_u16) mac_mib_get_dot11_association_saquery_retry_timeout(interval_timer_arg->mac_vap);
    frw_timer_restart_timer(&(interval_timer_arg->hmac_user->sa_query_info.sa_query_interval_timer), timeout, HI_TRUE);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼSA Query ��ѯ����
 �������  : pst_mac_vap:����SA��ѯ��mac vap�ṹ��
             puc_da:Ŀ��user��mac ��ַ
             en_is_protected:SA Query֡�ļ��ܱ�־λ
 �޸���ʷ      :
  1.��    ��   : 2014��4��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_start_sa_query(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user, hi_u8 is_protected)
{
    hi_u32 ret;
    hi_u16 us_init_trans_id;

    /* ����ж� */
    if ((mac_vap == HI_NULL) || (hmac_user == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_start_sa_query::param null, %p %p.}",
                       (uintptr_t)mac_vap, (uintptr_t)hmac_user);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �ж�vap����pmf���� */
    if (hmac_user->base_user->cap_info.pmf_active != HI_TRUE) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_start_sa_query::bit_pmf_active is down.}");
        return HI_ERR_CODE_PMF_DISABLED;
    }

    /* �����ظ�����SA Query���� */
    if (hmac_user->sa_query_info.us_sa_query_count != 0) {
        oam_info_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_start_sa_query::SA Query is already in process.}");
        return HI_SUCCESS;
    }

    /* ���hmac vap �ṹָ�� */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_start_sa_query::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ó�ʼtrans_id */
    us_init_trans_id = (hi_u16) hi_get_milli_seconds();

    /* ����timer��ʱ������� */
    hmac_interval_timer_stru *interval_timer_arg =
        (hmac_interval_timer_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(hmac_interval_timer_stru));
    if (interval_timer_arg == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_start_sa_query::pst_interval_timer_arg null.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    interval_timer_arg->mac_vap = mac_vap;
    interval_timer_arg->hmac_user = hmac_user;
    interval_timer_arg->is_protected = is_protected;
    interval_timer_arg->us_trans_id = us_init_trans_id;
    hi_u16 retry_timeout = (hi_u16) mac_mib_get_dot11_association_saquery_retry_timeout(mac_vap);

    /* ��¼sa query���̿�ʼʱ��,��λms */
    hmac_user->sa_query_info.sa_query_start_time = (hi_u32) hi_get_milli_seconds();
    /* ���ü����ʱ�� */
    frw_timer_create_timer(&(hmac_user->sa_query_info.sa_query_interval_timer),
                           hmac_sa_query_interval_timeout,
                           retry_timeout,
                           interval_timer_arg, HI_TRUE);

    /* ����SA Query request����ʼ��ѯ���� */
    ret = hmac_send_sa_query_req(mac_vap, hmac_user, is_protected, us_init_trans_id);
    if (ret != HI_SUCCESS) {
        if (hmac_user->sa_query_info.sa_query_interval_timer.is_enabled == HI_TRUE) {
            frw_timer_immediate_destroy_timer(&(hmac_user->sa_query_info.sa_query_interval_timer));
        }
        oam_error_log1(mac_vap->vap_id, OAM_SF_ANY, "{hmac_start_sa_query::hmac_send_sa_query_req failed[%d].}",
                       ret);
        oal_mem_free(interval_timer_arg);
        return HI_ERR_CODE_PMF_SA_QUERY_REQ_SEND_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����SA query response֡
 �������  : pst_mac_vap:����SA query responsed��mac vap�ṹ��
             pst_hdr:���յ�sa query request֡��֡ͷָ��
             en_is_protected:SA Query֡�ļ��ܱ�־λ
 �޸���ʷ      :
  1.��    ��   : 2014��4��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_send_sa_query_rsp(mac_vap_stru *mac_vap, hi_u8 *hdr, hi_u8 is_protected)
{
    hi_u16 us_sa_query_len;
    oal_netbuf_stru *sa_query = 0;
    hmac_tx_ctl_stru *tx_ctl = HI_NULL;
    hi_u32 ret;

    if (mac_vap == HI_NULL || hdr == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_send_sa_query_rsp::param null, %p %p.}",
                       (uintptr_t)mac_vap, (uintptr_t)hdr);
        return;
    }
    oam_info_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_send_sa_query_rsp::AP ready to TX a sa query rsp.}");

    sa_query = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);    /* align 4 */
    if (sa_query == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_send_sa_query_rsp::pst_sa_query null.}");
        return;
    }

    if (memset_s(oal_netbuf_cb(sa_query), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size()) != EOK) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_send_sa_query_rsp::memset_s fail!}");
        oal_netbuf_free(sa_query);
        return;
    }
    us_sa_query_len = hmac_encap_sa_query_rsp(mac_vap, hdr, (hi_u8 *)oal_netbuf_header(sa_query));
    if (us_sa_query_len == 0) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_send_sa_query_rsp::sa_query_len is 0!}");
        oal_netbuf_free(sa_query);
        return;
    }

    /* ��������֡���� */
    if (is_protected == HI_TRUE) {
        mac_set_protectedframe((hi_u8 *)oal_netbuf_header(sa_query));
    }

    tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(sa_query);      /* ��ȡcb�ṹ�� */
    tx_ctl->us_mpdu_len = us_sa_query_len;  /* dmac������Ҫ��mpdu���� */
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(sa_query);
    tx_ctl->mac_head_type = 1;
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    /* pmf5.3.3.4 ��֤ʧ�ܣ��޷�����sa response֡ */
    /* ���������Ҫ��ȡuser�ṹ�� */
    oal_netbuf_put(sa_query, us_sa_query_len);

    /* Buffer this frame in the Memory Queue for transmission */
    ret = hmac_tx_mgmt_send_event(mac_vap, sa_query, us_sa_query_len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(sa_query);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY,
                         "{hmac_send_sa_query_rsp::hmac_tx_mgmt_send_event failed[%d].}", ret);
    }

    return;
}
#endif
/*****************************************************************************
 ��������  : ����ȥ��֤֡
 �޸���ʷ      :
  1.��    ��   : 2013��7��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_mgmt_send_deauth_frame(mac_vap_stru *mac_vap, const hi_u8 *da_mac_addr, hi_u8 addr_len, hi_u16 err_code)
{
    hi_u8             user_idx   = 0xff;

    if ((mac_vap == HI_NULL) || (da_mac_addr == HI_NULL)) {
        oam_error_log2(0, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame::%p %p.}", (uintptr_t)mac_vap, (uintptr_t)mac_vap);
        return;
    }

    /* ����ȥ��֤ǰ��ȷ��vap���ڹ���״̬ */
    if (mac_vap->vap_state == MAC_VAP_STATE_BUTT) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame:vap_state%d}", mac_vap->vap_state);
        return;
    }

    oal_netbuf_stru  *deauth = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);    /* align 4 */
    if (deauth == HI_NULL) {
        deauth = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);                  /* align 4 */
        if (deauth == HI_NULL) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame::pst_deauth null.}");
            return;
        }
    }
    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(oal_netbuf_cb(deauth), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    hi_u16 deauth_len = hmac_mgmt_encap_deauth(mac_vap, (hi_u8 *)oal_netbuf_header(deauth), da_mac_addr, err_code);
    if (deauth_len == 0) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame:: us_deauth_len = 0.}");
        oal_netbuf_free(deauth);
        return;
    }
    oal_netbuf_put(deauth, deauth_len);

    /* ���ӷ���ȥ��֤֡ʱ��ά����Ϣ */
    oam_warning_log4(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame::frameXX:XX:XX:%2x:%2x:%2x,code[%d]}",
                     da_mac_addr[3], da_mac_addr[4], da_mac_addr[5], err_code); /* 3 4 5 Ԫ������ */

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(deauth);        /* ��ȡcb�ṹ�� */
    tx_ctl->us_mpdu_len = deauth_len;    /* dmac������Ҫ��mpdu���� */
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(deauth);
    tx_ctl->mac_head_type = 1;

    mac_vap_set_cb_tx_user_idx(mac_vap, tx_ctl, da_mac_addr);

    /* Buffer this frame in the Memory Queue for transmission */
    if (hmac_tx_mgmt_send_event(mac_vap, deauth, deauth_len) != HI_SUCCESS) {
        oal_netbuf_free(deauth);
        oam_warning_log0(mac_vap->vap_id, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame::hmac_tx_mgmt failed.}");
    }

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        hmac_vap_stru    *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
        if ((mac_vap_find_user_by_macaddr(mac_vap, da_mac_addr, addr_len, &user_idx) != HI_SUCCESS) ||
            (hmac_vap == HI_NULL)) {
            oam_warning_log0(0, OAM_SF_AUTH, "{hmac_mgmt_send_deauth_frame:mac_vap_find_user failed or hmac_vap null}");
            return;
        }

        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
    }
}

hi_u32 hmac_mgmt_send_disassoc_frame_param_check(mac_vap_stru *mac_vap, const hi_u8 *da_mac_addr)
{
    if (mac_vap == HI_NULL || da_mac_addr == HI_NULL) {
        oam_error_log2(0, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame_param_check::%p %p}",
            (uintptr_t)mac_vap, (uintptr_t)da_mac_addr);
        return HI_FAIL;
    }

    /* ����ȥ����ǰ��ȷ��vap���ڹ���״̬ */
    if (mac_vap->vap_state == MAC_VAP_STATE_BUTT) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame_param_check:state %d}",
            mac_vap->vap_state);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ȥ����֡
 �������  : vapָ��, DA, errcode
 �޸���ʷ      :
  1.��    ��   : 2014��1��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_mgmt_send_disassoc_frame(mac_vap_stru *mac_vap, const hi_u8 *da_mac_addr, hi_u16 err_code,
                                      hi_u8 is_protected)
{
    if (hmac_mgmt_send_disassoc_frame_param_check(mac_vap, da_mac_addr) != HI_SUCCESS) {
        return;
    }

    oal_netbuf_stru *disassoc = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);   /* align 4 */
    if (disassoc == HI_NULL) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame::pst_disassoc null.}");
        return;
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    hi_u32 pedding_data = 0;
    hmac_config_scan_abort(mac_vap, sizeof(hi_u32), (hi_u8 *)&pedding_data);
#endif

    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(oal_netbuf_cb(disassoc), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

    hi_u16 mpdu_len = hmac_mgmt_encap_disassoc(mac_vap, (hi_u8 *)oal_netbuf_header(disassoc), da_mac_addr, err_code);
    if (mpdu_len == 0) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame:: us_disassoc_len = 0.}");
        oal_netbuf_free(disassoc);
        return;
    }
#ifdef _PRE_WLAN_FEATURE_PMF
    if (is_protected == HI_TRUE) {
        mac_set_protectedframe((hi_u8 *)oal_netbuf_header(disassoc));
    }
#endif

    /* ���ӷ���ȥ����֡ʱ��ά����Ϣ */
    oam_warning_log4(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame:ecode[%d],da xx:xx:xx:%2x:%2x:%2x}",
        err_code, da_mac_addr[3], da_mac_addr[4], da_mac_addr[5]); /* 3 4 5 Ԫ������ */

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(disassoc);
    tx_ctl->us_mpdu_len = mpdu_len;
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(disassoc);
    tx_ctl->mac_head_type = 1;

    mac_vap_set_cb_tx_user_idx(mac_vap, tx_ctl, da_mac_addr);

    oal_netbuf_put(disassoc, mpdu_len);

    /* ���뷢�Ͷ��� */
    if (hmac_tx_mgmt_send_event(mac_vap, disassoc, mpdu_len) != HI_SUCCESS) {
        oal_netbuf_free(disassoc);
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame::hmac_tx_mgmt failed.}");
    }

    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
        if (hmac_vap == HI_NULL) {
            oam_error_log1(mac_vap->vap_id, OAM_SF_ASSOC, "{hmac_mgmt_send_disassoc_frame:vap_id:%d}", mac_vap->vap_id);
            return;
        }

        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);
    }
}

/*****************************************************************************
 ��������  : ���¶�Ӧ����ʵ���qos������Ϣ:�����Ĺ������ڹ����û�WMMʹ�ܵ������
             ��dmac���¼�д�Ĵ�������������û�֮ǰ����WMMʹ�ܵģ��򲻱��ظ�д��
             ���������֮ǰ����WMMʹ�ܵģ�����Ҳ����WMMʹ�ܵģ�����д�Ĵ���
 �������  : puc_payload :ָ��֡���ָ��
             ul_msg_len  :֡�ĳ���
             us_info_elem_offset:Ŀǰ֡��λ�õ�ƫ��
             pst_hmac_user      :ָ��hmac_user��ָ��
 �޸���ʷ      :
  1.��    ��   : 2013��10��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_mgmt_update_assoc_user_qos(hi_u8 *puc_payload,
                                        hi_u16 us_msg_len,
                                        hi_u16 us_info_elem_offset, const hmac_user_stru *hmac_user)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u16 us_msg_idx = us_info_elem_offset;

    /* ��������û�֮ǰ����wmmʹ�ܵģ�ʲô����������ֱ�ӷ���  */
    if (hmac_user->base_user->cap_info.qos == HI_TRUE) {
        oam_info_log0(hmac_user->base_user->vap_id, OAM_SF_ASSOC,
                      "{hmac_mgmt_update_assoc_user_qos_table::assoc user is wmm cap already.}");
        return;
    }

    mac_user_set_qos(hmac_user->base_user, HI_FALSE);
    while (us_msg_idx < us_msg_len) {
        if (mac_is_wmm_ie(&puc_payload[us_msg_idx]) == HI_TRUE) {
            mac_user_set_qos(hmac_user->base_user, HI_TRUE);
            break;
        }
        us_msg_idx += (puc_payload[us_msg_idx + 1] + MAC_IE_HDR_LEN);
    }

    mac_vap_stru *mac_vap = mac_vap_get_vap_stru(hmac_user->base_user->vap_id);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_error_log0(hmac_user->base_user->vap_id, OAM_SF_ASSOC,
                       "{hmac_mgmt_update_assoc_user_qos_table::pst_mac_vap null.}");
        return;
    }

    if (us_msg_len <= us_info_elem_offset) {
        oam_error_log0(hmac_user->base_user->vap_id, OAM_SF_ASSOC,
                       "{hmac_mgmt_update_assoc_user_qos_table::msg_len less offset.}");
        return;
    }

    puc_ie = mac_find_ie(MAC_EID_WMM, puc_payload + us_info_elem_offset, us_msg_len - us_info_elem_offset);
    if (puc_ie != HI_NULL) {
        mac_user_set_qos(hmac_user->base_user,
                         mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented);
    } else {
        if (is_sta(mac_vap)) {
            puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_payload + us_info_elem_offset, us_msg_len - us_info_elem_offset);
            /* ����HT CAP������2�ֽ�BIT5 short GI for 20M ����λ */
            if ((puc_ie != HI_NULL) && ((puc_ie[1] >= OAL_IE_HDR_LEN) && (puc_ie[2] & BIT5))) {
                mac_user_set_qos(hmac_user->base_user, HI_TRUE);
            }
        }
    }

    /* ��������û���������Ȼ����wmmʹ�ܵģ�ʲôҲ������ֱ�ӷ��� */
    if (hmac_user->base_user->cap_info.qos == HI_FALSE) {
        oam_info_log0(hmac_user->base_user->vap_id, OAM_SF_ASSOC,
                      "{hmac_mgmt_update_assoc_user_qos_table::assoc user is not wmm cap.}");
        return;
    }
}

/*****************************************************************************
 ��������  : check capabilities info field ��mac��Ϣ����BSS type, Privacy���Ƿ���VAP���
 �޸���ʷ      :
  1.��    ��   : 2013��12��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_check_bss_cap_info(hi_u16 us_cap_info, mac_vap_stru *mac_vap)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    wlan_mib_desired_bsstype_enum_uint8 bss_type;

    /* ��ȡCAP INFO��BSS TYPE */
    bss_type = mac_get_bss_type(us_cap_info);

    hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL || mac_vap->mib_info == HI_NULL) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_CFG, "{hmac_check_bss_cap_info::hmac_vap/mib_info null.}");
        return HI_FALSE;
    }

    /* �Ƚ�BSS TYPE�Ƿ�һ�� ��һ�£������STA��Ȼ�������������Ӽ����ԣ�����ģʽ�򷵻ز�֧�� */
#ifdef  _PRE_WLAN_FEATURE_MESH
    if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        if ((bss_type != mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type)
            && (bss_type != WLAN_MIB_DESIRED_BSSTYPE_ANY)) {
            oam_warning_log1(mac_vap->vap_id, OAM_SF_ASSOC,
                             "{hmac_check_bss_cap_info::MESH:asoc_user_bss_type[%d] is different from any and Infra}",
                             bss_type);
        }
    } else {
        if (bss_type != mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type) {
            oam_warning_log2(mac_vap->vap_id, OAM_SF_ASSOC,
                             "{hmac_check_bss_cap_info::vap_bss_type[%d] is different from asoc_user_bss_type[%d].}",
                             mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type, bss_type);
        }
    }
#else
    if (bss_type != mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_ASSOC,
                         "{hmac_check_bss_cap_info::vap_bss_type[%d] is different from asoc_user_bss_type[%d].}",
                         mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type, bss_type);
    }
#endif

    if (hmac_vap->wps_active == HI_TRUE) {
        return HI_TRUE;
    }

    /* �Ƚ�CAP INFO��privacyλ������Ƿ���ܣ����ܲ�һ�£�����ʧ�� */
    if (!mac_check_mac_privacy(us_cap_info, (hi_u8 *)mac_vap)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ASSOC,
                         "{hmac_check_bss_cap_info::mac privacy capabilities is different.}");
    }

    return HI_TRUE;
}

/*****************************************************************************
 ��������  : ��ȡ�û���Э��ģʽ
 �޸���ʷ      :
  1.��    ��   : 2013��10��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_set_user_protocol_mode(const mac_vap_stru *mac_vap, hmac_user_stru *hmac_user)
{
    mac_user_ht_hdl_stru *mac_ht_hdl = HI_NULL;
    mac_user_stru *mac_user = HI_NULL;
    hi_u32 is_support_11g;
    hi_u32 is_support_11b;

    /* ��ȡHT��VHT�ṹ��ָ�� */
    mac_user = hmac_user->base_user;
    mac_ht_hdl = &(mac_user->ht_hdl);

    if (mac_ht_hdl->ht_capable == HI_TRUE) {
        mac_user_set_protocol_mode(mac_user, WLAN_HT_MODE);
    } else {
        is_support_11g = hmac_is_support_11grate(hmac_user->op_rates.auc_rs_rates, hmac_user->op_rates.rs_nrates);
        is_support_11b = hmac_is_support_11brate(hmac_user->op_rates.auc_rs_rates, hmac_user->op_rates.rs_nrates);
        if (is_support_11g == HI_TRUE) {
            mac_user_set_protocol_mode(mac_user, WLAN_LEGACY_11G_MODE);
            if (is_support_11b == HI_TRUE) {
                mac_user_set_protocol_mode(mac_user, WLAN_MIXED_ONE_11G_MODE);
            }
        } else if (is_support_11b == HI_TRUE) {
            mac_user_set_protocol_mode(mac_user, WLAN_LEGACY_11B_MODE);
        } else {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY,
                             "{hmac_set_user_protocol_mode::set user protocol failed.}");
        }
    }

    /* ���������⣺˼��AP 2.4G��11b����5G(11a)����ʱ���͵�assoc rsp֡Я�������ʷֱ���11g��11b��
       ����STA�����û�ʱ֪ͨ�㷨ʧ�ܣ�AutorateʧЧ��DBAC����£�DBAC�޷������ѹ�����VAP״̬�޷��ָ������� ��ʱ������
       ������ԶԶ������쳣�����ͳһ�����Ż� */
    if (((mac_user->protocol_mode == WLAN_LEGACY_11B_MODE) && (mac_vap->protocol == WLAN_LEGACY_11A_MODE)) ||
        ((mac_user->protocol_mode == WLAN_LEGACY_11G_MODE) && (mac_vap->protocol == WLAN_LEGACY_11B_MODE))) {
        mac_user_set_protocol_mode(mac_user, mac_vap->protocol);
        if (memcpy_s((hi_void *)&(hmac_user->op_rates), sizeof(mac_rate_stru),
            (hi_void *)&(mac_vap->curr_sup_rates.rate), sizeof(mac_rate_stru)) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_set_user_protocol_mode:: st_rate memcpy_s fail.");
            return;
        }
    }
}

#ifdef _PRE_WLAN_FEATURE_PMF
/*****************************************************************************
 ��������  : AP��UP״̬�µĽ���SA Query request֡����
 �������  : pst_hmac_vap: HMAC VAPָ��
             pst_netbuf  : ����֡���ڵ�sk_buff
             en_is_protected �˹���֡�Ƿ��ܵ�������
 �޸���ʷ      :
  1.��    ��   : 2014��4��09��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_sa_query_req(hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf,
                             hi_u8 is_protected)
{
    hi_u8 *sa_mac_addr = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hi_u8 *puc_mac_hdr = HI_NULL;

    if ((hmac_vap == HI_NULL) || (netbuf == HI_NULL)) {
        oam_error_log2(0, OAM_SF_RX, "{hmac_rx_sa_query_req::null param %p %p.}",
                       (uintptr_t)hmac_vap, (uintptr_t)netbuf);
        return;
    }

    puc_mac_hdr = oal_netbuf_header(netbuf);

    mac_rx_get_sa((mac_ieee80211_frame_stru *)puc_mac_hdr, &sa_mac_addr);
    hmac_user = mac_vap_get_hmac_user_by_addr(hmac_vap->base_vap, sa_mac_addr, WLAN_MAC_ADDR_LEN);
    if (hmac_user == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                       "{hmac_rx_sa_query_req::pst_hmac_user null.}");
        return;
    }

    /* ������û��Ĺ���֡�������Բ�һ�£������ñ��� */
    if (is_protected != hmac_user->base_user->cap_info.pmf_active) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                       "{hmac_rx_sa_query_req::PMF check failed.}");
        return;
    }

    /* sa Query rsp���� */
    hmac_send_sa_query_rsp(hmac_vap->base_vap, puc_mac_hdr, is_protected);

    return;
}

 /*****************************************************************************
��������  : UP״̬�µĽ���SA Query rsponse֡����
�������  : pst_hmac_vap   : HMAC VAPָ��
            pst_netbuf     : ����֡���ڵ�sk_buff
            en_is_protected: ��������֡���ܵı�־λ
�޸���ʷ      :
   1.��    ��   : 2014��4��09��
    ��    ��   : Hisilicon
     �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_sa_query_rsp(hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf,
                             hi_u8 is_protected)
{
    hi_u8 *puc_mac_hdr = HI_NULL;
    hi_u8 *sa_mac_addr = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hi_u16 *pus_trans_id = HI_NULL;
    mac_sa_query_stru *sa_query_info = HI_NULL;

    if ((hmac_vap == HI_NULL) || (netbuf == HI_NULL)) {
        oam_error_log2(0, OAM_SF_AMPDU, "{hmac_rx_sa_query_rsp::param null,%p %p.}",
                       (uintptr_t)hmac_vap, (uintptr_t)netbuf);
        return;
    }

    puc_mac_hdr = oal_netbuf_header(netbuf);

    mac_rx_get_sa((mac_ieee80211_frame_stru *)puc_mac_hdr, &sa_mac_addr);
    hmac_user = mac_vap_get_hmac_user_by_addr(hmac_vap->base_vap, sa_mac_addr, WLAN_MAC_ADDR_LEN);
    if (hmac_user == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU,
                       "{hmac_rx_sa_query_rsp::pst_hmac_user null.}");
        return;
    }

    /* ������û��Ĺ���֡�������Բ�һ�£������ñ��� */
    if (is_protected != hmac_user->base_user->cap_info.pmf_active) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU,
                       "{hmac_rx_sa_query_rsp::PMF check failed.}");
        return;
    }

    /* �Ա�trans_id */
    pus_trans_id = (hi_u16 *)(puc_mac_hdr + MAC_80211_FRAME_LEN + 2); /* 2 ƫ���� */
    sa_query_info = &hmac_user->sa_query_info;

    /* �յ���Ч��SA query reqponse������������Ч��SA */
    if (0 == memcmp(pus_trans_id, &(sa_query_info->us_sa_query_trans_id), 2)) { /* 2 ���Ƴ��� */
        /* pending SA Query requests ���������� & sa query���̿�ʼʱ������ */
        sa_query_info->us_sa_query_count = 0;
        sa_query_info->sa_query_start_time = 0;

        /* ɾ��timer */
        if (sa_query_info->sa_query_interval_timer.is_registerd != HI_FALSE) {
            frw_timer_immediate_destroy_timer(&(sa_query_info->sa_query_interval_timer));
        }

        /* ɾ��timers����δ洢�ռ� */
        if (sa_query_info->sa_query_interval_timer.timeout_arg != HI_NULL) {
            oal_mem_free((hi_void *)sa_query_info->sa_query_interval_timer.timeout_arg);
            sa_query_info->sa_query_interval_timer.timeout_arg = HI_NULL;
        }
    }
    return;
}
#endif
#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
hi_u32 hmac_send_psm_opmode_notify_event(hmac_vap_stru *hmac_vap, mac_user_stru *mac_user, hi_u8 user_idx)
{
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(hi_u8));
    if (event_mem == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_ANY, "{hmac_mgmt_rx_opmode_notify_frame:event_allocErr}");
        return HI_FAIL;
    }

    /* ��д�¼� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_PSM_OPMODE_NOTIFY,
                       sizeof(hi_u16), FRW_EVENT_PIPELINE_STAGE_1, mac_user->vap_id);

    event->auc_event_data[0] = user_idx;

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(hi_u16));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ӿտڽ���opmode_notify֡�Ĵ�����
 �޸���ʷ      :
  1.��    ��   : 2014��6��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_mgmt_rx_opmode_notify_frame(hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf)
{
    hi_u8 user_idx = 0;
    hi_u8 sta_mac_addr[WLAN_MAC_ADDR_LEN] = {0};

    if ((mac_mib_get_VHTOptionImplemented(hmac_vap->base_vap) == HI_FALSE) ||
        (mac_mib_get_operating_mode_notification_implemented(hmac_vap->base_vap) == HI_FALSE)) {
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_ANY,
                      "{hmac_mgmt_rx_opmode_notify_frame::the vap is not support OperatingModeNotification}");
        return HI_SUCCESS;
    }

    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    mac_get_address2((hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr, WLAN_MAC_ADDR_LEN, sta_mac_addr, WLAN_MAC_ADDR_LEN);

    hi_u32 ret = mac_vap_find_user_by_macaddr(hmac_vap->base_vap, sta_mac_addr, WLAN_MAC_ADDR_LEN, &user_idx);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_SMPS, "{hmac_mgmt_rx_opmode_notify_frame:Err=%d}", ret);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_user_stru *mac_user = mac_user_get_user_stru(user_idx);
    if (mac_user == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_SMPS, "{hmac_mgmt_rx_opmode_notify_frame::mac_user null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ֡��ָ�� */
    hi_u8 *puc_data      = (hi_u8 *)rx_ctrl->pul_mac_hdr_start_addr;
    hi_u8  mgmt_frm_type = mac_get_frame_sub_type(puc_data);

    /* �Ƿ���Ҫ����Power Management bitλ */
    mac_ieee80211_frame_stru *mac_header = (mac_ieee80211_frame_stru *)puc_data;
    hi_u8 power_save = (hi_u8) mac_header->frame_control.power_mgmt;

    /* �������λ����(bit_power_mgmt == 1),���¼���DMAC�������û�������Ϣ */
    if ((power_save == HI_TRUE) && ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        || (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        )) {
        if (hmac_send_psm_opmode_notify_event(hmac_vap, mac_user, user_idx) != HI_SUCCESS) {
            return HI_FAIL;
        }
    }

    /****************************************************/
    /*   OperatingModeNotification Frame - Frame Body   */
    /* ------------------------------------------------- */
    /* |   Category   |   Action   |   OperatingMode   | */
    /* ------------------------------------------------- */
    /* |   1          |   1        |   1               | */
    /* ------------------------------------------------- */
    /*                                                  */
    /****************************************************/
    /* ��ȡpayload��ָ�� */
    hi_u8 *puc_frame_payload = puc_data + MAC_80211_FRAME_LEN;
    mac_opmode_notify_stru *opmode_notify = (mac_opmode_notify_stru*)(puc_frame_payload + MAC_ACTION_OFFSET_ACTION + 1);

    ret = hmac_ie_proc_opmode_field(hmac_vap->base_vap, mac_user, opmode_notify, mgmt_frm_type);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_user->vap_id, OAM_SF_CFG, "{hmac_mgmt_rx_opmode_notify_frame::proc_opmode Err=%d}", ret);
        return ret;
    }

    /* opmodeϢͬ��dmac */
    ret = hmac_config_update_opmode_event(hmac_vap->base_vap, mac_user, mgmt_frm_type);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(mac_user->vap_id, OAM_SF_CFG, "{hmac_mgmt_rx_opmode_notify_frame::update_opmode Err=%d}", ret);
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : �ϱ����յ��Ĺ���֡
 �������  : [1]hmac_vap
             [2]puc_buf
             [3]us_len
             [4]l_freq
 �� �� ֵ  : ��
*****************************************************************************/
hi_void hmac_send_mgmt_to_host(const hmac_vap_stru *hmac_vap,
                               oal_netbuf_stru *netbuf, hi_u16 us_len, hi_s32 l_freq)
{
    hmac_rx_mgmt_event_stru mgmt_frame;
    hmac_rx_ctl_stru *rx_info = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    hi_u8 *mgmt_data = (hi_u8 *)oal_memalloc(us_len);
    if (mgmt_data == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_SCAN, "{hmac_send_mgmt_to_host::pst_mgmt_data null.}");
        return;
    }
    memcpy_s(mgmt_data, us_len, (hi_u8 *)rx_info->pul_mac_hdr_start_addr, us_len);

    /* ��д�ϱ�����֡���� */
    mgmt_frame.puc_buf = (hi_u8 *)mgmt_data;
    mgmt_frame.us_len = us_len;
    mgmt_frame.l_freq = l_freq;
    oal_netbuf_len(netbuf) = us_len;

    memcpy_s(mgmt_frame.ac_name, OAL_IF_NAME_SIZE, hmac_vap->net_device->name, OAL_IF_NAME_SIZE);
#ifdef _PRE_WLAN_FEATURE_P2P
    mac_ieee80211_frame_stru *frame_hdr = (mac_ieee80211_frame_stru *)(rx_info->pul_mac_hdr_start_addr);
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    if (!is_legacy_vap(mac_vap)) {
        /* �����P2P�豸������P2P vap ����һ��vap ��Ӧ���hal_vap ���
         * ��P2P vap ������һ��vap ��Ӧ���hal_vap ���
         * �ԱȽ��յ��Ĺ���֡vap_id �Ƿ��vap ��hal_vap_id ��ͬ
         * �ӹ���֡cb�ֶ��е�hal vap id ����Ӧ��Ϣ���Ҷ�Ӧ��net dev ָ��
         */
        if (oal_compare_mac_addr(frame_hdr->auc_address1,
                                 mac_vap->mib_info->wlan_mib_sta_config.auc_p2p0_dot11_station_id,
                                 WLAN_MAC_ADDR_LEN) == 0) {
            /* �ڶ���net dev�� */
            memcpy_s(mgmt_frame.ac_name, OAL_IF_NAME_SIZE, hmac_vap->p2p0_net_device->name, OAL_IF_NAME_SIZE);
        } else if (oal_compare_mac_addr(frame_hdr->auc_address1,
                                        mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id,
                                        WLAN_MAC_ADDR_LEN) == 0) {
            memcpy_s(mgmt_frame.ac_name, OAL_IF_NAME_SIZE, hmac_vap->net_device->name, OAL_IF_NAME_SIZE);
        } else {
            oal_free(mgmt_data);
            return;
        }
    }
#endif
    if (hmac_send_event_to_host(hmac_vap->base_vap, (const hi_u8*)(&mgmt_frame),
        sizeof(hmac_rx_mgmt_event_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_RX_MGMT) != HI_SUCCESS) {
        oal_free(mgmt_data);
    }
    return;
}

/*****************************************************************************
 ��������  : ����wpa_supplicant action frame
 �޸���ʷ      :
  1.��    ��   : 2014��12��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_wpas_mgmt_tx(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hi_unref_param(us_len);
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_P2P, "{hmac_wpas_mgmt_tx::param null,%p %p}", (uintptr_t)mac_vap, (uintptr_t)mac_vap);
        return HI_FAIL;
    }

    mac_mgmt_frame_stru *mgmt_tx = (mac_mgmt_frame_stru *)puc_param;
    oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P, "{hmac_wpas_mgmt_tx::mgmt frame id=[%d]}", mgmt_tx->mgmt_frame_id);

    /*  ����netbuf �ռ� */
    oal_netbuf_stru *netbuf_mgmt_tx = (oal_netbuf_stru *)oal_netbuf_alloc(mgmt_tx->us_len, 0, 4);   /* align 4 */
    if (netbuf_mgmt_tx == HI_NULL) {
        netbuf_mgmt_tx = (oal_netbuf_stru *)oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);          /* align 4 */
        if (netbuf_mgmt_tx == HI_NULL) {
            oam_error_log0(mac_vap->vap_id, OAM_SF_P2P, "{hmac_wpas_mgmt_tx::pst_mgmt_tx null.}");
            return HI_FAIL;
        }
    }
    if (memset_s(oal_netbuf_cb(netbuf_mgmt_tx), sizeof(hmac_tx_ctl_stru), 0, sizeof(hmac_tx_ctl_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wpas_mgmt_tx::memset_s fail.");
        oal_netbuf_free(netbuf_mgmt_tx);
        return HI_FAIL;
    }

    /* ���netbuf */
    if (mgmt_tx->puc_frame != HI_NULL) {
        if (memcpy_s((hi_u8 *)oal_netbuf_header(netbuf_mgmt_tx), mgmt_tx->us_len, mgmt_tx->puc_frame,
            mgmt_tx->us_len) != EOK) {
            oal_netbuf_free(netbuf_mgmt_tx);
            oam_error_log0(0, OAM_SF_CFG, "hmac_wpas_mgmt_tx:: pst_mgmt_tx memcpy_s fail.");
            return HI_FAIL;
        }
    }
    oal_netbuf_put(netbuf_mgmt_tx, mgmt_tx->us_len);

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf_mgmt_tx);        /* ��ȡcb�ṹ�� */
    tx_ctl->us_mpdu_len = mgmt_tx->us_len;      /* dmac������Ҫ��mpdu���� */
    tx_ctl->need_rsp = HI_TRUE;
    tx_ctl->is_vipframe = HI_TRUE;
    tx_ctl->is_needretry = HI_TRUE;
    tx_ctl->mgmt_frame_id = mgmt_tx->mgmt_frame_id;
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)oal_netbuf_header(netbuf_mgmt_tx);
    tx_ctl->mac_head_type = 1;
    tx_ctl->frame_header_length = MAC_80211_FRAME_LEN;

    mac_vap_set_cb_tx_user_idx(mac_vap, tx_ctl, tx_ctl->frame_header->auc_address1);   /* ���������Ҫ��ȡuser�ṹ�� */

    /* Buffer this frame in the Memory Queue for transmission */
    hi_u32 ret = hmac_tx_mgmt_send_event(mac_vap, netbuf_mgmt_tx, mgmt_tx->us_len);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(netbuf_mgmt_tx);
        oam_warning_log1(mac_vap->vap_id, OAM_SF_P2P, "{hmac_wpas_mgmt_tx::hmac_tx_mgmt_send_event failed[%d].}", ret);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���յ�����֡���ϱ�host
 �������  : hmac_vap_stru *pst_hmac_vap
             oal_netbuf_stru *pst_netbuf
 �޸���ʷ      :
  1.��    ��   : 2015��7��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_mgmt_send_to_host(const hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf)
{
    hmac_rx_ctl_stru *rx_info = HI_NULL;
    hi_s32 l_freq;

    rx_info = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);

    l_freq = oal_ieee80211_channel_to_frequency(rx_info->channel_number,
                                                (rx_info->channel_number >
                                                 14) ? IEEE80211_BAND_5GHZ : IEEE80211_BAND_2GHZ); /* 14 �����ж� */
    hmac_send_mgmt_to_host(hmac_vap, netbuf, rx_info->us_frame_len, l_freq);
}
/*****************************************************************************
 ��������  : ����dmac�ϱ�����֡���͵Ľ��,�ϱ�WAL
 �޸���ʷ      :
  1.��    ��   : 2014��12��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* �ṹ������g_ast_hmac_config_syn��Աhmac_config_syn_stru(dmac_config_syn_stru)�����к���ָ��
   dmac_config_data_acq_status����ָ������ݽ������޸ģ�lin_t e818�澯���� */
hi_u32 hmac_mgmt_tx_event_status(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    dmac_crx_mgmt_tx_status_stru *mgmt_tx_status_param = HI_NULL;
    if (mac_vap == HI_NULL || puc_param == HI_NULL) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_mgmt_tx_event_status::pst_mac_vap[%p] NULL or pst_puc_param[%p] NULL!}",
            (uintptr_t)mac_vap, (uintptr_t)puc_param);
        return HI_ERR_CODE_PTR_NULL;
    }
    hi_unref_param(len);

    mgmt_tx_status_param = (dmac_crx_mgmt_tx_status_stru *)puc_param;

    oam_warning_log3(mac_vap->vap_id, OAM_SF_P2P,
        "{hmac_mgmt_tx_event_status::dmac tx mgmt status report.userindx[%d], tx mgmt status[%d], frame_id[%d]}",
        mgmt_tx_status_param->user_idx, mgmt_tx_status_param->tx_status, mgmt_tx_status_param->mgmt_frame_id);

    return hmac_send_event_to_host(mac_vap, (const hi_u8*)mgmt_tx_status_param,
        sizeof(dmac_crx_mgmt_tx_status_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_MGMT_TX_STATUS);
}

/*****************************************************************************
 ��������  : ��ȡ�û���VAP���õ�11a/b/g��������
 �޸���ʷ      :
  1.��    ��   : 2013��10��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_vap_set_user_avail_rates(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user)
{
    mac_user_stru *mac_user = HI_NULL;
    mac_curr_rateset_stru *mac_vap_rate = HI_NULL;
    mac_rate_stru *mac_user_rate = HI_NULL;
    mac_rate_stru avail_op_rates;
    hi_u8 mac_vap_rate_num;
    hi_u8 mac_user_rate_num;
    hi_u8 vap_rate_idx;
    hi_u8 user_rate_idx;
    hi_u8 user_avail_rate_idx = 0;

    /* ��ȡVAP��USER���ʵĽṹ��ָ�� */
    mac_user = hmac_user->base_user;
    mac_vap_rate = &(mac_vap->curr_sup_rates);
    mac_user_rate = &(hmac_user->op_rates);
    if (memset_s((hi_u8 *)(&avail_op_rates), sizeof(mac_rate_stru), 0, sizeof(mac_rate_stru)) != EOK) {
        return;
    }

    mac_vap_rate_num = mac_vap_rate->rate.rs_nrates;
    mac_user_rate_num = mac_user_rate->rs_nrates;

    for (vap_rate_idx = 0; vap_rate_idx < mac_vap_rate_num; vap_rate_idx++) {
        for (user_rate_idx = 0; user_rate_idx < mac_user_rate_num; user_rate_idx++) {
            if ((mac_vap_rate->rate.ast_rs_rates[vap_rate_idx].mac_rate > 0) &&
                ((mac_vap_rate->rate.ast_rs_rates[vap_rate_idx].mac_rate & 0x7F) ==
                 (mac_user_rate->auc_rs_rates[user_rate_idx] & 0x7F))) {
                avail_op_rates.auc_rs_rates[user_avail_rate_idx] =
                    mac_vap_rate->rate.ast_rs_rates[vap_rate_idx].mac_rate;
                user_avail_rate_idx++;
                avail_op_rates.rs_nrates++;
            }
        }
    }

    mac_user_set_avail_op_rates(mac_user, avail_op_rates.rs_nrates, avail_op_rates.auc_rs_rates);
    if (avail_op_rates.rs_nrates == 0) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY,
                         "{hmac_vap_set_user_avail_rates::uc_avail_op_rates_num=0.}");
    }
}

/*****************************************************************************
 ��������  : ����ht_cap_ie����������Ӧ��vap��user����
 �޸���ʷ      :
  1.��    ��   : 2015��6��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_proc_ht_cap_ie(mac_vap_stru *mac_vap, mac_user_stru *mac_user, const hi_u8 *puc_ht_cap_ie)
{
    hi_u16 us_offset = 0;

    if ((mac_vap == HI_NULL) || (mac_user == HI_NULL) || (puc_ht_cap_ie == HI_NULL)) {
        oam_warning_log3(0, OAM_SF_ANY,
                         "{hmac_proc_ht_cap_ie::PARAM NULL! vap=[%p],user=[%p],cap_ie=[%p].}",
                         (uintptr_t)mac_vap, (uintptr_t)mac_user, (uintptr_t)puc_ht_cap_ie);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����֧��11n�Ž��к����Ĵ��� */
    if (HI_FALSE == mac_mib_get_high_throughput_option_implemented(mac_vap)) {
        return HI_SUCCESS;
    }

    mac_user_set_ht_capable(mac_user, HI_TRUE);

    mac_user_ht_hdl_stru *ht_hdl = &mac_user->ht_hdl;

    /* ���� HT Capability Element �� AP����ʾ������HT capable. */
    ht_hdl->ht_capable = HI_TRUE;

    us_offset += MAC_IE_HDR_LEN;

    /********************************************/
    /*     ���� HT Capabilities Info Field      */
    /********************************************/
    hi_u16 us_ht_cap_info = hi_makeu16(puc_ht_cap_ie[us_offset], puc_ht_cap_ie[us_offset + 1]);

    /* ���STA��֧�ֵ�LDPC�������� B0��0:��֧�֣�1:֧�� */
    ht_hdl->ht_capinfo.ldpc_coding_cap = (us_ht_cap_info & BIT0);

    /* ��ȡAP��֧�ֵĴ�������  */
    ht_hdl->ht_capinfo.supported_channel_width = ((us_ht_cap_info & BIT1) >> 1);

    /* ���ռ临�ý���ģʽ B2~B3 */
    ht_hdl->ht_capinfo.sm_power_save = mac_ie_proc_sm_power_save_field((hi_u8)(us_ht_cap_info & (BIT2 | BIT3)));

    /* ��ȡAP֧��Greenfield��� */
    ht_hdl->ht_capinfo.ht_green_field = ((us_ht_cap_info & BIT4) >> 4); /* ����4λ */

    /* ��ȡAP֧��20MHz Short-GI��� */
    ht_hdl->ht_capinfo.short_gi_20mhz = ((us_ht_cap_info & BIT5) >> 5); /* ����5λ */

    /* ��ȡAP֧��40MHz Short-GI��� */
    ht_hdl->ht_capinfo.short_gi_40mhz = ((us_ht_cap_info & BIT6) >> 6); /* ����6λ */

    /* ��ȡAP֧��STBC PPDU��� */
    ht_hdl->ht_capinfo.rx_stbc = (hi_u8) ((us_ht_cap_info & 0x30) >> 4); /* ����4λ */

    /* ��ȡAP 40M��DSSS/CCK��֧����� */
    ht_hdl->ht_capinfo.dsss_cck_mode_40mhz = ((us_ht_cap_info & BIT12) >> 12); /* ����12λ */

    /* ��ȡAP L-SIG TXOP ������֧����� */
    ht_hdl->ht_capinfo.lsig_txop_protection = ((us_ht_cap_info & BIT15) >> 15); /* ����15λ */

    us_offset += MAC_HT_CAPINFO_LEN;

    /********************************************/
    /*     ���� A-MPDU Parameters Field         */
    /********************************************/
    /* ��ȡ Maximum Rx A-MPDU factor (B1 - B0) */
    ht_hdl->max_rx_ampdu_factor = (puc_ht_cap_ie[us_offset] & 0x03);

    /* ��ȡ Minmum Rx A-MPDU factor (B3 - B2) */
    ht_hdl->min_mpdu_start_spacing = (puc_ht_cap_ie[us_offset] >> 2) & 0x07;

    us_offset += MAC_HT_AMPDU_PARAMS_LEN;

    /********************************************/
    /*     ���� Supported MCS Set Field         */
    /********************************************/
    for (hi_u8 mcs_bmp_index = 0; mcs_bmp_index < WLAN_HT_MCS_BITMASK_LEN; mcs_bmp_index++) {
        ht_hdl->rx_mcs_bitmask[mcs_bmp_index] =
            (mac_vap->mib_info->supported_mcstx.auc_dot11_supported_mcs_tx_value[mcs_bmp_index]) &
            (*(hi_u8 *)(puc_ht_cap_ie + us_offset + mcs_bmp_index));
    }

    ht_hdl->rx_mcs_bitmask[WLAN_HT_MCS_BITMASK_LEN - 1] &= 0x1F;

    us_offset += MAC_HT_SUP_MCS_SET_LEN;

    /********************************************/
    /* ���� HT Extended Capabilities Info Field */
    /********************************************/
    us_ht_cap_info = hi_makeu16(puc_ht_cap_ie[us_offset], puc_ht_cap_ie[us_offset + 1]);

    /* ��ȡ HTC support Information */
    ht_hdl->htc_support = ((us_ht_cap_info & BIT10) >> 10); /* ����10λ */

    us_offset += MAC_HT_EXT_CAP_LEN;

    /********************************************/
    /*  ���� Tx Beamforming Field               */
    /********************************************/
    hi_u16 us_tmp_info_elem = hi_makeu16(puc_ht_cap_ie[us_offset], puc_ht_cap_ie[us_offset + 1]);
    hi_u16 us_tmp_txbf_low = hi_makeu16(puc_ht_cap_ie[us_offset + 2], puc_ht_cap_ie[us_offset + 3]); /* 2 3 ƫ���� */
    hi_u32 tmp_txbf_elem = hi_makeu32(us_tmp_info_elem, us_tmp_txbf_low);
    mac_ie_txbf_set_ht_hdl(ht_hdl, tmp_txbf_elem);

    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
