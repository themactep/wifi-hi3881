/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: The DMAC module receives the common operation function of the frame and the source file defined
                by the operation function of the data frame.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_frame.h"
#include "mac_data.h"
#include "hmac_rx_data.h"
#include "dmac_ext_if.h"
#include "hmac_vap.h"
#include "hmac_ext_if.h"
#include "oam_ext_if.h"
#include "oal_ext_if.h"
#include "oal_net.h"
#include "hmac_frag.h"
#include "hmac_11i.h"
#include "mac_vap.h"
#include "hmac_blockack.h"
#include "hmac_mgmt_bss_comm.h"
#include "hcc_hmac_if.h"
#include "wal_cfg80211_apt.h"
#ifdef _PRE_WLAN_FEATURE_WAPI
#include "hmac_wapi.h"
#endif
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
#include "hmac_edca_opt.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ����ʵ��
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_MESH
hi_void hmac_rx_process_data_mesh_tcp_ack_opt(hmac_vap_stru *hmac_vap, const oal_netbuf_head_stru *netbuf_header);
#endif

/*****************************************************************************
 ��������  : ��MSDUת��Ϊ��̫����ʽ��֡
 �������  : pst_netbuf : ָ����MSDU��netbuf��ָ��
             puc_da     : Ŀ�ĵ�ַ
             puc_sa     : Դ��ַ
 �޸���ʷ      :
  1.��    ��   : 2013��12��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_rx_frame_80211_to_eth(oal_netbuf_stru *netbuf,
    const hi_u8 *da_mac_addr, hi_u8 da_addr_len, const hi_u8 *sa_mac_addr, hi_u8 sa_addr_len)
{
    mac_ether_header_stru *ether_hdr = HI_NULL;
    mac_llc_snap_stru *snap = HI_NULL;
    hi_u16 us_ether_type;

    snap = (mac_llc_snap_stru *)oal_netbuf_data(netbuf);
    us_ether_type = snap->us_ether_type;

    /* ��payload��ǰ����6���ֽڣ����Ϻ���8���ֽڵ�snapͷ�ռ䣬������̫��ͷ��14�ֽڿռ� */
    oal_netbuf_push(netbuf, HMAC_RX_DATA_ETHER_OFFSET_LENGTH);
    ether_hdr = (mac_ether_header_stru *)oal_netbuf_data(netbuf);

    ether_hdr->us_ether_type = us_ether_type;
    if (memcpy_s(ether_hdr->auc_ether_shost, ETHER_ADDR_LEN,  sa_mac_addr, sa_addr_len) != EOK) {
        return;
    }
    if (memcpy_s(ether_hdr->auc_ether_dhost, ETHER_ADDR_LEN,  da_mac_addr, da_addr_len) != EOK) {
        return;
    }
}

/*****************************************************************************
 ��������  : �ͷ�ָ��������netbuf
 �������  : (1)����ɾ����netbuf����ʼָ��
             (2)��Ҫɾ����netbuf�ĸ���
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��12��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_free_netbuf(oal_netbuf_stru *netbuf, hi_u16 us_nums)
{
    oal_netbuf_stru *netbuf_temp = HI_NULL;
    hi_u16 us_netbuf_num;

    if (oal_unlikely(netbuf == HI_NULL)) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_rx_free_netbuf::pst_netbuf null.}\r\n");
        return;
    }

    for (us_netbuf_num = us_nums; us_netbuf_num > 0; us_netbuf_num--) {
        netbuf_temp = oal_netbuf_next(netbuf);

        /* ����netbuf��Ӧ��user���ü��� */
        oal_netbuf_free(netbuf);

        netbuf = netbuf_temp;
        if (netbuf == HI_NULL) {
            if (oal_unlikely(us_netbuf_num != 1)) {
                oam_error_log2(0, OAM_SF_RX,
                               "{hmac_rx_free_netbuf::pst_netbuf list broken, us_netbuf_num[%d]us_nums[%d].}",
                               us_netbuf_num, us_nums);
                return;
            }

            break;
        }
    }
}

/*****************************************************************************
 ��������  : free netbuff list
 �޸���ʷ      :
  1.��    ��   : 2015��1��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_free_netbuf_list(oal_netbuf_head_stru *netbuf_hdr, hi_u16 num_buf)
{
    oal_netbuf_stru *netbuf = HI_NULL;
    hi_u16 us_idx;

    if (oal_unlikely(netbuf_hdr == HI_NULL)) {
        oam_info_log0(0, OAM_SF_RX, "{hmac_rx_free_netbuf_list::pst_netbuf null.}");
        return;
    }

    for (us_idx = num_buf; us_idx > 0; us_idx--) {
        netbuf = oal_netbuf_delist(netbuf_hdr);
        if (netbuf != HI_NULL) {
            oal_netbuf_free(netbuf);
        }
    }
}

/*****************************************************************************
 ��������  : ������֡���͵�WLAN��Ľӿں�������һ��netbuf���׸��������̣�ÿ��
             netbuf�����ݶ���һ����̫����ʽ��MSDU
 �������  : (1)ָ���¼�ͷ��ָ��
             (2)ָ����Ҫ���͵�netbuf�ĵ�һ��Ԫ�ص�ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��11��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2016��06��20��
    ��    ��   : Hisilicon
    �޸�����   : DTS2016061403606:�޸�wlan to wlan ����ת��Ϊֱ�ӷ��ͣ�����Ҫ���¼�
*****************************************************************************/
static hi_u32 hmac_rx_transmit_to_wlan(frw_event_hdr_stru *event_hdr,
                                       oal_netbuf_head_stru *netbuf_head)
{
    oal_netbuf_stru *netbuf = HI_NULL;        /* ��netbuf����ȡ������ָ��netbuf��ָ�� */
    hi_u32 netbuf_num;
    hi_u32 ret;
    oal_netbuf_stru *buf_tmp = HI_NULL;       /* �ݴ�netbufָ�룬����whileѭ�� */
    hmac_tx_ctl_stru *tx_ctl = HI_NULL;
    mac_vap_stru *mac_vap = HI_NULL;

    if (oal_unlikely((event_hdr == HI_NULL) || (netbuf_head == HI_NULL))) {
        oam_error_log2(0, OAM_SF_RX, "{hmac_rx_transmit_to_wlan::param null, %p %p.}",
                       (uintptr_t)event_hdr, (uintptr_t)netbuf_head);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ��ͷ��net buffer */
    netbuf = oal_netbuf_peek(netbuf_head);

    /* ��ȡmac vap �ṹ */
    ret = hmac_tx_get_mac_vap(event_hdr->vap_id, &mac_vap);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        netbuf_num = oal_netbuf_list_num(netbuf_head);
        hmac_rx_free_netbuf(netbuf, (hi_u16) netbuf_num);
        oam_warning_log3(event_hdr->vap_id, OAM_SF_RX,
                         "{hmac_rx_transmit_to_wlan::find vap [%d] failed[%d], free [%d] netbuffer.}",
                         event_hdr->vap_id, ret, netbuf_num);
        return ret;
    }

    /* ѭ������ÿһ��netbuf��������̫��֡�ķ�ʽ���� */
    while (netbuf != HI_NULL) {
        buf_tmp = oal_netbuf_next(netbuf);
        oal_netbuf_next(netbuf) = HI_NULL;
        oal_netbuf_prev(netbuf) = HI_NULL;

        /* תWLAN�ı��ĳ��ȱ������ETHER_HDR_LEN,�����쳣���� */
        if (oal_netbuf_len(netbuf) < ETHER_HDR_LEN) {
            hmac_free_netbuf_list(netbuf);
            netbuf = buf_tmp;
            continue;
        }

        tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
        if (memset_s(tx_ctl, sizeof(hmac_tx_ctl_stru), 0, sizeof(hmac_tx_ctl_stru)) != EOK) {
            hmac_free_netbuf_list(netbuf);
            netbuf = buf_tmp;
            continue;
        }

        tx_ctl->event_type = FRW_EVENT_TYPE_WLAN_DTX;
        tx_ctl->event_sub_type = DMAC_TX_WLAN_DTX;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        /* set the queue map id when wlan to wlan */
        oal_skb_set_queue_mapping(netbuf, WLAN_NORMAL_QUEUE);
#endif

        ret = hmac_tx_lan_to_wlan(mac_vap, netbuf);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            hmac_free_netbuf_list(netbuf);
        }
        netbuf = buf_tmp;
    }

    return HI_SUCCESS;
}

hi_void hmac_rx_set_msdu_state(oal_netbuf_stru *netbuf, hmac_msdu_proc_state_stru *msdu_state)
{
    if (msdu_state->procd_msdu_in_netbuf == 0) {
        msdu_state->curr_netbuf = netbuf;

        /* AMSDUʱ���׸�netbuf���а���802.11ͷ����Ӧ��payload��Ҫƫ�� */
        hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(msdu_state->curr_netbuf);

        msdu_state->puc_curr_netbuf_data = (hi_u8 *)(rx_ctrl->pul_mac_hdr_start_addr) + rx_ctrl->mac_header_len;
        msdu_state->msdu_nums_in_netbuf = rx_ctrl->msdu_in_buffer;
        msdu_state->us_submsdu_offset = 0;
    }
}

/*****************************************************************************
 ��������  : ������ÿһ��AMSDU�е�MSDU
 �������  : ָ��MPDU�ĵ�һ��netbuf��ָ��
 �������  : (1)ָ��ǰҪת����MSDU��ָ��
             (2)���ڼ�¼����ǰ��MPDU��MSDU����Ϣ
             (3)��ǰMPDU�Ĵ���״̬:��ʶ��MPDU�Ƿ������
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��11��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_rx_parse_amsdu(oal_netbuf_stru *netbuf,
                           hmac_msdu_stru *msdu,
                           hmac_msdu_proc_state_stru *msdu_state,
                           hmac_msdu_proc_status_enum_uint8 *pen_proc_state)
{
    hi_u16 submsdu_len  = 0; /* submsdu�ĳ��� */
    hi_u8  submsdu_pad_len = 0; /* submsdu����䳤�� */

    /* �״ν���ú�������AMSDU */
    hmac_rx_set_msdu_state(netbuf, msdu_state);

    /* ָ��netbuf�������ָ�� */
    hi_u8 *submsdu = msdu_state->puc_curr_netbuf_data + msdu_state->us_submsdu_offset;

    /* ��ȡsubmsdu�������Ϣ */
    mac_get_submsdu_len(submsdu, &submsdu_len);
    if (submsdu_len > oal_netbuf_len(netbuf)) {
        oam_error_log2(0, OAM_SF_RX, "hmac_rx_parse_amsdu::msduLen=%d,bufLen=%d", submsdu_len, oal_netbuf_len(netbuf));
        return HI_FAIL;
    }
    mac_get_submsdu_pad_len(MAC_SUBMSDU_HEADER_LEN + submsdu_len, &submsdu_pad_len);

    if ((memcpy_s(msdu->auc_sa, WLAN_MAC_ADDR_LEN, (submsdu + MAC_SUBMSDU_SA_OFFSET), WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(msdu->auc_da, WLAN_MAC_ADDR_LEN, (submsdu + MAC_SUBMSDU_DA_OFFSET), WLAN_MAC_ADDR_LEN) != EOK)) {
        return HI_FAIL;
    }

#ifdef _PRE_LWIP_ZERO_COPY
    /* ����pbuf */
    msdu->netbuf = oal_pbuf_netbuf_alloc(MAC_SUBMSDU_HEADER_LEN + submsdu_len + submsdu_pad_len);
#else
    /* ��Ե�ǰ��netbuf�������µ�subnetbuf�������ö�Ӧ��netbuf����Ϣ����ֵ����Ӧ��msdu */
    msdu->netbuf = oal_netbuf_alloc((MAC_SUBMSDU_HEADER_LEN + submsdu_len + submsdu_pad_len), 0, 4);    /* align 4 */
#endif
    if (msdu->netbuf == HI_NULL) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_rx_parse_amsdu::pst_netbuf null.}");
        return HI_FAIL;
    }

    /* ���ÿһ����msdu���޸�netbuf��end��data��tail��lenָ�� */
#ifdef _PRE_LWIP_ZERO_COPY
    oal_netbuf_put(msdu->netbuf, submsdu_len + PBUF_ZERO_COPY_RESERVE);
    oal_netbuf_pull(msdu->netbuf, PBUF_ZERO_COPY_RESERVE);
#else
    oal_netbuf_put(msdu->netbuf, submsdu_len + HMAC_RX_DATA_ETHER_OFFSET_LENGTH);
    oal_netbuf_pull(msdu->netbuf, HMAC_RX_DATA_ETHER_OFFSET_LENGTH);
#endif

    if (memcpy_s(msdu->netbuf->data, submsdu_len, (submsdu + MAC_SUBMSDU_HEADER_LEN), submsdu_len) != EOK) {
        oal_netbuf_free(msdu->netbuf);
        oam_error_log0(0, OAM_SF_CFG, "hmac_rx_parse_amsdu:: puc_submsdu_hdr memcpy_s fail.");
        return HI_FAIL;
    }

    /* ���ӵ�ǰ�Ѵ����msdu�ĸ��� */
    msdu_state->procd_msdu_in_netbuf++;

    /* ��ȡ��ǰ��netbuf�е���һ��msdu���д��� */
    if (msdu_state->procd_msdu_in_netbuf < msdu_state->msdu_nums_in_netbuf) {
        msdu_state->us_submsdu_offset += submsdu_len + submsdu_pad_len + MAC_SUBMSDU_HEADER_LEN;
        *pen_proc_state = MAC_PROC_MORE_MSDU;
    } else if (msdu_state->procd_msdu_in_netbuf == msdu_state->msdu_nums_in_netbuf) {
        *pen_proc_state = MAC_PROC_LAST_MSDU;
        oal_netbuf_free(msdu_state->curr_netbuf);
    }

    return HI_SUCCESS;
}

hi_u32 hmac_rx_msdu_proc(const hmac_vap_stru *hmac_vap, oal_netbuf_head_stru *netbuf_header,
    oal_netbuf_stru *netbuf, mac_ieee80211_frame_stru *frame_hdr, const hmac_rx_ctl_stru *rx_ctrl)
{
    hi_u8  sa_mac_addr[WLAN_MAC_ADDR_LEN];
    hi_u8  da_mac_addr[WLAN_MAC_ADDR_LEN];
    hi_u8 *source_mac_addr = HI_NULL;
    hi_u8 *dest_mac_addr   = HI_NULL;

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(rx_ctrl->us_ta_user_idx);
    if (oal_unlikely(hmac_user == HI_NULL)) {
        return HI_ERR_CODE_PTR_NULL;
    }

    netbuf = hmac_defrag_process(hmac_user, netbuf, rx_ctrl->mac_header_len);
    if (netbuf == HI_NULL) {
        return HI_SUCCESS;
    }

    rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;

    /* ��MACͷ�л�ȡԴ��ַ��Ŀ�ĵ�ַ */
    mac_rx_get_sa(frame_hdr, &source_mac_addr);
    mac_rx_get_da(frame_hdr, &dest_mac_addr);
    if ((memcpy_s(sa_mac_addr, WLAN_MAC_ADDR_LEN, source_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(da_mac_addr, WLAN_MAC_ADDR_LEN, dest_mac_addr, WLAN_MAC_ADDR_LEN) != EOK)) {
        return HI_FAIL;
    }

    /* ��netbuf��dataָ��ָ��mac frame��payload����Ҳ����ָ����8�ֽڵ�snapͷ */
    oal_netbuf_pull(netbuf, rx_ctrl->mac_header_len);

    /* ��MSDUת��Ϊ��̫����ʽ��֡ */
    hmac_rx_frame_80211_to_eth(netbuf, da_mac_addr, WLAN_MAC_ADDR_LEN, sa_mac_addr, WLAN_MAC_ADDR_LEN);

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ�� */
    memset_s(oal_netbuf_cb(netbuf), oal_netbuf_cb_size(), 0, oal_netbuf_cb_size());

#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    mac_ether_header_stru *ether = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
    if (ether == HI_NULL) {
        return HI_FAIL;
    }
    if (hmac_11i_ether_type_filter(hmac_vap, ether->auc_ether_shost, ether->us_ether_type) != HI_SUCCESS) {
        return HI_FAIL;
    } else {
        /* ��MSDU���뵽netbuf������� */
        oal_netbuf_add_to_list_tail(netbuf, netbuf_header);
    }
#else
    /* ��MSDU���뵽netbuf������� */
    oal_netbuf_add_to_list_tail(netbuf, netbuf_header);
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����MPDU������Ƿ�AMSDU����MSDU��ԭΪ��̫����ʽ��֡�������뵽
             netbuf������������MPDU��AMSDU���������ÿһ��MSDU������ÿһ
             ��MSDUռ��һ��netbuf
 �������  : pst_netbuf_header: Ҫ�����������̵�netbuf����ͷ
             pst_netbuf       : ��ǰҪ�����MPDU�ĵ�һ��netbuf
             pst_frame_hdr    : ��ǰҪ�����MPDU��MACͷ
 �� �� ֵ  : �ɹ����ߴ�����
 �޸���ʷ      :
  1.��    ��   : 2013��12��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_rx_prepare_msdu_list_to_wlan(const hmac_vap_stru *hmac_vap,
                                                oal_netbuf_head_stru *netbuf_header,
                                                oal_netbuf_stru *netbuf,
                                                mac_ieee80211_frame_stru *frame_hdr)
{
    hmac_msdu_stru msdu = {0};     /* �������������ÿһ��MSDU */
    hmac_msdu_proc_state_stru msdu_state = {0};    /* ��¼MPDU�Ĵ�����Ϣ */
    hmac_msdu_proc_status_enum_uint8 process_state = MAC_PROC_BUTT;   /* ����AMSDU��״̬ */
    hi_u32 ret;
    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf); /* ��ȡ��MPDU�Ŀ�����Ϣ */

    /* ���һ:����AMSDU�ۺϣ����MPDU��Ӧһ��MSDU��ͬʱ��Ӧһ��NETBUF,��MSDU��ԭ
       ����̫����ʽ֡�Ժ�ֱ�Ӽ��뵽netbuf�������
     */
    if (rx_ctrl->amsdu_enable == HI_FALSE) {
        ret = hmac_rx_msdu_proc(hmac_vap, netbuf_header, netbuf, frame_hdr, rx_ctrl);
        return ret;
    } else { /* �����:AMSDU�ۺ� */
        msdu_state.procd_msdu_in_netbuf = 0;
        do {
            /* ��ȡ��һ��Ҫת����msdu */
            ret = hmac_rx_parse_amsdu(netbuf, &msdu, &msdu_state, &process_state);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                                 "{hmac_rx_prepare_msdu_list_to_wlan::hmac_rx_parse_amsdu failed[%d].}", ret);
                return ret;
            }

            /* ��MSDUת��Ϊ��̫����ʽ��֡ */
            hmac_rx_frame_80211_to_eth(msdu.netbuf, msdu.auc_da, WLAN_MAC_ADDR_LEN, msdu.auc_sa, WLAN_MAC_ADDR_LEN);

#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
            mac_ether_header_stru *ether = (mac_ether_header_stru *)oal_netbuf_data(msdu.netbuf);
            if (hmac_11i_ether_type_filter(hmac_vap, ether->auc_ether_shost, ether->us_ether_type) != HI_SUCCESS) {
                oal_netbuf_free(msdu.netbuf);
                continue;
            } else {
                /* ��MSDU���뵽netbuf������� */
                oal_netbuf_add_to_list_tail(msdu.netbuf, netbuf_header);
            }
#else
            /* ��MSDU���뵽netbuf������� */
            oal_netbuf_add_to_list_tail(msdu.netbuf, netbuf_header);
#endif
        } while (MAC_PROC_LAST_MSDU != process_state);

        return HI_SUCCESS;
    }
}

#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
static hi_void hmac_pkt_mem_opt_stat_reset(hmac_device_stru *hmac_dev,
                                           hi_u8 dscr_opt_state)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hmac_rx_dscr_opt_stru *dscr_opt = &hmac_dev->rx_dscr_opt;

    dscr_opt->dscr_opt_state = dscr_opt_state;
    dscr_opt->rx_pkt_num = 0;
    /***************************************************************************
        ���¼���dmacģ��,��ͳ����Ϣ����dmac
    ***************************************************************************/
    event_mem = frw_event_alloc(0);
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_rx_dscr_opt_timeout_fn::event_mem null.}");
        return;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_DSCR_OPT,
                       0,
                       FRW_EVENT_PIPELINE_STAGE_1,
                       0);

    /* �������� */
    event->auc_event_data[0] = dscr_opt->dscr_opt_state;

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, 0);
    frw_event_free(event_mem);
}

/*****************************************************************************
 ��������  : ����hmac_pkt_mem_opt_cfg����
 �������  : ul_cfg_type:0 enableʹ�ܿ���
                         1 opt_limit
                         2 reset_limit
 �޸���ʷ      :
  1.��    ��   : 2015��10��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_pkt_mem_opt_cfg(hi_u32 cfg_tpye, hi_u32 cfg_value)
{
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    hmac_rx_dscr_opt_stru *dscr_opt = HI_NULL;

    if (cfg_tpye > 2) { /* ����2 ��Ч���� */
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_rx_dscr_opt_cfg::invalid cfg tpye.}");
        return;
    }

    oam_warning_log2(0, OAM_SF_ANY, "{hmac_rx_dscr_opt_cfg::cfg type[%d], cfg value[%d].}", cfg_tpye, cfg_value);
    dscr_opt = &hmac_dev->rx_dscr_opt;
    if (cfg_tpye == 0) {
        dscr_opt->dscr_opt_enable = (hi_u8) cfg_value;
        if (dscr_opt->dscr_opt_enable == HI_FALSE && dscr_opt->dscr_opt_state == HI_TRUE) {
            hmac_pkt_mem_opt_stat_reset(hmac_dev, HI_FALSE);
        }
    } else if (cfg_tpye == 1) {
        dscr_opt->rx_pkt_opt_limit = cfg_value;
    } else if (cfg_tpye == 2) { /* ����2 reset */
        dscr_opt->rx_pkt_reset_limit = cfg_value;
    }
}

hi_u32 hmac_pkt_mem_opt_timeout_fn(hi_void *arg)
{
    hmac_device_stru *hmac_dev = HI_NULL;
    hmac_rx_dscr_opt_stru *dscr_opt = HI_NULL;

    if (oal_unlikely(arg == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_rx_dscr_opt_timeout_fn::p_arg is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_dev = (hmac_device_stru *)arg;
    dscr_opt = &hmac_dev->rx_dscr_opt;

    if (dscr_opt->dscr_opt_enable != HI_TRUE) {
        return HI_SUCCESS;
    }

    oam_info_log2(0, OAM_SF_ANY, "{hmac_rx_dscr_opt_timeout_fn::state[%d], pkt_num[%d]}",
                  dscr_opt->dscr_opt_state, dscr_opt->rx_pkt_num);

    /* rx_dscrδ����״̬ʱ, ��⵽RXҵ��,���������� */
    if (dscr_opt->dscr_opt_state == HI_FALSE && dscr_opt->rx_pkt_num > dscr_opt->rx_pkt_opt_limit) {
        hmac_pkt_mem_opt_stat_reset(hmac_dev, HI_TRUE);
    } else if (dscr_opt->dscr_opt_state == HI_TRUE
        && dscr_opt->rx_pkt_num < dscr_opt->rx_pkt_reset_limit) {
        /* rx_dscr�ѵ���״̬ʱ, δ��⵽RXҵ��, ������������,��֤TX���� */
        hmac_pkt_mem_opt_stat_reset(hmac_dev, HI_FALSE);
    } else {
        dscr_opt->rx_pkt_num = 0;
    }

    return HI_SUCCESS;
}

hi_void hmac_pkt_mem_opt_init(hmac_device_stru *hmac_dev)
{
    hmac_dev->rx_dscr_opt.dscr_opt_state = HI_FALSE;
    hmac_dev->rx_dscr_opt.rx_pkt_num = 0;
    hmac_dev->rx_dscr_opt.rx_pkt_opt_limit = WLAN_PKT_MEM_PKT_OPT_LIMIT;
    hmac_dev->rx_dscr_opt.rx_pkt_reset_limit = WLAN_PKT_MEM_PKT_RESET_LIMIT;
    /* ������Ч����ʱ�ر� */
    hmac_dev->rx_dscr_opt.dscr_opt_enable = HI_FALSE;

    frw_timer_create_timer(&(hmac_dev->rx_dscr_opt.rx_dscr_opt_timer), hmac_pkt_mem_opt_timeout_fn,
                           WLAN_PKT_MEM_OPT_TIME_MS, hmac_dev, HI_TRUE);
}

hi_void hmac_pkt_mem_opt_exit(hmac_device_stru *hmac_dev)
{
    if (hmac_dev->rx_dscr_opt.rx_dscr_opt_timer.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_dev->rx_dscr_opt.rx_dscr_opt_timer));
    }
}

static hi_void hmac_pkt_mem_opt_rx_pkts_stat(const oal_ip_header_stru *ip)
{
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    /* ����IP_LEN С�� WLAN_SHORT_NETBUF_SIZE�ı��� */
    if (oal_net2host_short(ip->us_tot_len) < WLAN_SHORT_NETBUF_SIZE) {
        return;
    }

    if ((ip->protocol == MAC_UDP_PROTOCAL) || (ip->protocol == MAC_TCP_PROTOCAL)) {
        hmac_dev->rx_dscr_opt.rx_pkt_num++;
    }
}
#endif

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
static hi_u32 hmac_rx_transmit_edca_opt_ap(const hmac_vap_stru *hmac_vap, mac_ether_header_stru *ether_hdr)
{
    mac_vap_stru         *mac_vap = hmac_vap->base_vap;
    hmac_user_stru       *hmac_user = HI_NULL;
    mac_ip_header_stru   *ip = HI_NULL;
    hi_u8                assoc_id = 0xff;

    if (((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
         || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        ) && (hmac_vap->edca_opt_flag_ap == HI_TRUE)) {
        /* Mesh IPv6���ܽ��б�ͷѹ�����ݲ�����˴����� */
        if (oal_host2net_short(ETHER_TYPE_IP) == ether_hdr->us_ether_type) {
            if (mac_vap_find_user_by_macaddr(mac_vap, ether_hdr->auc_ether_shost, ETHER_ADDR_LEN, &assoc_id) !=
                HI_SUCCESS) {
                oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_M2U,
                    "{hmac_rx_transmit_edca_opt_ap::find_user_by_macaddr[XX:XX:XX:%02x:%02x:%02x]failed}",
                                 (hi_u32) (ether_hdr->auc_ether_shost[3]),  /* 3 Ԫ������ */
                                 (hi_u32) (ether_hdr->auc_ether_shost[4]),  /* 4 Ԫ������ */
                                 (hi_u32) (ether_hdr->auc_ether_shost[5])); /* 5 Ԫ������ */
                return HI_FAIL;
            }
            hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(assoc_id);
            if (hmac_user == HI_NULL) {
                oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                    "{hmac_rx_transmit_edca_opt_ap::hmac_user_get_user_stru fail. assoc_id: %u}", assoc_id);
                return HI_FAIL;
            }

            ip = (mac_ip_header_stru *)(ether_hdr + 1);

            /* mips�Ż�:�������ҵ��ͳ�����ܲ�10M���� */
            if (((ip->protocol == MAC_UDP_PROTOCAL)
                 && (hmac_user->txrx_data_stat[WLAN_WME_AC_BE][WLAN_RX_UDP_DATA] <
                     (HMAC_EDCA_OPT_PKT_NUM + 10))) /* 10 ���ڼ��� */
                || ((ip->protocol == MAC_TCP_PROTOCAL)
                    && (hmac_user->txrx_data_stat[WLAN_WME_AC_BE][WLAN_RX_TCP_DATA] <
                        (HMAC_EDCA_OPT_PKT_NUM + 10)))) { /* 10 ���ڼ��� */
                hmac_edca_opt_rx_pkts_stat(hmac_user, WLAN_TIDNO_BEST_EFFORT, ip);
            }
        }
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ��MSDUת����LAN�Ľӿڣ�������ַת������Ϣ������
             ˵��:���������յ���netbuf�������Ǵ�snapͷ��ʼ
 �������  : (1)ָ��vap��ָ��
             (2)ָ����Ҫ���͵�msdu��ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_rx_transmit_msdu_to_lan(const hmac_vap_stru *hmac_vap, hmac_msdu_stru *msdu)
{
    /* ��ȡnetbuf����netbuf��dataָ���Ѿ�ָ��payload�� */
    oal_netbuf_stru *netbuf = msdu->netbuf;

    oal_netbuf_prev(netbuf) = HI_NULL;
    oal_netbuf_next(netbuf) = HI_NULL;

    hmac_rx_frame_80211_to_eth(netbuf, msdu->auc_da, WLAN_MAC_ADDR_LEN, msdu->auc_sa, WLAN_MAC_ADDR_LEN);

    mac_ether_header_stru *ether_hdr = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
    if (oal_unlikely(ether_hdr == HI_NULL)) {
        oal_netbuf_free(netbuf);
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                       "{hmac_rx_transmit_msdu_to_lan::pst_ether_hdr null.}");
        return;
    }
#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    hi_u8 *mac_addr = msdu->auc_ta;

    if (HI_SUCCESS != hmac_11i_ether_type_filter(hmac_vap, mac_addr, ether_hdr->us_ether_type)) {
        /* ���հ�ȫ���ݹ��� */
        oal_netbuf_free(netbuf);
        return;
    }
#endif
    /* ��ȡnet device hmac������ʱ����Ҫ��¼netdeviceָ�� */
    oal_net_device_stru *netdev = hmac_vap->net_device;

    /* ��protocolģʽ��ֵ */
    oal_netbuf_protocol(netbuf) = oal_eth_type_trans(netbuf, netdev);

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    if (hmac_rx_transmit_edca_opt_ap(hmac_vap, ether_hdr) != HI_SUCCESS) {
        oal_netbuf_free(netbuf);
        return;
    }
#endif

#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    hmac_pkt_mem_opt_rx_pkts_stat((oal_ip_header_stru *)(ether_hdr + 1));
#endif

    /* ��skbת������ */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    netbuf->dev = netdev;

    /* ��skb��dataָ��ָ����̫����֡ͷ */
    /* ����ǰ��pull��14�ֽڣ�����ط�Ҫpush��ȥ */
    oal_netbuf_push(netbuf, ETHER_HDR_LEN);
#endif

    if (HI_TRUE == hmac_get_rxthread_enable()) {
        hmac_rxdata_netbuf_enqueue(netbuf);

        hmac_rxdata_sched();
    } else {
        oal_netif_rx_ni(netbuf);
    }

    /* ��λnet_dev->jiffies���� */
#if (LINUX_VERSION_CODE < kernel_version(4, 11, 0))
    oal_netdevice_last_rx(netdev) = OAL_TIME_JIFFY;
#endif
}

hi_void hmac_rx_msdu_frame_classify(const hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf,
    mac_ieee80211_frame_stru *frame_hdr, hmac_msdu_stru *msdu, hmac_user_stru *hmac_user)
{
    hi_u8 *mac_addr = HI_NULL;
    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);

#ifdef _PRE_WLAN_FEATURE_WAPI
    hi_bool pairwise = !ether_is_multicast(frame_hdr->auc_address1);
    hmac_wapi_stru *wapi = hmac_user_get_wapi_ptr(hmac_vap->base_vap, pairwise, hmac_user->base_user->us_assoc_id);

    if (wapi == HI_NULL) {
        oam_warning_log0(0, OAM_SF_WPA, "{hmac_rx_lan_frame_classify:: get pst_wapi Err!.}");
        return;
    }

    if ((wapi_is_port_valid(wapi) == HI_TRUE) && (wapi->wapi_netbuff_rxhandle != HI_NULL)) {
        netbuf = wapi->wapi_netbuff_rxhandle(wapi, netbuf);
        if (netbuf == HI_NULL) {
            oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_rx_lan_frame_classify:WapiDecrypt Err}");
            return;
        }

        /* ���»�ȡ��MPDU�Ŀ�����Ϣ */
        rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    }
#endif

    netbuf = hmac_defrag_process(hmac_user, netbuf, rx_ctrl->mac_header_len);
    if (netbuf == HI_NULL) {
        return;
    }

    /* ��ӡ���ؼ�֡(dhcp)��Ϣ */
    hi_u8 datatype = mac_get_data_type_from_80211(netbuf, rx_ctrl->mac_header_len);
    if (datatype <= MAC_DATA_VIP) {
        oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_RX,
            "{hmac_rx_lan_frame_classify:user=%d,type=%u,len=%u}[0~3dhcp 4arp_req 5arp_rsp 6eapol]",
            rx_ctrl->us_ta_user_idx, datatype, rx_ctrl->us_frame_len);
    }

    /* �Ե�ǰ��msdu���и�ֵ */
    msdu->netbuf = netbuf;

    /* ��netbuf��dataָ��ָ��mac frame��payload�� */
    oal_netbuf_pull(netbuf, rx_ctrl->mac_header_len);

    /* ��ȡԴ��ַ��Ŀ�ĵ�ַ */
    mac_rx_get_sa(frame_hdr, &mac_addr);
    if (memcpy_s(msdu->auc_sa, WLAN_MAC_ADDR_LEN,  mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return;
    }

    mac_rx_get_da(frame_hdr, &mac_addr);
    if (memcpy_s(msdu->auc_da, WLAN_MAC_ADDR_LEN,  mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return;
    }

    /* ��MSDUת����LAN */
    hmac_rx_transmit_msdu_to_lan(hmac_vap, msdu);
}

/*****************************************************************************
 ��������  : HMAC����ģ�飬WLAN��LAN��ת���ӿ�
 �������  : (1)��ӦMPDU�ĵ�һ��netbuf��ָ��
             (2)��Ӧ��MPDUռ�õ�netbuf����Ŀ
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��12��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_rx_lan_frame_classify(const hmac_vap_stru *hmac_vap,
                                  oal_netbuf_stru *netbuf, mac_ieee80211_frame_stru *frame_hdr)
{
    hmac_msdu_stru msdu = {0};                                      /* �������������ÿһ��MSDU */
    hmac_msdu_proc_state_stru        msdu_state = {0};              /* ��¼MPDU�Ĵ�����Ϣ */
    hmac_msdu_proc_status_enum_uint8 process_state = MAC_PROC_BUTT; /* ����AMSDU��״̬ */
    hi_u8 *mac_addr = HI_NULL;

    if (oal_unlikely(frame_hdr == HI_NULL)) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_rx_lan_frame_classify::params null.}");
        return HI_FAIL;
    }

    /* ��ȡ��MPDU�Ŀ�����Ϣ */
    hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);

    mac_get_transmit_addr(frame_hdr, &mac_addr);
    if (memcpy_s(msdu.auc_ta, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }

    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(rx_ctrl->us_ta_user_idx);
    if (oal_unlikely((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL))) {
        oam_error_log3(hmac_vap->base_vap->vap_id, OAM_SF_RX,
            "{hmac_rx_lan_frame_classify::hmac_user null,user_idx=%d,net_buf ptr addr=%p,cb ptr addr=%p}",
            rx_ctrl->us_ta_user_idx, (uintptr_t)netbuf, (uintptr_t)rx_ctrl);

        /* ��ӡ��net buf�����Ϣ */
        oam_error_log4(hmac_vap->base_vap->vap_id, OAM_SF_RX,
            "{hmac_rx_lan_frame_classify:vap id=%d,mac_hdr_len=%d,frame_len=%d,mac_hdr_start_addr=%p}", rx_ctrl->vap_id,
            rx_ctrl->mac_header_len, rx_ctrl->us_frame_len, (uintptr_t)rx_ctrl->pul_mac_hdr_start_addr);

        return HI_FAIL;
    }

    hmac_ba_update_rx_bitmap(hmac_user, frame_hdr);

    /* ���һ:����AMSDU�ۺϣ����MPDU��Ӧһ��MSDU��ͬʱ��Ӧһ��NETBUF */
    if (rx_ctrl->amsdu_enable == HI_FALSE) {
        hmac_rx_msdu_frame_classify(hmac_vap, netbuf, frame_hdr, &msdu, hmac_user);
    } else { /* �����:AMSDU�ۺ� */
        msdu_state.procd_msdu_in_netbuf = 0;

        do {
            /* ��ȡ��һ��Ҫת����msdu */
            hi_u32 ret = hmac_rx_parse_amsdu(netbuf, &msdu, &msdu_state, &process_state);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                                 "{hmac_rx_lan_frame_classify::hmac_rx_parse_amsdu failed[%d].}", ret);
                return HI_FAIL;
            }

            /* ��ÿһ��MSDUת����LAN */
            hmac_rx_transmit_msdu_to_lan(hmac_vap, &msdu);
        } while (MAC_PROC_LAST_MSDU != process_state);
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : copy netbuff
 �޸���ʷ      :
  1.��    ��   : 2015��1��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_rx_copy_netbuff(oal_netbuf_stru **dest_netbuf, const oal_netbuf_stru *src_netbuf,
                            hi_u8 vap_id, mac_ieee80211_frame_stru **ppul_mac_hdr_start_addr)
{
    hmac_rx_ctl_stru *rx_ctrl = HI_NULL;

    hi_unref_param(vap_id);
    *dest_netbuf = oal_netbuf_alloc(WLAN_LARGE_NETBUF_SIZE, 0, 4);  /* align 4 */
    if (oal_unlikely(*dest_netbuf == HI_NULL)) {
        oam_warning_log0(vap_id, OAM_SF_RX, "{hmac_rx_copy_netbuff::pst_netbuf_copy null.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* ��Ϣ���� */
    if (memcpy_s(oal_netbuf_cb(*dest_netbuf), sizeof(hmac_rx_ctl_stru), oal_netbuf_cb(src_netbuf),
                 sizeof(hmac_rx_ctl_stru)) != EOK) {
        oal_netbuf_free(*dest_netbuf);
        oam_error_log0(0, OAM_SF_CFG, "hmac_rx_copy_netbuff:: pst_src_netbuf memcpy_s fail.");
        return HI_FAIL;
    }
    if (memcpy_s(oal_netbuf_data(*dest_netbuf), oal_netbuf_len(src_netbuf), oal_netbuf_data(src_netbuf),
                 oal_netbuf_len(src_netbuf)) != EOK) {
        oal_netbuf_free(*dest_netbuf);
        oam_error_log0(0, OAM_SF_CFG, "hmac_rx_copy_netbuff:: pst_src_netbuf memcpy_s fail.");
        return HI_FAIL;
    }
    /* ����netbuf���ȡ�TAILָ�� */
    oal_netbuf_put(*dest_netbuf, oal_netbuf_len(src_netbuf));
    /* ����MAC֡ͷ��ָ��copy�󣬶�Ӧ��mac header��ͷ�Ѿ������仯) */
    rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(*dest_netbuf);
    rx_ctrl->pul_mac_hdr_start_addr = (hi_u32 *)oal_netbuf_data(*dest_netbuf);
    *ppul_mac_hdr_start_addr = (mac_ieee80211_frame_stru *)oal_netbuf_data(*dest_netbuf);

    return HI_SUCCESS;
}

hi_void hmac_rx_netbuf_add_to_list_tail(oal_netbuf_head_stru *netbuf_header, hmac_rx_ctl_stru *rx_ctrl,
    hi_u32 ret, hi_u8 buf_nums, hi_u8 is_ba_buf)
{
    oal_netbuf_stru *netbuf = HI_NULL;

    hi_unref_param(rx_ctrl);

    if (ret != HI_SUCCESS) {
        hmac_rx_free_netbuf_list(netbuf_header, buf_nums);
        return;
    }

    if (is_ba_buf == HI_TRUE) {
        return;
    }

    /* �����buff��reorder���У������¹ҵ�����β������ */
    for (hi_u8 netbuf_num = 0; netbuf_num < buf_nums; netbuf_num++) {
        netbuf = oal_netbuf_delist(netbuf_header);
        if (oal_likely(netbuf != HI_NULL)) {
            oal_netbuf_add_to_list_tail(netbuf, netbuf_header);
        } else {
            oam_warning_log0(rx_ctrl->vap_id, OAM_SF_RX, "{hmac_rx_process_data_filter::no buff error.}");
        }
    }
}

/*****************************************************************************
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2015��1��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_process_data_filter(oal_netbuf_head_stru *netbuf_header, oal_netbuf_stru *temp_netbuf,
                                    hi_u16 us_netbuf_num)
{
    hi_u8  buf_nums;
    hi_u32 ret = HI_SUCCESS;

    while (us_netbuf_num != 0) {
        hi_u8 is_ba_buf = HI_FALSE;
        oal_netbuf_stru *netbuf = temp_netbuf;
        if (netbuf == HI_NULL) {
            oam_warning_log1(0, OAM_SF_RX, "{hmac_rx_process_data_filter::us_netbuf_num = %d}", us_netbuf_num);
            break;
        }

        hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
        buf_nums = rx_ctrl->buff_nums;

        /* ��ȡ��һ��Ҫ�����MPDU */
        oal_netbuf_get_appointed_netbuf(netbuf, buf_nums, &temp_netbuf);
        us_netbuf_num = hi_sub(us_netbuf_num, buf_nums);
#ifdef _PRE_WLAN_FEATURE_AMPDU
        hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(rx_ctrl->us_ta_user_idx);
        if (oal_unlikely((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL) ||
            (hmac_user->base_user->is_user_alloced != MAC_USER_ALLOCED))) {
            hmac_rx_free_netbuf_list(netbuf_header, buf_nums);
            oam_info_log0(rx_ctrl->vap_id, OAM_SF_RX, "{hmac_rx_process_data_filter::user null.}");
            continue;
        }
        mac_ieee80211_frame_stru *frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;
#endif

        mac_vap_stru *mac_vap = mac_vap_get_vap_stru(rx_ctrl->mac_vap_id);
        if (oal_unlikely(mac_vap == HI_NULL)) {
            hmac_rx_free_netbuf_list(netbuf_header, buf_nums);
            oam_warning_log0(rx_ctrl->vap_id, OAM_SF_RX, "{hmac_rx_process_data_filter::pst_vap null.}");
            continue;
        }

        if (mac_vap->vap_id == 0 || mac_vap->vap_id > WLAN_VAP_NUM_PER_DEVICE) {
            oam_error_log1(0, OAM_SF_RX, "{hmac_rx_process_data_filter::Invalid vap_id.vap_id[%u]}", mac_vap->vap_id);
            hmac_rx_free_netbuf_list(netbuf_header, buf_nums);
            continue;
        }

#ifdef _PRE_WLAN_FEATURE_AMPDU
        hmac_filter_serv_info_stru filter_serv_info;
        filter_serv_info.netbuf_header = netbuf_header;
        filter_serv_info.pen_is_ba_buf = &is_ba_buf;
        ret = HI_SUCCESS;
        if (rx_ctrl->amsdu_enable == HI_FALSE) {
            ret = hmac_ba_filter_serv(mac_vap, hmac_user, rx_ctrl, frame_hdr, &filter_serv_info);
        }
#endif

        hmac_rx_netbuf_add_to_list_tail(netbuf_header, rx_ctrl, ret, buf_nums, is_ba_buf);
    }
}

/*****************************************************************************
 ��������  : ��һ������Ҫ�ϱ���֡
 �޸���ʷ      :
  1.��    ��   : 2015��1��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_lan_frame(const oal_netbuf_head_stru *netbuf_header)
{
    hi_u32 netbuf_num;
    oal_netbuf_stru *temp_netbuf = HI_NULL;
    oal_netbuf_stru *netbuf = HI_NULL;
    hi_u8 buf_nums;
    hmac_rx_ctl_stru *rx_ctrl = HI_NULL;
    mac_ieee80211_frame_stru *frame_hdr = HI_NULL;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hi_u32 err_code;

    netbuf_num = oal_netbuf_get_buf_num(netbuf_header);
    temp_netbuf = oal_netbuf_peek(netbuf_header);

    while (netbuf_num != 0) {
        netbuf = temp_netbuf;
        if (netbuf == NULL) {
            break;
        }

        rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
        frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;
        buf_nums = rx_ctrl->buff_nums;

        netbuf_num = hi_sub(netbuf_num, buf_nums);
        oal_netbuf_get_appointed_netbuf(netbuf, buf_nums, &temp_netbuf);

        hmac_vap = hmac_vap_get_vap_stru(rx_ctrl->mac_vap_id);
        if (hmac_vap == HI_NULL) {
            oam_error_log1(0, OAM_SF_RX, "{hmac_rx_lan_frame::hmac_vap_get_vap_stru null. vap_id:%u}",
                           rx_ctrl->mac_vap_id);
            continue;
        }
        rx_ctrl->us_da_user_idx = hmac_vap->base_vap->assoc_vap_id;

        err_code = hmac_rx_lan_frame_classify(hmac_vap, netbuf, frame_hdr);
        if (err_code != HI_SUCCESS) {
            hmac_rx_free_netbuf(netbuf, (hi_u16)buf_nums);
        }
    }
}

static hi_void hmac_rx_process_data_insert_list(hi_u16 us_netbuf_num, oal_netbuf_stru *temp_netbuf,
    oal_netbuf_head_stru *netbuf_header, const hmac_vap_stru *hmac_vap)
{
    oal_netbuf_stru *netbuf = HI_NULL;        /* ���ڱ��浱ǰ�����MPDU�ĵ�һ��netbufָ�� */
#ifdef _PRE_WLAN_FEATURE_PROMIS
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hmac_rx_ctl_stru *rx_ctrl = HI_NULL;
    hi_u8 bssid[WLAN_MAC_ADDR_LEN] = {0};
    mac_ieee80211_frame_stru *mac_frame = HI_NULL;
#endif
#endif
    while (us_netbuf_num != 0) {
        netbuf = temp_netbuf;
        if (netbuf == HI_NULL) {
            break;
        }
        temp_netbuf = oal_netbuf_next(netbuf);
#ifdef _PRE_WLAN_FEATURE_PROMIS
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        mac_device_stru *mac_dev = mac_res_get_dev();
        if (mac_dev->promis_switch) {
            /* �����ϱ�������BSS�鲥���ݰ� */
            hi_u32 ret = hwal_send_others_bss_data(netbuf);
            if (ret != HI_SUCCESS) {
                oam_error_log1(0, OAM_SF_RX, "hwal_send_others_bss_data failed! ul_ret=%d", ret);
            }
            rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
            if (rx_ctrl == HI_NULL) {
                oal_netbuf_free(netbuf);
                us_netbuf_num--;
                continue;
            }
            mac_frame = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;
            mac_get_bssid((const hi_u8 *)mac_frame, (hi_u8 *)bssid, WLAN_MAC_ADDR_LEN);
            if (memcmp(bssid, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != 0) {
                oal_netbuf_free(netbuf);
                us_netbuf_num--;
                continue;
            }
        }
#endif
#endif
        oal_netbuf_add_to_list_tail(netbuf, netbuf_header);
        us_netbuf_num--;
    }
    if (us_netbuf_num != 0) {
        oam_error_log1(0, OAM_SF_RX, "{hmac_rx_process_data_insert_list::us_netbuf_num[%d].}", us_netbuf_num);
    }
}

/*****************************************************************************
 ��������  : APģʽ�£�HMACģ�����WLAN_DRX�¼�(����֡)�Ĵ�����
 �������  : �¼��ṹ��ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2013��3��05��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_rx_process_data_ap(frw_event_mem_stru *event_mem)
{
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_rx_process_data_ap::evenevent_memt is NULL!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȡ�¼�ͷ���¼��ṹ��ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_stru *event_hdr = &(event->event_hdr);
    dmac_wlan_drx_event_stru *wlan_rx_event = (dmac_wlan_drx_event_stru *)(event->auc_event_data);
    /* ������ʱ������һ����Ҫ�����netbufָ�� */
    oal_netbuf_stru *temp_netbuf = (oal_netbuf_stru *)wlan_rx_event->netbuf;
    hi_u16 us_netbuf_num = wlan_rx_event->us_netbuf_num; /* netbuf����ĸ��� */
    oal_netbuf_head_stru netbuf_header;      /* �洢�ϱ������������� */

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(event_hdr->vap_id);
    if (hmac_vap == HI_NULL || hmac_vap->base_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_rx_process_data_ap::hmac_vap/mac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ������netbuffȫ�������� */
    oal_netbuf_list_head_init(&netbuf_header);
    hmac_rx_process_data_insert_list(us_netbuf_num, temp_netbuf, &netbuf_header, hmac_vap);

    if (oal_netbuf_list_empty(&netbuf_header) == HI_TRUE) {
        return HI_SUCCESS;
    }

    /* ��Dmac�ϱ���֡����reorder���й���һ�� */
    hmac_rx_process_data_filter(&netbuf_header, (oal_netbuf_stru *)wlan_rx_event->netbuf, wlan_rx_event->us_netbuf_num);

#ifdef _PRE_WLAN_FEATURE_MESH
    if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        /* ����Ҫ�ϱ���֡��һ���Ӵ��� */
        hmac_rx_process_data_mesh_tcp_ack_opt(hmac_vap, &netbuf_header);
    } else {
        hmac_rx_process_data_ap_tcp_ack_opt(hmac_vap, &netbuf_header);
    }
#else
    hmac_rx_process_data_ap_tcp_ack_opt(hmac_vap, &netbuf_header);
#endif

    return HI_SUCCESS;
}

hi_void hmac_rx_process_no_multicast_proc(const hmac_vap_stru *hmac_vap, const hi_u8 *mac_addr, oal_netbuf_stru *netbuf,
                                          oal_netbuf_head_stru *w2w_netbuf_hdr)
{
    hi_u8 user_idx;
    hmac_rx_ctl_stru         *rx_ctrl   = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    mac_ieee80211_frame_stru *frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;

    /* ��ȡĿ�ĵ�ַ��Ӧ���û�ָ�� */
    hi_u32 rslt = mac_vap_find_user_by_macaddr(hmac_vap->base_vap, mac_addr, WLAN_MAC_ADDR_LEN, &user_idx);
    if (rslt == HI_ERR_CODE_PTR_NULL) { /* �����û�ʧ�� */
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_rx_process_no_multicast_proc::get user Err}");

        /* �ͷŵ�ǰ�����MPDUռ�õ�netbuf */
        hmac_rx_free_netbuf(netbuf, (hi_u16)rx_ctrl->buff_nums);
        return;
    }

    /* û���ҵ���Ӧ���û� */
    if (rslt != HI_SUCCESS) {
        /* Ŀ���û�����AP���û����У�����wlan_to_lanת���ӿ� */
        rslt = hmac_rx_lan_frame_classify(hmac_vap, netbuf, frame_hdr);
        if (rslt != HI_SUCCESS) {
            oam_warning_log1(rx_ctrl->vap_id, OAM_SF_RX,
                "hmac_rx_process_data_ap_tcp_ack_opt:: rx_lan_frame_fail[%d]", rslt);
            hmac_rx_free_netbuf(netbuf, (hi_u16)rx_ctrl->buff_nums);
        }
        return;
    }

    /* Ŀ���û�����AP���û����У�����WLAN_TO_WLANת�� */
    hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
    if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "{hmac_rx_process_no_multicast_proc::hmac_user null}");

        hmac_rx_free_netbuf(netbuf, (hi_u16)rx_ctrl->buff_nums);
        return;
    }

    if (hmac_user->base_user->user_asoc_state != MAC_USER_STATE_ASSOC) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX,
                         "{hmac_rx_process_no_multicast_proc::the station is not associated with ap.}");

        hmac_rx_free_netbuf(netbuf, (hi_u16)rx_ctrl->buff_nums);
        hmac_mgmt_send_deauth_frame(hmac_vap->base_vap, mac_addr, WLAN_MAC_ADDR_LEN, MAC_NOT_AUTHED);
        return;
    }

    /* ��Ŀ�ĵ�ַ����Դ������ֵ�ŵ�cb�ֶ��У�user��asoc id���ڹ�����ʱ�򱻸�ֵ */
    rx_ctrl->us_da_user_idx = hmac_user->base_user->us_assoc_id;

    /* ��MPDU�����ɵ���MSDU�������е�MSDU���һ��netbuf�� */
    if (hmac_rx_prepare_msdu_list_to_wlan(hmac_vap, w2w_netbuf_hdr, netbuf, frame_hdr) != HI_SUCCESS) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_RX, "hmac_rx_prepare_msdu_list_to_wlan return NON SUCCESS");
        hmac_rx_free_netbuf(netbuf, (hi_u16)rx_ctrl->buff_nums);
    }
}

/*****************************************************************************
 ��������  : APģʽ�£�HMACģ�����WLAN_DRX�¼�(����֡)�Ĵ�����
 �������  : �¼��ṹ��ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2013��3��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_process_data_ap_tcp_ack_opt(const hmac_vap_stru *hmac_vap, const oal_netbuf_head_stru *netbuf_header)
{
    mac_ieee80211_frame_stru *copy_frame_hdr = HI_NULL; /* ����mac֡��ָ�� */
    oal_netbuf_stru          *netbuf_copy = HI_NULL;    /* ���ڱ����鲥֡copy */
    oal_netbuf_stru          *temp_netbuf = oal_netbuf_peek(netbuf_header);
    hi_u8                    *mac_addr = HI_NULL;       /* �����û�Ŀ�ĵ�ַ��ָ�� */
    hi_u16 us_netbuf_num = (hi_u16)oal_netbuf_get_buf_num(netbuf_header);
    oal_netbuf_head_stru w2w_netbuf_hdr; /* ����wlan to wlan��netbuf�����ͷ */
    frw_event_hdr_stru   event_hdr;

    event_hdr.vap_id = hmac_vap->base_vap->vap_id;
    /* ѭ���յ���ÿһ��MPDU�����������:
       1���鲥֡ʱ������WLAN TO WLAN��WLAN TO LAN�ӿ�
       2������������ʵ�����������WLAN TO LAN�ӿڻ���WLAN TO WLAN�ӿ� */
    oal_netbuf_list_head_init(&w2w_netbuf_hdr);
    while (us_netbuf_num != 0) {
        oal_netbuf_stru *netbuf = temp_netbuf;
        if (netbuf == HI_NULL) {
            break;
        }
        hmac_rx_ctl_stru *rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
        /* ��ȡ֡ͷ��Ϣ */
        mac_ieee80211_frame_stru *frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;
        /* ��ȡ��һ��Ҫ�����MPDU */
        oal_netbuf_get_appointed_netbuf(netbuf, rx_ctrl->buff_nums, &temp_netbuf);
        us_netbuf_num = hi_sub(us_netbuf_num, rx_ctrl->buff_nums);
        hmac_vap = hmac_vap_get_vap_stru(rx_ctrl->mac_vap_id);
        if (oal_unlikely(hmac_vap == HI_NULL)) {
            hmac_rx_free_netbuf(netbuf, (hi_u16) rx_ctrl->buff_nums);
            continue;
        }

        /* ��ȡ���ն˵�ַ  */
        mac_rx_get_da(frame_hdr, &mac_addr);
        /* �������Ĵ��� */
        if (ether_is_multicast(mac_addr) == HI_FALSE) {
            hmac_rx_process_no_multicast_proc(hmac_vap, mac_addr, netbuf, &w2w_netbuf_hdr);
            continue;
        }
        /* Ŀ�ĵ�ַΪ�鲥��ַʱ������WLAN_TO_WLAN��WLAN_TO_LAN��ת�� */
        if (hmac_rx_copy_netbuff(&netbuf_copy, netbuf, rx_ctrl->mac_vap_id, &copy_frame_hdr) == HI_SUCCESS) {
            /* ��MPDU�����ɵ���MSDU�������е�MSDU���һ��netbuf�� */
            if (hmac_rx_prepare_msdu_list_to_wlan(hmac_vap, &w2w_netbuf_hdr, netbuf_copy, copy_frame_hdr)
                != HI_SUCCESS) {
                oam_warning_log0(0, OAM_SF_RX, "hmac_rx_prepare_msdu_list_to_wlan return NON SUCCESS");
                oal_netbuf_free(netbuf_copy);
            }
        }
        /* �ϱ������ WLAN_TO_LAN */
        hi_u32 err_code = hmac_rx_lan_frame_classify(hmac_vap, netbuf, frame_hdr);
        if (err_code != HI_SUCCESS) {
            hmac_rx_free_netbuf(netbuf, (hi_u16) rx_ctrl->buff_nums);
        }
    }

    /*  ��MSDU�������������̴��� WLAN_TO_WLAN */
    if ((oal_netbuf_list_empty(&w2w_netbuf_hdr) == HI_FALSE) && (oal_netbuf_tail(&w2w_netbuf_hdr) != HI_NULL) &&
        (oal_netbuf_peek(&w2w_netbuf_hdr) != HI_NULL)) {
        oal_netbuf_next((oal_netbuf_tail(&w2w_netbuf_hdr))) = HI_NULL;
        oal_netbuf_prev((oal_netbuf_peek(&w2w_netbuf_hdr))) = HI_NULL;

        hmac_rx_transmit_to_wlan(&event_hdr, &w2w_netbuf_hdr);
    }
}

/*****************************************************************************
 ��������  : STAģʽ�£�HMACģ�����WLAN_DRX�¼�(����֡)�Ĵ�����
 �������  : �¼��ṹ��ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2013��3��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
************************ *****************************************************/
hi_u32 hmac_rx_process_data_sta(frw_event_mem_stru *event_mem)
{
    hi_u16 us_netbuf_num;   /* netbuf����ĸ��� */
    oal_netbuf_head_stru netbuf_header;      /* �洢�ϱ������������� */

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_rx_process_data_sta::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ�¼�ͷ���¼��ṹ��ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_stru *event_hdr = &(event->event_hdr);
    dmac_wlan_drx_event_stru *wlan_rx_event = (dmac_wlan_drx_event_stru *)(event->auc_event_data);
    oal_netbuf_stru *temp_netbuf = (oal_netbuf_stru *)wlan_rx_event->netbuf;
    us_netbuf_num = wlan_rx_event->us_netbuf_num;

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(event_hdr->vap_id);
    if (hmac_vap == HI_NULL || hmac_vap->base_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_RX, "{hmac_rx_process_data_sta::hmac_vap/mac_vap null.}");
        hmac_rx_free_netbuf(temp_netbuf, us_netbuf_num);
        return HI_ERR_CODE_PTR_NULL;
    }
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* If mib info is null ptr,release the netbuf */
    if (hmac_vap->base_vap->mib_info == NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_rx_process_data_sta::pst_mib_info null.}");
        hmac_rx_free_netbuf(temp_netbuf, us_netbuf_num);
        return HI_SUCCESS;
    }
#endif

    /* ������netbuffȫ�������� */
    oal_netbuf_list_head_init(&netbuf_header);
    hmac_rx_process_data_insert_list(us_netbuf_num, temp_netbuf, &netbuf_header, hmac_vap);

    if (oal_netbuf_list_empty(&netbuf_header) == HI_TRUE) {
        return HI_SUCCESS;
    }

    hmac_rx_process_data_filter(&netbuf_header, (oal_netbuf_stru *)wlan_rx_event->netbuf, wlan_rx_event->us_netbuf_num);
    hmac_rx_lan_frame(&netbuf_header);
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  : meshģʽ�£�HMACģ�����WLAN_DRX�¼�(����֡)�Ĵ�����
 �������  : �¼��ṹ��ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2019��2��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_rx_process_data_mesh_tcp_ack_opt(hmac_vap_stru *hmac_vap, const oal_netbuf_head_stru *netbuf_header)
{
    mac_ieee80211_frame_stru *frame_hdr = HI_NULL;   /* ����mac֡��ָ�� */
    hi_u8                    *da_mac_addr = HI_NULL;          /* �����û�Ŀ�ĵ�ַ��ָ�� */
    hmac_rx_ctl_stru         *rx_ctrl = HI_NULL;     /* ÿһ��MPDU�Ŀ�����Ϣ */
    hi_u16                    us_netbuf_num;             /* netbuf����ĸ��� */
    hi_u8                     buf_nums;               /* ÿ��mpduռ��buf�ĸ��� */
    oal_netbuf_stru          *netbuf = HI_NULL;      /* ���ڱ��浱ǰ�����MPDU�ĵ�һ��netbufָ�� */
    oal_netbuf_stru          *temp_netbuf = HI_NULL; /* ������ʱ������һ����Ҫ�����netbufָ�� */
    hi_u32                    err_code;

    temp_netbuf = oal_netbuf_peek(netbuf_header);
    us_netbuf_num = (hi_u16) oal_netbuf_get_buf_num(netbuf_header);

    while (us_netbuf_num != 0) {
        netbuf = temp_netbuf;
        if (netbuf == HI_NULL) {
            break;
        }

        rx_ctrl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);

        /* ��ȡ֡ͷ��Ϣ */
        frame_hdr = (mac_ieee80211_frame_stru *)rx_ctrl->pul_mac_hdr_start_addr;

        /* ��ȡ��ǰMPDUռ�õ�netbuf��Ŀ */
        buf_nums = rx_ctrl->buff_nums;

        /* ��ȡ��һ��Ҫ�����MPDU */
        oal_netbuf_get_appointed_netbuf(netbuf, buf_nums, &temp_netbuf);
        us_netbuf_num = hi_sub(us_netbuf_num, buf_nums);

        hmac_vap = hmac_vap_get_vap_stru(rx_ctrl->mac_vap_id);
        if (oal_unlikely(hmac_vap == HI_NULL)) {
            oam_warning_log0(rx_ctrl->vap_id, OAM_SF_RX,
                             "{hmac_rx_process_data_mesh_tcp_ack_opt::pst_vap null.}");
            hmac_rx_free_netbuf(netbuf, (hi_u16) buf_nums);
            continue;
        }
        /* ��ȡ���ն˵�ַ  */
        mac_rx_get_da(frame_hdr, &da_mac_addr);

        err_code = hmac_rx_lan_frame_classify(hmac_vap, netbuf, frame_hdr); /* �ϱ������ */
        if (err_code != HI_SUCCESS) {
            oam_warning_log1(rx_ctrl->vap_id, OAM_SF_RX,
                "hmac_rx_process_data_ap_tcp_ack_opt:: rx_lan_frame_fail[%d]", err_code);
            hmac_rx_free_netbuf(netbuf, (hi_u16)buf_nums);
        }
    }

    return;
}
#endif

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
