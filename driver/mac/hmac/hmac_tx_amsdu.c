/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Amsdu polymerization.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hmac_tx_amsdu.h"
#include "hmac_tx_data.h"
#include "hcc_hmac_if.h"
#include "hmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
static hi_u32 hmac_amsdu_tx_timeout_process(hi_void *arg);
static hi_u8 hmac_tx_amsdu_is_overflow(const hmac_amsdu_stru *amsdu, const hmac_tx_ctl_stru *tx_ctl,
                                       hi_u32 frame_len);

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : amsdu��д��֡ͷ����
 �������  : pst_amsdu: amsdu�ṹ��ָ��
             pst_buf: �¼������֡
             ul_framelen: �����ĳ���
 �� �� ֵ  : �ɹ�:HI_SUCCESS;ʧ��:HI_FAIL
*****************************************************************************/
static hi_u32 hmac_amsdu_encap_hdr_data(hmac_amsdu_stru *amsdu, oal_netbuf_stru *msdu_netbuf)
{
    mac_ether_header_stru *ether_head = (mac_ether_header_stru *)oal_netbuf_data(msdu_netbuf);
    mac_ether_header_stru *msdu_head = HI_NULL; /* Ϊ��дamsdu��֡ͷ����ʱָ�� */
    mac_llc_snap_stru     *snap_head = HI_NULL;  /* Ϊ��дsnapͷ����ʱָ�� */

    if (memcpy_s(amsdu->auc_eth_da, WLAN_MAC_ADDR_LEN, ether_head->auc_ether_dhost, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_amsdu_encap_hdr_data::copy auc_eth_da failed!}");
        return HI_FAIL;
    }
    if (memcpy_s(amsdu->auc_eth_sa, WLAN_MAC_ADDR_LEN, ether_head->auc_ether_shost, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_amsdu_encap_hdr_data::copy auc_eth_sa failed!}");
        return HI_FAIL;
    }

    /* ��дsnapͷ */
    snap_head = (mac_llc_snap_stru *)oal_netbuf_pull(msdu_netbuf, ETHER_HDR_LEN - SNAP_LLC_FRAME_LEN);
    if (snap_head == HI_NULL) {
        return HI_FAIL;
    }
    snap_head->llc_dsap      = SNAP_LLC_LSAP;
    snap_head->llc_ssap      = SNAP_LLC_LSAP;
    snap_head->control       = LLC_UI;
    snap_head->auc_org_code[0]  = SNAP_RFC1042_ORGCODE_0;
    snap_head->auc_org_code[1]  = SNAP_RFC1042_ORGCODE_1;
    snap_head->auc_org_code[2]  = SNAP_RFC1042_ORGCODE_2; /* 2 Ԫ������ */
    snap_head->us_ether_type    = ether_head->us_ether_type;

    /* ��дamsdu��֡ͷ */
    msdu_head = (mac_ether_header_stru *)oal_netbuf_push(msdu_netbuf, ETHER_HDR_LEN);
    if (msdu_head == HI_NULL) {
        oam_error_log0(0, OAM_SF_AMSDU, "{hmac_amsdu_encap_hdr_data::oal_net_push fail.}");
        return HI_FAIL;
    }
    if (memcpy_s(msdu_head->auc_ether_dhost, ETHER_ADDR_LEN, amsdu->auc_eth_da, ETHER_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_amsdu_encap_hdr_data::copy auc_ether_dhost failed!}");
        return HI_FAIL;
    }
    if (memcpy_s(msdu_head->auc_ether_shost, ETHER_ADDR_LEN, amsdu->auc_eth_sa, ETHER_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_amsdu_encap_hdr_data::copy auc_ether_shost failed!}");
        return HI_FAIL;
    }
    msdu_head->us_ether_type = hi_swap_byteorder_16((hi_u16)(oal_netbuf_len(msdu_netbuf) - ETHER_HDR_LEN));

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : amsdu��֡ͷ��װ
 �������  : pst_amsdu: amsdu�ṹ��ָ��
             pst_buf: �¼������֡
             ul_framelen: �����ĳ���
 �� �� ֵ  : �ɹ�:HI_SUCCESS;ʧ��HI_ERR_CODE_PTR_NULL
*****************************************************************************/
static hi_u32 hmac_amsdu_encap_hdr(hmac_amsdu_stru *amsdu, oal_netbuf_stru **netbuf)
{
    oal_netbuf_stru        *amsdu_netbuf = HI_NULL;
    oal_netbuf_stru        *msdu_netbuf = *netbuf;
    hmac_tx_ctl_stru       *amsdu_cb = HI_NULL;
    hmac_tx_ctl_stru       *msdu_cb = HI_NULL;
    hi_u32              tailroom;    /* �ݴ�skbʣ��β���ռ� */
    hi_u32              headroom;    /* �ݴ�skbʣ��ͷ���ռ� */
    hi_u32              frame_len = oal_netbuf_len(msdu_netbuf);
    hi_u32              msdu_len = hi_byte_align(frame_len, 4) + SNAP_LLC_FRAME_LEN; /* 4�ֽڶ��� */

    amsdu_netbuf = oal_netbuf_peek(&amsdu->msdu_head);
    /* WLAN TO WLAN �� AMSDU���� */
    if (amsdu_netbuf == HI_NULL) {
        oam_error_log0(0, OAM_SF_AMSDU, "{hmac_amsdu_tx_encap_mpdu::oal_netbuf_peek return NULL}");
        return HMAC_TX_PASS;
    }

    /* �ݴ�����ʣ��ռ���Ϣ */
    tailroom = oal_netbuf_tailroom(amsdu_netbuf);
    if (tailroom < msdu_len) {
        /* �����ں���hmac_tx_amsdu_is_overflow ����������жϣ�����ȥ��4�ֽڶ����PAD��
           ���Ա�֤amsdu netbufβ��ʣ��ռ��㹻 */
        msdu_len = frame_len + SNAP_LLC_FRAME_LEN;
    }

    amsdu_cb = (hmac_tx_ctl_stru *)oal_netbuf_cb(amsdu_netbuf);
    msdu_cb  = (hmac_tx_ctl_stru *)oal_netbuf_cb(msdu_netbuf);
    amsdu_cb->us_mpdu_bytes += msdu_cb->us_mpdu_bytes;

    headroom = oal_netbuf_headroom(msdu_netbuf);
    /* ͷ��ʣ��ռ䲻����Ҫ��չͷ���ռ� */
    if (oal_unlikely(headroom < SNAP_LLC_FRAME_LEN)) {
        oam_error_log2(0, 0, "hmac_amsdu_encap_hdr:: headroom[%d] is not enough, need[%d]",
            oal_netbuf_headroom(msdu_netbuf), SNAP_LLC_FRAME_LEN);
        return HI_FAIL;
    }
    /* ��װ֡ͷ���� */
    if (hmac_amsdu_encap_hdr_data(amsdu, msdu_netbuf) != HI_SUCCESS) {
        return HI_FAIL;
    }
    /* ����amsdu��Ϣ */
    msdu_cb->us_mpdu_len = (hi_u16)oal_netbuf_len(msdu_netbuf);
    amsdu->last_pad_len = (hi_u8)(msdu_len - SNAP_LLC_FRAME_LEN - frame_len);
    amsdu->msdu_num++;
    amsdu->us_amsdu_size += (hi_u16)oal_netbuf_len(msdu_netbuf);
    /* ���PAD */
    if (amsdu->last_pad_len != 0) {
        oal_netbuf_put(msdu_netbuf, amsdu->last_pad_len);
        if (memset_s(oal_netbuf_data(msdu_netbuf) + oal_netbuf_len(msdu_netbuf), amsdu->last_pad_len, 0,
                     amsdu->last_pad_len) != EOK) {
            oam_error_log0(0, 0, "{hmac_amsdu_encap_hdr_data::mem safe function err!}");
            return HI_FAIL;
        }
    }

    oam_info_log2(0, 0, "{hmac_amsdu_encap::num[%d] size[%d].}", amsdu->msdu_num, amsdu->us_amsdu_size);
    return HI_SUCCESS;
}

static hi_u32  hmac_amsdu_send_event(const hmac_vap_stru *hmac_vap, hmac_amsdu_stru *amsdu, oal_netbuf_stru *net_buf)
{
    /* ���¼� */
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::pst_amsdu_send_event_mem null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���¼�ͷ */
    frw_event_stru *event = (frw_event_stru *)(event_mem->puc_data);
    if (oal_unlikely(event == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::pst_amsdu_send_event null}");
        frw_event_free(event_mem);
        return HI_ERR_CODE_PTR_NULL;
    }
    dmac_tx_event_stru *amsdu_event = (dmac_tx_event_stru *)(event->auc_event_data);
    amsdu_event->netbuf = net_buf;

    /* ����ͷβ���� */
    net_buf = oal_netbuf_delist(&(amsdu->msdu_head));
    if (net_buf == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::oal_netbuf_delist null}");
        frw_event_free(event_mem);
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_HOST_DRX, DMAC_TX_HOST_DRX, sizeof(dmac_tx_event_stru),
        FRW_EVENT_PIPELINE_STAGE_1, hmac_vap->base_vap->vap_id);

    hi_u32 ret = hcc_hmac_tx_data_event(event_mem, net_buf, HI_FALSE);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU, "hmac_amsdu_send::frw_event_dispatch fail[%d]", ret);
        hmac_free_netbuf_list(net_buf);
    }

    /* ����amsdu�ṹ����Ϣ */
    amsdu->us_amsdu_size = 0;
    amsdu->msdu_num   = 0;
    oal_netbuf_list_head_init(&amsdu->msdu_head);

    /* �ͷ��¼��ڴ� */
    frw_event_free(event_mem);

    oam_info_log0(0, OAM_SF_AMSDU, "{hmac_amsdu_send::amsdu send success.");

    return ret;
}

/* AMSDU �˻�Ϊ msdu */
static hi_u32 hmac_amsdu_degenerate_to_msdu(const hmac_vap_stru *hmac_vap, const hmac_amsdu_stru *amsdu,
                                            oal_netbuf_stru *net_buf, hmac_tx_ctl_stru *cb,
                                            mac_ieee80211_qos_frame_stru *mac_header)
{
    if (cb->mac_head_type == 1) { /* MAC ͷ��skb�� */
        hi_u8 *dst_data = (hi_u8 *)oal_netbuf_data(net_buf) + cb->frame_header_length;
        hi_u8 *src_data = (hi_u8 *)oal_netbuf_data(net_buf) + cb->frame_header_length + ETHER_HDR_LEN;
        hi_u32 copy_length = oal_netbuf_len(net_buf) - cb->frame_header_length - ETHER_HDR_LEN;
        if (memmove_s(dst_data, copy_length, src_data, copy_length) != EOK) {
            oam_error_log0(0, 0, "hmac_amsdu_send:: memmove_s fail");
            return HI_FAIL;
        }
        net_buf->len -= ETHER_HDR_LEN;
    } else {
        oal_netbuf_pull(net_buf, ETHER_HDR_LEN);
    }

    if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        if (memcpy_s(cb->frame_header->auc_address3, WLAN_MAC_ADDR_LEN,
                     amsdu->auc_eth_da, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{hmac_amsdu_send::mem safe function err!}");
            return HI_FAIL;
        }
    } else if (!(cb->use_4_addr)) {
        /* ����AP */
        if (memcpy_s(cb->frame_header->auc_address3, WLAN_MAC_ADDR_LEN,
                     amsdu->auc_eth_sa, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{hmac_amsdu_send::mem safe function err!}");
            return HI_FAIL;
        }
    } else { /* WDS */
        /* ��ַ3�� DA */
        if (memcpy_s(cb->frame_header->auc_address3, WLAN_MAC_ADDR_LEN,
                     amsdu->auc_eth_da, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, 0, "{hmac_amsdu_send::mem safe function err!}");
            return HI_FAIL;
        }
    }

    cb->is_amsdu = HI_FALSE;
    cb->is_first_msdu = HI_FALSE;
    cb->us_mpdu_len -= ETHER_HDR_LEN;
    mac_header->qc_amsdu = 0;
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_amsdu_send
 ��������  : ����amsdu
 �������  : pst_user: �û��ṹ��ָ��
             pst_amsdu: Ҫ���͵�amsdu
 �������  : ��
 �� �� ֵ  : �ɹ�HI_SUCCESS��ʧ��HI_ERR_CODE_PTR_NULL
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  hmac_amsdu_send(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, hmac_amsdu_stru *amsdu)
{
    /* ��μ�� */
    if (oal_unlikely((hmac_vap == HI_NULL) || (hmac_user == HI_NULL) || (amsdu == HI_NULL))) {
        oam_error_log3(0, OAM_SF_AMPDU, "{hmac_amsdu_send::input error %p %p %p}",
            (uintptr_t)hmac_vap, (uintptr_t)hmac_user, (uintptr_t)amsdu);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��dmac���͵�amsdu��ص���Ϣ�Լ�802.11ͷ�ҽ� */
    oal_netbuf_stru *net_buf = oal_netbuf_peek(&(amsdu->msdu_head));
    if (oal_unlikely(net_buf == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::pst_net_buf null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_tx_ctl_stru *cb = (hmac_tx_ctl_stru *)oal_netbuf_cb(net_buf);
    cb->us_mpdu_len      = amsdu->us_amsdu_size - amsdu->last_pad_len;
    cb->mpdu_num         = 1;

    /* Ϊ����amsdu��װ802.11ͷ */
    if (oal_unlikely(hmac_tx_encap(hmac_vap, hmac_user, net_buf) != HI_SUCCESS)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMPDU, "{hmac_amsdu_send::hmac_tx_encap failed}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ʾamsdu */
    mac_ieee80211_qos_frame_stru *mac_header = (mac_ieee80211_qos_frame_stru *)cb->frame_header;
    mac_header->qc_amsdu    = 1;

    /* �����һ����֡��PADȥ�� */
    oal_netbuf_trim(net_buf, amsdu->last_pad_len);

    /* ���ֻ��һ��֡(amsdu��ʱ���Σ�tid��ֻ��һ��amsdu�ȴ��ۺϣ�����һֱû�б��
       msdu����)����ȥ����֡����̫��ͷ�����շ�AMSDU����
    */
    if (amsdu->msdu_num == 1) {
        hi_u32 ret = hmac_amsdu_degenerate_to_msdu(hmac_vap, amsdu, net_buf, cb, mac_header);
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, 0, "hmac_amsdu_send:: degenerate_to_msdu failed[%d]", ret);
            return ret;
        }
    }

    return hmac_amsdu_send_event(hmac_vap, amsdu, net_buf);
}

/*****************************************************************************
 �� �� ��  : hmac_amsdu_build_netbuf
 ��������  : �ۺ���װamsdu
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��1��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void hmac_amsdu_build_netbuf(const hmac_amsdu_stru *amsdu, oal_netbuf_stru *netbuf)
{
    hi_u16       us_buf_len;
    hi_u16       us_offset;
    oal_netbuf_stru *dest_buf = HI_NULL;

    us_buf_len = (hi_u16)oal_netbuf_len(netbuf);
    dest_buf = oal_netbuf_peek(&amsdu->msdu_head);
    if (dest_buf == HI_NULL) {
        oam_error_log0(0, OAM_SF_AMSDU, "{hmac_amsdu_build_netbuf::oal_netbuf_peek return NULL}");
        oal_netbuf_free(netbuf);
        return;
    }

    us_offset = (hi_u16)oal_netbuf_len(dest_buf);
    oal_netbuf_put(dest_buf, us_buf_len);
    if (oal_netbuf_data(netbuf) != HI_NULL) {
        if (memcpy_s(oal_netbuf_data(dest_buf) + us_offset, us_buf_len, oal_netbuf_data(netbuf), us_buf_len) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_amsdu_build_netbuf:: pst_buf memcpy_s fail.");
            return;
        }
    }
}
/*****************************************************************************
 �� �� ��  : hmac_amsdu_alloc_netbuf
 ��������  : ����netbuf���ھۺ���װamsdu
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��1��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 hmac_amsdu_alloc_netbuf(hmac_amsdu_stru *amsdu, const oal_netbuf_stru *netbuf)
{
    hmac_tx_ctl_stru *cb = HI_NULL;
    oal_netbuf_stru  *dest_buf = HI_NULL;

    dest_buf = oal_netbuf_alloc(WLAN_LARGE_NETBUF_SIZE, 0, 4);  /* align 4 */
    if (dest_buf == HI_NULL) {
        return HI_FAIL;
    }

    if (memcpy_s(oal_netbuf_cb(dest_buf), sizeof(hmac_tx_ctl_stru), oal_netbuf_cb(netbuf),
                 sizeof(hmac_tx_ctl_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_amsdu_alloc_netbuf:: pst_buf memcpy_s fail.");
        oal_netbuf_free(dest_buf);
        return HI_FAIL;
    }

    /* ��֡����amsduβ�� */
    oal_netbuf_add_to_list_tail(dest_buf, &amsdu->msdu_head);
    oal_netbuf_copy_queue_mapping(dest_buf, netbuf);

    cb = (hmac_tx_ctl_stru *)oal_netbuf_cb(dest_buf);
    cb->is_first_msdu    = HI_TRUE;
    cb->is_amsdu         = HI_TRUE;
    cb->netbuf_num       = 1;
    cb->us_mpdu_bytes       = 0;

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_amsdu_tx_process
 ��������  : amsdu�ۺϷ��ʹ�����
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��1��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  hmac_amsdu_tx_process(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf)
{
    hi_u8               tid_no;
    hi_u32              frame_len;
    hi_u32              ret;
    hmac_amsdu_stru    *amsdu = HI_NULL;
    hmac_tx_ctl_stru   *tx_ctl = HI_NULL;

    tx_ctl = (hmac_tx_ctl_stru *)(oal_netbuf_cb(netbuf));

    frame_len = oal_netbuf_len(netbuf);

    /* ��¼�ֽ�������������̫��ͷ���ȣ�ά���� */
    tx_ctl->us_mpdu_bytes = (hi_u16)(frame_len - ETHER_HDR_LEN);

    tid_no    = tx_ctl->tid;
    amsdu    = hmac_user->past_hmac_amsdu[tid_no];
    if (oal_unlikely(amsdu == HI_NULL)) {
        /* ���ô��Ѿ����ж�, �߼����������ߵ��˴� �����жϷ�ֹ�ȿ�ָ�� */
        return HMAC_TX_DROP_AMSDU_ENCAP_FAIL;
    }

    if (hmac_tx_amsdu_is_overflow(amsdu, tx_ctl, frame_len)) {
        /* ������ʱ�� */
        frw_timer_immediate_destroy_timer(&amsdu->amsdu_timer);

        ret = hmac_amsdu_send(hmac_vap, hmac_user, amsdu);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU,
                             "{hmac_amsdu_tx_process::amsdu send fails. erro code is %d}", (hi_s32)ret);
        }
        return HMAC_TX_PASS;
    }

    if (amsdu->msdu_num == 0) {
        oal_netbuf_list_head_init(&(amsdu->msdu_head));
        /* ����netbuf���ھۺ�amsdu */
        if (HI_SUCCESS != hmac_amsdu_alloc_netbuf(amsdu, netbuf)) {
            oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU, "{hmac_amsdu_process::failed to alloc netbuf.}");
            return HMAC_TX_DROP_AMSDU_ENCAP_FAIL;
        }
        /* ������ʱ�� */
        frw_timer_create_timer(&amsdu->amsdu_timer, hmac_amsdu_tx_timeout_process,
                               HMAC_AMSDU_LIFE_TIME, amsdu, HI_FALSE);
    }

    ret = hmac_amsdu_encap_hdr(amsdu, &netbuf);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU,
            "{in amsdu notify, amsdu encapsulation fails. erro code is %d.}", (hi_s32)ret);
        return HMAC_TX_DROP_AMSDU_ENCAP_FAIL;
    }

    /* ����ۺ�amsdu ��װbuffer */
    hmac_amsdu_build_netbuf(amsdu, netbuf);

    return HMAC_TX_BUFF;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_amsdu_is_overflow
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��2��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static  hi_u8 hmac_tx_amsdu_is_overflow(
    const hmac_amsdu_stru    *amsdu,
    const hmac_tx_ctl_stru    *tx_ctl,
    hi_u32          frame_len)
{
    hi_u32 msdu_len;
    hi_u32 tailroom;
    hmac_tx_ctl_stru     *head_ctl = HI_NULL;
    oal_netbuf_stru     *head_buf = HI_NULL;

    if (amsdu->msdu_num == 0) {
        oam_info_log0(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::uc_msdu_num=0.}");
        return HI_FALSE;
    }

    head_buf = oal_netbuf_peek(&amsdu->msdu_head);
    if (head_buf == HI_NULL) {
        oam_info_log0(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::pst_head_buf null.}");
        return HI_FALSE;
    }

    head_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(head_buf);
    /* amsdu��Ϊ�գ�����amsdu�е���֡��Դ(lan����wlan)�뵱ǰҪ��װ��netbuf��ͬ����amsdu���ͳ�ȥ��
       ����������Ϊ�ڷ���������ͷ�һ��mpduʱ���Ǹ��ݵ�һ��netbuf��cb����д���¼�������ѡ���ͷŲ��ԣ�
       ���һ��mpdu�е�netbuf��Դ��ͬ��������ڴ�й©
    */
    if (tx_ctl->event_type != head_ctl->event_type) {
        oam_info_log2(0, OAM_SF_TX, "{hmac_tx_amsdu_is_overflow::en_event_type mismatched. %d %d.}",
                      tx_ctl->event_type, head_ctl->event_type);
        return HI_TRUE;
    }

    /* ��amsduβ��ʣ��ռ䲻����װ�µ�ǰmsdu ��amsdu���ͳ�ȥ */
    msdu_len = frame_len + SNAP_LLC_FRAME_LEN;
    tailroom = oal_netbuf_tailroom(head_buf);
    if (tailroom < msdu_len) {
        return HI_TRUE;
    }

    /* payload + padmax(3) ���ܴ���1568, ��������֡�� */
    if (((amsdu->us_amsdu_size + frame_len + SNAP_LLC_FRAME_LEN + 3) > 1568) ||
        ((amsdu->msdu_num + 1) > amsdu->amsdu_maxnum)) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : amsdu��ں���
 �������  : pst_user: �û��ṹ��ָ��
             pst_buf: skb�ṹ��ָ��
 �޸���ʷ      :
  1.��    ��   : 2012��11��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_tx_return_type_enum_uint8 hmac_amsdu_notify(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user,
    oal_netbuf_stru *netbuf)
{
    hi_u32 ret;

    /* ���amsdu�����Ƿ��; ����Թر�WMM����QOS֡���� */
    if ((!hmac_vap->amsdu_active) || (!hmac_user->base_user->cap_info.qos)) {
        return HMAC_TX_PASS;
    }

    hmac_tx_ctl_stru *tx_ctl = (hmac_tx_ctl_stru *)(oal_netbuf_cb(netbuf));
    hi_u8 tid_no = tx_ctl->tid;
    if ((hmac_user_is_amsdu_support(hmac_user, tid_no) == HI_FALSE) || /* �жϸ�tid�Ƿ���ampdu�����֧��amsdu�ķ��� */
        (oal_netbuf_is_tcp_ack((oal_ip_header_stru *)(oal_netbuf_data(netbuf) + ETHER_HDR_LEN))) ||
        /* ���Сҵ����ping���ӳ� */
        (oal_netbuf_is_icmp((oal_ip_header_stru *)(oal_netbuf_data(netbuf) + ETHER_HDR_LEN))) ||
        (!hmac_user_xht_support(hmac_user))) { /* ����û��Ƿ���HT/VHT */
        return HMAC_TX_PASS;
    }

    if (oal_unlikely(tid_no >= WLAN_TID_MAX_NUM)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU,
            "{hmac_amsdu_notify::invalid tid number obtained from the cb in asmdu notify function}");
        return HMAC_TX_PASS;
    }
    if (tid_no == WLAN_TIDNO_VOICE) {
        return HMAC_TX_PASS;
    }

    hmac_amsdu_stru *amsdu = hmac_user->past_hmac_amsdu[tid_no];
    if (oal_unlikely(amsdu == HI_NULL)) {
        /* ִ�е�����ָ��Ϊ��,��ʾδ����AMSDU�ڴ�,�����쳣,��ӡά����־ */
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU, "{hmac_amsdu_notify::hmac_amsdu[%d] null}", tid_no);
        return HMAC_TX_PASS;
    }

    oal_spin_lock_bh(&amsdu->st_amsdu_lock);

    /* �����������AMSDU�ۺ��������ҵ�ǰAMSDU�������Ѿ��оۺϰ� ���Ѿۺϵİ����ͳ�ȥ */
    if (oal_netbuf_len(netbuf) > WLAN_MSDU_MAX_LEN) {
        if (amsdu->msdu_num) {
            /* ������ʱ�� */
            frw_timer_immediate_destroy_timer(&amsdu->amsdu_timer);
            ret = hmac_amsdu_send(hmac_vap, hmac_user, amsdu);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU,
                    "{hmac_amsdu_process:: length or number overflow, amsdu send fails. error code is %d}", ret);
            }
        }

        oal_spin_unlock_bh(&amsdu->st_amsdu_lock);
        return HMAC_TX_PASS;
    }
    ret = hmac_amsdu_tx_process(hmac_vap, hmac_user, netbuf);
    oal_spin_unlock_bh(&amsdu->st_amsdu_lock);

    return (hi_u8)ret;
}

/*****************************************************************************
 �� �� ��  : hmac_amsdu_tx_timeout_process
 ��������  : ʱ���ж��¼��Ĵ�����
 �������  : pst_hmac_vap:
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��1��31��
    ��    ��   : Hisilicon
    �޸�����   : ���뻥����

*****************************************************************************/
static hi_u32  hmac_amsdu_tx_timeout_process(hi_void *arg)
{
    hmac_amsdu_stru         *temp_amsdu = HI_NULL;
    hmac_tx_ctl_stru         *cb = HI_NULL;
    hmac_user_stru          *hmac_user = HI_NULL;
    hi_u32               ret;
    oal_netbuf_stru         *netbuf = HI_NULL;
    hmac_vap_stru           *hmac_vap = HI_NULL;
    if (oal_unlikely(arg == HI_NULL)) {
        oam_error_log0(0, OAM_SF_AMPDU, "{hmac_amsdu_tx_timeout_process::input null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    temp_amsdu = (hmac_amsdu_stru *)arg;

    oal_spin_lock_bh(&temp_amsdu->st_amsdu_lock);

    if (temp_amsdu->msdu_num == 0) {
        oam_warning_log1(0, OAM_SF_AMSDU, "hmac_amsdu_tx_timeout_process::msdu_num error[%d]", temp_amsdu->msdu_num);
        oal_spin_unlock_bh(&temp_amsdu->st_amsdu_lock);
        return HI_FAIL;
    }

    /* ����Ҫ���͵�amsdu�µ�һ��msdu��֡��cb�ֶε���ϢѰ�Ҷ�Ӧ�û��ṹ�� */
    netbuf      = oal_netbuf_peek(&temp_amsdu->msdu_head);
    if (netbuf == HI_NULL) {
        oam_error_log1(0, OAM_SF_AMSDU, "hmac_amsdu_tx_timeout_process::pst_netbuf NULL. msdu_num[%d]",
            temp_amsdu->msdu_num);
        oal_spin_unlock_bh(&temp_amsdu->st_amsdu_lock);
        return HI_ERR_CODE_PTR_NULL;
    }

    cb          = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
    hmac_vap    = hmac_vap_get_vap_stru(cb->tx_vap_index);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oal_spin_unlock_bh(&temp_amsdu->st_amsdu_lock);
        oam_error_log0(0, OAM_SF_AMPDU, "{hmac_amsdu_tx_timeout_process::pst_hmac_vap null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(cb->us_tx_user_idx);
    if (oal_unlikely(hmac_user == HI_NULL)) {
        oal_spin_unlock_bh(&temp_amsdu->st_amsdu_lock);
        oam_error_log0(0, OAM_SF_AMPDU, "{hmac_amsdu_tx_timeout_process::pst_user null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    ret = hmac_amsdu_send(hmac_vap, hmac_user, temp_amsdu);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_AMSDU,
            "hmac_amsdu_tx_timeout_process::hmac_amsdu_send fail[%d]", ret);
    }

    oal_spin_unlock_bh(&temp_amsdu->st_amsdu_lock);

    return HI_SUCCESS;
}

#if defined(_PRE_WLAN_FEATURE_SIGMA) || defined(_PRE_WLAN_FEATURE_HIPRIV)
/*****************************************************************************
 ��������  : Ϊhmac user�µ�amsduָ�������ڴ沢��ʼ��,Ŀǰ��֧�������AMSDU
*****************************************************************************/
hi_void hmac_amsdu_mem_alloc(hmac_user_stru *hmac_user, hi_u8 tid_num, hi_u8 max_num)
{
    if (hmac_user == HI_NULL) {
        oam_error_log0(0, OAM_SF_AMPDU, "hmac_amsdu_mem_alloc: hmac_user is null.");
        return;
    }
    if (tid_num >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(0, OAM_SF_AMPDU, "hmac_amsdu_mem_alloc: tid[%d] is invalid.", tid_num);
        return;
    }
    /* ָ�벻Ϊ��,��ʾ�Ѿ�����,���ظ����� */
    if (hmac_user->past_hmac_amsdu[tid_num] == HI_NULL) {
        hmac_user->past_hmac_amsdu[tid_num] = (hmac_amsdu_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL,
            sizeof(hmac_amsdu_stru));
        if (hmac_user->past_hmac_amsdu[tid_num] == HI_NULL) {
            /* ����ʧ�� �������쳣����TID�ɼ�������,��ӡһ����Ϣ���� */
            oam_error_log1(0, OAM_SF_AMPDU,
                "{hmac_config_set_amsdu_tx_on::mem alloc amsdu[tid=%d] ptr null.}", tid_num);
        } else {
            /* amsdu ��ʼ��
               ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
            memset_s(hmac_user->past_hmac_amsdu[tid_num], sizeof(hmac_amsdu_stru), 0, sizeof(hmac_amsdu_stru));
            hmac_amsdu_set_maxnum(hmac_user->past_hmac_amsdu[tid_num], max_num);
            oal_spin_lock_init(&hmac_user->past_hmac_amsdu[tid_num]->st_amsdu_lock);
            oam_warning_log2(0, 0, "hmac_amsdu_mem_alloc:: amsdu_tx_on, tid_num[%d], max_num[%d]",
                tid_num, max_num);
        }
    }
}
#endif

/*****************************************************************************
 ��������  : �ͷ�hmac user�µ�amsduָ���ڴ�
 �޸���ʷ      :
  1.��    ��   : 2019��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_amsdu_mem_free(hmac_user_stru *hmac_user)
{
    hi_u8           index;
    oal_netbuf_stru     *amsdu_net_buf = HI_NULL;

    for (index = 0; index < WLAN_TID_MAX_NUM; index++) {
        hmac_amsdu_stru *amsdu = hmac_user->past_hmac_amsdu[index];
        if (hmac_user->past_hmac_amsdu[index] == HI_NULL) {
            continue;
        }

        /* tid��, �����ж� */
        oal_spin_lock_bh(&amsdu->st_amsdu_lock);

        if (hmac_user->past_hmac_amsdu[index]->amsdu_timer.is_registerd == HI_TRUE) {
            frw_timer_immediate_destroy_timer(&(hmac_user->past_hmac_amsdu[index]->amsdu_timer));
        }
        /* ��վۺ϶��� */
        if (hmac_user->past_hmac_amsdu[index]->msdu_num == 0) {
            oal_mem_free(hmac_user->past_hmac_amsdu[index]);
            hmac_user->past_hmac_amsdu[index] = HI_NULL;
            /* tid����, ʹ�����ж� */
            oal_spin_unlock_bh(&amsdu->st_amsdu_lock);
            continue;
        }

        while (HI_TRUE != oal_netbuf_list_empty(&(hmac_user->past_hmac_amsdu[index]->msdu_head))) {
                    amsdu_net_buf = oal_netbuf_delist(&(hmac_user->past_hmac_amsdu[index]->msdu_head));
            if (amsdu_net_buf) {
                oal_netbuf_free(amsdu_net_buf);
            }
        }
        hmac_user->past_hmac_amsdu[index]->msdu_num = 0;
        oal_mem_free(hmac_user->past_hmac_amsdu[index]);
        hmac_user->past_hmac_amsdu[index] = HI_NULL;
        /* tid����, ʹ�����ж� */
        oal_spin_unlock_bh(&amsdu->st_amsdu_lock);
    }
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
