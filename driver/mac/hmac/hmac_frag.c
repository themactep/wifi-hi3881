/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Slice to slice function
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "frw_timer.h"
#include "hmac_frag.h"
#include "hmac_11i.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ���ķ�Ƭ����
*****************************************************************************/
/* ����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������: ���ķ�Ƭ���������ھۣ��������� */
static hi_u32 hmac_frag_process(oal_netbuf_stru *netbuf_original,
                                hmac_tx_ctl_stru *tx_ctl,
                                hi_u32 cip_hdrsize,
                                hi_u32 max_tx_unit)
{
    mac_ieee80211_frame_stru *frag_header = HI_NULL;
    oal_netbuf_stru          *netbuf = HI_NULL;
    hi_u32                    mac_hdr_size;
    hi_u32                    offset;
    hi_s32                    l_remainder;

    /* �����ֽ��������ڷ�Ƭ�����У�Ԥ�������ֽڳ��ȣ���Ӳ����д����ͷ */
    mac_hdr_size = tx_ctl->frame_header_length;
    offset       = max_tx_unit - cip_hdrsize;
    l_remainder  = (hi_s32)(oal_netbuf_len(netbuf_original) - offset);

    mac_ieee80211_frame_stru *mac_header = tx_ctl->frame_header;
    mac_header->frame_control.more_frag = HI_TRUE;

    hi_u32           total_hdrsize = mac_hdr_size + cip_hdrsize;
    hi_u32           frag_num      = 1;
    oal_netbuf_stru *netbuf_prev   = netbuf_original;

    do {
        hi_u32 frag_size = total_hdrsize + (hi_u32)l_remainder;

        /* �ж��Ƿ��и���ķ�Ƭ */
        frag_size = (frag_size > max_tx_unit) ? max_tx_unit : frag_size;

        netbuf = oal_netbuf_alloc(frag_size + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN,
            MAC_80211_QOS_HTC_4ADDR_FRAME_LEN, 4); /* align 4 */
        if (netbuf == HI_NULL) {
            /* ���ⲿ�ͷ�֮ǰ����ı��� */
            oam_error_log0(0, OAM_SF_ANY, "{hmac_frag_process::pst_netbuf null.}");
            return HI_ERR_CODE_PTR_NULL;
        }

        hmac_tx_ctl_stru *tx_ctl_copy = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
        /* ����cb�ֶ� */
        if (memcpy_s(tx_ctl_copy, sizeof(hmac_tx_ctl_stru), tx_ctl, sizeof(hmac_tx_ctl_stru)) != EOK) {
            oal_netbuf_free(netbuf);
            oam_error_log0(0, OAM_SF_CFG, "hmac_frag_process:: pst_tx_ctl memcpy_s fail.");
            return HI_FAIL;
        }

        /* netbuf��headroom����802.11 macͷ���� */
        frag_header = (mac_ieee80211_frame_stru *)(oal_netbuf_payload(netbuf) - mac_hdr_size);
        tx_ctl_copy->mac_head_type = 1;  /* ָʾmacͷ����skb�� */

        /* ����֡ͷ���� */
        if (memcpy_s(frag_header, mac_hdr_size, mac_header, tx_ctl->frame_header_length) != EOK) {
            oal_netbuf_free(netbuf);
            oam_error_log0(0, OAM_SF_CFG, "hmac_frag_process:: pst_mac_header memcpy_s fail.");
            return HI_FAIL;
        }

        /* ��ֵ��Ƭ�� */
        frag_header->frag_num = frag_num;
        frag_num++;

        /* �����Ƭ����֡�峤�� */
        hi_u32 copy_offset = offset;

        hi_u32 ret = oal_netbuf_copydata(netbuf_original, copy_offset, oal_netbuf_payload(netbuf),
            (frag_size + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN), (frag_size - total_hdrsize));
        if (ret != HI_SUCCESS) {
            oal_netbuf_free(netbuf);
            oam_error_log0(0, OAM_SF_CFG, "hmac_frag_process:: oal_netbuf_copydata return fail.");
            return ret;
        }

        oal_netbuf_set_len(netbuf, (frag_size - total_hdrsize));
        ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf))->frame_header = frag_header;
        ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf))->us_mpdu_len  = (hi_u16)(frag_size - total_hdrsize);
        oal_netbuf_next(netbuf_prev) = netbuf;
        netbuf_prev                  = netbuf;

        oal_netbuf_push(netbuf, mac_hdr_size);

        /* ������һ����Ƭ���ĵĳ��Ⱥ�ƫ�� */
        l_remainder -= (hi_s32)(frag_size - total_hdrsize);
        offset      += (frag_size - total_hdrsize);
    } while (l_remainder > 0);

    frag_header->frame_control.more_frag = HI_FALSE;
    oal_netbuf_next(netbuf) = HI_NULL;

    /* ԭʼ������Ϊ��Ƭ���ĵĵ�һ�� */
    oal_netbuf_trim(netbuf_original, oal_netbuf_len(netbuf_original) - (max_tx_unit - cip_hdrsize));

    tx_ctl->us_mpdu_len = (hi_u16)(oal_netbuf_len(netbuf_original));

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ķ�Ƭ����
 �޸���ʷ      :
  1.��    ��   : 2014��2��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32  hmac_frag_process_proc(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf,
    hmac_tx_ctl_stru *tx_ctl)
{
    hi_u32          threshold;
    hi_u8           ic_header    = 0;
    hi_u32          ret;
    hi_u32          last_frag;

    /* ��ȡ��Ƭ���� */
    threshold = hmac_vap->base_vap->mib_info->wlan_mib_operation.dot11_fragmentation_threshold;

    /* ���ü��ܽӿ���ʹ��TKIPʱ��MSDU���м��ܺ��ڽ��з�Ƭ */
    ret = hmac_en_mic(hmac_user, netbuf, &ic_header);
    if (ret != HI_SUCCESS) {
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_ANY,
            "{hmac_frag_process_proc::hmac_en_mic failed[%d].}", ret);
        return ret;
    }
    /* D2�ֻ�ping��ͨ����,������ֵ4*n+2 */
    threshold = (threshold & (~(BIT0 | BIT1))) + 2;

    /* ���1151Ӳ��bug,������Ƭ���ޣ�TKIP����ʱ�������һ����Ƭ��payload����С�ڵ���8ʱ���޷����м��� */
    if (hmac_user->base_user->key_info.cipher_type == WLAN_80211_CIPHER_SUITE_TKIP) {
        last_frag = oal_netbuf_len(netbuf) % (threshold - (hi_u32)ic_header - tx_ctl->frame_header_length);
        if ((last_frag > 0) && (last_frag <= 8)) { /* 0:���ȣ�8:���� */
            threshold = threshold + 8; /* 8:���޼�8 */
            oam_info_log1(hmac_vap->base_vap->vap_id, OAM_SF_ANY,
                "{hmac_frag_process_proc::adjust the frag threshold to %d.}", threshold);
        }
    }
    /* ���з�Ƭ���� */
    ret = hmac_frag_process(netbuf, tx_ctl, (hi_u32)ic_header, threshold);

    return ret;
}

/*****************************************************************************
 ��������  : ���Ƭ��ʱ����
 �޸���ʷ      :
  1.��    ��   : 2014��2��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32  hmac_defrag_timeout_fn(hi_void *arg)
{
    hmac_user_stru  *hmac_user = HI_NULL;
    oal_netbuf_stru *netbuf = HI_NULL;
    hmac_user = (hmac_user_stru *)arg;

    /* ��ʱ���ͷ���������ķ�Ƭ���� */
    if (hmac_user->defrag_netbuf) {
        netbuf = hmac_user->defrag_netbuf;

        oal_netbuf_free(netbuf);
        hmac_user->defrag_netbuf = HI_NULL;
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_defrag_process_frame(hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf, hi_u8 frag_num,
    const mac_ieee80211_frame_stru *mac_hdr, hi_u8 more_frag)
{
    /* ��Ƭ��Ƭ�ķ�Ƭ�Ų�Ϊ0���ͷ� */
    if (frag_num != 0) {
        oal_netbuf_free(netbuf);
        oam_info_log3(hmac_user->base_user->vap_id, OAM_SF_ANY,
            "{hmac_defrag_process:frag_num not Zero %d,seq_num %d,frag %d}", frag_num, mac_hdr->seq_num, more_frag);
        return HI_FAIL;
    }

    /* ������ʱ��ʱ������ʱ�ͷ����鱨�� */
    frw_timer_create_timer(&hmac_user->defrag_timer, hmac_defrag_timeout_fn, HMAC_FRAG_TIMEOUT, hmac_user,
                           HI_FALSE);
#ifdef _PRE_LWIP_ZERO_COPY
    oal_netbuf_stru *new_buf = oal_pbuf_netbuf_alloc(HMAC_MAX_FRAG_SIZE);
#else
    /* �ڴ��netbufֻ��1600 ���ܲ���������A��˾����2500����ϵͳԭ��̬���� */
    oal_netbuf_stru *new_buf = oal_netbuf_alloc(HMAC_MAX_FRAG_SIZE, 0, 4);  /* align 4 */
#endif
    if (new_buf == HI_NULL) {
        oam_error_log0(hmac_user->base_user->vap_id, OAM_SF_ANY, "{hmac_defrag_process::Alloc new_buf null.}");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    if (memcpy_s(oal_netbuf_cb(new_buf), oal_netbuf_cb_size(),
        oal_netbuf_cb(netbuf), oal_netbuf_cb_size()) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_defrag_process::mem safe function err!}");
        oal_netbuf_free(new_buf);
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }
    hmac_rx_ctl_stru *rx_ctl = (hmac_rx_ctl_stru *)oal_netbuf_cb(new_buf);
    hmac_user->defrag_netbuf = new_buf;

#ifdef _PRE_LWIP_ZERO_COPY
    oal_netbuf_reserve(new_buf, WLAN_MAX_MAC_HDR_LEN - rx_ctl->mac_header_len);
#endif

    /* ����Ƭ���Ŀ�����������ı����в��ҽӵ��û��ṹ���£��ͷ�ԭ�еı��� */
    oal_netbuf_init(new_buf, oal_netbuf_len(netbuf));
    if (memcpy_s(new_buf->data, HMAC_MAX_FRAG_SIZE, netbuf->data, netbuf->len) != EOK) {
        oam_error_log0(0, 0, "hmac_defrag_process_frame:: memcpy_s FAILED");
        oal_netbuf_free(hmac_user->defrag_netbuf);
        hmac_user->defrag_netbuf = HI_NULL;
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }
    rx_ctl->pul_mac_hdr_start_addr = (hi_u32 *)oal_netbuf_header(new_buf);
    oal_netbuf_free(netbuf);

    return HI_SUCCESS;
}

oal_netbuf_stru* hmac_get_defraged_netbuf(hmac_user_stru *hmac_user, mac_ieee80211_frame_stru *last_hdr)
{
    oal_netbuf_stru *netbuf = hmac_user->defrag_netbuf;
    /* ������õı��Ľ���mic��� */
    if (hmac_de_mic(hmac_user, netbuf) != HI_SUCCESS) {
        oal_netbuf_free(netbuf);
        netbuf = HI_NULL;
        last_hdr = HI_NULL;
    }

    hmac_user->defrag_netbuf = HI_NULL;
    if (last_hdr == HI_NULL) {
        oam_error_log0(0, 0, "{get_defraged_netbuf::pst_last_hdr null.}");
        return HI_NULL;
    }

    last_hdr->frag_num = 0;
    frw_timer_immediate_destroy_timer(&hmac_user->defrag_timer);
    return netbuf;
}

/*****************************************************************************
 ��������  : ȥ��Ƭ����
 �޸���ʷ      :
  1.��    ��   : 2014��2��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
oal_netbuf_stru* hmac_defrag_process(hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf, hi_u32 hrdsize)
{
    mac_ieee80211_frame_stru *last_hdr  = HI_NULL;

    mac_ieee80211_frame_stru *mac_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(netbuf);
    hi_u8 more_frag = (hi_u8)mac_hdr->frame_control.more_frag;

    /* ���û��ʲô����ȥ��Ƭ����ֱ�ӷ��� */
    if (!more_frag && ((hi_u8)mac_hdr->frag_num == 0) && (hmac_user->defrag_netbuf == HI_NULL)) {
        return netbuf;
    }

    /* ���ȼ�鵽���ķ�Ƭ�����ǲ���������������ķ�Ƭ���� */
    if (hmac_user->defrag_netbuf) {
        frw_timer_restart_timer(&hmac_user->defrag_timer, HMAC_FRAG_TIMEOUT, HI_FALSE);
        last_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(hmac_user->defrag_netbuf);
        /* �����ַ��ƥ�䣬���кŲ�ƥ�䣬��Ƭ�Ų�ƥ�����ͷ�������������ı��� */
        if (mac_hdr->seq_num != last_hdr->seq_num || (hi_u8)mac_hdr->frag_num != ((hi_u8)last_hdr->frag_num + 1) ||
            oal_compare_mac_addr(last_hdr->auc_address1, mac_hdr->auc_address1, WLAN_MAC_ADDR_LEN) ||
            oal_compare_mac_addr(last_hdr->auc_address2, mac_hdr->auc_address2, WLAN_MAC_ADDR_LEN)) {
            oal_netbuf_free(hmac_user->defrag_netbuf);
            frw_timer_immediate_destroy_timer(&hmac_user->defrag_timer);
            hmac_user->defrag_netbuf = HI_NULL;
        }
    }

    /* �жϵ����ķ�Ƭ�����Ƿ��ǵ�һ����Ƭ */
    if (hmac_user->defrag_netbuf == HI_NULL) {
        if (hmac_defrag_process_frame(hmac_user, netbuf, (hi_u8)mac_hdr->frag_num, mac_hdr, more_frag) != HI_SUCCESS) {
            return HI_NULL;
        }
    } else {
        /* �˷�Ƭ�������ĵ����ķ�Ƭ��������ʱ�������������� */
        frw_timer_restart_timer(&hmac_user->defrag_timer, HMAC_FRAG_TIMEOUT, HI_FALSE);
        oal_netbuf_pull(netbuf, hrdsize);
        /* ȥ��Ƭʧ���ͷŵ�ǰ��Ƭ���� */
        if (oal_netbuf_concat(hmac_user->defrag_netbuf, netbuf) != HI_SUCCESS) {
            oal_netbuf_free(hmac_user->defrag_netbuf);
            frw_timer_immediate_destroy_timer(&hmac_user->defrag_timer);
            hmac_user->defrag_netbuf = HI_NULL;
            return HI_NULL;
        }
        /* ��¼���·�Ƭ���ĵķ�Ƭ�� */
        last_hdr->seq_num   = mac_hdr->seq_num;
        last_hdr->frag_num  = mac_hdr->frag_num;
    }

    /* �ж��Ƿ�������ϣ����ڸ��౨�ķ��ؿ�ָ�룬������Ϸ�����õı��� */
    if (more_frag) {
        return HI_NULL;
    }

    return hmac_get_defraged_netbuf(hmac_user, last_hdr);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

