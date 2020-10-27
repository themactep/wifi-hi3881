/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hmac_chan_mgmt.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  ͷ�ļ�����
*****************************************************************************/
#include "dmac_ext_if.h"
#include "frw_event.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ��������
*****************************************************************************/
/* dmac -> hmac cb�ֶ�ת�� */
hi_void get_mac_rx_ctl(hmac_rx_ctl_stru *hmac_rx_ctl, const dmac_rx_ctl_stru *dmac_rx_ctl)
{
    hmac_rx_ctl->amsdu_enable    = dmac_rx_ctl->rx_info.amsdu_enable;
    hmac_rx_ctl->buff_nums       = dmac_rx_ctl->rx_info.buff_nums;
    hmac_rx_ctl->us_da_user_idx  = dmac_rx_ctl->rx_info.da_user_idx;
    hmac_rx_ctl->is_first_buffer = dmac_rx_ctl->rx_info.is_first_buffer;
    hmac_rx_ctl->is_fragmented   = dmac_rx_ctl->rx_info.is_fragmented;
    hmac_rx_ctl->mac_header_len  = dmac_rx_ctl->rx_info.mac_header_len;
    hmac_rx_ctl->us_ta_user_idx  = dmac_rx_ctl->rx_info.ta_user_idx;
    hmac_rx_ctl->vap_id          = dmac_rx_ctl->rx_info.vap_id;
    hmac_rx_ctl->msdu_in_buffer  = dmac_rx_ctl->rx_info.msdu_in_buffer;
    hmac_rx_ctl->us_frame_len    = dmac_rx_ctl->rx_info.us_frame_len;
    hmac_rx_ctl->mac_vap_id      = dmac_rx_ctl->rx_info.mac_vap_id;
    hmac_rx_ctl->channel_number  = dmac_rx_ctl->rx_info.channel_number;
    hmac_rx_ctl->is_beacon       = dmac_rx_ctl->rx_info.is_beacon;
    hmac_rx_ctl->rssi_dbm        = dmac_rx_ctl->rx_statistic.rssi_dbm;
}

hi_u32 hmac_hcc_rx_event_comm_adapt(const frw_event_mem_stru *hcc_event_mem)
{
    hi_u8                       mac_header_len;
    frw_event_hdr_stru         *event_hdr = HI_NULL;
    hcc_event_stru             *hcc_event_payload = HI_NULL;

    hmac_rx_ctl_stru           *pst_rx_ctrl = HI_NULL;
    hi_u8                      *hcc_extend_hdr = HI_NULL;

    /* step1 ��ȡǶ�׵�ҵ���¼����� */
    event_hdr           = frw_get_event_hdr(hcc_event_mem);
    hcc_event_payload   = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);
    /* ��ɴ�51Mac rx ctl ��02 Mac rx ctl�Ŀ���,�����˴�,pad_payload�Ѿ���0 */
    /* hcc protocol header
        |-------hcc total(64B)-----|-----------package mem--------------|
        |hcc hdr|pad hdr|hcc extend|pad_payload|--------payload---------|
    */
    if (OAL_WARN_ON(hcc_event_payload->netbuf == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "hmac_hcc_rx_event_comm_adapt:did't found netbuf!");
        return HI_FAIL;
    }
    hcc_extend_hdr  = oal_netbuf_data((oal_netbuf_stru *)hcc_event_payload->netbuf);
    mac_header_len = ((dmac_rx_ctl_stru *)hcc_extend_hdr)->rx_info.mac_header_len;
    if (mac_header_len) {
        if (mac_header_len > WLAN_MAX_MAC_HDR_LEN) {
            oam_error_log3(event_hdr->vap_id, OAM_SF_ANY, "invaild mac header len:%d,main:%d,sub:%d",
                           mac_header_len, event_hdr->type, event_hdr->sub_type);
            oal_print_hex_dump(hcc_extend_hdr,
                (hi_s32)oal_netbuf_len((oal_netbuf_stru *)hcc_event_payload->netbuf),
                32, "invaild mac header len");  /* group size 32 */
            return HI_FAIL;
        }

        pst_rx_ctrl  = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)hcc_event_payload->netbuf);
        get_mac_rx_ctl(pst_rx_ctrl, (dmac_rx_ctl_stru *)hcc_extend_hdr) ;

        /* ��Ҫ�޸�pst_rx_ctrl������ָ�� */
        pst_rx_ctrl->pul_mac_hdr_start_addr =
            (hi_u32 *)(hcc_extend_hdr + HI_MAX_DEV_CB_LEN + WLAN_MAX_MAC_HDR_LEN - pst_rx_ctrl->mac_header_len);

        /* ��mac header��������ߵ�ַƫ��8���ֽڿ�����ʹ��mac header��payload���������� */
        if (memmove_s((hi_u8 *)pst_rx_ctrl->pul_mac_hdr_start_addr, pst_rx_ctrl->mac_header_len,
            (hi_u8 *)((hi_u8 *)pst_rx_ctrl->pul_mac_hdr_start_addr -
            (WLAN_MAX_MAC_HDR_LEN - pst_rx_ctrl->mac_header_len)), pst_rx_ctrl->mac_header_len) != EOK) {
                return HI_FAIL;
        }

        /* ��netbuff dataָ���Ƶ�payloadλ�� */
        oal_netbuf_pull(hcc_event_payload->netbuf, HI_MAX_DEV_CB_LEN +
            (WLAN_MAX_MAC_HDR_LEN - pst_rx_ctrl->mac_header_len));
    } else {
        oal_netbuf_pull(hcc_event_payload->netbuf, (HI_MAX_DEV_CB_LEN + WLAN_MAX_MAC_HDR_LEN));
    }

    return HI_SUCCESS;
}

frw_event_mem_stru *hmac_hcc_expand_rx_adpat_event(const frw_event_mem_stru *hcc_event_mem, hi_u32 event_size)
{
    frw_event_hdr_stru             *hcc_event_hdr;
    hcc_event_stru                 *hcc_event_payload;
    oal_netbuf_stru                *hcc_netbuf;
    frw_event_type_enum_uint8       en_type;
    hi_u8                           sub_type;
    hi_u8                           vap_id;
    frw_event_mem_stru             *event_mem;              /* ҵ���¼������Ϣ */

    /* ��ȡHCC�¼���Ϣ */
    hcc_event_hdr       = frw_get_event_hdr(hcc_event_mem);
    hcc_event_payload   = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);
    hcc_netbuf          = hcc_event_payload->netbuf;
    en_type             = hcc_event_hdr->type;
    sub_type            = hcc_event_hdr->sub_type;
    vap_id              = hcc_event_hdr->vap_id;

    /* ����ҵ���¼� */
    event_mem = frw_event_alloc((hi_u16)event_size);
    if (OAL_WARN_ON(event_mem == HI_NULL)) {
        oam_warning_log1(0, 0, "hmac_hcc_expand_rx_adpat_event:: alloc event failed, event len[%d]", event_size);
        /* �ͷ�hcc�¼��������netbuf�ڴ� */
        oal_netbuf_free(hcc_netbuf);
        return HI_NULL;
    }

    /* ��ҵ���¼�ͷ */
    frw_event_hdr_init(frw_get_event_hdr(event_mem),
                       en_type,
                       sub_type,
                       (hi_u16)event_size,
                       FRW_EVENT_PIPELINE_STAGE_1,
                       vap_id);

    return event_mem;
}

/* Hmac ģ�齫netbuf�е��¼����ݻ�ԭ���¼��ڴ��� */
frw_event_mem_stru *hmac_hcc_rx_netbuf_convert_to_event(const frw_event_mem_stru *hcc_event_mem, hi_u32 revert_size)
{
    hcc_event_stru                 *hcc_event_payload = HI_NULL;
    oal_netbuf_stru                *hcc_netbuf = HI_NULL;
    frw_event_mem_stru             *event_mem = HI_NULL;              /* ҵ���¼������Ϣ */
    hi_u32 ret;

    if (OAL_WARN_ON(hcc_event_mem == HI_NULL)) {
        return HI_NULL;
    }

    /* filter the extend buf */
    ret = hmac_hcc_rx_event_comm_adapt(hcc_event_mem);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hmac_hcc_rx_netbuf_convert_to_event:call hmac_hcc_rx_event_comm_adapt fail!");
    }

    hcc_event_payload   = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);
    hcc_netbuf          = hcc_event_payload->netbuf;

    if (OAL_WARN_ON(hcc_netbuf == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "Fatal Error,payload did't contain any netbuf!");
        return HI_NULL;
    }

    if (revert_size > oal_netbuf_len(hcc_netbuf)) {
        revert_size = oal_netbuf_len(hcc_netbuf);
    }

    event_mem = hmac_hcc_expand_rx_adpat_event(hcc_event_mem, revert_size);
    if (event_mem == HI_NULL) {
        return HI_NULL;
    }

    if (revert_size) {
        if (memcpy_s((hi_u8 *)frw_get_event_payload(event_mem), revert_size,
            (hi_u8 *)oal_netbuf_data(hcc_netbuf), revert_size) != EOK) {
            return HI_NULL;
        }
    }

    /* �ͷ�hcc�¼��������netbuf�ڴ� */
    oal_netbuf_free(hcc_netbuf);

    return event_mem;
}

frw_event_mem_stru* hmac_hcc_rx_convert_netbuf_to_event_default(frw_event_mem_stru *hcc_event_mem)
{
    hcc_event_stru                  *hcc_event_payload = HI_NULL;

    if (OAL_WARN_ON(hcc_event_mem == HI_NULL)) {
        return HI_NULL;
    }

    hcc_event_payload = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);
    return hmac_hcc_rx_netbuf_convert_to_event(hcc_event_mem, hcc_event_payload->buf_len);
}

frw_event_mem_stru* hmac_rx_convert_netbuf_to_netbuf_default(frw_event_mem_stru *hcc_event_mem)
{
    hcc_event_stru                  *hcc_event_payload = HI_NULL;
    frw_event_mem_stru              *event_mem = HI_NULL;
    dmac_tx_event_stru              *dmax_ctx_event = HI_NULL;
    hmac_rx_ctl_stru                *hmac_rx_ctrl = HI_NULL;
    hi_u32 ret;

    hcc_event_payload   = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);

    /* filter the extend buf */
    ret = hmac_hcc_rx_event_comm_adapt(hcc_event_mem);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hmac_hcc_rx_netbuf_convert_to_event:call hmac_hcc_rx_event_comm_adapt fail!");
    }

    event_mem = hmac_hcc_expand_rx_adpat_event(hcc_event_mem, sizeof(dmac_tx_event_stru));
    if (event_mem == HI_NULL) {
        return HI_NULL;
    }

    hmac_rx_ctrl  = (hmac_rx_ctl_stru *)oal_netbuf_cb((oal_netbuf_stru *)hcc_event_payload->netbuf);
    dmax_ctx_event               = (dmac_tx_event_stru *)frw_get_event_payload(event_mem);

    dmax_ctx_event->netbuf   = hcc_event_payload->netbuf;
    dmax_ctx_event->us_frame_len = oal_netbuf_len((oal_netbuf_stru *)hcc_event_payload->netbuf) -
                                  hmac_rx_ctrl->mac_header_len;

    return event_mem;
}

frw_event_mem_stru* hmac_rx_process_data_sta_rx_adapt(frw_event_mem_stru *hcc_event_mem)
{
    hcc_event_stru                  *hcc_event_payload;
    frw_event_mem_stru              *event_mem = HI_NULL;
    dmac_wlan_drx_event_stru        *wlan_rx_event = HI_NULL;
    hi_u32 ret;

    hcc_event_payload   = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);

    /* filter the extend buf */
    ret = hmac_hcc_rx_event_comm_adapt(hcc_event_mem);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hmac_hcc_rx_netbuf_convert_to_event:call hmac_hcc_rx_event_comm_adapt fail!");
    }

    event_mem = hmac_hcc_expand_rx_adpat_event(hcc_event_mem, sizeof(dmac_wlan_drx_event_stru));
    if (event_mem == HI_NULL) {
        return HI_NULL;
    }

    /* ��ҵ���¼���Ϣ */
    wlan_rx_event                 = (dmac_wlan_drx_event_stru *)frw_get_event_payload(event_mem);
    wlan_rx_event->netbuf     = hcc_event_payload->netbuf;
    wlan_rx_event->us_netbuf_num  = 1; /* Ŀǰ��֧��ͨ��SDIO��������Ĭ�϶��ǵ�֡ */

    return event_mem;
}

frw_event_mem_stru* hmac_rx_process_mgmt_event_rx_adapt(frw_event_mem_stru *hcc_event_mem)
{
    hcc_event_stru                  *hcc_event_payload;
    frw_event_mem_stru              *event_mem = HI_NULL;
    dmac_wlan_crx_event_stru        *wlan_rx_event = HI_NULL;
    hi_u32 ret;

    /* ȡHCC�¼���Ϣ */
    hcc_event_payload   = (hcc_event_stru *)frw_get_event_payload(hcc_event_mem);

    /* filter the extend buf */
    ret = hmac_hcc_rx_event_comm_adapt(hcc_event_mem);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hmac_hcc_rx_netbuf_convert_to_event:call hmac_hcc_rx_event_comm_adapt fail!");
    }

    event_mem = hmac_hcc_expand_rx_adpat_event(hcc_event_mem, sizeof(dmac_wlan_crx_event_stru));
    if (event_mem == HI_NULL) {
        return HI_NULL;
    }

    /* ��ҵ���¼���Ϣ */
    wlan_rx_event                 = (dmac_wlan_crx_event_stru *)frw_get_event_payload(event_mem);
    wlan_rx_event->netbuf         = hcc_event_payload->netbuf;

    return event_mem;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

