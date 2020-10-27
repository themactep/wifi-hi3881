/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_rx_data.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_RX_DATA_H__
#define __HMAC_RX_DATA_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_frame.h"
#include "dmac_ext_if.h"
#include "hmac_user.h"
#include "oal_net.h"
#include "hmac_device.h"
#include "hmac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define HMAC_RX_DATA_ETHER_OFFSET_LENGTH      6 /* ������lan�İ�����Ҫ��д��̫��ͷ����Ҫ��ǰƫ��6 */

/*****************************************************************************
  3 �ṹ�嶨��
*****************************************************************************/
/* ÿһ��MSDU���������ݵĽṹ��Ķ��� */
typedef struct {
    hi_u8               auc_sa[WLAN_MAC_ADDR_LEN];      /* MSDU���͵�Դ��ַ */
    hi_u8               auc_da[WLAN_MAC_ADDR_LEN];      /* MSDU���յ�Ŀ�ĵ�ַ */
    hi_u8               auc_ta[WLAN_MAC_ADDR_LEN];      /* MSDU���յķ��͵�ַ */
    hi_u8               priority;
    hi_u8               auc_resv;

    oal_netbuf_stru        *netbuf;                 /* MSDU��Ӧ��netbufָ��(����ʹclone��netbuf) */
}hmac_msdu_stru;

/* ����MPDU��MSDU�Ĵ���״̬�Ľṹ��Ķ��� */
typedef struct {
    oal_netbuf_stru        *curr_netbuf;          /* ��ǰ�����netbufָ�� */
    hi_u8              *puc_curr_netbuf_data;         /* ��ǰ�����netbuf��dataָ�� */
    hi_u16              us_submsdu_offset;            /* ��ǰ�����submsdu��ƫ����,   */
    hi_u8               msdu_nums_in_netbuf;       /* ��ǰnetbuf�������ܵ�msdu��Ŀ */
    hi_u8               procd_msdu_in_netbuf;      /* ��ǰnetbuf���Ѵ����msdu��Ŀ */
}hmac_msdu_proc_state_stru;

/* HMACģ��������̴���MSDU״̬ */
typedef enum {
    MAC_PROC_ERROR  = 0,
    MAC_PROC_LAST_MSDU,
    MAC_PROC_MORE_MSDU,
    MAC_PROC_LAST_MSDU_ODD,

    MAC_PROC_BUTT
}hmac_msdu_proc_status_enum;
typedef hi_u8 hmac_msdu_proc_status_enum_uint8;

/*****************************************************************************
  4 ��������
*****************************************************************************/
hi_u32 hmac_rx_process_data_ap(frw_event_mem_stru *event_mem);
hi_void hmac_rx_process_data_ap_tcp_ack_opt(const hmac_vap_stru *hmac_vap, const oal_netbuf_head_stru *netbuf_header);
hi_u32 hmac_rx_process_data_sta(frw_event_mem_stru *event_mem);
hi_void hmac_rx_free_netbuf(oal_netbuf_stru *netbuf, hi_u16 us_nums);
hi_void hmac_rx_free_netbuf_list(oal_netbuf_head_stru *netbuf_hdr, hi_u16 num_buf);

hi_void hmac_rx_lan_frame(const oal_netbuf_head_stru *netbuf_header);
#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
hi_void hmac_pkt_mem_opt_init(hmac_device_stru *hmac_dev);
hi_void hmac_pkt_mem_opt_exit(hmac_device_stru *hmac_dev);
hi_void hmac_pkt_mem_opt_cfg(hi_u32 cfg_tpye, hi_u32 cfg_value);
#endif

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_RX_DATA_H__ */
