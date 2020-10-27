/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hcc driver implementatioin.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_HCC_SLAVE_IF_H
#define __OAL_HCC_SLAVE_IF_H

#include "oal_net.h"
#include "oal_mem.h"
#include "hcc_comm.h"
#include "wlan_spec_1131h.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/******************************************************************************
 * �궨��
******************************************************************************/
#define HCC_LONG_PACKAGE_SIZE       (WLAN_LARGE_NETBUF_SIZE)
#ifndef FRW_EVENT_HCC_BURST_COUNT
#define FRW_EVENT_HCC_BURST_COUNT   64
#endif

/******************************************************************************
 * ö�ٶ���
******************************************************************************/
typedef hi_void (*hcc_msg_cb)(hi_u32 msg);

typedef enum {
    HCC_TX_LINUX_BYPASS,
    HCC_TX_SDIO_HOST_BYPASS,
    HCC_TX_SDIO_SLAVE_BYPASS,
    HCC_TX_HAL_HARDWARE_BYPASS,
    HCC_THRUPUT_BYPASS_BUTT,
} hcc_thruput_bypass;  /* oal_thruput_bypass_enum */

/* ���ͽṹ�� */
typedef struct {
    hi_u32             tx_pkt_bytes;         /* ���������ֽ��� */
    oal_dev_netbuf_stru* netbuf;
} hcc_slave_tx_pack;

/* ���ͷ�����Ϣ�ṹ��,Device To Host */
typedef struct {
    hi_u32             aggr_tx_num;         /* TX����ۺ�֡���� */
    hi_u32             tx_aggr_total_len;   /* TX����ۺ�֡Pad֮ǰ���ܳ��� */
    hcc_slave_tx_pack  hcc_tx_aggr[HISDIO_DEV2HOST_SCATT_MAX]; /* TX����ۺ�֡���� */
} hcc_slave_tx_info;

/* ���սṹ�� */
typedef struct {
    hi_u32               rx_pkt_bytes;         /* ���������ֽ��� ,����HCCͷ+PayLoad */
    oal_dev_netbuf_stru* netbuf;
} hcc_slave_rx_pack;

/* ���շ�����Ϣ�ṹ��, Host To Device */
typedef struct {
    hi_u32             aggr_rx_num;          /* RX����ۺ�֡���� */
    hi_u32             trans_len;            /* RX�����䱨�ĳ��� */
    hi_u32             rx_aggr_total_len;    /* TX����ۺ�֡Pad֮ǰ���ܳ��� */
    hcc_slave_rx_pack  hcc_rx_aggr[HISDIO_HOST2DEV_SCATT_MAX + 1]; /* RX����ۺ�֡����,��1�����ڷ���Padding���� */
} hcc_slave_rx_info;

typedef struct {
    hi_s32               len;                /* for hcc transfer */
    oal_dev_netbuf_stru* net_buf;
} hcc_slave_netbuf;

typedef hi_s32(*hcc_rx_pre_do) (hi_u8 stype, hcc_slave_netbuf* net_buf, hi_u8** pre_do_context);
typedef hi_s32(*hcc_rx_post_do) (hi_u8 stype, const hcc_slave_netbuf* net_buf, hi_u8* pre_do_context);

typedef struct {
    hi_u32         pkts_count;
    hcc_rx_pre_do  pre_do;
    hcc_rx_post_do post_do;
    hi_void*       context;              /* the callback argument */
} hcc_rx_action;

typedef struct {
    hcc_rx_action action[HCC_ACTION_TYPE_BUTT];
} hcc_rx_action_info;

struct hcc_handler {
    hcc_rx_action_info rx_action_info;
};

/******************************************************************************
 * ȫ�ֱ�������
******************************************************************************/
/******************************************************************************
  ��������
******************************************************************************/
hi_u32 hcc_slave_init(hi_void);
hi_u32 hcc_slave_reinit(hi_void);
hi_void hcc_slave_clean(hi_void);
hi_void hcc_slave_tx_queue_sched(hi_void);
hi_void hcc_slave_rx_queue_sched(hi_void);
struct hcc_handler* hcc_get_default_handler(hi_void);
hi_void hcc_slave_tx(oal_dev_netbuf_stru* dev_netbuf, hi_u16 pay_load_len, const hcc_transfer_param* param);
hi_void hcc_register_msg_callback(hcc_msg_cb msg_callback);
hi_u32 hcc_rx_register(struct hcc_handler* hcc, hi_u8 mtype, hcc_rx_post_do post_do, hcc_rx_pre_do pre_do);
hi_u8 hcc_get_thruput_bypass_enable(hcc_thruput_bypass bypass_type);
hi_void hcc_set_thruput_bypass_enable(hcc_thruput_bypass bypass_type, hi_u8 value);
hi_u8* hcc_get_extend_payload_addr(const oal_dev_netbuf_stru* dev_netbuf);
hi_void* hcc_get_extern_address(const oal_dev_netbuf_stru* dev_netbuf, hi_u32 extend_len);
hi_u8* hcc_get_extend_addr(const oal_dev_netbuf_stru* dev_netbuf, hi_u32 extend_len);
hi_void hcc_update_high_priority_buffer_credit(hi_u8 free_large_buffer, hi_u8 free_mgmt_buffer, hi_u8 tx_dscr_free_cnt);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hcc_slave.h */
