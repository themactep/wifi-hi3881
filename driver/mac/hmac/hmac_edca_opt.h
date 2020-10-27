/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_edca_opt.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_EDCA_OPT_H__
#define __HMAC_EDCA_OPT_H__

/*****************************************************************************
   ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_device.h"
#include "dmac_ext_if.h"
#include "oam_ext_if.h"
#include "hmac_user.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
   �궨��
*****************************************************************************/
#define HMAC_EDCA_OPT_MIN_PKT_LEN       256                 /* С�ڸó��ȵ�ip���Ĳ���ͳ�ƣ��ų�chariot���Ʊ��� */
#define HMAC_EDCA_OPT_TIME_MS           30000               /* edca��������Ĭ�϶�ʱ�� */
#define HMAC_EDCA_OPT_PKT_NUM           ((HMAC_EDCA_OPT_TIME_MS) >> 3)  /* ƽ��ÿ���뱨�ĸ��� */
#define WLAN_EDCA_OPT_MAX_WEIGHT_STA    3
#define WLAN_EDCA_OPT_WEIGHT_STA        2

/*****************************************************************************
  ��������
*****************************************************************************/
hi_void hmac_edca_opt_rx_pkts_stat(hmac_user_stru *hmac_user, hi_u8 tidno, const mac_ip_header_stru *ip);
hi_void hmac_edca_opt_tx_pkts_stat(const hmac_tx_ctl_stru *tx_ctl, hi_u8 tidno, const mac_ip_header_stru *ip);
hi_u32 hmac_edca_opt_timeout_fn(hi_void *arg);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __HMAC_EDCA_OPT_H__ */
