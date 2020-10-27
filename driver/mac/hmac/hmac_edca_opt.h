/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_edca_opt.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_EDCA_OPT_H__
#define __HMAC_EDCA_OPT_H__

/*****************************************************************************
   其他头文件包含
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
   宏定义
*****************************************************************************/
#define HMAC_EDCA_OPT_MIN_PKT_LEN       256                 /* 小于该长度的ip报文不被统计，排除chariot控制报文 */
#define HMAC_EDCA_OPT_TIME_MS           30000               /* edca参数调整默认定时器 */
#define HMAC_EDCA_OPT_PKT_NUM           ((HMAC_EDCA_OPT_TIME_MS) >> 3)  /* 平均每毫秒报文个数 */
#define WLAN_EDCA_OPT_MAX_WEIGHT_STA    3
#define WLAN_EDCA_OPT_WEIGHT_STA        2

/*****************************************************************************
  函数声明
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
