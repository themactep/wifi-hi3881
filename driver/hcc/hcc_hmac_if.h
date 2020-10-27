/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hcc_hmac.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HCC_HMAC_H__
#define __HCC_HMAC_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "hi_types.h"
#include "oal_err_wifi.h"
#include "frw_event.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
/*****************************************************************************
  3 枚举定义
*****************************************************************************/
/*****************************************************************************
  4 全局变量声明
*****************************************************************************/
/*****************************************************************************
  5 消息头定义
*****************************************************************************/
typedef hi_u32 (*hcc_hmac_rx_control_event)(frw_event_mem_stru *event_mem);
typedef hi_u32 (*hcc_hmac_rx_data_event)(frw_event_mem_stru *event_mem, oal_netbuf_stru *netbuf,
    hi_u16 netbuf_num);

typedef struct {
    hcc_hmac_rx_control_event control;
    hcc_hmac_rx_data_event data;
} hcc_hmac_rx_event_handle;

/*****************************************************************************
  6 消息定义
*****************************************************************************/
/*****************************************************************************
  7 STRUCT定义
*****************************************************************************/
/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
/*****************************************************************************
  10 函数声明
*****************************************************************************/
/* 模块外部调用 */
hi_u32 hcc_hmac_init(hi_void);
hi_void hcc_hmac_exit(hi_void);
hi_u32 hcc_hmac_tx_control_event(frw_event_mem_stru *event_mem, hi_u16 payload_len);
hi_u32 hcc_hmac_tx_data_event(frw_event_mem_stru *event_mem, oal_netbuf_stru *netbuf, hi_bool mgmt);

/* 模块内部调用 */
hi_u32 hcc_to_hmac_control_event_dispatch(frw_event_mem_stru *event_mem);
hi_u32 hcc_to_hmac_data_event_dispatch(frw_event_mem_stru *event_mem, oal_dev_netbuf_stru *dev_netbuf);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hmac_main */

