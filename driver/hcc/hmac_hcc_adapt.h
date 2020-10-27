/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HMAC module initialization and uninstallation.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_HCC_ADAPT_H__
#define __HMAC_HCC_ADAPT_H__

/*****************************************************************************
  头文件包含
*****************************************************************************/
#include "hi_types.h"

/*****************************************************************************
  函数声明
*****************************************************************************/
frw_event_mem_stru* hmac_hcc_rx_convert_netbuf_to_event_default(frw_event_mem_stru *hcc_event_mem);
hi_u32 hmac_proc_tx_process_action_event_tx_adapt(frw_event_mem_stru *event_mem);
frw_event_mem_stru* hmac_rx_convert_netbuf_to_netbuf_default(frw_event_mem_stru *hcc_event_mem);
frw_event_mem_stru* hmac_rx_process_data_sta_rx_adapt(frw_event_mem_stru *hcc_event_mem);
frw_event_mem_stru* hmac_rx_process_mgmt_event_rx_adapt(frw_event_mem_stru *hcc_event_mem);

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
