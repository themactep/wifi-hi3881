/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_config.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_EVENT_H__
#define __HMAC_EVENT_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "frw_event.h"
#include "dmac_ext_if.h"
#include "hmac_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 全局变量声明
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
extern frw_event_sub_table_item_stru g_ast_hmac_wlan_drx_event_sub_table[DMAC_WLAN_DRX_EVENT_SUB_TYPE_BUTT];
extern frw_event_sub_table_item_stru g_ast_hmac_wlan_crx_event_sub_table[DMAC_WLAN_CRX_SUB_TYPE_BUTT];
extern frw_event_sub_table_item_stru g_ast_hmac_wlan_ctx_event_sub_table[DMAC_TO_HMAC_SYN_BUTT];
extern frw_event_sub_table_item_stru g_ast_hmac_wlan_misc_event_sub_table[DMAC_MISC_SUB_TYPE_BUTT];
extern frw_event_sub_table_item_stru g_ast_hmac_wlan_dtx_event_sub_table[DMAC_TX_WLAN_DTX_BUTT];
extern frw_event_sub_table_item_stru g_ast_wal_host_crx_table[WAL_HOST_CRX_SUBTYPE_BUTT];
#endif

/*****************************************************************************
  3 函数声明
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
hi_u32  hmac_proc_query_response_event(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param);
#endif
hi_u32 hmac_send_event_to_host(const mac_vap_stru *mac_vap, const hi_u8 *param, hi_u16 len, hi_u8  sub_type);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* __HMAC_CONFIG_EVENT_H__ */

