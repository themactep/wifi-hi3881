/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_mgmt_classifier.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_MGMT_CLASSIFIER_H__
#define __HMAC_MGMT_CLASSIFIER_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "dmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 函数声明
*****************************************************************************/
hi_u32 hmac_rx_process_mgmt_event(frw_event_mem_stru *event_mem);
hi_u32 hmac_mgmt_rx_delba_event(frw_event_mem_stru *event_mem);
hi_u32 hmac_mgmt_tx_action(hmac_vap_stru *hmac_vap,
                           hmac_user_stru *hmac_user, mac_action_mgmt_args_stru *action_args);
hi_u32 hmac_mgmt_tx_priv_req(hmac_vap_stru *hmac_vap,
                             hmac_user_stru *hmac_user, mac_priv_req_args_stru *priv_req);
hi_u32 hmac_mgmt_send_disasoc_deauth_event(frw_event_mem_stru *event_mem);
hi_u32 hmac_proc_disasoc_misc_event(frw_event_mem_stru *event_mem);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_u32 hmac_mesh_report_new_peer_candidate(frw_event_mem_stru *event_mem);
#endif
#ifdef _PRE_WLAN_FEATURE_PROMIS
hi_u32 hmac_rx_process_mgmt_promis(frw_event_mem_stru *event_mem);
#endif

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_MGMT_CLASSIFIER_H__ */
