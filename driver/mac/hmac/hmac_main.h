/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_main.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_MAIN_H__
#define __HMAC_MAIN_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oam_ext_if.h"
#include "mac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  STRUCT定义
*****************************************************************************/
typedef struct {
    oal_semaphore_stru rxdata_sema;
    hi_s32   rxdata_taskid;
    oal_wait_queue_head_stru rxdata_wq;
    oal_netbuf_head_stru rxdata_netbuf_head;
    hi_u32 pkt_loss_cnt;
    hi_u8 rxthread_enable;
} hmac_rxdata_thread_stru;

/*****************************************************************************
  函数声明
*****************************************************************************/
hi_void hmac_main_exit(hi_void);
hi_u32 hmac_main_init(hi_void);
hi_u32 hmac_config_send_event(const mac_vap_stru *mac_vap, wlan_cfgid_enum_uint16 cfg_id,
                              hi_u16 us_len, const hi_u8 *puc_param);
hi_void hmac_rxdata_netbuf_enqueue(oal_netbuf_stru *netbuf);
hi_void hmac_rxdata_sched(hi_void);
hi_u8 hmac_get_rxthread_enable(hi_void);
hi_u32 hmac_init_event_process(frw_event_mem_stru *event_mem);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_MAIN_H__ */
