/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_frag.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_FRAG_H__
#define __HMAC_FRAG_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_tx_data.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define HMAC_FRAG_TIMEOUT   2000
#define HMAC_MAX_FRAG_SIZE  1600

/*****************************************************************************
  3 函数声明
*****************************************************************************/
oal_netbuf_stru* hmac_defrag_process(hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf, hi_u32 hrdsize);
hi_u32  hmac_frag_process_proc(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf,
    hmac_tx_ctl_stru *tx_ctl);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_FRAG_H__ */
