/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_resource.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_RESOURCE_H__
#define __MAC_RESOURCE_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"
#include "oal_queue.h"
#include "mac_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define MAC_RES_VAP_SIZE        3000
#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
/* 增加业务识别功能后，hmac_user_stru结构体中增加用户业务信息，扩充规格为1700 */
#define FEATURE_TX_CLASSIFY_LAN_TO_WLAN_RES_SIZE 1700
#else
#define FEATURE_TX_CLASSIFY_LAN_TO_WLAN_RES_SIZE 0
#endif  /* end of _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN */
#define MAC_RES_USER_SIZE       (4000 + FEATURE_TX_CLASSIFY_LAN_TO_WLAN_RES_SIZE)

/*****************************************************************************
  STRUCT定义
*****************************************************************************/
typedef struct {
    hi_list                 entry;
    hi_u8               user_idx;                /* 记录对应的USER的索引值 */
    hi_u8               uc_resv;
    hi_u16              us_hash_res_idx;            /* 记录对应的HASH资源池的索引值 */
}mac_res_user_hash_stru;

typedef struct {
    mac_res_user_hash_stru     *user_hash_info;
    oal_queue_stru              queue;
    hi_u32                   *pul_idx;
    hi_u8                  *puc_user_cnt;
}mac_res_hash_stru;

/*****************************************************************************
  10 函数声明
*****************************************************************************/
hi_void mac_res_exit(hi_void);
hi_u32 mac_res_init(hi_void);
hi_u32 mac_res_free_hash(hi_u32 hash_idx);
hi_u32  mac_res_alloc_hash(hi_u8 *puc_hash_idx);
mac_res_user_hash_stru* mac_res_get_hash(hi_u8 dev_idx);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __MAC_RESOURCE_H__ */
