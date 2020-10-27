/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Protection related.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_PROTECTION_H__
#define __HMAC_PROTECTION_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
/*****************************************************************************
  3 函数声明
*****************************************************************************/
hi_u32 hmac_protection_del_user(mac_vap_stru *mac_vap, mac_user_stru *mac_user);
hi_u32 hmac_user_protection_sync_data(const mac_vap_stru *mac_vap);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_PROTECTION_H__ */
