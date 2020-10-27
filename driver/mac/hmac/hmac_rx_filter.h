/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_rx_filter.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_RX_FILTER_H__
#define __HMAC_RX_FILTER_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "hi_types.h"
#include "oal_err_wifi.h"
#include "mac_vap.h"
#include "mac_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 函数声明
*****************************************************************************/
hi_u32 hmac_set_rx_filter_value(const mac_vap_stru *mac_vap);
hi_u32 hmac_calc_up_vap_num(const mac_device_stru *mac_dev);
hi_u8 hmac_find_is_ap_up(const mac_device_stru *mac_dev);
hi_u8 hmac_find_is_ap(const mac_device_stru *mac_dev);
#ifdef _PRE_WLAN_FEATURE_PROMIS
hi_u8 hwal_get_promis_filter(void);
#endif

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_RX_FILTER_H__ */
