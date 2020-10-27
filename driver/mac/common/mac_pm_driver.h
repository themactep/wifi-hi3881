/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: pm_driver.c header file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __PM_DRIVER_H__
#define __PM_DRIVER_H__

#include "hi_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
    宏定义
*****************************************************************************/
#define PM_SWITCH_MIN_TIMESLOT                  33                               /* 33ms */
#define PM_SWITCH_MAX_TIMESLOT                  4000                             /* 4000ms */
#define PM_SWITCH_ON                            1
#define PM_SWITCH_OFF                           0
#define STA_NUM                                 0x2UL
#define PM_SWITCH_AUTO_FLAG                     1

/*****************************************************************************
    枚举，结构定义
*****************************************************************************/
enum wlan_pm_mode {
    WLAN_PM_WORK,
    WLAN_PM_LIGHT_SLEEP,
    WLAN_PM_DEEP_SLEEP
};

/*****************************************************************************
    对外函数
*****************************************************************************/
hi_u8 *mac_get_pm_wlan_need_stop_ba(hi_void);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif
