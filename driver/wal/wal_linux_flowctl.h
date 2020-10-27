/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_linux_flowctl.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_LINUX_FLOWCTL_H__
#define __WAL_LINUX_FLOWCTL_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_FLOWCTL

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define WAL_NETDEV_USER_MAX_NUM             (WLAN_ACTIVE_USER_MAX_NUM + 4)
#define WAL_NETDEV_SUBQUEUE_PER_USE         4
#define WAL_NETDEV_SUBQUEUE_MAX_NUM         ((WAL_NETDEV_USER_MAX_NUM) * (WAL_NETDEV_SUBQUEUE_PER_USE))

/*****************************************************************************
  3 枚举定义
*****************************************************************************/
/*****************************************************************************
  4 全局变量声明
*****************************************************************************/
/*****************************************************************************
  5 消息头定义
*****************************************************************************/
/*****************************************************************************
  6 消息定义
*****************************************************************************/
/*****************************************************************************
  7 STRUCT定义
*****************************************************************************/
typedef struct {
    hi_u8       auc_mac_addr[OAL_MAC_ADDR_LEN];
}wal_macaddr_subq_stru;

/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
/*****************************************************************************
  10 函数声明
*****************************************************************************/
hi_u16   wal_netdev_select_queue(oal_net_device_stru *netdev, oal_netbuf_stru *netbuf);
hi_u32   wal_flowctl_backp_event_handler(frw_event_mem_stru *event_mem);

#endif /* endif for _PRE_WLAN_FEATURE_FLOWCTL */

#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
hi_u16   wal_netdev_select_queue(oal_net_device_stru *netdev, oal_netbuf_stru *netbuf, hi_void *accel_priv,
    select_queue_fallback_t fallback);
#endif /* end if for _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL */

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of wal_linux_flowctl.h */

