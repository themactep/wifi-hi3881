/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal timer.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LINUX_TIMER_H__
#define __OAL_LINUX_TIMER_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include <linux/timer.h>
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <los_swtmr.h>
#include "oal_time.h"
#endif
#include "oal_util.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 STRUCT定义
*****************************************************************************/
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
typedef struct oal_timer_list_stru_tag {
  struct timer_list timer;
  unsigned long     data;
  void (*function)(unsigned long);
} oal_timer_list_stru;

static void oal_timer_callback(struct timer_list *new_timer) {
  oal_timer_list_stru *oal_timer = container_of(new_timer, oal_timer_list_stru, timer);
  if (oal_timer->function != NULL) {
    oal_timer->function(oal_timer->data);
  }
  return;
}
#else
typedef struct timer_list              oal_timer_list_stru;
#endif
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
  7 宏定义
*****************************************************************************/
/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
typedef void (*oal_timer_func)(unsigned long);

/*****************************************************************************
  10 函数声明
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)

/*****************************************************************************
 功能描述  : 初始化定时器
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_timer_init(oal_timer_list_stru *pst_timer, unsigned long ul_delay,
    oal_timer_func p_func, unsigned long ui_arg)
{
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
    timer_setup(&(pst_timer->timer), oal_timer_callback, 0);
    pst_timer->timer.expires = jiffies + msecs_to_jiffies(ul_delay);
#else
    init_timer(pst_timer);
    pst_timer->expires = jiffies + msecs_to_jiffies(ul_delay);
#endif
    pst_timer->function = p_func;
    pst_timer->data = ui_arg;
}

/*****************************************************************************
 功能描述  : 删除定时器
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_s32  oal_timer_delete(oal_timer_list_stru *pst_timer)
{
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
    return del_timer(&(pst_timer->timer));
#else
    return del_timer(pst_timer);
#endif
}

/*****************************************************************************
 功能描述  : 同步删除定时器，用于多核
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_s32  oal_timer_delete_sync(oal_timer_list_stru *pst_timer)
{
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
    return del_timer_sync(&(pst_timer->timer));
#else
    return del_timer_sync(pst_timer);
#endif
}

/*****************************************************************************
 功能描述  : 激活定时器
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_timer_add(oal_timer_list_stru *pst_timer)
{
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
    add_timer(&(pst_timer->timer));
#else
    add_timer(pst_timer);
#endif
}

/*****************************************************************************
 功能描述  : 重启定时器
 输入参数  : pst_timer: 结构体指针
             ui_expires: 重启的溢出事件
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_s32  oal_timer_start(oal_timer_list_stru *pst_timer, unsigned long ui_delay)
{
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
    return mod_timer(&(pst_timer->timer), (jiffies + msecs_to_jiffies(ui_delay)));
#else
    return mod_timer(pst_timer, (jiffies + msecs_to_jiffies(ui_delay)));
#endif
}

/*****************************************************************************
 功能描述  : 指定cpu,重启定时器,调用时timer要处于非激活状态否者会死机
 输入参数  : pst_timer: 结构体指针
             ui_expires: 重启的溢出事件
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_timer_start_on(oal_timer_list_stru *pst_timer, unsigned long ui_delay, hi_s32 cpu)
{
#if (LINUX_VERSION_CODE >= kernel_version(4,14,0))
    pst_timer->timer.expires = jiffies + msecs_to_jiffies(ui_delay);
    add_timer_on(&(pst_timer->timer), cpu);
#else
    pst_timer->expires = jiffies + msecs_to_jiffies(ui_delay);
    add_timer_on(pst_timer, cpu);
#endif
}
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 功能描述  : 初始化定时器
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void oal_timer_init(oal_timer_list_stru *pst_timer, hi_u32 ul_delay,
    oal_timer_func p_func, hi_u64 ui_arg)
{
    init_timer(pst_timer);
    pst_timer->expires = OAL_MSECS_TO_JIFFIES(ul_delay);
    pst_timer->function = p_func;
    pst_timer->data = ui_arg;
}

/*****************************************************************************
 功能描述  : 删除定时器
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_s32 oal_timer_delete(oal_timer_list_stru *pst_timer)
{
    return del_timer(pst_timer);
}

/*****************************************************************************
 功能描述  : 同步删除定时器，用于多核
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_s32 oal_timer_delete_sync(oal_timer_list_stru *pst_timer)
{
    return del_timer_sync(pst_timer);
}

/*****************************************************************************
 功能描述  : 激活定时器
 输入参数  : pst_timer: 定时器结构体指针
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void oal_timer_add(oal_timer_list_stru *pst_timer)
{
    add_timer(pst_timer);
}

/*****************************************************************************
 功能描述  : 重启定时器
 输入参数  : pst_timer: 结构体指针
             ui_expires: 重启的溢出事件
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_s32 oal_timer_start(oal_timer_list_stru *pst_timer, hi_u64 ui_delay)
{
    if (pst_timer->flag == TIMER_UNVALID) {
        pst_timer->expires = OAL_MSECS_TO_JIFFIES((hi_u32)ui_delay);
        add_timer(pst_timer);
        return 0;
    } else {
        return mod_timer(pst_timer, OAL_MSECS_TO_JIFFIES((hi_u32)ui_delay));
    }
}

/*****************************************************************************
 功能描述  : 指定cpu,重启定时器,调用时timer要处于非激活状态否者会死机
 输入参数  : pst_timer: 结构体指针
             ui_expires: 重启的溢出事件
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void oal_timer_start_on(oal_timer_list_stru *pst_timer, hi_u64 ui_delay, hi_s32 cpu)
{
    hi_unref_param(cpu);
    pst_timer->expires = OAL_MSECS_TO_JIFFIES(ui_delay);
    add_timer(pst_timer);
}
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_timer.h */

