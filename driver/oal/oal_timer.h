/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal timer.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LINUX_TIMER_H__
#define __OAL_LINUX_TIMER_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
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
  2 STRUCT����
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
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 �궨��
*****************************************************************************/
/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
typedef void (*oal_timer_func)(unsigned long);

/*****************************************************************************
  10 ��������
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)

/*****************************************************************************
 ��������  : ��ʼ����ʱ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ɾ����ʱ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ͬ��ɾ����ʱ�������ڶ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ���ʱ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ������ʱ��
 �������  : pst_timer: �ṹ��ָ��
             ui_expires: ����������¼�
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ָ��cpu,������ʱ��,����ʱtimerҪ���ڷǼ���״̬���߻�����
 �������  : pst_timer: �ṹ��ָ��
             ui_expires: ����������¼�
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ��ʼ����ʱ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ɾ����ʱ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_s32 oal_timer_delete(oal_timer_list_stru *pst_timer)
{
    return del_timer(pst_timer);
}

/*****************************************************************************
 ��������  : ͬ��ɾ����ʱ�������ڶ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_s32 oal_timer_delete_sync(oal_timer_list_stru *pst_timer)
{
    return del_timer_sync(pst_timer);
}

/*****************************************************************************
 ��������  : ���ʱ��
 �������  : pst_timer: ��ʱ���ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_timer_add(oal_timer_list_stru *pst_timer)
{
    add_timer(pst_timer);
}

/*****************************************************************************
 ��������  : ������ʱ��
 �������  : pst_timer: �ṹ��ָ��
             ui_expires: ����������¼�
 �������  : ��
 �� �� ֵ  :
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
 ��������  : ָ��cpu,������ʱ��,����ʱtimerҪ���ڷǼ���״̬���߻�����
 �������  : pst_timer: �ṹ��ָ��
             ui_expires: ����������¼�
 �������  : ��
 �� �� ֵ  :
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

