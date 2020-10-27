/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_workqueue.h ��ͷ�ļ�
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LINUX_WORKQUEUE_H__
#define __OAL_LINUX_WORKQUEUE_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#endif
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include "hi_types.h"
#include "oal_util.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 STRUCT����
*****************************************************************************/
typedef struct workqueue_struct          oal_workqueue_stru;
typedef struct work_struct               oal_work_stru;
typedef struct delayed_work              oal_delayed_work;

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
extern struct workqueue_struct *g_pstSystemWq;
#endif

/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 �궨��
*****************************************************************************/
#define OAL_INIT_WORK(_p_work, _p_func)            INIT_WORK(_p_work, _p_func)
#define OAL_INIT_DELAYED_WORK(_work, _func)         INIT_DELAYED_WORK(_work, _func)
#define OAL_CREATE_SINGLETHREAD_WORKQUEUE(_name)   create_singlethread_workqueue(_name)
#define oal_create_workqueue(name)                 create_workqueue(name)

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
/*****************************************************************************
 ��������  : ����һ�����̵߳Ĺ�������
 �������  : ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline oal_workqueue_stru* oal_create_singlethread_workqueue(hi_char *pc_workqueue_name)
{
    return create_singlethread_workqueue(pc_workqueue_name);
}

/*****************************************************************************
 ��������  : ���ٹ�������
 �������  : ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_destroy_workqueue(oal_workqueue_stru *pst_workqueue)
{
    destroy_workqueue(pst_workqueue);
}

/*****************************************************************************
 ��������  : ���һ�����񵽹�������
 �������  : ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_u32  oal_queue_work(oal_workqueue_stru *pst_workqueue, oal_work_stru *pst_work)
{
    return queue_work(pst_workqueue, pst_work);
}

/**
 * queue_delayed_work - queue work on a workqueue after delay
 * @wq: workqueue to use
 * @dwork: delayable work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Equivalent to queue_delayed_work_on() but tries to use the local CPU.
 */
static inline hi_u32  oal_queue_delayed_work(oal_workqueue_stru *pst_workqueue,
                                             oal_delayed_work *pst_work, unsigned long delay)
{
    return queue_delayed_work(pst_workqueue, pst_work, delay);
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/**
 * queue_delayed_work_on - queue work on specific CPU after delay
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Returns %false if @work was already on a queue, %true otherwise.  If
 * @delay is zero and @dwork is idle, it will be scheduled for immediate
 * */
static inline hi_u32  oal_queue_delayed_work_on(hi_u32 cpu, oal_workqueue_stru *pst_workqueue,
                                                oal_delayed_work *pst_work, unsigned long delay)
{
    return queue_delayed_work_on(cpu, pst_workqueue, pst_work, delay);
}
#endif

/*****************************************************************************
 ��������  : queue work on system wq after delay
 �������  :  @dwork: delayable work to queue
              @delay: number of jiffies to wait before queueing
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_u32  oal_queue_delayed_system_work(oal_delayed_work *pst_work, unsigned long delay)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 4, 35))
    return queue_delayed_work(system_wq, pst_work, delay);
#else
    return 1;
#endif

#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (queue_delayed_work(g_pstSystemWq, pst_work, delay)) {
        return OAL_SUCC;
    }
    return OAL_EFAIL;
#endif
}

#define oal_work_is_busy(work)              work_busy(work)
#define oal_cancel_delayed_work_sync(dwork) cancel_delayed_work_sync(dwork)
#define oal_cancel_work_sync(work)          cancel_work_sync(work)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_workqueue.h */
