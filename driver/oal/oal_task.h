/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_task.h ��ͷ�ļ�
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LINUX_TASK_H__
#define __OAL_LINUX_TASK_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/mutex.h>
#endif
#include "oal_workqueue.h"
#include "oal_spinlock.h"
#include "oal_wait.h"
#include "oal_atomic.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 STRUCT����
*****************************************************************************/
typedef struct _oal_task_lock_stru_ {
    oal_wait_queue_head_stru    wq;
    struct task_struct         *claimer;    /* task that has host claimed */
    oal_spin_lock_stru          lock;       /* lock for claim and bus ops */
    unsigned long               claim_addr;
    hi_u32                      claimed;
    hi_s32                      claim_cnt;
} oal_task_lock_stru;

typedef struct tasklet_struct       oal_tasklet_stru;
typedef hi_void (*oal_defer_func)(unsigned long);

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
/* tasklet���� */
#define OAL_DECLARE_TASK    DECLARE_TASKLET

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : �����ʼ������ʼ����ɺ������ڹ���״̬��
 �������  : pst_task: ����ṹ��ָ��
             func: ������������ڵ�ַ
             p_args: ����д����ĺ�������ε�ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_task_init(oal_tasklet_stru *pst_task, oal_defer_func p_func, hi_void *p_args)
{
    tasklet_init(pst_task, p_func, (uintptr_t)p_args);
}

/*****************************************************************************
 ��������  : �˳�task����
 �������  : pst_task: ����ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_task_kill(oal_tasklet_stru *pst_task)
{
    return tasklet_kill(pst_task);
}

/*****************************************************************************
 ��������  : ������ȣ���������׼������״̬��������ִ������ֻص�����״
             ̬��
 �������  : pst_task: ����ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_task_sched(oal_tasklet_stru *pst_task)
{
    tasklet_schedule(pst_task);
}

/*****************************************************************************
 ��������  : ���tasklet�Ƿ�ȴ�ִ��
 �������  : pst_task: ����ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline unsigned long oal_task_is_scheduled(oal_tasklet_stru *pst_task)
{
    return oal_bit_atomic_test(TASKLET_STATE_SCHED, (unsigned long *)&pst_task->state);
}
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_task.h */

