/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for frw_task.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __FRW_TASK_H__
#define __FRW_TASK_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ö�ٶ���
*****************************************************************************/
/* �̵߳�����״̬ */
typedef enum {
    FRW_TASK_STATE_IRQ_UNBIND = 0, /* �̴߳�����ͣ״̬ */
    FRW_TASK_STATE_IRQ_BIND,       /* �̴߳�������״̬ */

    FRW_TASK_BUTT
} frw_task_state_enum;
typedef hi_u8 frw_task_state_enum_uint8;

/*****************************************************************************
  4 STRUCT����
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
typedef struct {
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
    hi_u32             taskid;                                /* task���� */
    oal_wait_queue_head_stru frw_wq;                          /* waitqueue */
    hi_void (*event_handler_func)(hi_void *_pst_bind_cpu);    /* kthread������ */

#elif (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET)
    oal_tasklet_stru   event_tasklet;                        /* tasklet���� */
    hi_void (*event_handler_func)(hi_u32);                   /* tasklet������� */
#endif
} frw_task_stru;

#else /* (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

typedef struct {
    oal_kthread_stru        *pst_event_kthread;
    oal_wait_queue_head_stru frw_wq;
    hi_u8                    uc_task_state;
    hi_u8                    auc_resv[3];   /* resv 3 byte */
    hi_u32                   ul_total_loop_cnt;
    hi_u32                   ul_total_event_cnt;
    hi_u32                   ul_max_empty_count;
    hi_void (*p_event_handler_func)(hi_void *_pst_bind_cpu);
} frw_task_stru;
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

/*****************************************************************************
  ��������
*****************************************************************************/
hi_u32 frw_task_init(hi_void);
hi_void frw_task_exit(hi_void);
hi_void frw_task_event_handler_register(hi_void (*func)(hi_void));
hi_void frw_task_sched(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of frw_task.h */
