/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: frw_task.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */
/* 1 ͷ�ļ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "hi_task.h"
#endif
#include "frw_event.h"
#include "frw_task.h"
#include "frw_main.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define FRW_THREAD_NAME_MAX_SIZE    20
#endif
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
#define FRW_TASK_PRIO       4       /* ����task�����ȼ�,������ϲ�� */
hi_char g_frw_thread_name[] = {"hisi_frw"};
#endif
/******************************************************************************
    �¼�����ȫ�ֱ���
*******************************************************************************/
frw_task_stru g_ast_event_task;
/*****************************************************************************
    �߳��˳���־ȫ�ֱ���
*******************************************************************************/
hi_u8 g_frw_exit = HI_FALSE;
hi_u8 g_frw_stop = HI_FALSE;
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
/*****************************************************************************S
 ��������  : frw �ں��߳�������
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_void* frw_task_thread(hi_void* bind_cpu)
{
#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_HMAC)
    hi_u32      event;
#else
    hi_s32      ret;
#endif
    hi_unref_param(bind_cpu);
    /* ��ѭ��ֱ���¼������� */
    for (;;) {
#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_HMAC)
        while (!frw_task_thread_condition_check()) {
            hi_event_wait(get_app_event_id(), HI_EVENT_FRW_TASK, &event, HI_SYS_WAIT_FOREVER,
                          HI_EVENT_WAITMODE_AND | HI_EVENT_WAITMODE_CLR);
        }
#else
        /* stateΪTASK_INTERRUPTIBLE��condition���������߳�������ֱ�������ѽ���waitqueue */
        ret = hi_wait_event_interruptible(g_ast_event_task.frw_wq, frw_task_thread_condition_check() == HI_TRUE);
        if (oal_unlikely(ret == -ERESTARTSYS)) {
            hi_diag_log_msg_i0(0, "wifi task was interrupted by a signal\n");
            break;
        }
#endif
        frw_event_process_all_event();
    }
    return HI_NULL; /* �����������for (;;) ��ѭ������Ҫreturn��lin_t e527�澯���� */
}
#endif
#endif /* #if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD) */
/*****************************************************************************
 ��������  : kthread��ʼ���ӿ�
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 frw_task_init(void)
{
    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&g_ast_event_task, sizeof(g_ast_event_task), 0, sizeof(g_ast_event_task));

    hi_wait_queue_init_head(&g_ast_event_task.frw_wq);

#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
    hi_u32 ret, taskid;
    hi_task_attr attr = {0};

    attr.stack_size = FRW_TASK_SIZE;
    attr.task_prio = FRW_TASK_PRIO;
    attr.task_name = g_frw_thread_name;
    attr.task_policy = 1; /* SCHED_FIFO */
    attr.task_cpuid = 0;
    ret = hi_task_create(&taskid, &attr, frw_task_thread, 0);
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    g_ast_event_task.taskid = taskid;
#elif (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET)
    oal_task_kill(&g_ast_event_task.event_tasklet);
#endif
    return HI_SUCCESS;
}
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : �߳��˳�����
 �޸���ʷ      :
  1.��    ��   : 2015��4��9��
*****************************************************************************/
hi_void frw_task_exit(hi_void)
{
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
        if (g_ast_event_task.taskid) {
            hi_task_delete(g_ast_event_task.taskid);
            g_ast_event_task.taskid = 0;
        }
#elif (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET)
        oal_task_kill(&g_ast_event_task.event_tasklet);
#endif
}
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

/*****************************************************************************
 ��������  : ���ⲿģ��ע��tasklet��������ִ�еĺ���
 �������  : p_func: ��Ҫ��ִ�еĺ���

 �޸���ʷ      :
  1.��    ��   : 2015��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void frw_task_event_handler_register(hi_void (*func)(hi_void))
{
    if (oal_unlikely(func == HI_NULL)) {
        hi_diag_log_msg_i0(0, "{frw_task_event_handler_register:: p_func is null ptr}");
        return;
    }

#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET)
    g_ast_event_task.event_handler_func = func;
#endif
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ����eventʱ�䴦���̣߳���wake_event_interruptible��Ӧ
 �޸���ʷ      :
  1.��    ��   : 2015��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void frw_task_sched(hi_void)
{
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_HMAC)
    (hi_void)hi_event_send(get_app_event_id(), HI_EVENT_FRW_TASK);
#else
    hi_wait_queue_wake_up_interrupt(&g_ast_event_task.frw_wq);
#endif
#elif (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET)
    if (oal_task_is_scheduled(&g_ast_event_task.event_tasklet)) {
        return;
    }
    oal_task_sched(&g_ast_event_task.event_tasklet);
#endif
}
#endif

#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_TASKLET)
/*****************************************************************************
 ��������  : ��tasklet����ִ�У���IPI�жϵ���ִ��
*****************************************************************************/
hi_void frw_remote_task_receive(hi_void *info)
{
    oal_tasklet_stru *task = (oal_tasklet_stru *)info;
    oal_task_sched(task);
}

/*****************************************************************************
 ��������  : ʹ��IPI�жϣ�����Ŀ��core�ϵ�taskletִ�д����¼�
*****************************************************************************/
hi_void frw_task_sched_on_cpu(oal_tasklet_stru *task)
{
    oal_smp_call_function_single(0, frw_remote_task_receive, (hi_void *)task, 0);
}

#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static hi_s32 frw_task_thread(hi_void* ul_bind_cpu)
{
    hi_s32       ret = 0;
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
    hi_u32 ul_empty_count = 0;
#endif
    g_frw_exit = HI_FALSE; /* �̳߳�ʼ��ʱΪ��ȫ�ֱ�����ֵ */
    g_frw_stop = HI_FALSE; /* �̳߳�ʼ��ʱΪ��ȫ�ֱ�����ֵ */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    allow_signal(SIGTERM);
#endif
    for (;;) {
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
        hi_u32 ul_event_count;
#endif
        if (oal_kthread_should_stop()) {
            break;
        }

        /* stateΪTASK_INTERRUPTIBLE��condition���������߳�������ֱ�������ѽ���waitqueue */
        /*lint -e730*/
#ifdef  _PRE_FRW_EVENT_PROCESS_TRACE_DEBUG
        frw_event_last_pc_trace(__FUNCTION__, __LINE__, (hi_u32)(unsigned long)ul_bind_cpu);
#endif
        ret = hi_wait_event_interruptible(g_ast_event_task.frw_wq,
            (HI_TRUE == frw_task_thread_condition_check() || g_frw_exit));
        /*lint +e730*/
        if (oal_unlikely(ret == -ERESTARTSYS)) {
            oal_io_print1("wifi task %s was interrupted by a signal\n", oal_get_current_task_name());
            break;
        }
        if (g_frw_exit == HI_TRUE) {
            break;
        }
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
        g_ast_event_task.ul_total_loop_cnt++;

        ul_event_count = g_ast_event_task.ul_total_event_cnt;
#endif
        frw_event_process_all_event();
#if (_PRE_FRW_FEATURE_PROCCESS_ENTITY_TYPE == _PRE_FRW_FEATURE_PROCCESS_ENTITY_THREAD)
        if (ul_event_count == g_ast_event_task.ul_total_event_cnt) {
            /* ��ת */
            ul_empty_count++;
            if (ul_empty_count == 10000) {   /* empty count 10000 */
            }
        } else {
            if (ul_empty_count > g_ast_event_task.ul_max_empty_count) {
                g_ast_event_task.ul_max_empty_count = ul_empty_count;
            }
            ul_empty_count = 0;
        }
#endif
#ifdef  _PRE_FRW_EVENT_PROCESS_TRACE_DEBUG
        frw_event_last_pc_trace(__FUNCTION__, __LINE__, (hi_u32)(unsigned long)ul_bind_cpu);
#endif
#if (!defined(CONFIG_PREEMPT) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION))
        cond_resched();
#endif
    }
    g_frw_stop = HI_TRUE;
    return 0;
}

hi_u32 frw_task_init()
{
    oal_kthread_stru   *kthread = HI_NULL;
    oal_kthread_param_stru st_thread_param = {0};

    memset_s(&g_ast_event_task, sizeof(g_ast_event_task), 0, sizeof(g_ast_event_task));

    hi_wait_queue_init_head(&g_ast_event_task.frw_wq);

    memset_s(&st_thread_param, sizeof(oal_kthread_param_stru), 0, sizeof(oal_kthread_param_stru));
    st_thread_param.l_cpuid      = 0;
    st_thread_param.l_policy     = OAL_SCHED_RR;
    st_thread_param.l_prio       = FRW_TASK_PRIO;
    st_thread_param.ul_stacksize = FRW_TASK_SIZE;

    kthread = oal_kthread_create(g_frw_thread_name, frw_task_thread,
        (hi_void *)(st_thread_param.l_cpuid), &st_thread_param);
    if (IS_ERR_OR_NULL(kthread)) {
        return HI_FAIL;
    }

    g_ast_event_task.pst_event_kthread = kthread;
    g_ast_event_task.uc_task_state     = FRW_TASK_STATE_IRQ_UNBIND;
    return HI_SUCCESS;
}

hi_void frw_task_exit(hi_void)
{
    int times = 0;
    if (g_ast_event_task.pst_event_kthread) {
        g_frw_exit = HI_TRUE;
        frw_task_sched();
        while (!g_frw_stop && times < 10000) {
            usleep_range(50, 100); /* 50 100 ��Ϊ��ʱ��������С��ʱ50�����100 */
            times++;
        }
    }
}
hi_void frw_task_sched(hi_void)
{
    hi_wait_queue_wake_up_interrupt(&g_ast_event_task.frw_wq);
}
#endif /* #if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) */

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

