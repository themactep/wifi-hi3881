/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for oal_err_wifi.h.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_SCHEDULE_H__
#define __OAL_SCHEDULE_H__

#include "hi_types.h"
#include "oal_err_wifi.h"
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "los_swtmr.h"
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/time.h>
#endif

#include <linux/sched.h>
#include "hi_types.h"
#include "oal_mm.h"
#include "oal_time.h"
#include "oal_timer.h"
#include "oal_wakelock.h"
#include "oal_spinlock.h"
#include "oal_atomic.h"
#include "oal_file.h"
#include "oal_wait.h"
#include "oal_semaphore.h"
#include "oal_completion.h"

#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include "oal_util.h"
#include "oal_err_wifi.h"
#include "linux/completion.h"
#include "hi_atomic.h"
#include "hi_event.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define in_atomic()   0
#define MAX_ERRNO   4095
#define EXPORT_SYMBOL_GPL(x)
#define OAL_EXPORT_SYMBOL(x)
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)(-MAX_ERRNO))
#define OAL_S_IRUGO         S_IRUGO

#define oal_module_symbol(_symbol)      EXPORT_SYMBOL(_symbol)
#define OAL_MODULE_DEVICE_TABLE(_type, _name) MODULE_DEVICE_TABLE(_type, _name)
#define oal_smp_call_function_single(core, task, info, wait) smp_call_function_single(core, task, info, wait)
#endif
#define oal_in_atomic()     in_atomic()
#define oal_in_interrupt()  in_interrupt()

/* module entry */
#define oal_module_init(_module_name)   module_init(_module_name)
#define oal_module_exit(_module_name)   module_exit(_module_name)
#define oal_module_license(_license_name)
#define oal_module_param(_symbol, _type, _name)

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
typedef hi_void (*oal_defer_func)(unsigned long);
typedef hi_void (*oal_timer_func)(unsigned long);
#endif
typedef hi_u32 (*oal_module_func_t)(hi_void);

typedef enum {
    OAL_DFT_TRACE_OTHER = 0x0,
    OAL_DFT_TRACE_SUCC,
    OAL_DFT_TRACE_FAIL,  /* fail while dump the key_info to kernel */
    OAL_DFT_TRACE_EXCEP, /* exception */
    OAL_DFT_TRACE_BUTT,
} oal_dft_type;

typedef struct proc_dir_entry   oal_proc_dir_entry_stru;

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
enum {
    TASKLET_STATE_SCHED,    /* Tasklet is scheduled for execution */
    TASKLET_STATE_RUN       /* Tasklet is running (SMP only) */
};

static inline hi_u32 IS_ERR_OR_NULL(const void *ptr)
{
    return !ptr;
}
#endif

/*****************************************************************************
 ��������  : ���û�̬���ݿ������ں�̬
 �������  : [1]to Ŀ�ĵ�
             [2]len ����
             [3]from Դ
             [4]size ��Ҫ�����ĳ���
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
static inline hi_u32 oal_copy_from_user(hi_void *to, hi_u32 len, const hi_void *from, hi_u32 size)
{
    if (memcpy_s(to, len, from, size) != EOK) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ں�̬���ݿ������û�̬
 �������  : [1]to Ŀ�ĵ�
             [2]len ����
             [3]from  Դ
             [4]size ��Ҫ�����ĳ���
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
static inline hi_u32 oal_copy_to_user(hi_void *to, hi_u32 len, const hi_void *from, hi_u32 size)
{
    if (memcpy_s(to, len, from, size) != EOK) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����proc_entry�ṹ��
 �������  : name: ������proc_entry������
             proc_dir: ĸproc_entry�ṹ�壬�̳�����
 �������  : ��
 �� �� ֵ  : ��
*****************************************************************************/
static inline hi_void oal_remove_proc_entry(const hi_char *name, oal_proc_dir_entry_stru *proc_dir)
{
#if ((LINUX_VERSION_CODE >= kernel_version(3,10,44)) || (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION))
    hi_unref_param(name);
    hi_unref_param(proc_dir);
#else
    return remove_proc_entry(name, proc_dir);
#endif
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_schedule.h */
