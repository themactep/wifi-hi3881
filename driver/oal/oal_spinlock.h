/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_spinlock.h 的头文件
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LINUX_SPINLOCK_H__
#define __OAL_LINUX_SPINLOCK_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/spinlock.h>
#endif
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <linux/spinlock.h>
#include <los_task.h>
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
typedef spinlock_t oal_spinlock;

#define OAL_SPIN_LOCK_MAGIC_TAG (0xdead4ead)
typedef struct _oal_spin_lock_stru_ {
#ifdef CONFIG_SPIN_LOCK_MAGIC_DEBUG
    hi_u32  magic;
    hi_u32  reserved;
#endif
    spinlock_t  lock;
} oal_spin_lock_stru;

#ifdef CONFIG_SPIN_LOCK_MAGIC_DEBUG
#define OAL_DEFINE_SPINLOCK(x)   oal_spin_lock_stru x = {   \
                                                        .magic = OAL_SPIN_LOCK_MAGIC_TAG,  \
                                                        .lock = __SPIN_LOCK_UNLOCKED(x)}
#else
#define OAL_DEFINE_SPINLOCK(x)   oal_spin_lock_stru x = {\
                                                        .lock = __SPIN_LOCK_UNLOCKED(x)}
#endif

/* 函数指针，用来指向需要自旋锁保护的的函数 */
typedef hi_u32(*oal_irqlocked_func)(hi_void *);
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
typedef struct _oal_spin_lock_stru_ {
    spinlock_t  lock;
} oal_spin_lock_stru;

#ifdef _PRE_LOSCFG_KERNEL_SMP

#define oal_spin_lock_init(stlock) do { LOS_SpinInit(&((stlock)->lock)); } while (0)
#define oal_spin_lock(stlock) do { LOS_SpinLock(&((stlock)->lock)); } while (0)
#define oal_spin_unlock(stlock) do {LOS_SpinUnlock(&((stlock)->lock)); } while (0)
#define oal_spin_lock_bh(stlock) do { LOS_SpinLock(&((stlock)->lock)); } while (0)
#define oal_spin_unlock_bh(stlock) do { LOS_SpinUnlock(&((stlock)->lock)); } while (0)
#define oal_spin_lock_irq_save(stlock, flags)  do { LOS_SpinLockSave(&((stlock)->lock), (UINT32 *)flags);} while (0)
#define oal_spin_unlock_irq_restore(stlock, flags)  do { LOS_SpinUnlockRestore(&((stlock)->lock), (UINT32)*flags);} while (0)

#else

#define oal_spin_lock_init(lock) do { (void)lock; } while (0)

/*
锁线程调度，支持嵌套
*/
#define oal_spin_lock(lock) do { (void)lock; LOS_TaskLock(); } while (0)
#define oal_spin_unlock(lock) do { (void)lock; LOS_TaskUnlock(); } while (0)

/*
锁线程调度，支持嵌套
*/
#define oal_spin_lock_bh(lock) do { (void)lock; LOS_TaskLock(); } while (0)
#define oal_spin_unlock_bh(lock) do { (void)lock; LOS_TaskUnlock(); } while (0)

/*
锁硬件中断，不支持嵌套
*/
#define oal_spin_lock_irq(lock) do { (void)lock; LOS_IntLock(); } while (0)
#define oal_spin_unlock_irq(lock) do { (void)lock; LOS_IntUnLock(); } while (0)


/*
锁硬件中断，支持嵌套
*/
#define oal_spin_lock_irq_save(lock, flags)  do { *flags = LOS_IntLock(); } while (0)
#define oal_spin_unlock_irq_restore(lock, flags)  do { LOS_IntRestore(*flags); } while (0)

#endif

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
  7 STRUCT定义
*****************************************************************************/
/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
/*****************************************************************************
  10 函数声明
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 功能描述  : 自旋锁初始化，把自旋锁设置为1（未锁状态）。
 输入参数  : *pst_lock: 锁的地址
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_spin_lock_init(oal_spin_lock_stru *pst_lock)
{
    spin_lock_init(&pst_lock->lock);
#ifdef CONFIG_SPIN_LOCK_MAGIC_DEBUG
    pst_lock->magic = OAL_SPIN_LOCK_MAGIC_TAG;
#endif
}
#define SPIN_LOCK_CONSTANT (32)
static inline hi_void  oal_spin_lock_magic_bug(oal_spin_lock_stru *pst_lock)
{
#ifdef CONFIG_SPIN_LOCK_MAGIC_DEBUG
    if (oal_unlikely((hi_u32)OAL_SPIN_LOCK_MAGIC_TAG != pst_lock->magic)) {
#ifdef CONFIG_PRINTK
        /* spinlock never init or memory overwrite */
        printk(KERN_EMERG "[E]SPIN_LOCK_BUG: spinlock:%p on CPU#%d, %s,magic:%08x should be %08x\n", pst_lock,
               raw_smp_processor_id(), current->comm, pst_lock->magic, OAL_SPIN_LOCK_MAGIC_TAG);
        print_hex_dump(KERN_EMERG, "spinlock_magic: ", DUMP_PREFIX_ADDRESS, 16, 1,  /* 16:hex */
                       (hi_u8 *)((uintptr_t)pst_lock - SPIN_LOCK_CONSTANT),
                       SPIN_LOCK_CONSTANT + sizeof(oal_spin_lock_stru) + SPIN_LOCK_CONSTANT, true);
        printk(KERN_EMERG"\n");
#endif
    }
#else
    hi_unref_param(pst_lock);
#endif
}

/*****************************************************************************
 功能描述  : 自旋锁在软中断以及内核线程等核心态上下文环境下的加锁操作。如果
             能够立即获得锁，它就马上返回，否则，它将自旋在那里，直到该自旋
             锁的保持者释放，这时，它获得锁并返回。
 输入参数  : *pst_lock:自旋锁地址
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_spin_lock(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_lock(&pst_lock->lock);
}

/*****************************************************************************
 功能描述  : Spinlock在内核线程等核心态上下文环境下的解锁操作。
 输入参数  : *pst_lock:自旋锁地址
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_spin_unlock(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_unlock(&pst_lock->lock);
}

/*****************************************************************************
 功能描述  : 自旋锁在软中断以及内核线程等核心态上下文环境下的加锁操作。如果
             能够立即获得锁，它就马上返回，否则，它将自旋在那里，直到该自旋
             锁的保持者释放，这时，它获得锁并返回。
 输入参数  : pst_lock:自旋锁地址
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void oal_spin_lock_bh(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_lock_bh(&pst_lock->lock);
}

/*****************************************************************************
 功能描述  : Spinlock在软中断以及内核线程等核心态上下文环境下的解锁操作。
 输入参数  : 无
 输出参数  : 无
 返 回 值  : hi_void
*****************************************************************************/
static inline hi_void oal_spin_unlock_bh(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_unlock_bh(&pst_lock->lock);
}

/*****************************************************************************
 功能描述  : 获得自旋锁的同时获得保存标志寄存器的值，并且失效本地中断。
 输入参数  : *pst_lock:自旋锁地址
             pui_flags:标志寄存器
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_spin_lock_irq_save(oal_spin_lock_stru *pst_lock, unsigned long *pui_flags)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_lock_irqsave(&pst_lock->lock, *pui_flags);
}

/*****************************************************************************
 功能描述  : 释放自旋锁的同时，恢复标志寄存器的值，恢复本地中断。它与oal_sp-
             in_lock_irq配对使用
 输入参数  : *pst_lock:自旋锁地址
             pui_flags:标志寄存器
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_void  oal_spin_unlock_irq_restore(oal_spin_lock_stru *pst_lock, unsigned long *pui_flags)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_unlock_irqrestore(&pst_lock->lock, *pui_flags);
}

/*****************************************************************************
 功能描述  : 获取自旋锁，关闭中断，执行某个函数，完了之后再打开中断，释放自
             旋锁。
 输入参数  : *pst_lock:自旋锁地址
             func：函数指针地址
             *p_arg：函数参数
             *pui_flags: 中断标志寄存器
 输出参数  : 无
 返 回 值  :
*****************************************************************************/
static inline hi_u32  oal_spin_lock_irq_exec(oal_spin_lock_stru *pst_lock, oal_irqlocked_func func,
    hi_void *p_arg, unsigned long *pui_flags)
{
    hi_u32  ul_rslt;

    spin_lock_irqsave(&pst_lock->lock, *pui_flags);
    ul_rslt = func(p_arg);
    spin_unlock_irqrestore(&pst_lock->lock, *pui_flags);

    return ul_rslt;
}
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_spinlock.h */

