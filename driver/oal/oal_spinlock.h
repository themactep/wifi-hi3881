/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_spinlock.h ��ͷ�ļ�
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LINUX_SPINLOCK_H__
#define __OAL_LINUX_SPINLOCK_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
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
  2 �궨��
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

/* ����ָ�룬����ָ����Ҫ�����������ĵĺ��� */
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
���̵߳��ȣ�֧��Ƕ��
*/
#define oal_spin_lock(lock) do { (void)lock; LOS_TaskLock(); } while (0)
#define oal_spin_unlock(lock) do { (void)lock; LOS_TaskUnlock(); } while (0)

/*
���̵߳��ȣ�֧��Ƕ��
*/
#define oal_spin_lock_bh(lock) do { (void)lock; LOS_TaskLock(); } while (0)
#define oal_spin_unlock_bh(lock) do { (void)lock; LOS_TaskUnlock(); } while (0)

/*
��Ӳ���жϣ���֧��Ƕ��
*/
#define oal_spin_lock_irq(lock) do { (void)lock; LOS_IntLock(); } while (0)
#define oal_spin_unlock_irq(lock) do { (void)lock; LOS_IntUnLock(); } while (0)


/*
��Ӳ���жϣ�֧��Ƕ��
*/
#define oal_spin_lock_irq_save(lock, flags)  do { *flags = LOS_IntLock(); } while (0)
#define oal_spin_unlock_irq_restore(lock, flags)  do { LOS_IntRestore(*flags); } while (0)

#endif

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
  7 STRUCT����
*****************************************************************************/
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
 ��������  : ��������ʼ����������������Ϊ1��δ��״̬����
 �������  : *pst_lock: ���ĵ�ַ
 �������  : ��
 �� �� ֵ  :
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
 ��������  : �����������ж��Լ��ں��̵߳Ⱥ���̬�����Ļ����µļ������������
             �ܹ�������������������Ϸ��أ������������������ֱ��������
             ���ı������ͷţ���ʱ��������������ء�
 �������  : *pst_lock:��������ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_spin_lock(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_lock(&pst_lock->lock);
}

/*****************************************************************************
 ��������  : Spinlock���ں��̵߳Ⱥ���̬�����Ļ����µĽ���������
 �������  : *pst_lock:��������ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_spin_unlock(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_unlock(&pst_lock->lock);
}

/*****************************************************************************
 ��������  : �����������ж��Լ��ں��̵߳Ⱥ���̬�����Ļ����µļ������������
             �ܹ�������������������Ϸ��أ������������������ֱ��������
             ���ı������ͷţ���ʱ��������������ء�
 �������  : pst_lock:��������ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_spin_lock_bh(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_lock_bh(&pst_lock->lock);
}

/*****************************************************************************
 ��������  : Spinlock�����ж��Լ��ں��̵߳Ⱥ���̬�����Ļ����µĽ���������
 �������  : ��
 �������  : ��
 �� �� ֵ  : hi_void
*****************************************************************************/
static inline hi_void oal_spin_unlock_bh(oal_spin_lock_stru *pst_lock)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_unlock_bh(&pst_lock->lock);
}

/*****************************************************************************
 ��������  : �����������ͬʱ��ñ����־�Ĵ�����ֵ������ʧЧ�����жϡ�
 �������  : *pst_lock:��������ַ
             pui_flags:��־�Ĵ���
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_spin_lock_irq_save(oal_spin_lock_stru *pst_lock, unsigned long *pui_flags)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_lock_irqsave(&pst_lock->lock, *pui_flags);
}

/*****************************************************************************
 ��������  : �ͷ���������ͬʱ���ָ���־�Ĵ�����ֵ���ָ������жϡ�����oal_sp-
             in_lock_irq���ʹ��
 �������  : *pst_lock:��������ַ
             pui_flags:��־�Ĵ���
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_spin_unlock_irq_restore(oal_spin_lock_stru *pst_lock, unsigned long *pui_flags)
{
    oal_spin_lock_magic_bug(pst_lock);
    spin_unlock_irqrestore(&pst_lock->lock, *pui_flags);
}

/*****************************************************************************
 ��������  : ��ȡ���������ر��жϣ�ִ��ĳ������������֮���ٴ��жϣ��ͷ���
             ������
 �������  : *pst_lock:��������ַ
             func������ָ���ַ
             *p_arg����������
             *pui_flags: �жϱ�־�Ĵ���
 �������  : ��
 �� �� ֵ  :
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

