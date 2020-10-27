/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hi_atomic.c ��ͷ�ļ�
 * Author: Hisilicon
 * Create: 2019-05-29
 */

/**
 * @defgroup iot_atomic  Atomic Operation
 * @ingroup osa
 */

/**
* @file hi_atomic.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: Atomic operation APIs.
*/

#ifndef __HI_ATOMIC_H__
#define __HI_ATOMIC_H__
#include <hi_types.h>
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <los_hwi.h>
#ifdef _PRE_LOSCFG_KERNEL_SMP
#include <los_spinlock.h>
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    volatile hi_s32 counter;
} hi_atomic;

#ifdef _PRE_LOSCFG_KERNEL_SMP
#ifndef G_SPIN_LOCK
#define G_SPIN_LOCK
static SPIN_LOCK_INIT(g_spinlock);
#endif
#endif

#define hi_atomic_init(i)            { (i) }
#define hi_atomic_read(v)            ((v)->counter)
#define hi_atomic_set(v, i)          (((v)->counter) = (i))

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define hi_atomic_inc(v)             hi_atomic_add_return(1, v)
#define hi_atomic_dec(v)             hi_atomic_sub_return(1, v)

#define hi_atomic_inc_return(v)      (hi_atomic_add_return(1, v))
#define hi_atomic_dec_return(v)      (hi_atomic_sub_return(1, v))
#define hi_atomic_inc_return_optimize(v)      (hi_atomic_add_return_optimize(1, v))
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define hi_atomic_inc(v)             atomic_add_return(1, (atomic_t *)v)
#define hi_atomic_dec(v)             atomic_sub_return(1, (atomic_t *)v)
#define hi_atomic_inc_return(v)      (atomic_add_return(1, (atomic_t *)v))
#define hi_atomic_dec_return(v)      (atomic_sub_return(1, (atomic_t *)v))
#endif /* _PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION */

/**
 * @ingroup  iot_atomic
 * If the atomic operation is performed, the operation result is returned.
CNcomment:ԭ�ӼӲ��������ز������CNend
 */
#define hi_atomic_add_return_op(i, v)   (hi_atomic_add_return(i, v))

/**
 * @ingroup  iot_atomic
 * The operation result is returned when the atomic subtraction operation is performed.
CNcomment:ԭ�Ӽ����������ز������CNend
 */
#define hi_atomic_sub_return_op(i, v)   (hi_atomic_sub_return(i, v))

/**
 * @ingroup  iot_atomic
 * The specified bit in the atomic setting variable is 1.
CNcomment:ԭ�����ñ�����ָ��bitλΪ1CNend
 */
#define hi_atomic_bit_set_op(bit, v)    (hi_atomic_bit_set(bit, v))
/**
 * @ingroup  iot_atomic
 * The specified bit in the atomic setting variable is 0.
CNcomment:ԭ�����ñ�����ָ��bitλΪ0CNend
 */
#define hi_atomic_bit_clear_op(bit, v)  (hi_atomic_bit_clear(bit, v))

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/**
* @ingroup  iot_atomic
* @brief   If the atomic operation is performed, the operation result is returned.
CNcomment:ԭ�ӼӲ��������ز������CNend
*
* @par ����:
*          If the atomic operation is performed, the operation result is returned.
CNcomment:ԭ�ӼӲ��������ز������CNend
*
* @attention None
* @param  i     [IN] type #hi_s32�� The number of operands added to an atom.CNcomment:��ԭ����ӵĲ�����CNend
* @param  v     [IN] type #hi_atomic*��Pointer to the atomic structure address.CNcomment:ԭ�ӽṹ��ַָ��CNend
*
* @retval #hi_s32  Add Operation Result. CNcomment:�Ӳ������CNend
* @par ����:
*           @li hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
static inline hi_s32 hi_atomic_add_return(hi_s32 i, hi_atomic *v)
{
    hi_u32 irq_status;
    int val;

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &irq_status);
#else
    irq_status = LOS_IntLock();
#endif
    v->counter += i;
    val = v->counter;
#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, irq_status);
#else
    (hi_void)LOS_IntRestore(irq_status);
#endif

    return val;
}

/**
* @ingroup  iot_atomic
* @brief   The operation result is returned when the atomic subtraction operation is performed.
CNcomment:ԭ�Ӽ����������ز������CNend
*
* @par ����:
*          The operation result is returned when the atomic subtraction operation is performed.
CNcomment:ԭ�Ӽ����������ز������CNend
*
* @attention None
* @param  i     [IN] type #hi_s32�� The number of operands subtracted from the atom.
CNcomment:��ԭ������Ĳ�����CNend
* @param  v     [IN] type #hi_atomic*��Pointer to the atomic structure address.CNcomment:ԭ�ӽṹ��ַָ��CNend
*
* @retval #hi_s32 Reduce the operation result. CNcomment:���������CNend
* @par ����:
*           @li hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
static inline hi_s32 hi_atomic_sub_return(hi_s32 i, hi_atomic *v)
{
    hi_u32 irq_status;
    int val;

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &irq_status);
#else
    irq_status = LOS_IntLock();
#endif
    v->counter = v->counter - i;
    val = v->counter;
#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, irq_status);
#else
    (hi_void)LOS_IntRestore(irq_status);
#endif

    return val;
}

/**
* @ingroup  iot_atomic
* @brief   The specified bit in the atomic setting variable is 1.CNcomment:ԭ�����ñ�����ָ��bitλΪ1CNend
*
* @par ����:
*          The specified bit in the atomic setting variable is 1.CNcomment:ԭ�����ñ�����ָ��bitλΪ1CNend
*
* @attention None
* @param  bit     [IN] type #hi_s32�� Position of the bit that is set to 1. The value range is 0-31.
CNcomment:����1��bitλ�ã���Χ0-31.CNend
* @param  value   [IN] type #hi_u32*��Address pointer of the set variable.CNcomment:��λ�����ĵ�ַָ��CNend
*
* @retval #None
* @par ����:
*           @li hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
static inline hi_void hi_atomic_bit_set(hi_s32 bit, hi_atomic *v)
{
    hi_u32 irq_status;
#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &irq_status);
#else
    irq_status = LOS_IntLock();
#endif

    v->counter |= (1 << bit);

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, irq_status);
#else
    (hi_void)LOS_IntRestore(irq_status);
#endif
}

/**
* @ingroup  iot_atomic
* @brief   The specified bit in the atomic setting variable is 0.CNcomment:ԭ�����ñ�����ָ��bitλΪ0CNend
*
* @par ����:
*          The specified bit in the atomic setting variable is 0.CNcomment:ԭ�����ñ�����ָ��bitλΪ0CNend
*
* @attention None
* @param  bit     [IN] type #hi_s32�� Position of the bit that is set to 0. The value range is 0-31.
CNcomment:����0��bitλ�ã���Χ0-31.CNend
* @param  value   [IN] type #hi_u32*��Address pointer of the set variable.CNcomment:��λ�����ĵ�ַָ��CNend
*
* @retval #None
* @par ����:
*           @li hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
static inline hi_void hi_atomic_bit_clear(hi_s32 bit, hi_atomic *v)
{
    hi_u32 irq_status;
    hi_u32 mask;

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &irq_status);
#else
    irq_status = LOS_IntLock();
#endif
    mask = 1 << bit;
    v->counter = (v->counter) & (~mask);

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, irq_status);
#else
    (hi_void)LOS_IntRestore(irq_status);
#endif
}

__attribute__((always_inline)) static inline hi_s32 hi_atomic_add_return_optimize(hi_s32 i, hi_atomic *v)
{
    hi_u32 irq_status;
    int val;

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &irq_status);
#else
    irq_status = LOS_IntLock();
#endif
    v->counter += i;
    val = v->counter;
#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, irq_status);
#else
    (hi_void)LOS_IntRestore(irq_status);
#endif

    return val;
}
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hi_atomic.h */

