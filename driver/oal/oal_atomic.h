/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_atomic.h ��ͷ�ļ�
 * Author: Hisilicon
 * Create: 2018-08-04
 */
#ifndef __OAL_ATOMIC_H__
#define __OAL_ATOMIC_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include "hi_types.h"
#include <asm/atomic.h>
#ifndef HAVE_PCLINT_CHECK
#include <linux/bitops.h>
#endif
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
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

/*****************************************************************************
  2 STRUCT����
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)

typedef atomic_t        oal_atomic;
typedef unsigned long   oal_bitops;

#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)

typedef struct {
    volatile int counter;
} oal_atomic;

#ifdef _PRE_LOSCFG_KERNEL_SMP
#ifndef G_SPIN_LOCK
#define G_SPIN_LOCK
static SPIN_LOCK_INIT(g_spinlock);
#endif
#endif

typedef unsigned long oal_bitops;

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
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)

#define oal_atomic_inc_return atomic_inc_return
#define oal_bit_atomic_for_each_set(nr, p_addr, size) for_each_set_bit(nr, p_addr, size)

#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)

#define BITS_PER_LONG       32
#define IS_BIT_SET(nr)        (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)        ((nr) / BITS_PER_LONG)
#define BITOP_WORD(nr)      ((nr) / BITS_PER_LONG)
#define OAL_ATOMIC_INIT(i)  { (i) }

#define oal_atomic_inc_return(v)    (oal_atomic_add_return(1, v))
#define oal_atomic_dec_return(v)    (oal_atomic_sub_return(1, v))
#define oal_atomic_sub_and_test(i, v) (oal_atomic_sub_return(i, v) == 0)

#define oal_bit_atomic_for_each_set(bit, addr,size) \
            for ((bit) = find_next_bit((addr), (size), 0); \
            (bit) < (size); \
            (bit) = (hi_s32)find_next_bit((addr), (size), (bit) + 1))

#endif

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#if __LINUX_ARM_ARCH__ >= 6

/*
 * ARMv6 UP and SMP safe atomic ops.  We use load exclusive and
 * store exclusive to ensure that these are atomic.  We may loop
 * to ensure that the update happens.
 */
static inline void atomic_add(int i, oal_atomic *v)
{
    unsigned long tmp;
    int result;

    __asm__ __volatile__("@ atomic_add\n"
"1: ldrex   %0, [%2]\n"
"   add %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq %1, #0\n"
"   bne 1b"
    : "=&r" (result), "=&r" (tmp)
    : "r" (&v->counter), "Ir" (i)
    : "cc");
}

static inline int atomic_add_return(int i, oal_atomic *v)
{
    unsigned long tmp;
    int result;

    smp_mb();

    __asm__ __volatile__("@ atomic_add_return\n"
"1: ldrex   %0, [%2]\n"
"   add %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq %1, #0\n"
"   bne 1b"
    : "=&r" (result), "=&r" (tmp)
    : "r" (&v->counter), "Ir" (i)
    : "cc");

    smp_mb();

    return result;
}

static inline void atomic_sub(int i, oal_atomic *v)
{
    unsigned long tmp;
    int result;

    __asm__ __volatile__("@ atomic_sub\n"
"1: ldrex   %0, [%2]\n"
"   sub %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq %1, #0\n"
"   bne 1b"
    : "=&r" (result), "=&r" (tmp)
    : "r" (&v->counter), "Ir" (i)
    : "cc");
}

static inline int atomic_sub_return(int i, oal_atomic *v)
{
    unsigned long tmp;
    int result;

    smp_mb();

    __asm__ __volatile__("@ atomic_sub_return\n"
"1: ldrex   %0, [%2]\n"
"   sub %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq %1, #0\n"
"   bne 1b"
    : "=&r" (result), "=&r" (tmp)
    : "r" (&v->counter), "Ir" (i)
    : "cc");

    smp_mb();

    return result;
}

#else /* ARM_ARCH_6 */

#ifdef CONFIG_SMP
#error SMP not supported on pre-ARMv6 CPUs
#endif

static inline int oal_atomic_add_return(int i, oal_atomic *v)
{
    hi_u32 int_save;
    int val;

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &int_save);
#else
    int_save = LOS_IntLock();
#endif
    val = v->counter;
    v->counter = val += i;
#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, int_save);
#else
    (VOID)LOS_IntRestore(int_save);
#endif

    return val;
}
#define oal_atomic_add(i, v)    (void) oal_atomic_add_return(i, v)

static inline int oal_atomic_sub_return(int i, oal_atomic *v)
{
    hi_u32 int_save;
    int val;

#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinLockSave(&g_spinlock, &int_save);
#else
    int_save = LOS_IntLock();
#endif
    val = v->counter;
    v->counter = val -= i;
#ifdef _PRE_LOSCFG_KERNEL_SMP
    LOS_SpinUnlockRestore(&g_spinlock, int_save);
#else
    (VOID)LOS_IntRestore(int_save);
#endif

    return val;
}
#define oal_atomic_sub(i, v)    (void) oal_atomic_sub_return(i, v)

#endif /* end of __LINUX_ARM_ARCH__ */

static inline unsigned long __ffs(unsigned long word)
{
    unsigned long num = 0;

#if BITS_PER_LONG == 64
    if ((word & 0xffffffff) == 0) {
        num += 32;      /* num add 32 */
        word >>= 32;    /* word right shift 32 */
    }
#endif
    if ((word & 0xffff) == 0) {
        num += 16;      /* num add 16 */
        word >>= 16;    /* word right shift 16 */
    }
    if ((word & 0xff) == 0) {
        num += 8;       /* num add 8 */
        word >>= 8;     /* word right shift 8 */
    }
    if ((word & 0xf) == 0) {
        num += 4;       /* num add 4 */
        word >>= 4;     /* word right shift 4 */
    }
    if ((word & 0x3) == 0) {
        num += 2;       /* num add 2 */
        word >>= 2;     /* word right shift 2 */
    }
    if ((word & 0x1) == 0)
        num += 1;
    return num;
}


static inline oal_bitops find_next_bit(const oal_bitops *addr, oal_bitops size,
    oal_bitops offset)
{
    const oal_bitops *p = addr + BITOP_WORD(offset);
    oal_bitops result = offset & ~(BITS_PER_LONG - 1);
    oal_bitops tmp;

    if (offset >= size) {
        return size;
    }
    size -= result;
    offset %= BITS_PER_LONG;
    if (offset) {
        tmp = *(p++);
        tmp &= (~0UL << offset);
        if (size < BITS_PER_LONG) {
            goto found_first;
        }
        if (tmp) {
            goto found_middle;
        }
        size -= BITS_PER_LONG;
        result += BITS_PER_LONG;
    }
    while (size & ~(BITS_PER_LONG - 1)) {
        if ((tmp = *(p++))) {
            goto found_middle;
        }
        result += BITS_PER_LONG;
        size -= BITS_PER_LONG;
    }
    if (!size) {
        return result;
    }
    tmp = *p;

found_first:
    tmp &= (~0UL >> (BITS_PER_LONG - size));
    if (tmp == 0UL) {    /* Are any bits set? */
        return result + size;   /* Nope. */
    }
found_middle:
    return result + __ffs(tmp);
}

#endif /* end of _PRE_OS_VERSION_LITEOS */


/*****************************************************************************
 ��������  : ��ȡԭ�ӱ�����ֵ
 �������  : *p_vector: ��Ҫ����ԭ�Ӳ�����ԭ�ӱ�����ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_s32 oal_atomic_read(const oal_atomic *p_vector)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return atomic_read(p_vector);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return p_vector->counter;
#endif
}

/*****************************************************************************
 ��������  : ԭ�ӵ�����ԭ�ӱ���p_vectorֵΪul_val
 �������  : p_vector: ��Ҫ����ԭ�Ӳ�����ԭ�ӱ�����ַ
             l_val  : ��Ҫ�����óɵ�ֵ
 �������  : ��
 �� �� ֵ  : hi_void
*****************************************************************************/
static inline hi_void oal_atomic_set(oal_atomic *p_vector, hi_s32 l_val)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    atomic_set(p_vector, l_val);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    p_vector->counter = l_val;
#endif
}

/*****************************************************************************
 ��������  : ԭ�ӵĸ���μ�1��
 �������  : *p_vector: ��Ҫ����ԭ�Ӳ�����ԭ�ӱ�����ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_atomic_dec(oal_atomic *p_vector)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    atomic_dec(p_vector);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_atomic_sub(1, p_vector);
#endif
}

/*****************************************************************************
 ��������  : ԭ�ӵĸ���μ�һ
 �������  : *p_vector: ��Ҫ����ԭ�Ӳ�����ԭ�ӱ�����ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_atomic_inc(oal_atomic *p_vector)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    atomic_inc(p_vector);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_atomic_add(1, p_vector);
#endif
}

/*****************************************************************************
 ��������  : ԭ�ӵ����������Ƿ�Ϊ0
 �������  : *p_vector: ��Ҫ����ԭ�Ӳ�����ԭ�ӱ�����ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_s32  oal_atomic_inc_and_test(oal_atomic *p_vector)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return atomic_inc_and_test(p_vector);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return (oal_atomic_add_return(1, p_vector) == 0);
#endif
}

/*****************************************************************************
 ��������  : ԭ�ӵݼ��������Ƿ�Ϊ0
 �������  : *p_vector: ��Ҫ����ԭ�Ӳ�����ԭ�ӱ�����ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_s32 oal_atomic_dec_and_test(oal_atomic *p_vector)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return atomic_dec_and_test(p_vector);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return (oal_atomic_sub_return(1, p_vector) == 0);
#endif
}

static inline hi_void oal_bit_atomic_set(hi_s32 nr, HI_VOLATILE oal_bitops *p_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    set_bit(nr, p_addr);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    UINTPTR int_save;
    int_save = LOS_IntLock();

    oal_bitops mask = IS_BIT_SET(nr);
    oal_bitops *p = ((oal_bitops *)p_addr) + BIT_WORD(nr);
    *p  |= mask;

    (VOID)LOS_IntRestore(int_save);
#endif
}

static inline hi_s32 oal_bit_atomic_test(hi_s32 nr, HI_VOLATILE const oal_bitops *p_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return test_bit(nr, p_addr);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return (1UL & (p_addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG - 1))));
#endif
}

/*****************************************************************************
 ��������  : ԭ�ӵĶ�ĳ��λ������1�����������ظ�λ�õľ�ֵ��
 �������  : nr: ��Ҫ���õ�λ
             p_addr��Ҫ��λ�ı�����ַ
 �������  :
 �� �� ֵ  : ����ԭ��bitλ��ֵ
*****************************************************************************/
static inline oal_bitops oal_bit_atomic_test_and_set(hi_s32 nr, HI_VOLATILE oal_bitops *p_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return test_and_set_bit(nr, p_addr);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    UINTPTR int_save;
    int_save = LOS_IntLock();

    oal_bitops mask = IS_BIT_SET(nr);
    oal_bitops *p = ((oal_bitops *)p_addr) + BIT_WORD(nr);
    oal_bitops old = *p;
    *p = old | mask;

    (VOID)LOS_IntRestore(int_save);
    return ((old & mask) != 0);
#endif
}

static inline oal_bitops oal_bit_atomic_test_and_clear(hi_u32 nr, HI_VOLATILE oal_bitops *p_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return (oal_bitops)test_and_clear_bit(nr, p_addr);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    UINTPTR int_save;
    int_save = LOS_IntLock();

    oal_bitops mask = IS_BIT_SET(nr);
    oal_bitops *p = ((oal_bitops *)p_addr) + BIT_WORD(nr);
    oal_bitops old = *p;
    *p = old & ~mask;

    (VOID)LOS_IntRestore(int_save);
    return (old & mask) != 0;
#endif
}

/*****************************************************************************
 ��������  : ��װ��������ϵͳƽ̨�¶�ĳ��λ����ԭ����0������
 �������  : nr: ��Ҫ�����λ
             p_addr��Ҫ����ı�����ַ
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_bit_atomic_clear(hi_s32 nr, HI_VOLATILE oal_bitops *p_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    clear_bit(nr, p_addr);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    UINTPTR int_save;
    int_save = LOS_IntLock();

    oal_bitops mask = IS_BIT_SET(nr);
    oal_bitops *p = ((oal_bitops *)p_addr) + BIT_WORD(nr);
    *p &= ~mask;

    (VOID)LOS_IntRestore(int_save);
#endif
}


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_atomic.h */
