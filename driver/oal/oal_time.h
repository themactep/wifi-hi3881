/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_time.h ��ͷ�ļ�
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_TIME_H__
#define __OAL_TIME_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/rtc.h>
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <los_sys.h>
#include <linux/kernel.h>
#include "hi_types.h"
#include <linux/hrtimer.h>
#include <linux/rtc.h>
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* 32λ�Ĵ�����󳤶� */
#define OAL_TIME_US_MAX_LEN  (0xFFFFFFFF - 1)

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/* ��ȡ���뼶ʱ��� */
#define hi_get_milli_seconds() jiffies_to_msecs(jiffies)
#endif
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define hi_get_milli_seconds() LOS_Tick2MS(OAL_TIME_JIFFY)
#endif

/* ��ȡ�߾��Ⱥ���ʱ���,����1ms */
#define OAL_TIME_GET_HIGH_PRECISION_MS()  oal_get_time_stamp_from_timeval()

#define OAL_ENABLE_CYCLE_COUNT()
#define OAL_DISABLE_CYCLE_COUNT()
#define OAL_GET_CYCLE_COUNT() 0

/* �Ĵ�����תģ������ʱ����� */
#define OAL_TIME_CALC_RUNTIME(_ul_start, _ul_end)   \
    ((((OAL_TIME_US_MAX_LEN) / HZ) * 1000) + ((OAL_TIME_US_MAX_LEN) % HZ) * (1000 / HZ) - (_ul_start) + (_ul_end))

#define OAL_TIME_HZ       HZ

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define OAL_TIME_JIFFY    jiffies
#define OAL_MSECS_TO_JIFFIES(_msecs)    msecs_to_jiffies(_msecs)

#define OAL_JIFFIES_TO_MSECS(_jiffies)      jiffies_to_msecs(_jiffies)
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define OAL_TIME_JIFFY    LOS_TickCountGet()
#define OAL_MSECS_TO_JIFFIES(_msecs)    LOS_MS2Tick(_msecs)
#define OAL_JIFFIES_TO_MSECS(_jiffies)      LOS_Tick2MS(_jiffies)
#endif

/* ��ȡ��_ul_start��_ul_end��ʱ��� */
#define OAL_TIME_GET_RUNTIME(_ul_start, _ul_end) \
    (((_ul_start) > (_ul_end)) ? (OAL_TIME_CALC_RUNTIME((_ul_start), (_ul_end))) : ((_ul_end) - (_ul_start)))

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
typedef struct {
    signed long i_sec;
    signed long i_usec;
} oal_time_us_stru;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
typedef ktime_t oal_time_t_stru;
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
typedef union ktime oal_time_t_stru;

#ifndef ktime_t
#define ktime_t union ktime
#endif

#endif
typedef struct timeval oal_timeval_stru;
typedef struct rtc_time oal_rtctime_stru;

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
 ��������  : ��ȡ΢��ȼ���ʱ���
 �������  : pst_usec: ʱ��ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void  oal_time_get_stamp_us(oal_time_us_stru *pst_usec)
{
    struct timespec ts;
    getnstimeofday(&ts);
    pst_usec->i_sec     = ts.tv_sec;
    pst_usec->i_usec    = ts.tv_nsec / 1000; /* 1us �� 1000ns */
}

/*****************************************************************************
 ��������  : �����ں˺�����ȡ��ǰʱ���
 �������  : hi_void
 �������  :
 �� �� ֵ  :
*****************************************************************************/
static inline oal_time_t_stru oal_ktime_get(hi_void)
{
    return ktime_get();
}

/*****************************************************************************
 ��������  : �����ں˺�����ȡʱ���ֵ
 �������  :
 �������  :
 �� �� ֵ  :
*****************************************************************************/
static inline oal_time_t_stru oal_ktime_sub(const oal_time_t_stru lhs, const oal_time_t_stru rhs)
{
    return ktime_sub(lhs, rhs);
}

/*****************************************************************************
 ��������  : ��ȡʱ�侫��
 �������  : ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_u64 oal_get_time_stamp_from_timeval(hi_void)
{
    struct timeval tv;
    hi_u64 curr_time;

    do_gettimeofday(&tv);
    curr_time = tv.tv_usec;
    do_div(curr_time, 1000);                    /* div 1000 */
    curr_time = curr_time + tv.tv_sec * 1000;   /* mul 1000 */

    return curr_time;
}

static inline hi_void oal_do_gettimeofday(oal_timeval_stru *tv)
{
    do_gettimeofday(tv);
}

static inline hi_void oal_rtc_time_to_tm(unsigned long time, oal_rtctime_stru *tm)
{
    rtc_time_to_tm(time, tm);
}

/*****************************************************************************
 ��������  : �ж�ul_time�Ƿ�ȵ�ǰʱ����
             ���磬��ʾ��ʱʱ���ѹ��������磬������δ��ʱ
 �������  : unsigned long ui_time
 �������  : ��
 �� �� ֵ  : static inline hi_u32
*****************************************************************************/
static inline hi_u32 oal_time_is_before(unsigned long ui_time)
{
    return (hi_u32)time_is_before_jiffies(ui_time);
}

/*****************************************************************************
 ��������  : �ж�ʱ���ul_time_a�Ƿ���ul_time_b֮��:
 �������  : unsigned long ui_time
 �������  : ��
 �� �� ֵ  : Return: 1 ul_time_a��ul_time_b֮��; ���� Return: 0
*****************************************************************************/
static inline hi_u32 oal_time_after(hi_u64 ul_time_a, hi_u64 ul_time_b)
{
    return (hi_u32)time_after((unsigned long)ul_time_a, (unsigned long)ul_time_b);
}

static inline unsigned long oal_ktime_to_us(const oal_time_t_stru kt)
{
    return ktime_to_us(kt);
}

static inline hi_u32 oal_time_before_eq(hi_u32 ul_time_a, hi_u32 ul_time_b)
{
    return (hi_u32)time_before_eq((unsigned long)ul_time_a, (unsigned long)ul_time_b);
}

static inline hi_u32 oal_time_before(hi_u32 ul_time_a, hi_u32 ul_time_b)
{
    return (hi_u32)time_before((unsigned long)ul_time_a, (unsigned long)ul_time_b);
}
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ��ȡ΢��ȼ���ʱ���
 �������  : pst_usec: ʱ��ṹ��ָ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_void oal_time_get_stamp_us(oal_time_us_stru *pst_usec)
{
    oal_timeval_stru tv;
    do_gettimeofday(&tv);
    pst_usec->i_sec     = tv.tv_sec;
    pst_usec->i_usec    = tv.tv_usec;
}

/*****************************************************************************
 ��������  : �����ں˺�����ȡ��ǰʱ���
 �������  : hi_void
 �������  :
 �� �� ֵ  :
*****************************************************************************/
static inline oal_time_t_stru oal_ktime_get(hi_void)
{
    oal_time_t_stru time;
    time.tv64 = (hi_s64)LOS_TickCountGet();
    return time;
}

/*****************************************************************************
 ��������  : �����ں˺�����ȡʱ���ֵ
 �������  :
 �������  :
 �� �� ֵ  :
*****************************************************************************/
static inline oal_time_t_stru oal_ktime_sub(const oal_time_t_stru lhs, const oal_time_t_stru rhs)
{
    oal_time_t_stru res;
    res.tv64 = lhs.tv64 - rhs.tv64;
    return res;
}

/*****************************************************************************
 ��������  : ��ȡʱ�侫��
 �������  : ��
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_u64 oal_get_time_stamp_from_timeval(hi_void)
{
    oal_timeval_stru tv;
    do_gettimeofday(&tv);
    return ((hi_u64)tv.tv_usec / 1000 + (hi_u64)tv.tv_sec * 1000);  /* div/mul 1000 */
}

static inline hi_void oal_do_gettimeofday(oal_timeval_stru *tv)
{
    do_gettimeofday(tv);
}

/*****************************************************************************
 ��������  : �ж�ʱ���ul_time_a�Ƿ���ul_time_b֮��:
 �������  : hi_u64 ui_time
 �������  : ��
 �� �� ֵ  : Return: 1 ul_time_a��ul_time_b֮��; ���� Return: 0
*****************************************************************************/
static inline hi_u32 oal_time_after(hi_u64 ul_time_a, hi_u64 ul_time_b)
{
    return (hi_u32)((hi_s64)((hi_s64)(ul_time_b) - (ul_time_a)) < 0);
}

/*****************************************************************************
 ��������  : �ж�ul_time�Ƿ�ȵ�ǰʱ����
             ���磬��ʾ��ʱʱ���ѹ��������磬������δ��ʱ
 �������  :
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_u32 oal_time_is_before(hi_u64 ui_time)
{
    return oal_time_after(OAL_TIME_JIFFY, ui_time);
}

static inline hi_u64 oal_ktime_to_us(const oal_time_t_stru kt)
{
    return (OAL_JIFFIES_TO_MSECS((hi_u32)kt.tv64) * 1000);  /* mul 1000 */
}

static inline hi_u64 oal_ktime_to_ms(const oal_time_t_stru kt)
{
    return (OAL_JIFFIES_TO_MSECS(kt.tv64));
}

static inline hi_u32 oal_time_before_eq(hi_u32 ul_time_a, hi_u32 ul_time_b)
{
    return (hi_u32)((hi_s64)((ul_time_a) - (ul_time_b)) <= 0);
}

static inline hi_u32 oal_time_before(hi_u32 ul_time_a, hi_u32 ul_time_b)
{
    return (hi_u32)((hi_s64)((hi_s64)(ul_time_a) - (ul_time_b)) < 0);
}

#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_time.h */
