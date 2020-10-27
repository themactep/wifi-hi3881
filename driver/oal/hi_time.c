/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: system time interface.
 * Author: Hisilicon
 * Create: 2019-03-04
 */
#include <hi_types_base.h>
#include <los_sys.h>
#include <hi_stdlib.h>
#include <time.h>
#include "hi_config.h"

#define SEC_TO_US   1000000
#define US_TO_NSEC  1000

hi_u32 hi_get_tick(hi_void)
{
    return (hi_u32) (LOS_TickCountGet() & 0xffffffff);
}

hi_u64 hi_get_tick64(hi_void)
{
    return LOS_TickCountGet();
}

hi_u32 hi_get_milli_seconds(hi_void)
{
    return ((hi_u32) (LOS_TickCountGet() & 0xffffffff) * HI_MILLISECOND_PER_TICK);
}

hi_u32 hi_get_seconds(hi_void)
{
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) == 0) {
        return (hi_u32) (tp.tv_sec);
    } else {
        return (hi_u32) (HI_ERR_FAILURE);
    }
}

hi_u64 hi_get_us(hi_void)
{
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) == 0) {
        return (hi_u64)(hi_u32)tp.tv_sec * SEC_TO_US + (hi_u32)tp.tv_nsec / US_TO_NSEC;
    } else {
        return (hi_u64) (HI_ERR_FAILURE);
    }
}

hi_u32 hi_get_real_time(hi_void)
{
    struct timespec tp;

    if (clock_gettime(CLOCK_REALTIME, &tp) == 0) {
        return (hi_u32) (tp.tv_sec);
    } else {
        return (hi_u32) (HI_ERR_FAILURE);
    }
}

hi_u32 hi_set_real_time(hi_u32 sec)
{
    struct timespec tp;

    memset_s((hi_void *) &tp, sizeof(struct timespec), 0x0, sizeof(struct timespec));
    tp.tv_sec = (int) sec;
    tp.tv_nsec = 0;

    if (clock_settime(CLOCK_REALTIME, &tp) == 0) {
        return (hi_u32) (HI_ERR_SUCCESS);
    } else {
        return (hi_u32) (HI_ERR_FAILURE);
    }
}

