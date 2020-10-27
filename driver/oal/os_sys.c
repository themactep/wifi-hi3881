/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: system interface:tick/delay.
 * Author: Hisilicon
 * Create: 2019-03-04
 */
#include <hi_types_base.h>
#include <hi_config.h>

hi_u32 ms2systick(HI_IN hi_u32 ms, HI_IN hi_bool include0)
{
    hi_u32 tick;

    /* >10ms���¶��� */
    if (ms > HI_MILLISECOND_PER_TICK) {
        tick = ms / HI_MILLISECOND_PER_TICK;    /* convert from ms to ticks */
    }
    /* <10ms���϶��� */
    else {
        if ((HI_TRUE == include0) && (0 == ms)) {
            tick = 0;
        } else {
            tick = 1;
        }
    }

    return tick;
}
