/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: board resource get
 * Author: Hisilicon
 * Create: 2018-08-04
 */
#include "hcc_host.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_u32 hi_wifi_open_gpio_soft_reset_device(hi_void)
{
    hcc_open_gpio_soft_rest soft_reset = {0};
    soft_reset.is_open = 1;
    return hcc_send_control_msg(hcc_host_get_handler(),
        OAM_SET_SOFT_RST,
        (hi_u8*)&soft_reset,
        sizeof(soft_reset));
}

hi_u32 hi_wifi_close_gpio_soft_reset_device(hi_void)
{
    hcc_open_gpio_soft_rest soft_reset = {0};
    soft_reset.is_open = 0;
    return hcc_send_control_msg(hcc_host_get_handler(),
        OAM_SET_SOFT_RST,
        (hi_u8*)&soft_reset,
        sizeof(soft_reset));
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

