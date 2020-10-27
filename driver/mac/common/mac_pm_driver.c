/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: STA PM save site recovery field drive.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include "mac_pm_driver.h"

hi_u8 g_pm_wlan_need_stop_ba;

hi_u8 *mac_get_pm_wlan_need_stop_ba(hi_void)
{
    return &g_pm_wlan_need_stop_ba;
}
