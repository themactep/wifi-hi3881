/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: plat_pm.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 Header File Including
*****************************************************************************/
#include <linux/interrupt.h>
#ifndef HAVE_PCLINT_CHECK
#include <linux/platform_device.h>
#endif
#include "plat_board_adapt.h"
#include "plat_firmware.h"
#include "plat_pm.h"
#include "oal_sdio_host_if.h"
#include "hcc_host.h"
#include "oal_schedule.h"
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/kobject.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/host.h>
#include <linux/gpio.h>
#include <linux/irq.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/notifier.h>
#include "exception_rst.h"
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <linux/module.h>   /* kernel module definitions */
#include <linux/timer.h>
#include <linux/wakelock.h>
#endif
#include "oal_channel_host_if.h"
#include "oal_mm.h"
#include "oam_ext_if.h"

/*****************************************************************************
  2 Global Variable Definition
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
unsigned int g_ul_wlan_resume_state = 0;
unsigned int g_ul_wlan_resume_wifi_init_flag = 0;
#endif

/*****************************************************************************
 * Description  : download wlan patch
 * Input        :
 * Output       : none
 * Return       : 0 means succeed,-1 means failed
*****************************************************************************/
int firmware_download_function(hi_u32 which_cfg)
{
    hi_s32 ret;
    unsigned long long total_time;

    static unsigned long long count = 0;



    if (which_cfg >= CFG_FILE_TOTAL) {
        oam_error_log1(0, 0, "firmware_download_function:: cfg file index [%d] outof range", which_cfg);
        return -FAILURE;
    }

#ifndef _PRE_FEATURE_NO_GPIO
    board_power_on();
#endif

    oam_info_log0(0, 0, "firmware_download_function:: firmware_download begin");
    ret = firmware_download(which_cfg);
    if (ret < 0) {
        oam_error_log0(0, 0, "firmware_download_function:: firmware download fail");
        return ret;
    }
    oam_info_log0(0, 0, "firmware_download_function:: firmware_download success");


    count++;
    ret = SUCCESS;
    return ret;
}

hi_s32 wlan_power_on(hi_void)
{
    hi_s32  ret;
    static unsigned long long num = 0;



    ret = firmware_download_function(WIFI_CFG);
    if (ret != SUCCESS) {
        oam_error_log0(0, 0, "wlan_power_on:: firmware download fail");
        return -FAILURE;
    }

    oam_warning_log0(0, 0, "wlan_power_on:: firmware download success");
    /* 注册SDIO中断入口函数 */
    if (HI_SUCCESS != oal_channel_transfer_prepare(hcc_host_get_handler()->hi_channel)) {
        oam_error_log0(0, 0, "wlan_power_on:: channel transfer prepare fail");
        return -FAILURE;
    }



    num++;

    ret = WIFI_POWER_SUCCESS;

#ifndef _PRE_FEATURE_NO_GPIO
    board_set_host_to_dev_gpio_val_high();
#endif
    return ret;
}

