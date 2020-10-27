/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hcc driver implementatioin.
 * Author: dujinxin
 * Create: 2020-07-14
 */
#ifndef _OAL_CHR_H
#define _OAL_CHR_H
#include "oal_util.h"
#include "exception_rst.h"
#include "oal_err_wifi.h"
#include "hi_wifi_api.h"

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)

hi_u32 oal_register_ioctl(hi_void);

#else
hi_u32 oal_register_ioctl(hi_wifi_driver_event_cb event_cb);
#endif
hi_void oal_unregister_ioctl(hi_void);
hi_u32 hisi_sched_event(hi_wifi_driver_event event);
#endif
