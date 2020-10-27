/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: plat sdio driver
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 Header File Including
*****************************************************************************/
#include "oal_sdio.h"
#include "oal_sdio_host_if.h"
#include "oal_mm.h"

#include "plat_sdio.h"
#include "plat_pm.h"
#include "plat_firmware.h"
#include "oal_time.h"
#include "oam_ext_if.h"

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
extern struct sdio_func *g_p_gst_sdio_func;
#endif

/*****************************************************************************
  2 Global Variable Definition
*****************************************************************************/
/*****************************************************************************
  3 Function Definition
*****************************************************************************/
/*
 * Description  : provide interface for pm driver
 * Input        : hi_u8* buf, hi_u32 len
 * Output       : None
 * Return Value : hi_s32
 *
 */
hi_s32 sdio_patch_writesb(hi_u8* buf, hi_u32 len)
{
    int ret;
    oal_channel_stru* hi_sdio;
    struct sdio_func *func = HI_NULL;

    hi_sdio = oal_get_sdio_default_handler();
    if (hi_sdio == NULL) {
        return -FAILURE;
    }

    func = hi_sdio->func;
    if (func == NULL) {
        return -FAILURE;
    }

    if (buf == NULL || len == 0) {
        return -FAILURE;
    }

    len  = HISDIO_ALIGN_4_OR_BLK(len);

    sdio_claim_host(func);
    ret = oal_sdio_writesb(func, HISDIO_REG_FUNC1_FIFO, buf, len);
    if (ret < 0) {
    }
    sdio_release_host(func);
    return ret;
}

/*
 * Description  : provide interface for pm driver
 * Input        : hi_u8* buf, hi_u32 len hi_u32 timeout (ms)
 * Output       : None
 * Return Value : hi_s32
 */
hi_s32 sdio_patch_readsb(hi_u8* buf, hi_u32 len, hi_u32 timeout)
{
    hi_u8   int_mask;
    hi_u8  *ver_info = HI_NULL;
    int     ret = 0;
    unsigned long timeout_jiffies;
    hi_u32  xfer_count;
    hi_u32  i;
    oal_channel_stru* hi_sdio;
    struct sdio_func *func = HI_NULL;

    hi_sdio = oal_get_sdio_default_handler();
    if (hi_sdio == NULL) {
        return -FAILURE;
    }

    func = hi_sdio->func;
    if (func == NULL) {
        return -FAILURE;
    }

    if (buf == NULL || len == 0) {
        return -FAILURE;
    }
    sdio_claim_host(func);
    timeout_jiffies = OAL_TIME_JIFFY + OAL_MSECS_TO_JIFFIES(timeout);
    for (;;) {
        int_mask = oal_sdio_readb(func, HISDIO_REG_FUNC1_INT_STATUS, &ret);
        if (ret) {
            sdio_release_host(func);
            return -FAILURE;
        }

        if (int_mask & HISDIO_FUNC1_INT_MASK) {
            /* sdio int came */
            break;
        }

        if (oal_time_after(OAL_TIME_JIFFY, timeout_jiffies)) {
            sdio_release_host(func);
            return -FAILURE;
        }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        cpu_relax();
#endif
    }

    oal_sdio_writeb(func, int_mask, HISDIO_REG_FUNC1_INT_STATUS, &ret);
    if (ret < 0) {
        sdio_release_host(func);
        return -FAILURE;
    }

    timeout_jiffies = OAL_TIME_JIFFY + OAL_MSECS_TO_JIFFIES(timeout);
    for (;;) {
        int_mask = oal_sdio_readb(func, HISDIO_REG_FUNC1_INT_STATUS, &ret);
        if (ret) {
            sdio_release_host(func);
            return -FAILURE;
        }

        if ((int_mask & HISDIO_FUNC1_INT_MASK) == 0) {
            /* sdio int came */
            break;
        }

        if (oal_time_after((hi_u32)OAL_TIME_JIFFY, timeout_jiffies)) {
            sdio_release_host(func);
            return -FAILURE;
        }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        cpu_relax();
#endif
    }

    xfer_count = oal_sdio_readl(func, HISDIO_REG_FUNC1_XFER_COUNT, &ret);
    if (ret < 0) {
        sdio_release_host(func);
        return -FAILURE;
    }

    if (xfer_count < len) {
        len = xfer_count;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    ver_info = oal_kzalloc((xfer_count + 1), OAL_GFP_KERNEL);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    ver_info = (hi_u8 *)memalign(32, SKB_DATA_ALIGN(xfer_count + 1));   /* 32 */
#endif
    if (ver_info == NULL) {
        sdio_release_host(func);
        return -ENOMEM;
    }

    /* ��ȫ��̹���6.6����(3) �Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(ver_info, xfer_count + 1, 0, xfer_count);
    ret = oal_sdio_readsb(func, ver_info, HISDIO_REG_FUNC1_FIFO, xfer_count);
    if (ret >= 0) {
        for (i = 0; i < len; i++) {
            buf[i] = ver_info[i];
        }
    }
    oal_free(ver_info);

    sdio_release_host(func);

    return xfer_count;
}

