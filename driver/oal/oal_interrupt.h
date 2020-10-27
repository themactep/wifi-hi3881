/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_mm.h
 * Author: Hisilicon
 * Create: 2020-01-09
 */

#ifndef __OAL_INTERRUPT_H__
#define __OAL_INTERRUPT_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include <linux/interrupt.h>
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <asm/hal_platform_ints.h>
#include <gpio.h>
#include <hisoc/gpio.h>
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 STRUCT定义
*****************************************************************************/
/*****************************************************************************
  3 枚举定义
*****************************************************************************/
/*****************************************************************************
  4 全局变量声明
*****************************************************************************/
/*****************************************************************************
  5 消息头定义
*****************************************************************************/
/*****************************************************************************
  6 消息定义
*****************************************************************************/
/*****************************************************************************
  7 宏定义
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifndef IRQF_NO_SUSPEND
#define IRQF_NO_SUSPEND 0x0000
#endif

#ifndef IRQF_DISABLED
#define IRQF_DISABLED 0x0000
#endif

#define GPIO_TO_IRQ(group, bit)  ((group) * (GPIO_BIT_NUM) + (bit) + (OS_USER_HWI_MAX))
#define IRQ_TO_GPIO_GROUP(irq)  (((irq) - (OS_USER_HWI_MAX)) / (GPIO_BIT_NUM))
#define IRQ_TO_GPIO_BIT(irq)    (((irq) - (OS_USER_HWI_MAX)) % (GPIO_BIT_NUM))
#endif

/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
/*****************************************************************************
  10 函数声明
*****************************************************************************/
static inline hi_s32 oal_request_irq(hi_u32 irq, irq_handler_t handler, unsigned long flags,
                                     const hi_char *name, hi_void *dev)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return request_irq(irq, handler, flags, name, dev);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (irq <= OS_USER_HWI_MAX) {
        return request_irq(irq, handler, flags, name, dev);
    } else {
        gpio_groupbit_info st_gpio_info = {0};
        st_gpio_info.groupnumber     = IRQ_TO_GPIO_GROUP(irq);
        st_gpio_info.bitnumber       = IRQ_TO_GPIO_BIT(irq);
        st_gpio_info.irq_handler     = (irq_func)handler;
        st_gpio_info.irq_type        = 0;
        st_gpio_info.data            = dev;

        return gpio_irq_register(&st_gpio_info);
    }
#endif
}

static inline hi_void oal_free_irq(hi_u32 irq, hi_void *dev)
{
    free_irq(irq, dev);
}

static inline hi_void oal_enable_irq(hi_u32 irq)
{
    enable_irq(irq);
}

static inline hi_void oal_disable_irq(hi_u32 irq)
{
    disable_irq(irq);
}

static inline hi_void oal_disable_irq_nosync(hi_u32 irq)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    disable_irq_nosync(irq);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    disable_irq(irq);
#endif
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_completion.h */

