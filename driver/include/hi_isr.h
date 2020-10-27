/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Oal external public interface header file.
 * Author: Hisilicon
 * Create: 2020-03-23
 */

#ifndef __HI_ISR_H__
#define __HI_ISR_H__
#include "hi_types.h"

#define HI_EXC_FLAG_NO_FLOAT                0x10000000
#define HI_EXC_FLAG_FAULTADDR_VALID         0x01
#define HI_EXC_FLAG_IN_HWI                  0x02

typedef struct {
    /* handler save */
    hi_u32 r4;
    hi_u32 r5;
    hi_u32 r6;
    hi_u32 r7;
    hi_u32 r8;
    hi_u32 r9;
    hi_u32 r10;
    hi_u32 r11;
    hi_u32 pri_mask;
    /* auto save */
    hi_u32 sp;
    hi_u32 r0;
    hi_u32 r1;
    hi_u32 r2;
    hi_u32 r3;
    hi_u32 r12;
    hi_u32 lr;
    hi_u32 pc;
    hi_u32 xpsr;
} hi_exc_context;

/**
* @ingroup  iot_isr
* @brief  HISR callback function type.CNcomment:HISR�жϻص����������͡�CNend
*
* @par ������
*           HISR callback function type.CNcomment:HISR�жϻص����������͡�CNend
*
* @attention None
* @param  param [IN] type #hi_u32��Callback input parameter.CNcomment:�ص���Ρ�CNend
*
* @retval None
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
typedef hi_void (*irq_routine)(hi_u32 param);

/**
* @ingroup  iot_isr
* @brief  Interrupt off.CNcomment:���жϡ�CNend
*
* @par ����:
*           Interrupt off.CNcomment:���жϡ�CNend
*
* @attention
*           @li A function that causes scheduling cannot be executed in an interrupt off context, for example,
*               hi_sleep and other blocked APIs.
*               CNcomment:���жϺ���ִ��������ȵĺ�������hi_sleep�����������ӿڡ�CNend
*           @li Interrupt off only protects short-time operations that can be expected. Otherwise, the interrupt
*               response and the performance may be affected.
*               CNcomment:���жϽ�������Ԥ�ڵĶ�ʱ��Ĳ���������Ӱ���ж���Ӧ�����������������⡣CNend
*
* @param  None
*
* @retval #Interruption status value  Interrupt status before interrupt off.
CNcomment:�ж�״ֵ̬  ���ж�ǰ���ж�״̬��CNend
*
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  hi_int_restore��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_int_lock(hi_void);

/**
* @ingroup  iot_isr
* @brief  Restores the status before interrupt off.CNcomment:�ָ����ж�ǰ��״̬��CNend
*
* @par ����:
*           Restores the status before interrupt off.CNcomment:�ָ����ж�ǰ��״̬��CNend
*
* @attention The input argument must be the value of CPSR that is saved before interrupt off.
* CNcomment:��α�������֮��Ӧ�Ĺ��ж�ʱ����Ĺ��ж�֮ǰ��CPSR��ֵ��CNend
*
* @param  int_value [IN] type #hi_u32��Interrupt status.CNcomment:�ж�״̬��CNend
*
* @retval None
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  hi_int_lock��
* @since Hi3861_V100R001C00
*/
hi_void hi_int_restore(hi_u32 int_value);


/**
* @ingroup  iot_isr
* @brief  Enables a specified interrupt.CNcomment:ʹ��ָ���жϡ�CNend
*
* @par ����:
*           Enables a specified interrupt.CNcomment:ʹ��ָ���жϡ�CNend
*
* @attention None
*
* @param  vector [IN] type #hi_u32��Interrupt ID.CNcomment:�жϺš�CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  hi_irq_disable��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_irq_enable(hi_u32 vector);

/**
* @ingroup  iot_isr
* @brief  Disables a specified interrupt.CNcomment:ȥʹ��ָ���жϡ�CNend
*
* @par ����:
*           Disables a specified interrupt.CNcomment:ȥʹ��ָ���жϡ�CNend
*
* @attention None
* @param  vector [IN] type #hi_u32��Interrupt ID.CNcomment:�жϺš�CNend
*
* @retval None
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  hi_irq_enable��
* @since Hi3861_V100R001C00
*/
hi_void hi_irq_disable(hi_u32 vector);

/* ���ڲ�֧���ж�Ƕ�ף������ж�ͬʱ�����ĳ�������Ч�� */
#define HI_IRQ_FLAG_PRI1    1
#define HI_IRQ_FLAG_PRI2    2
#define HI_IRQ_FLAG_PRI3    3
#define HI_IRQ_FLAG_PRI4    4
#define HI_IRQ_FLAG_PRI5    5
#define HI_IRQ_FLAG_PRI6    6
#define HI_IRQ_FLAG_PRI7    7
#define HI_IRQ_FLAG_PRI_MASK  0x7
#define HI_IRQ_FLAG_NOT_IN_FLASH 0x10

#define HI_IRQ_FLAG_DEFAULT    HI_IRQ_FLAG_NOT_IN_FLASH

/**
* @ingroup  iot_isr
* @brief  Registers an interrupt.CNcomment:ע���жϡ�CNend
*
* @par ����:
*           Registers an interrupt.CNcomment:ע���жϡ�CNend
*
* @attention The interruption handling program cannot take too long a time, which affects the timely response of the
*            CPU to the interrupt.CNcomment:�жϴ�������ʱ���ܹ�����Ӱ��CPU���жϵļ�ʱ��Ӧ��CNend
*
* @param  vector [IN] type #hi_u32��Interrupt ID.CNcomment:�жϺš�CNend
* @param  flag [IN]   type #hi_u32, attributes like priority,etc.CNcomment:�ж����ȼ������ԡ�CNend
* @param  routine  [IN] type #irq_routine��Interrupt callback function.CNcomment:�жϻص�������CNend
* @param  param    [IN] type #hi_u32��Parameter transferred to the callback function.
CNcomment:�жϻص���������Ρ�CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  hi_irq_free��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_irq_request(hi_u32 vector, hi_u32 flags, irq_routine routine, hi_u32 param);

/**
* @ingroup  iot_isr
* @brief  Clears a registered interrupt.CNcomment:���ע���жϡ�CNend
*
* @par ����:
*           Clears a registered interrupt.CNcomment:���ע���жϡ�CNend
*
* @attention None
* @param  vector [IN] type #hi_u32��Interrupt ID.CNcomment:�жϺš�CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  hi_irq_request��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_irq_free(hi_u32 vector);

/**
* @ingroup  iot_isr
* @brief  Checks whether it is in the interrupt context.CNcomment:����Ƿ����ж��������С�CNend
*
* @par ����:
*           Checks whether it is in the interrupt context.CNcomment:����Ƿ����ж��������С�CNend
*
* @attention None
* @param  None
*
* @retval #0     Not in the interrupt context.CNcomment:�����ж��������С�CNend
* @retval #1     In the interrupt context.CNcomment:���ж��������С�CNend
* @par ����:
*            @li hi_isr.h��Describes ISR APIs.CNcomment:�ļ���������ISR��ؽӿڡ�CNend
* @see  �ޡ�
* @since Hi3861_V100R001C00
*/
hi_bool hi_is_int_context(hi_void);

#endif


