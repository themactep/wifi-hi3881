/*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: time APIs.CNcomment:ʱ��ӿ�����CNend
* Author: Hisilicon
* Create: 2018-08-04
*/

/**
 * @defgroup iot_time System Clock
 * @ingroup osa
 */
#ifndef __HI_TIME_H__
#define __HI_TIME_H__
#include <hi_types_base.h>

/**
* @ingroup  iot_time
* @brief  Delay, in microseconds.CNcomment:��ʱ��΢�뼶��CNend
*
* @par ����:
*           Delay operation implemented by software based on the system clock, blocking the CPU.
CNcomment:��ʱ����������CPU��CNend
*
* @attention This API cannot be used for a long time in an interrupt.CNcomment:�������ж���ʹ�á�CNend
*
* @param  us                [IN] type #hi_u32��delay period (unit: microsecond).
CNcomment:��ʱʱ�䣨��λ����s����CNend
*
* @retval  None
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_udelay(hi_u32 us);

/**
* @ingroup  iot_time
* @brief  Obtains the tick value of the system (32-bit).CNcomment:��ȡϵͳtickֵ��32bit����CNend
*
* @par ����:
*           Obtains the tick value of the system (32-bit).CNcomment:��ȡϵͳtickֵ��32bit����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 Tick value of the system.CNcomment:ϵͳtickֵ��CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_tick(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the tick value of the system (64-bit).CNcomment:��ȡϵͳtickֵ��64bit����CNend
*
* @par ����:
*           Obtains the tick value of the system (64-bit).CNcomment:��ȡϵͳtickֵ��64bit����CNend
*
* @attention The hi_mdm_time.h file must be included where the API is called. Otherwise, the API is considered not
*            declared, and the tick value is returned as an int type, resulting in a truncation error.
CNcomment:�ýӿڵ��ô��������ͷ�ļ�hi_time.h��������δ�����ӿڴ����Ὣtickֵ����int���ͷ��أ������ضϴ���CNend
* @param None
*
* @retval  #hi_u64 Tick value of the system.CNcomment:ϵͳtickֵ��CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u64 hi_get_tick64(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the system time (unit: s).CNcomment:��ȡϵͳʱ�䣨��λ��s����CNend
*
* @par ����:
*           Obtains the system time (unit: s).CNcomment:��ȡϵͳʱ�䣨��λ��s����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 System time.CNcomment:ϵͳʱ�䡣CNend
* @retval #HI_ERR_FAILURE failed to be obtained. CNcomment:��ȡʱ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_seconds(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the system time (unit: us).CNcomment:��ȡϵͳʱ�䣨��λ��us����CNend
*
* @par ����:
*           Obtains the system time (unit: us).CNcomment:��ȡϵͳʱ�䣨��λ��us����CNend
*
* @attention None
* @param None
*
* @retval #hi_u64 System time.CNcomment:ϵͳʱ�䡣CNend
* @retval #HI_ERR_FAILURE failed to be obtained. CNcomment:��ȡʱ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u64 hi_get_us(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the real time of the system (unit: s).CNcomment:��ȡϵͳʵʱʱ�䣨��λ��s����CNend
*
* @par ����:
*           Obtains the real time of the system (unit: s).CNcomment:��ȡϵͳʵʱʱ�䣨��λ��s����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 Real time of the system.CNcomment: ϵͳʵʱʱ�䡣CNend
* @retval #HI_ERR_FAILURE failed to be obtained. CNcomment:��ȡʱ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_real_time(hi_void);

/**
* @ingroup  iot_time
* @brief  Sets the real time of the system.CNcomment:����ϵͳʵʱʱ�䡣CNend
*
* @par ����:
*           Sets the real time of the system.CNcomment:����ϵͳʵʱʱ�䡣CNend
*
* @attention None
* @param  seconds            [IN] type #hi_u32��set the real time of the system to this value.
CNcomment:��ϵͳʵʱʱ������Ϊ��ֵ��CNend
*
* @retval #HI_ERR_SUCCESS    Success.
* @retval #HI_ERR_FAILURE    Failure.
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_set_real_time(hi_u32 seconds);

#endif

