/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: system event API
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/**
* @file hi_event.h
* Description: system event API.CNcomment:ϵͳ�¼��ӿڡ�CNend
* @li Before sending, waiting, or clearing an event, the event must be created to obtain the event ID.
CNcomment:�ڷ��͡��ȴ�������¼�֮ǰ������Ҫ�����¼�����ȡ�¼�ʹ��ID��CNend
* @li Wait event: The wait event API cannot be called in the interrupt, interrupt off,
* and lock task contexts to avoid uncontrollable exceptional scheduling.CNcomment:�ȴ��¼�:���жϡ�
���жϡ������������Ľ�ֹ���õȴ��¼��ӿڣ������������ɿص��쳣���ȡ�CNend
* @li TX event: The TX event API cannot be called in the interrupt off context to avoid uncontrollable
exceptional scheduling.CNcomment:�����¼�:�ڹ��ж������Ľ�ֹ���÷����¼��ӿڣ�
�����������ɿص��쳣���ȡ�CNend
* @li Each bit of bit[0:23] of an event can represent an event type. The meaning of each bit is allocated by the user.
CNcomment:һ���¼���[0:23]bit��ÿһbit���Ա�ʾһ���¼���ÿһλ���������û��Զ�����䡣CNend
* @li Bit[24:31] of an event are reserved and cannot be used by the user.
CNcomment:һ���¼���[24:31]bitϵͳ�������û�����ʹ�á�CNend
*
*/

/** @defgroup iot_event Event
 *  @ingroup osa
 */
#ifndef __HI_EVENT_H__
#define __HI_EVENT_H__
#include <hi_types_base.h>

#define HI_INVALID_EVENT_ID           0xffffffff   /**< Failed to obtain the event ID.CNcoment:��ȡ�¼�IDʧ��CNend  */
#define HI_EVENT_WAITMODE_AND         4            /**< If all expected events occur, the wait is successful.
                                                        It cannot be used with HI_EVENT_WAITMODE_OR at the same time.
                                                        CNcomment:����Ԥ�ڵȴ����¼�������ʱ�����϶��ȴ��ɹ���
                                                        ��������HI_EVENT_WAITMODE_ORͬʱʹ�� CNend */
#define HI_EVENT_WAITMODE_OR          2            /**< If any of the expected events occurs, the wait is successful.
                                                        It cannot be used with HI_EVENT_WAITMODE_AND at the same time.
                                                        CNcomment:����Ԥ�ڵȴ����¼���������һ�֣��϶��ȴ��ɹ���
                                                        ��������HI_EVENT_WAITMODE_ANDͬʱʹ�� CNend */
#define HI_EVENT_WAITMODE_CLR         1            /**< The waited event is cleared when the wait event is successful.
                                                        CNcomment:�ȴ��¼��ɹ�ʱ������ȴ������¼�CNend  */

/**
* @ingroup  iot_event
* @brief  Creates an event.CNcomment:�����¼���CNend
*
* @par ����:
*           Creates an event to obtain the event ID.CNcomment:�����¼�����ȡ�¼�ʹ��ID��CNend
*
* @attention
*           @li The read/write event interface cannot be invoked before system initialization.
CNcomment:��ϵͳ��ʼ��֮ǰ���ܵ��ö�д�¼��ӿڡ�CNend
*           @li In the interrupt, the event object can be written, but cannot be read.
CNcomment:���ж��У����Զ��¼��������д�����������ܶ�������CNend
*           @li In the lock task scheduling state, a write operation can be performed on an event object, but the
*               read operation cannot be performed.CNcomment:�����������״̬�£����Զ��¼��������д������
�����ܶ�������CNend
*
* @param  id       [OUT] type #hi_u32*��Event ID.
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_event.h��Describes event APIs.CNcomment:�ļ����������¼���ؽӿڡ�CNend
* @see  hi_event_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_event_create(HI_OUT hi_u32 *id);

/**
* @ingroup  iot_event
* @brief  Defines the TX event. CNcomment:�����¼���CNend
*
* @par ����:
*           Defines the TX event.CNcomment:�����¼���CNend
*
* @attention
*           @li The read/write event interface cannot be invoked before system initialization.
CNcomment:��ϵͳ��ʼ��֮ǰ���ܵ��ö�д�¼��ӿڡ�CNend
*           @li In the interrupt, the event object can be written, but cannot be read.
CNcomment:���ж��У����Զ��¼��������д�����������ܶ�������CNend
*           @li In the lock task scheduling state, a write operation can be performed on an event object, but the
*               read operation cannot be performed.CNcomment:�����������״̬�£����Զ��¼��������д������
�����ܶ�������CNend
*
* @param  id       [OUT]  type #hi_u32*��Event ID.
* @param  event_bits [IN] type #hi_u32��Set of events to be sent.CNcomment:�¼�bitλ��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_event.h��Describes event APIs.CNcomment:�ļ����������¼���ؽӿڡ�CNend
* @see  hi_event_wait��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_event_send(hi_u32 id, hi_u32 event_bits);

/**
* @ingroup  iot_event
* @brief  Defines the wait event.CNcomment:�ȴ��¼���CNend
*
* @par ����:
*          Defines the wait event.CNcomment:�ȴ��¼���CNend
*
* @attention
*           @li The read/write event interface cannot be invoked before system initialization.
CNcomment:��ϵͳ��ʼ��֮ǰ���ܵ��ö�д�¼��ӿڡ�CNend
*           @li In the interrupt, the event object can be written, but cannot be read.
CNcomment:���ж��У����Զ��¼��������д�����������ܶ�������CNend
*           @li In the lock task scheduling state, a write operation can be performed on an event object, but the
*               read operation cannot be performed.CNcomment:�����������״̬�£����Զ��¼��������д������
�����ܶ�������CNend
*
* @param  id       [OUT]  type #hi_u32*��Event ID.
* @param  mask       [IN] type #hi_u32��Set of events to be waited for, which may be one bit or multiple bits in
*                    bits 0-23.CNcomment:Ԥ�ȴ����¼����ϣ�����Ϊ0~23bit�е�1bit���bit��CNend
* @param  event_bits [IN] type #hi_u32��Set of events to be sent.CNcomment:�¼�bitλ��CNend
* @param  timeout    [IN] type #hi_u32��Waiting timeout period (unit: ms).
CNcomment:�ȴ���ʱʱ�䣨��λ��ms����CNend
* @param  flag       [IN] type #hi_u32��Waiting option. For details, see #HI_EVENT_WAITMODE_AND,
*                    #HI_EVENT_WAITMODE_OR, and #HI_EVENT_WAITMODE_CLR.
CNcomment:�ȴ�ѡ��,ȡֵ��#HI_EVENT_WAITMODE_AND��#HI_EVENT_WAITMODE_OR��#HI_EVENT_WAITMODE_CLR��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_event.h��Describes event APIs.CNcomment:�ļ����������¼���ؽӿڡ�CNend
* @see  hi_event_send��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_event_wait(hi_u32 id, hi_u32 mask, HI_OUT hi_u32 *event_bits, hi_u32 timeout, hi_u32 flag);

/**
* @ingroup  iot_event
* @brief  Defines the clearing event.CNcomment:����¼���CNend
*
* @par ����:
*           Defines the clearing event.CNcomment:����¼���CNend
*
* @attention
*           @li The read/write event interface cannot be invoked before system initialization.
CNcomment:��ϵͳ��ʼ��֮ǰ���ܵ��ö�д�¼��ӿڡ�CNend
*           @li In the interrupt, the event object can be written, but cannot be read.
CNcomment:���ж��У����Զ��¼��������д�����������ܶ�������CNend
*           @li In the lock task scheduling state, a write operation can be performed on an event object, but the
*               read operation cannot be performed.CNcomment:�����������״̬�£����Զ��¼��������д������
�����ܶ�������CNend
*
* @param  id       [OUT]  type #hi_u32*��Event ID.
* @param  event_bits [IN] type #hi_u32��Set of events to be cleared, which may be one bit or multiple bits in
*                    bits 0-23.CNcomment:������¼����ϣ�����Ϊ0~23bit�е�1bit���bit��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_event.h��Describes event APIs.CNcomment:�ļ����������¼���ؽӿڡ�CNend
* @see  hi_event_wait��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_event_clear(hi_u32 id, hi_u32 event_bits);

/**
* @ingroup  iot_event
* @brief  Deletion event.CNcomment:ɾ���¼���CNend
*
* @par ����:
*           Defines the deletion event, releasing an event ID.CNcomment:ɾ���¼����ͷ��¼�ʹ��id��CNend
*
* @attention
*           @li The read/write event interface cannot be invoked before system initialization.
CNcomment:��ϵͳ��ʼ��֮ǰ���ܵ��ö�д�¼��ӿڡ�CNend
*           @li In the interrupt, the event object can be written, but cannot be read.
CNcomment:���ж��У����Զ��¼��������д�����������ܶ�������CNend
*           @li In the lock task scheduling state, a write operation can be performed on an event object, but the
*               read operation cannot be performed.CNcomment:�����������״̬�£����Զ��¼��������д������
�����ܶ�������CNend
*
* @param  id       [OUT]  type #hi_u32*��Event ID.
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_event.h��Describes event APIs.CNcomment:�ļ����������¼���ؽӿڡ�CNend
* @see  hi_event_create��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_event_delete(hi_u32 id);

/**
* @ingroup  iot_event
* @brief  Initializes event resources.CNcomment:��ʼ���¼���Դ��CNend
*
* @par ����:
*           Initializes event resources. This API is called during system initialization only once.
CNcomment:��ʼ��event��Դ����ʼ���׶ε��á�CNend
*
* @attention Change the number of event resources based on the site requirements.
CNcomment:�û������ʵ��ʹ������޸�event��Դ����CNend
*
* @param  max_event_cnt   [IN] type #hi_u8��Number of event resources.CNcomment:event��Դ������CNend
* @param  event_space   [IN]   type #hi_pvoid��Event resource space. If the value is null,
* it indicates that the space is applied internally. If this parameter is not null,
* external space is used to create event resources. Currently, set this parameter to HI_NULL.
CNcomment:event��Դ�ռ䡣���ձ�ʾ�ռ����ڲ����룻�ǿձ�ʾʹ���ⲿ�ռ����ڴ���event��Դ��
��ǰ�봫HI_NULL��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_event.h��Describes event APIs.CNcomment:�ļ����������¼���ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_event_init(hi_u8 max_event_cnt, hi_pvoid event_space);

#endif

