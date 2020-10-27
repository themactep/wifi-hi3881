/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: task APIs.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/**
 * @defgroup iot_task Tasko
 * @ingroup osa
 */
#ifndef __HI_TASK_H__
#define __HI_TASK_H__

#include <hi_types_base.h>

#define HI_INVALID_TASK_ID   0xFFFFFFFF
#define HI_TASK_NAME_LEN     32
#define HI_DEFAULT_TSKNAME   "default"  /**< hi_task_attr default value. CNcomment:hi_task_attr��Ĭ��ֵCNend */
#define HI_DEFAULT_TSKPRIO   20         /**< hi_task_attr default value. CNcomment:hi_task_attr��Ĭ��ֵCNend */
#define HI_DEFAULT_STACKSIZE (4 * 1024) /**< hi_task_attr default value. CNcomment:hi_task_attr��Ĭ��ֵCNend */
#define NOT_BIND_CPU         (-1)

typedef struct {
    hi_char name[HI_TASK_NAME_LEN]; /**< Task entrance function.CNcomment:��ں���CNend */
    hi_u32 id;                      /**< Task ID.CNcomment:����ID CNend */
    hi_u16 status;                  /**< Task status.CNcomment:����״̬ CNend */
    hi_u16 priority;                /**< Task priority.CNcomment:�������ȼ� CNend */
    hi_pvoid task_sem;              /**< Semaphore pointer.CNcomment:�ź���ָ��CNend */
    hi_pvoid task_mutex;            /**< Mutex pointer.CNcomment:������ָ��CNend */
    hi_u32 event_stru[3];           /**< Event: 3 nums.CNcomment:3���¼�CNend */
    hi_u32 event_mask;              /**< Event mask.CNcomment:�¼�����CNend */
    hi_u32 stack_size;              /**< Task stack size.CNcomment:ջ��СCNend */
    hi_u32 top_of_stack;            /**< Task stack top.CNcomment:ջ��CNend */
    hi_u32 bottom_of_stack;         /**< Task stack bottom.CNcomment:ջ��CNend */
    hi_u32 mstatus;                 /**< Task current mstatus.CNcomment:��ǰmstatusCNend */
    hi_u32 mepc;                    /**< Task current mepc.CNcomment:��ǰmepc.CNend */
    hi_u32 tp;                      /**< Task current tp.CNcomment:��ǰtp.CNend */
    hi_u32 ra;                      /**< Task current ra.CNcomment:��ǰra.CNend */
    hi_u32 sp;                      /**< Task SP pointer.CNcomment:��ǰSP.CNend */
    hi_u32 curr_used;               /**< Current task stack usage.CNcomment:��ǰ����ջʹ����CNend */
    hi_u32 peak_used;               /**< Task stack usage peak.CNcomment:ջʹ�÷�ֵCNend */
    hi_u32 overflow_flag;           /**< Flag that indicates whether a task stack overflow occurs.
                                       CNcomment:ջ������λCNend */
} hi_task_info;

typedef struct {
    hi_u16 task_prio;
    hi_u32 stack_size;
    hi_u32 task_policy;
    hi_u32 task_nice;
    hi_u32 task_cpuid;
    hi_char *task_name;
    hi_void *resved;
} hi_task_attr;

/**
* @ingroup  iot_task
* @brief  Creates a task.CNcomment:��������CNend
*
* @par ����:
*           Creates a task.CNcomment:��������CNend
*
* @attention
*           @li The space occupied by a task name string must be applied for by the caller and saved statically.
*               The task name is not stored internally in the API.CNcomment:�������ַ���ռ�ÿռ���Ҫ������
                ���벢��̬���棬�ӿ��ڲ��������������д洢��CNend
*           @li If the size of the specified task stack is 0, use the default size specified by
*               #OS_TSK_DEFAULT_STACK_SIZE. CNcomment:��ָ��������ջ��СΪ0����ʹ��������
                HI_DEFAULT_STACKSIZEָ��Ĭ�ϵ�����ջ��С��CNend
*           @li The size of the task stack should be 8-byte aligned. The principle for determining the task stack
*               size is as follows: Do not use a too large or too small task stack size (to avoid waste or
*               overflow).CNcomment:����ջ�Ĵ�С��8byte��С���롣ȷ������ջ��С��ԭ�򣺹��ü��ɣ������˷ѣ�
                ��������ջ�������CNend
*           @li The recommended user priority should be within the range of [20, 30]. Do not use the priorities of
*               [0, 2] and [31].CNcomment:�û����ȼ����ý���ʹ��[20,30]���мǲ���ʹ��[0,2]��[31]�ŵ����ȼ���CNend
*
* @param  taskid         [OUT] type #hi_u32*��task ID.CNcomment:����ID�š�CNend
* @param  attr           [IN]  type #const task_attr_t*��task attributes,when NULL was set here,the properties
                               are configured as follows: task_name:"default" task_prio:20  stack_size:(4*1024)
                               CNcomment:��������,����ֵΪ��ʱ��������:������:"default"
                               �������ȼ�:20 ����ջ��С:(4*1024),CNend
* @param  task_route     [IN]  type #task_route task entry function.CNcomment:������ں�����CNend
* @param  arg            [IN]  type #hi_void*��parameter that needs to be input to the task entry when a task is
*                              created. If this parameter does not need to be input, set this parameter to 0.
                               CNcomment:��������ʱ��Ҫ����������ڵĲ������������Ҫ���ݣ�����ֱ����0��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  hi_task_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_create(hi_u32 *taskid, const hi_task_attr *attr,
                      hi_void* (*task_route)(hi_void *), hi_void *arg);

/**
* @ingroup  iot_task
* @brief  Deletes a task.CNcomment:ɾ������CNend
*
* @par ����:
*          Deletes a task.CNcomment:ɾ������CNend
*
* @attention
*           @li Use this API with caution. A task can be deleted only after the confirmation of the user. The idle task
*           and Swt_Task cannot be deleted.idle.CNcomment:����Swt_Task�����ܱ�ɾ����CNend
*           @li When deleting a task, ensure that the resources (such as mutex and semaphore) applied by the task have
*           been released.��ɾ������ʱҪ��֤�����������Դ���绥�������ź����ȣ��ѱ��ͷš�CNend
*
* @param  taskid      [IN] type #hi_u32��task ID. CNcomment:����ID�š�CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  hi_task_create��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_delete(hi_u32 taskid);

/**
* @ingroup  iot_task
* @brief  Suspends a task.CNcomment:��������CNend
*
* @par ����:
*           Suspends a task.CNcomment:����ָ������CNend
*
* @attention
*          @li A task cannot be suspended if it is the current task and is locked.
CNcomment:���������ʱ����Ϊ��ǰ�����������������ܱ�����CNend
*          @li The idle task and Swt_Task cannot be suspended.
CNcomment:idle����Swt_Task�����ܱ�����CNend
*          @li The task cannot be blocked or suspended in the lock task status.
CNcomment:�����������״̬�£���ֹ����������CNend
*
* @param  taskid      [IN] type #hi_u32��task ID. CNcomment:����ID�š�CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  hi_task_resume��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_suspend(hi_u32 taskid);

/**
* @ingroup  iot_task
* @brief  Resumes a task.CNcomment:�ָ���������CNend
*
* @par ����:
*           Resumes a task.CNcomment:�ָ�����ָ������CNend
*
* @attention None
* @param  taskid      [IN] ���� #hi_u32������ID�š�
*
* @param  taskid      [IN] type #hi_u32��task ID. CNcomment:����ID�š�CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  hi_task_suspend��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_resume(hi_u32 taskid);

/**
* @ingroup  iot_task
* @brief  Obtains the task priority.CNcomment:��ȡ�������ȼ���CNend
*
* @par ����:
*           Obtains the task priority.CNcomment:��ȡ�������ȼ���CNend
*
* @attention None
*
* @param  taskid      [IN] type #hi_u32��task ID. CNcomment:����ID�š�CNend
* @param  priority   [OUT] type #hi_u32*��task priority.CNcomment:�������ȼ���CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  hi_task_set_priority��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_get_priority(hi_u32 taskid, hi_u32 *priority);

/**
* @ingroup  iot_task
* @brief  Sets the task priority.CNcomment:�����������ȼ���CNend
*
* @par ����:
            Sets the task priority.CNcomment:�����������ȼ���CNend
*
* @attention
*           @li Only the ID of the task created by the user can be configured.
CNcomment:���������û��Լ�����������ID��CNend
*           @li The recommended user priority should be within the range of [20, 30]. Do not use the priorities of
*            [0, 2] and [31].CNcomment:�û����ȼ����ý���ʹ��[20,30]���мǲ���ʹ��[0,2]��[31]�ŵ����ȼ���CNend
*           @li Setting user priorities may affect task scheduling. The user needs to plan tasks in the SDK.
CNcomment:�����û����ȼ��п���Ӱ��������ȣ��û���ҪSDK�жԸ�����ͳһ�滮��CNend
*
* @param  taskid      [IN] type #hi_u32��task ID. CNcomment:����ID�š�CNend
* @param  priority   [OUT] type #hi_u32*��task priority.CNcomment:�������ȼ���CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  hi_task_get_priority��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_set_priority(hi_u32 taskid, hi_u32 priority);

/**
* @ingroup  iot_task
* @brief  Obtains the task information.CNcomment:��ȡ������Ϣ��CNend
*
* @par ����:
*           Obtains the task information.CNcomment:��ȡ������Ϣ��CNend
*
* @attention None
* @param  taskid      [IN] type #hi_u32��task ID. CNcomment:����ID�š�CNend
* @param  inf        [OUT] type #hi_task_info* ��task information.CNcomment:������Ϣ��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_get_info(hi_u32 taskid, hi_task_info *inf);

/**
* @ingroup  iot_task
* @brief  Obtains the current task ID.CNcomment:��ȡ��ǰ����ID��CNend
*
* @par ����:
*         Obtains the current task ID.CNcomment:��ȡ��ǰ����ID��CNend
*
* @attention None
* @param  None
*
* @retval #hi_u32  Task ID. If the task fails, #HI_INVALID_TASK_ID is returned.
CNcomment:����ID��ʧ�ܷ���#HI_INVALID_TASK_ID��CNend
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_task_get_current_id(hi_void);

/**
* @ingroup  iot_task
* @brief  Lock task switch.CNcomment:��ֹϵͳ������ȡ�CNend
*
* @par ����:
*         Lock task switch.CNcomment:��ֹϵͳ������ȡ�CNend
*
* @attention  Work pair with hi_task_unlock.CNcomment:��hi_task_unlock���ʹ�á�CNend
* @param  None
*
* @retval None
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_task_lock(hi_void);

/**
* @ingroup  iot_task
* @brief  Unlock task switch. CNcomment:����ϵͳ������ȡ�CNend
*
* @par ����:
*         Unlock task switch. CNcomment:����ϵͳ������ȡ�CNend
*
* @attention  Work pair with hi_task_lock; Call hi_task_lock to disable task switch, then call hi_task_unlock
*             reenable it.
CNcomment:��hi_task_lock���ʹ�ã��ȵ���hi_task_lock��ֹ������ȣ�Ȼ�����hi_task_unlock��������ȡ�CNend
* @param  None
*
* @retval  None
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_task_unlock(hi_void);

/**
* @ingroup  iot_task
* @brief Task sleep.CNcomment:����˯�ߡ�CNend
*
* @par ����:
*          Task sleep.CNcomment:����˯�ߡ�CNend
*
* @attention
*           @li In the interrupt processing function or in the case of a lock task, the hi_sleep operation fails.
CNcomment:���жϴ������л����������������£�ִ��hi_sleep������ʧ�ܡ�CNend
*           @li When less than 10 ms, the input parameter value should be replaced by 10 ms. When greater than 10 ms,
*            the input parameter value should be exactly divided and then rounded-down to the nearest integer.
CNcomment:���С��10msʱ������10ms����Tick=1������10msʱ���������¶��룬Tick = ms/10��CNend
*           @li This function cannot be used for precise timing and will be woken up after Tick system scheduling.
*            The actual sleep time is related to the time consumed by the Tick when the function is called.
CNcomment:�������������ھ�ȷ��ʱ������Tick��ϵͳ���Ⱥ��ѣ�ʵ��˯��ʱ���뺯��������ʱ��Tick�����ĵ�ʱ����ء�CNend
* @param  ms      [IN] type #hi_u32��sleep time (unit: ms). The precision is 10 ms.
CNcomment:˯��ʱ�䣨��λ��ms��������Ϊ10ms��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_task.h��Describes the task APIs.CNcomment:�ļ���������������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sleep(hi_u32 ms);

#endif

