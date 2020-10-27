/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: frw_event_sched.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "frw_event_sched.h"
#include "oam_ext_if.h"
#include "frw_event.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/*****************************************************************************
  3 ����ԭ������
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  5 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ���õ��ȶ����ϸ����¼����е�Ȩ�ؼ�����
 �������  : pst_sched_queue: ���ȶ���ָ��
*****************************************************************************/
hi_void frw_event_sched_reset_weight(frw_event_sched_queue_stru *sched_queue)
{
    hi_list                *list = HI_NULL;
    frw_event_queue_stru   *event_queue = HI_NULL;

    /* ���������������� */
    hi_list_for_each(list, &sched_queue->head) {
        /* ��ȡ���������е�һ���¼����� */
        event_queue = hi_list_entry(list, frw_event_queue_stru, list);
        /* ֻ�����ûָ�״̬VAP��Ȩ��ֵ */
        if (event_queue->vap_state == FRW_VAP_STATE_RESUME) {
            /* �����¼����е�Ȩ�ؼ����� */
            event_queue->weight_cnt = event_queue->weight;
            /* ���µ��ȶ����ϵ���Ȩ�ؼ����� */
            sched_queue->total_weight_cnt += event_queue->weight;
        }
    }
}

/*****************************************************************************
 ��������  : �¼�������ں���

 �޸���ʷ      :
  1.��    ��   : 2012��10��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void* frw_event_schedule(frw_event_sched_queue_stru *sched_queue)
{
    hi_void                     *event = HI_NULL;
    frw_event_sched_queue_stru   *queue = HI_NULL;

    /* ����ȫ�������� */
    queue = &sched_queue[FRW_SCHED_POLICY_HI];

    /* ��������ȼ����ȶ���Ϊ�գ���ȡ��һ�����ȶ��� */
    if (!hi_is_list_empty(&queue->head)) {
        /* �ӵ���������ѡ��һ����������¼� */
        event = frw_event_sched_pick_next_event_queue_wrr(queue);
        if (event != HI_NULL) {
            return event;
        }
    }

    queue = &sched_queue[FRW_SCHED_POLICY_NORMAL];

    /* �����ͨ���ȼ����ȶ���Ϊ�գ���ȡ��һ�����ȶ��� */
    if (!hi_is_list_empty(&queue->head)) {
        /* �ӵ���������ѡ��һ����������¼� */
        event = frw_event_sched_pick_next_event_queue_wrr(queue);
        if (event != HI_NULL) {
            return event;
        }
    }

    return HI_NULL;
}
/*****************************************************************************
 ��������  : �ӵ��ȶ���ɾ��һ���¼�����
 �������  : pst_sched_queue: ���ȶ���ָ��
             pst_event_queue: �¼�����ָ��

 �޸���ʷ      :
  1.��    ��   : 2015��3��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void frw_event_sched_deactivate_queue_no_lock(frw_event_sched_queue_stru  *sched_queue,
                                                 frw_event_queue_stru  *event_queue)
{
    if (event_queue->queue.element_cnt != 0) {
        return;
    }

    /* ���µ��ȶ����ϵ���Ȩ�ؼ����� */
    sched_queue->total_weight_cnt -= event_queue->weight_cnt;
    /* ���¼����е�Ȩ�ؼ��������� */
    event_queue->weight_cnt = 0;
    /* ���¼����дӵ���������ɾ�� */
    hi_list_delete(&event_queue->list);
    /* ���¼�������Ϊ����Ծ״̬ */
    event_queue->state = FRW_EVENT_QUEUE_STATE_INACTIVE;
}

/*****************************************************************************
 ��������  : ����ȶ������һ���µ��¼�����
 �������  : past_sched_queue: ���ȶ���ָ��
             pst_event_queue : �¼�����ָ��

 �޸���ʷ      :
  1.��    ��   : 2012��11��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

  2.��    ��   : 2015��4��23��
    ��    ��   : Hisilicon
    �޸�����   : ��װΪ�������ӿڣ����ֽӿڶԳ��ԣ��������ӿڵ���
*****************************************************************************/
hi_u32 frw_event_sched_activate_queue_no_lock(frw_event_sched_queue_stru   *sched_queue,
                                              frw_event_queue_stru         *event_queue)
{
    /* ����¼������Ѿ��ڿ�ִ�ж�����(���ڼ���״̬)����ֱ�ӷ��سɹ� */
    if (event_queue->state == FRW_EVENT_QUEUE_STATE_ACTIVE) {
        return HI_SUCCESS;
    }

    /* ��Ϊ�¼����е�Ȩ�ؼ����� */
    event_queue->weight_cnt = event_queue->weight;
    /* ���µ��ȶ����ϵ���Ȩ�ؼ����� */
    sched_queue->total_weight_cnt += event_queue->weight_cnt;

    /* ���¼����м�����������ĩβ */
    hi_list_tail_insert(&event_queue->list, &sched_queue->head);

    /* ���¼�������Ϊ����״̬ */
    event_queue->state = FRW_EVENT_QUEUE_STATE_ACTIVE;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��������ʼ��
 �������  : pst_sched_queue: ���ȶ���ָ��

 �޸���ʷ      :
  1.��    ��   : 2012��11��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 frw_event_sched_init(frw_event_sched_queue_stru *sched_queue)
{
    /* ��ʼ���� */
    /* ��ʼ�����ȶ�����Ȩ�ؼ����� */
    sched_queue->total_weight_cnt = 0;

    /* ��ʼ����������ͷ */
    hi_list_init(&sched_queue->head);
    oal_spin_lock_init(&sched_queue->st_lock);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����¼����в���
 �������  : pst_prio_queue: �¼�����ָ��
             us_weight     : ����Ȩ��
             en_policy     : ���е��Ȳ���
             en_state      : �¼�����״̬
*****************************************************************************/
hi_void frw_event_queue_set(frw_event_queue_stru *event_queue, hi_u8 weight,
                            frw_sched_policy_enum_uint8 policy, frw_event_queue_state_enum_uint8 state)
{
    event_queue->weight     = weight;
    event_queue->weight_cnt = 0;
    event_queue->policy     = policy;
    event_queue->state      = state;
    event_queue->vap_state  = FRW_VAP_STATE_RESUME;
}

/*****************************************************************************
 ��������  : ���г�ʼ��, uc_max_events������2����������
 �������  : pst_queue      : ����ָ��
             uc_max_events: ���Ԫ�ظ���
*****************************************************************************/
hi_u32 oal_queue_init(oal_queue_stru *queue, hi_u8 max_events)
{
    hi_u32 *pul_buf = HI_NULL;

    if (max_events == 0) {
        return HI_SUCCESS;
    } else {
        if (oal_unlikely(oal_is_not_pow_of_2(max_events))) {
            return HI_ERR_CODE_CONFIG_UNSUPPORT;
        }

        pul_buf = (hi_u32 *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, (hi_u16)(max_events * sizeof(hi_u32)));
        if (oal_unlikely(pul_buf == HI_NULL)) {
            return HI_ERR_CODE_ALLOC_MEM_FAIL;
        }
        /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
        memset_s(pul_buf, max_events * sizeof(hi_u32), 0, max_events * sizeof(hi_u32));
        oal_queue_set(queue, pul_buf, max_events);

        return HI_SUCCESS;
    }
}

/*****************************************************************************
 ��������  : �¼����г�ʼ��
 �������  : pst_event_queue: �¼�����ָ��
             us_weight      : ����Ȩ��
             en_policy      : ���е��Ȳ���
             en_state       : �¼�����״̬
             us_max_events  : ����¼�����

 �޸���ʷ      :
  1.��    ��   : 2012��10��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 frw_event_queue_init(frw_event_queue_stru *event_queue, hi_u8 weight,
                            frw_sched_policy_enum_uint8 policy,
                            frw_event_queue_state_enum_uint8 state, hi_u8 max_events)
{
    hi_u32 ret;

    /* ��ʼ���� */
    oal_spin_lock_init(&event_queue->st_lock);
    ret = oal_queue_init(&event_queue->queue, max_events);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_FRW, "{frw_event_queue_init:: OAL_QUEUE_INIT return != HI_SUCCESS! %d}", ret);
        frw_event_queue_set(event_queue, 0, FRW_SCHED_POLICY_BUTT, FRW_EVENT_QUEUE_STATE_INACTIVE);

        return ret;
    }

    frw_event_queue_set(event_queue, weight, policy, state);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����¼�����
 �������  : pst_event_queue: �¼�����ָ��

 �޸���ʷ      :
  1.��    ��   : 2012��10��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void frw_event_queue_destroy(frw_event_queue_stru *event_queue)
{
    oal_queue_destroy(&event_queue->queue);

    frw_event_queue_set(event_queue, 0, FRW_SCHED_POLICY_BUTT, FRW_EVENT_QUEUE_STATE_INACTIVE);
}

/*****************************************************************************
 ��������  : �ӵ���������ѡ��һ����������¼�

 �޸���ʷ      :
  1.��    ��   : 2012��10��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void* frw_event_sched_pick_next_event_queue_wrr(frw_event_sched_queue_stru *sched_queue)
{
    hi_list                   *list = HI_NULL;
    frw_event_queue_stru      *event_queue = HI_NULL;
    hi_void                   *event = HI_NULL;
    unsigned long             flag;

    oal_spin_lock_irq_save(&sched_queue->st_lock, &flag);

    /* ���������������� */
    hi_list_for_each(list, &sched_queue->head) {
        event_queue = hi_list_entry(list, frw_event_queue_stru, list);
        /* ����¼����е�vap_stateΪ��ͣ����������������ѡ��һ���¼����� */
        if (event_queue->vap_state == FRW_VAP_STATE_PAUSE) {
            continue;
        }

        /* ����¼����е�Ȩ�ؼ�����Ϊ0������ѡ��һ���¼����� */
        if (event_queue->weight_cnt == 0) {
            continue;
        }

        /* �����¼�����Ȩ�ؼ����� */
        event_queue->weight_cnt--;
        /* ���µ��ȶ��е���Ȩ�ؼ����� */
        sched_queue->total_weight_cnt--;
        /* ���¼�������ȡ��һ���¼� */
        event = frw_event_queue_dequeue(event_queue);

        /* ����¼����б�գ���Ҫ����ӵ��ȶ�����ɾ���������¼�����״̬��Ϊ����Ծ(���ɱ�����) */
        frw_event_sched_deactivate_queue_no_lock(sched_queue, event_queue);
        /* } */
        break;
    }

    /* ������ȶ��е���Ȩ�ؼ�����Ϊ0������Ҫ���õ��ȶ����ϸ����¼����е�Ȩ�ؼ����� */
    if (sched_queue->total_weight_cnt == 0) {
        frw_event_sched_reset_weight(sched_queue);
    }

    oal_spin_unlock_irq_restore(&sched_queue->st_lock, &flag);
    return event;
}

/*****************************************************************************
 ��������  : �ӵ��ȶ���ɾ��һ���¼�����
 �������  : pst_sched_queue: ���ȶ���ָ��
             pst_event_queue: �¼�����ָ��

 �޸���ʷ      :
  1.��    ��   : 2012��11��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void frw_event_sched_deactivate_queue(frw_event_sched_queue_stru   *sched_queue,
                                         frw_event_queue_stru         *event_queue)
{
    unsigned long flag;

    /* ���жϣ����� */
    oal_spin_lock_irq_save(&sched_queue->st_lock, &flag);

    frw_event_sched_deactivate_queue_no_lock(sched_queue, event_queue);

    /* ���������ж� */
    oal_spin_unlock_irq_restore(&sched_queue->st_lock, &flag);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

