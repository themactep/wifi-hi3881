/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for frw_event_sched.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __FRW_EVENT_SCHED_H__
#define __FRW_EVENT_SCHED_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* ��ȡ�¼��������Ѿ�������¼����� */
#define frw_event_queue_get_pending_events_num(_pst_event_queue)  oal_queue_get_length(&(_pst_event_queue)->queue)

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  ö����  : frw_sched_policy_enum_uint8
  Э����:
  ö��˵��: �¼����ж�Ӧ�ĵ��Ȳ���
*****************************************************************************/
typedef enum {
    FRW_SCHED_POLICY_HI     = 0,   /* �����ȼ����� */
    FRW_SCHED_POLICY_NORMAL = 1,   /* ��ͨ���ȼ����� */
    FRW_SCHED_HCC_ASSEM     = 2,   /* �����¼�������HCC�ۺ� */

    FRW_SCHED_POLICY_BUTT
}frw_sched_policy_enum;
typedef hi_u8 frw_sched_policy_enum_uint8;

/*****************************************************************************
  ö����  : frw_event_queue_state_enum_uint8
  Э����:
  ö��˵��: �¼�����״̬
*****************************************************************************/
typedef enum {
    FRW_EVENT_QUEUE_STATE_INACTIVE = 0,   /* �¼����в���Ծ(���ɱ�����) */
    FRW_EVENT_QUEUE_STATE_ACTIVE,         /* �¼����л�Ծ(�ɱ�����) */

    FRW_EVENT_QUEUE_STATE_BUTT
}frw_event_queue_state_enum;
typedef hi_u8 frw_event_queue_state_enum_uint8;

/*****************************************************************************
  ö����  : frw_vap_state_enum_uint8
  Э����:
  ö��˵��: �¼���������
*****************************************************************************/
typedef enum {
    FRW_VAP_STATE_RESUME  = 0,    /* VAP�ָ� */
    FRW_VAP_STATE_PAUSE,          /* VAP��ͣ */

    FRW_VAP_STATE_BUTT
}frw_vap_state_enum;
typedef hi_u8 frw_vap_state_enum_uint8;

/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
/*****************************************************************************
  �ṹ��  : frw_event_sched_queue_stru
  �ṹ˵��: �ɵ��ȶ���
*****************************************************************************/
typedef struct {
    oal_spin_lock_stru                   st_lock;
    hi_u32         total_weight_cnt;    /* �ɵ��ȶ����ϵ���Ȩ�ؼ����� */
    hi_list        head;                /* �ɵ��ȶ��е��¼�����ͷ */
}frw_event_sched_queue_stru;

/*****************************************************************************
  �ṹ��  : frw_event_queue_stru
  �ṹ˵��: �¼����нṹ��
*****************************************************************************/
typedef struct tag_frw_event_queue_stru {
    oal_spin_lock_stru               st_lock;
    oal_queue_stru                   queue;       /* ���� */
    frw_event_queue_state_enum_uint8 state;       /* ����״̬ */
    frw_sched_policy_enum_uint8      policy;      /* ���е��Ȳ���(�����ȼ�����ͨ���ȼ�) */

    hi_u8                            weight;      /* WRRȨ������ֵ */
    hi_u8                            weight_cnt;  /* WRRȨ�ؼ����� */

    frw_vap_state_enum_uint8         vap_state;   /* VAP��״ֵ̬��0Ϊ�ָ���1Ϊ��ͣ */
    hi_u8                            auc_resv[3]; /* 3:���������С */
    hi_list                          list;
}frw_event_queue_stru;

/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32 frw_event_sched_init(frw_event_sched_queue_stru *sched_queue);
hi_u32 frw_event_queue_init(frw_event_queue_stru *event_queue, hi_u8 weight, frw_sched_policy_enum_uint8 policy,
    frw_event_queue_state_enum_uint8 state, hi_u8 max_events);
hi_void frw_event_queue_destroy(frw_event_queue_stru *event_queue);
hi_void* frw_event_sched_pick_next_event_queue_wrr(frw_event_sched_queue_stru *sched_queue);
hi_void frw_event_sched_deactivate_queue(frw_event_sched_queue_stru *sched_queue,
                                         frw_event_queue_stru *event_queue);
hi_u32 frw_event_sched_activate_queue_no_lock(frw_event_sched_queue_stru *sched_queue,
                                              frw_event_queue_stru *event_queue);
hi_void* frw_event_schedule(frw_event_sched_queue_stru *sched_queue);

/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of frw_event_sched.h */
