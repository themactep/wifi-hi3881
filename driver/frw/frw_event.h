/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for frw_event_main.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __FRW_EVENT_MAIN_H__
#define __FRW_EVENT_MAIN_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "frw_event_sched.h"
#include "oal_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define HI_EVENT_DEVICE_READY             BIT0
#define HI_EVENT_OPEN_BCPU_DONE           BIT1
#define HI_EVENT_CLOSE_BCPU_DONE          BIT2
#define HI_EVENT_HALT_BCPU_DONE           BIT3
#define HI_EVENT_WAKEUP_DONE              BIT4
#define HI_EVENT_SLEEP_REQUEST_ACK        BIT5
#define HI_EVENT_SLEEP_REQUEST_DONE       BIT6
#define HI_EVENT_SLEEPWORK_DONE           BIT7
#define HI_EVENT_RESUME_DONE              BIT8
#define HI_EVENT_SDIO_DRIVE_READY         BIT9
#define HI_EVENT_D2H_READY_EVENT          BIT10
#define HI_EVENT_WOW_ENABLE_READY         BIT11
#define HI_EVENT_CLOSE_DONE               BIT12
#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_HMAC)
#define HI_EVENT_FRW_TASK                 BIT13
#endif

#ifdef _PRE_OAL_FEATURE_TASK_NEST_LOCK
extern oal_task_lock_stru  g_frw_event_task_lock;
#define frw_event_task_lock()     do { oal_smp_task_lock(&g_frw_event_task_lock); } while (0)
#define frw_event_task_unlock()   do { oal_smp_task_unlock(&g_frw_event_task_lock); } while (0)
#else
#define frw_event_task_lock()     do {} while (0)
#define frw_event_task_unlock()   do {} while (0)
#endif
/*****************************************************************************
  2 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  ö����  : frw_event_deploy_enum_uint8
  Э����:
  ö��˵��: �¼���������
*****************************************************************************/
typedef enum {
    FRW_EVENT_DEPLOY_NON_IPC  = 0,    /* �Ǻ˼�ͨ�� */
    FRW_EVENT_DEPLOY_IPC,             /* �˼�ͨѶ */

    FRW_EVENT_DEPLOY_BUTT
} frw_event_deploy_enum;
typedef hi_u8 frw_event_deploy_enum_uint8;

typedef enum {
    FRW_TIMEOUT_TIMER_EVENT,      /* ��FRW_TIMER_DEFAULT_TIMEΪ���ڵĶ�ʱ���¼������� */

    FRW_TIMEOUT_SUB_TYPE_BUTT
} hmac_timeout_event_sub_type_enum;
typedef hi_u8 hmac_timeout_event_sub_type_enum_uint8;

/*****************************************************************************
  ö����  : frw_event_type_enum_uint8
  Э����:
  ö��˵��: �¼�����
*****************************************************************************/
typedef enum {
    FRW_EVENT_TYPE_HIGH_PRIO = 0,         /* �����ȼ��¼����� */
    FRW_EVENT_TYPE_HOST_CRX,              /* ����Host�෢���������¼� */
    FRW_EVENT_TYPE_HOST_DRX,              /* ����Host�෢���������¼� */
    FRW_EVENT_TYPE_HOST_CTX,              /* ����HOST��������¼� */
    FRW_EVENT_TYPE_DMAC_TO_HMAC_CFG  = 4, /* DMAC����HMAC�������¼� */
    FRW_EVENT_TYPE_WLAN_CRX,             /* ����Wlan�෢���Ĺ���/����֡�¼� */
    FRW_EVENT_TYPE_WLAN_DRX,             /* ����Wlan�෢��������֡�¼� */
    FRW_EVENT_TYPE_WLAN_CTX,             /* ����/����֡������Wlan���¼� */
    FRW_EVENT_TYPE_WLAN_DTX,             /* ����֡������Wlan���¼� */
    FRW_EVENT_TYPE_WLAN_TX_COMP  = 9,    /* ��������¼� */
    FRW_EVENT_TYPE_TBTT,                 /* TBTT�ж��¼� */
    FRW_EVENT_TYPE_TIMEOUT,              /* FRW��ͨ��ʱ�¼� */
    FRW_EVENT_TYPE_DMAC_MISC     = 12,   /* DMAC��ɢ�¼� */
    FRW_EVENT_TYPE_HCC           = 13,    /* HCC �¼� */
    /* ����µ��¼����� */
    FRW_EVENT_TYPE_BUTT
} frw_event_type_enum;
typedef hi_u8 frw_event_type_enum_uint8;

typedef enum {
    OAM_DUMP_TYPE = 4,
    OAM_BACK_TRACE_TYPE,
    OAM_LOG_TYPE,
    OAM_PM_TYPE,
    OAM_HEATBAET_TYPE,
    OAM_SET_SOFT_RST,
}oam_even_type;

/*****************************************************************************
  ö����  : frw_event_type_enum_uint8
  Э����:
  ö��˵��: �¼��ֶκţ�ȡֵ[0, 1]
*****************************************************************************/
typedef enum {
    FRW_EVENT_PIPELINE_STAGE_0 = 0,
    FRW_EVENT_PIPELINE_STAGE_1,

    FRW_EVENT_PIPELINE_STAGE_BUTT
} frw_event_pipeline_enum;
typedef hi_u8 frw_event_pipeline_enum_uint8;

typedef oal_mem_stru    frw_event_mem_stru;    /* �¼��ṹ���ڴ��ת���� */

/*****************************************************************************
  3 �궨��
*****************************************************************************/
/* �¼���������� */
/* һ�����͵��¼���Ӧ������������¼���Ĵ�СΪ�¼����͵�2�� */
#define FRW_EVENT_TABLE_MAX_ITEMS    (FRW_EVENT_TYPE_BUTT * 2)

/* �¼�ͷ���� */
#define FRW_EVENT_HDR_LEN            sizeof(frw_event_hdr_stru)
#define FRW_RX_EVENT_TRACK_NUM       256
#define FRW_EVENT_TRACK_NUM          128

#define frw_field_setup(_p, _m, _v)    ((_p)->_m = (_v))

/* �¼�ͷ�޸ĺ�(�޸��¼�ͷ�е�pipeline��subtype) */
#define frw_event_hdr_modify_pipeline_and_subtype(_pst_event_hdr, _uc_sub_type) \
    do {                                                                        \
        frw_field_setup((_pst_event_hdr), pipeline, 1);                      \
        frw_field_setup((_pst_event_hdr), sub_type, (_uc_sub_type));         \
    } while (0)

/* �¼�ͷ��ʼ���� */
#define frw_event_hdr_init(_pst_event_hdr, _en_type, _uc_sub_type, _us_length, _en_pipeline, _uc_vap_id) \
    do {\
        frw_field_setup((_pst_event_hdr), us_length, ((_us_length) + FRW_EVENT_HDR_LEN));\
        frw_field_setup((_pst_event_hdr), type, (_en_type));\
        frw_field_setup((_pst_event_hdr), sub_type, (_uc_sub_type));\
        frw_field_setup((_pst_event_hdr), pipeline, (_en_pipeline));\
        frw_field_setup((_pst_event_hdr), vap_id, (_uc_vap_id));\
    } while (0)

#define frw_get_event_stru(event_mem)   ((frw_event_stru *)(event_mem)->puc_data)
#define frw_get_event_hdr(event_mem) ((frw_event_hdr_stru*)(&((frw_event_stru *)(event_mem)->puc_data)->event_hdr))
#define frw_get_event_payload(event_mem)   ((hi_u8*)((frw_event_stru *)(event_mem)->puc_data)->auc_event_data)

/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
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
  �ṹ��  : frw_event_hdr_stru
  �ṹ˵��: �¼�ͷ�ṹ��,
  ��ע    : uc_length��ֵΪ(payload���� + �¼�ͷ���� - 2)
*****************************************************************************/
typedef struct {
    frw_event_type_enum_uint8     type    : 4;    /* �¼����� */
    hi_u8                         vap_id  : 4;    /* VAP ID */
    hi_u8                         sub_type: 6;    /* �¼������� */
    frw_event_pipeline_enum_uint8 pipeline: 2;    /* �¼��ֶκ� */
    hi_u16                        us_length;      /* �¼����峤�� */
} frw_event_hdr_stru;

/*****************************************************************************
  �ṹ��  : frw_event_stru
  �ṹ˵��: �¼��ṹ��
*****************************************************************************/
typedef struct {
    frw_event_hdr_stru    event_hdr;           /* �¼�ͷ */
    hi_u8                auc_event_data[];       /* 4:�¼����������С */
} frw_event_stru;

/*****************************************************************************
  �ṹ��  : frw_event_sub_table_item_stru
  �ṹ˵��: �¼��ӱ�ṹ��
*****************************************************************************/
typedef struct {
    hi_u32 (*func)(frw_event_mem_stru *);        /* (type, subtype, pipeline)���͵��¼���Ӧ�Ĵ����� */
    hi_u32 (*p_tx_adapt_func)(frw_event_mem_stru *);
    frw_event_mem_stru *(*p_rx_adapt_func)(frw_event_mem_stru *);
} frw_event_sub_table_item_stru;

/*****************************************************************************
  �ṹ��  : frw_event_table_item_stru
  �ṹ˵��: �¼���ṹ��
*****************************************************************************/
typedef struct {
    const frw_event_sub_table_item_stru *sub_table;    /* ָ���ӱ��ָ�� */
} frw_event_table_item_stru;

typedef struct {
    hi_u32      event_cnt;
    hi_u32      aul_event_time[FRW_EVENT_TRACK_NUM];
    hi_u16      us_event_type[FRW_EVENT_TRACK_NUM];
    hi_u16      us_event_sub_type[FRW_EVENT_TRACK_NUM];
} frw_event_track_time_stru;

/*****************************************************************************
  �ṹ��  : frw_event_cfg_stru
  �ṹ˵��: �¼�����������Ϣ�ṹ��
*****************************************************************************/
typedef struct {
    hi_u8                       weight;        /* ����Ȩ�� */
    hi_u8                       max_events;    /* �����������ɵ�����¼����� */
    frw_sched_policy_enum_uint8 policy;        /* �����������Ȳ���(�����ȼ�����ͨ���ȼ�) */
    hi_u8                       auc_resv;
} frw_event_cfg_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32 frw_event_init(hi_void);
hi_void frw_event_exit(hi_void);
hi_u32 frw_event_queue_enqueue(frw_event_queue_stru *event_queue, frw_event_mem_stru *event_mem);
frw_event_mem_stru* frw_event_queue_dequeue(frw_event_queue_stru *event_queue);
hi_u32 frw_event_vap_flush_event(hi_u8 vap_id, frw_event_type_enum_uint8 event_type, hi_u8 drop);
hi_u32 frw_event_lookup_process_entry(frw_event_mem_stru *event_mem, const frw_event_hdr_stru *event_hrd);
frw_event_mem_stru* frw_event_alloc(hi_u16 us_payload_length);
hi_u32 frw_event_free(frw_event_mem_stru *event_mem);
hi_u32 frw_event_dispatch_event(frw_event_mem_stru *event_mem);
hi_u32 frw_event_post_event(frw_event_mem_stru *event_mem);
hi_void frw_event_table_register(frw_event_type_enum_uint8 type, frw_event_pipeline_enum_uint8 pipeline,
                                 const frw_event_sub_table_item_stru *sub_table);
hi_u32 frw_event_flush_event_queue(frw_event_type_enum_uint8 event_type);
hi_void frw_event_process_all_event(hi_void);
hi_u8 frw_is_vap_event_queue_empty(hi_u8 vap_id, hi_u8 event_type);
const frw_event_sub_table_item_stru* frw_get_event_sub_table(hi_u8 type, hi_u8 pipeline);
hi_u8 frw_task_thread_condition_check(hi_void);
#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
hi_void hcc_host_update_vi_flowctl_param(hi_u32 be_cwmin, hi_u32 vi_cwmin);
#endif
hi_u32 get_app_event_id(hi_void);
hi_void frw_event_sub_rx_adapt_table_init(frw_event_sub_table_item_stru *pst_sub_table, hi_u32 ul_table_nums,
    frw_event_mem_stru* (*p_rx_adapt_func)(frw_event_mem_stru *));

/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of frw_event_main.h */
