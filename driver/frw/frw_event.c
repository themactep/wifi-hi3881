/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Event management external interface (for IPC interface, business interface).
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "frw_task.h"
#include "frw_event.h"
#include "frw_main.h"
#include "oam_ext_if.h"
#include "exception_rst.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
hi_u32 g_app_event_id = 0;
hi_u32 g_frw_enqueue_fail_nums = 0;

#define FRW_ENQUEUE_FAIL_LIMIT 10

/*****************************************************************************
  2 STRUCT����
*****************************************************************************/
/*****************************************************************************
  �ṹ��  : frw_event_mgmt_stru
  �ṹ˵��: �¼�����ṹ��
*****************************************************************************/
typedef struct _frw_event_mgmt_stru_ {
    frw_event_queue_stru       *event_queue;    /* �¼����� */
    frw_event_sched_queue_stru sched_queue[FRW_SCHED_POLICY_BUTT];       /* �ɵ��ȶ��� */
    hi_atomic                     total_element_cnt;
}frw_event_mgmt_stru;

/******************************************************************************
    �¼�����ʵ��
*******************************************************************************/
frw_event_mgmt_stru g_ast_event_manager;

/******************************************************************************
    �¼���ȫ�ֱ���
*******************************************************************************/
frw_event_table_item_stru g_ast_event_table[FRW_EVENT_TABLE_MAX_ITEMS];

/* �¼����г�ʼ��Ԥ���ص������޸��¼���������ֵ */
typedef hi_u32 (*frw_event_init_queue_cb)(hi_void);

/*****************************************************************************
  4 ����ʵ��
*****************************************************************************/
hi_u32 get_app_event_id(hi_void)
{
    return g_app_event_id;
}

/*****************************************************************************
 ��������  : �����¼��ڴ�
 �������  : us_length: payload���� + �¼�ͷ����
 �� �� ֵ  : �ɹ�: ָ��frw_event_mem_stru��ָ��
             ʧ��: HI_NULL
 �޸���ʷ      :
  1.��    ��   : 2012��10��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
frw_event_mem_stru* frw_event_alloc(hi_u16 us_payload_length)
{
    us_payload_length += OAL_MEM_INFO_SIZE;
    return oal_mem_alloc_enhanced(OAL_MEM_POOL_ID_EVENT, (us_payload_length + FRW_EVENT_HDR_LEN));
}

/*****************************************************************************
 ��������  : �ͷ��¼���ռ�õ��ڴ�
 �������  : event_mem: ָ���¼��ڴ���ָ��
 �� �� ֵ  : HI_SUCCESS ������������

 �޸���ʷ      :
  1.��    ��   : 2012��10��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 frw_event_free(frw_event_mem_stru   *event_mem)
{
    hi_u32       ret;
    frw_event_stru  *frw_event = HI_NULL;
    hi_unref_param(frw_event);

    ret = oal_mem_free_enhanced(event_mem);
    if (oal_warn_on(ret != HI_SUCCESS)) {
        frw_event = (frw_event_stru *)event_mem->puc_data;
        hi_diag_log_msg_i3(0, "[E]frw event free failed!, ret:%d, type:%d, subtype:%d",
            ret, frw_event->event_hdr.type, frw_event->event_hdr.sub_type);
    }
    return ret;
}

/*****************************************************************************
 ��������  : �����¼����ݻ�ȡ��Ӧ���¼�����ID
 �������  : event_mem: ָ���¼��ڴ���ָ��
 �������  : pus_qid      : ����ID
 �� �� ֵ  : HI_SUCCESS ������������
*****************************************************************************/
hi_u32 frw_event_to_qid(const frw_event_mem_stru *event_mem, hi_u16 *pus_qid)
{
    hi_u16            us_qid;
    frw_event_hdr_stru   *event_hrd = HI_NULL;

    /* ��ȡ�¼�ͷ�ṹ */
    event_hrd = (frw_event_hdr_stru *)event_mem->puc_data;

    us_qid = event_hrd->vap_id * FRW_EVENT_TYPE_BUTT + event_hrd->type;
    /* �쳣: ����ID�������ֵ */
    if ((us_qid >= FRW_EVENT_MAX_NUM_QUEUES)) {
        oam_error_log4(0, OAM_SF_FRW,
            "{frw_event_to_qid, array overflow! us_qid[%d], vap_id[%d], en_type[%d],sub_type[%d]}",
            us_qid, event_hrd->vap_id, event_hrd->type, event_hrd->sub_type);
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }

    *pus_qid = us_qid;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼ���¼�����
 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 frw_event_init_event_queue(hi_void)
{
    hi_u8  vap_res_num = oal_mem_get_vap_res_num();
    hi_u16 us_total_cnt = vap_res_num * FRW_EVENT_TYPE_BUTT; /* �߼���֤������� */
    hi_u16 us_qid;
    hi_u32 ret;
    frw_event_cfg_stru ast_event_cfg_vap[] = WLAN_FRW_EVENT_CFG_TABLE; /* �¼���ʼֵ,�����Դֵ4vap */
    /* ���Ӻ���������澯 -g- lin_t !e611 */
    frw_event_init_queue_cb func_cb = (frw_event_init_queue_cb)frw_get_rom_resv_func(FRW_ROM_RESV_FUNC_QUEUE_INIT);
    if (func_cb != HI_NULL) {
        /* Ԥ���ص��ǿ� ԭ�д��벻����Ҫ */
        return func_cb();
    }
    /* ����֧�ֵ�vap������������ָ���ڴ� */
    g_ast_event_manager.event_queue =
        (frw_event_queue_stru *)hi_malloc(HI_MOD_ID_WIFI_DRV, us_total_cnt * sizeof(frw_event_queue_stru));
    if (g_ast_event_manager.event_queue == HI_NULL) {
        hi_diag_log_msg_e0(0, "{frw_event_init_event_queue, hi_malloc event queue null.}");
        return HI_FAIL;
    }
    /* ��ȫ��̹���6.6����(3)�Ӷ��з����ڴ�󣬸����ֵ */
    memset_s((hi_void *)g_ast_event_manager.event_queue, us_total_cnt * sizeof(frw_event_queue_stru), 0,
        us_total_cnt * sizeof(frw_event_queue_stru));
    /* ѭ����ʼ���¼����� */
    for (us_qid = 0; us_qid < us_total_cnt; us_qid++) {
        ret = frw_event_queue_init(&g_ast_event_manager.event_queue[us_qid], ast_event_cfg_vap[us_qid].weight,
            ast_event_cfg_vap[us_qid].policy, FRW_EVENT_QUEUE_STATE_INACTIVE, ast_event_cfg_vap[us_qid].max_events);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            hi_free(HI_MOD_ID_WIFI_DRV, g_ast_event_manager.event_queue);
            g_ast_event_manager.event_queue = HI_NULL;
            hi_diag_log_msg_e0(0, "{frw_event_init_event_queue, frw_event_queue_init failed.}");
            return ret;
        }
    }

    return HI_SUCCESS;
}

const frw_event_sub_table_item_stru* frw_get_event_sub_table(hi_u8 type, hi_u8 pipeline)
{
    frw_event_table_item_stru *frw_event_table = HI_NULL;
    hi_u8 index;

    /* �����¼����ͼ��ֶκż����¼������� */
    index = (hi_u8)((type << 1) | (pipeline & 0x01));
    frw_event_table = &g_ast_event_table[index];

    return frw_event_table->sub_table;
}

/*****************************************************************************
 ��������  : ��ʼ��������
*****************************************************************************/
hi_u32 frw_event_init_sched(hi_void)
{
    hi_u16    us_qid;
    hi_u32    ret;

    /* ѭ����ʼ�������� */
    for (us_qid = 0; us_qid < FRW_SCHED_POLICY_BUTT; us_qid++) {
        ret = frw_event_sched_init(&g_ast_event_manager.sched_queue[us_qid]);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(0, OAM_SF_FRW,
                "{frw_event_init_sched, frw_event_sched_init return != HI_SUCCESS!%d}", ret);
            return ret;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �¼��ַ��ӿ�(�ַ��¼����˼�ͨѶ���¼����С����߲��Ѱ����Ӧ�¼�������)
*****************************************************************************/
hi_u32 frw_event_dispatch_event(frw_event_mem_stru *event_mem)
{
    frw_event_hdr_stru *event_hrd = HI_NULL;
#if defined(_PRE_MEM_DEBUG_MODE) || defined(_PRE_DEBUG_MODE)
    hi_u32 dog_tag;
#endif

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_event_dispatch_event: event_mem is null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �쳣: �ڴ�дԽ�� */
#if defined(_PRE_MEM_DEBUG_MODE) || defined(_PRE_DEBUG_MODE)
    dog_tag = (*((hi_u32 *)(event_mem->puc_origin_data + event_mem->us_len - OAL_DOG_TAG_SIZE)));
    if (dog_tag != OAL_DOG_TAG) {
        hi_diag_log_msg_i2(0,
            "[line = %d], frw_event_dispatch_event, ul_dog_tag changed is [%d]\r\n", __LINE__, dog_tag);
        return HI_ERR_CODE_MEM_DOG_TAG;
    }
#endif

    /* ��ȡ�¼�ͷ�ṹ */
    event_hrd = (frw_event_hdr_stru *)event_mem->puc_data;
    if (oal_unlikely(event_hrd->pipeline >= FRW_EVENT_PIPELINE_STAGE_BUTT)) {
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }

    /* ���piplelineΪ0�����¼���ӡ�����
       �����¼����ͣ��������Լ��ֶκţ�ִ����Ӧ���¼������� */
    if (event_hrd->pipeline == FRW_EVENT_PIPELINE_STAGE_0) {
        return frw_event_post_event(event_mem);
    }

    return frw_event_lookup_process_entry(event_mem, event_hrd);
}

/*****************************************************************************
 ��������  : �¼�����ģ���ʼ�������
 �� �� ֵ  : HI_SUCCESS ������������

 �޸���ʷ      :
  1.��    ��   : 2012��10��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 frw_event_init(hi_void)
{
    hi_u32    ret;
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_event_init(4, HI_NULL); /* 4:��������¼���Ϊ4 */
    hi_event_create(&g_app_event_id);
#endif
    ret = frw_event_init_event_queue(); /* ��ʼ���¼����� */
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_FRW, "{frw_event_init, frw_event_init_event_queue != HI_SUCCESS!%d}", ret);
        return ret;
    }
    /* ��ʼ�������� */
    ret = frw_event_init_sched();
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_FRW, "frw_event_init, frw_event_init_sched != HI_SUCCESS!%d", ret);
        return ret;
    }
    frw_task_event_handler_register(frw_event_process_all_event);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����¼�����
*****************************************************************************/
hi_void frw_event_destroy_event_queue(hi_void)
{
    hi_u8  vap_res_num;
    hi_u16 us_total_cnt;
    hi_u16 us_qid;

    if (g_ast_event_manager.event_queue == HI_NULL) {
        return;
    }
    vap_res_num = oal_mem_get_vap_res_num();
    us_total_cnt = vap_res_num * FRW_EVENT_TYPE_BUTT; /* �߼���֤������� */
    /* ѭ�������¼����� */
    for (us_qid = 0; us_qid < us_total_cnt; us_qid++) {
        frw_event_queue_destroy(&g_ast_event_manager.event_queue[us_qid]);
    }
    /* �ͷ��¼������ڴ� */
    hi_free(HI_MOD_ID_WIFI_DRV, g_ast_event_manager.event_queue);
    g_ast_event_manager.event_queue = HI_NULL;
}

/*****************************************************************************
 ��������  : �¼�����ģ��ж�ؽӿ�
 �޸���ʷ      :
  1.��    ��   : 2012��10��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void frw_event_exit(hi_void)
{
    /* �����¼����� */
    frw_event_destroy_event_queue();
}

/*****************************************************************************
 ��������  : ���¼��ڴ������Ӧ���¼�����
 �������  : event_mem: ָ���¼��ڴ���ָ��
 �� �� ֵ  : HI_SUCCESS ������������

 �޸���ʷ      :
  1.��    ��   : 2015��4��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 frw_event_queue_enqueue(frw_event_queue_stru *event_queue, frw_event_mem_stru *event_mem)
{
    return oal_queue_enqueue(&event_queue->queue, (hi_void *)event_mem);
}

/*****************************************************************************
 ��������  : ע����Ӧ�¼���Ӧ���¼�������
 �������  : en_type:       �¼�����
             en_pipeline:   �¼��ֶκ�
             pst_sub_table: �¼��ӱ�ָ��
 �޸���ʷ      :
  1.��    ��   : 2012��10��12��
    ��    ��   : Hisilicon
*****************************************************************************/
hi_void frw_event_table_register(frw_event_type_enum_uint8 type, frw_event_pipeline_enum_uint8 pipeline,
                                 const frw_event_sub_table_item_stru *sub_table)
{
    hi_u8 index;

    if (oal_unlikely(sub_table == HI_NULL)) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_event_table_register: pst_sub_table is null ptr!}");
        return;
    }
    /* �����¼����ͼ��ֶκż����¼������� */
    index = (hi_u8)((type << 1) | (pipeline & 0x01));
    if (oal_unlikely(index >= FRW_EVENT_TABLE_MAX_ITEMS)) {
        oam_error_log1(0, OAM_SF_FRW, "{frw_event_table_register, array overflow! %d}", index);
        return;
    }
    g_ast_event_table[index].sub_table = sub_table;
}

/*****************************************************************************
 ��������  : ���ĳ���¼������е������¼�
 �� �� ֵ  : HI_SUCCESS ������������

 �޸���ʷ      :
  1.��    ��   : 2013��11��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 frw_event_flush_event_queue(frw_event_type_enum_uint8 event_type)
{
    frw_event_queue_stru *event_queue = HI_NULL;
    frw_event_mem_stru   *event_mem = HI_NULL;
    frw_event_hdr_stru   *event_hrd = HI_NULL;
    hi_u32               event_succ = 0;
    hi_u32               ret;
    hi_u16               us_qid;
    hi_u8                vap_id;
    hi_u8                vap_res_num = oal_mem_get_vap_res_num();

    if (g_ast_event_manager.event_queue == HI_NULL) {
        hi_diag_log_msg_e0(0, "{frw_event_flush_event_queue, event queue null.}");
        return event_succ;
    }
    /* ����ÿ���˵�ÿ��vap��Ӧ���¼����� */
    for (vap_id = 0; vap_id < vap_res_num; vap_id++) {
        us_qid = vap_id * FRW_EVENT_TYPE_BUTT + event_type;
        /* ���ݺ˺� + ����ID���ҵ���Ӧ���¼����� */
        event_queue = &(g_ast_event_manager.event_queue[us_qid]);
        /* flush���е�event */
        while (event_queue->queue.element_cnt != 0) {
            event_mem = (frw_event_mem_stru *)frw_event_queue_dequeue(event_queue);
            if (event_mem == HI_NULL) {
                return event_succ;
            }
            hi_atomic_dec(&(g_ast_event_manager.total_element_cnt));

            /* ��ȡ�¼�ͷ�ṹ */
            event_hrd = (frw_event_hdr_stru *)event_mem->puc_data;

            /* �����¼��ҵ���Ӧ���¼������� */
            ret = frw_event_lookup_process_entry(event_mem, event_hrd);
            if (ret != HI_SUCCESS) {
                oam_error_log1(0, OAM_SF_FRW,
                    "{frw_event_process_all_event: frw_event_lookup_process_entry return value :%d}", ret);
            }

            /* �ͷ��¼��ڴ� */
            frw_event_free(event_mem);

            event_succ++;
        }

        /* ����¼����б�գ���Ҫ����ӵ��ȶ�����ɾ���������¼�����״̬��Ϊ����Ծ(���ɱ�����) */
        if (event_queue->queue.element_cnt == 0) {
            frw_event_sched_deactivate_queue(&g_ast_event_manager.sched_queue[event_queue->policy],
                                             event_queue);
        }
    }

    return event_succ;
}

/*****************************************************************************
 ��������  : ��ˢָ��VAP��ָ���¼����͵������¼���ͬʱ����ָ���Ƕ�����Щ�¼�����ȫ������
 �������  : uc_vap_id:     VAP IDֵ
             en_event_type: �¼�����
             en_drop:       �¼�����(1)���ߴ���(0)

 �޸���ʷ      :
  1.��    ��   : 2013��12��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 frw_event_vap_flush_event(hi_u8 vap_id, frw_event_type_enum_uint8 event_type, hi_u8 drop)
{
    hi_u16              us_qid;
    hi_u32              ret;
    frw_event_queue_stru   *event_queue = HI_NULL;
    frw_event_mem_stru     *event_mem = HI_NULL;
    frw_event_hdr_stru     *event_hrd = HI_NULL;

    if (event_type == FRW_EVENT_TYPE_WLAN_TX_COMP) {
        vap_id = 0;
    }

    if (g_ast_event_manager.event_queue == HI_NULL) {
        hi_diag_log_msg_e0(0, "{frw_event_flush_event_queue, event queue null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    us_qid = vap_id * FRW_EVENT_TYPE_BUTT + event_type;
    /* ���ݺ˺� + ����ID���ҵ���Ӧ���¼����� */
    event_queue = &(g_ast_event_manager.event_queue[us_qid]);
    /* ����¼����б���Ϊ�գ�û���¼������ڵ��ȶ��У����ش��� */
    if (event_queue->queue.element_cnt == 0) {
        return HI_FAIL;
    }

    /* flush���е�event */
    while (event_queue->queue.element_cnt != 0) {
        event_mem = (frw_event_mem_stru *)frw_event_queue_dequeue(event_queue);
        if (event_mem == HI_NULL) {
            return HI_FAIL;
        }
        hi_atomic_dec(&(g_ast_event_manager.total_element_cnt));

        /* �����¼�������ֱ���ͷ��¼��ڴ�������¼� */
        if (drop == 0) {
            /* ��ȡ�¼�ͷ�ṹ */
            event_hrd = (frw_event_hdr_stru *)event_mem->puc_data;
            /* �����¼��ҵ���Ӧ���¼������� */
            ret = frw_event_lookup_process_entry(event_mem, event_hrd);
            if (ret != HI_SUCCESS) {
                oam_warning_log0(vap_id, OAM_SF_FRW, "frw_event_lookup_process_entry return NON SUCCESS. ");
            }
        }

        /* �ͷ��¼��ڴ� */
        frw_event_free(event_mem);
    }

    /* ���¼������Ѿ���գ���Ҫ����ӵ��ȶ�����ɾ���������¼�����״̬��Ϊ����Ծ(���ɱ�����) */
    if (event_queue->queue.element_cnt == 0) {
        frw_event_sched_deactivate_queue(&g_ast_event_manager.sched_queue[event_queue->policy],
            event_queue);
    } else {
        oam_error_log1(vap_id, OAM_SF_FRW, "{flush vap event failed, left!=0: type=%d}", event_type);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ݺ�id���¼����ͣ��ж�vap�¼������Ƿ��
 �������  : event_type:  �¼�ID;
 �޸���ʷ      :
  1.��    ��   : 2015��4��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 frw_is_vap_event_queue_empty(hi_u8 vap_id, hi_u8 event_type)
{
    frw_event_queue_stru *event_queue = HI_NULL;
    hi_u16               us_qid;

    us_qid  = (hi_u16)(vap_id * FRW_EVENT_TYPE_BUTT + event_type);
    /* ���ݺ˺� + ����ID���ҵ���Ӧ���¼����� */
    if (g_ast_event_manager.event_queue == HI_NULL) {
        hi_diag_log_msg_e0(0, "{frw_event_flush_event_queue, event queue null.}");
        return HI_TRUE;
    }
    event_queue = &(g_ast_event_manager.event_queue[us_qid]);
    if (event_queue->queue.element_cnt != 0) {
        return HI_FALSE;
    }
    return HI_TRUE;
}

/*****************************************************************************
 ��������  : �ж��Ƿ����¼���Ҫ����

 �޸���ʷ      :
  1.��    ��   : 2015��4��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u8 frw_task_thread_condition_check(hi_void)
{
    return (hi_atomic_read(&g_ast_event_manager.total_element_cnt) != 0);
}

/*****************************************************************************
 ��������  : �����¼������е������¼�
 patch�޸� : FRW�����¼�ʱ��cnt�ݼ�
*****************************************************************************/
hi_void frw_event_process_all_event(hi_void)
{
    frw_event_mem_stru            *event_mem = HI_NULL;
    frw_event_sched_queue_stru    *sched_queue = HI_NULL;
    frw_event_hdr_stru            *event_hrd = HI_NULL;

    /* ��ȡ�˺� */
    sched_queue = g_ast_event_manager.sched_queue;
    /* �����¼�����ģ�飬ѡ��һ���¼� */
    event_mem = (frw_event_mem_stru *)frw_event_schedule(sched_queue);
    while (event_mem != HI_NULL) {
        hi_atomic_dec(&g_ast_event_manager.total_element_cnt);
        /* ��ȡ�¼�ͷ�ṹ */
        event_hrd  = (frw_event_hdr_stru *)event_mem->puc_data;
        if (event_hrd != HI_NULL) {
            /* �����¼��ҵ���Ӧ���¼������� */
            if (frw_event_lookup_process_entry(event_mem, event_hrd) != HI_SUCCESS) {
                oam_warning_log0(0, OAM_SF_FRW, "frw_event_process_all_event_patch return NON SUCCESS.");
            }
        }
        /* �ͷ��¼��ڴ� */
        frw_event_free(event_mem);
        /* �����¼�����ģ�飬ѡ��һ���¼� */
        event_mem = (frw_event_mem_stru *)frw_event_schedule(sched_queue);
    }
}

/*****************************************************************************
 ��������  : �¼��ڴ����
 �������  : pst_event_queue: �¼�����
 �� �� ֵ  : HI_SUCCESS ������������

 �޸���ʷ      :
  1.��    ��   : 2015��4��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
frw_event_mem_stru* frw_event_queue_dequeue(frw_event_queue_stru *event_queue)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    unsigned long irq_flag;

    oal_spin_lock_irq_save(&event_queue->st_lock, &irq_flag);
    event_mem = (frw_event_mem_stru *)oal_queue_dequeue(&event_queue->queue);
    oal_spin_unlock_irq_restore(&event_queue->st_lock, &irq_flag);
    return event_mem;
}

/*****************************************************************************
 ��������  : ���¼��ڴ������Ӧ���¼�����
 �������  : event_mem: ָ���¼��ڴ���ָ��
 �� �� ֵ  : HI_SUCCESS ������������
*****************************************************************************/
hi_u32 frw_event_post_event(frw_event_mem_stru *event_mem)
{
    hi_u16                     us_qid;
    frw_event_queue_stru       *event_queue = HI_NULL;
    hi_u32                     ret;
    unsigned long              irq_flag;
    frw_event_hdr_stru         *event_hdr = HI_NULL;
    frw_event_sched_queue_stru *sched_queue = HI_NULL;

    /* ��ȡ�¼�����ID */
    ret = frw_event_to_qid(event_mem, &us_qid);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_FRW, "{frw_event_post_event, frw_event_to_qid return != HI_SUCCESS!%d}", ret);
        return ret;
    }
    /* ���ݺ˺� + ����ID���ҵ���Ӧ���¼����� */
    if (g_ast_event_manager.event_queue == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_event_post_event, event queue null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    event_queue = &(g_ast_event_manager.event_queue[us_qid]);
    /* ���policy */
    if (oal_unlikely(event_queue->policy >= FRW_SCHED_POLICY_BUTT)) {
        oam_error_log1(0, OAM_SF_FRW, "{frw_event_post_event, array overflow!%d}", event_queue->policy);
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }
    /* ��ȡ���ȶ��� */
    sched_queue = &(g_ast_event_manager.sched_queue[event_queue->policy]);

    /* ��ȡ�����ã���ֹenqueue��ȡ������֮�䱻�ͷ� */
    event_mem->user_cnt++;

    /* �¼���� */
    oal_spin_lock_irq_save(&event_queue->st_lock, &irq_flag);
    ret = frw_event_queue_enqueue(event_queue, event_mem);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oal_spin_unlock_irq_restore(&event_queue->st_lock, &irq_flag);
        event_hdr = (frw_event_hdr_stru *)(event_mem->puc_data);
        oam_error_log4(0, OAM_SF_FRW,
            "frw_event_post_event:: enqueue fail, type:%d, sub type:%d, pipeline:%d,max num:%d",
            event_hdr->type, event_hdr->sub_type, event_hdr->pipeline,
            event_queue->queue.max_elements);
        g_frw_enqueue_fail_nums++;
        /* �ͷ��¼��ڴ����� */
        frw_event_free(event_mem);
        if (g_frw_enqueue_fail_nums > FRW_ENQUEUE_FAIL_LIMIT) {
            oal_frw_exception_report();
        }
        return ret;
    }
    g_frw_enqueue_fail_nums = 0;
    hi_atomic_inc(&(g_ast_event_manager.total_element_cnt));
    /* �����������Ȳ��ԣ����¼����м���ɵ��ȶ��� */
    ret = frw_event_sched_activate_queue_no_lock(sched_queue, event_queue);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oal_spin_unlock_irq_restore(&event_queue->st_lock, &irq_flag);
        oam_error_log0(0, OAM_SF_FRW, "{frw_event_post_event, sched_activate_queue failed!}");
        return ret;
    }
    oal_spin_unlock_irq_restore(&event_queue->st_lock, &irq_flag);
    frw_task_sched();

    return HI_SUCCESS;
}

hi_void frw_event_sub_rx_adapt_table_init(frw_event_sub_table_item_stru *pst_sub_table, hi_u32 ul_table_nums,
    frw_event_mem_stru* (*p_rx_adapt_func)(frw_event_mem_stru *))
{
    hi_u32 i;
    frw_event_sub_table_item_stru* pst_curr_table = HI_NULL;
    for (i = 0; i < ul_table_nums; i++) {
        pst_curr_table = pst_sub_table + i;
        pst_curr_table->p_rx_adapt_func = p_rx_adapt_func;
    }
}

/*****************************************************************************
 ��������  : �����¼����ͣ��������Լ��ֶκţ��ҵ���Ӧ�¼�������
 �������  : event_mem: ָ���¼��ڴ���ָ��
 �� �� ֵ  : HI_SUCCESS ������������

 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 frw_event_lookup_process_entry(frw_event_mem_stru *event_mem, const frw_event_hdr_stru *event_hrd)
{
    frw_event_table_item_stru *frw_event_table = HI_NULL;
    hi_u8                     index;
    hi_u8                     sub_type;
    frw_event_mem_stru       *rx_adapt_event_mem = HI_NULL;
    hi_u32                    err_code;

    sub_type = event_hrd->sub_type;

    /* �����¼����ͼ��ֶκż����¼������� */
    index = (hi_u8)((event_hrd->type << 1) | (event_hrd->pipeline & 0x01));
    if (oal_unlikely(index >= FRW_EVENT_TABLE_MAX_ITEMS)) {
        hi_diag_log_msg_e3(0, "{frw_event_lookup_process_entry::array overflow! type[%d], sub_type[%d], pipeline[%d]}",
            event_hrd->type, sub_type, event_hrd->pipeline);
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }

    /* �Ȱ�ȫ�ֱ�����ɾֲ����� */
    frw_event_table = &g_ast_event_table[index];
    if (frw_event_table->sub_table == HI_NULL) {
        hi_diag_log_msg_e2(0, "{frw_event_lookup_process_entry::pst_sub_table is NULL! sub_type[%d], index[%d].}",
            sub_type, index);
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ֱ�Ӻ������� */
    if (frw_event_table->sub_table[sub_type].func == HI_NULL) {
        hi_diag_log_msg_e2(0, "{frw_event_lookup_process_entry:: p_func is NULL! sub_type[%d], index[%d].}",
            sub_type, index);
        return HI_ERR_CODE_PTR_NULL;
    }

    if (event_hrd->pipeline == 0) {
        if (frw_event_table->sub_table[sub_type].func != HI_NULL) {
            err_code = frw_event_table->sub_table[sub_type].func(event_mem);
            return err_code;
        } else {
            oam_error_log2(0, OAM_SF_FRW,
                "{frw_event_lookup_process_entry:: func is NULL! sub_type[%d], index[0x%x], pipeline=0.}",
                           sub_type, index);
            return HI_ERR_CODE_PTR_NULL;
        }
    }

    /* For rx adapt */
    if (frw_event_table->sub_table[sub_type].p_rx_adapt_func == HI_NULL) {
        oam_warning_log2(0, 0, "frw_event_lookup_process_entry:: rx_adapt_func is NULL, type[%d], sub_type[%d]",
            event_hrd->type, sub_type);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* rx adapt first */
    rx_adapt_event_mem = frw_event_table->sub_table[sub_type].p_rx_adapt_func(event_mem);
    if (rx_adapt_event_mem == HI_NULL) {
        oam_error_log0(0, 0, "frw_event_lookup_process_entry:: rx_adapt_event_mem NULL");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (frw_event_table->sub_table[sub_type].func != HI_NULL) {
        /* then call action frame */
        err_code = frw_event_table->sub_table[sub_type].func(rx_adapt_event_mem);
    } else {
        err_code = HI_ERR_CODE_PTR_NULL;
    }

    frw_event_free(rx_adapt_event_mem);

    return err_code;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

