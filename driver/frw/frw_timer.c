/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Timer processing.
 * Author: Hisilicon
 * Create: 2018-08-04
 */
/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "frw_timer.h"
#include "frw_main.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
hi_list                     g_ast_timer_list;
oal_spin_lock_stru          g_ast_timer_list_spinlock;
hi_u32                      g_timer_id = 0;

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/* ��������:FRW��ʱ����ʱ�����¼� */
hi_void frw_timer_timeout_event(uintptr_t data)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru     *event = HI_NULL;
    frw_timeout_stru   *timeout = HI_NULL;
    hi_u32              ret;

    timeout = (frw_timeout_stru *)data;
    event_mem = frw_event_alloc(sizeof(hi_u32));
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_timeout_event:: event_mem == HI_NULL}");
        return;
    }

    event = (frw_event_stru *)event_mem->puc_data;
    frw_field_setup((&event->event_hdr), type, (FRW_EVENT_TYPE_TIMEOUT));
    frw_field_setup((&event->event_hdr), sub_type, (FRW_TIMEOUT_TIMER_EVENT));
    frw_field_setup((&event->event_hdr), us_length, (WLAN_MEM_EVENT_SIZE1));
    frw_field_setup((&event->event_hdr), pipeline, (FRW_EVENT_PIPELINE_STAGE_0));
    frw_field_setup((&event->event_hdr), vap_id, (0));

    *(hi_u32 *)event->auc_event_data = timeout->timer_id;

    ret = frw_event_dispatch_event(event_mem);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_FRW, "{frw_timer_timeout_event::frw_event_dispatch_event failed[%d].}", ret);
    }

    /* �ͷ��¼� */
    frw_event_free(event_mem);
}

/*
 * ��������:FRW��ʱ����ʱ������
 */ /* ��ȫ�ֱ���g_ast_frw_timeout_event_sub_table����,����const����,lin_t e801�澯���Σ�lin_t e818�澯���� */
hi_u32 frw_timer_timeout_proc(frw_event_mem_stru *event_mem)
{
    hi_list            *timeout_entry = HI_NULL;
    frw_event_stru     *event = HI_NULL;
    frw_timeout_stru   *timeout_element = HI_NULL;
    hi_u32              timer_id;

    event = (frw_event_stru *)event_mem->puc_data;
    timer_id = *(hi_u32 *)event->auc_event_data;

    timeout_entry = g_ast_timer_list.next;
    while (timeout_entry != &g_ast_timer_list) {
        if (timeout_entry == HI_NULL) {
            oam_warning_log0(0, OAM_SF_FRW, "{frw_timer_timeout_proc:: pst_timeout_entry is null! }");
            break;
        }

        timeout_element = hi_list_entry(timeout_entry, frw_timeout_stru, entry);
        /* ����ö�ʱ��û��ʹ�ܻ��ߴ�ɾ������ֱ�ӿ���һ�� */
        if ((timeout_element->is_deleting == HI_TRUE) ||
            (timeout_element->is_enabled == HI_FALSE)) {
            timeout_entry = timeout_entry->next;
            continue;
        }

        if ((timeout_element->timer_id == timer_id) &&
            (timeout_element->func != HI_NULL)) {
            timeout_element->func(timeout_element->timeout_arg);
            break;
        }
        timeout_entry = timeout_entry->next;
    }
    return HI_SUCCESS;
}

const frw_event_sub_table_item_stru g_ast_frw_timeout_event_sub_table[FRW_TIMEOUT_SUB_TYPE_BUTT] = {
    {frw_timer_timeout_proc, HI_NULL, HI_NULL}           /* FRW_TIMEOUT_TIMER_EVENT */
};

/* ��������:FRW��ʱ����ʼ�� */
hi_void frw_timer_init(hi_void)
{
    oal_spin_lock_init(&g_ast_timer_list_spinlock);
    hi_list_init(&g_ast_timer_list);
    frw_event_table_register(FRW_EVENT_TYPE_TIMEOUT, FRW_EVENT_PIPELINE_STAGE_0, g_ast_frw_timeout_event_sub_table);
}

/*
 * ��������:��Ӷ�ʱ��
 */
hi_void frw_timer_add_timer(frw_timeout_stru *timeout)
{
    if (timeout == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_add_timer:: pst_timeout == HI_NULL}");
        return;
    }
    hi_list_tail_insert(&timeout->entry, &g_ast_timer_list);
}

hi_void frw_timer_create_timer(frw_timeout_stru *timeout, frw_timeout_func timeout_func,
    hi_u32 timeoutval, hi_void *timeout_arg, hi_u8  is_periodic)
{
    if (timeout == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_create_timer:: HI_NULL == pst_timeout}");
        return;
    }

    oal_spin_lock_bh(&g_ast_timer_list_spinlock);

    timeout->func = timeout_func;
    timeout->timeout_arg = timeout_arg;
    timeout->timeout     = timeoutval;
    timeout->is_periodic = is_periodic;
    timeout->is_enabled  = HI_TRUE; /* Ĭ��ʹ�� */
    timeout->is_deleting = HI_FALSE;

    if (timeout->is_registerd != HI_TRUE) {
        timeout->timer_id = g_timer_id++; /* timer id���ڱ�ʶ��ʱ����Ψһ�� */
        oal_timer_init(&timeout->timer, timeoutval, frw_timer_timeout_proc_event, (unsigned long)timeout->timer_id);
        oal_timer_add(&timeout->timer);
    } else {
        oal_timer_start(&timeout->timer, (unsigned long)timeout->timeout);
    }

    if (timeout->is_registerd != HI_TRUE) {
        timeout->is_running  = HI_FALSE;
        timeout->is_registerd = HI_TRUE;
        frw_timer_add_timer(timeout);
    }
    oal_spin_unlock_bh(&g_ast_timer_list_spinlock);
    return;
}

hi_void  frw_timer_timeout_proc_event(unsigned long arg)
{
    frw_event_mem_stru *event_mem;
    frw_event_stru     *event = HI_NULL;

    event_mem = frw_event_alloc(sizeof(frw_event_stru));
    /* ����ֵ��� */
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_timeout_proc_event:: FRW_EVENT_ALLOC failed!}");
        return;
    }
    event = (frw_event_stru *)event_mem->puc_data;
    /* ����¼�ͷ */
    frw_field_setup((&event->event_hdr), type, (FRW_EVENT_TYPE_TIMEOUT));
    frw_field_setup((&event->event_hdr), sub_type, (FRW_TIMEOUT_TIMER_EVENT));
    frw_field_setup((&event->event_hdr), us_length, (WLAN_MEM_EVENT_SIZE1));
    frw_field_setup((&event->event_hdr), pipeline, (FRW_EVENT_PIPELINE_STAGE_0));
    frw_field_setup((&event->event_hdr), vap_id, (0));

    *(hi_u32 *)event->auc_event_data = (hi_u32)arg;

    /* ���¼� */
    frw_event_dispatch_event(event_mem);
    frw_event_free(event_mem);
}

hi_void frw_timer_immediate_destroy_timer(frw_timeout_stru *timeout)
{
    if (timeout == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_immediate_destroy_timer:: HI_NULL == pst_timeout}");
        return;
    }

    /* �����ʱ��δע�ᣬ��ֱ�ӷ��� */
    if (timeout->is_registerd == HI_FALSE) {
        return;
    }
    timeout->is_enabled  = HI_FALSE;
    timeout->is_registerd = HI_FALSE;
    timeout->is_deleting  = HI_FALSE;
    hi_s32 ret = oal_timer_delete(&timeout->timer);
    if (ret != 0 && ret != 1) { /* �Ǽ����ʱ����del_timer()����0,�����ʱ������1 */
        oam_error_log1(0, OAM_SF_FRW, "{frw_timer_immediate_destroy_timer:: fail ret = %d}", ret);
    }

    oal_spin_lock_bh(&g_ast_timer_list_spinlock);
    hi_list_delete(&timeout->entry);
    oal_spin_unlock_bh(&g_ast_timer_list_spinlock);
}

hi_void frw_timer_restart_timer(frw_timeout_stru *timeout, hi_u32 timeoutval, hi_u8 is_periodic)
{
    if (timeout == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_restart_timer:: HI_NULL == pst_timeout}");
        return;
    }

    if (timeout->is_registerd == HI_FALSE) {
        return;
    }
    timeout->timeout     = timeoutval;
    timeout->is_enabled  = HI_TRUE;
    timeout->is_periodic = is_periodic;
    timeout->is_deleting = HI_FALSE;
    hi_u32 ret = (hi_u32)oal_timer_start(&timeout->timer, (unsigned long)timeout->timeout);
    if (ret != 0 && ret != 1) { /* �Ǽ����ʱ����mod_timer()����0,�����ʱ������1 */
        oam_error_log1(0, OAM_SF_FRW, "{frw_timer_immediate_destroy_timer:: fail ret = %d}", ret);
    }
}

/* ��������:ֹͣ��ʱ�� */
hi_void frw_timer_stop_timer(frw_timeout_stru *timeout)
{
    if (timeout == HI_NULL) {
        oam_error_log0(0, OAM_SF_FRW, "{frw_timer_stop_timer:: HI_NULL == pst_timeout}");
        return;
    }
    if (timeout->is_registerd == HI_FALSE || timeout->is_enabled == HI_FALSE) {
        return;
    }
    timeout->is_enabled  = HI_FALSE;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
