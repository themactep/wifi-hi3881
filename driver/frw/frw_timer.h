/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for frw_timer.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __FRW_TIMER_H__
#define __FRW_TIMER_H__

/****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "frw_event.h"
#include "oal_ext_if.h"
#include "oam_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
typedef hi_u32          (*frw_timeout_func)(hi_void *);

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
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
typedef struct {
    hi_u32            handle;
    hi_void          *timeout_arg;      /* ��ʱ��������� */
    frw_timeout_func  func;             /* ��ʱ������ */
    hi_u32            time_stamp;      /* ��ʱ������ʱ�� */
    hi_u32            timeout;         /* ���೤ʱ�䶨ʱ����ʱ */
    hi_u32            timer_id;        /* ��ʱ��Ψһ��ʶ */
    hi_u8             is_deleting;     /* �Ƿ���Ҫɾ�� */
    hi_u8             is_registerd;    /* ��ʱ���Ƿ��Ѿ�ע�� */
    hi_u8             is_periodic;     /* ��ʱ���Ƿ�Ϊ���ڵ� */
    hi_u8             is_enabled :4;   /* ��ʱ���Ƿ�ʹ�� */
    hi_u8             is_running :4;
    oal_timer_list_stru      timer;
    hi_list           entry;           /* ��ʱ���������� */
}frw_timeout_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_void frw_timer_init(hi_void);
hi_void frw_timer_timeout_proc_event(unsigned long arg);
hi_void frw_timer_create_timer(frw_timeout_stru *timeout,
                               frw_timeout_func  timeout_func,
                               hi_u32 timeoutval,
                               hi_void *timeout_arg,
                               hi_u8 is_periodic);
hi_void frw_timer_immediate_destroy_timer(frw_timeout_stru *timeout);
hi_void frw_timer_restart_timer(frw_timeout_stru *timeout,
                                hi_u32 timeoutval,
                                hi_u8  is_periodic);
hi_void frw_timer_stop_timer(frw_timeout_stru *timeout);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of frw_timer.h */
