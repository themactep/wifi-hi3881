/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_fsm.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_FSM_H__
#define __HMAC_FSM_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_main.h"
#include "hmac_vap.h"
#include "hmac_rx_filter.h"
#include "hmac_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
typedef hi_u32(*hmac_fsm_func) (hmac_vap_stru *hmac_vap, hi_void *p_param);

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/* ״̬����������ö�� */
typedef enum {
    /* AP STA���е��������� */
    HMAC_FSM_INPUT_RX_MGMT,
    HMAC_FSM_INPUT_RX_DATA,
    HMAC_FSM_INPUT_TX_DATA,
    HMAC_FSM_INPUT_TIMER0_OUT,
    HMAC_FSM_INPUT_MISC,        /* TBTT �쳣 �������������� */

    /* AP ���е��������� */
    HMAC_FSM_INPUT_START_REQ,

    /* STA���е��������� */
    HMAC_FSM_INPUT_SCAN_REQ,
    HMAC_FSM_INPUT_JOIN_REQ,
    HMAC_FSM_INPUT_AUTH_REQ,
    HMAC_FSM_INPUT_ASOC_REQ,
    HMAC_FSM_INPUT_LISTEN_REQ,  /*  �������� */
    HMAC_FSM_INPUT_LISTEN_TIMEOUT,
    HMAC_FSM_INPUT_SCHED_SCAN_REQ,      /* PNO����ɨ������ */
    HMAC_FSM_INPUT_TYPE_BUTT
} hmac_fsm_input_type_enum;
typedef hi_u8 hmac_fsm_input_type_enum_uint8;

#define HMAC_FSM_AP_INPUT_TYPE_BUTT     (HMAC_FSM_INPUT_RX_MGMT + 1)
#define HMAC_FSM_STA_INPUT_TYPE_BUTT    HMAC_FSM_INPUT_TYPE_BUTT
#define HMAC_SWITCH_STA_PSM_PERIOD      120000  /* staut�򿪵͹��ĳ�ʱ��ʱ��ο�1101 120s */

/* MISC�������͵������Ͷ��� */
typedef enum {
    HMAC_MISC_TBTT,
    HMAC_MISC_ERROR,
    HMAC_MISC_RADAR,

    HMAC_MISC_BUTT
} hmac_misc_input_enum;
typedef hi_u8 hmac_misc_input_enum_uint8;

/*****************************************************************************
  4 STRUCT����
*****************************************************************************/
/* MISC�������ͣ���νṹ�嶨�� */
typedef struct {
    hmac_misc_input_enum_uint8 type;
    hi_u8 auc_resv[3]; /* 3 �����ֽ� */
    hi_void *data;
} hmac_misc_input_stru;

/*****************************************************************************
  5 ��������
*****************************************************************************/
hi_u32 hmac_fsm_handle_scan_req(const mac_vap_stru *mac_vap, mac_scan_req_stru *scan_params);
hi_void hmac_fsm_change_state(hmac_vap_stru *hmac_vap, mac_vap_state_enum_uint8 vap_state);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_FSM_H__ */
