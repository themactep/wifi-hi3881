/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_event_msg.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_EVENT_MSG_H__
#define __WAL_EVENT_MSG_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "wlan_mib.h"
#include "frw_event.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define WAL_MSG_WRITE_MSG_HDR_LENGTH    (sizeof(wal_msg_hdr_stru))
#define WAL_MSG_WRITE_MAX_LEN           (WLAN_MEM_EVENT_SIZE2 - FRW_EVENT_HDR_LEN - WAL_MSG_WRITE_MSG_HDR_LENGTH)
#define WAL_MSG_HDR_LENGTH              sizeof(wal_msg_hdr_stru)
#define WAL_MSG_WID_LENGTH              sizeof(wlan_cfgid_enum_uint16)
#define WAL_MSG_QUERY_LEN               16
#define WAL_BW_STR_MAX_LEN              20

/* ��д������Ϣͷ */
#define wal_cfg_msg_hdr_init(_pst_cfg_msg_hdr, _en_type, _us_len, _uc_sn) \
    do                                                      \
    {                                                       \
        (_pst_cfg_msg_hdr)->msg_type = (_en_type);       \
        (_pst_cfg_msg_hdr)->us_msg_len  = (_us_len);        \
        (_pst_cfg_msg_hdr)->msg_sn   = (_uc_sn);         \
    } while (0)

/* ��дwrite msg��Ϣͷ */
#define wal_write_msg_hdr_init(_pst_write_msg, _en_wid, _us_len) \
    do                                                      \
    {                                                       \
        (_pst_write_msg)->wid = (_en_wid);               \
        (_pst_write_msg)->us_len = (_us_len);               \
    } while (0)

/*****************************************************************************
  4 ö�ٶ���
*****************************************************************************/
/* ������Ϣ���� */
typedef enum {
    WAL_MSG_TYPE_QUERY,     /* ��ѯ */
    WAL_MSG_TYPE_WRITE,     /* ���� */
    WAL_MSG_TYPE_RESPONSE,  /* ���� */

    WAL_MSG_TYPE_BUTT
}wal_msg_type_enum;
typedef hi_u8 wal_msg_type_enum_uint8;

/*****************************************************************************
  5 STRUCT����
*****************************************************************************/
/* ������Ϣͷ */
typedef struct {
    wal_msg_type_enum_uint8     msg_type;       /* msg type:W or Q */
    hi_u8                   msg_sn;         /* msg ���к� */
    hi_u16                  us_msg_len;        /* msg ���� */
}wal_msg_hdr_stru;

/* ������Ϣ */
typedef struct {
    wal_msg_hdr_stru            msg_hdr;         /* ������Ϣͷ */
    hi_u8                   auc_msg_data[];    /* ������Ϣpayload */
}wal_msg_stru;

/* write��Ϣʱ�ķ�����Ϣ */
typedef struct {
    wlan_cfgid_enum_uint16  wid;
    hi_u8               auc_resv[2]; /* 2: �����ֽ� */
    hi_u32              err_code;    /* write��Ϣ���صĴ����� */
}wal_msg_write_rsp_stru;

/* write��Ϣ��ʽ */
typedef struct {
    wlan_cfgid_enum_uint16  wid;
    hi_u16              us_len;
    hi_u8               auc_value[WAL_MSG_WRITE_MAX_LEN];
}wal_msg_write_stru;

/* response��Ϣ��ʽ����Write��Ϣ��ʽ��ͬ */
typedef wal_msg_write_stru wal_msg_rsp_stru;

/* query��Ϣ��ʽ:2�ֽ�WID x N */
typedef struct {
    wlan_cfgid_enum_uint16  wid;
}wal_msg_query_stru;

/* WMM SET��Ϣ��ʽ */
typedef struct {
    wlan_cfgid_enum_uint16      cfg_id;
    hi_u8                   uc_resv[2]; /* 2: �����ֽ� */
    hi_u32                  ac;
    hi_u32                  value;
}wal_msg_wmm_stru;

/* WMM query��Ϣ��ʽ:2�ֽ�WID x N */
typedef struct {
    wlan_cfgid_enum_uint16  wid;
    hi_u8               uc_resv[2]; /* 2: �����ֽ� */
    hi_u32              ac;
}wal_msg_wmm_query_stru;

/* WID request struct */
typedef struct {
    hi_list             entry;
    uintptr_t           request_address;
    hi_void             *resp_mem;
    hi_u32              resp_len;
    hi_u32              ret;
}wal_msg_request_stru;

typedef struct {
    uintptr_t           request_address;
}wal_msg_rep_hdr;

typedef struct {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock_stru  st_lock;
#endif
    hi_list             head;
    oal_wait_queue_head_stru  wait_queue;
    hi_u32              count;
}wal_msg_queue;

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

hi_u32 wal_check_and_release_msg_resp(wal_msg_stru *rsp_msg);
hi_void wal_msg_queue_init(hi_void);
hi_void wal_cfg_msg_task_sched(hi_void);
hi_u32 wal_set_msg_response_by_addr(hi_u32 addr, hi_u8 *resp_mem, hi_u32 resp_ret, hi_u32 rsp_len);

#endif /* end of wal_event_msg.h */
