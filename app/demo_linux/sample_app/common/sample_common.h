/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sample common file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __SAMPLE_COMMON_H__
#define __SAMPLE_COMMON_H__

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hi_type.h"
#include "hi_wlan.h"

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define WLAN_CMD_MAX_LEN 512

/*****************************************************************************
  3 ö�١��ṹ�嶨��
*****************************************************************************/
typedef hi_s32(*wlan_cmd_func)(hi_void *wdata, hi_char *param, hi_void *pmsg);
typedef struct {
    hi_char           *cmd_name;    /* �����ַ��� */
    wlan_cmd_func      func;        /* �����Ӧ������ */
} wlan_cmd_entry_stru;

typedef struct {
    wlan_cmd_entry_stru *cmd_tbl;   /* ����� */
    hi_u32               count;     /* �������� */
} wlan_cmd_common;

extern hi_wlan_mode_conf g_bw_ap_config;

/*****************************************************************************
  4 ��������
*****************************************************************************/
hi_s32 wlan_get_cmd_one_arg(const hi_char *pc_cmd, hi_char *pc_arg, hi_u32 pc_arg_len, hi_u32 *pul_cmd_offset);

hi_s32 wlan_parse_cmd(hi_void *wdata, hi_char *cmd, hi_void *msg);

hi_s32 wlan_sock_cmd_entry(hi_void *wdata, const char *cmd, ssize_t len, hi_void *msg);

hi_s32 wlan_register_cmd(wlan_cmd_entry_stru *cmd_tbl, hi_u32 num);

#endif

