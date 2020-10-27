/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_regdb.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_REGDB_H__
#define __WAL_REGDB_H__

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
#ifndef array_size
#define array_size(array) (sizeof(array) / sizeof((array)[0]))
#endif

/*****************************************************************************
  3 ȫ�ֱ�������
*****************************************************************************/
extern const oal_ieee80211_regdomain_stru g_default_regdom;

/*****************************************************************************
  4 ��������
*****************************************************************************/
const oal_ieee80211_regdomain_stru* wal_regdb_find_db(const hi_char *pc_str);
hi_void wal_set_cfg_regdb(const oal_ieee80211_regdomain_stru *regdom);
const oal_ieee80211_regdomain_stru *wal_get_cfg_regdb(hi_void);

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
struct callback_head {
    struct callback_head *next;
    hi_void (*func)(struct callback_head *head);
};

#define RCU_HEAD callback_head

struct ieee80211_regdomain {
    struct RCU_HEAD RCU_HEAD;
    hi_u32 n_reg_rules;
    hi_char alpha2[2]; /* Ԫ�ظ���Ϊ2 */
    hi_u8 dfs_region;
    struct ieee80211_reg_rule reg_rules[];
};

#ifndef ARRAY_SIZE
#define array_size(array) (sizeof(array) / sizeof((array)[0]))
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of wal_regdb.h */
