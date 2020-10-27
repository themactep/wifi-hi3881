/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_hipriv.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_HIPRIV_H__
#define __WAL_HIPRIV_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_ext_if.h"
#include "wal_main.h"
#include "mac_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* ˽�����������ַ�����󳤶ȣ���Ӧ�����ڴ��һ����С */
#define WAL_HIPRIV_CMD_MAX_LEN       (WLAN_MEM_LOCAL_SIZE3 - 4)

#define WAL_HIPRIV_CMD_NAME_MAX_LEN  36                             /* �ַ�����ÿ�����ʵ���󳤶� */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define WAL_HIPRIV_PROC_ENTRY_NAME   "hipriv"
#endif
#ifdef _PRE_WLAN_FEATURE_BW_HIEX
#define WAL_HIPRIV_SELFCTS_DURATION_MAX      32
#define WAL_HIPRIV_SELFCTS_PER_MAX           1000
#endif

#define WAL_HIPRIV_HT_MCS_MIN           0
#define WAL_HIPRIV_HT_MCS_MAX           7
#define WAL_HIPRIV_VHT_MCS_MIN          0
#define WAL_HIPRIV_VHT_MCS_MAX          9
#define WAL_HIPRIV_NSS_MIN              1
#define WAL_HIPRIV_NSS_MAX              4
#define WAL_HIPRIV_CH_NUM               4
#define WAL_HIPRIV_SNPRINTF_DST         10

#define WAL_HIPRIV_BOOL_NIM             0
#define WAL_HIPRIV_BOOL_MAX             1
#define WAL_HIPRIV_FREQ_SKEW_ARG_NUM    8

#define WAL_HIPRIV_MS_TO_S                   1000   /* ms��s֮�䱶���� */
#define WAL_HIPRIV_KEEPALIVE_INTERVAL_MIN    5000   /* ��Ĭ���ϻ�����������ʱ�������� */
#define WAL_HIPRIV_KEEPALIVE_INTERVAL_MAX    0xffff /* timer���ʱ����������(oal_uin16) */

#define CAL_BAND_POWER_OFFSET_MAX            60
#define CAL_BAND_POWER_OFFSET_MIN            -60
#define CAL_RATE_POWER_OFFSET_MAX            7
#define CAL_RATE_POWER_OFFSET_MIN            -8
#define CAL_FREP_OFFSET_MAX                  127
#define CAL_FREP_OFFSET_MIN                  -128
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
#define HI_WIFI_MODE_11BGN                  0
#define HI_WIFI_MODE_11BG                   1
#define HI_WIFI_MODE_11B                    2
#endif

#define HI_CCA_THRESHOLD_LO (-128)
#define HI_CCA_THRESHOLD_HI 127

typedef hi_u32  (*wal_hipriv_cmd_func)(oal_net_device_stru *netdev, hi_char *pc_param);

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/* ���ܲ������ */
typedef enum {
    WAL_ALWAYS_TX_DISABLE,         /* ���ó��� */
    WAL_ALWAYS_TX_RF,              /* ������RF���Թ㲥���� */
    WAL_ALWAYS_TX_AMPDU_ENABLE,    /* ʹ��AMPDU�ۺϰ����� */
    WAL_ALWAYS_TX_MPDU,            /* ʹ�ܷǾۺϰ����� */
    WAL_ALWAYS_TX_DC,              /* ʹ��DC����,����CE��֤��Ƶƫ */
    WAL_ALWAYS_TX_BUTT
}wal_device_always_tx_state_enum;

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
/* ˽��������ڽṹ���� */
typedef struct {
    hi_char            *pc_cmd_name;    /* �����ַ��� */
    wal_hipriv_cmd_func func;         /* �����Ӧ������ */
}wal_hipriv_cmd_entry_stru;

/* �㷨�������ýṹ�� */
typedef struct {
    hi_char                         *pc_name;        /* ���������ַ��� */
    mac_alg_cfg_enum_uint8           alg_cfg;     /* ���������Ӧ��ö��ֵ */
    hi_u8                            auc_resv[3];    /* 3: �ֽڶ��� */
}wal_ioctl_alg_cfg_stru;

/* TPC����ģʽ */
typedef enum {
    ALG_TPC_MODE_DISABLE        = 0, /* ����TPCģʽ: ֱ�Ӳ���RF���õĹ������� */
    ALG_TPC_MODE_FIX_POWER      = 1, /* �̶�����ģʽ: ����֡��Data0�������õ�, Data1~3�Լ�����֡������֡��������� */
    /* ����Ӧ����ģʽ: ����֡��Data0��������Ӧ����, Data1~3�Լ�����֡������֡��������� */
    ALG_TPC_MODE_ADAPT_POWER    = 2,

    ALG_TPC_MODE_BUTT
}alg_tpc_mode_enum;
typedef hi_u8 alg_tpc_mode_enum_uint8;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32 wal_hipriv_set_rate(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_mcs(oal_net_device_stru *netdev, hi_char *pc_param);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
hi_u32 wal_hipriv_create_proc(hi_void *proc_arg);
#endif
#endif
hi_u32 wal_hipriv_del_vap(oal_net_device_stru *netdev);
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_vap_info(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
hi_u32 wal_hipriv_remove_proc(hi_void);
#endif
#endif
hi_u32 wal_hipriv_get_mac_addr(const hi_char *pc_param, hi_u8 mac_addr[], hi_u8 addr_len, hi_u32 *pul_total_offset);
hi_u32 wal_hipriv_get_bw(oal_net_device_stru *netdev, hal_channel_assemble_enum_uint8 *pen_bw_index);
hi_u32 wal_hipriv_set_bw(oal_net_device_stru *netdev, hi_char *pc_param);
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_reg_write(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
hi_u32 wal_hipriv_getcountry(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_vap_state(oal_net_device_stru *netdev, hi_char *pc_param);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_u32 wal_hipriv_get_mesh_node_info(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#ifdef _PRE_WLAN_FEATURE_STA_PM
hi_u32 wal_hipriv_sta_pm_on(oal_net_device_stru *netdev, const hi_char *pc_param);
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
hi_u32 wal_hipriv_set_uapsd_cap(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_uapsd_para(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_uapsd_cap(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_sta_set_psm_offset(oal_net_device_stru *netdev, hi_char *param);
hi_u32 wal_hipriv_sta_set_offload_param(oal_net_device_stru *netdev, hi_char *param);
hi_u32 wal_hipriv_sta_set_hw_ps_mode(oal_net_device_stru *netdev, hi_char *param);
hi_u32 wal_hipriv_set_pm_switch(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#endif
#if defined _PRE_WLAN_FEATURE_SIGMA
hi_u32 wal_hipriv_rts_threshold(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
hi_u32 wal_hipriv_frag_threshold(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
hi_u32 wal_hipriv_setcountry(oal_net_device_stru *netdev, hi_char *pc_param);
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
hi_u32 wal_hipriv_ampdu_tx_on(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
hi_u32 wal_hipriv_amsdu_tx_on(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_shortgi20(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#if defined _PRE_WLAN_FEATURE_SIGMA
hi_u32 wal_hipriv_set_stbc_cap(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_addba_req(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
hi_u32 wal_hipriv_entry(const hi_char *pc_buffer, hi_u32 count);
#endif
hi_u32 wal_hipriv_tx_proc(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_rx_proc(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_rx_fcs_info(oal_net_device_stru *netdev, hi_char *pc_param);
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_user_info(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
hi_u32 wal_hipriv_get_netdev(const hi_char *pc_cmd, oal_net_device_stru **netdev, hi_u32 *pul_off_set);
hi_u32 wal_hipriv_always_tx(oal_net_device_stru *netdev, hi_u8 tx_flag);
hi_u32  wal_hipriv_always_rx(oal_net_device_stru *netdev, hi_u8 rx_flag, hi_u8 mac_filter_flag);
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_get_cal_data(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_cal_band_power(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_cal_rate_power(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_rate_power(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_cal_freq_power(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_dataefuse(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_set_customer_mac(oal_net_device_stru *netdev, hi_char *pc_param);
hi_u32 wal_hipriv_get_customer_mac(oal_net_device_stru *netdev, hi_char *pc_param);
#endif
hi_u32 hi_hipriv_set_tx_pwr_offset(oal_net_device_stru *netdev, hi_char *pc_param);
#ifdef _PRE_WLAN_FEATURE_WOW
hi_u32 wal_get_add_wow_pattern_param(hi_u8 index, hi_char *pattern, hmac_cfg_wow_pattern_param_stru *cfg_wow_param);
#endif
hi_bool is_under_ps(hi_void);
hi_void set_under_ps(hi_bool under_ps);
hi_void set_under_mfg(hi_u32 under_mfg);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of wal_hipriv.h */

