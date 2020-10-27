/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: The header file of hmac_device.c, including the definition of the hmac device structure.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_DEVICE_H__
#define __HMAC_DEVICE_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "frw_timer.h"
#include "mac_vap.h"
#include "hmac_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
/* �洢ÿ��ɨ�赽��bss��Ϣ */
typedef struct {
    hi_list                dlist_head;        /* ����ָ�� */
    mac_bss_dscr_stru      bss_dscr_info;    /* bss������Ϣ�������ϱ��Ĺ���֡ */
}hmac_scanned_bss_info;

/* �洢��hmac device�µ�ɨ����ά���Ľṹ�� */
typedef struct {
    oal_spin_lock_stru  st_lock;
    hi_list             bss_list_head;
    hi_u32              bss_num;
}hmac_bss_mgmt_stru;

/* ɨ�����н����¼ */
typedef struct {
    hmac_bss_mgmt_stru          bss_mgmt;                    /* �洢ɨ��BSS����Ĺ���ṹ */
    hi_u8                       chan_numbers;                /* �˴�ɨ���ܹ���Ҫɨ����ŵ����� */
    hi_u8                       vap_id;                      /* ����ִ��ɨ���vap id */
    mac_scan_status_enum_uint8  scan_rsp_status;             /* ����ɨ����ɷ��ص�״̬�룬�ǳɹ����Ǳ��ܾ� */
    mac_vap_state_enum_uint8    vap_last_state;              /* ����VAP����ɨ��ǰ��״̬,AP/P2P GOģʽ��20/40Mɨ��ר�� */

    mac_scan_cb_fn              fn_cb;                       /* �˴�ɨ������Ļص�����ָ�� */
    hi_u8                       is_any_scan;
    hi_u8                       resv[3]; /* 3 �����ֽ� */
    hi_u64                      ull_cookie;                  /* ����P2P ���������ϱ���cookie ֵ */
}hmac_scan_record_stru;

/* ɨ�������ؿ�����Ϣ */
typedef struct {
    /* scan ��ؿ�����Ϣ */
    hi_u8                    is_scanning;                /* host���ɨ�������Ƿ�����ִ�� */
    hi_u8                    is_random_mac_addr_scan;    /* �Ƿ�Ϊ���mac addrɨ�裬Ĭ�Ϲر�(���ƻ��꿪���·���) */
    hi_u8                    complete;                   /* �ں���ͨɨ�������Ƿ���ɱ�־ */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_u8                    sched_scan_complete;        /* ����ɨ���Ƿ��������б�� */
    oal_spin_lock_stru       st_scan_request_spinlock;            /* �ں��·���request��Դ�� */
#else
    hi_u8                    resv;
#endif
    oal_cfg80211_scan_request_stru         *request;               /* �ں��·���ɨ������ṹ�� */
    oal_cfg80211_sched_scan_request_stru   *sched_scan_req;        /* �ں��·��ĵ���ɨ������ṹ�� */

    frw_timeout_stru                       scan_timeout;            /* ɨ��ģ��host��ĳ�ʱ������ʹ�õĶ�ʱ�� */
    /* ɨ�����м�¼������Ϣ������ɨ�����ͷ���ɨ���ߵ������Ϣ */
    hmac_scan_record_stru                  scan_record_mgmt;
    /* ��¼�·���listen channel�����ϱ���app�� DTS2015061505129  */
    mac_channel_stru                       p2p_listen_channel;
    /* ��¼�����ŵ��б��map,11bģʽ���յ��ǵ�ǰ�ŵ�ɨ��֡����ʹ��,5g����֡��ʹ��11b���� */
    hi_u32                                 scan_2g_ch_list_map;
}hmac_scan_stru;

typedef struct {
    frw_timeout_stru    rx_dscr_opt_timer;     /* rx_dscr������ʱ�� */
    hi_u32              rx_pkt_num;
    hi_u32              rx_pkt_opt_limit;
    hi_u32              rx_pkt_reset_limit;

    hi_u8               dscr_opt_state;        /* TRUE��ʾ�ѵ��� */
    hi_u8               dscr_opt_enable;
    hi_u8               resv[2]; /* 2 �����ֽ� */
}hmac_rx_dscr_opt_stru;

/* hmac device�ṹ�壬��¼ֻ������hmac��device������Ϣ */
typedef struct {
    hmac_scan_stru         scan_mgmt;                            /* ɨ�����ṹ�� */
    hi_u32                 p2p_intf_status;
    oal_wait_queue_head_stru     netif_change_event;
    hi_u8                  auc_rx_ba_lut_idx_table[DMAC_BA_LUT_IDX_BMAP_LEN];   /* ���ն�LUT�� */
#ifndef _PRE_WLAN_FEATURE_AMPDU_VAP
    hi_u8                  rx_ba_session_num;                   /* ��device�£�rx BA�Ự����Ŀ */
    hi_u8                  tx_ba_session_num;                   /* ��device�£�tx BA�Ự����Ŀ */
#endif
#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    hmac_rx_dscr_opt_stru rx_dscr_opt;
#endif
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    d2h_btcoex_delba_event_stru      d2h_btcoex_delba;
#endif
    hi_u8                 resv1[4]; /* 4 BYTE �����ֶ� */
}hmac_device_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
hmac_device_stru *hmac_get_device_stru(hi_void);
hi_u32 hmac_device_init(hi_void);
hi_u32 hmac_device_exit(hi_void);
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
hi_u32 hmac_config_host_dev_init(mac_vap_stru *mac_vap, hi_u16 len, const hi_u8 *param);
hi_u32 hmac_config_host_dev_exit(mac_vap_stru *pst_mac_vap, hi_u16 len, const hi_u8 *param);
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_DEVICE_H__ */
