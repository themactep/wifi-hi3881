/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_vap.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_VAP_H__
#define __HMAC_VAP_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_vap.h"
#include "hmac_user.h"
#include "hmac_main.h"
#ifdef FEATURE_DAQ
#include "oal_data_collect.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define   hmac_vap_dft_stats_pkt_incr(_member, _cnt)
#define   hmac_vap_stats_pkt_incr(_member, _cnt)            ((_member) += (_cnt))

#define HMAC_RSP_MSG_MAX_LEN  64   /* get wid������Ϣ��󳤶� */
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
    ��ʼ��vap����ö��
*****************************************************************************/
typedef enum {
    HMAC_ADDBA_MODE_AUTO,
    HMAC_ADDBA_MODE_MANUAL,

    HMAC_ADDBA_MODE_BUTT
}hmac_addba_mode_enum;
typedef hi_u8 hmac_addba_mode_enum_uint8;

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
/* hmac����˽�нṹ */
typedef struct {
    /* ����wal_config���̵߳ȴ�(wal_config-->hmac),��SDT�·����Ĵ�������ʱ�� */
    oal_wait_queue_head_stru  wait_queue_for_sdt_reg;
    hi_u8               wait_ack_for_sdt_reg;
    hi_u8               auc_resv2[3]; /* 3 �����ֽ� */
    hi_s8               ac_rsp_msg[HMAC_RSP_MSG_MAX_LEN];     /* get wid������Ϣ�ڴ�ռ� */
    hi_u32              dog_tag;
}hmac_vap_cfg_priv_stru;

typedef struct {
    oal_wait_queue_head_stru  wait_queue;
    hi_u8                mgmt_tx_status;
    hi_u8                mgmt_tx_complete;
    hi_u8                mgmt_frame_id;
    hi_u8                uc_resv;
}oal_mgmt_tx_stru;

typedef enum {
    HMAC_REPORT_DISASSOC = 0,   /* Disassociation֡ */
    HMAC_REPORT_DEAUTH = 1,     /* Deauthentication֡ */
    HMAC_REPORT_ACTION = 2,     /* ACTION֡(Ŀǰֻ��SA Query Action֡) */

    DEVICE_REPORT_PROTECTED_BUTT
} hmac_report_disasoc_reason;
typedef hi_u16   hmac_report_disasoc_reason_uint16;

/* end add */
typedef struct {
    hi_list             timeout_head;
}hmac_mgmt_timeout_stru;

typedef struct {
    hi_u8                   user_index;
    mac_vap_state_enum_uint8    state;
    hi_u8                   vap_id;
    hi_u8                   uc_resv;
}hmac_mgmt_timeout_param_stru;

/* �޸Ĵ˽ṹ����Ҫͬ��֪ͨSDT�������ϱ��޷����� */
typedef struct {
    /***************************************************************************
                                ���Ͱ�ͳ��
    ***************************************************************************/
    /* ����lan�����ݰ�ͳ�� */
    hi_u32  rx_pkt_to_lan;                               /* �������̷�����̫�������ݰ���Ŀ��MSDU */
    hi_u32  rx_bytes_to_lan;                             /* �������̷�����̫�����ֽ��� */

    /***************************************************************************
                                ���Ͱ�ͳ��
    ***************************************************************************/
    /* ��lan���յ������ݰ�ͳ�� */
    hi_u32  tx_pkt_num_from_lan;                         /* ��lan�����İ���Ŀ,MSDU */
    hi_u32  tx_bytes_from_lan;                           /* ��lan�������ֽ��� */
}hmac_vap_query_stats_stru;
/* װ������ */
typedef struct {
    hi_u32                       rx_pkct_succ_num;                       /* �������ݰ��� */
    hi_u32                       dbb_num;                                /* DBB�汾�� */
    hi_u32                       check_fem_pa_status;                    /* fem��pa�Ƿ��ջٱ�־ */
    hi_s16                        s_rx_rssi;
    hi_u8              get_dbb_completed_flag;                 /* ��ȡDBB�汾�ųɹ��ϱ���־ */
    hi_u8              check_fem_pa_flag;                      /* fem��pa�Ƿ��ջ��ϱ���־ */
    hi_u8              get_rx_pkct_flag;                       /* �������ݰ��ϱ���־λ */
    hi_u8              lte_gpio_check_flag;                    /* �������ݰ��ϱ���־λ */
    hi_u8                        reserved[2];                   /* 2 �����ֽ� */
}hmac_atcmdsrv_get_stats_stru;

typedef enum _hmac_tcp_opt_queue_ {
    HMAC_TCP_ACK_QUEUE = 0,
    HMAC_TCP_OPT_QUEUE_BUTT
} hmac_tcp_opt_queue;

/* hmac vap�ṹ�� */
/* ����˽ṹ�������ӳ�Ա��ʱ���뱣�������ṹ��8�ֽڶ��� */
typedef struct hmac_vap_tag {
    /* ap sta�����ֶ� */
    oal_net_device_stru            *net_device;                   /* VAP��Ӧ��net_devices */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hmac_atcmdsrv_get_stats_stru     st_atcmdsrv_get_status;
    oal_spin_lock_stru               st_lock_state;               /* ������Ϳ������VAP״̬���л��� */
#endif
    oal_mgmt_tx_stru                mgmt_tx;
    frw_timeout_stru                mgmt_timer;
    hmac_mgmt_timeout_param_stru    mgmt_timetout_param;
    frw_timeout_stru                scan_timeout;                  /* vap����ɨ��ʱ����������ʱ��������ʱ�������� */
    frw_timeout_stru                scanresult_clean_timeout;      /* vapɨ�����ʱ����������ʱ������ɨ�����ϻ����� */

    wlan_auth_alg_enum_uint8        auth_mode;           /* ��֤�㷨 */
    hi_u8                           is80211i_mode;       /* ָʾ��ǰ�ķ�ʽʱWPA����WPA2, bit0 = 1,WPA; bit1 = 1, RSN */
    hi_u8                           ba_dialog_token;     /* BA�Ự����α���ֵ */
#ifdef _PRE_WLAN_FEATURE_PMF
    hi_u8                           pre_assoc_status;
#else
    hi_u8                           resv;
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    oal_net_device_stru            *p2p0_net_device;              /* ָ��p2p0 net device */
    oal_net_device_stru            *del_net_device;               /* ָ����Ҫͨ��cfg80211 �ӿ�ɾ���� net device */
    oal_work_stru                   del_virtual_inf_worker;    /* ɾ��net_device �������� */
#endif
#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
    oal_netbuf_head_stru            tx_queue_head[2];              /* 2�����Ͷ��У�2���߳�pinpon���� */
    hi_u8                           in_queue_id;
    hi_u8                           out_queue_id;
    hi_u8                           auc_resv1[2];                  /* 2 �����ֽ� */
    hi_atomic                       tx_event_num;                  /* frw�����¼��ĸ��� */
    hi_u32                          tx_quata;                      /* �������������� */
#endif
    hi_u16                          us_asoc_req_ie_len;
    hi_u16                          us_del_timeout;                     /* �೤ʱ�䳬ʱɾ��ba�Ự �����0��ɾ�� */

    hi_u8                           protocol_fall       : 1,        /* ��Э���־λ */
                                    reassoc_flag        : 1,        /* �����������ж��Ƿ�Ϊ�ع������� */
                                    init_flag           : 1,        /* �����ر��ٴδ򿪱�־ */
                                    ack_policy          : 1,        /* ack policy: 0:normal ack 1:normal ack */
                                    wmm_cap             : 1,        /* ������STA������AP�Ƿ�֧��wmm������Ϣ */
                                    cfg_sta_pm_manual   : 1,        /* �ֶ�����sta pm mode�ı�־ */
                                    query_wait_q_flag   : 2;        /* ��ѯ��־��HI_TRUE��ѯ������HI_FALSEδ���� */

    hi_u8                           addr_filter          : 1,
                                    amsdu_active         : 1,
                                    amsdu_ampdu_active   : 1,
                                    wps_active           : 1,
                                    tx_aggr_on           : 1,
                                    ampdu_tx_on_switch   : 1,
                                    pm_status_with_csi   : 1,        /* CSI��ʱ���浱ǰ�͹���״̬ */
                                    is_csi_open          : 1;        /* CSI�򿪱�־���Թ��жϵ�ǰ�Ƿ�ɴ򿪵͹��� */
    hi_u8                           auth_cnt             : 4,        /* STA��֤���Դ���,���ֵ=3 */
                                    asoc_cnt             : 4;        /* �������Դ���,���ֵ=5 */
    hi_u8                           rs_nrates;                       /* ���ʸ��� */

    hi_u8                           auc_supp_rates[WLAN_MAX_SUPP_RATES]; /* ֧�ֵ����ʼ� */
    hi_u8                          *puc_asoc_req_ie_buff;
    mac_cfg_mode_param_stru         preset_para;                         /* STAЭ����ʱ���ǰ��Э��ģʽ */
    oal_wait_queue_head_stru        query_wait_q;
#ifdef FEATURE_DAQ
    wlan_acq_result_addr_stru       acq_result_addr;
    hi_u8                           station_info_query_completed_flag;
    hi_u8                           acq_status_filter;
    hi_u8                           auc_resv3[2];                         /* 2 �����ֽ� */
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_station_info_stru           station_info;
    oal_spin_lock_stru              cache_user_lock;                        /* cache_user lock */
#endif
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    frw_timeout_stru                edca_opt_timer;                       /* edca����������ʱ�� */
    hi_u16                          us_edca_opt_time_ms;                  /* edca����������ʱ������ ms */
    hi_u8                           edca_opt_flag_ap;                     /* apģʽ���Ƿ�ʹ��edca�Ż����� */
    hi_u8                           edca_opt_flag_sta;                    /* staģʽ���Ƿ�ʹ��edca�Ż����� */
#endif

#ifdef _PRE_WLAN_FEATURE_AMPDU_VAP
    hi_u8                           rx_ba_session_num;                    /* ��vap�£�rx BA�Ự����Ŀ */
    hi_u8                           tx_ba_session_num;                    /* ��vap�£�tx BA�Ự����Ŀ */
    hi_u8                           auc_resv4[2];                         /* 2 �����ֽ� */
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    mac_h2d_protection_stru         prot;
#endif
#ifdef _PRE_WLAN_FEATURE_STA_PM
    frw_timeout_stru                ps_sw_timer;                          /* �͹��Ŀ��� */
#endif

    hi_s8                           ap_rssi;

    hi_u8                           query_ap_rssi_flag : 1;     /* ȡֵ��Χ��HI_TRUE��HI_FALSE */
    hi_u8                           hmac_al_rx_flag    : 1;     /* hmac����ʹ�ܱ�־ */
    hi_u8                           mac_filter_flag    : 1;     /* ����mac��ַ����ʹ�ܱ�־ */
    hi_u8                           resv5              : 5;     /* 5 bit�����ֶ� */

    hi_u8                           max_ampdu_num;              /* ADDBA_REQ�У�buffer_size��Ĭ�ϴ�С */
    hi_u8                           tx_traffic_classify_flag;   /* ҵ��ʶ���ܿ��� */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_u8                           resv[4];                    /* resv 4 bytes */
#endif
    mac_vap_stru                    *base_vap;              /* MAC VAPָ��,��mac��Դ��Ŷ�Ӧ,��������,�Ҳ����޸� */
}hmac_vap_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32 hmac_vap_res_exit(hi_void);
hi_u32 hmac_vap_res_init(hi_void);
oal_net_device_stru *hmac_vap_get_net_device(hi_u8 vap_id);
hmac_vap_stru *hmac_vap_get_vap_stru(hi_u8 idx);
hi_u32 hmac_vap_destroy(hmac_vap_stru *hmac_vap);
hi_u32 hmac_vap_init(hmac_vap_stru *hmac_vap, hi_u8 vap_id, const mac_cfg_add_vap_param_stru *param);
hi_u32 hmac_vap_creat_netdev(hmac_vap_stru *hmac_vap, hi_char *puc_netdev_name,
    const hi_s8 *mac_addr, hi_u8 mac_addr_len);

hi_u16 hmac_vap_check_ht_capabilities_ap(
     const hmac_vap_stru                  *hmac_vap,
     hi_u8                      *puc_payload,
     hi_u16                      us_info_elem_offset,
     hi_u32                      msg_len,
     hmac_user_stru                 *hmac_user);
hi_u32  hmac_search_ht_cap_ie_ap(
         const hmac_vap_stru               *hmac_vap,
         hmac_user_stru              *hmac_user,
         hi_u8                   *puc_payload,
         hi_u16                   us_current_offset,
         hi_bool                prev_asoc_ht);
hi_void hmac_vap_net_startall(hi_void);

#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
hi_u8 hmac_flowctl_check_device_is_sta_mode(hi_void);
hi_void hmac_vap_net_start_subqueue(hi_u16 us_queue_idx);
hi_void hmac_vap_net_stop_subqueue(hi_u16 us_queue_idx);
#endif

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
hi_u32 hmac_check_opmode_notify(
                hmac_vap_stru                   *hmac_vap,
                hi_u8                       *puc_mac_hdr,
                hi_u8                       *puc_payload,
                hi_u16                       us_info_elem_offset,
                hi_u32                       msg_len,
                hmac_user_stru                  *hmac_user);
#endif
hi_void hmac_handle_disconnect_rsp(hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
                                   hmac_report_disasoc_reason_uint16  disasoc_reason);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_u32 hmac_handle_close_peer_mesh(const hmac_vap_stru *hmac_vap, const hi_u8 *mac_addr, hi_u8 mac_addr_len,
                                   hi_u16 us_disasoc_reason_code, hi_u16 us_dmac_reason_code);
#endif
hi_u32 hmac_tx_get_mac_vap(hi_u8 vap_id, mac_vap_stru **mac_vap);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_VAP_H__ */
