/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: The header file of mac_device.c, including the definition of board, chip, and device structure.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_DEVICE_H__
#define __MAC_DEVICE_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "frw_timer.h"
#include "mac_vap.h"
#include "mac_mib.h"
#include "mac_cfg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define MAC_DATARATES_PHY_80211G_NUM        12
#define DMAC_BA_LUT_IDX_BMAP_LEN            ((HAL_MAX_BA_LUT_SIZE + 7) >> 3)

/* DMAC SCANNER ɨ��ģʽ */
#define MAC_SCAN_FUNC_MEAS          0x1
#define MAC_SCAN_FUNC_STATS         0x2
#define MAC_SCAN_FUNC_RADAR         0x4
#define MAC_SCAN_FUNC_BSS           0x8
#define MAC_SCAN_FUNC_P2P_LISTEN    0x10
#define MAC_SCAN_FUNC_ALL           (MAC_SCAN_FUNC_MEAS | MAC_SCAN_FUNC_STATS | MAC_SCAN_FUNC_RADAR | MAC_SCAN_FUNC_BSS)

#define MAC_DEV_MAX_40M_INTOL_USER_BITMAP_LEN 4

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
#define MAC_MIB_MESH_VENDOR_SPECIFIC    255
#define MAC_MIB_NEIGHBOR_OFFSET_SYNC    1
#define MAC_MIB_AUTH_PROTOCOL_SAE       1
#define MAC_MESH_MULTI_MAC_ADDR_MAX_NUM 10
#endif

#define MAC_FCS_MAX_CHL_NUM    2
#define MAC_FCS_DEFAULT_PROTECT_TIMEOUT    2000    /* ��һ�η�����֡��ʱʱ��,��λ:us */
#define MAC_FCS_DEFAULT_PROTECT_TIMEOUT2   1000    /* �ڶ��η�����֡��ʱʱ��,��λ:us */
#define MAC_DBAC_ONE_PACKET_TIMEOUT        1000    /* dbac����֡��ʱʱ��,��λ:10us */
#define MAC_ONE_PACKET_TIMEOUT             1000    /* ��dbac����֡��ʱʱ��,��λ:10us */
#define MAC_FCS_CTS_MAX_DURATION           32767   /* us */

#define MAX_PNO_SSID_COUNT          16
#define MAX_PNO_REPEAT_TIMES        4
#define PNO_SCHED_SCAN_INTERVAL     (30 * 1000)

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    MAC_CH_TYPE_NONE      = 0,
    MAC_CH_TYPE_PRIMARY   = 1,
    MAC_CH_TYPE_SECONDARY = 2,
} mac_ch_type_enum;
typedef hi_u8 mac_ch_type_enum_uint8;

typedef enum {
    MAC_SCAN_OP_INIT_SCAN,
    MAC_SCAN_OP_FG_SCAN_ONLY,
    MAC_SCAN_OP_BG_SCAN_ONLY,

    MAC_SCAN_OP_BUTT
} mac_scan_op_enum;
typedef hi_u8 mac_scan_op_enum_uint8;

typedef enum {
    MAC_CHAN_NOT_SUPPORT = 0,        /* ������֧�ָ��ŵ� */
    MAC_CHAN_AVAILABLE_ALWAYS,       /* �ŵ�һֱ����ʹ�� */
    MAC_CHAN_AVAILABLE_TO_OPERATE,   /* �������(CAC, etc...)�󣬸��ŵ�����ʹ�� */
    MAC_CHAN_DFS_REQUIRED,           /* ���ŵ���Ҫ�����״��� */
    MAC_CHAN_BLOCK_DUE_TO_RADAR,     /* ���ڼ�⵽�״ﵼ�¸��ŵ���Ĳ����� */

    MAC_CHAN_STATUS_BUTT
} mac_chan_status_enum;
typedef hi_u8 mac_chan_status_enum_uint8;

/* device resetͬ��������ö�� */
typedef enum {
    MAC_RESET_SWITCH_SET_TYPE,
    MAC_RESET_SWITCH_GET_TYPE,
    MAC_RESET_STATUS_GET_TYPE,
    MAC_RESET_STATUS_SET_TYPE,
    MAC_RESET_SWITCH_SYS_TYPE = MAC_RESET_SWITCH_SET_TYPE,
    MAC_RESET_STATUS_SYS_TYPE = MAC_RESET_STATUS_SET_TYPE,

    MAC_RESET_SYS_TYPE_BUTT
} mac_reset_sys_type_enum;
typedef hi_u8 mac_reset_sys_type_enum_uint8;

typedef enum {
    MAC_TRY_INIT_SCAN_VAP_UP,
    MAC_TRY_INIT_SCAN_SET_CHANNEL,
    MAC_TRY_INIT_SCAN_START_DBAC,
    MAC_TRY_INIT_SCAN_RESCAN,

    MAC_TRY_INIT_SCAN_BUTT
} mac_try_init_scan_type;
typedef hi_u8 mac_try_init_scan_type_enum_uint8;

typedef enum {
    MAC_INIT_SCAN_NOT_NEED,
    MAC_INIT_SCAN_NEED,
    MAC_INIT_SCAN_IN_SCAN,
} mac_need_init_scan_res;
typedef hi_u8 mac_need_init_scan_res_enum_uint8;

/* ɨ��״̬��ͨ���жϵ�ǰɨ���״̬���ж϶��ɨ������Ĵ�������Լ��ϱ�ɨ�����Ĳ��� */
typedef enum {
    MAC_SCAN_STATE_IDLE,
    MAC_SCAN_STATE_RUNNING,

    MAC_SCAN_STATE_BUTT
} mac_scan_state_enum;
typedef hi_u8 mac_scan_state_enum_uint8;

typedef enum {
    MAC_FCS_STATE_STANDBY        = 0,  // free to use
    MAC_FCS_STATE_REQUESTED,           // requested by other module, but not in switching
    MAC_FCS_STATE_IN_PROGESS,          // in switching

    MAC_FCS_STATE_BUTT
} mac_fcs_state_enum;
typedef hi_u8 mac_fcs_state_enum_uint8;

typedef enum {
    MAC_FCS_SUCCESS = 0,
    MAC_FCS_ERR_NULL_PTR,
    MAC_FCS_ERR_INVALID_CFG,
    MAC_FCS_ERR_BUSY,
    MAC_FCS_ERR_UNKNOWN_ERR,
} mac_fcs_err_enum;
typedef hi_u8   mac_fcs_err_enum_uint8;

typedef enum {
    MAC_ACS_RSN_INIT,
    MAC_ACS_RSN_LONG_TX_BUF,
    MAC_ACS_RSN_LARGE_PER,
    MAC_ACS_RSN_MWO_DECT,
    MAC_ACS_RSN_RADAR_DECT,

    MAC_ACS_RSN_BUTT
} mac_acs_rsn_enum;
typedef hi_u8 mac_acs_rsn_enum_uint8;

typedef enum {
    MAC_ACS_SW_NONE = 0x0,
    MAC_ACS_SW_INIT = 0x1,
    MAC_ACS_SW_DYNA = 0x2,
    MAC_ACS_SW_BOTH = 0x3,

    MAC_ACS_SW_BUTT
} mac_acs_sw_enum;
typedef hi_u8 en_mac_acs_sw_enum_uint8;

typedef enum {
    MAC_ACS_SET_CH_DNYA = 0x0,
    MAC_ACS_SET_CH_INIT = 0x1,

    MAC_ACS_SET_CH_BUTT
} mac_acs_set_ch_enum;
typedef hi_u8 en_mac_acs_set_ch_enum_uint8;

/* ɨ������¼�����״̬�� */
typedef enum {
    MAC_SCAN_SUCCESS = 0,       /* ɨ��ɹ� */
    MAC_SCAN_TIMEOUT = 2,       /* ɨ�賬ʱ */
    MAC_SCAN_REFUSED = 3,       /* ɨ�豻�ܾ� */
    MAC_SCAN_STATUS_BUTT,       /* ��Ч״̬�룬��ʼ��ʱʹ�ô�״̬�� */
} mac_scan_status_enum;
typedef hi_u8   mac_scan_status_enum_uint8;

/*****************************************************************************
  STRUCT����
*****************************************************************************/
typedef void (*mac_scan_cb_fn)(void *p_scan_record);

typedef struct {
    hi_u32  offset_addr;
    hi_u32  value[MAC_FCS_MAX_CHL_NUM];
} mac_fcs_reg_record_stru;

typedef struct tag_mac_fcs_mgr_stru {
    volatile hi_u8              fcs_done;
    mac_fcs_state_enum_uint8    fcs_state;
    hi_u8                       vap_id;    /* Ŀ���ŵ���Ӧ��vap id,�������ô��� */
    hi_u8                       uc_resv;
} mac_fcs_mgr_stru;

/* device reset�¼�ͬ���ṹ�� */
typedef struct {
    mac_reset_sys_type_enum_uint8   reset_sys_type;  /* ��λͬ������ */
    hi_u8                           value;           /* ͬ����Ϣֵ */
    hi_u8                           uc_resv[2];      /* 2 byteԤ���ֶ� */
} mac_reset_sys_stru;

typedef struct {
    hi_u16                    us_num_networks;
    mac_ch_type_enum_uint8    ch_type;
    hi_u8                     auc_resv;
} mac_ap_ch_info_stru;

typedef struct {
    hi_u16    us_num_networks;    /* ��¼��ǰ�ŵ���ɨ�赽��BSS���� */
    hi_u8     auc_resv[2];        /* 2 byteԤ���ֶ� */
    hi_u8     auc_bssid_array[WLAN_MAX_SCAN_BSS_PER_CH][WLAN_MAC_ADDR_LEN];  /* ��¼��ǰ�ŵ���ɨ�赽������BSSID */
} mac_bss_id_list_stru;

/* PNOɨ����Ϣ�ṹ�� */
typedef struct {
    hi_s8           ac_match_ssid_set[MAX_PNO_SSID_COUNT][WLAN_SSID_MAX_LEN];
    hi_u8           auc_sour_mac_addr[WLAN_MAC_ADDR_LEN];   /* probe req֡��Я���ķ��Ͷ˵�ַ */
    hi_u8           pno_scan_repeat;                     /* pnoɨ���ظ����� */
    hi_u8           is_random_mac_addr_scan;             /* �Ƿ����mac */
    hi_s32          l_ssid_count;                           /* �·�����Ҫƥ���ssid���ĸ��� */
    hi_s32          l_rssi_thold;                           /* ���ϱ���rssi���� */
    hi_u32          pno_scan_interval;                   /* pnoɨ���� */
    mac_scan_cb_fn  fn_cb;                               /* ����ָ������������˼�ͨ�ų����� */
} mac_pno_scan_stru;

/* PNO����ɨ�����ṹ�� */
typedef struct {
    mac_pno_scan_stru       pno_sched_scan_params;             /* pno����ɨ������Ĳ��� */
    /* frw_timeout_stru      st_pno_sched_scan_timer;             pno����ɨ�趨ʱ�� */
    /* pno����ɨ��rtcʱ�Ӷ�ʱ�����˶�ʱ����ʱ���ܹ�����˯�ߵ�device */
    hi_void                 *pno_sched_scan_timer;
    hi_u8                   curr_pno_sched_scan_times;         /* ��ǰpno����ɨ����� */
    hi_u8                   is_found_match_ssid;               /* �Ƿ�ɨ�赽��ƥ���ssid */
    hi_u8                   auc_resv[2]; /* 2 byteԤ���ֶ� */
} mac_pno_sched_scan_mgmt_stru;

/* ɨ������ṹ�� */
typedef struct {
    wlan_mib_desired_bsstype_enum_uint8 bss_type;            /* Ҫɨ���bss���� */
    wlan_scan_type_enum_uint8           scan_type;           /* ����/���� */
    hi_u8                               auc_sour_mac_addr[WLAN_MAC_ADDR_LEN];    /* probe req֡��Я���ķ��Ͷ˵�ַ */

    hi_u8                               max_scan_cnt_per_channel       : 4,   /* ÿ���ŵ���ɨ����� */
                                        max_send_probe_cnt_per_channel : 4;   /* ÿ�η���ɨ������֡�ĸ�����Ĭ��Ϊ1 */
    hi_u8                               curr_channel_scan_count        : 4,   /* ��¼��ǰ�ŵ���ɨ����� */
                                        is_p2p0_scan                  : 1,   /* �Ƿ�Ϊp2p0 ����ɨ�� */
                                        working_in_home_chan           : 1,
                                        need_switch_back_home_channel  : 1,   /* ɨ����һ���ŵ��Ƿ�Ҫ�лع����ŵ� */
                                        is_random_mac_addr_scan        : 1;   /* �Ƿ������mac addrɨ�� */
    hi_u8                               auc_bssid[WLAN_SCAN_REQ_MAX_BSS][WLAN_MAC_ADDR_LEN];    /* ������bssid */

    hi_s8                               ac_ssid[WLAN_SCAN_REQ_MAX_BSS][WLAN_SSID_MAX_LEN];      /* ������ssid */
    hi_u8                               last_channel_band;
    hi_u8                               scan_func;                   /* DMAC SCANNER ɨ��ģʽ */
    hi_u8                               p2p0_listen_channel;         /* ��¼�ϲ��·���p2 plisten channel */

    mac_channel_stru                    ast_channel_list[WLAN_MAX_CHANNEL_NUM];
    wlan_scan_mode_enum_uint8           scan_mode : 4;          /* ɨ��ģʽ:ǰ��ɨ�� or ����ɨ�� */
    hi_u8                               vap_id    : 4;          /* �·�ɨ�������vap id */
    hi_u8                               channel_nums;           /* �ŵ��б����ŵ��ĸ��� */
    hi_u8                               channel_interval;
    hi_u16                              us_scan_time;           /* ɨ����ĳһ�ŵ�ͣ����ʱ���ɨ�����, 10��������ms */

    hi_u64                              ull_cookie;             /* P2P �����·���cookie ֵ */
    hi_u32                              resv2;
    mac_scan_cb_fn                      fn_cb;                  /* �ص�����ָ�� */
} mac_scan_req_stru;

/* ��ӡ���ձ��ĵ�rssi��Ϣ�ĵ��Կ�����صĽṹ�� */
typedef struct {
    hi_u32     rssi_debug_switch;        /* ��ӡ���ձ��ĵ�rssi��Ϣ�ĵ��Կ��� */
    hi_u32     rx_comp_isr_interval;     /* ������ٸ���������жϴ�ӡһ��rssi��Ϣ */
    hi_u32     curr_rx_comp_isr_count;   /* һ�ּ���ڣ���������жϵĲ������� */
} mac_rssi_debug_switch_stru;

/* ACS ����ظ���ʽ */
typedef struct {
    hi_u8  cmd;
    hi_u8  chip_id;
    hi_u8  device_id;
    hi_u8  uc_resv;

    hi_u32 len;      /* �ܳ��ȣ���������ǰ4���ֽ� */
    hi_u32 cmd_cnt;  /* ����ļ��� */
} mac_acs_response_hdr_stru;

typedef struct {
    hi_u8                       sw_when_connected_enable : 1;
    hi_u8                       drop_dfs_channel_enable  : 1;
    hi_u8                       lte_coex_enable          : 1;
    en_mac_acs_sw_enum_uint8    acs_switch               : 5;
} mac_acs_switch_stru;

/* DMAC SCAN �ŵ�ɨ��BSS��ϢժҪ�ṹ */
typedef struct {
    hi_s8                               rssi;                     /* bss���ź�ǿ�� */
    hi_u8                               channel_number;          /* �ŵ��� */
    hi_u8                               auc_bssid[WLAN_MAC_ADDR_LEN];

    /* 11n, 11ac��Ϣ */
    hi_u8                               ht_capable;             /* �Ƿ�֧��ht */
    hi_u8                               vht_capable;            /* �Ƿ�֧��vht */
    wlan_bw_cap_enum_uint8              bw_cap;                 /* ֧�ֵĴ��� 0-20M 1-40M */
    wlan_channel_bandwidth_enum_uint8   channel_bandwidth;      /* �ŵ��������� */
} mac_scan_bss_stats_stru;

/* DMAC SCAN �ŵ�ͳ�Ʋ�������ṹ�� */
typedef struct {
    hi_u8   channel_number;      /* �ŵ��� */
    hi_u8   auc_resv[3];         /* 3 byteԤ���ֶ� */

    hi_u8   stats_cnt;           /* �ŵ���æ��ͳ�ƴ��� */
    hi_u8   free_power_cnt;      /* �ŵ����й��� */
    hi_s16  s_free_power_stats_20_m;
    hi_s16  s_free_power_stats_40_m;
    hi_s16  s_free_power_stats_80_m;

    hi_u32  total_stats_time_us;
    hi_u32  total_free_time_20_m_us;
    hi_u32  total_free_time_40_m_us;
    hi_u32  total_free_time_80_m_us;
    hi_u32  total_send_time_us;
    hi_u32  total_recv_time_us;
} mac_scan_chan_stats_stru;

typedef struct {
    hi_s8                               rssi;                         /* bss���ź�ǿ�� */
    hi_u8                               channel_number;              /* �ŵ��� */

    hi_u8                               ht_capable   : 1;            /* �Ƿ�֧��ht */
    hi_u8                               vht_capable  : 1;            /* �Ƿ�֧��vht */
    wlan_bw_cap_enum_uint8              bw_cap       : 3;            /* ֧�ֵĴ��� 0-20M 1-40M */
    wlan_channel_bandwidth_enum_uint8   channel_bandwidth : 3;       /* �ŵ��������� */
} mac_scan_bss_stats_simple_stru;

/* DMAC SCAN �ص��¼��ṹ�� */
typedef struct {
    hi_u8                   nchans;      /* �ŵ�����       */
    hi_u8                   nbss;        /* BSS���� */
    hi_u8                   scan_func;   /* ɨ�������Ĺ��� */

    hi_u8                   need_rank    : 1; // kernel write, app read
    hi_u8                   obss_on      : 1;
    hi_u8                   dfs_on       : 1;
    hi_u8                   uc_resv         : 1;
    hi_u8                   chip_id      : 2;
    hi_u8                   device_id    : 2;
} mac_scan_event_stru;

/* bss��ȫ�����Ϣ�ṹ�� */
typedef struct {
    hi_u8 bss_80211i_mode;                                  /* ָʾ��ǰAP�İ�ȫ��ʽ��WPA��WPA2��BIT0: WPA; BIT1:WPA2 */
    hi_u8 rsn_grp_policy;                                   /* ���ڴ��WPA2��ʽ�£�AP���鲥�����׼���Ϣ */
    hi_u8 auc_rsn_pairwise_policy[MAC_PAIRWISE_CIPHER_SUITES_NUM]; /* ���ڴ��WPA2��ʽ�£�AP�ĵ��������׼���Ϣ */
    hi_u8 auc_rsn_auth_policy[MAC_AUTHENTICATION_SUITE_NUM];       /* ���ڴ��WPA2��ʽ�£�AP����֤�׼���Ϣ */
    hi_u8 auc_rsn_cap[2];                                   /* 2 byte ���ڱ���RSN������Ϣ��ֱ�Ӵ�֡������copy���� */
    hi_u8 auc_wpa_pairwise_policy[MAC_PAIRWISE_CIPHER_SUITES_NUM]; /* ���ڴ��WPA��ʽ�£�AP�ĵ��������׼���Ϣ */
    hi_u8 auc_wpa_auth_policy[MAC_AUTHENTICATION_SUITE_NUM];       /* ���ڴ��WPA��ʽ�£�AP����֤�׼���Ϣ */
    hi_u8 wpa_grp_policy;                                       /* ���ڴ��WPA��ʽ�£�AP���鲥�����׼���Ϣ */
    hi_u8 grp_policy_match;                                     /* ���ڴ��ƥ����鲥�׼� */
    hi_u8 pairwise_policy_match;                                /* ���ڴ��ƥ��ĵ����׼� */
    hi_u8 auth_policy_match;                                    /* ���ڴ��ƥ�����֤�׼� */
} mac_bss_80211i_info_stru;

/* ɨ���� */
typedef struct {
    mac_scan_status_enum_uint8  scan_rsp_status;
    hi_u8                   auc_resv[7]; /* 7 byteԤ���ֶ� */
    hi_u64                  ull_cookie;
} mac_scan_rsp_stru;

/* ɨ�赽��BSS�����ṹ�� */
typedef struct {
    /* ������Ϣ */
    wlan_mib_desired_bsstype_enum_uint8 bss_type;                    /* bss�������� */
    hi_u8                           dtim_period;                     /* dtime���� */
    hi_u8                           dtim_cnt;                        /* dtime cnt */
    hi_u8                           ntxbf;                           /* 11n txbf */
    hi_u8                           new_scan_bss;                    /* �Ƿ�����ɨ�赽��BSS */
    hi_u8                           auc_resv1[1];
    hi_s8                           rssi;                             /* bss���ź�ǿ�� */
    hi_char                         ac_ssid[WLAN_SSID_MAX_LEN];         /* ����ssid */
    hi_u16                          us_beacon_period;                   /* beacon���� */
    hi_u16                          us_cap_info;                        /* ����������Ϣ */
    hi_u8                           auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* ���������� mac��ַ��bssid��ͬ */
    hi_u8                           auc_bssid[WLAN_MAC_ADDR_LEN];       /* ����bssid */
    mac_channel_stru                channel;                         /* bss���ڵ��ŵ� */
    hi_u8                           wmm_cap;                         /* �Ƿ�֧��wmm */
    hi_u8                           uapsd_cap;                       /* �Ƿ�֧��uapsd */
    hi_u8                           desired;                         /* ��־λ����bss�Ƿ��������� */
    hi_u8                           num_supp_rates;                  /* ֧�ֵ����ʼ����� */
    hi_u8                           auc_supp_rates[WLAN_MAX_SUPP_RATES]; /* ֧�ֵ����ʼ� */
    hi_u8                           need_drop;                           /* �жϵ�ǰɨ�����Ƿ���Ҫ���� */
    hi_u8                           auc_resv2[3];                        /* reserve 3byte */
#ifdef _PRE_WLAN_FEATURE_11D
    hi_char                         ac_country[WLAN_COUNTRY_STR_LEN];   /* �����ַ��� */
    hi_u8                           auc_resv3[1];
#endif
    hi_u8                           is_mesh_accepting_peer;          /* �Ƿ�֧��Mesh���� */
    hi_u8                           is_hisi_mesh;                    /* �Ƿ���HISI-MESH�ڵ� */

#ifdef _PRE_WLAN_FEATURE_ANY
    hi_u8                           supp_any;
    hi_u8                           is_any_sta;
#endif

    /* ��ȫ��ص���Ϣ */
    mac_bss_80211i_info_stru        bss_sec_info;                    /* ���ڱ���STAģʽ�£�ɨ�赽��AP��ȫ�����Ϣ */

    /* 11n 11ac��Ϣ */
    hi_u8                           ht_capable;                      /* �Ƿ�֧��ht */
    hi_u8                           vht_capable;                     /* �Ƿ�֧��vht */
    wlan_bw_cap_enum_uint8              bw_cap;                      /* ֧�ֵĴ��� 0-20M 1-40M */
    wlan_channel_bandwidth_enum_uint8   channel_bandwidth;           /* �ŵ����� */
    hi_u8                           coex_mgmt_supp;                  /* �Ƿ�֧�ֹ������ */
    hi_u8                           ht_ldpc;                         /* �Ƿ�֧��ldpc */
    hi_u8                           ht_stbc;                         /* �Ƿ�֧��stbc */
    hi_u8                           wapi;
    hi_u32                          timestamp;                       /* ���´�bss��ʱ��� */

    /* ����֡��Ϣ */
    hi_u32                          mgmt_len;                        /* ����֡�ĳ��� */
    hi_u8                           auc_mgmt_buff[4];                /* 4 byte ��¼beacon֡��probe rsp֡ */
} mac_bss_dscr_stru;

typedef struct {
    hi_u32                          tx_seqnum;                        /* ���һ��tx�ϱ���SN�� */
    hi_u16                          us_seqnum_used_times;                /* ���ʹ����ul_tx_seqnum�Ĵ��� */
    hi_u16                          us_incr_constant;                    /* ά����Qos ��Ƭ֡�ĵ������� */
} mac_tx_seqnum_struc;

typedef struct {
    hi_u64                          ull_send_action_id;          /* P2P action id/cookie */
    hi_u64                          ull_last_roc_id;
    hi_u8                           p2p_device_num:4,            /* ��ǰdevice�µ�P2P_DEVICE���� MAX 1 */
                                    p2p_goclient_num:4;          /* ��ǰdevice�µ�P2P_CL/P2P_GO���� MAX 1 */
    hi_u8                           p2p0_vap_idx;
    /* P2P0/P2P_CL ����VAP �ṹ�����������±���VAP �������ǰ��״̬ */
    mac_vap_state_enum_uint8        last_vap_state;
    hi_u8                           p2p_ps_pause;                /* P2P �����Ƿ���pause״̬ */
    oal_nl80211_channel_type_uint8  listen_channel_type;
    hi_u8                           resv[7];                     /* reserve 7byte */
    oal_ieee80211_channel_stru      st_listen_channel;
} mac_p2p_info_stru;

/* device�ṹ�� */
typedef struct {
    /* device�µ�vap���˴�ֻ��¼VAP ID */
    hi_u8                               auc_vap_id[WLAN_SERVICE_VAP_NUM_PER_DEVICE];
    hi_u8                               vap_num           : 3,             /* ��ǰdevice�µ�ҵ��VAP����(AP+STA) MAX 3 */
                                        sta_num           : 3,             /* ��ǰdevice�µ�STA���� MAX 2 */
                                        reset_in_progress : 1,             /* ��λ������ */
    /* ��ʶ�Ƿ��Ѿ������䣬(HI_TRUE��ʼ����ɣ�HI_FALSEδ��ʼ�� ) */
                                        device_state      : 1;
    /* ��eeprom��flash��õ�mac��ַ��ko����ʱ����hal�ӿڸ�ֵ */
    hi_u8                               auc_hw_addr[WLAN_MAC_ADDR_LEN];
    /* ������VAP���ŵ��ţ�����VAP����ֵ�������ֵì�ܣ����ڷ�DBACʱʹ�� */
    hi_u8                               max_channel;
    /* ������VAP��Ƶ�Σ�����VAP����ֵ�������ֵì�ܣ����ڷ�DBACʱʹ�� */
    wlan_channel_band_enum_uint8        max_band;

    /* ������VAP���������ֵ������VAP����ֵ�������ֵì�ܣ����ڷ�DBACʱʹ�� */
    wlan_channel_bandwidth_enum_uint8   max_bandwidth;
    wlan_protocol_cap_enum_uint8        protocol_cap;                        /* Э������ */
    wlan_band_cap_enum_uint8            band_cap;                            /* Ƶ������ */
    wlan_bw_cap_enum_uint8              bandwidth_cap;                       /* �������� */

    hi_u8                               wmm          : 1,                    /* wmmʹ�ܿ��� */
                                        reset_switch : 1,                    /* �Ƿ�ʹ�ܸ�λ���� */
                                        dbac_same_ch : 1,                    /* �Ƿ�ͬ�ŵ�dbac */
                                        in_suspend   : 1,
                                        dbac_enabled : 1,
                                        dbac_running : 1,                    /* DBAC�Ƿ������� */
                                        dbac_has_vip_frame : 1,              /* ���DBAC����ʱ�յ��˹ؼ�֡ */
                                        arpoffload_switch  : 1;
    hi_u8                               ldpc_coding : 1,                    /* �Ƿ�֧�ֽ���LDPC����İ� */
                                        tx_stbc     : 1,                    /* �Ƿ�֧������2x1 STBC���� */
                                        rx_stbc     : 3,                    /* �Ƿ�֧��stbc���� */
                                        promis_switch : 1,                  /* ����ģʽ���� */
                                        mu_bfmee    : 1,                    /* �Ƿ�֧�ֶ��û�beamformee */
                                        resv        : 1;
    hi_s16                              s_upc_amend;         /* UPC����ֵ */
    hi_u32                              duty_ratio_lp;       /* ����͹���ǰ����ռ�ձ� */
    hi_u32                              rx_nondir_duty_lp;   /* ����͹���ǰ����non-direct����ռ�ձ� */
    hi_u32                              rx_dir_duty_lp;      /* ����͹���ǰ����direct����ռ�ձ� */
    hi_u32                              beacon_interval;     /* device����beacon interval,device������VAPԼ��Ϊͬһֵ */
    hi_u32                              duty_ratio;          /* ռ�ձ�ͳ�� */

    mac_data_rate_stru                  mac_rates_11g[MAC_DATARATES_PHY_80211G_NUM];  /* 11g���� */
    mac_pno_sched_scan_mgmt_stru       *pno_sched_scan_mgmt; /* pno����ɨ�����ṹ��ָ�룬�ڴ涯̬���룬�Ӷ���ʡ�ڴ� */
    mac_scan_req_stru                   scan_params;         /* ����һ�ε�ɨ�������Ϣ */
    frw_timeout_stru                    scan_timer;          /* ɨ�趨ʱ�������л��ŵ� */
    frw_timeout_stru                    obss_scan_timer;     /* obssɨ�趨ʱ����ѭ����ʱ�� */
    mac_channel_stru                    p2p_vap_channel;     /* p2p listenʱ��¼p2p���ŵ�������p2p listen������ָ� */
    frw_timeout_stru                    go_scan_timer;
    frw_timeout_stru                    keepalive_timer;                    /* keepalive��ʱ�� */

    hi_u8                               tid;
    hi_u8                               asoc_user_cnt;                      /* �����û��� */
    hi_u8                               wapi;
    hi_u8                               sar_pwr_limit;                      /* CE��֤SAR��׼��������� */
    /* linux�ں��е�device������Ϣ */
    /* ���ڴ�ź�VAP��ص�wiphy�豸��Ϣ����AP/STAģʽ�¾�Ҫʹ�ã����Զ��VAP��Ӧһ��wiphy */
    oal_wiphy_stru                     *wiphy;

    /* ���Device�ĳ�Ա�����ƶ���dmac_device OFFLOADģʽ�¿���DEVICE���� */
    hi_u8                               scan_chan_idx;                       /* ��ǰɨ���ŵ����� */
    /* ��ǰɨ��״̬�����ݴ�״̬����obssɨ���host���·���ɨ�������Լ�ɨ�������ϱ����� */
    mac_scan_state_enum_uint8           curr_scan_state;
    hi_u8                               auc_original_mac_addr[WLAN_MAC_ADDR_LEN]; /* ɨ�迪ʼǰ����ԭʼ��MAC��ַ */
    mac_channel_stru                    home_channel;                        /* ��¼�����ŵ� ���л�ʱʹ�� */
    mac_scan_chan_stats_stru            chan_result;                         /* dmacɨ��ʱ һ���ŵ����ŵ�������¼ */
    mac_fcs_mgr_stru                    fcs_mgr;
    mac_p2p_info_stru                   p2p_info;                           /* P2P �����Ϣ */
    /* ÿ��AP����һ��CSA֡���ü�����1��AP�л����ŵ��󣬸ü������� */
    hi_u8                               csa_cnt;
    hi_u8                               txop_enable;                        /* �����޾ۺ�ʱ����TXOPģʽ */
    hi_u8                               tx_ba_num;                          /* ���ͷ���BA�Ự���� */
    hi_u8                               nss_num;
    hi_u32                               auc_resv;                          /* Ԥ���ֶ� */
} mac_device_stru;

#pragma pack(push, 1)
/* �ϱ���ɨ��������չ��Ϣ�������ϱ�host��Ĺ���֡netbuf�ĺ��� */
typedef struct {
    hi_s32                           l_rssi;                    /* �ź�ǿ�� */
    wlan_mib_desired_bsstype_enum_uint8 bss_type;               /* ɨ�赽��bss���� */
    hi_u8                           channel;                    /* ��ǰɨ����ŵ� */
    hi_u8                           auc_resv[2];                /* 2 byteԤ���ֶ� */
} mac_scanned_result_extend_info_stru;
#pragma pack(pop)

typedef struct {
    mac_device_stru                    *mac_device;
} mac_wiphy_priv_stru;

/*****************************************************************************
  ��������
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : mac_is_dbac_running
 ��������  : �ж϶�Ӧdevice��dbac�����Ƿ�������
 �������  : mac_device_stru *pst_device
 �� �� ֵ  : static  inline  hi_u8
 �޸���ʷ      :
  1.��    ��   : 2014��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_is_dbac_running(const mac_device_stru *mac_dev)
{
    return mac_dev->dbac_enabled && mac_dev->dbac_running;
}

/*****************************************************************************
 ��������  : ����֡�Ƿ���Ҫ��tid����
 �������  : mac_device_stru *pst_device
             mac_vap_stru *pst_vap
 �޸���ʷ      :
  1.��    ��   : 2014��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_need_enqueue_tid_for_dbac(const mac_device_stru *mac_dev, const mac_vap_stru *mac_vap)
{
    return (mac_dev->dbac_enabled && (mac_vap->vap_state == MAC_VAP_STATE_PAUSE));
}

static inline hi_u8 mac_device_is_scaning(const mac_device_stru *mac_dev)
{
    return (mac_dev->curr_scan_state == MAC_SCAN_STATE_RUNNING);
}

static  inline  hi_u8 mac_device_is_listening(const mac_device_stru *mac_dev)
{
    return ((mac_dev->curr_scan_state == MAC_SCAN_STATE_RUNNING)
            && (mac_dev->scan_params.scan_func & MAC_SCAN_FUNC_P2P_LISTEN));
}

static inline hi_void mac_device_set_channel(mac_device_stru *mac_dev,
                                             const mac_cfg_channel_param_stru *channel_param)
{
    mac_dev->max_channel = channel_param->channel;
    mac_dev->max_band = channel_param->band;
    mac_dev->max_bandwidth = channel_param->en_bandwidth;
}

static inline hi_void mac_device_get_channel(const mac_device_stru *mac_dev,
                                             mac_cfg_channel_param_stru *channel_param)
{
    channel_param->channel = mac_dev->max_channel;
    channel_param->band = mac_dev->max_band;
    channel_param->en_bandwidth = mac_dev->max_bandwidth;
}

/*****************************************************************************
   ��������
*****************************************************************************/
mac_device_stru* mac_res_get_dev(hi_void);
const hi_u8 *mac_get_mac_bcast_addr(hi_void);
hi_void mac_device_init(mac_device_stru *mac_dev);
hi_void mac_device_set_vap_id(mac_device_stru *mac_dev, mac_vap_stru *mac_vap,
                              const mac_cfg_add_vap_param_stru *param, hi_u8 vap_idx, hi_u8 is_add_vap);
hi_void mac_device_find_up_vap(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap);
hi_u8 mac_device_has_other_up_vap(const mac_device_stru *mac_dev, const mac_vap_stru *mac_vap_ref);
hi_u32 mac_device_calc_up_vap_num(const mac_device_stru *mac_dev);
hi_u32 mac_device_find_up_vap_with_mode(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap,
    wlan_vap_mode_enum_uint8 vap_mode);
hi_u32 mac_device_find_up_p2p_go(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap);
hi_u32 mac_device_find_2up_vap(const mac_device_stru *mac_dev, mac_vap_stru **mac_vap1, mac_vap_stru **mac_vap2);
hi_u32 mac_device_is_p2p_connected(const mac_device_stru *mac_dev);

hi_void mac_fcs_release(mac_fcs_mgr_stru *fcs_mgr);
hi_u8 mac_fcs_get_protect_cnt(const mac_vap_stru *mac_vap);
hi_u32 mac_fcs_get_prot_datarate(const mac_vap_stru *mac_vap);
hi_u8  mac_fcs_get_fake_q_id(const mac_vap_stru *mac_vap);

hi_void mac_fcs_init(mac_fcs_mgr_stru *fcs_mgr);
mac_fcs_err_enum_uint8 mac_fcs_request(mac_fcs_mgr_stru *fcs_mgr);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __MAC_DEVICE_H__ */
