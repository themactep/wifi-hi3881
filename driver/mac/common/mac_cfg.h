/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_cfg.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_CFG_H__
#define __MAC_CFG_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  �궨��
*****************************************************************************/
#define MAC_NUM_2G_BAND             3           /* 2g band���� */
#define MAC_NUM_2G_CH_NUM           13          /* 2g �ŵ����� */
/*****************************************************************************
  ö�ٶ���
*****************************************************************************/
typedef enum {
    MAC_CFG_RETRY_DATA      = 0,
    MAC_CFG_RETRY_MGMT      = 1,
    MAC_CFG_RETRY_TIMEOUT   = 2,
    MAC_CFG_RETRY_TYPE_BUTT,
}mac_cfg_retry_type_enum;
typedef hi_u8 mac_cfg_retry_type_enum_uint8;

typedef enum {
    MAC_PSM_OFFSET_TBTT,
    MAC_PSM_OFFSET_EXT_TBTT,
    MAC_PSM_OFFSET_BCN_TIMEOUT,
#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
    MAC_PSM_FREE_ARP_INTERVAL
#endif
} mac_cfg_psm_offset_type;
typedef hi_u8 mac_cfg_psm_offset_type_uint8;

typedef enum {
    MAC_STA_PM_SWITCH_OFF         = 0,        /* �رյ͹��� */
    MAC_STA_PM_SWITCH_ON          = 1,        /* �򿪵͹��� */
    MAC_STA_PM_MANUAL_MODE_ON     = 2,        /* �����ֶ�sta pm mode */
    MAC_STA_PM_MANUAL_MODE_OFF    = 3,        /* �ر��ֶ�sta pm mode */
    MAC_STA_PM_SWITCH_BUTT,                   /* ������� */
}mac_pm_switch_enum;
typedef hi_u8 mac_pm_switch_enum_uint8;

typedef enum {
    MAC_STA_PM_CTRL_TYPE_HOST    = 0,        /* �͹��Ŀ������� HOST */
    MAC_STA_PM_CTRL_TYPE_DBAC    = 1,        /* �͹��Ŀ������� DBAC */
    MAC_STA_PM_CTRL_TYPE_MONITOR = 2,        /* �͹��Ŀ������� MONITOR */
    MAC_STA_PM_CTRL_TYPE_CSI     = 3,        /* �͹��Ŀ������� CSI */
    MAC_STA_PM_CTRL_TYPE_ANY     = 4,        /* �͹��Ŀ������� ANY */
    MAC_STA_PM_CTRL_TYPE_FLOW    = 5,        /* �͹��Ŀ������� FLOW */
    MAC_STA_PM_CTRL_TYPE_BTCOEX  = 6,        /* �͹��Ŀ������� BTCOEX */
    MAC_STA_PM_CTRL_TYPE_BUTT,               /* ������ͣ�ӦС��8 */
}mac_pm_ctrl_type_enum;
typedef hi_u8 mac_pm_ctrl_type_enum_uint8;

/**
 * enum nl80211_mfp - Management frame protection state
 * @NL80211_MFP_NO: Management frame protection not used
 * @NL80211_MFP_REQUIRED: Management frame protection required
 */
typedef enum {
    MAC_NL80211_MFP_NO,
    MAC_NL80211_MFP_REQUIRED,

    MAC_NL80211_MFP_BUTT
}mac_nl80211_mfp_enum;
typedef hi_u8 mac_nl80211_mfp_enum_uint8;

/* ���÷����������ڲ�Ԫ�ؽṹ�� */
typedef enum {
    RF_PAYLOAD_ALL_ZERO = 0,
    RF_PAYLOAD_ALL_ONE,
    RF_PAYLOAD_RAND,
    RF_PAYLOAD_BUTT
}mac_rf_payload_enum;
typedef hi_u8 mac_rf_payload_enum_uint8;

#ifdef _PRE_WLAN_FEATURE_MESH
typedef enum {
    HISI_PLINK_IDLE = 1,
    HISI_PLINK_OPN_SNT,
    HISI_PLINK_OPN_RCVD,
    HISI_PLINK_CNF_RCVD,
    HISI_PLINK_ESTAB,
    HISI_PLINK_HOLDING,
    HISI_PLINK_BLOCKED,

    HISI_PLINK_BUTT
}mac_mesh_plink_state_enum;
typedef hi_u8 mac_mesh_plink_state_enum_uint8;
#endif

/* ���÷���������֡����ö�� */
typedef enum {
    MAC_SET_DSCR_TYPE_UCAST_DATA  = 0,  /* ��������֡ */
    MAC_SET_DSCR_TYPE_MCAST_DATA,       /* �鲥����֡ */
    MAC_SET_DSCR_TYPE_BCAST_DATA,       /* �㲥����֡ */
    MAC_SET_DSCR_TYPE_UCAST_MGMT_2G,    /* ��������֡,��2G */
    MAC_SET_DSCR_TYPE_MBCAST_MGMT_2G,   /* �顢�㲥����֡,��2G */

    MAC_SET_DSCR_TYPE_BUTT,
} mac_set_dscr_frame_type_enum;
typedef hi_u8 mac_set_dscr_frame_type_enum_uint8;

#ifdef _PRE_WLAN_FEATURE_MESH
/* mesh�ڵ�����ö�� */
typedef enum {
    MAC_HISI_MESH_UNSPEC = 0, /* δȷ��mesh�ڵ��ɫ */
    MAC_HISI_MESH_STA,        /* Mesh-STA�ڵ��ɫ */
    MAC_HISI_MESH_MG,         /* Mesh-MG�ڵ��ɫ */
    MAC_HISI_MESH_MBR,        /* Mesh-MBR�ڵ��ɫ */

    MAC_HISI_MESH_NODE_BUTT,
} mac_hisi_mesh_node_type_enum;
typedef hi_u8 mac_hisi_mesh_node_type_enum_uint8;
#endif

typedef enum {
    WLAN_11B_PHY_PROTOCOL_MODE              = 0,   /* 11b CCK */
    WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE      = 1,   /* 11g/a OFDM */
    WLAN_HT_PHY_PROTOCOL_MODE               = 2,   /* 11n HT */
    WLAN_VHT_PHY_PROTOCOL_MODE              = 3,   /* 11ac VHT */
    WLAN_PHY_PROTOCOL_BUTT
}wlan_phy_protocol_enum;
typedef hi_u8 wlan_phy_protocol_enum_uint8;

/*****************************************************************************
  �ṹ�嶨��
*****************************************************************************/
typedef struct {
    hi_u8                        param;      /* ��ѯ��������Ϣ */
    wlan_phy_protocol_enum_uint8     protocol_mode;
    mac_rf_payload_enum_uint8        payload_flag;
    wlan_tx_ack_policy_enum_uint8    ack_policy;
    hi_u32                       payload_len;
}mac_cfg_tx_comp_stru;

typedef struct {
    hi_u8                   offset_addr_a;
    hi_u8                   offset_addr_b;
    hi_u16                  us_delta_gain;
}mac_cfg_dbb_scaling_stru;

/* wfa edca�������� */
typedef struct {
    hi_u8             switch_code;              /* ���� */
    hi_u8     ac;                               /* AC */
    hi_u16                      us_val;         /* ���� */
}mac_edca_cfg_stru;

/* PPM���������ʽ */
typedef struct {
    hi_s8                     ppm_val;         /* PPM��ֵ */
    hi_u8                    clock_freq;       /* ʱ��Ƶ�� */
    hi_u8                    uc_resv[1];
}mac_cfg_adjust_ppm_stru;

/* ��������������ṹ�� */
typedef struct {
    hi_void *mac_regdom;
}mac_cfg_country_stru;

/* ����������͹������� */
typedef struct {
    hi_u8 pwr;
    hi_u8 exceed_reg;
    hi_u8 auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_regdomain_max_pwr_stru;

/* ��ȡ��ǰ������������ַ���������ṹ�� */
typedef struct {
    hi_char    ac_country[WLAN_COUNTRY_STR_LEN];
    hi_u8      auc_resv[1];
}mac_cfg_get_country_stru;

/* query��Ϣ��ʽ:2�ֽ�WID x N */
typedef struct {
    hi_u8 tid;
    hi_u8 uc_resv[3]; /* 3 byte�����ֶΣ���֤word���� */
}mac_cfg_get_tid_stru;

/* ���ƻ� linkloss�������ò��� */
typedef struct {
    hi_u8                   linkloss_threshold_wlan_near;
    hi_u8                   linkloss_threshold_wlan_far;
    hi_u8                   linkloss_threshold_p2p;
    hi_u8                   auc_resv[1];
}mac_cfg_linkloss_threshold;

/* ���ƻ� power ref 2g 5g���ò��� */
typedef struct {
    hi_u32                  power_ref_2g;
}mac_cfg_power_ref;

/* customize rf cfg struct */
typedef struct {
    hi_s8                    rf_gain_db_2g_mult4;             /* �ⲿPA/LNA bypassʱ������(0.25dB) */
    hi_s8                    rf_gain_db_2g_mult10;            /* �ⲿPA/LNA bypassʱ������(0.1dB) */
}mac_cfg_gain_db_2g_band;

typedef struct {
    mac_cfg_gain_db_2g_band ac_gain_db_2g[MAC_NUM_2G_BAND];
}mac_cfg_customize_rf;

#ifdef _PRE_WLAN_FEATURE_MESH
typedef struct _mac_cfg_set_mesh_user_param_stru {
    hi_u8 auc_addr[WLAN_MAC_ADDR_LEN];
    mac_mesh_plink_state_enum_uint8 plink_sta;
    hi_u8 set;
    hi_u8 bcn_prio;
    hi_u8 is_mbr;
    hi_u8 mesh_initiative_peering;
}mac_cfg_set_mesh_user_param_stru;

typedef struct _mac_cfg_set_multi_mac_addr_stru {
    hi_u8 auc_addr[WLAN_MAC_ADDR_LEN];
    hi_u8 set;   /* 0 - ɾ��ĳ�ಥ��ַ��1 - ����ĳ�ಥ��ַ */
    hi_u8 rsv;
} mac_cfg_set_multi_mac_addr_stru;

typedef mac_cfg_set_multi_mac_addr_stru mac_cfg_unset_multi_mac_addr_stru;

typedef struct _mac_cfg_auto_peer_params_stru {
    hi_s8 rssi_low;                    /* �û����ٵ�ʱ���õ�rssi���� */
    hi_s8 rssi_middle;                 /* �û������е�ʱ���õ�rssi���� */
    hi_s8 rssi_high;                   /* �û������ʱ���õ�rssi���� */
}mac_cfg_auto_peer_params_stru;

typedef struct _mac_cfg_mesh_nodeinfo_stru {
    mac_hisi_mesh_node_type_enum_uint8 node_type;   /* ���ڵ��ɫ */
    hi_u8 mesh_accept_sta;                          /* �Ƿ����sta���� */
    hi_u8 user_num;                                 /* �����û��� */
    hi_u8 privacy;                                  /* �Ƿ���� */
    hi_u8 chan;                                     /* �ŵ��� */
    hi_u8 priority;                                 /* bcn���ȼ� */
    hi_u8 rsv[2];                                   /* 2 byte���� */
}mac_cfg_mesh_nodeinfo_stru;
#endif

/* ����֡��FCSͳ����Ϣ */
typedef struct {
    hi_u32  data_op;    /* ���ݲ���ģʽ:<0>����,<1>��� */
    hi_u32  print_info; /* ��ӡ��������:<0>�������� <1>��֡�� <2>self fcs correct, <3>other fcs correct, <4>fcs error */
} mac_cfg_rx_fcs_info_stru;

/* �޳��û������������ */
typedef struct {
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u16              us_reason_code;                     /* ȥ���� reason code */
}mac_cfg_kick_user_param_stru;

/* ��ͣtid����������� */
typedef struct {
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u8               tid;
    hi_u8               is_paused;
}mac_cfg_pause_tid_param_stru;

/* �����û��Ƿ�Ϊvip */
typedef struct {
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u8               vip_flag;
}mac_cfg_user_vip_param_stru;

/* ��ͣtid����������� */
typedef struct {
    hi_u8               aggr_tx_on;
    hi_u8               tid;
    hi_u8               max_num;
    hi_u8               resv;
}mac_cfg_ampdu_tx_on_param_stru;

#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
/* ����hostĳ�����е�ÿ�ε��ȱ��ĸ�����low_waterline, high_waterline */
typedef struct {
    hi_u8               queue_type;
    hi_u8               auc_resv[1];
    hi_u16              us_burst_limit;
    hi_u16              us_low_waterline;
    hi_u16              us_high_waterline;
}mac_cfg_flowctl_param_stru;
#endif

/* ʹ��qempty���� */
typedef struct {
    hi_u8   is_on;
    hi_u8   auc_resv[3]; /* 3 byte�����ֶΣ���֤word���� */
}mac_cfg_resume_qempty_stru;

/* ����mpdu/ampdu�������  */
typedef struct {
    hi_u8               tid;
    hi_u8               packet_num;
    hi_u16              us_packet_len;
    hi_u8               auc_ra_mac[OAL_MAC_ADDR_LEN];
}mac_cfg_mpdu_ampdu_tx_param_stru;
/* AMPDU��ص������������ */
typedef struct {
    hi_u8                       auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* �û���MAC ADDR */
    hi_u8                       tidno;                              /* ��Ӧ��tid�� */
    hi_u8                       auc_reserve[1];                     /* ȷ�ϲ��� */
}mac_cfg_ampdu_start_param_stru;

typedef mac_cfg_ampdu_start_param_stru mac_cfg_ampdu_end_param_stru;

/* BA�Ự��ص������������ */
typedef struct {
    hi_u8                       auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* �û���MAC ADDR */
    hi_u8                       tidno;                              /* ��Ӧ��tid�� */
    mac_ba_policy_enum_uint8        ba_policy;                      /* BAȷ�ϲ��� */
    hi_u16                      us_buff_size;                       /* BA���ڵĴ�С */
    hi_u16                      us_timeout;                         /* BA�Ự�ĳ�ʱʱ�� */
}mac_cfg_addba_req_param_stru;

typedef struct {
    hi_u8                       auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* �û���MAC ADDR */
    hi_u8                       tidno;                              /* ��Ӧ��tid�� */
    mac_delba_initiator_enum_uint8  direction;                      /* ɾ��ba�Ự�ķ���� */
    hi_u8                       auc_reserve[1];                     /* ɾ��ԭ�� */
}mac_cfg_delba_req_param_stru;

typedef struct {
    hi_u8                           auc_mac_addr[WLAN_MAC_ADDR_LEN];
    hi_u8                           amsdu_max_num;   /* amsdu������ */
    hi_u8                           auc_reserve;
}mac_cfg_amsdu_start_param_stru;

/* �����û����ò��� */
typedef struct {
    hi_u8                               function_index;
    hi_u8                               auc_reserve[2]; /* 2 byte�����ֶΣ���֤word���� */
    mac_set_dscr_frame_type_enum_uint8      type;       /* ���õ�֡���� */
    hi_s32                               l_value;
}mac_cfg_set_dscr_param_stru;

/* non-HTЭ��ģʽ���������ýṹ�� */
typedef struct {
    wlan_legacy_rate_value_enum_uint8       rate;            /* ����ֵ */
    wlan_phy_protocol_enum_uint8            protocol_mode;   /* ��Ӧ��Э�� */
    hi_u8                               auc_reserve[2];      /* 2 byte���� */
}mac_cfg_non_ht_rate_stru;

/* �û���ص������������ */
typedef struct {
    hi_u8     auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u8     ht_cap;                          /* ht���� */
    hi_u8     user_idx;              /* �û����� */
}mac_cfg_add_user_param_stru;
typedef mac_cfg_add_user_param_stru mac_cfg_del_user_param_stru;

/* ���ƻ� ʱ�����ò��� */
typedef struct {
    hi_u32                  rtc_clk_freq;
    hi_u8                   clk_type;
    hi_u8                   auc_resv[3]; /* 3 byte�����ֶΣ���֤word���� */
}mac_cfg_pm_param;

typedef struct {
    mac_cfg_psm_offset_type_uint8 type;
    hi_u8  resv;
    hi_u16 value;
} mac_cfg_psm_offset;

typedef struct {
    hi_u16                  us_tx_ratio;                        /* txռ�ձ� */
    hi_u16                  us_tx_pwr_comp_val;                 /* ���书�ʲ���ֵ */
}mac_tx_ratio_vs_pwr_stru;

/* ���ƻ�TXռ�ձ�&�¶Ȳ������书�ʵĲ��� */
typedef struct {
    mac_tx_ratio_vs_pwr_stru ast_txratio2pwr[3];                /* 3��ռ�ձȷֱ��Ӧ���ʲ���ֵ */
    hi_u32                   more_pwr;                          /* �����¶ȶ��ⲹ���ķ��书�� */
}mac_cfg_customize_tx_pwr_comp_stru;

typedef struct {
    mac_cfg_retry_type_enum_uint8       type;
    hi_u8                               limit;
    hi_u8                               auc_rsv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_retry_param_stru;

typedef struct {
    hi_u8                               auc_mac_da[WLAN_MAC_ADDR_LEN];
    hi_u8                               category;
    hi_u8                               auc_resv[1];
}mac_cfg_send_action_param_stru;

typedef struct {
    hi_s32   l_is_psm;                           /* �Ƿ������� */
    hi_s32   l_is_qos;                           /* �Ƿ�qosnull */
    hi_s32   l_tidno;                            /* tid�� */
}mac_cfg_tx_nulldata_stru;

/* ��ȡmpdu��Ŀ��Ҫ�Ĳ��� */
typedef struct {
    hi_u8                   auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    hi_u8                   auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_get_mpdu_num_stru;

#ifdef _PRE_DEBUG_MODE
typedef struct {
    hi_u8                   auc_user_macaddr[WLAN_MAC_ADDR_LEN];
    hi_u8                   param;
    hi_u8                   tid_no;
}mac_cfg_ampdu_stat_stru;
#endif

typedef struct {
    hi_u8                   aggr_num_switch; /* ���ƾۺϸ������� */
    hi_u8                   aggr_num;        /* �ۺϸ��� */
    hi_u8                   auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_aggr_num_stru;

typedef struct {
    hi_u32   mib_idx;
    hi_u32   mib_value;
}mac_cfg_set_mib_stru;

typedef struct {
    hi_u8  bypass_type;
    hi_u8  value;
    hi_u8  auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_set_thruput_bypass_stru;

typedef struct {
    hi_u8  performance_log_switch_type;
    hi_u8  value;
    hi_u8  auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_set_performance_log_switch_stru;

typedef struct {
    hi_u32   timeout;
    hi_u8    is_period;
    hi_u8    stop_start;
    hi_u8    auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_test_timer_stru;

typedef struct {
    hi_u8    user_idx;
    hi_u8    uc_resv;
    hi_u16   us_rx_pn;
}mac_cfg_set_rx_pn_stru;

typedef struct {
    hi_u32   frag_threshold;
}mac_cfg_frag_threshold_stru;

typedef struct {
    hi_u32   rts_threshold;
}mac_cfg_rts_threshold_stru;

typedef struct {
    /* software_retryֵ */
    hi_u8   software_retry;
    /* �Ƿ�ȡtest���õ�ֵ��Ϊ0��Ϊ������������ */
    hi_u8   retry_test;
    hi_u8   resv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg_set_soft_retry_stru;

/* STA PS ���Ͳ��� */
#ifdef _PRE_WLAN_FEATURE_STA_PM
typedef struct {
    hi_u8   vap_ps_mode;
}mac_cfg_ps_mode_param_stru;

typedef struct {
    hi_u16   beacon_timeout;
    hi_u16   tbtt_offset;
    hi_u16   ext_tbtt_offset;
}mac_cfg_ps_param_stru;
#endif

typedef struct {
    hi_u8   show_ip_addr                 :4;  /* show ip addr */
    hi_u8   show_arpoffload_info         :4;  /* show arpoffload ά�� */
}mac_cfg_arpoffload_info_stru;

typedef struct {
    hi_u8   in_suspend;        /* ������ */
    hi_u8   arpoffload_switch; /* arpoffload���� */
}mac_cfg_suspend_stru;

typedef struct {
    mac_pm_ctrl_type_enum_uint8     pm_ctrl_type;       /* mac_pm_ctrl_type_enum */
    mac_pm_switch_enum_uint8        pm_enable;          /* mac_pm_switch_enum */
}mac_cfg_ps_open_stru;

/* ======================== cfg id��Ӧ�Ĳ����ṹ�� ==================================== */
/* ����VAP�����ṹ��, ��Ӧcfgid: WLAN_CFGID_ADD_VAP */
typedef struct {
    wlan_vap_mode_enum_uint8  vap_mode;
    hi_u8                 cfg_vap_indx;
    hi_u8                 muti_user_id;          /* ���vap ��Ӧ��muti user index */
    hi_u8                 vap_id;                /* ��Ҫ��ӵ�vap id */

    wlan_p2p_mode_enum_uint8  p2p_mode;              /* 0:��P2P�豸; 1:P2P_GO; 2:P2P_Device; 3:P2P_CL */
    hi_u8                 ac2g_enable           :1,
                          disable_capab_2ght40  :1,
                          uapsd_enable    :1,
                          reserve1        :5;
    hi_u8                 auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
    oal_net_device_stru      *net_dev;
}mac_cfg_add_vap_param_stru;
typedef mac_cfg_add_vap_param_stru mac_cfg_del_vap_param_stru;

/* Э����� ��Ӧcfgid: WLAN_CFGID_MODE */
typedef struct {
    wlan_protocol_enum_uint8            protocol;       /* Э�� */
    wlan_channel_band_enum_uint8        band;           /* Ƶ�� */
    wlan_channel_bandwidth_enum_uint8   en_bandwidth;   /* ���� */
    hi_u8                           channel_idx;        /* ��20M�ŵ��� */
}mac_cfg_mode_param_stru;

/* ����VAP�����ṹ�� ��Ӧcfgid: WLAN_CFGID_START_VAP */
typedef struct {
    hi_u8         mgmt_rate_init_flag;      /* start vapʱ�򣬹���֡�����Ƿ���Ҫ��ʼ�� */
    hi_u8         protocol;
    hi_u8         band;
    hi_u8         uc_bandwidth;
#ifdef _PRE_WLAN_FEATURE_P2P_ROM
    wlan_p2p_mode_enum_uint8   p2p_mode;
    hi_u8                      auc_resv2[3]; /* 3 byte�����ֶΣ���֤word���� */
#endif
    oal_net_device_stru *net_dev;
}mac_cfg_start_vap_param_stru;
typedef mac_cfg_start_vap_param_stru mac_cfg_down_vap_param_stru;

/* ����mac��ַ���� ��Ӧcfgid: WLAN_CFGID_STATION_ID */
typedef struct {
    hi_u8                   auc_station_id[WLAN_MAC_ADDR_LEN];
    wlan_p2p_mode_enum_uint8    p2p_mode;
    hi_u8                   auc_resv[1];
}mac_cfg_staion_id_param_stru;

/* SSID���� ��Ӧcfgid: WLAN_CFGID_SSID */
typedef struct {
    hi_u8   ssid_len;
    hi_u8   auc_resv[2]; /* 2 byte�����ֶΣ���֤word���� */
    hi_char ac_ssid[WLAN_SSID_MAX_LEN];
}mac_cfg_ssid_param_stru;

/* HOSTAPD ���ù���Ƶ�Σ��ŵ��ʹ������ */
typedef struct {
    wlan_channel_band_enum_uint8        band;        /* Ƶ�� */
    wlan_channel_bandwidth_enum_uint8   en_bandwidth;   /* ���� */
    hi_u8                           channel;     /* �ŵ���� */
    hi_u8                           rsv;
}mac_cfg_channel_param_stru;

/* HOSTAPD ����wiphy �����豸��Ϣ������RTS ����ֵ����Ƭ��������ֵ */
typedef struct {
    hi_u8  frag_threshold_changed;
    hi_u8  rts_threshold_changed;
    hi_u8  rsv[2]; /* 2 byte�����ֶΣ���֤word���� */
    hi_u32 frag_threshold;
    hi_u32 rts_threshold;
}mac_cfg_wiphy_param_stru;

/* P2P OPS �������ò��� */
typedef struct {
    hi_s32 ops_ctrl;
    hi_u8 ct_window;
    hi_u8 resv[3]; /* reserve 3byte */
    hi_s32 pause_ops;
} mac_cfg_p2p_ops_param_stru;

/* P2P NOA�������ò��� */
typedef struct {
    hi_u32 start_time;
    hi_u32 duration;
    hi_u32 interval;
    hi_u8  count;
    hi_u8  resv[3]; /* 3 byte�����ֶΣ���֤word���� */
} mac_cfg_p2p_noa_param_stru;

/* P2P ���ܿ������� */
typedef struct {
    hi_u8 p2p_statistics_ctrl;    /* 0:���P2P ͳ��ֵ�� 1:��ӡ���ͳ��ֵ */
    hi_u8 auc_rsv[3]; /* 3 byte�����ֶΣ���֤word���� */
} mac_cfg_p2p_stat_param_stru;

/* �鲥ת���� ���Ͳ��� */
typedef struct {
    hi_u8 m2u_mcast_mode;
    hi_u8 m2u_snoop_on;
}mac_cfg_m2u_snoop_on_param_stru;

/* =================== ����Ϊ�����ں����ò���ת��Ϊ�����ڲ������·��Ľṹ�� ======================== */
/* �����ں����õ�ɨ��������·���������ɨ����� */
typedef struct {
    oal_ssids_stru          ssids[WLAN_SCAN_REQ_MAX_BSS];
    hi_u32                  l_ssid_num;
    const hi_u8            *puc_ie;
    hi_u32                  ie_len;
    hi_u32                 *pul_channels_2_g;
    /* WLAN/P2P ��������£�p2p0 ��p2p-p2p0 cl ɨ��ʱ����Ҫʹ�ò�ͬ�豸������bit_is_p2p0_scan������ */
    hi_u8                   is_p2p0_scan : 1;       /* �Ƿ�Ϊp2p0 ����ɨ�� */
    hi_u8                   rsv          : 7;       /* ����λ */
    hi_u8                   scan_type;
    hi_u8                   num_channels_2_g;
    hi_u8                   auc_arry;
}mac_cfg80211_scan_param_stru;

typedef struct {
    mac_cfg80211_scan_param_stru  *mac_cfg80211_scan_param;
}mac_cfg80211_scan_param_pst_stru;

/* �����ں����õ�connect�������·���������connect���� */
typedef struct {
    hi_u8               wpa_versions;
    hi_u8               cipher_group;
    hi_u8               n_ciphers_pairwise;
    hi_u8               ciphers_pairwise[OAL_NL80211_MAX_NR_CIPHER_SUITES];
    hi_u8               n_akm_suites;
    hi_u8               akm_suites[OAL_NL80211_MAX_NR_AKM_SUITES];

    hi_u8     control_port;
}mac_cfg80211_crypto_settings_stru;

typedef struct {
    hi_u8                           channel;              /* ap�����ŵ���ţ�eg 1,2,11,36,40... */
    hi_u8                           ssid_len;             /* SSID ���� */
    mac_nl80211_mfp_enum_uint8          mfp;
    hi_u8                           wapi;

    hi_u8                          *puc_ie;
    hi_u8                          *puc_ssid;               /* ����������AP SSID  */
    hi_u8                          *puc_bssid;              /* ����������AP BSSID  */

    hi_u8                 privacy;                          /* �Ƿ���ܱ�־ */
    oal_nl80211_auth_type_enum_uint8    auth_type;          /* ��֤���ͣ�OPEN or SHARE-KEY */

    hi_u8                           wep_key_len;         /* WEP KEY���� */
    hi_u8                           wep_key_index;       /* WEP KEY���� */
    const hi_u8                *puc_wep_key;             /* WEP KEY��Կ */

    mac_cfg80211_crypto_settings_stru   crypto;          /* ��Կ�׼���Ϣ */
    hi_u32                          ie_len;
}mac_cfg80211_connect_param_stru;

typedef struct {
    hi_u8                               privacy;             /* �Ƿ���ܱ�־ */
    oal_nl80211_auth_type_enum_uint8    auth_type;           /* ��֤���ͣ�OPEN or SHARE-KEY */
    hi_u8                               wep_key_len;         /* WEP KEY���� */
    hi_u8                               wep_key_index;       /* WEP KEY���� */
    hi_u8                               auc_wep_key[WLAN_WEP104_KEY_LEN];            /* WEP KEY��Կ */
    mac_nl80211_mfp_enum_uint8          mgmt_proteced;       /* ��������pmf�Ƿ�ʹ�� */
    wlan_pmf_cap_status_uint8           pmf_cap;             /* �豸pmf���� */
    hi_u8                               wps_enable;

    mac_cfg80211_crypto_settings_stru   crypto;              /* ��Կ�׼���Ϣ */
    hi_s8                               rssi;                /* ����AP��RSSI��Ϣ */
    hi_u8                               auc_rsv[3]; /* 3 byte�����ֶΣ���֤word���� */
}mac_cfg80211_connect_security_stru;

typedef struct {
    hi_u8       auc_mac_addr[OAL_MAC_ADDR_LEN];
    hi_u8       auc_rsv[2]; /* 2 byte�����ֶΣ���֤word���� */
}mac_cfg80211_init_port_stru;

#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
typedef enum {
    MAC_CONFIG_IPV4 = 0,                /* ����IPv4��ַ */
    MAC_CONFIG_IPV6,                    /* ����IPv6��ַ */
    MAC_CONFIG_BUTT
}mac_ip_type;
typedef hi_u8 mac_ip_type_enum_uint8;

typedef enum {
    MAC_IP_ADDR_DEL = 0,                /* ɾ��IP��ַ */
    MAC_IP_ADDR_ADD,                    /* ����IP��ַ */
    MAC_IP_OPER_BUTT
}mac_ip_oper;
typedef hi_u8 mac_ip_oper_enum_uint8;

typedef struct {
    mac_ip_type_enum_uint8 type;
    mac_ip_oper_enum_uint8 oper;
    hi_u8 resv[2];                     /* ���2�ֽ� */
    union {
        hi_u32 ipv4; /* ע�⣺�����ֽ��򡢴�ˡ� */
        hi_u8  ipv6[OAL_IP_ADDR_MAX_SIZE];
    } ip;
} mac_ip_addr_config_stru;
#endif

typedef struct {
    hi_u8  band_num;
    hi_u8  resv[3];  /* 3 byte�����ֶ� */
    hi_s32 offset;
} mac_cfg_cal_bpower;

typedef struct {
    hi_u8  protol;
    hi_u8  rate;
    hi_u8  resv[2];  /* 2 byte�����ֶ� */
    hi_s32 val;
} mac_cfg_cal_rpower;

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __MAC_CFG_H__ */
