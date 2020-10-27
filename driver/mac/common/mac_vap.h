/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_vap.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_VAP_H__
#define __MAC_VAP_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "mac_user.h"
#include "mac_cfg.h"
#include "mac_regdomain.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define MAC_VAP_RES_ID_INVALID          0xFF /* �Ƿ���vap res idֵ */
#define MAC_NUM_DR_802_11A              8    /* 11A 5gģʽʱ����������(DR)���� */
#define MAC_NUM_BR_802_11A              3    /* 11A 5gģʽʱ�Ļ�������(BR)���� */
#define MAC_NUM_NBR_802_11A             5    /* 11A 5gģʽʱ�ķǻ�������(NBR)���� */

#define MAC_NUM_DR_802_11B              4    /* 11B 2.4Gģʽʱ����������(DR)���� */
#define MAC_NUM_BR_802_11B              2    /* 11B 2.4Gģʽʱ����������(BR)���� */
#define MAC_NUM_NBR_802_11B             2    /* 11B 2.4Gģʽʱ����������(NBR)���� */

#define MAC_NUM_DR_802_11G              8    /* 11G 2.4Gģʽʱ����������(DR)���� */
#define MAC_NUM_BR_802_11G              3    /* 11G 2.4Gģʽʱ�Ļ�������(BR)���� */
#define MAC_NUM_NBR_802_11G             5    /* 11G 2.4Gģʽʱ�ķǻ�������(NBR)���� */

#define MAC_NUM_DR_802_11G_MIXED        12   /* 11G ���ģʽʱ����������(DR)���� */
#define MAC_NUM_BR_802_11G_MIXED_ONE    4    /* 11G ���1ģʽʱ�Ļ�������(BR)���� */
#define MAC_NUM_NBR_802_11G_MIXED_ONE   8    /* 11G ���1ģʽʱ�ķǻ�������(NBR)���� */

#define MAC_NUM_BR_802_11G_MIXED_TWO    7    /* 11G ���2ģʽʱ�Ļ�������(BR)���� */
#define MAC_NUM_NBR_802_11G_MIXED_TWO   5    /* 11G ���2ģʽʱ�ķǻ�������(NBR)���� */

#define MAC_MAX_RATE_SINGLE_NSS_20M_11N 0   /* 1���ռ���20MHz��������� */
#define MAC_MAX_RATE_SINGLE_NSS_40M_11N 0   /* 1���ռ���40MHz��������� */
#define MAC_MAX_RATE_DOUBLE_NSS_20M_11N 0   /* 1���ռ���80MHz��������� */
#define MAC_MAX_RATE_DOUBLE_NSS_40M_11N 0   /* 2���ռ���20MHz��������� */
/* 11AC MCS��ص����� */
#define MAC_MAX_SUP_MCS7_11AC_EACH_NSS   0   /* 11AC���ռ���֧�ֵ����MCS��ţ�֧��0-7 */
#define MAC_MAX_SUP_MCS8_11AC_EACH_NSS   1   /* 11AC���ռ���֧�ֵ����MCS��ţ�֧��0-8 */
#define MAC_MAX_SUP_MCS9_11AC_EACH_NSS   2   /* 11AC���ռ���֧�ֵ����MCS��ţ�֧��0-9 */
#define MAC_MAX_UNSUP_MCS_11AC_EACH_NSS  3   /* 11AC���ռ���֧�ֵ����MCS��ţ���֧��n���ռ��� */

#define MAC_MAX_RATE_SINGLE_NSS_20M_11AC 86  /* 1���ռ���20MHz��������� */
#define MAC_MAX_RATE_SINGLE_NSS_40M_11AC 200 /* 1���ռ���40MHz��������� */
#define MAC_MAX_RATE_SINGLE_NSS_80M_11AC 433 /* 1���ռ���80MHz��������� */
#define MAC_MAX_RATE_DOUBLE_NSS_20M_11AC 173 /* 2���ռ���20MHz��������� */
#define MAC_MAX_RATE_DOUBLE_NSS_40M_11AC 400 /* 2���ռ���40MHz��������� */
#define MAC_MAX_RATE_DOUBLE_NSS_80M_11AC 866 /* 2���ռ���80MHz��������� */

#define MAC_MESH_MAX_ID                     64        /* MBR+MR�ڵ����ID�� */
#define MAC_MESH_INVALID_ID                 0         /* Mesh MBR/MR�ڵ���ЧID�� */
#define MAC_MESH_DEFAULT_ID                 255       /* Mesh MBR�ڵ�Ĭ��ID�ţ�����Ĭ��id����tbtt������ֵ */
#define MAC_MESH_MAX_MBR_NUM                5         /* MBR�ڵ������Ŀ */

#define MAC_VAP_USER_HASH_MAX_VALUE         4         /* 31H���֧��8���û� ������HASHͰ����1�� */
/* HASH����ȡMAC���������� ���͸��Ӷ� */
#define mac_calculate_hash_value(_puc_mac_addr)     \
    (((_puc_mac_addr)[4] + (_puc_mac_addr)[5]) & (MAC_VAP_USER_HASH_MAX_VALUE - 1))

#define is_ap(_pst_mac_vap)  ((WLAN_VAP_MODE_BSS_AP  == (_pst_mac_vap)->vap_mode) || \
    ((_pst_mac_vap)->vap_mode == WLAN_VAP_MODE_MESH))

#define is_sta(_pst_mac_vap) (WLAN_VAP_MODE_BSS_STA == (_pst_mac_vap)->vap_mode)
#define is_p2p_dev(_pst_mac_vap)    (WLAN_P2P_DEV_MODE    == (_pst_mac_vap)->p2p_mode)
#define is_p2p_go(_pst_mac_vap)     (WLAN_P2P_GO_MODE     == (_pst_mac_vap)->p2p_mode)
#define is_p2p_cl(_pst_mac_vap)     (WLAN_P2P_CL_MODE     == (_pst_mac_vap)->p2p_mode)
#define is_legacy_vap(_pst_mac_vap) (WLAN_LEGACY_VAP_MODE == (_pst_mac_vap)->p2p_mode)

#define MAC_SEND_TWO_DEAUTH_FLAG    0xf000

#ifdef _PRE_WLAN_FEATURE_WOW
#define MAC_SSID_WAKEUP_TIME        (50 * 60)   /* 5 ����,��λ100ms */
#endif

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
#define MAC_MAX_REPORT_TIME         6           /* ״̬ΪTX_SUCCʱ�������ϱ��ĸ�����ֵ */
#define MAC_MAX_REPORT_TX_CNT       10          /* ��Ҫ�ϱ��ķ��ʹ�����ֵ����ʼֵͬDMAC_MAX_SW_RETRIES */
#endif

#ifdef _PRE_WLAN_FEATURE_WOW_ROM
#define WOW_NETPATTERN_MAX_NUM      4
#define WOW_NETPATTERN_MAX_LEN      64
#endif

#define H2D_SYNC_MASK_BARK_PREAMBLE (1<<1)
#define H2D_SYNC_MASK_MIB           (1<<2)
#define H2D_SYNC_MASK_PROT          (1<<3)

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/* VAP״̬����AP STA����һ��״̬ö�� */
typedef enum {
    /* ap sta����״̬ */
    MAC_VAP_STATE_INIT               = 0,
    MAC_VAP_STATE_UP                 = 1,       /* VAP UP */
    MAC_VAP_STATE_PAUSE              = 2,       /* pause , for ap &sta */
    /* ap ����״̬ */
    MAC_VAP_STATE_AP_WAIT_START      = 3,
    /* sta����״̬ */
    MAC_VAP_STATE_STA_FAKE_UP        = 4,
    MAC_VAP_STATE_STA_WAIT_SCAN      = 5,
    MAC_VAP_STATE_STA_SCAN_COMP      = 6,
    MAC_VAP_STATE_STA_JOIN_COMP      = 7,
    MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2 = 8,
    MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4 = 9,
    MAC_VAP_STATE_STA_AUTH_COMP      = 10,
    MAC_VAP_STATE_STA_WAIT_ASOC      = 11,
    MAC_VAP_STATE_STA_OBSS_SCAN      = 12,
    MAC_VAP_STATE_STA_BG_SCAN        = 13,
    MAC_VAP_STATE_STA_LISTEN         = 14, /* p2p0 ���� */
    MAC_VAP_STATE_BUTT,
}mac_vap_state_enum;
typedef hi_u8  mac_vap_state_enum_uint8;

/* оƬ��֤������֡/����֡���� */
typedef enum {
    MAC_TEST_MGMT_BCST   =  0,  /* ��beacon�㲥����֡ */
    MAC_TEST_MGMT_MCST  =   1,  /* ��beacon�鲥����֡ */
    MAC_TEST_ATIM_UCST =    2,  /* ����ATIM֡ */
    MAC_TEST_UCST =         3,  /* ��������֡ */
    MAC_TEST_CTL_BCST =     4,  /* �㲥����֡ */
    MAC_TEST_CTL_MCST =     5,  /* �鲥����֡ */
    MAC_TEST_CTL_UCST =     6,  /* ��������֡ */
    MAC_TEST_ACK_UCST =     7,  /* ACK����֡ */
    MAC_TEST_CTS_UCST =     8,  /* CTS����֡ */
    MAC_TEST_RTS_UCST =     9,  /* RTS����֡ */
    MAC_TEST_BA_UCST =      10, /* BA����֡ */
    MAC_TEST_CF_END_UCST =  11, /* CF-End����֡ */
    MAC_TEST_TA_RA_EUQAL =  12, /* RA,TA��ͬ֡ */
    MAC_TEST_MAX_TYPE_NUM
}mac_test_frame_type;
typedef hi_u8 mac_test_frame_type_enum_uint8;

/* ���÷�������������ö�� */
typedef enum {
    MAC_SET_DSCR_PARAM_DATA0,          /* data0����Ӧ����������14�У�32bit 10����ֵ */
    MAC_SET_DSCR_PARAM_DATA1,          /* data1����Ӧ����������19�� */
    MAC_SET_DSCR_PARAM_DATA2,          /* data2����Ӧ����������20�� */
    MAC_SET_DSCR_PARAM_DATA3,          /* data3����Ӧ����������21�� */
    MAC_SET_DSCR_PARAM_RATE,           /* ����11b/g/n���� */
    MAC_SET_DSCR_PARAM_POWER,          /* tx power: ��Ӧ����������22�� */
    MAC_SET_DSCR_PARAM_SHORTGI,        /* ����short GI��long GI */

    MAC_SET_DSCR_PARAM_BUTT
}mac_set_dscr_param_enum;
typedef hi_u8 mac_set_dscr_param_enum_uint8;

typedef enum {
    /* ҵ������㷨���ò���,����ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_SCHEDULE_START,

    MAC_ALG_CFG_SCHEDULE_VI_CTRL_ENA,
    MAC_ALG_CFG_SCHEDULE_BEBK_MIN_BW_ENA,
    MAC_ALG_CFG_SCHEDULE_MVAP_SCH_ENA,
    MAC_ALG_CFG_FLOWCTRL_ENABLE_FLAG,
    MAC_ALG_CFG_SCHEDULE_VI_SCH_LIMIT,
    MAC_ALG_CFG_SCHEDULE_VO_SCH_LIMIT,
    MAC_ALG_CFG_SCHEDULE_VI_DROP_LIMIT,
    MAC_ALG_CFG_SCHEDULE_VI_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_VO_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_BE_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_BK_MSDU_LIFE_MS,
    MAC_ALG_CFG_SCHEDULE_VI_LOW_DELAY_MS,
    MAC_ALG_CFG_SCHEDULE_VI_HIGH_DELAY_MS,
    MAC_ALG_CFG_SCHEDULE_VI_CTRL_MS,
    MAC_ALG_CFG_SCHEDULE_SCH_CYCLE_MS,
    MAC_ALG_CFG_SCHEDULE_TRAFFIC_CTRL_CYCLE,
    MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS,
    MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS_BE,
    MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS_BK,
    MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS,
    MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS_BE,
    MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS_BK,
    MAC_ALG_CFG_SCHEDULE_CIR_VAP_KBPS,
    MAC_ALG_CFG_SCHEDULE_SM_TRAIN_DELAY,
    MAC_ALG_CFG_VIDEO_DROP_PKT_LIMIT,
    MAC_ALG_CFG_SCHEDULE_LOG_START,
    MAC_ALG_CFG_SCHEDULE_VAP_SCH_PRIO,
    MAC_ALG_CFG_SCHEDULE_LOG_END,
    MAC_ALG_CFG_SCHEDULE_END,
    /* AUTORATE�㷨���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_AUTORATE_START,
    MAC_ALG_CFG_AUTORATE_ENABLE,
    MAC_ALG_CFG_AUTORATE_USE_LOWEST_RATE,
    MAC_ALG_CFG_AUTORATE_SHORT_STAT_NUM,
    MAC_ALG_CFG_AUTORATE_SHORT_STAT_SHIFT,
    MAC_ALG_CFG_AUTORATE_LONG_STAT_NUM,
    MAC_ALG_CFG_AUTORATE_LONG_STAT_SHIFT,
    MAC_ALG_CFG_AUTORATE_MIN_PROBE_INTVL_PKTNUM,
    MAC_ALG_CFG_AUTORATE_MAX_PROBE_INTVL_PKTNUM,
    MAC_ALG_CFG_AUTORATE_PROBE_INTVL_KEEP_TIMES,
    MAC_ALG_CFG_AUTORATE_DELTA_GOODPUT_RATIO,
    MAC_ALG_CFG_AUTORATE_VI_PROBE_PER_LIMIT,
    MAC_ALG_CFG_AUTORATE_VO_PROBE_PER_LIMIT,
    MAC_ALG_CFG_AUTORATE_AMPDU_DURATION,
    MAC_ALG_CFG_AUTORATE_MCS0_CONT_LOSS_NUM,
    MAC_ALG_CFG_AUTORATE_UP_PROTOCOL_DIFF_RSSI,
    MAC_ALG_CFG_AUTORATE_RTS_MODE,
    MAC_ALG_CFG_AUTORATE_LEGACY_1ST_LOSS_RATIO_TH,
    MAC_ALG_CFG_AUTORATE_HT_VHT_1ST_LOSS_RATIO_TH,
    MAC_ALG_CFG_AUTORATE_LOG_ENABLE,
    MAC_ALG_CFG_AUTORATE_VO_RATE_LIMIT,
    MAC_ALG_CFG_AUTORATE_JUDGE_FADING_PER_TH,
    MAC_ALG_CFG_AUTORATE_AGGR_OPT,
    MAC_ALG_CFG_AUTORATE_AGGR_PROBE_INTVL_NUM,
    MAC_ALG_CFG_AUTORATE_DBG_VI_STATUS,
    MAC_ALG_CFG_AUTORATE_DBG_AGGR_LOG,
    MAC_ALG_CFG_AUTORATE_AGGR_NON_PROBE_PCK_NUM,
    MAC_ALG_CFG_AUTORATE_AGGR_MIN_AGGR_TIME_IDX,
    MAC_ALG_CFG_AUTORATE_MAX_AGGR_NUM,
    MAC_ALG_CFG_AUTORATE_LIMIT_1MPDU_PER_TH,
    MAC_ALG_CFG_AUTORATE_BTCOEX_PROBE_ENABLE,
    MAC_ALG_CFG_AUTORATE_BTCOEX_AGGR_ENABLE,
    MAC_ALG_CFG_AUTORATE_COEX_STAT_INTVL,
    MAC_ALG_CFG_AUTORATE_COEX_LOW_ABORT_TH,
    MAC_ALG_CFG_AUTORATE_COEX_HIGH_ABORT_TH,
    MAC_ALG_CFG_AUTORATE_COEX_AGRR_NUM_ONE_TH,
    MAC_ALG_CFG_AUTORATE_DYNAMIC_BW_ENABLE,
    MAC_ALG_CFG_AUTORATE_THRPT_WAVE_OPT,
    MAC_ALG_CFG_AUTORATE_GOODPUT_DIFF_TH,
    MAC_ALG_CFG_AUTORATE_PER_WORSE_TH,
    MAC_ALG_CFG_AUTORATE_RX_CTS_NO_BA_NUM,
    MAL_ALG_CFG_AUTORATE_VOICE_AGGR,
    MAC_ALG_CFG_AUTORATE_FAST_SMOOTH_SHIFT,
    MAC_ALG_CFG_AUTORATE_FAST_SMOOTH_AGGR_NUM,
    MAC_ALG_CFG_AUTORATE_SGI_PUNISH_PER,
    MAC_ALG_CFG_AUTORATE_SGI_PUNISH_NUM,
    MAC_ALG_CFG_AUTORATE_VI_HOLD_RATE_RSSI_TH,
    MAC_ALG_CFG_AUTORATE_VI_HOLDING_RATE,
    MAC_ALG_CFG_AUTORATE_END,
    /* AUTORATE�㷨��־���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_AUTORATE_LOG_START,
    MAC_ALG_CFG_AUTORATE_STAT_LOG_START,
    MAC_ALG_CFG_AUTORATE_SELECTION_LOG_START,
    MAC_ALG_CFG_AUTORATE_FIX_RATE_LOG_START,
    MAC_ALG_CFG_AUTORATE_STAT_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_SELECTION_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_FIX_RATE_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_AGGR_STAT_LOG_START,
    MAC_ALG_CFG_AUTORATE_AGGR_STAT_LOG_WRITE,
    MAC_ALG_CFG_AUTORATE_LOG_END,
    /* AUTORATE�㷨ϵͳ�����������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_AUTORATE_TEST_START,
    MAC_ALG_CFG_AUTORATE_DISPLAY_RATE_SET,
    MAC_ALG_CFG_AUTORATE_CONFIG_FIX_RATE,
    MAC_ALG_CFG_AUTORATE_CYCLE_RATE,
    MAC_ALG_CFG_AUTORATE_DISPLAY_RX_RATE,
    MAC_ALG_CFG_AUTORATE_TEST_END,
    /* �������㷨���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_ANTI_INTF_START,
    MAC_ALG_CFG_ANTI_INTF_IMM_ENABLE,
    MAC_ALG_CFG_ANTI_INTF_UNLOCK_ENABLE,
    MAC_ALG_CFG_ANTI_INTF_RSSI_STAT_CYCLE,
    MAC_ALG_CFG_ANTI_INTF_UNLOCK_CYCLE,
    MAC_ALG_CFG_ANTI_INTF_UNLOCK_DUR_TIME,
    MAC_ALG_CFG_ANTI_INTF_NAV_IMM_ENABLE,
    MAC_ALG_CFG_ANTI_INTF_GOODPUT_FALL_TH,
    MAC_ALG_CFG_ANTI_INTF_KEEP_CYC_MAX_NUM,
    MAC_ALG_CFG_ANTI_INTF_KEEP_CYC_MIN_NUM,
    MAC_ALG_CFG_ANTI_INTF_TX_TIME_FALL_TH,
    MAC_ALG_CFG_ANTI_INTF_PER_PROBE_EN,
    MAC_ALG_CFG_ANTI_INTF_PER_FALL_TH,
    MAC_ALG_CFG_ANTI_INTF_GOODPUT_JITTER_TH,
    MAC_ALG_CFG_ANTI_INTF_DEBUG_MODE,
    MAC_ALG_CFG_ANTI_INTF_END,
    /* EDCA�Ż��㷨���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_EDCA_OPT_START,
    MAC_ALG_CFG_EDCA_OPT_CO_CH_DET_CYCLE,
    MAC_ALG_CFG_EDCA_OPT_AP_EN_MODE,
    MAC_ALG_CFG_EDCA_OPT_STA_EN,
    MAC_ALG_CFG_EDCA_OPT_STA_WEIGHT,
    MAC_ALG_CFG_EDCA_OPT_NONDIR_TH,
    MAC_ALG_CFG_EDCA_OPT_TH_UDP,
    MAC_ALG_CFG_EDCA_OPT_TH_TCP,
    MAC_ALG_CFG_EDCA_OPT_DEBUG_MODE,
    MAC_ALG_CFG_EDCA_OPT_END,
    /* CCA�Ż��㷨���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_CCA_OPT_START,
    MAC_ALG_CFG_CCA_OPT_ALG_EN_MODE,
    MAC_ALG_CFG_CCA_OPT_DEBUG_MODE,
    MAC_ALG_CFG_CCA_OPT_SET_T1_COUNTER_TIME,
    MAC_ALG_CFG_CCA_OPT_END,
    /* CCA OPT�㷨��־���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_CCA_OPT_LOG_START,
    MAC_ALG_CFG_CCA_OPT_STAT_LOG_START,
    MAC_ALG_CFG_CCA_OPT_STAT_LOG_WRITE,
    MAC_ALG_CFG_CCA_OPT_LOG_END,

    /* TPC�㷨���ò���, ����ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_TPC_START,
    MAC_ALG_CFG_TPC_MODE,
    MAC_ALG_CFG_TPC_DEBUG,
    MAC_ALG_CFG_TPC_POWER_LEVEL,
    MAC_ALG_CFG_TPC_LOG,
    MAC_ALG_CFG_TPC_MANAGEMENT_MCAST_FRM_POWER_LEVEL,
    MAC_ALG_CFG_TPC_CONTROL_FRM_POWER_LEVEL,
    MAC_ALG_CFG_TPC_OVER_TMP_TH,
    MAC_ALG_CFG_TPC_DPD_ENABLE_RATE,
    MAC_ALG_CFG_TPC_TARGET_RATE_11B,
    MAC_ALG_CFG_TPC_TARGET_RATE_11AG,
    MAC_ALG_CFG_TPC_TARGET_RATE_HT20,
    MAC_ALG_CFG_TPC_NO_MARGIN_POW,
    MAC_ALG_CFG_TPC_POWER_AMEND,
    MAC_ALG_CFG_TPC_END,
    /* TPC�㷨��־���ò���������ӵ���Ӧ��START��END֮�� */
    MAC_ALG_CFG_TPC_LOG_START,
    MAC_ALG_CFG_TPC_STAT_LOG_START,
    MAC_ALG_CFG_TPC_STAT_LOG_WRITE,
    MAC_ALG_CFG_TPC_PER_PKT_LOG_START,
    MAC_ALG_CFG_TPC_PER_PKT_LOG_WRITE,
    MAC_ALG_CFG_TPC_GET_FRAME_POW,
    MAC_ALG_CFG_TPC_RESET_STAT,
    MAC_ALG_CFG_TPC_RESET_PKT,
    MAC_ALG_CFG_TPC_LOG_END,
    MAC_ALG_CFG_BUTT
}mac_alg_cfg_enum;
typedef hi_u8 mac_alg_cfg_enum_uint8;

typedef enum {           /* hi1131-cb */
    SHORTGI_20_CFG_ENUM,
    SHORTGI_40_CFG_ENUM,
    SHORTGI_80_CFG_ENUM,
    SHORTGI_BUTT_CFG
}short_gi_cfg_type;

typedef enum {
    MAC_SET_BEACON  = 0,
    MAC_ADD_BEACON  = 1,

    MAC_BEACON_OPERATION_BUTT
}mac_beacon_operation_type ;
typedef hi_u8 mac_beacon_operation_type_uint8;

typedef enum {
    MAC_WMM_SET_PARAM_TYPE_DEFAULT,
    MAC_WMM_SET_PARAM_TYPE_UPDATE_EDCA,

    MAC_WMM_SET_PARAM_TYPE_BUTT
}mac_wmm_set_param_type_enum;
typedef hi_u8 mac_wmm_set_param_type_enum_uint8;

#ifdef _PRE_WLAN_FEATURE_STA_UAPSD
typedef enum {
    MAC_APSD_SP_LEN_ALL  = 0,     /* ��Ӧbit5 bit6 Ϊ00 */
    MAC_APSD_SP_LEN_TWO  = 2,     /* ��Ӧbit5 bit6 Ϊ01 */
    MAC_APSD_SP_LEN_FOUR = 4,     /* ��Ӧbit5 bit6 Ϊ10 */
    MAC_APSD_SP_LEN_SIX  = 6,     /* ��Ӧbit5 bit6 Ϊ11 */
    MAC_APSD_SP_LEN_BUTT
}mac_apsd_sp_len_enum;
typedef hi_u8 mac_apsd_sp_len_enum_uint8;
#endif

#ifdef _PRE_WLAN_FEATURE_STA_PM
/* Power save modes specified by the user */
typedef enum {
    NO_POWERSAVE     = 0,
    MIN_FAST_PS      = 1,
    MAX_FAST_PS      = 2,
    MIN_PSPOLL_PS    = 3,
    MAX_PSPOLL_PS    = 4,
    NUM_PS_MODE      = 5
} ps_user_mode_enum;
typedef hi_u8 ps_user_mode_enum_uint8;
#endif

#define MAC_VAP_AP_STATE_BUTT       (MAC_VAP_STATE_AP_WAIT_START + 1)
#define MAC_VAP_STA_STATE_BUTT      MAC_VAP_STATE_BUTT

typedef enum {
    HISTREAM_SWITCH_OFF   = 0,        /* Histream ����ʹ�ܹر�  */
    HISTREAM_SWITCH_ON    = 1,        /* Histream ����ʹ�ܴ�  */
    HISTREAM_SWITCH_ON_BUTT,          /* ������ͣ�ӦС�� 8  */
}mac_histream_switch_enum;

#ifdef _PRE_WLAN_FEATURE_WOW
typedef enum {
    MAC_WOW_DISABLE,
    MAC_WOW_ENABLE,
    MAC_WOW_EN_BUTT
}mac_wow_en_enum;

typedef enum {
    MAC_WOW_WAKEUP_NOTIFY,
    MAC_WOW_SLEEP_REQUEST,
    MAC_WOW_NOTIFY_TYPE_BUTT
}mac_wow_notify_type_enum;

/* ȥ��������ͳһ�� MAC_WOW_FIELD_DISASSOC,
   MAC_WOW_FIELD_DISASSOC_RX ��û�� netbuf ���ݣ�Ŀǰ���� MAC_WOW_FIELD_DISASSOC_TX ������� */
typedef enum {
    MAC_WOW_FIELD_ALL_CLEAR          = 0,          /* Clear all events */
    MAC_WOW_FIELD_MAGIC_PACKET       = BIT0,       /* Wakeup on Magic Packet */
    MAC_WOW_FIELD_NETPATTERN_TCP     = BIT1,       /* Wakeup on TCP NetPattern */
    MAC_WOW_FIELD_NETPATTERN_UDP     = BIT2,       /* Wakeup on UDP NetPattern */
    MAC_WOW_FIELD_DISASSOC           = BIT3,       /* ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
    MAC_WOW_FIELD_AUTH_RX            = BIT4,       /* �Զ˹�������Wakeup on auth */
    MAC_WOW_FIELD_HOST_WAKEUP        = BIT5,       /* Host wakeup */
    MAC_WOW_FIELD_TCP_UDP_KEEP_ALIVE = BIT6,       /* Wakeup on TCP/UDP keep alive timeout */
    MAC_WOW_FIELD_OAM_LOG_WAKEUP     = BIT7,       /* OAM LOG wakeup */
    MAC_WOW_FIELD_SSID_WAKEUP        = BIT8,       /* SSID Scan wakeup */
}mac_wow_field_enum;

typedef enum {
    MAC_WOW_WKUP_REASON_TYPE_NULL               = 0,        /* None */
    MAC_WOW_WKUP_REASON_TYPE_MAGIC_PACKET       = 1,        /* Wakeup on Magic Packet */
    MAC_WOW_WKUP_REASON_TYPE_NETPATTERN_TCP     = 2,        /* Wakeup on TCP NetPattern */
    MAC_WOW_WKUP_REASON_TYPE_NETPATTERN_UDP     = 3,        /* Wakeup on UDP NetPattern */
    MAC_WOW_WKUP_REASON_TYPE_DISASSOC_RX        = 4,        /* �Զ�ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
    MAC_WOW_WKUP_REASON_TYPE_DISASSOC_TX        = 5,        /* �Զ�ȥ����/ȥ��֤��Wakeup on Disassociation/Deauth */
    MAC_WOW_WKUP_REASON_TYPE_AUTH_RX            = 6,        /* ���˶˹�������Wakeup on auth */
    MAC_WOW_WKUP_REASON_TYPE_TCP_UDP_KEEP_ALIVE = 7,        /* Wakeup on TCP/UDP keep alive timeout */
    MAC_WOW_WKUP_REASON_TYPE_HOST_WAKEUP        = 8,        /* Host wakeup */
    MAC_WOW_WKUP_REASON_TYPE_OAM_LOG            = 9,        /* OAM LOG wakeup */
    MAC_WOW_WKUP_REASON_TYPE_SSID_SCAN          = 10,       /* SSID Scan wakeup */
    MAC_WOW_WKUP_REASON_TYPE_BUT
}mac_wow_wakeup_reason_type_enum;
#endif

/*****************************************************************************
  STRUCT����
*****************************************************************************/
/* channel�ṹ�� */
typedef struct {
    hi_u8                           chan_number;         /* ��20MHz�ŵ��� */
    wlan_channel_band_enum_uint8        band;            /* Ƶ�� */
    wlan_channel_bandwidth_enum_uint8   en_bandwidth;    /* ����ģʽ */
    hi_u8                           idx;                 /* �ŵ������� */
}mac_channel_stru;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
typedef struct {
    hi_u8                       type;    /* shortgi 20/40/80     */
    hi_u8                       enable;  /* 1:enable; 0:disable  */
    hi_u8                       resv[2]; /* 2 byte�����ֶ� */
}shortgi_cfg_stru;
#endif

#define SHORTGI_CFG_STRU_LEN            4

typedef struct {
    hi_u8                            announced_channel;          /* ���ŵ��� AP�� */
    hi_u8                            ch_switch_cnt;              /* �ŵ��л����� AP�� */
    hi_u8                            new_channel;                /* STA�� ���Կ��Ǹ�����ϲ� */
    hi_u8                            new_ch_swt_cnt;             /* STA�� ���Կ��Ǹ�����ϲ� */

    wlan_channel_bandwidth_enum_uint8    announced_bandwidth : 4;    /* �´���ģʽ AP�� */
    wlan_channel_bandwidth_enum_uint8    new_bandwidth       : 4;    /* STA�� ���Կ��Ǹ�����ϲ� */
    hi_u8                            ch_swt_cnt;                     /* ap��һ�η��͵��л����� */
    hi_u8                            csa_rsv_cnt;                    /* ap csa ���������ļ��� */
    wlan_ch_switch_status_enum_uint8     ch_switch_status : 2;       /* �ŵ��л�״̬ */
    wlan_bw_switch_status_enum_uint8     bw_switch_status : 2;       /* �����л�״̬ 31Hֻ֧��20M ���ܲ�֧�� */
    hi_u8                  csa_present_in_bcn : 1,                   /* Beacon֡���Ƿ����CSA IE */
                                         waiting_to_shift_channel : 1,
                                         channel_swt_cnt_zero : 1,
                                         bad_ap         : 1 ;        /* ����ʶ���ap����beacon��csa�������ŵ� */
    /*
     *  ---|--------|--------------------|-----------------|-----------
     *     0        3                    0                 0
     *     X        A                    B                 C
     *
     *  sta���ŵ��л���ͨ����ͼ�������, ����Ϊ�л���������
     *  X->A A֮ǰΪδ���������ŵ��л�ʱ,�л�������Ϊ0
     *  ��A->Bʱ���Ϊsta�ȴ��л�״̬: en_waiting_to_shift_channelΪtrue
     *  ��B->CΪsta�ŵ��л���,���ȴ�ap��beacon״̬: en_waiting_for_apΪtrue
     *  C-> Ϊsta�յ���ap��beacon����׼�ŵ��л�����
     *
     *  A��ͨ�����յ�csa ie(beacon/action...), B��ͨ��Ϊtbtt�ж����л���������Ϊ
     *  0����csa ie�м�����Ϊ0��C����Ϊ�յ�beacon
     *
     *  ��A->C�Ĺ����У�������ظ��յ���csa ie�����ŵ��л�����
     *
     */
}mac_ch_switch_info_stru;

typedef struct {
    hi_u8   mac_rate; /* MAC��Ӧ���� */
    hi_u8   phy_rate; /* PHY��Ӧ���� */
    hi_u8   mbps;     /* ���� */
    hi_u8   auc_resv[1];
}mac_data_rate_stru;

typedef struct {
    hi_u8           rs_nrates;   /* ���ʸ��� */
    hi_u8           auc_resv[3]; /* 3 BYTE�����ֶ� */
    mac_data_rate_stru  ast_rs_rates[WLAN_MAX_SUPP_RATES];
}mac_rateset_stru;

typedef struct {
    hi_u8         br_rate_num;   /* �������ʸ��� */
    hi_u8         nbr_rate_num;  /* �ǻ������ʸ��� */
    hi_u8         max_rate;      /* ���������� */
    hi_u8         min_rate;      /* ��С�������� */
    mac_rateset_stru  rate;
}mac_curr_rateset_stru;

/* wme���� */
typedef struct {
    hi_u8     aifsn;          /* AIFSN parameters �߼�4bit mibʹ��uint32 */
    hi_u8     logcwmin;       /* cwmin in exponential form, ��λ2^n -1 slot �߼�4bit mibʹ��uint32 */
    hi_u16    us_logcwmax;    /* cwmax in exponential form, ��λ2^n -1 slot ͬcwin ����ʹ��u16 */
    hi_u32    txop_limit;     /* txopLimit, us */
}mac_wme_param_stru;

/* MAC vap�������Ա�ʶ */
typedef struct {
    hi_u32  uapsd                          : 1,
                txop_ps                        : 1,
                wpa                            : 1,
                wpa2                           : 1,
                dsss_cck_mode_40mhz            : 1,                 /* �Ƿ�������40M��ʹ��DSSS/CCK, 1-����, 0-������ */
                rifs_tx_on                     : 1,
                tdls_prohibited                : 1,                 /* tdlsȫ�ֽ��ÿ��أ� 0-���ر�, 1-�ر� */
                tdls_channel_switch_prohibited : 1,                 /* tdls�ŵ��л�ȫ�ֽ��ÿ��أ� 0-���ر�, 1-�ر� */
                hide_ssid                      : 1,                 /* AP��������ssid,  0-�ر�, 1-���� */
                wps                            : 1,                 /* AP WPS����:0-�ر�, 1-���� */
                ac2g                           : 1,                 /* 2.4G�µ�11ac:0-�ر�, 1-���� */
                keepalive                      : 1,                 /* vap KeepAlive���ܿ���: 0-�ر�, 1-���� */
                smps                           : 2,                 /* vap ��ǰSMPS���� */
                dpd_enbale                     : 1,                 /* dpd�Ƿ��� */
                dpd_done                       : 1,                 /* dpd�Ƿ���� */
                ntxbf                          : 1,                 /* 11n txbf���� */
                disable_2ght40                 : 1,                 /* 2ght40��ֹλ��1-��ֹ��0-����ֹ */
                auto_dtim_enbale               : 1,                 /* ��̬DTIM���� */
                hide_meshid                    :1,                  /* �Ƿ�����MeshID */
                bit_resv                           : 12;
}mac_cap_flag_stru;

/* VAP�շ���ͳ�� */
typedef struct {
    /* net_device��ͳ����Ϣ, net_deviceͳ�ƾ�����̫���ı��� */
    hi_u32  rx_packets_to_lan;               /* �������̵�LAN�İ��� */
    hi_u32  rx_bytes_to_lan;                 /* �������̵�LAN���ֽ��� */
    hi_u32  rx_dropped_packets;              /* ���������ж����İ��� */
    hi_u32  rx_vap_non_up_dropped;           /* vapû��up�����İ��ĸ��� */
    hi_u32  rx_dscr_error_dropped;           /* �������������İ��ĸ��� */
    hi_u32  rx_first_dscr_excp_dropped;      /* �������װ��쳣�����İ��ĸ��� */
    hi_u32  rx_alg_filter_dropped;           /* �㷨���˶����İ��ĸ��� */
    hi_u32  rx_feature_ap_dropped;           /* AP����֡���˶������� */
    hi_u32  rx_null_frame_dropped;           /* �յ�NULL֡����Ŀ */
    hi_u32  rx_transmit_addr_checked_dropped; /* ���Ͷ˵�ַ����ʧ�ܶ��� */
    hi_u32  rx_dest_addr_checked_dropped;    /* Ŀ�ĵ�ַ����ʧ�ܶ��� */
    hi_u32  rx_multicast_dropped;            /* �鲥֡ʧ��(netbuf copyʧ��)���� */

    hi_u32  tx_packets_from_lan;             /* ��������LAN�����İ��� */
    hi_u32  tx_bytes_from_lan;               /* ��������LAN�������ֽ��� */
    hi_u32  tx_dropped_packets;              /* ���������ж����İ��� */

    /* ��������ͳ����Ϣ */
}mac_vap_stats_stru;

typedef struct {
    hi_u8                           user_idx;
    wlan_protocol_enum_uint8            avail_protocol_mode; /* �û�Э��ģʽ */
    wlan_protocol_enum_uint8            cur_protocol_mode;
    wlan_protocol_enum_uint8            protocol_mode;
}mac_h2d_user_protocol_stru;

typedef struct {
    hi_u8                           user_idx;
    hi_u8                           arg1;
    hi_u8                           arg2;
    hi_u8                           uc_resv;

    /* Э��ģʽ��Ϣ */
    wlan_protocol_enum_uint8            cur_protocol_mode;
    wlan_protocol_enum_uint8            protocol_mode;
    hi_u8                           avail_protocol_mode;     /* �û���VAPЭ��ģʽ����, ���㷨���� */

    wlan_bw_cap_enum_uint8              bandwidth_cap;       /* �û�����������Ϣ */
    wlan_bw_cap_enum_uint8              avail_bandwidth;     /* �û���VAP������������,���㷨���� */
    wlan_bw_cap_enum_uint8              cur_bandwidth;       /* Ĭ��ֵ��en_avail_bandwidth��ͬ,���㷨�����޸� */

    hi_u8                 user_pmf;
    mac_user_asoc_state_enum_uint8      user_asoc_state;     /* �û�����״̬ */
}mac_h2d_usr_info_stru;

typedef struct {
    mac_user_cap_info_stru          user_cap_info; /* �û�������Ϣ */
    hi_u8                           user_idx;
    hi_u8                           auc_resv[3];   /* 3 BYTE�����ֶ� */
}mac_h2d_usr_cap_stru;

/* ���ⵥDTS2015033104278: hamc��dmacͬ�����ʼ�����Ϣʱ��
   ʹ�õĽṹ���С�������¼��ڴ�Ĵ�С�������¼�ͬ���п���ʧ�ܡ�
   ��������ṹ��mac_h2d_user_rate_info_stru,��֤mac_h2d_usr_info_stru���������� */
typedef struct {
    hi_u8                           user_idx;
    hi_u8                           uc_resv;
    wlan_protocol_enum_uint8            protocol_mode;                            /* �û�Э��ģʽ */
    /* legacy���ʼ���Ϣ */
    hi_u8                           avail_rs_nrates;
    hi_u8                           auc_avail_rs_rates[WLAN_MAX_SUPP_RATES];
    /* ht���ʼ���Ϣ */
    mac_user_ht_hdl_stru                 ht_hdl;
}mac_h2d_usr_rate_info_stru;

typedef struct {
    hi_u16                         us_sta_aid;
    hi_u8                          uapsd_cap;
    hi_u8                          auc_resv[1];
}mac_h2d_vap_info_stru;

typedef struct {
    hi_u8                           user_idx;
    wlan_protocol_enum_uint8            avail_protocol_mode; /* �û�Э��ģʽ */
    wlan_bw_cap_enum_uint8              bandwidth_cap;       /* �û�����������Ϣ */
    wlan_bw_cap_enum_uint8              avail_bandwidth;     /* �û���VAP������������,���㷨���� */
    wlan_bw_cap_enum_uint8              cur_bandwidth;       /* Ĭ��ֵ��en_avail_bandwidth��ͬ,���㷨�����޸� */
    hi_u8                           auc_rsv[3];              /* 3 BYTE�����ֶ� */
}mac_h2d_user_bandwidth_stru;

typedef struct {
    mac_channel_stru                    channel;
    hi_u8                           user_idx;
    wlan_bw_cap_enum_uint8              bandwidth_cap;       /* �û�����������Ϣ */
    wlan_bw_cap_enum_uint8              avail_bandwidth;     /* �û���VAP������������,���㷨���� */
    wlan_bw_cap_enum_uint8              cur_bandwidth;       /* Ĭ��ֵ��en_avail_bandwidth��ͬ,���㷨�����޸� */
}mac_d2h_syn_info_stru;

typedef struct {
    mac_channel_stru                channel;        /* vap���ڵ��ŵ� */
    mac_ch_switch_info_stru         ch_switch_info;
    hi_u8                           user_idx;
    hi_u8                           vap_id;
    hi_u8                           auc_rsv[2];     /* 2 BYTE�����ֶ� */
}mac_d2h_syn_data_stru;

typedef struct {
    hi_u32                          data_blk_cnt;    /* ��Ҫ��������ݿ���� */
    hi_u32                          wakeup_reason;
}mac_d2h_syn_hdr_stru;

typedef struct {
    mac_channel_stru                    channel;             /* vap���ڵ��ŵ� */
    mac_ch_switch_info_stru             ch_switch_info;
    mac_user_ht_hdl_stru                ht_hdl;              /* HT capability IE�� operation IE�Ľ�����Ϣ */
    mac_vht_hdl_stru                    vht_hdl;             /* VHT capability IE�� operation IE�Ľ�����Ϣ */
    hi_u8                           user_idx;
    hi_u8                           vap_id;
    wlan_bw_cap_enum_uint8              bandwidth_cap;       /* �û�����������Ϣ */
    wlan_bw_cap_enum_uint8              avail_bandwidth;     /* �û���VAP������������,���㷨���� */
    wlan_bw_cap_enum_uint8              cur_bandwidth;       /* Ĭ��ֵ��en_avail_bandwidth��ͬ,���㷨�����޸� */
    hi_u8                           auc_rsv[3];              /* 3 BYTE�����ֶ� */
}mac_h2d_syn_data_stru;

/* WOW������Ϣ���� */
typedef enum {
    MAC_WOW_SLEEP_NOTIFY_MSG,
    MAC_WOW_SYNC_DATA_MSG,
    MAC_WOW_MSG_BUTT,
}mac_wow_msg_enum;
typedef hi_u8 mac_wow_msg_enum_uint8;

typedef struct {
    mac_wow_msg_enum_uint8              msg_type;    /* �������Ϣ���� */
    hi_u8                           notify_param;    /* ˯��֪ͨ���� */
    hi_u8                           auc_resv[2];     /* 2 BYTE�����ֶ� */
    hi_u32                          data_blk_cnt;    /* ��Ҫ��������ݿ���� */
}mac_h2d_syn_info_hdr_stru;

typedef struct {
    hi_u8                           user_idx;
    mac_user_asoc_state_enum_uint8      asoc_state;
    hi_u8                           rsv[2]; /* 2 BYTE�����ֶ� */
}mac_h2d_user_asoc_state_stru;

typedef struct {
    hi_u8 auc_addr[WLAN_MAC_ADDR_LEN];
    hi_u8 auc_pmkid[WLAN_PMKID_LEN];
    hi_u8 auc_resv0[2]; /* 2 BYTE�����ֶ� */
} mac_pmkid_info_stu;

typedef struct {
    hi_u8       num_elems;
    hi_u8       auc_resv0[3]; /* 3 BYTE�����ֶ� */
    mac_pmkid_info_stu ast_elem[WLAN_PMKID_CACHE_SIZE];
} mac_pmkid_cache_stru;

typedef struct {
    /* word 0 */
    wlan_prot_mode_enum_uint8           protection_mode;                         /* ����ģʽ */
    hi_u8                           obss_non_erp_aging_cnt;                      /* ָʾOBSS��non erp վ����ϻ�ʱ�� */
    hi_u8                           obss_non_ht_aging_cnt;                       /* ָʾOBSS��non ht վ����ϻ�ʱ�� */
    /* ָʾ���������Ƿ�����HI_SWITCH_ON �򿪣� HI_SWITCH_OFF �ر� */
    hi_u8                           auto_protection        : 1;
    hi_u8                           obss_non_erp_present   : 1;                  /* ָʾobss���Ƿ����non ERP��վ�� */
    hi_u8                           obss_non_ht_present    : 1;                  /* ָʾobss���Ƿ����non HT��վ�� */
    /* ָrts_cts ���������Ƿ��, HI_SWITCH_ON �򿪣� HI_SWITCH_OFF �ر� */
    hi_u8                           rts_cts_protect_mode   : 1;
    /* ָʾL-SIG protect�Ƿ��, HI_SWITCH_ON �򿪣� HI_SWITCH_OFF �ر� */
    hi_u8                           lsig_txop_protect_mode : 1;
    hi_u8                           reserved               : 3;

    /* word 1 */
    hi_u8                           sta_no_short_slot_num;                    /* ��֧��short slot��STA���� */
    hi_u8                           sta_no_short_preamble_num;                /* ��֧��short preamble��STA���� */
    hi_u8                           sta_non_erp_num;                          /* ��֧��ERP��STA���� */
    hi_u8                           sta_non_ht_num;                           /* ��֧��HT��STA���� */
    /* word 2 */
    hi_u8                           sta_non_gf_num;                           /* ֧��ERP/HT,��֧��GF��STA���� */
    hi_u8                           sta_20_m_only_num;                        /* ֻ֧��20M Ƶ�ε�STA���� */
    hi_u8                           sta_no_40dsss_cck_num;                    /* ����40M DSSS-CCK STA����  */
    hi_u8                           sta_no_lsig_txop_num;                     /* ��֧��L-SIG TXOP Protection STA���� */
} mac_protection_stru;

/* ����ͬ��������صĲ��� */
typedef struct {
    wlan_mib_ht_protection_enum_uint8   dot11_ht_protection;
    hi_u8 dot11_rifs_mode;
    hi_u8 dot11_lsigtxop_full_protection_activated;
    hi_u8 dot11_non_gf_entities_present;
    mac_protection_stru protection;
}mac_h2d_protection_stru;

typedef struct {
    hi_u8                          *puc_ie;                                      /* APP ��ϢԪ�� */
    hi_u32                          ie_len;                                      /* APP ��ϢԪ�س��� */
} mac_app_ie_stru;

#ifdef _PRE_WLAN_FEATURE_STA_UAPSD
/* STA UAPSD �������� */
typedef  struct {
    hi_u8       max_sp_len;
    hi_u8       delivery_map;
    hi_u8       trigger_map;
    hi_u8       uc_resv;
}mac_cfg_uapsd_sta_stru;
#endif

/* RTS ���Ͳ��� */
typedef struct {
    wlan_legacy_rate_value_enum_uint8   auc_rate[WLAN_TX_RATE_MAX_NUM];           /* �������ʣ���λmpbs */
    /* Э��ģʽ, ȡֵ�μ�wlan_phy_protocol_enum_uint8 */
    wlan_phy_protocol_enum_uint8        auc_protocol_mode[WLAN_TX_RATE_MAX_NUM];
    wlan_channel_band_enum_uint8        band;
    hi_u8                               auc_recv[3];                              /* 3 byte�����ֶ� */
}mac_cfg_rts_tx_param_stru;

/* VAP�����ݽṹ */
typedef struct {
    hi_u8                           vap_id;                                         /* vap ID ����Դ������ֵ */
    wlan_vap_mode_enum_uint8            vap_mode;                                   /* vapģʽ  */
    /* BSSID����MAC��ַ��MAC��ַ��mib�е�auc_dot11StationID  */
    hi_u8                           auc_bssid[WLAN_MAC_ADDR_LEN];

    mac_vap_state_enum_uint8            vap_state;                                  /* VAP״̬ */
    wlan_protocol_enum_uint8            protocol;                                   /* ������Э��ģʽ */
    hi_u8                           tx_power;                                       /* ���书��, ��λdBm */
    /* ��ʼΪ0��APģʽ�£�ÿ����һ��wmm�������������1,��beacon֡��assoc rsp�л���д��4bit�����ܳ���15��STAģʽ��
        ����֡���������ֵ */
    hi_u8                           wmm_params_update_count;

    mac_channel_stru                    channel;                                     /* vap���ڵ��ŵ� */
    mac_ch_switch_info_stru             ch_switch_info;

    hi_u8                           has_user_bw_limit   : 1,        /* ��vap�Ƿ����user���� */
                                        vap_bw_limit        : 1,    /* ��vap�Ƿ������� */
                                        voice_aggr          : 1,    /* ��vap�Ƿ����VOҵ��֧�־ۺ� */
                                        support_any         : 1,    /* ��vap�Ƿ�ǰ֧��ANY���� */
                                        uapsd_cap           : 1,    /* ������STA������AP�Ƿ�֧��uapsd������Ϣ */
                                        user_pmf_cap        : 1,    /* STA����δ����userǰ���洢Ŀ��user��pmfʹ����Ϣ */
                                        mesh_accept_sta     : 1, /* ��ʾ��ǰMesh�Ƿ�֧��sta����(��Accepting Peer��ͬ) */
                                        mesh_tbtt_adjusting : 1;    /* ��ʾMesh�Ƿ����ڵ���TBTT */

    hi_u8                           user_nums;                                   /* VAP���ѹҽӵ��û����� */
    hi_u8                           multi_user_idx;                              /* �鲥�û�ID */
    hi_u8                           cache_user_id;                               /* cache user��Ӧ��userID */

    hi_u8                           al_tx_flag  : 1,          /* ������־ */
                                        payload_flag: 2,      /* payload����:0:ȫ0  1:ȫ1  2:random */
                                        first_run   : 1,      /* �����ر��ٴδ򿪱�־ */
                                        need_send_keepalive_null : 1, /* ��־sta Pause״̬���Ƿ���Ҫ����Keepalive֡ */
                                        is_conn_to_mesh : 1,  /* ��־sta�Ƿ������Mesh */
                                        csi_flag : 1,         /* ��־��ǰMAC_VAP��CSI�����Ƿ���� */
                                        reserved : 1;
    wlan_p2p_mode_enum_uint8            p2p_mode;             /* 0:��P2P�豸; 1:P2P_GO; 2:P2P_Device; 3:P2P_CL */
    hi_u8                           p2p_listen_channel;       /* P2P Listen channel */
    /* VAPΪSTAģʽʱ����user(ap)����Դ��������VAPΪAPģʽʱ�����ô˳�Ա���� */
    hi_u8                           assoc_vap_id;

    hi_u8                           report_times_limit;       /* MESH ״̬���䣬�����ϱ��ô�������������ϱ�������Ϣ */
    hi_u8                           report_tx_cnt_limit;      /* MESH ���ϱ��ķ��ʹ�����ֵ */
    hi_u8                           priority;                 /* ��ǰmesh�ڵ�����ȼ�,����ѡ��Ǳ����Խڵ�(0-256) */
    hi_u8                           mnid;                     /* �������ڵ㷢��ʱ϶,��meshЭ��ջ�ṩ(0��ʾ�Ƿ�ֵ) */

    hi_u8                           is_mbr;                   /* ��ʶ�Ƿ���MBR�ڵ�(true:MBR,false:MR) */
    hi_u8                           vap_rx_nss;
    hi_u8                           auc_cache_user_mac_addr[WLAN_MAC_ADDR_LEN];     /* cache user��Ӧ��MAC��ַ */

    /* VAPΪSTAģʽʱ����AP�����STA��AID(����Ӧ֡��ȡ),ȡֵ��Χ1~2007; VAPΪAPģʽʱ�����ô˳�Ա���� */
    hi_u16                          us_sta_aid;
    hi_u16                          us_assoc_user_cap_info;                         /* staҪ�������û���������Ϣ */

    hi_list                             ast_user_hash[MAC_VAP_USER_HASH_MAX_VALUE]; /* hash����,ʹ��HASH�ṹ�ڵ�DLIST */
    hi_list                             mac_user_list_head;          /* �����û��ڵ�˫������,ʹ��USER�ṹ�ڵ�DLIST */
    mac_cap_flag_stru                   cap_flag;                    /* vap�������Ա�ʶ */
    wlan_mib_ieee802dot11_stru         *mib_info;        /* mib��Ϣ(��ʱ����vapʱ������ֱ�ӽ�ָ��ֵΪNULL����ʡ�ռ�)  */
    mac_curr_rateset_stru               curr_sup_rates;              /* ��ǰ֧�ֵ����ʼ� */
    mac_protection_stru                 protection;                  /* �뱣����ر��� */
    mac_app_ie_stru                     ast_app_ie[OAL_APP_IE_NUM];
#ifdef _PRE_WLAN_FEATURE_STA_UAPSD
    mac_cfg_uapsd_sta_stru              sta_uapsd_cfg;     /* UAPSD��������Ϣ */
#endif
    oal_spin_lock_stru                  cache_user_lock;                        /* cache_user lock */
#ifdef _PRE_WLAN_FEATURE_BW_HIEX
    hi_u8                           selfcts;                                /* �Ƿ�ʹ��խ���п������selfcts */
    hi_u8                           duration;                               /* selfcts��ռ���ŵ�ʱ�䣬��λms */
    hi_u16                          us_per;                                 /* ����selfcts��PER��ֵ */
#endif
}mac_vap_stru;

typedef struct {
    mac_vap_stru                *mac_vap;
    hi_s8                     pc_param[4];      /* ��ѯ��������Ϣ,ռ4 byte */
}mac_cfg_event_stru;

/* HOSTAPD ���� Beacon ��Ϣ */
typedef struct {
    hi_s32                l_interval;                            /* beacon interval */
    hi_s32                l_dtim_period;                         /* DTIM period     */
    hi_u8      privacy;
    hi_u8                crypto_mode;                              /* WPA/WPA2 */
    hi_u8                group_crypto;                             /* �鲥��Կ���� */
    hi_u8      hidden_ssid;
    hi_u8                auc_auth_type[MAC_AUTHENTICATION_SUITE_NUM];  /* akm ���� */
    hi_u8                auc_pairwise_crypto_wpa[MAC_PAIRWISE_CIPHER_SUITES_NUM];
    hi_u8                auc_pairwise_crypto_wpa2[MAC_PAIRWISE_CIPHER_SUITES_NUM];
    hi_u16               us_rsn_capability;
    hi_u8      shortgi_20;
    hi_u8      shortgi_40;
    hi_u8      shortgi_80;
    wlan_protocol_enum_uint8 protocol;

    hi_u8                       smps_mode;
    mac_beacon_operation_type_uint8 operation_type;
    hi_u8                auc_resv1[2];  /* 2 byte�����ֶ� */
#ifdef _PRE_WLAN_FEATURE_MESH
    hi_u8 mesh_auth_protocol;
    hi_u8 mesh_formation_info;
    hi_u8 mesh_capability;
    hi_u8 auc_resv2[1];
#endif
}mac_beacon_param_stru;

/* CSI�������ýṹ�� */
typedef struct {
    hi_u8               mac_addr[WLAN_MAC_ADDR_LEN];           /* ���õ�MAC��ַ */
    hi_u8               sample_period;                         /* ���õĲ������� */
    hi_u8               frame_type;                            /* ���õ�֡���� */
} csi_entry_stru;

typedef struct {
    csi_entry_stru      ast_csi_param[OAL_CSI_MAX_MAC_NUM];    /* �������6��mac��ַ�ϱ� */
    hi_u32              report_min_interval;
    hi_u8               entry_num;
    hi_u8               resv[3];  /* 3 byte�����ֶ� */
} mac_csi_config_stru;

/* �ϱ���CSI���ݽṹ�� */
typedef struct {
    hi_u8               csi_data[OAL_CSI_DATA_BUFF_SIZE];      /* ��184�ֽ�CSI�����ϱ���wal�� */
    hi_u32              data_len;
} mac_csi_data_stru;

typedef struct {
    hi_u8 default_key;
    hi_u8           key_index;
    hi_u8           key_len;
    hi_u8           auc_wep_key[WLAN_WEP104_KEY_LEN];
} mac_wep_key_param_stru;

typedef struct mac_pmksa_tag {
    hi_u8 auc_bssid[OAL_MAC_ADDR_LEN];
    hi_u8 auc_pmkid[OAL_PMKID_LEN];
}mac_pmksa_stru;

typedef struct {
    hi_u8                key_index;
    hi_u8      pairwise;
    hi_u8                auc_mac_addr[OAL_MAC_ADDR_LEN];
    mac_key_params_stru      key;
}mac_addkey_param_stru;

typedef struct {
    hi_s32  key_len;
    hi_u8 auc_key[OAL_WPA_KEY_LEN];
}mac_key_stru;

typedef struct {
    hi_s32  seq_len;
    hi_u8 auc_seq[OAL_WPA_SEQ_LEN];
}mac_seq_stru;

typedef struct {
    hi_u8                  key_index;
    hi_u8        pairwise;
    hi_u8                  auc_mac_addr[OAL_MAC_ADDR_LEN];
    hi_u8                  cipher;
    hi_u8                  auc_rsv[3]; /* 3 byte�����ֶ� */
    mac_key_stru               key;
    mac_seq_stru               seq;
}mac_addkey_hmac2dmac_param_stru;

typedef struct {
    oal_net_device_stru     *netdev;
    hi_u8                key_index;
    hi_u8      pairwise;
    hi_u8                auc_resv1[2]; /* 2 byte�����ֶ� */
    hi_u8               *puc_mac_addr;
    hi_void                *cookie;
    hi_void               (*callback)(hi_void *cookie, oal_key_params_stru *key_param);
}mac_getkey_param_stru;

typedef struct {
    hi_u8                key_index;
    hi_u8      pairwise;
    hi_u8                auc_mac_addr[OAL_MAC_ADDR_LEN];
}mac_removekey_param_stru;

typedef struct {
    hi_u8                key_index;
    hi_u8      unicast;
    hi_u8      multicast;
    hi_u8                auc_resv1[1];
}mac_setdefaultkey_param_stru;

/* �㷨����ö�٣�����ֵ */
typedef struct {
    mac_alg_cfg_enum_uint8  alg_cfg;     /* ��������ö�� */
    hi_u8                   is_negtive;  /* ���ò���ֵ�Ƿ�Ϊ�� */
    hi_u8                   uc_resv[2];  /* 2 �ֽڶ��� */
    hi_u32                  value;       /* ���ò���ֵ */
}mac_ioctl_alg_param_stru;

/* AUTORATE LOG �㷨����ö�٣�����ֵ */
typedef struct {
    mac_alg_cfg_enum_uint8  alg_cfg;                        /* ��������ö�� */
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u8               ac_no;                              /* AC���� */
    hi_u8               auc_resv[2];                        /* 2 BYTE�����ֶ� */
    hi_u16              us_value;                           /* ���ò���ֵ */
}mac_ioctl_alg_ar_log_param_stru;

/* AUTORATE ������ص�������� */
typedef struct {
    mac_alg_cfg_enum_uint8  alg_cfg;                         /* ��������ö�� */
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];     /* MAC��ַ */
    hi_u8               auc_resv[1];
    hi_u16              us_value;                            /* ������� */
}mac_ioctl_alg_ar_test_param_stru;

/* TXMODE LOG �㷨����ö�٣�����ֵ */
typedef struct {
    mac_alg_cfg_enum_uint8  alg_cfg;                        /* ��������ö�� */
    hi_u8               ac_no;                              /* AC���� */
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u8               auc_resv1[2];                       /* 2 BYTE�����ֶ� */
    hi_u16              us_value;                           /* ���ò���ֵ */
}mac_ioctl_alg_txbf_log_param_stru;
/* �㷨��������ӿ� */
typedef struct {
    hi_u8       argc;
    hi_u8       auc_argv_offset[DMAC_ALG_CONFIG_MAX_ARG];
}mac_ioctl_alg_config_stru;

/* TPC LOG �㷨����ö�٣�����ֵ */
typedef struct {
    mac_alg_cfg_enum_uint8  alg_cfg;                        /* ��������ö�� */
    hi_u8               auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* MAC��ַ */
    hi_u8               ac_no;                              /* AC���� */
    hi_u16              us_value;                           /* ���ò���ֵ */
    hi_u16              resv;
    hi_char            *pc_frame_name;                      /* ��ȡ�ض�֡����ʹ�øñ��� */
}mac_ioctl_alg_tpc_log_param_stru;

/* cca opt LOG �㷨����ö�٣�����ֵ */
typedef struct {
    hi_u16              us_value;                            /* ͳ����ʱ�� */
    mac_alg_cfg_enum_uint8  alg_cfg;                         /* ��������ö�� */
    hi_u8               auc_resv;
}mac_ioctl_alg_cca_opt_log_param_stru;

/* ���鲥ת���������� */
typedef struct {
    hi_u32 deny_group_addr;
}mac_add_m2u_deny_table_stru;

/* ����鲥ת���������� */
typedef struct {
    hi_u8 m2u_clear_deny_table;
    hi_u8 m2u_show_deny_table;
}mac_clg_m2u_deny_table_stru;

/* print snoop table */
typedef struct {
    hi_u8 m2u_show_snoop_table;
}mac_show_m2u_snoop_table_stru;

/* add snoop table */
typedef struct {
    hi_u8 m2u_add_snoop_table;
}mac_add_m2u_snoop_table_stru;

typedef struct {
    hi_u8 proxyarp;
    hi_u8           auc_rsv[3]; /* 3 BYTE�����ֶ� */
}mac_proxyarp_en_stru;

typedef struct {
    hi_u64                          ull_cookie;
    hi_u32                          listen_duration;             /* ����ʱ��   */
    hi_u8                           uc_listen_channel;           /* �������ŵ� */
    wlan_channel_bandwidth_enum_uint8   listen_channel_type;     /* �����ŵ����� */
    hi_u8                           home_channel;                /* �����������ص��ŵ� */
    wlan_channel_bandwidth_enum_uint8   home_channel_type;       /* �����������������ŵ����� */
    /* P2P0��P2P_CL ����VAP �ṹ������������ǰVAP ��״̬�����ڼ�������ʱ�ָ���״̬ */
    mac_vap_state_enum_uint8            last_vap_state;
    wlan_channel_band_enum_uint8        band;
    hi_u16                              resv;
    oal_ieee80211_channel_stru          st_listen_channel;
}mac_remain_on_channel_param_stru;

/* WPAS ����֡���ͽṹ */
typedef struct {
    hi_s32               channel;
    hi_u8               mgmt_frame_id;
    hi_u8               rsv;
    hi_u16              us_len;
    const hi_u8    *puc_frame;
} mac_mgmt_frame_stru;

/* P2P����action֡״̬�ṹ�� */
typedef struct {
    hi_u8 *puc_buf;
    hi_u32 len;
    hi_u8  ack;
    hi_u8  resv[3]; /* 3 BYTE�����ֶ� */
} mac_p2p_tx_status_stru;

#ifdef _PRE_WLAN_FEATURE_WOW
/* WOW ssid wakeup �������ã��������� */
typedef struct {
    hi_u8                     ssid_set_flag;
    hi_s8                     ac_ssid[WLAN_SSID_MAX_LEN]; /* 32+1 */
    hi_u8                     auc_res[2];                 /* 2 BYTE�����ֶ� */
}wow_ssid_cfg_stru;
#endif

#ifdef _PRE_WLAN_FEATURE_WOW_ROM
/* WOW netpattern ��������,�������� */
typedef struct {
    hi_u8   auc_pattern_data[WOW_NETPATTERN_MAX_LEN];
    hi_u32  pattern_len;
}wow_pattern_stru;

/* WOW netpattern �������ã��������� */
typedef struct {
    wow_pattern_stru   ast_pattern[WOW_NETPATTERN_MAX_NUM];
    hi_u16         us_pattern_map;
    hi_u16         us_pattern_num;
}wow_pattern_cfg_stru;

typedef struct {
    hi_u8                   wow_en;
    hi_u8                   auc_res[3]; /* ����Ϊpno����auc_res[0]Ϊɨ���ŵ�,auc_res[1]��auc_res[2]Ϊpno����,��3byte */
    hi_u32                  wow_event;
    wow_pattern_cfg_stru        wow_pattern;
}mac_wow_cfg_stu;
#endif

/* RF�Ĵ������ƻ��ṹ�� */
typedef struct {
    hi_u16                 us_rf_reg117;
    hi_u16                 us_rf_reg123;
    hi_u16                 us_rf_reg124;
    hi_u16                 us_rf_reg125;
    hi_u16                 us_rf_reg126;
    hi_u8                  auc_resv[2]; /* 2 BYTE �����ֶ� */
}mac_cus_dts_rf_reg;

/* FCC��֤ �����ṹ�� */
typedef struct {
    hi_u8       index;           /* �±��ʾƫ�� */
    hi_u8       max_txpower;     /* ����͹��� */
    hi_u8       dbb_scale;       /* dbb scale */
    hi_u8       uc_resv;
}mac_cus_band_edge_limit_stru;

/* ���ƻ� У׼���ò��� */
typedef struct {
    /* dts */
    hi_u16                  aus_cali_txpwr_pa_dc_ref_2g_val[13];        /* txpwr���ŵ�refֵ,ռ13 short */
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band1;
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band2;
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band3;
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band4;
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band5;
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band6;
    hi_s16                  us_cali_txpwr_pa_dc_ref_5g_val_band7;
    hi_s8                   band_5g_enable;
    hi_u8                   tone_amp_grade;
    hi_s8                   auc_resv_wifi_cali[2]; /* ռ2 BYTE */
    /* bt tmp */
    hi_u16                  us_cali_bt_txpwr_pa_ref_band1;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band2;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band3;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band4;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band5;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band6;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band7;
    hi_u16                  us_cali_bt_txpwr_pa_ref_band8;
    hi_u16                  us_cali_bt_txpwr_numb;
    hi_u16                  us_cali_bt_txpwr_pa_fre1;
    hi_u16                  us_cali_bt_txpwr_pa_fre2;
    hi_u16                  us_cali_bt_txpwr_pa_fre3;
    hi_u16                  us_cali_bt_txpwr_pa_fre4;
    hi_u16                  us_cali_bt_txpwr_pa_fre5;
    hi_u16                  us_cali_bt_txpwr_pa_fre6;
    hi_u16                  us_cali_bt_txpwr_pa_fre7;
    hi_u16                  us_cali_bt_txpwr_pa_fre8;
    hi_u8                   bt_tone_amp_grade;
    hi_u8                   auc_resv_bt_cali[1];
}mac_cus_dts_cali_stru;

/* dbb scaling �����ṹ�� */
typedef struct {
    hi_u32       dbb_scale[9];       /* DBB��ֵ 9 WORD */
}dbb_scaling_stru;

typedef struct {
    hi_u32       tx_pwr[MAC_NUM_2G_CH_NUM];     /* FCC���ŵ������ʵķ��͹��� */
}fcc_tx_pwr_stru;

typedef struct {
    hi_s16      high_temp_th;     /* ������ֵ */
    hi_s16      low_temp_th;      /* ���͵�����ֵ */
    hi_s16      comp_val;         /* ����ֵ */
}freq_comp_stru;
/* ======================== cfg id��Ӧ��get set���� ==================================== */
typedef struct {
    wlan_cfgid_enum_uint16      cfgid;
    hi_u8                       auc_resv[2];    /* 2 �ֽڶ��� */
    hi_u32                      (*get_func)(mac_vap_stru *mac_vap, hi_u8 *puc_len, hi_u8 *puc_param);
    hi_u32                      (*set_func)(mac_vap_stru *mac_vap, hi_u8 uc_len, hi_u8 *puc_param);
}mac_cfgid_stru;

/*****************************************************************************
  ������������
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_UAPSD
/*****************************************************************************
 ��������  : ����U-APSDʹ��
 �޸���ʷ      :
*****************************************************************************/
static inline hi_void mac_vap_set_uapsd_en(mac_vap_stru *mac_vap, hi_u8 value)
{
    mac_vap->cap_flag.uapsd = (value) ? HI_TRUE : HI_FALSE;
}

/*****************************************************************************
 ��������  : ��ȡbeacon interval��ֵ
 �޸���ʷ      :
  1.��    ��   : 2013��1��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_vap_get_uapsd_en(const mac_vap_stru *mac_vap)
{
    return mac_vap->cap_flag.uapsd;
}

/*****************************************************************************
 ��������  : ����vap��uapsd����
 �� �� ֵ  : hi_void
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_uapsd_para(mac_vap_stru *mac_vap, const mac_cfg_uapsd_sta_stru *uapsd_info)
{
    hi_u8                 ac;

    mac_vap->sta_uapsd_cfg.max_sp_len = uapsd_info->max_sp_len;
    for (ac = 0; ac < WLAN_WME_AC_BUTT; ac++) {
        mac_vap->sta_uapsd_cfg.delivery_map = uapsd_info->delivery_map;
        mac_vap->sta_uapsd_cfg.trigger_map  = uapsd_info->trigger_map;
    }
}
#endif

/*****************************************************************************
 ��������  : ���dmac list�ļ��
 �޸���ʷ      :
  1.��    ��   : 2015��04��02��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��05��02��
    ��    ��   : Hisilicon
    �޸�����   : �޸ĺ�����������ֵ
*****************************************************************************/
static inline hi_u8 mac_vap_user_exist(const hi_list *new_code, const hi_list *head)
{
    hi_list                  *user_list_head = HI_NULL;
    hi_list                  *member_entry = HI_NULL;

    hi_list_for_each_safe(member_entry, user_list_head, head) {
        if (new_code == member_entry) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
/*****************************************************************************
��������  : ��ʼ��Mesh���Mibֵ
�޸���ʷ      :
 1.��    ��   : 2019��1��29��
    ��    ��   : Hisilicon
   �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_init_mib_mesh(const mac_vap_stru *mac_vap)
{
    wlan_mib_ieee802dot11_stru      *mib_info;
    mib_info = mac_vap->mib_info;
    mib_info->wlan_mib_sta_config.dot11_mesh_activated = (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) ?
        HI_TRUE : HI_FALSE;
    mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_accepting_additional_peerings = HI_TRUE;
    mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_security_activated = HI_FALSE;
    mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol = 0;
    mib_info->wlan_mib_mesh_sta_cfg.dot11_mbca_activated = HI_FALSE;
}
#endif

/*****************************************************************************
 ��������  : ����vap�ķ��͹���
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_tx_power(mac_vap_stru *mac_vap, hi_u8 tx_power)
{
    mac_vap->tx_power = tx_power;
}

/*****************************************************************************
 ��������  : ����vap��aid
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_aid(mac_vap_stru *mac_vap, hi_u16 us_aid)
{
    mac_vap->us_sta_aid = us_aid;
}

/*****************************************************************************
 ��������  : ����vap��assoc_vap_id �ò���ֻ��STA��Ч
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static inline hi_void mac_vap_set_assoc_id(mac_vap_stru *mac_vap, hi_u8 assoc_vap_id)
{
    mac_vap->assoc_vap_id = assoc_vap_id;
}

/*****************************************************************************
 ��������  : ����vap��assoc_vap_id �ò���ֻ��STA��Ч
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_uapsd_cap(mac_vap_stru *mac_vap, hi_u8 uapsd_cap)
{
    mac_vap->uapsd_cap = uapsd_cap & BIT0;
}

/*****************************************************************************
 ��������  : ����vap��p2pģʽ
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_p2p_mode(mac_vap_stru *mac_vap, wlan_p2p_mode_enum_uint8 p2p_mode)
{
    mac_vap->p2p_mode = p2p_mode;
}

/*****************************************************************************
 ��������  : ����vap���鲥�û�id
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_multi_user_idx(mac_vap_stru *mac_vap, hi_u8 multi_user_idx)
{
    mac_vap->multi_user_idx = multi_user_idx;
}

/*****************************************************************************
 ��������  : ����vap�ĳ���payload����
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_al_tx_payload_flag(mac_vap_stru *mac_vap, hi_u8 paylod)
{
    mac_vap->payload_flag = paylod;
}

/*****************************************************************************
 ��������  : ����vap�ĳ���ģʽ
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_al_tx_first_run(mac_vap_stru *mac_vap, hi_u8 flag)
{
    mac_vap->first_run = flag;
}

/*****************************************************************************
 ��������  : ����vap��wmm update count
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_wmm_params_update_count(mac_vap_stru *mac_vap, hi_u8 update_count)
{
    mac_vap->wmm_params_update_count = update_count;
}

/*****************************************************************************
 ��������  : ����vap��hide ssid
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_set_hide_ssid(mac_vap_stru *mac_vap, hi_u8 value)
{
    mac_vap->cap_flag.hide_ssid = value;
}

/*****************************************************************************
 ��������  : ��ȡVap��P2Pģʽ
 �޸���ʷ      :
  1.��    ��   : 2014��11��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline wlan_p2p_mode_enum_uint8 mac_get_p2p_mode(const mac_vap_stru *mac_vap)
{
    return (mac_vap->p2p_mode);
}

/*****************************************************************************
 ��������  : ��������ie
 �������  : mac_vap_stru *pst_mac_vap
           enum WPS_IE_TYPE en_type
 �޸���ʷ      :
 1.��    ��   : 2015��4��28��
    ��    ��   : Hisilicon
  �޸�����   : �����ɺ���
 *****************************************************************************/
static inline hi_void mac_vap_clear_app_ie(mac_vap_stru *mac_vap, en_app_ie_type_uint8 type)
{
    if (type < OAL_APP_IE_NUM) {
        if (mac_vap->ast_app_ie[type].puc_ie != HI_NULL) {
            oal_mem_free(mac_vap->ast_app_ie[type].puc_ie);
            mac_vap->ast_app_ie[type].puc_ie    = HI_NULL;
        }
        mac_vap->ast_app_ie[type].ie_len     = 0;
    }
    return;
}

static inline hi_void mac_vap_free_mib(mac_vap_stru *mac_vap)
{
    if (mac_vap->mib_info != HI_NULL) {
        wlan_mib_ieee802dot11_stru  *mib_info = mac_vap->mib_info;
        /* ���ÿ����ͷ� */
        mac_vap->mib_info = HI_NULL;
        oal_mem_free(mib_info);
    }
}

/*****************************************************************************
 ��������  : legacyЭ���ʼ��vap����
 �޸���ʷ      :
  1.��    ��   : 2013��11��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_cap_init_legacy(mac_vap_stru *mac_vap)
{
    mac_vap->cap_flag.rifs_tx_on = HI_FALSE;
    mac_vap->cap_flag.smps       = WLAN_MIB_MIMO_POWER_SAVE_MIMO;
}

/*****************************************************************************
 ��������  : ht vhtЭ���ʼ��vap����
 �޸���ʷ      :
  1.��    ��   : 2013��11��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_cap_init_htvht(mac_vap_stru *mac_vap)
{
    mac_vap->cap_flag.rifs_tx_on = HI_FALSE;
    mac_vap->cap_flag.smps = WLAN_MIB_MIMO_POWER_SAVE_MIMO;
}

/*****************************************************************************
 ��������  : ����BSSID
 �������  : [1]mac_vap,
             [2]puc_bssid
             [3]ssid_len
 �� �� ֵ  : ��
*****************************************************************************/
static inline hi_void mac_vap_set_bssid(mac_vap_stru *mac_vap, const hi_u8 *puc_bssid, hi_u8 ssid_len)
{
    if (memcpy_s(mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN, puc_bssid, ssid_len) != EOK) {
        return;
    }
}

/*****************************************************************************
 ��������  : VAP״̬Ǩ���¼�����Ϣ��ʽ�ϱ�SDT
 �������  : en_vap_state:��Ҫ��Ϊ��״̬
 �޸���ʷ      :
  1.��    ��   : 2013��12��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_vap_state_change(mac_vap_stru *mac_vap, mac_vap_state_enum_uint8 vap_state)
{
    mac_vap->vap_state = vap_state;
}

/*****************************************************************************
 ��������  : ��ѯ�Զ����������Ƿ���
 �޸���ʷ      :
  1.��    ��   : 2014��1��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_vap_protection_autoprot_is_enabled(const mac_vap_stru *mac_vap)
{
    return mac_vap->protection.auto_protection;
}

/*****************************************************************************
 ��������  : ��ȡvap�� mac��ַ
 �������  : dmac_vap_stru *pst_dmac_vap
 �޸���ʷ      :
  1.��    ��   : 2015��7��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8* mac_vap_get_mac_addr(const mac_vap_stru *mac_vap)
{
    /* _PRE_WLAN_FEATURE_P2P + */
    if (is_p2p_dev(mac_vap)) {
        /* ��ȡP2P DEV MAC ��ַ����ֵ��probe req ֡�� */
        return mac_vap->mib_info->wlan_mib_sta_config.auc_p2p0_dot11_station_id;
    } else {
        /* ���õ�ַ2Ϊ�Լ���MAC��ַ */
        return mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id;
    }
}

static inline hi_void mac_protection_set_lsig_txop_mechanism(mac_vap_stru *mac_vap, hi_u8 flag)
{
    /* ����֡/����֡����ʱ����Ҫ����bit_lsig_txop_protect_modeֵ��д�����������е�L-SIG TXOP enableλ */
    mac_vap->protection.lsig_txop_protect_mode = flag;
}

/*****************************************************************************
 ��������  : �����֤��ʽ�Ƿ�ƥ��
 �������  : wlan_mib_ieee802dot11_stru *pst_mib_info
             hi_u8 uc_policy
 �� �� ֵ  : hi_u8    HI_TRUE:ƥ��ɹ�
                                    HI_FALSE:ƥ��ʧ��
 �޸���ʷ      :
  1.��    ��   : 2013��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_check_auth_policy(const wlan_mib_ieee802dot11_stru *mib_info, hi_u8 policy)
{
    for (hi_u8 loop = 0; loop < MAC_AUTHENTICATION_SUITE_NUM; loop++) {
        /* �����֤�׼��Ƿ�ʹ�ܺ�ƥ�� */
        if ((mib_info->ast_wlan_mib_rsna_cfg_auth_suite[loop].dot11_rsna_config_authentication_suite_activated) &&
            (policy == \
                mib_info->ast_wlan_mib_rsna_cfg_auth_suite[loop].dot11_rsna_config_authentication_suite_implemented)) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

/*****************************************************************************
  ��������
*****************************************************************************/
hi_void mac_dec_p2p_num(const mac_vap_stru *mac_vap);
hi_void mac_inc_p2p_num(const mac_vap_stru *mac_vap);
hi_u8 mac_is_wep_allowed(const mac_vap_stru *mac_vap);
mac_wme_param_stru *mac_get_wmm_cfg(wlan_vap_mode_enum_uint8 vap_mode);
hi_u32 mac_device_find_user_by_macaddr(const mac_vap_stru *mac_vap, const hi_u8 *sta_mac_addr, hi_u8 addr_len,
                                       hi_u8 *puc_user_idx);
hi_void mac_protection_set_rts_tx_param(mac_vap_stru *mac_vap, hi_u8 flag, wlan_prot_mode_enum_uint8 prot_mode,
                                        mac_cfg_rts_tx_param_stru *rts_tx_param);
hi_bool mac_protection_lsigtxop_check(const mac_vap_stru *mac_vap);

/*****************************************************************************
    VAP��������
*****************************************************************************/
hi_u32 mac_vap_res_exit(hi_void);
hi_u32 mac_vap_res_init(const hi_u8 vap_num);
hi_u8 mac_vap_alloc_vap_res(hi_void);
hi_void mac_vap_free_vap_res(hi_u8 idx);
mac_vap_stru *mac_vap_get_vap_stru(hi_u8 idx);
hi_u32 mac_vap_is_valid(hi_u8 idx);
hi_void mac_vap_exit(mac_vap_stru *mac_vap);
hi_void mac_vap_init_rates(mac_vap_stru *mac_vap);
hi_void mac_vap_init_rates_by_protocol(mac_vap_stru *mac_vap, wlan_protocol_enum_uint8 vap_protocol,
    mac_data_rate_stru *rates);
hi_u32 mac_vap_del_user(mac_vap_stru *mac_vap, hi_u8 user_idx);
hi_u32 mac_vap_add_assoc_user(mac_vap_stru *mac_vap, hi_u8 user_idx);
hi_u32 mac_vap_find_user_by_macaddr(mac_vap_stru *mac_vap, const hi_u8 *sta_mac_addr, hi_u8 mac_addr_len,
    hi_u8 *puc_user_idx);
hi_u32 mac_vap_init(mac_vap_stru *mac_vap, hi_u8 vap_id, const mac_cfg_add_vap_param_stru *param);
hi_void mac_vap_init_wme_param(const mac_vap_stru *mac_vap);
hi_void mac_vap_check_bss_cap_info_phy_ap(hi_u16 us_cap_info, const mac_vap_stru *mac_vap);
hi_void mac_vap_get_bandwidth_cap(mac_vap_stru *mac_vap, wlan_bw_cap_enum_uint8 *pen_cap);
hi_void mac_vap_init_user_security_port(const mac_vap_stru *mac_vap, mac_user_stru *mac_user);
hi_void mac_vap_change_mib_by_bandwidth(const mac_vap_stru *mac_vap, wlan_channel_bandwidth_enum_uint8 bandwidth);
hi_u32 mac_vap_config_vht_ht_mib_by_protocol(const mac_vap_stru *mac_vap);
hi_u32 mac_vap_set_default_key(const mac_vap_stru *mac_vap, hi_u8  key_index);
hi_u32 mac_vap_set_default_mgmt_key(const mac_vap_stru *mac_vap, hi_u8 key_index);
hi_u32 mac_vap_set_beacon(mac_vap_stru *mac_vap, const mac_beacon_param_stru *beacon_param);
hi_u32 mac_vap_add_beacon(mac_vap_stru *mac_vap, const mac_beacon_param_stru *beacon_param);
hi_u32 mac_vap_init_by_protocol(mac_vap_stru *mac_vap, wlan_protocol_enum_uint8 protocol);
hi_u32 mac_vap_save_app_ie(mac_vap_stru *mac_vap, const oal_app_ie_stru *app_ie, en_app_ie_type_uint8 type);
hi_u32 mac_vap_init_privacy(mac_vap_stru *mac_vap, mac_cfg80211_connect_security_stru *mac_sec_param);
hi_u32 mac_vap_set_current_channel(mac_vap_stru *mac_vap, wlan_channel_band_enum_uint8 band, hi_u8 channel);
hi_u32 mac_vap_add_key(const mac_vap_stru *mac_vap, mac_user_stru *mac_user, hi_u8 key_id,
                       const mac_key_params_stru *key);
hi_u8 mac_vap_get_default_key_id(const mac_vap_stru *mac_vap);
hi_u8 mac_vap_get_curr_baserate(mac_vap_stru *mac_vap, hi_u8 br_idx);
mac_user_stru *mac_vap_get_user_by_addr(mac_vap_stru *mac_vap, const hi_u8 *mac_addr);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_void mac_vap_set_mib_mesh(const mac_vap_stru *mac_vap, hi_u8 mesh_auth_protocol);
#endif
wlan_prot_mode_enum_uint8 mac_vap_get_user_protection_mode(const mac_vap_stru *mac_vap, const mac_user_stru *mac_user);
hi_void mac_vap_set_cb_tx_user_idx(mac_vap_stru *mac_vap, hi_void *tx_ctl, const hi_u8 *mac_addr);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __MAC_VAP_H__ */

