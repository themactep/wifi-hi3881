/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Dmac external public interface header file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __DMAC_EXT_IF_H__
#define __DMAC_EXT_IF_H__
/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "mac_device.h"
#include "frw_event.h"
#include "hcc_comm.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define DMAC_UCAST_TX_COMP_TIMES      5           /* ����BA�Ựǰ����Ҫ��������֡�ķ�������ж� */

#define DMAC_BA_SEQNO_MASK                  0x0FFF      /* max sequece number */
#define DMAC_BA_MAX_SEQNO_BY_TWO            2048
#define DMAC_BA_GREATER_THAN_SEQHI          1
#define DMAC_BA_BETWEEN_SEQLO_SEQHI         2
#define DMAC_BA_BMP_SIZE                    64
#define dmac_ba_seq_add(_seq1, _seq2)       (((_seq1) + (_seq2)) & DMAC_BA_SEQNO_MASK)
#define dmac_ba_seq_sub(_seq1, _seq2)       (((_seq1) - (_seq2)) & DMAC_BA_SEQNO_MASK)
#define dmac_ba_seqno_add(_seq1, _seq2)     (((_seq1) + (_seq2)) & DMAC_BA_SEQNO_MASK)
#define dmac_ba_seqno_sub(_seq1, _seq2)     (((_seq1) - (_seq2)) & DMAC_BA_SEQNO_MASK)

#define DMAC_INVALID_BA_LUT_INDEX          HAL_MAX_BA_LUT_SIZE
#define DMAC_TID_MAX_BUFS                  128          /* ����BA���ڼ�¼seq number����������������2���������� */
#define DMAC_TX_BUF_BITMAP_WORD_SIZE       32           /* ����BA���ڼ�¼seq number��bitmap��ʹ�õ����ͳ��� */
/* ����BA���ڼ�¼seq number��bit map�ĳ��� */
#define DMAC_TX_BUF_BITMAP_WORDS \
    ((DMAC_TID_MAX_BUFS + DMAC_TX_BUF_BITMAP_WORD_SIZE - 1) / DMAC_TX_BUF_BITMAP_WORD_SIZE)
#define DMAC_WPA_802_11I                   BIT0         /* ��ȫ���� :  bss_info �м�¼AP ������ʶ�� WPA or WPA2 */
#define DMAC_RSNA_802_11I                  BIT1

#define DMAC_TX_MAX_RISF_NUM                6
#define DMAC_TX_QUEUE_AGGR_DEPTH            2
#define DMAX_TX_QUEUE_SINGLE_DEPTH          2
#define DMAC_TX_QEUEU_MAX_PPDU_NUM          2
#define DMAC_TX_QUEUE_UAPSD_DEPTH           5
#define DMAC_TX_QUEUE_FAIL_CHECK_NUM        1000
#define DMAC_PA_ERROR_OFFSET 3
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  ö��˵��: DMACģ��ROM��Ԥ���ص��ӿ����Ͷ���
*****************************************************************************/
typedef enum {
    DMAC_ROM_RESV_FUNC_FCS_START,
    DMAC_ROM_RESV_FUNC_RX_FILTER_AP,
    DMAC_ROM_RESV_FUNC_RX_FILTER_STA,
    DMAC_ROM_RESV_FUNC_RX_PROCESS_CONTROL,
    DMAC_ROM_RESV_FUNC_STA_UP_RX_BEACON,
    DMAC_ROM_RESV_FUNC_SCAN_MGMT_FILER,
    DMAC_ROM_RESV_FUNC_AP_UP_RX_OBSS_BEACON,
    DMAC_ROM_RESV_FUNC_AP_UP_RX_PROBE_REQ,
    DMAC_ROM_RESV_FUNC_MESH_CHECK_UNICAST_REPORT,
    DMAC_ROM_RESV_FUNC_MAC_MBCA_IE,
    DMAC_ROM_RESV_FUNC_TX_DEL_BA,
    DMAC_ROM_RESV_FUNC_HANDLE_CHAN_MGMT_STA,
    DMAC_ROM_RESV_FUNC_CHAN_SWITCH_SYNC,
    DMAC_ROM_RESV_FUNC_PSM_ALARM_CALLBACK,
    DMAC_ROM_RESV_FUNC_BCN_RX_ADJUST,
    DMAC_ROM_RESV_FUNC_TBTT_EVENT_HANDLE,
    DMAC_ROM_RESV_FUNC_BUTT
} dmac_rom_resv_func_enum;
typedef hi_u8 dmac_rom_resv_func_enum_uint8;
/*****************************************************************************
  ö��˵��: HOST DRX�¼������Ͷ���
*****************************************************************************/
typedef enum {
    DMAC_TX_HOST_DRX = 0,

    DMAC_TX_HOST_DRX_BUTT
} dmac_tx_host_drx_subtype_enum;
typedef hi_u8 dmac_tx_host_drx_subtype_enum_uint8;

/*****************************************************************************
  ö��˵��: WLAN DTX�¼������Ͷ���
*****************************************************************************/
typedef enum {
    DMAC_TX_WLAN_DTX = 0,

    DMAC_TX_WLAN_DTX_BUTT
} dmac_tx_wlan_dtx_subtype_enum;
typedef hi_u8 dmac_tx_wlan_dtx_subtype_enum_uint8;

/*****************************************************************************
  ö��˵��: WLAN CTX�¼������Ͷ���
*****************************************************************************/
typedef enum {
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_ACTION = 0,
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_ADD_USER,
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_NOTIFY_ALG_ADD_USER,
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_DEL_USER,
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_BA_SYNC,               /* �յ�wlan��Delba��addba rsp���ڵ�dmac��ͬ�� */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_PRIV_REQ,              /* 11N�Զ����������¼����� */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_SCAN_REQ,              /* ɨ������ */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_SCHED_SCAN_REQ,        /* PNO����ɨ������ */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_MGMT,                  /* ����֡���� */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_RESET_PSM,             /* �յ���֤���� �������󣬸�λ�û��Ľ���״̬ */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_JOIN_SET_REG,
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_JOIN_DTIM_TSF_REG,
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_CONN_RESULT,           /* ������� */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_STA_SET_EDCA_REG,      /* STA�յ�beacon��assoc rspʱ������EDCA�Ĵ��� */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_SWITCH_TO_NEW_CHAN,    /* �л������ŵ��¼� */
    DMAC_WALN_CTX_EVENT_SUB_TYPR_SELECT_CHAN,           /* �����ŵ��¼� */
    DMAC_WALN_CTX_EVENT_SUB_TYPR_DISABLE_TX,            /* ��ֹӲ������ */
    DMAC_WALN_CTX_EVENT_SUB_TYPR_ENABLE_TX,             /* �ָ�Ӳ������ */
    DMAC_WLAN_CTX_EVENT_SUB_TYPR_RESTART_NETWORK,       /* �л��ŵ��󣬻ָ�BSS������ */
#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_PSM_OPMODE_NOTIFY,     /* AP��opmode notify֡ʱ�жϽ�����Ϣ */
#endif
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_SET_RX_FILTER,
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    DMAC_WLAN_CTX_EVENT_SUB_TYPR_EDCA_OPT,                /* edca�Ż���ҵ��ʶ��֪ͨ�¼� */
#endif
#ifdef _PRE_WLAN_RF_110X_CALI_DPD
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_DPD_DATA_PROCESSED,
#endif
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_CALI_HMAC2DMAC,
#ifdef _PRE_WLAN_FEATURE_PKT_MEM_OPT
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_DSCR_OPT,
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_SET_MESH_USER_WHITELIST,    /* ����Mesh�û�����������ָ�����鲥/�㲥����֡ */
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_UNSET_MESH_USER_WHITELIST,  /* ɾ��Mesh�û��������е�ĳ����ַ */
#endif
    DMAC_WLAN_CTX_EVENT_SUB_TYPE_CONN_FAIL_SET_CHANNEL,      /* ���ڹ���ʱ����ʧ�ָܻ�ap�ŵ����� */

    DMAC_WLAN_CTX_EVENT_SUB_TYPE_BUTT
} dmac_wlan_ctx_event_sub_type_enum;
typedef hi_u8 dmac_wlan_ctx_event_sub_type_enum_uint8;

/* DMACģ�� WLAN_DRX�����Ͷ��� */
typedef enum {
    DMAC_WLAN_DRX_EVENT_SUB_TYPE_RX_AP,                 /* APģʽ: DMAC WLAN DRX ���� */
    DMAC_WLAN_DRX_EVENT_SUB_TYPE_RX_STA,                /* STAģʽ: DMAC WLAN DRX ���� */
    DMAC_WLAN_DRX_EVENT_SUB_TYPE_TKIP_MIC_FAILE,        /* DMAC tkip mic faile �ϱ���HMAC */

    DMAC_WLAN_DRX_EVENT_SUB_TYPE_BUTT
} dmac_wlan_drx_event_sub_type_enum;
typedef hi_u8 dmac_wlan_drx_event_sub_type_enum_uint8;

/* DMACģ�� WLAN_CRX�����Ͷ��� */
typedef enum {
    DMAC_WLAN_CRX_INIT,              /* DMAC �� HMAC�ĳ�ʼ������ */
    DMAC_WLAN_CRX_RX,                /* DMAC WLAN CRX ���� */
    DMAC_WLAN_CRX_DELBA,             /* DMAC���������DELBA֡ */
    DMAC_WLAN_CRX_SCAN_RESULT,       /* ɨ�赽һ��bss��Ϣ���ϱ���� */
    DMAC_WLAN_CRX_SCAN_COMP,         /* DMACɨ������ϱ���HMAC */
    DMAC_WLAN_CRX_OBSS_SCAN_COMP,    /* DMAC OBSSɨ���ϱ�HMAC */
    DMAC_WLAN_CRX_ACS_RESP,          /* ACS */
#ifdef _PRE_WLAN_FEATURE_FLOWCTL
    DMAC_WLAN_CRX_FLOWCTL_BACKP,     /* dmac��hmac���������Ʒ�ѹ��Ϣ */
#endif
    DMAC_WLAN_CRX_DISASSOC,          /* DMAC�ϱ�ȥ�����¼���HMAC, HMAC��ɾ���û� */
    DMAC_WLAN_CRX_DEAUTH,            /* DMAC�ϱ�ȥ��֤�¼���HMAC */
    DMAC_WLAN_CRX_CH_SWITCH_COMPLETE, /* �ŵ��л�����¼� */
    DMAC_WLAN_CRX_DBAC,              /* DBAC enable/disable�¼� */
#ifdef _PRE_WLAN_FEATURE_WOW_ROM
    DMAC_WLAN_CRX_DEV_SYNC_HOST,
#endif
    DMAC_WLAN_CRX_SLEEP_REQ,
#ifdef _PRE_WLAN_FEATURE_CSI
    DMAC_WLAN_CRX_CSI_REPORT,       /* DMAC�ɼ�CSI�������¼���HMAC */
#endif
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    DMAC_WLAN_CRX_NEW_PEER_REPORT,  /* DMAC�ϱ�new peer beacon֡ */
#endif
#ifdef _PRE_WLAN_FEATURE_PROMIS
    DMAC_WLAN_CRX_EVENT_PROMIS,
#endif
    DMAC_WLAN_CRX_SUB_TYPE_BUTT
} dmac_wlan_crx_event_sub_type_enum;
typedef hi_u8 dmac_wlan_crx_event_sub_type_enum_uint8;

/* ����HOST��������¼� */
typedef enum {
    DMAC_TO_HMAC_CREATE_BA,
    DMAC_TO_HMAC_DEL_BA,
    DMAC_TO_HMAC_SYN_CFG,
    DMAC_TO_HMAC_ALG_INFO_SYN,
    DMAC_TO_HMAC_VOICE_AGGR,
    DMAC_TO_HMAC_PROTECTION_INFO_SYN,

    DMAC_TO_HMAC_SYN_BUTT
} dmac_to_hmac_syn_type_enum;

/* MISC��ɢ�¼� */
typedef enum {
    DMAC_MISC_SUB_TYPE_DISASOC,
#ifdef _PRE_WLAN_FEATURE_WOW
    DMAC_MISC_SUB_TYPE_DEV_READY_FOR_HOST_SLP,
#endif
    DMAC_MISC_SUB_TYPE_BUTT
} dmac_misc_sub_type_enum;

typedef enum {
    WAIT_ADD,
    DMAC_HCC_RX_EVENT_SUB_TYPE_BUTT
} dmac_hcc_rx_event_sub_type_enum;

typedef enum {
    DMAC_DISASOC_MISC_LINKLOSS = 0,
    DMAC_DISASOC_MISC_KEEPALIVE = 1,
    DMAC_DISASOC_MISC_CHANNEL_MISMATCH = 2,
    DMAC_DISASOC_MISC_WOW_RX_DISASSOC = 3,
    DMAC_DISASOC_MISC_WOW_RX_DEAUTH = 4,
    DMAC_DISASOC_MISC_KICKUSER = 5,
    DMAC_DISASOC_ROAM_HANDLE_FAIL = 6,
    DMAC_DISASOC_SA_QUERY_DEL_USER = 7,

    DMAC_DISASOC_MISC_BUTT
} dmac_disasoc_misc_reason_enum;
typedef hi_u16 dmac_disasoc_misc_reason_enum_uint16;

/* HMAC to DMACͬ������ */
typedef enum {
    HMAC_TO_DMAC_SYN_INIT,
    HMAC_TO_DMAC_SYN_CREATE_CFG_VAP,
    HMAC_TO_DMAC_SYN_CFG,
    HMAC_TO_DMAC_SYN_ALG,

    HMAC_TO_DMAC_SYN_BUTT
} hmac_to_dmac_syn_type_enum;
typedef hi_u8 hmac_to_dmac_syn_type_enum_uint8;

/* TXRX�����ص����ζ��� */
typedef enum {
    DMAC_TXRX_PASS = 0,     /* �������� */
    DMAC_TXRX_DROP = 1,     /* ��Ҫ���� */
    DMAC_TXRX_SENT = 2,     /* �ѱ����� */
    DMAC_TXRX_BUFF = 3,     /* �ѱ����� */

    DMAC_TXRX_BUTT
} dmac_txrx_output_type_enum;
typedef hi_u8 dmac_txrx_output_type_enum_uint8;

/* ����ѵ��״̬ */
typedef enum {
    DMAC_USER_SMARTANT_NON_TRAINING        = 0,
    DMAC_USER_SMARTANT_NULLDATA_TRAINING   = 1,
    DMAC_USER_SMARTANT_DATA_TRAINING       = 2,

    DMAC_USER_SMARTANT_TRAINING_BUTT
} dmac_user_smartant_training_enum;
typedef hi_u8 dmac_user_smartant_training_enum_uint8;

/* �㷨�ı���̽���־ (ע:����1102��ö��ֻ����ʹ��3bit�ռ�, �����Чö��ֵ���Ϊ7) */
typedef enum {
    DMAC_USER_ALG_NON_PROBE                     = 0,    /* ��̽�ⱨ�� */
    DMAC_USER_ALG_TXBF_SOUNDING                 = 1,    /* TxBf sounding���� */
    DMAC_USER_ALG_AUOTRATE_PROBE                = 2,    /* Autorate̽�ⱨ�� */
    DMAC_USER_ALG_AGGR_PROBE                    = 3,    /* �ۺ�̽�ⱨ�� */
    DMAC_USER_ALG_TPC_PROBE                     = 4,    /* TPC̽�ⱨ�� */
    DMAC_USER_ALG_TX_MODE_PROBE                 = 5,    /* ����ģʽ̽�ⱨ��(TxBf, STBC, Chain) */
    DMAC_USER_ALG_SMARTANT_NULLDATA_PROBE       = 6,    /* ��������NullDataѵ������ */
    DMAC_USER_ALG_SMARTANT_DATA_PROBE           = 7,    /* ��������Dataѵ������ */

    DMAC_USER_ALG_PROBE_BUTT
} dmac_user_alg_probe_enum;
typedef hi_u8 dmac_user_alg_probe_enum_uint8;

/* BA�Ự��״̬ö�� */
typedef enum {
    DMAC_BA_INIT        = 0,    /* BA�Ựδ���� */
    DMAC_BA_INPROGRESS,         /* BA�Ự���������� */
    DMAC_BA_COMPLETE,           /* BA�Ự������� */
    DMAC_BA_HALTED,             /* BA�Ự������ͣ */
    DMAC_BA_FAILED,             /* BA�Ự����ʧ�� */

    DMAC_BA_BUTT
} dmac_ba_conn_status_enum;
typedef hi_u8 dmac_ba_conn_status_enum_uint8;

/* Type of Tx Descriptor status */
typedef enum {
    DMAC_TX_INVALID   = 0,                /* ��Ч */
    DMAC_TX_SUCC,                         /* �ɹ� */
    DMAC_TX_FAIL,                         /* ����ʧ�ܣ������ش����ƣ�������Ӧ֡��ʱ�� */
    DMAC_TX_TIMEOUT,                      /* lifetime��ʱ��û���ͳ�ȥ�� */
    DMAC_TX_RTS_FAIL,                     /* RTS ����ʧ�ܣ������ش����ƣ�����cts��ʱ�� */
    DMAC_TX_NOT_COMPRASS_BA,              /* �յ���BA�Ƿ�ѹ����ȷ�� */
    DMAC_TX_TID_MISMATCH,                 /* �յ���BA��TID�뷢��ʱ��д���������е�TID��һ�� */
    DMAC_TX_KEY_SEARCH_FAIL,              /* Key search failed */
    DMAC_TX_AMPDU_MISMATCH,               /* �������쳣 */
    DMAC_TX_PENDING,                      /* tx pending��mac���͹���֡������û�гɹ����ȴ��ش� */
    DMAC_TX_FAIL_ACK_ERROR,               /* ����ʧ�ܣ������ش����ƣ����յ�����Ӧ֡���� */
    DMAC_TX_RTS_FAIL_CTS_ERROR,           /* RTS����ʧ�ܣ������ش����ƣ����յ���CTS���� */
    DMAC_TX_FAIL_ABORT,                   /* ����ʧ�ܣ���Ϊabort�� */
    DMAC_TX_FAIL_STATEMACHINE_PHY_ERROR,  /* MAC���͸�֡�쳣������״̬����ʱ��phy��ǰ������ԭ�� */
    DMAC_TX_SOFT_PSM_BACK,                /* ������ܻ��� */
    DMAC_TX_SOFT_RESERVE,                 /* reserved */
} dmac_tx_dscr_status_enum;
typedef hi_u8 dmac_tx_dscr_status_enum_uint8;

typedef enum {
    DMAC_TX_MODE_NORMAL  = 0,
    DMAC_TX_MODE_RIFS    = 1,
    DMAC_TX_MODE_AGGR    = 2,
    DMAC_TX_MODE_BUTT
} dmac_tx_mode_enum;
typedef hi_u8 dmac_tx_mode_enum_uint8;

/* mib index���� */
typedef enum {
    WLAN_MIB_INDEX_LSIG_TXOP_PROTECTION_OPTION_IMPLEMENTED,
    WLAN_MIB_INDEX_HT_GREENFIELD_OPTION_IMPLEMENTED,
    WLAN_MIB_INDEX_SPEC_MGMT_IMPLEMENT,
    WLAN_MIB_INDEX_FORTY_MHZ_OPERN_IMPLEMENT,
    WLAN_MIB_INDEX_2040_COEXT_MGMT_SUPPORT,
    WLAN_MIB_INDEX_FORTY_MHZ_INTOL,
    WLAN_MIB_INDEX_VHT_CHAN_WIDTH_OPTION_IMPLEMENT,
    WLAN_MIB_INDEX_MINIMUM_MPDU_STARTING_SPACING,

    WLAN_MIB_INDEX_OBSSSCAN_TRIGGER_INTERVAL,   /* 8 */
    WLAN_MIB_INDEX_OBSSSCAN_TRANSITION_DELAY_FACTOR,
    WLAN_MIB_INDEX_OBSSSCAN_PASSIVE_DWELL,
    WLAN_MIB_INDEX_OBSSSCAN_ACTIVE_DWELL,
    WLAN_MIB_INDEX_OBSSSCAN_PASSIVE_TOTAL_PER_CHANNEL,
    WLAN_MIB_INDEX_OBSSSCAN_ACTIVE_TOTAL_PER_CHANNEL,
    WLAN_MIB_INDEX_OBSSSCAN_ACTIVITY_THRESHOLD, /* 14 */

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
    WLAN_MIB_INDEX_MESH_ACCEPTING_PEER,
    WLAN_MIB_INDEX_MESH_SECURITY_ACTIVATED,
#endif
    WLAN_MIB_INDEX_BUTT
} wlan_mib_index_enum;
typedef hi_u16 wlan_mib_index_enum_uint16;

typedef enum {
    DMAC_TID_PAUSE_RESUME_TYPE_BA   = 0,
    DMAC_TID_PAUSE_RESUME_TYPE_PS   = 1,
    DMAC_TID_PAUSE_RESUME_TYPE_BUTT
} dmac_tid_pause_type_enum;
typedef hi_u8 dmac_tid_pause_type_enum_uint8;

/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
typedef struct {
    dmac_disasoc_misc_reason_enum_uint16     disasoc_reason;
    hi_u8                               user_idx;
    hi_u8                                uc_resv;
} dmac_disasoc_misc_stru;

/* ����֡��ͳ����Ϣ */
typedef struct {
    hi_u32  total_num;           /* ���� */
    hi_u32  self_fcs_correct;    /* �����Լ���FCS��ȷ�ĵ���֡ */
    hi_u32  other_fcs_correct;   /* ���Ƿ����Լ���FCS��ȷ�ĵ���֡ */
    hi_u32  total_fcs_error;     /* FCS���������֡ */
} dmac_rx_fcs_statistic;

typedef struct {
    hi_u8                   tid_num;                            /* ��Ҫ���͵�tid���к� */
    dmac_tx_mode_enum_uint8 tx_mode;                            /* ����tid�ķ���ģʽ */
    hi_u8                   mpdu_num[DMAC_TX_QUEUE_AGGR_DEPTH]; /* ���ȵõ�����Ҫ���͵�mpdu���� */
    hi_u8                   user_idx;                           /* Ҫ���͵�tid����������user */
    hi_u8                   ba_is_jamed;                        /* ��ǰBA���Ƿ����ı�־λ */
    hi_u8                   uc_resv[2];                         /* 2 byte�����ֶ� */
} mac_tid_schedule_output_stru;

/* DMAC��HMACģ�鹲�õ�WLAN DRX�¼��ṹ�� */
typedef struct {
    oal_dev_netbuf_stru *netbuf;            /* netbuf����һ��Ԫ�� */
    hi_u16              us_netbuf_num;      /* netbuf����ĸ��� */
    hi_u8               auc_resv[2];        /* �ֽڶ���, 2 byte�����ֶ� */
} dmac_wlan_drx_event_stru;

/* DMAC��HMACģ�鹲�õ�WLAN CRX�¼��ṹ�� */
typedef struct {
    oal_dev_netbuf_stru        *netbuf;         /* ָ�����֡��Ӧ��netbuf */
    hi_u8              *puc_chtxt;          /* Shared Key��֤�õ�challenge text */
} dmac_wlan_crx_event_stru;

#ifdef _PRE_WLAN_FEATURE_BTCOEX
typedef struct {
    hi_u8 need_delba;
    hi_u8 ba_size;
    hi_u8 auc_reserve[2]; /* 2 byte�����ֶ� */
} d2h_btcoex_delba_event_stru;
#endif

typedef struct {
    hi_u8       user_index;
    hi_u8       tid;
    hi_u8       vap_id;
    hi_u8       cur_protocol;
} dmac_to_hmac_ctx_event_stru;

typedef struct {
    hi_u8       user_index;
    hi_u8       cur_bandwidth;
    hi_u8       cur_protocol;
    hi_u8       uc_resv;
} dmac_to_hmac_syn_info_event_stru;

typedef struct {
    hi_u8       vap_id;
    hi_u8       voice_aggr;  /* �Ƿ�֧��Voice�ۺ� */
    hi_u8       auc_resv[2]; /* 2 byte�����ֶ� */
} dmac_to_hmac_voice_aggr_event_stru;

/* mic���� */
typedef struct {
    hi_u8                  auc_user_mac[WLAN_MAC_ADDR_LEN];
    hi_u8                  auc_reserve[2]; /* 2 byte�����ֶ� */
    oal_nl80211_key_type       key_type;
    hi_s32                  l_key_id;
} dmac_to_hmac_mic_event_stru;

/* DMAC��HMACģ�鹲�õ�DTX�¼��ṹ�� */
typedef struct {
    void                   *netbuf;         /* netbuf����һ��Ԫ�� */
    hi_u32                  us_frame_len;
} dmac_tx_event_stru;

#ifdef _PRE_WLAN_RF_110X_CALI_DPD
typedef struct {
    hi_u32        us_dpd_data[128];  /* dpd calibration data,128 byte */
    hi_u16        us_data_len;       /* data length */
    hi_u8         reserve[2];        /* 2 byte�����ֶ� */
} dpd_cali_data_stru;
#endif

typedef struct {
    mac_channel_stru                     channel;
    mac_ch_switch_info_stru              ch_switch_info;

    hi_u8                  switch_immediately;  /* 1 - �����л�  0 - �ݲ��л�, �Ƴٵ�tbtt���л� */
    hi_u8                  check_cac;
    hi_u8                            auc_resv[2]; /* 2 byte�����ֶ� */
} dmac_set_chan_stru;

typedef struct {
    wlan_ch_switch_status_enum_uint8  ch_switch_status;      /* �ŵ��л�״̬ */
    hi_u8                             announced_channel;     /* ���ŵ��� */
    wlan_channel_bandwidth_enum_uint8 announced_bandwidth;   /* �´���ģʽ */
    hi_u8                             ch_switch_cnt;         /* �ŵ��л����� */
    hi_u8                             csa_present_in_bcn;    /* Beacon֡���Ƿ����CSA IE */
    hi_u8                             auc_reserve[3];        /* 3 byte�����ֶ� */
} dmac_set_ch_switch_info_stru;

/*
    (1)DMAC��HMACģ�鹲�õ�CTX������ACTION��Ӧ���¼��Ľṹ��
    (2)��DMAC�������DELBA֡ʱ��ʹ�øýṹ����HMACģ�����¼�
*/
typedef struct {
    mac_category_enum_uint8 action_category;     /* ACTION֡������ */
    hi_u8                   action;              /* ��ͬACTION���µ���֡���� */
    hi_u8                   user_idx;
    hi_u8                   uc_resv;

    hi_u32                  us_frame_len;        /* ֡���� */

    hi_u8                   hdr_len;             /* ֡ͷ���� */
    hi_u8                   tidno;               /* tidno������action֡ʹ�� */
    hi_u8                   initiator;           /* �����˷��� */
    /* ����Ϊ���յ�req֡������rsp֡����Ҫͬ����dmac������ */
    hi_u8                   stauts;              /* rsp֡�е�״̬ */

    hi_u16                  us_baw_start;        /* ���ڿ�ʼ���к� */
    hi_u16                  us_baw_size;         /* ���ڴ�С */

    hi_u8                   ampdu_max_num;       /* BA�Ự�µ����ۺϵ�AMPDU�ĸ��� */
    hi_u8                   amsdu_supp;          /* �Ƿ�֧��AMSDU */
    hi_u16                  us_ba_timeout;       /* BA�Ự������ʱʱ�� */

    mac_back_variant_enum_uint8     back_var;    /* BA�Ự�ı��� */
    hi_u8                   dialog_token;        /* ADDBA����֡��dialog token */
    hi_u8                   ba_policy;           /* Immediate=1 Delayed=0 */
    hi_u8                   lut_index;           /* LUT���� */
    hi_u8                   auc_mac_addr[WLAN_MAC_ADDR_LEN];    /* ����DELBA����HMAC�û� */
    hi_u8                   resv[2];             /* 2 byte�����ֶ� */
} dmac_ctx_action_event_stru;

/* ����û��¼�payload�ṹ�� */
typedef struct {
    hi_u8   user_idx;     /* �û�index */
    hi_u8   uc_resv;
    hi_u16  us_sta_aid;

    hi_u8   auc_user_mac_addr[WLAN_MAC_ADDR_LEN];
    hi_u8   auc_bssid[WLAN_MAC_ADDR_LEN];

    mac_vht_hdl_stru          vht_hdl;
    mac_user_ht_hdl_stru      ht_hdl;
    mac_ap_type_enum_uint8    ap_type;
    hi_u8                     resv[3]; /* 3 byte�����ֶ� */
} dmac_ctx_add_user_stru;

/* ɾ���û��¼��ṹ�� */
typedef dmac_ctx_add_user_stru dmac_ctx_del_user_stru;

/* ɨ�������¼�payload�ṹ�� */
typedef struct {
    mac_scan_req_stru   *scan_params;   /* ��ɨ���������ȥ */
} dmac_ctx_scan_req_stru;

typedef struct {
    hi_u8                   scan_idx;
    hi_u8                   auc_resv[3]; /* 3 byte�����ֶ� */
    mac_scan_chan_stats_stru    chan_result;
} dmac_crx_chan_result_stru;

/* Update join req ����д�Ĵ����Ľṹ�嶨�� */
typedef struct {
    hi_u8             auc_bssid[WLAN_MAC_ADDR_LEN];           /* �����AP��BSSID  */
    hi_u16            us_beacon_period;
    mac_channel_stru  current_channel;                     /* Ҫ�л����ŵ���Ϣ */
    hi_u32            beacon_filter;                       /* ����beacon֡���˲���������ʶλ */
    hi_u32            non_frame_filter;                    /* ����no_frame֡���˲���������ʶλ */
    hi_char           auc_ssid[WLAN_SSID_MAX_LEN];            /* �����AP��SSID  */
    hi_u8             dtim_period;                         /* dtim period      */
    hi_u8             dot11_forty_m_hz_operation_implemented;
    hi_u8             auc_resv;
} dmac_ctx_join_req_set_reg_stru;

/* wait joinд�Ĵ��������Ľṹ�嶨�� */
typedef struct {
    hi_u32              dtim_period;                  /* dtim period */
    hi_u32              dtim_cnt;                     /* dtim count  */
    hi_u8               auc_bssid[WLAN_MAC_ADDR_LEN];    /* �����AP��BSSID  */
    hi_u16              us_tsf_bit0;                     /* tsf bit0  */
} dmac_ctx_set_dtim_tsf_reg_stru;

/* wait join miscд�Ĵ��������Ľṹ�嶨�� */
typedef struct {
    hi_u32              beacon_filter;                /* ����beacon֡���˲���������ʶλ */
} dmac_ctx_join_misc_set_reg_stru;

/* wait joinд�Ĵ��������Ľṹ�嶨�� */
typedef struct {
    hi_u16             user_index;  /* user index */
    hi_u8              auc_resv[2]; /* 2 byte�����ֶ� */
} dmac_ctx_asoc_set_reg_stru;

/* sta����edca�����Ĵ����Ľṹ�嶨�� */
typedef struct {
    hi_u8                             vap_id;
    mac_wmm_set_param_type_enum_uint8 set_param_type;
    hi_u8                             auc_resv[2]; /* 2 byte�����ֶ� */
    wlan_mib_dot11_qapedca_entry_stru ast_wlan_mib_qap_edac[WLAN_WME_AC_BUTT];
} dmac_ctx_sta_asoc_set_edca_reg_stru;

#ifdef _PRE_WLAN_FEATURE_MESH
typedef struct {
    hi_u8 auc_addr[WLAN_MAC_ADDR_LEN];
    hi_u8 set;                       /* 0 - ɾ��ĳ�ಥ��ַ��1 - ����ĳ�ಥ��ַ */
    hi_u8 rsv;
} dmac_ctx_mesh_mac_addr_whitelist_stru;
#endif

/* DMACģ��ģ��������̿�����Ϣ���ݽṹ����, ��hal_rx_ctl_stru�ṹ�屣��һ�� */
typedef struct {
    /* word 0 */
    hi_u8                   vap_id            : 5;
    hi_u8                   amsdu_enable      : 1;
    hi_u8                   is_first_buffer   : 1;
    hi_u8                   is_fragmented     : 1;
    hi_u8                   msdu_in_buffer;
    hi_u8                   da_user_idx       : 4;
    hi_u8                   ta_user_idx       : 4;
    hi_u8                   mac_header_len    : 6;  /* mac header֡ͷ���� */
    hi_u8                   is_beacon         : 1;
    hi_u8                   reserved1         : 1;
    /* word 1 */
    hi_u16                  us_frame_len;            /* ֡ͷ��֡����ܳ��� */
    hi_u8                   mac_vap_id         : 4;
    hi_u8                   buff_nums          : 4;  /* ÿ��MPDUռ�õ�buf�� */
    hi_u8                   channel_number;          /* ����֡���ŵ� */
} dmac_rx_info_stru;

/* rx cb�ֶ� 20�ֽڿ��� �������������ֽ�! */
typedef struct {
    hi_s8            rssi_dbm;
    union {
        struct {
            hi_u8   bit_vht_mcs       : 4;
            hi_u8   bit_nss_mode      : 2;
            hi_u8   bit_protocol_mode : 2;
        } st_vht_nss_mcs;                                   /* 11ac�����ʼ����� */
        struct {
            hi_u8   bit_ht_mcs        : 6;
            hi_u8   bit_protocol_mode : 2;
        } st_ht_rate;                                       /* 11n�����ʼ����� */
        struct {
            hi_u8   bit_legacy_rate   : 4;
            hi_u8   bit_reserved1     : 2;
            hi_u8   bit_protocol_mode : 2;
        } st_legacy_rate;                                   /* 11a/b/g�����ʼ����� */
    } un_nss_rate;

    hi_u8           uc_short_gi;
    hi_u8           uc_bandwidth;
} hal_rx_statistic_stru;

#pragma pack(push, 1)
typedef struct {
    /* word 0 */
    hi_u8   cipher_protocol_type  : 3;
    hi_u8   ampdu                 : 1;
    hi_u8   dscr_status           : 4;
    hi_u8   stbc                  : 2;
    hi_u8   gi                    : 1;
    hi_u8   smoothing             : 1;
    hi_u8   preabmle              : 1;
    hi_u8   rsvd                  : 3;
    hi_u8   auc_resv[2];   /* 2: Ԥ�������С */
} hal_rx_status_stru;
#pragma pack(pop)

typedef struct {
    dmac_rx_info_stru           rx_info;         /* hal����dmac��������Ϣ */
    hal_rx_status_stru          rx_status;       /* ����������ͼ�֡����Ϣ */
    hal_rx_statistic_stru       rx_statistic;    /* ���������������ͳ����Ϣ */
} dmac_rx_ctl_stru;

/* hmac to dmac����ͬ����Ϣ�ṹ */
typedef struct {
    wlan_cfgid_enum_uint16 syn_id;          /* ͬ���¼�ID */
    hi_u16                 us_len;          /* �¼�payload���� */
    hi_u8                  auc_msg_body[4]; /* �¼�payload, 4byte */
} hmac_to_dmac_cfg_msg_stru;

typedef hmac_to_dmac_cfg_msg_stru dmac_to_hmac_cfg_msg_stru;

/* HMAC��DMAC����ͬ������ */
typedef struct {
    wlan_cfgid_enum_uint16  cfgid;
    hi_u8                   auc_resv[2]; /* 2 byte�����ֶ� */
    hi_u32(*set_func)(mac_vap_stru *mac_vap, hi_u8 uc_len, const hi_u8 *puc_param);
} dmac_config_syn_stru;

typedef dmac_config_syn_stru hmac_config_syn_stru;

/* tx cb�ֶ� ��ǰ����19�ֽڣ�ֻ��20�ֽڿ��� �������������ֽ�! */
struct dmac_tx_ctl {
    /* ampdu�а�����MPDU����,ʵ����������д��ֵΪ��ֵ-1 */
    hi_u8                               mpdu_num                : 7;
    hi_u8                               netbuf_num              : 1;   /* ÿ��MPDUռ�õ�netbuf��Ŀ */

    hi_u8                               frame_header_length     : 6;   /* ��MPDU��802.11ͷ���� */
    hi_u8                               is_first_msdu           : 1;   /* �Ƿ��ǵ�һ����֡��HI_FALSE���� HI_TRUE�� */
    hi_u8                               is_amsdu                : 1;   /* �Ƿ�AMSDU: HI_FALSE���ǣ�HI_TRUE�� */

    /* ȡֵ:FRW_EVENT_TYPE_WLAN_DTX��FRW_EVENT_TYPE_HOST_DRX������:���ͷ�ʱ�������ڴ�ص�netbuf����ԭ��̬�� */
    frw_event_type_enum_uint8           en_event_type           : 6;
    hi_u8                               is_needretry            : 1;
    hi_u8                               is_vipframe             : 1;   /* ��֡�Ƿ���EAPOL֡��DHCP֡ */

    /* dmac tx �� tx complete ���ݵ�user�ṹ�壬Ŀ���û���ַ */
    hi_u8                               tx_user_idx             : 4;
    dmac_user_alg_probe_enum_uint8      is_probe_data           : 3;    /* �Ƿ�̽��֡ */
    /* ��MPDU�ǵ������Ƕಥ:HI_FALSE������HI_TRUE�ಥ */
    hi_u8                               ismcast                 : 1;

    hi_u8                               retried_num             : 4;
    hi_u8                               need_rsp                : 1;   /* WPAS send mgmt,need dmac response tx status */
    hi_u8                               is_eapol                : 1;   /* ��֡�Ƿ���EAPOL֡ 1102����ȥ�� */
    /* ���������ã���ʶһ��MPDU�Ƿ�ӽ��ܶ�����ȡ������ */
    hi_u8                               is_get_from_ps_queue    : 1;
    hi_u8                               is_eapol_key_ptk        : 1;   /* 4 �����ֹ��������õ�����ԿEAPOL KEY ֡��ʶ */

    hi_u8                               tx_vap_index            : 3;
    hi_u8                               mgmt_frame_id           : 4;   /* wpas ���͹���֡��frame id */
    hi_u8                               roam_data               : 1;

    hi_u8                               ac                      : 3;   /* ac */
    wlan_tx_ack_policy_enum_uint8       ack_policy              : 3;   /* ACK ���� */
    hi_u8                               is_any_frame            : 1;
    hi_u8                               high_prio_sch           : 1;

    hi_u8                               alg_pktno;                     /* �㷨�õ����ֶΣ�Ψһ��ʾ�ñ��� */

    struct timeval                      timestamp_us;                  /* ά��ʹ����TID����ʱ��ʱ��� */

    hi_u8                               tid                     : 4;
    hi_u8                               tx_user_idx_bak         : 4;
    hi_u8                               tsf;
    /* mpdu�ֽ�����ά���ã�������ͷβ��������snap��������padding */
    hi_u16                              us_mpdu_bytes;
} __OAL_DECLARE_PACKED;
typedef struct dmac_tx_ctl  dmac_tx_ctl_stru;

typedef struct {
    hi_u32      best_rate_goodput_kbps;
    hi_u32      rate_kbps;           /* ���ʴ�С(��λ:kbps) */
    hi_u8       aggr_subfrm_size;    /* �ۺ���֡������ֵ */
    hi_u8       per;                 /* �����ʵ�PER(��λ:%) */
    hi_u16      resv;
} dmac_tx_normal_rate_stats_stru;

typedef struct {
    hi_void                               *ba;
    hi_u8                               tid;
    mac_delba_initiator_enum_uint8          direction;
    hi_u8                               mac_user_idx;
    hi_u8                               vap_id;
    hi_u16                              us_timeout_times;
    hi_u8                               uc_resv[2]; /* 2 byte�����ֶ� */
} dmac_ba_alarm_stru;

/* һ��վ���µ�ÿһ��TID�µľۺϽ��յ�״̬��Ϣ */
typedef struct {
    hi_u16                      us_baw_start;         /* ��һ��δ�յ���MPDU�����к� */
    hi_u8                       is_ba;                /* Session Valid Flag */
    hi_u8                       auc_resv;

    /* ����BA�Ự��ص���Ϣ */
    dmac_ba_conn_status_enum_uint8  ba_conn_status;    /* BA�Ự��״̬ */
    mac_back_variant_enum_uint8     back_var;          /* BA�Ự�ı��� */
    hi_u8                       ba_policy;             /* Immediate=1 Delayed=0 */
    hi_u8                       lut_index;             /* ���ն�Session H/w LUT Index */
    hi_u8                      *puc_transmit_addr;     /* BA�Ự���Ͷ˵�ַ */
} dmac_ba_rx_stru;

typedef struct {
    hi_u8    in_use;
    hi_u8    uc_resv[1];
    hi_u16   us_seq_num;
    hi_void *tx_dscr;
} dmac_retry_queue_stru;

typedef struct {
    hi_u16                      us_baw_start;           /* ��һ��δȷ�ϵ�MPDU�����к� */
    hi_u16                      us_last_seq_num;        /* ���һ�����͵�MPDU�����к� */

    hi_u16                      us_baw_size;            /* Block_Ack�Ự��buffer size��С */
    hi_u16                      us_baw_head;            /* bitmap�м�¼�ĵ�һ��δȷ�ϵİ���λ�� */

    hi_u16                      us_baw_tail;            /* bitmap����һ��δʹ�õ�λ�� */
    hi_u8                       is_ba;                  /* Session Valid Flag */
    dmac_ba_conn_status_enum_uint8  ba_conn_status;     /* BA�Ự��״̬ */

    mac_back_variant_enum_uint8 back_var;                /* BA�Ự�ı��� */
    hi_u8                       dialog_token;            /* ADDBA����֡��dialog token */
    hi_u8                       ba_policy;               /* Immediate=1 Delayed=0 */
    hi_u8                       amsdu_supp;              /* BLOCK ACK֧��AMSDU�ı�ʶ */

    hi_u8                      *puc_dst_addr;            /* BA�Ự���ն˵�ַ */
    hi_u16                      us_ba_timeout;           /* BA�Ự������ʱʱ�� */
    hi_u8                       ampdu_max_num;           /* BA�Ự�£��ܹ��ۺϵ�����mpdu�ĸ��� */
    hi_u8                       mac_user_idx;

    hi_u16                      us_pre_baw_start;        /* ��¼ǰһ���ж�ba���Ƿ���ʱ��ssn */
    hi_u16                      us_pre_last_seq_num;     /* ��¼ǰһ���ж�ba���Ƿ���ʱ��lsn */

    hi_u16                      ba_jamed_cnt;            /* BA������ͳ�ƴ��� */
    hi_u8                       resv[2];                 /* 2�����������ֶ� */

    hi_u32                      aul_tx_buf_bitmap[DMAC_TX_BUF_BITMAP_WORDS];
} dmac_ba_tx_stru;

/* 11n�µĲ�������Ҫ�ڹ���ʱ�������� */
typedef struct {
    hi_u8               ampdu_max_num;
    hi_u8               auc_reserve[1];
    hi_u16              us_ampdu_max_size;
} dmac_ht_handle_stru;

#ifdef _PRE_DEBUG_MODE
typedef oam_stats_ampdu_stat_stru dmac_tid_ampdu_stat_stru;
#endif

typedef struct {
    hi_u8               tid          : 4,            /* ͨ�ű�ʶ�� */
                        is_paused    : 2,            /* TID����ͣ���� */
                        is_delba_ing : 1,            /* ��tid�Ƿ����ڷ�delba */
                        uc_resv         : 1;
    hi_u8               retry_num;                   /* tid�������ش����ĵĸ��� */
    hi_u16              us_mpdu_num;                    /* MPDU���� */

    hi_u8               user_idx;                    /* ��ЧֵΪMAC_RES_MAC_USER_NUM */
    hi_u8               vap_id;
    dmac_tx_mode_enum_uint8 tx_mode;                 /* ����ģʽ: rifs,aggr,normal���� */
    hi_u8               rx_wrong_ampdu_num;          /* ��tidδ����BA�Ựʱ�յ��ľۺ���֡��(һ����DELBAʧ��) */

    hi_list             hdr;                         /* tid�������ͷ */

    hi_void             *alg_priv;                   /* TID�����㷨˽�нṹ�� */
    dmac_tx_normal_rate_stats_stru rate_stats;       /* �����㷨�ڷ��������ͳ�Ƴ�����Ϣ */
    dmac_ba_tx_stru     *ba_tx_hdl;
    dmac_ba_rx_stru     *ba_rx_hdl;
    dmac_ht_handle_stru ht_tx_hdl;

#ifdef _PRE_DEBUG_MODE
    dmac_tid_ampdu_stat_stru *tid_ampdu_stat;    /* ampduҵ������ͳ����Ϣ */
#endif
} dmac_tid_stru;

/* ��λԭ���� */
typedef enum {
    DMAC_RESET_REASON_SW_ERR = 0,
    DMAC_RESET_REASON_HW_ERR,
    DMAC_RESET_REASON_CONFIG,
    DMAC_RETST_REASON_OVER_TEMP,

    DMAC_RESET_REASON_BUTT
} dmac_reset_mac_submod_enum;
typedef hi_u8 dmac_reset_mac_submod_enum_uint8;

typedef struct {
    hi_u8 reason;
    hi_u8 event;
    hi_u8 auc_des_addr[WLAN_MAC_ADDR_LEN];
} dmac_diasoc_deauth_event;

#define DMAC_QUERY_EVENT_LEN            48   /* ��Ϣ���ݵĳ��� */
typedef enum {
    OAL_QUERY_STATION_INFO_EVENT      = 1,
    OAL_ATCMDSRV_DBB_NUM_INFO_EVENT   = 2,
    OAL_ATCMDSRV_FEM_PA_INFO_EVENT    = 3,
    OAL_ATCMDSRV_GET_RX_PKCG          = 4,
    OAL_ATCMDSRV_LTE_GPIO_CHECK       = 5,
    OAL_QUERY_EVNET_BUTT
} oal_query_event_id_enum;

typedef struct {
    hi_u8        query_event;
    hi_u8        auc_query_sta_addr[WLAN_MAC_ADDR_LEN];
} dmac_query_request_event;

typedef struct {
    hi_u8        query_event;
    hi_s8        reserve[DMAC_QUERY_EVENT_LEN];
} dmac_query_response_event;

typedef struct {
    hi_u8        query_event;
    hi_u8        auc_query_sta_addr[WLAN_MAC_ADDR_LEN]; /* sta mac��ַ */
} dmac_query_station_info_request_event;

typedef struct {
    hi_s32   signal;          /* �ź�ǿ�� */
    hi_u32   rx_packets;      /* total packets received   */
    hi_u32   tx_packets;      /* total packets transmitted    */
    hi_u32   rx_bytes;        /* total bytes received     */
    hi_u32   tx_bytes;        /* total bytes transmitted  */
    hi_u32   tx_retries;      /* �����ش����� */
    hi_u32   rx_dropped_misc; /* ����ʧ�ܴ��� */
    hi_u32   tx_failed;       /* ����ʧ�ܴ���  */
    /* word10 */
    hi_u16   asoc_id;           /* Association ID of the STA */
    hi_s16   s_free_power;      /* ���� */
    /* word11 */
    oal_rate_info_stru txrate;   /* vap��ǰ���� */
    hi_u8    query_event;        /* ��Ϣ�� */
    hi_u8    resv;
} dmac_query_station_info_response_event;

typedef struct {
    hi_u32  cycles;                  /* ͳ�Ƽ��ʱ�������� */
    hi_u32  sw_tx_succ_num;          /* ���ͳ�Ʒ��ͳɹ�ppdu���� */
    hi_u32  sw_tx_fail_num;          /* ���ͳ�Ʒ���ʧ��ppdu���� */
    hi_u32  sw_rx_ampdu_succ_num;    /* ���ͳ�ƽ��ճɹ���ampdu���� */
    hi_u32  sw_rx_mpdu_succ_num;     /* ���ͳ�ƽ��ճɹ���mpdu���� */
    hi_u32  sw_rx_ppdu_fail_num;     /* ���ͳ�ƽ���ʧ�ܵ�ppdu���� */
    hi_u32  hw_rx_ampdu_fcs_fail_num; /* Ӳ��ͳ�ƽ���ampdu fcsУ��ʧ�ܸ��� */
    hi_u32  hw_rx_mpdu_fcs_fail_num;  /* Ӳ��ͳ�ƽ���mpdu fcsУ��ʧ�ܸ��� */
} dmac_thruput_info_sync_stru;

typedef struct {
    hi_u8         tx_status;
    hi_u8                   mgmt_frame_id;
    hi_u8                   user_idx;
    hi_u8                   uc_resv;
} dmac_crx_mgmt_tx_status_stru;

/* ����ִ�п���ö�� */
typedef enum {
    DMAC_RX_FRAME_CTRL_GOON,        /* ������֡��Ҫ�������� */
    DMAC_RX_FRAME_CTRL_DROP,        /* ������֡��Ҫ���� */
    DMAC_RX_FRAME_CTRL_BA_BUF,      /* ������֡��BA�Ự���� */

    DMAC_RX_FRAME_CTRL_BUTT
} dmac_rx_frame_ctrl_enum;
typedef hi_u8 dmac_rx_frame_ctrl_enum_uint8;

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
/* ��������֡������Ϣ�ϱ�lwip */
typedef struct {
    /* Word1-2 */
    hi_u8   auc_da[WLAN_MAC_ADDR_LEN];           /* MSDU���͵�Ŀ�ĵ�ַ */
    hi_u16  us_length;                           /* ֡�ĳ���(������802.11 ͷ��) */
    /* Word3 */
    hi_u8   tx_count;
    wlan_mesh_tx_status_enum_uint8 mesh_tx_status;
    hi_u8   resv[2];                          /* 2 byte�����ֶ� */
    /* Word4-5 */
    hi_u32  bw;                               /* ���� */
    hi_u32  rate_kbps;                        /* �������� */
} dmac_tx_info_report_stru;

typedef struct {
    hi_u8 auc_da[WLAN_MAC_ADDR_LEN];            /* MSDU���͵�Ŀ�ĵ�ַ */
    wlan_mesh_tx_status_enum_uint8 mesh_tx_status;
    hi_u8 rsv;
} dmac_tx_info_sync_stru;
#endif

/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/* ��hccͷ�������mpdu len */
#define dmac_get_frame_subtype_by_txcb(_pst_tx_ctrl)   \
    (((mac_ieee80211_frame_stru *)((hi_u8 *)(_pst_tx_ctrl) + HI_MAX_DEV_CB_LEN))->frame_control.sub_type)
#ifdef HAVE_PCLINT_CHECK
#define dmac_get_mpdu_len_by_txcb(_pst_tx_ctrl)           \
    (((hcc_header_stru *)((hi_u8 *)(_pst_tx_ctrl) - (OAL_HCC_HDR_LEN)))->pay_len)
#else
#define dmac_get_mpdu_len_by_txcb(_pst_tx_ctrl)           \
    (((hcc_header_stru *)((hi_u8 *)(_pst_tx_ctrl) - (OAL_HCC_HDR_LEN + OAL_PAD_HDR_LEN)))->pay_len)
#endif
#define dmac_get_frame_type_by_txcb(_pst_tx_ctrl)   \
    (((mac_ieee80211_frame_stru *)((hi_u8 *)(_pst_tx_ctrl) + HI_MAX_DEV_CB_LEN))->frame_control.type)

/*****************************************************************************
 ��������  : ��ȡseqnum��ֵ
*****************************************************************************/
static inline hi_u16 dmac_get_seqnum_by_txcb(const dmac_tx_ctl_stru *tx_ctrl)
{
    return ((mac_ieee80211_frame_stru *)((hi_u8 *)tx_ctrl + HI_MAX_DEV_CB_LEN))->seq_num;
}

/*****************************************************************************
 ��������  : ͨ��cb�ֶλ�ȡmacͷָ�� CB�ֶκ�ΪMACͷ
*****************************************************************************/
static inline mac_ieee80211_frame_stru *dmac_get_mac_hdr_by_txcb(dmac_tx_ctl_stru *tx_ctrl)
{
    return (mac_ieee80211_frame_stru *)((hi_u8 *)tx_ctrl + HI_MAX_DEV_CB_LEN);
}

/*****************************************************************************
 ��������  : device���ȡmacͷ��ֵ
*****************************************************************************/
static inline hi_u32 *dmac_get_mac_hdr_by_rxcb(dmac_rx_info_stru *cb_ctrl)
{
    return (hi_u32 *)((hi_u8 *)cb_ctrl + HI_MAX_DEV_CB_LEN);
}


/*****************************************************************************
  HOST�� CB�ֶ��Լ���ȡCB�ֶεĺ궨�� ��hmac������ɺ��ƶ���hmac  TBD
*****************************************************************************/
/* HMACģ��������̿�����Ϣ���ݽṹ���� ֻʹ��20bytes hal��ά����Ϣhmac����Ҫ */
typedef struct {
    /* word 0 */
    hi_u8                   vap_id            : 5;
    hi_u8                   amsdu_enable      : 1;
    hi_u8                   is_first_buffer   : 1;
    hi_u8                   is_fragmented     : 1;
    hi_u8                   msdu_in_buffer;
    hi_u8                   buff_nums         : 4;      /* ÿ��MPDUռ�õ�buf��Ŀ */
    hi_u8                   is_beacon         : 1;
    hi_u8                   reserved1         : 3;
    hi_u8                   mac_header_len;             /* mac header֡ͷ���� */
    /* word 1 */
    hi_u16                  us_frame_len;               /* ֡ͷ��֡����ܳ��� */
    hi_u16                  us_da_user_idx;             /* Ŀ�ĵ�ַ�û����� */
    /* word 2 */
    hi_u32                 *pul_mac_hdr_start_addr;     /* ��Ӧ��֡��֡ͷ��ַ,�����ַ */
    /* word 3 */
    hi_u8                   us_ta_user_idx;             /* ���Ͷ˵�ַ�û����� */
    hi_u8                   mac_vap_id;
    hi_u8                   channel_number;             /* ����֡���ŵ� */
    /* word 4 */
    hi_s8                   rssi_dbm;
} hmac_rx_ctl_stru;

/* host��netbuf�����ֶ�(CB)���ܳ���Ϊ48�ֽ� (Ŀǰ����42�ֽ�) */
typedef struct {
    hi_u8                               mpdu_num;                /* ampdu�а�����MPDU����,ʵ����������д��ֵΪ��ֵ-1 */
    hi_u8                               netbuf_num;              /* ÿ��MPDUռ�õ�netbuf��Ŀ */
    hi_u8                               resv[2];                 /* 2 byte�����ֶ� */
    hi_u32                              us_mpdu_len;             /* ÿ��MPDU�ĳ��Ȳ�����mac header length */

    hi_u8                               is_amsdu               : 1;    /* �Ƿ�AMSDU: HI_FALSE���ǣ�HI_TRUE�� */
    /* ��MPDU�ǵ������Ƕಥ:HI_FALSE������HI_TRUE�ಥ */
    hi_u8                               ismcast                : 1;
    hi_u8                               is_eapol               : 1;    /* ��֡�Ƿ���EAPOL֡ */
    hi_u8                               use_4_addr             : 1;    /* �Ƿ�ʹ��4��ַ����WDS���Ծ��� */
    /* ���������ã���ʶһ��MPDU�Ƿ�ӽ��ܶ�����ȡ������ */
    hi_u8                               is_get_from_ps_queue   : 1;
    hi_u8                               is_first_msdu          : 1;    /* �Ƿ��ǵ�һ����֡��HI_FALSE���� HI_TRUE�� */
    hi_u8                               need_pause_tid         : 1;
    hi_u8                               is_bar                 : 1;
    hi_u8                               frame_header_length;           /* ��MPDU��802.11ͷ���� */
    hi_u8                               is_qosdata             : 1;    /* ָʾ��֡�Ƿ���qos data */
    /* 0: 802.11 macͷ����skb�У������������ڴ��ţ� 1: 802.11 macͷ��skb�� */
    hi_u8                               mac_head_type          : 1;
    hi_u8                               is_vipframe            : 1;    /* ��֡�Ƿ���EAPOL֡��DHCP֡ */
    hi_u8                               is_needretry           : 1;
    /* ��֡��SN�������ά����Ӳ����ֹά��(Ŀǰ�����ڷ�QOS��Ƭ֡ ) */
    hi_u8                               seq_ctrl_bypass        : 1;
    hi_u8                               need_rsp               : 1;    /* WPAS send mgmt,need dmac response tx status */
    hi_u8                               is_eapol_key_ptk       : 1;    /* 4 �����ֹ��������õ�����ԿEAPOL KEY ֡��ʶ */
    hi_u8                               roam_data              : 1;

    wlan_frame_type_enum_uint8          frame_type;                    /* ֡���ͣ�����֡������֡... */
    mac_ieee80211_frame_stru           *frame_header;                  /* ��MPDU��֡ͷָ�� */

    hi_u8                               ac;                            /* ac */
    hi_u8                               tid;                           /* tid */
    /* ȡֵ:FRW_EVENT_TYPE_WLAN_DTX��FRW_EVENT_TYPE_HOST_DRX������:���ͷ�ʱ�������ڴ�ص�netbuf����ԭ��̬�� */
    frw_event_type_enum_uint8           event_type;
    hi_u8                               event_sub_type;  /* amsdu���¼��õ� */
    hi_u8                               rsv[4];          /* �滻hal_tx_dscr_stru resv 4 byte */
    hi_u16                              us_eapol_ts;     /* eapol֡ʱ��� */
    hi_u16                              us_mpdu_bytes;   /* mpdu�ֽ�����ά���ã�������ͷβ��������snap��������padding */
    struct timeval                      timestamp_us;    /* ά��ʹ����TID����ʱ��ʱ��� */

    hi_u32                              alg_pktno;       /* �㷨�õ����ֶΣ�Ψһ��ʾ�ñ��� */
    hi_u16                              us_seqnum;       /* ��¼��������seqnum */
    wlan_tx_ack_policy_enum_uint8       ack_policy;      /* ACK ���� */
    hi_u8                               tx_vap_index;

    hi_u8                               us_tx_user_idx;  /* dmac tx �� tx complete ���ݵ�user�ṹ�壬Ŀ���û���ַ */
    hi_u8                               retried_num;
    dmac_user_alg_probe_enum_uint8      is_probe_data;                   /* �Ƿ���̽��֡ */
    hi_u8                               mgmt_frame_id           : 4;     /* wpas ���͹���֡��frame id */
    hi_u8                               is_any_frame            : 1;
#ifdef _PRE_WLAN_FEATURE_MESH
    /* pbuf��֪��ǰ����֡���ȼ���flags(����ipv6��ͷѹ����֪�������ȼ�) */
    hi_u8                               pbuf_flags              : 2;
#endif
    hi_u8                               high_prio_sch           : 1;    /* ���ȵ��� */
} hmac_tx_ctl_stru;

hi_u32 dmac_tid_pause(dmac_tid_stru *tid, hi_u8 type);
hi_u32 dmac_from_hmac_rx_control_handle(frw_event_mem_stru *event_mem);
hi_u32 dmac_from_hmac_rx_data_handle(frw_event_mem_stru *event_mem, oal_dev_netbuf_stru *dev_netbuf, hi_u16 netbuf_len);
hi_u32 dmac_alg_get_qap_wme_info(const mac_vap_stru *mac_vap, hi_u8 wme_type, mac_wme_param_stru *wme_info);
hi_void dmac_set_rom_resv_func(dmac_rom_resv_func_enum_uint8 func_id, hi_void *func);
hi_void *dmac_get_rom_resv_func(dmac_rom_resv_func_enum_uint8 func_id);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of dmac_ext_if.h */
