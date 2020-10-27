/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Hmac external public interface header file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_EXT_IF_H__
#define __HMAC_EXT_IF_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "mac_device.h"
#include "mac_vap.h"
#include "mac_user.h"
#include "mac_frame.h"
#include "mac_data.h"
#include "hmac_config.h"
#include "hmac_device.h"
#include "hmac_vap.h"
#include "hmac_p2p.h"
#ifdef _PRE_WLAN_FEATURE_WOW
#include "hmac_wow.h"
#endif
#ifdef _PRE_WLAN_FEATURE_WAPI
#include "hmac_wapi.h"
#endif
#include "hmac_11i.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/* ����ֵ���Ͷ��� */
typedef enum {
    HMAC_TX_PASS = 0,           /* �������� */
    HMAC_TX_BUFF = 1,           /* �ѱ����� */
    HMAC_TX_DONE = 2,           /* �鲥ת�ɵ����ѷ��� */

    HMAC_TX_DROP_PROXY_ARP = 3, /* PROXY ARP������ */
    HMAC_TX_DROP_USER_UNKNOWN,  /* δ֪user */
    HMAC_TX_DROP_USER_NULL,     /* user�ṹ��ΪNULL */
    HMAC_TX_DROP_USER_INACTIVE, /* Ŀ��userδ���� */
    HMAC_TX_DROP_SECURITY_FILTER,       /* ��ȫ�����˵� */
    HMAC_TX_DROP_BA_SETUP_FAIL, /* BA�Ự����ʧ�� */
    HMAC_TX_DROP_AMSDU_ENCAP_FAIL,      /* amsdu��װʧ�� */
    HMAC_TX_DROP_MUSER_NULL,    /* �鲥userΪNULL */
    HMAC_TX_DROP_MTOU_FAIL,     /* �鲥ת����ʧ�� */
    HMAC_TX_DROP_80211_ENCAP_FAIL,      /* 802.11 head��װʧ�� */
    HMAC_TX_DROP_POLICY,                /* ���Զ������� */

    HMAC_TX_BUTT
} hmac_tx_return_type_enum;
typedef hi_u8 hmac_tx_return_type_enum_uint8;

/*****************************************************************************
  ö����  : hmac_host_ctx_event_sub_type_enum_uint8
  Э����:
  ö��˵��: HOST CTX�¼������Ͷ���
*****************************************************************************/
typedef enum {
    HMAC_HOST_CTX_EVENT_SUB_TYPE_SCAN_COMP_STA = 0,     /* STA��ɨ����������� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ASOC_COMP_STA, /* STA ������������� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_DISASOC_COMP_STA,      /* STA �ϱ�ȥ������� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_CONNECT_AP,        /* AP �ϱ��¼���BSS��STA��� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_DISCONNECT_AP,     /* AP �ϱ��뿪BSS��STA��� */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    HMAC_HOST_CTX_EVENT_SUB_TYPE_MIC_FAILURE,   /* �ϱ�MIC���� */
#endif
    HMAC_HOST_CTX_EVENT_SUB_TYPE_RX_MGMT,       /* �ϱ����յ��Ĺ���֡ */
#ifdef _PRE_WLAN_FEATURE_P2P
    HMAC_HOST_CTX_EVENT_SUB_TYPE_LISTEN_EXPIRED,    /* �ϱ�������ʱ */
#endif
    HMAC_HOST_CTX_EVENT_SUB_TYPE_STA_CONN_RESULT, /* ֪ͨlwip sta�Ƿ���� */
#ifdef _PRE_WLAN_FEATURE_FLOWCTL
    HMAC_HOST_CTX_EVENT_SUB_TYPE_FLOWCTL_BACKP, /* �ϱ����ط�ѹ��Ϣ */
#endif
    HMAC_HOST_CTX_EVENT_SUB_TYPE_MGMT_TX_STATUS,

#ifdef _PRE_WLAN_FEATURE_ANY
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_RX_DATA,           /* �ϱ����յ���ANY����֡������ */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_TX_STATUS,         /* �ϱ�ANY����֡�ķ���״̬ */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_SCAN_RESULT,       /* �ϱ���ɨ�赽��ANY�豸��Ϣ */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ANY_PEER_INFO,         /* �ϱ���ѯ��ANY�Զ��豸��Ϣ */
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
    HMAC_HOST_CTX_EVENT_SUB_TYPE_PEER_CLOSE_MESH,   /* ֪ͨWPA��Զ���豸�Ͽ����� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_NEW_PEER_CANDIDATE, /* ֪ͨwpa�пɹ���Զ�˽ڵ� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_TX_DATA_INFO,  /* ֪ͨlwip��������֡�����Ϣ */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_MESH_USER_INFO, /* ֪ͨlwip�û�����״̬��Ϣ */
#endif
#ifdef _PRE_WLAN_FEATURE_CSI
    HMAC_HOST_CTX_EVENT_SUB_TYPE_CSI_REPORT,    /* �ײ��ȡ��CSI�����ϱ���WAL���¼� */
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    HMAC_HOST_CTX_EVENT_SUB_TYPE_P2P_TX_STATUS, /* P2P����ACTION֡״̬�ϱ���WAL���¼� */
#endif
#ifdef FEATURE_DAQ
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ACQ_STATUS,    /* ����״̬�ϱ���WAL���¼� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_ACQ_RESULT,    /* ���ɽ���ϱ���WAL���¼� */
#endif
#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
    HMAC_HOST_CTX_EVENT_SUB_TYPE_CHANNEL_SWITCH, /* �ŵ��л��ϵ���WAL���¼� */
#endif
    HMAC_HOST_CTX_EVENT_GET_MAC_FROM_EFUSE,      /* HOST���ȡefuse�е�mac��ַ */
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
    HMAC_HOST_CTX_EVENT_GET_DBG_CAL_DATA,        /* HOST���ȡdevice���Բ������ */
#endif
    HMAC_HOST_CTX_EVENT_REPORT_TX_PARAMS,        /* device���ϱ�algģ�������goodput��wal���¼� */
    HMAC_HOST_CTX_EVENT_SUB_TYPE_BUTT
} hmac_host_ctx_event_sub_type_enum;
typedef hi_u8 hmac_host_ctx_event_sub_type_enum_uint8;

/* Status code for MLME operation confirm */
typedef enum {
    HMAC_MGMT_SUCCESS = 0,
    HMAC_MGMT_INVALID = 1,
    HMAC_MGMT_TIMEOUT = 2,
    HMAC_MGMT_REFUSED = 3,
    HMAC_MGMT_TOMANY_REQ = 4,
    HMAC_MGMT_ALREADY_BSS = 5
} hmac_mgmt_status_enum;
typedef hi_u8 hmac_mgmt_status_enum_uint8;

/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
/* ɨ���� */
typedef struct {
    hi_u8 num_dscr;
    hi_u8 result_code;
    hi_u8 auc_resv[2];  /* 2:Ԥ�������С */
} hmac_scan_rsp_stru;

/* ������� */
typedef struct {
    hmac_mgmt_status_enum_uint8  result_code;         /* �����ɹ�,��ʱ�� */
    hi_u8                    auc_resv1[1];
    mac_status_code_enum_uint16  status_code;         /* ieeeЭ��涨��16λ״̬��  */

    hi_u8                    auc_addr_ap[WLAN_MAC_ADDR_LEN];
    hi_u16                   us_freq;

    hi_u32                   asoc_req_ie_len;
    hi_u32                   asoc_rsp_ie_len;

    hi_u8 *puc_asoc_req_ie_buff;
    hi_u8 *puc_asoc_rsp_ie_buff;
} hmac_asoc_rsp_stru;

/* mic���� */
typedef struct {
    hi_u8 auc_user_mac[WLAN_MAC_ADDR_LEN];
    hi_u8 auc_reserve[2];  /* 2:Ԥ�������С */
    oal_nl80211_key_type key_type;
    hi_s32 l_key_id;
} hmac_mic_event_stru;

/* �ϱ����յ�����֡�¼������ݽṹ */
typedef struct {
    hi_u8  *puc_buf;
    hi_u16  us_len;
    hi_u8   rsv[2];   /* 2:Ԥ�������С */
    hi_s32  l_freq;
    hi_char ac_name[OAL_IF_NAME_SIZE];
} hmac_rx_mgmt_event_stru;

typedef struct {
    hi_u32 cfg_id;
    hi_u32 ac;
    hi_u32 value;
} hmac_config_wmm_para_stru;

typedef struct {
    hi_u8 is_assoc;                      /* ��ʶ�ǹ����¼�/ȥ�����¼� */
    hi_u8 conn_to_mesh;                  /* ��ʶ�Ƿ������Mesh/��ͨAP */
    hi_u8 rssi;                          /* �����Ľڵ��ɨ��RSSI */
    hi_u8 auc_mac_addr[WLAN_MAC_ADDR_LEN];
    hi_u8 auc_rsv[3];                    /* 3:Ԥ�������С */
}hmac_sta_report_assoc_info_stru;
#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_EXT_IF_H__ */
