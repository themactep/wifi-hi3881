/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_user.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_USER_H__
#define __MAC_USER_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "frw_timer.h"
#include "wlan_types.h"
#include "wlan_mib.h"
#include "mac_frame.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define MAC_USER_INIT_STREAM        1
#define MAC_INVALID_USER_ID         0xff         /* �Ƿ��û�IDоƬ�����,��ֹ��ͬ�汾�û�������� */
#define MAC_INVALID_USER_ID2         0xf
#define MAC_USER_FREED              0            /* USER��Դδ���� */
#define MAC_USER_ALLOCED            1            /* USER�ѱ����� */

#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
#define MAC_REKEY_OFFLOAD_KCK_LEN              16
#define MAC_REKEY_OFFLOAD_KEK_LEN              16
#define MAC_REKEY_OFFLOAD_REPLAY_LEN           8
#endif

/*****************************************************************************
  STRUCT����
*****************************************************************************/
typedef struct {
    wlan_security_txop_params_stru       security;
}mac_user_tx_param_stru;

typedef struct {
    hi_u8        rs_nrates;                          /* ���� */
    hi_u8        auc_resv[3];                        /* 3 BYTE �����ֶ� */
    hi_u8        auc_rs_rates[WLAN_MAX_SUPP_RATES];  /* ���� */
}mac_rate_stru;

typedef struct {
    hi_u32  spectrum_mgmt           : 1,        /* Ƶ�׹���: 0=��֧��, 1=֧�� */
                qos                 : 1,        /* QOS: 0=��QOSվ��, 1=QOSվ�� */
                barker_preamble_mode: 1,        /* ��STA����BSS��վ���Ƿ�֧��short preamble�� 0=֧�֣� 1=��֧�� */
                /* �Զ�����: 0=��֧��, 1=֧�� Ŀǰbit_apsdֻ��дû�ж���wifi�������Լ�������WMM����IE����
                    cap apsd���� ,�˴�Ԥ��Ϊ�������ܳ��ļ����������ṩ�ӿ� */
                apsd                : 1,
                pmf_active          : 1,        /* ����֡����ʹ�ܿ��� */
                erp_use_protect     : 1,        /* ��STA����AP�Ƿ�������ERP���� */
                ntxbf               : 1,
                bit_resv            : 25;
}mac_user_cap_info_stru;

/* user��ht�����Ϣ */
typedef struct {
    hi_u8           ht_capable               : 1,              /* HT capable              */
                        max_rx_ampdu_factor      : 2,              /* Max AMPDU Rx Factor 2bits    */
                        min_mpdu_start_spacing   : 3,              /* Min AMPDU Start Spacing 3bits */
                        htc_support              : 1,              /* HTC ��֧��              */
                        uc_resv                     : 1;
    hi_u8           primary_channel;

    mac_frame_ht_cap_stru ht_capinfo;
    hi_u8           rx_mcs_bitmask[WLAN_HT_MCS_BITMASK_LEN];   /* Rx MCS bitmask */
    hi_u8           secondary_chan_offset             : 2,
                        sta_chan_width                    : 1,
                        rifs_mode                         : 1,
                        ht_protection                     : 2,
                        nongf_sta_present                 : 1,
                        obss_nonht_sta_present            : 1;
    hi_u8           dual_beacon                       : 1,
                        dual_cts_protection               : 1,
                        secondary_beacon                  : 1,
                        lsig_txop_protection_full_support : 1,
                        pco_active                        : 1,
                        pco_phase                         : 1,
                        resv6                             : 2;

    hi_u32          imbf_receive_cap                :   1,      /* ��ʽTxBf�������� */
                        receive_staggered_sounding_cap  :   1,  /* ���ս���̽��֡������ */
                        transmit_staggered_sounding_cap :   1,  /* ���ͽ���̽��֡������ */
                        receive_ndp_cap                 :   1,  /* ����NDP���� */
                        transmit_ndp_cap                :   1,  /* ����NDP���� */
                        imbf_cap                        :   1,  /* ��ʽTxBf���� */
                        /* 0=��֧�֣�1=վ�������CSI������ӦУ׼���󣬵����ܷ���У׼��2=������3=վ����Է���
                            Ҳ������ӦУ׼���� */
                        calibration                     :   2,
                        exp_csi_txbf_cap                :   1,  /* Ӧ��CSI��������TxBf������ */
                        exp_noncomp_txbf_cap            :   1,  /* Ӧ�÷�ѹ���������TxBf������ */
                        exp_comp_txbf_cap               :   1,  /* Ӧ��ѹ���������TxBf������ */
                        exp_csi_feedback                :   2,  /* 0=��֧�֣�1=�ӳٷ�����2=����������3=�ӳٺ��������� */
                        exp_noncomp_feedback            :   2,  /* 0=��֧�֣�1=�ӳٷ�����2=����������3=�ӳٺ��������� */
                        exp_comp_feedback               :   2,  /* 0=��֧�֣�1=�ӳٷ�����2=����������3=�ӳٺ��������� */
                        min_grouping                    :   2,  /* 0=�����飬1=1,2���飬2=1,4���飬3=1,2,4���� */
                        /* CSI����ʱ��bfee���֧�ֵ�beamformer��������0=1Tx����̽�⣬1=2Tx����̽�⣬2=3Tx����̽�⣬
                            3=4Tx����̽�� */
                        csi_bfer_ant_number             :   2,
                        /* ��ѹ��������ʱ��bfee���֧�ֵ�beamformer��������0=1Tx����̽�⣬1=2Tx����̽�⣬
                            2=3Tx����̽�⣬3=4Tx����̽�� */
                        noncomp_bfer_ant_number         :   2,
                        /* ѹ��������ʱ��bfee���֧�ֵ�beamformer��������0=1Tx����̽�⣬1=2Tx����̽�⣬
                            2=3Tx����̽�⣬3=4Tx����̽�� */
                        comp_bfer_ant_number            :   2,
                        csi_bfee_max_rows               :   2,  /* bfer֧�ֵ�����bfee��CSI��ʾ������������� */
                        channel_est_cap                 :   2,  /* �ŵ����Ƶ�������0=1��ʱ�������ε��� */
                        reserved                        :   3;
}mac_user_ht_hdl_stru;

typedef struct {
hi_u16              us_max_mcs_1ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_2ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_3ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_4ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_5ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_6ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_7ss : 2,                             /* һ���ռ�����MCS���֧��MAP */
                        us_max_mcs_8ss : 2;                             /* һ���ռ�����MCS���֧��MAP */
}mac_max_mcs_map_stru;

typedef mac_max_mcs_map_stru mac_tx_max_mcs_map_stru;
typedef mac_max_mcs_map_stru mac_rx_max_mcs_map_stru;

typedef struct {
    hi_u16  us_max_mpdu_length;
    hi_u16  us_basic_mcs_set;

    mac_vht_cap_info_stru       vht_cap_info;

    mac_tx_max_mcs_map_stru     tx_max_mcs_map;
    mac_rx_max_mcs_map_stru     rx_max_mcs_map;

    hi_u16  rx_highest_rate : 13,
                resv2           : 3;
    hi_u16  tx_highest_rate : 13,
                resv3           : 3;                 /* ����vht Capabilities IE: VHT Supported MCS Set field */

    hi_u8 vht_capable;                               /* VHT capable */

    /* vht operationֻ����ap��������� */
    hi_u8           channel_width;                   /* ����VHT Operation IE */
                                                     /* uc_channel_width��ȡֵ��0 -- 20/40M, 1 -- 80M, 2 -- 160M */
    hi_u8           channel_center_freq_seg0;
    hi_u8           channel_center_freq_seg1;
} mac_vht_hdl_stru;

/* user�ṹ�壬��SA Query������Ϣ�ı���ṹ */
typedef struct {
    hi_u16          us_sa_query_count;           /* number of pending SA Query requests, 0 = no SA Query in progress */
    hi_u16          us_sa_query_trans_id;             /* trans id */
    hi_u32          sa_query_start_time;              /* sa_query ���̿�ʼʱ��,��λms */
    frw_timeout_stru    sa_query_interval_timer;      /* SA Query �����ʱ�������dot11AssociationSAQueryRetryTimeout */
}mac_sa_query_stru;

typedef struct {
    hi_u8               qos_info;                            /* ���������е�WMM IE��QOS info field */
    hi_u8               max_sp_len;                          /* ��qos info�ֶ�����ȡ����������񳤶� */
    hi_u8               auc_resv[2];                         /* 2 byte �����ֶ� */
    hi_u8               ac_trigger_ena[WLAN_WME_AC_BUTT];    /* 4��AC��trigger���� */
    hi_u8               ac_delievy_ena[WLAN_WME_AC_BUTT];    /* 4��AC��delivery���� */
}mac_user_uapsd_status_stru;

/* �û���AP�Ĺ���״̬ö�� */
typedef enum {
    MAC_USER_STATE_AUTH_COMPLETE   = 1,
    MAC_USER_STATE_AUTH_KEY_SEQ1   = 2,
    MAC_USER_STATE_ASSOC           = 3,

    MAC_USER_STATE_BUTT            = 4
}hmac_user_asoc_state_enum;
typedef hi_u8 mac_user_asoc_state_enum_uint8;
typedef struct {
    hi_u8 auc_user_addr[WLAN_MAC_ADDR_LEN];      /* �û�mac��ַ */
    hi_u8 conn_rx_rssi;
    mac_user_asoc_state_enum_uint8 assoc_state;
    hi_u8 bcn_prio;
    hi_u8 is_mesh_user;
    hi_u8 is_initiative_role;
}mac_user_assoc_info_stru;

/* 802.1X-port ״̬�ṹ�� */
/* 1X�˿�״̬˵��:                                                  */
/* 1) portvalid && keydone ���� TRUE: ��ʾ�˿ڴ��ںϷ�״̬          */
/* 2) portvalid == TRUE && keydone == FALSE:��ʾ�˿ڴ���δ֪״̬    */
/*                                     ��Կ��δ��Ч                 */
/* 3) portValid == FALSE && keydone== TRUE:��ʾ�˿ڴ��ڷǷ�״̬     */
/*                                      ��Կ��ȡʧ��                */
/* 4) portValid && keyDone are FALSE: ��ʾ�˿ڴ��ںϷ�״̬          */
/*                                          ��Կ��δ��Ч            */
typedef struct {
    hi_u8             keydone;                      /* �˿ںϷ����Ƿ�������� */
    hi_u8             portvalid;                    /* �˿ںϷ��Ա�ʶ */
    hi_u8             auc_resv0[2];                 /* 2 BYTE �����ֶ� */
}mac_8021x_port_status_stru;
/* ��AP�鿴STA�Ƿ�ͳ�Ƶ���Ӧ�� */
typedef struct {
    /* ָʾuser�Ƿ�ͳ�Ƶ�no short slot num��, 0��ʾδ��ͳ�ƣ� 1��ʾ�ѱ�ͳ�� */
    hi_u8             no_short_slot_stats_flag     :1;
    hi_u8             no_short_preamble_stats_flag :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no short preamble num�� */
    hi_u8             no_erp_stats_flag            :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no erp num�� */
    hi_u8             no_ht_stats_flag             :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no ht num�� */
    hi_u8             no_gf_stats_flag             :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no gf num�� */
    hi_u8             m_only_stats_flag            :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no 20M only num�� */
    hi_u8             no_40dsss_stats_flag         :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no 40dsss num�� */
    hi_u8             no_lsig_txop_stats_flag      :1;      /* ָʾuser�Ƿ�ͳ�Ƶ�no lsig txop num�� */
}mac_user_stats_flag_stru;
/* AP��keepalive��Ŀ��ƽṹ�� */
typedef struct {
    hi_u8             keepalive_count_ap;                  /* AP��ʱ��������������� */
    /* ����aging timer/STAʡ��ģʽ��ʱ���Ѳ��ԣ���ʱ����keepalive֡�ļ����� */
    hi_u8             timer_to_keepalive_count;
    hi_u8             delay_flag;                          /* ��־�û�����˯��״̬������������������֡������״̬ */

    hi_u8             auc_resv[1];
}mac_user_keepalive;
/* ��Կ����ṹ�� */
typedef struct {
    wlan_ciper_protocol_type_enum_uint8     cipher_type  : 7;
    hi_u8                               gtk         : 1;                    /* ָʾRX GTK�Ĳ�λ��02ʹ�� */
    hi_u8                               default_index;                       /* Ĭ������ */
    hi_u8                               igtk_key_index;                      /* igtk���� */
    hi_u8                               last_gtk_key_idx;                    /* igtk���� */

    wlan_priv_key_param_stru                ast_key[WLAN_NUM_TK + WLAN_NUM_IGTK];   /* key���� */
}mac_key_mgmt_stru;
/* �ռ�����Ϣ�ṹ�� */
typedef struct {
    hi_u8             user_idx;
    hi_u8             uc_resv;
    hi_u8             avail_num_spatial_stream;            /* Tx��Rx֧��Nss�Ľ���,���㷨���� */
    hi_u8             num_spatial_stream;                  /* �û�֧�ֵĿռ������� */
}mac_user_nss_stru;
/* opmode��Ϣ�ṹ�� */
typedef struct {
    hi_u8               user_idx;
    hi_u8               avail_num_spatial_stream;            /* Tx��Rx֧��Nss�Ľ���,���㷨���� */
    hi_u8               avail_bf_num_spatial_stream;         /* �û�֧�ֵ�Beamforming�ռ������� */
    hi_u8               frame_type;

    wlan_bw_cap_enum_uint8  avail_bandwidth;                 /* �û���VAP������������,���㷨���� */
    wlan_bw_cap_enum_uint8  cur_bandwidth;                   /* Ĭ��ֵ��en_avail_bandwidth��ͬ,���㷨�����޸� */
    hi_u8                   auc_resv[2];                     /* 2 BYTE �����ֶ� */
}mac_user_opmode_stru;
typedef struct mac_key_params_tag {
    hi_u8 auc_key[OAL_WPA_KEY_LEN];
    hi_u8 auc_seq[OAL_WPA_SEQ_LEN];
    hi_s32  key_len;
    hi_s32  seq_len;
    hi_u32 cipher;
}mac_key_params_stru;
#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
typedef struct _mac_rekey_offload_stru {
    hi_u8   auc_kck[MAC_REKEY_OFFLOAD_KCK_LEN];
    hi_u8   auc_kek[MAC_REKEY_OFFLOAD_KEK_LEN];
    hi_u8   auc_replay_ctr[MAC_REKEY_OFFLOAD_REPLAY_LEN];
}mac_rekey_offload_stru;
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
typedef struct _mac_set_mesh_user_gtk_stru {
    hi_u8 auc_addr[WLAN_MAC_ADDR_LEN];
    hi_u8 auc_gtk[WLAN_CCMP_KEY_LEN];
}mac_set_mesh_user_gtk_stru;
#endif
/* mac user�ṹ��, hmac_user_stru��dmac_user_stru�������� */
typedef struct {
    /* ��ǰVAP������AP��STAģʽ�������ֶ�Ϊuser��STA��APʱ�����ֶΣ�������ֶ���ע��!!! */
    hi_list                             user_dlist;                          /* ����hash˫�����е�˫������ */
    hi_u8                               vap_id           : 4,                /* vap ID 0-7 */
                                        is_mesh_user     : 1,                /* ��־��User�û��Ƿ�ΪMesh�Ǹ����û� */
                                        port_valid       : 1,                /* 802.1X�˿ںϷ��Ա�ʶ */
                                        is_multi_user    : 1,
                                        is_mesh_mbr      : 1;                /* ��ʶ�����ڵ��Ƿ�ΪMBR�ڵ� */
    hi_u8                               user_hash_idx;                       /* ����ֵ(����) */
    hi_u8                               user_mac_addr[WLAN_MAC_ADDR_LEN];   /* user��Ӧ��MAC��ַ */

    hi_u8                               is_user_alloced  : 1,                /* ��־��user��Դ�Ƿ��Ѿ������� */
                                        mesh_user_leave  : 1,                /* ��־��user�뿪(�յ�user�����뱣��֡) */
                                        mesh_initiative_role: 1,             /* Mesh��������� */
                                        uc_resv             : 5;
    mac_user_asoc_state_enum_uint8      user_asoc_state;                     /* �û�����״̬  */
    /* user��Ӧ��Դ������ֵ; userΪSTAʱ����ʾ���ڹ���֡�е�AID��ֵΪ�û�����Դ������ֵ1~32(Э��涨��ΧΪ1~2007) */
    hi_u8                               us_assoc_id;
    wlan_protocol_enum_uint8            protocol_mode        : 4;            /* �û�����Э�� */
    wlan_protocol_enum_uint8            avail_protocol_mode  : 4;            /* �û���VAPЭ��ģʽ����, ���㷨���� */

    /* Ĭ��ֵ��en_avail_protocol_modeֵ��ͬ, ���㷨�����޸� */
    wlan_protocol_enum_uint8            cur_protocol_mode    : 4;
    wlan_bw_cap_enum_uint8              bandwidth_cap        : 4;            /* �û�����������Ϣ */
    wlan_bw_cap_enum_uint8              avail_bandwidth      : 4;            /* �û���VAP������������,���㷨���� */
    /* Ĭ��ֵ��en_avail_bandwidth��ͬ,���㷨�����޸� */
    wlan_bw_cap_enum_uint8              cur_bandwidth        : 4;
    hi_u8                               avail_num_spatial_stream : 4;        /* Tx��Rx֧��Nss�Ľ���,���㷨���� */
    hi_u8                               num_spatial_stream   : 4;            /* �û�֧�ֵĿռ������� */
    /* ��ʾ��mesh�û��Ľڵ����ȼ�,beacon��probe rsp��Я������mesh�û���Ч */
    hi_u8                               bcn_prio;
    mac_rate_stru                       avail_op_rates;                /* �û���VAP���õ�11a/b/g���ʽ��������㷨���� */
    mac_user_tx_param_stru              user_tx_info;                  /* TX��ز��� */
    mac_user_cap_info_stru              cap_info;                      /* user����������Ϣλ */
    mac_user_ht_hdl_stru                ht_hdl;                        /* HT capability IE�� operation IE�Ľ�����Ϣ */
    mac_key_mgmt_stru                   key_info;

    hi_s8                               rx_conn_rssi;                  /* �û��������̽��չ���֡RSSIͳ���� MESH */
    hi_u8                               resv[3];                       /* reserve 3byte */
#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
    hi_u8                                   avail_bf_num_spatial_stream;         /* �û�֧�ֵ�Beamforming�ռ������� */
#endif
}mac_user_stru;

#ifdef _PRE_WLAN_FEATURE_UAPSD
#define MAC_USR_UAPSD_EN     0x01  /* U-APSDʹ�� */
#define MAC_USR_UAPSD_TRIG   0x02  /* U-APSD���Ա�trigger */
#define MAC_USR_UAPSD_SP     0x04  /* u-APSD��һ��Service Period������ */

/* AC��trigge_en�����û���ǰ����trigger״̬��can be trigger */
#define mac_usr_uapsd_ac_can_tigger(_ac,_dmac_usr) \
    (((_dmac_usr)->uapsd_status.ac_trigger_ena[_ac])&&((_dmac_usr)->uapsd_flag & MAC_USR_UAPSD_TRIG))

/* AC��delivery_en�����û���ǰ����trigger״̬,can be delivery */
#define mac_usr_uapsd_ac_can_delivery(_ac,_dmac_usr) \
    (((_dmac_usr)->uapsd_status.ac_delievy_ena[_ac])&&((_dmac_usr)->uapsd_flag & MAC_USR_UAPSD_TRIG))

#define mac_usr_uapsd_use_tim(_dmac_usr) \
    (mac_usr_uapsd_ac_can_delivery(WLAN_WME_AC_BK, _dmac_usr) && \
        mac_usr_uapsd_ac_can_delivery(WLAN_WME_AC_BE, _dmac_usr) && \
        mac_usr_uapsd_ac_can_delivery(WLAN_WME_AC_VI, _dmac_usr) && \
        mac_usr_uapsd_ac_can_delivery(WLAN_WME_AC_VO, _dmac_usr))
#endif

#define mac_11i_is_ptk(macaddr_is_zero, pairwise)   ((HI_TRUE != (macaddr_is_zero)) && (HI_TRUE == (pairwise)))

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
#define MAC_USER_STATE_DEL 0
#endif

/*****************************************************************************
  inline��������
*****************************************************************************/
/*****************************************************************************
 ��������  : �����û��İ�ȫ��Ϣ
 �� �� ֵ  : 0:�ɹ�,����:ʧ��
 ��    ��  : ��ֹ�˺�����дʱ��ֻ��keyid�õ�ʹ�ã�multiuser�µİ�ȫ��Ϣ�����Ż�һ��
 �޸���ʷ      :
  1.��    ��   : 2015��03��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_key(mac_user_stru *multiuser, wlan_cipher_key_type_enum_uint8 keytype,
                          wlan_ciper_protocol_type_enum_uint8 ciphertype, hi_u8 keyid)
{
    multiuser->user_tx_info.security.cipher_key_type      = keytype;
    multiuser->user_tx_info.security.cipher_protocol_type = ciphertype;
    multiuser->user_tx_info.security.cipher_key_id        = keyid;
    oam_warning_log4(0, OAM_SF_WPA,
                     "{mac_user_set_key::keytpe==%u, ciphertype==%u, keyid==%u, usridx==%u}",
                     keytype, ciphertype, keyid, multiuser->us_assoc_id);
}

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
/*****************************************************************************
 ��������  : ����user��������uc_avail_num_spatial_stream Tx��Rx֧��Nss�Ľ���,���㷨���õ�ֵ
 �� �� ֵ  : hi_void
 �޸���ʷ      :
  1.��    ��   : 2015��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_avail_bf_num_spatial_stream(mac_user_stru *mac_user, hi_u8 value)
{
    mac_user->avail_bf_num_spatial_stream = value;
}
#endif

/*****************************************************************************
 ��������  : ����user��������uc_avail_num_spatial_stream Tx��Rx֧��Nss�Ľ���,���㷨���õ�ֵ
 �޸���ʷ      :
  1.��    ��   : 2015��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_avail_num_spatial_stream(mac_user_stru *mac_user, hi_u8 value)
{
    mac_user->avail_num_spatial_stream = value;
}

/*****************************************************************************
 ��������  : ����user��������uc_num_spatial_stream�û�֧�ֿռ���������ֵ
 �޸���ʷ      :
  1.��    ��   : 2015��4��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_num_spatial_stream(mac_user_stru *mac_user, hi_u8 value)
{
    mac_user->num_spatial_stream = value;
}

/*****************************************************************************
 ��������  : �����û���bandwidth����
 �޸���ʷ      :
  1.��    ��   : 2015��4��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_bandwidth_cap(mac_user_stru *mac_user, wlan_bw_cap_enum_uint8 bandwidth_value)
{
    mac_user->bandwidth_cap = bandwidth_value;
}

/*****************************************************************************
 ��������  : ��ֻmac user�е�user��vapЭ��ģʽ�Ľ���ģʽ
 �޸���ʷ      :
  1.��    ��   : 2015��4��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_protocol_mode(mac_user_stru *mac_user, wlan_protocol_enum_uint8 protocol_mode)
{
    mac_user->protocol_mode = protocol_mode;
}

/*****************************************************************************
 ��������  : ����user�¿������ʼ�
 �޸���ʷ      :
  1.��    ��   : 2015��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_avail_op_rates(mac_user_stru *mac_user, hi_u8 rs_nrates, const hi_u8 *puc_rs_rates)
{
    mac_user->avail_op_rates.rs_nrates = rs_nrates;
    if (memcpy_s(mac_user->avail_op_rates.auc_rs_rates, WLAN_MAX_SUPP_RATES, puc_rs_rates,
                 WLAN_MAX_SUPP_RATES) != EOK) {
        mac_user->avail_op_rates.rs_nrates = 0;
        return;
    }
}

/*****************************************************************************
 ��������  : �������û�pmf����Э�̵Ľ��
 �޸���ʷ      :
  1.��    ��   : 2015��5��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_pmf_active(mac_user_stru *mac_user, hi_u8 pmf_active)
{
    mac_user->cap_info.pmf_active = pmf_active;
}

/*****************************************************************************
 ��������  : �����û�barker_preamble��ģʽ
 �޸���ʷ      :
  1.��    ��   : 2015��5��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_barker_preamble_mode(mac_user_stru *mac_user, hi_u8 barker_preamble_mode)
{
    mac_user->cap_info.barker_preamble_mode = barker_preamble_mode;
}

/*****************************************************************************
 ��������  : �������û���qosʹ�ܽ����
 �޸���ʷ      :
  1.��    ��   : 2015��5��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void mac_user_set_qos(mac_user_stru *mac_user, hi_u8 qos_mode)
{
    mac_user->cap_info.qos = qos_mode;
}

/*****************************************************************************
  ��������
*****************************************************************************/
hi_u32 mac_user_res_init(const hi_u8 user_num);
hi_void mac_user_res_exit(hi_void);
hi_u8 mac_user_get_user_num(hi_void);
hi_u8 mac_user_alloc_user_res(hi_void);
hi_void mac_user_free_user_res(hi_u8 idx);
hi_u8 *mac_user_init_get_user_stru(hi_u8 idx);
mac_user_stru *mac_user_get_user_stru(hi_u8 idx);
hi_u32 mac_user_add_wep_key(mac_user_stru *mac_user, hi_u8 key_index, const mac_key_params_stru *key);
hi_u32 mac_user_add_rsn_key(mac_user_stru *mac_user, hi_u8 key_index, const mac_key_params_stru *key);
hi_u32 mac_user_add_bip_key(mac_user_stru *mac_user, hi_u8 key_index, const mac_key_params_stru *key);
wlan_priv_key_param_stru *mac_user_get_key(mac_user_stru *mac_user, hi_u8 key_id);
hi_void mac_user_init(mac_user_stru *mac_user, hi_u8 user_idx, const hi_u8 *mac_addr, hi_u8 vap_id);
hi_void mac_user_set_bandwidth_info(mac_user_stru *mac_user, wlan_bw_cap_enum_uint8 avail_bandwidth,
    wlan_bw_cap_enum_uint8 cur_bandwidth);
hi_void mac_user_get_sta_cap_bandwidth(mac_user_stru *mac_user, wlan_bw_cap_enum_uint8 *pen_bandwidth_cap);
hi_void mac_user_get_ap_opern_bandwidth(mac_user_stru *mac_user, wlan_bw_cap_enum_uint8 *pen_bandwidth_cap);
hi_u32 mac_user_update_bandwidth(mac_user_stru *mac_user, wlan_bw_cap_enum_uint8 bwcap);
hi_void mac_user_set_asoc_state(mac_user_stru *mac_user, mac_user_asoc_state_enum_uint8 value);
hi_void mac_user_get_vht_hdl(mac_user_stru *mac_user, mac_vht_hdl_stru *ht_hdl);
hi_void mac_user_set_ht_hdl(mac_user_stru *mac_user, const mac_user_ht_hdl_stru *ht_hdl);
hi_void mac_user_get_ht_hdl(const mac_user_stru *mac_user, mac_user_ht_hdl_stru *ht_hdl);
hi_void mac_user_set_ht_capable(mac_user_stru *mac_user, hi_u8 ht_capable);
hi_void mac_user_set_spectrum_mgmt(mac_user_stru *mac_user, hi_u8 spectrum_mgmt);
hi_void mac_user_set_apsd(mac_user_stru *mac_user, hi_u8 apsd);
hi_void mac_user_init_key(mac_user_stru *mac_user);
hi_u32 mac_user_update_wep_key(mac_user_stru *mac_usr, hi_u8 multi_user_idx);
hi_u8 mac_addr_is_zero(const hi_u8 *mac_addr);
hi_u8 mac_user_is_user_valid(hi_u8 idx);
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __MAC_USER_H__ */
