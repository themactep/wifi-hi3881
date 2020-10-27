/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_user.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_USER_H__
#define __HMAC_USER_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "mac_user.h"
#include "mac_resource.h"
#include "dmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define HMAC_ADDBA_EXCHANGE_ATTEMPTS        10  /* ��ͼ����ADDBA�Ự������������ */

#define hmac_user_is_amsdu_support(_user, _tid)         (((_user)->amsdu_supported) & (0x01 << ((_tid) & 0x07)))
#define hmac_user_set_amsdu_support(_user, _tid)        (((_user)->amsdu_supported) |= (0x01 << ((_tid) & 0x07)))
#define hmac_user_set_amsdu_not_support(_user, _tid)    (((_user)->amsdu_supported) &= \
    (hi_u8)(~(0x01 << ((_tid) & 0x07))))

#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
#define MAX_JUDGE_CACHE_LENGTH      20  /* ҵ��ʶ��-�û���ʶ����г��� */
#define MAX_CONFIRMED_FLOW_NUM      2   /* ҵ��ʶ��-�û���ʶ��ҵ������ */
#endif

#define   hmac_user_stats_pkt_incr(_member, _cnt)            ((_member) += (_cnt))

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    WLAN_TX_TCP_DATA = 0,    /* ����TCP data */
    WLAN_RX_TCP_DATA = 1,    /* ����TCP data */
    WLAN_TX_UDP_DATA = 2,    /* ����UDP data */
    WLAN_RX_UDP_DATA = 3,    /* ����UDP data */

    WLAN_TXRX_DATA_BUTT = 4,
}wlan_txrx_data_type_enum;
typedef hi_u8 wlan_txrx_data_enum_uint8;
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
typedef struct {
    oal_netbuf_head_stru            msdu_head;         /* msdu����ͷ */
    frw_timeout_stru                amsdu_timer;
    oal_spin_lock_stru              st_amsdu_lock;        /* amsdu task lock */
    hi_u8                       last_pad_len;      /* ���һ��msdu��pad���� */
    hi_u8                       msdu_num     : 4;  /* Number of sub-MSDUs accumulated */
    hi_u8                       amsdu_maxnum : 4;  /* ���ۺϸ��� value = 12�� */
    hi_u16                      us_amsdu_size;        /* Present size of the AMSDU */

    hi_u8                       auc_eth_da[WLAN_MAC_ADDR_LEN];
    hi_u8                       auc_eth_sa[WLAN_MAC_ADDR_LEN];
}hmac_amsdu_stru;
/* TID��Ӧ�ķ���BA�Ự��״̬ */
typedef struct {
    dmac_ba_conn_status_enum_uint8  ba_status;       /* ��TID��Ӧ��BA�Ự��״̬ */
    hi_u8                       dialog_token;    /* �������� */
    hi_u8                       uc_resv[2]; /* 2 �����ֽ� */
    frw_timeout_stru                addba_timer;
    dmac_ba_alarm_stru              alarm_data;
}hmac_ba_tx_stru;

typedef struct {
    hi_u8                     in_use;                     /* ����BUF�Ƿ�ʹ�� */
    hi_u8                               num_buf;                 /* MPDUռ�õ�netbuf(����������)���� */
    hi_u16                              us_seq_num;                 /* MPDU��Ӧ�����к� */
    oal_netbuf_head_stru                    netbuf_head;             /* MPDU��Ӧ���������׵�ַ */
    hi_u32                              rx_time;                 /* ���ı������ʱ��� */
} hmac_rx_buf_stru;

typedef struct {
    hi_void                             *ba;
    hi_u8                               tid;
    hi_u8                               vap_id;
    hi_u16                              us_timeout_times;
}hmac_ba_alarm_stru;

/* Hmac����ղ�BA�Ự��� */
typedef struct {
    hi_u16                      us_baw_start;               /* ��һ��δ�յ���MPDU�����к� */
    hi_u16                      us_baw_end;                 /* ���һ�����Խ��յ�MPDU�����к� */
    hi_u16                      us_baw_tail;                /* ĿǰRe-Order�����У��������к� */
    hi_u16                      us_baw_size;                /* Block_Ack�Ự��buffer size��С */

    oal_spin_lock_stru          st_ba_lock;                 /* 02����hcc�̺߳��¼��̲߳��� */

    hi_u8             timer_triggered;         /* ��һ���ϱ��Ƿ�Ϊ��ʱ���ϱ� */
    hi_u8             is_ba;                   /* Session Valid Flag */
    dmac_ba_conn_status_enum_uint8  ba_status;               /* ��TID��Ӧ��BA�Ự��״̬ */
    hi_u8                       mpdu_cnt;                /* ��ǰRe-Order�����У�MPDU����Ŀ */

    hmac_rx_buf_stru                ast_re_order_list[WLAN_AMPDU_RX_BUFFER_SIZE];  /* Re-Order���� */
    hmac_ba_alarm_stru              alarm_data;
    frw_timeout_stru                ba_timer;                /* ���������򻺳峬ʱ */

    /* ����action֡��� */
    mac_back_variant_enum_uint8     back_var;        /* BA�Ự�ı��� */
    hi_u8                       dialog_token;        /* ADDBA����֡��dialog token */
    hi_u8                       ba_policy;           /* Immediate=1 Delayed=0 */
    hi_u8                       lut_index;           /* ���ն�Session H/w LUT Index */
    hi_u16                      us_status_code;      /* ����״̬�� */
    hi_u16                      us_ba_timeout;       /* BA�Ự������ʱʱ�� */
    hi_u8                      *puc_transmit_addr;   /* BA�Ự���Ͷ˵�ַ */
    hi_u8                       amsdu_supp;      /* BLOCK ACK֧��AMSDU�ı�ʶ */
    hi_u8                       auc_resv1[1];
    hi_u16                      us_baw_head;         /* bitmap����ʼ���к� */
    hi_u32                      aul_rx_buf_bitmap[2]; /* Ԫ�ظ���Ϊ2 */
}hmac_ba_rx_stru;

/* user�ṹ�У�TID��Ӧ��BA��Ϣ�ı���ṹ */
typedef struct {
    hi_u8               tid_no;
    hi_u8               ampdu_start;            /* ��ʶ��tid�µ�AMPDU�Ƿ��Ѿ������� */
    hi_u8               tx_ba_attemps;
    hi_u8               ba_flag;                /* ���ڵ���5ʱ��ʾ�Ƿ���Խ���BA�Ự���û���ʼ����ɾ��BA�Ựʱ���� */
    hmac_ba_tx_stru        *ba_tx_info;
    hmac_ba_rx_stru        *ba_rx_info;             /* ���ڲ��ִ������ƣ��ⲿ���ڴ浽LocalMem������ */
}hmac_tid_stru;

typedef struct {
    hi_u32  short_preamble          : 1,        /* �Ƿ�֧��802.11b��ǰ���� 0=��֧�֣� 1=֧�� */
                erp                 : 1,        /* AP����STA����ʹ��,ָʾuser�Ƿ���ERP������ 0=��֧�֣�1=֧�� */
                short_slot_time     : 1,        /* ��ʱ϶: 0=��֧��, 1=֧�� */
                ac2g                : 1,
                bit_resv            : 28;
}hmac_user_cap_info_stru;

#ifdef _PRE_WLAN_FEATURE_WAPI
#define WAPI_KEY_LEN                    16
#define WAPI_PN_LEN                     16
#define HMAC_WAPI_MAX_KEYID             2

typedef struct {
    hi_u32 ulrx_mic_calc_fail;           /* ���ڲ���������mic������� */
    hi_u32 ultx_ucast_drop;              /* ����Э��û����ɣ���֡drop�� */
    hi_u32 ultx_wai;
    hi_u32 ultx_port_valid;             /* Э����ɵ�����£����͵�֡���� */
    hi_u32 ulrx_port_valid;             /* Э����ɵ�����£����յ�֡���� */
    hi_u32 ulrx_idx_err;                /* ����idx������� */
    hi_u32 ulrx_netbuff_len_err;        /* ����netbuff���ȴ��� */
    hi_u32 ulrx_idx_update_err;         /* ��Կ���´��� */
    hi_u32 ulrx_key_en_err;             /* ��Կû��ʹ�� */
    hi_u32 ulrx_pn_odd_err;             /* PN��żУ����� */
    hi_u32 ulrx_pn_replay_err;          /* PN�ط� */
    hi_u32 ulrx_memalloc_err;           /* rx�ڴ�����ʧ�� */
    hi_u32 ulrx_decrypt_ok;             /* ���ܳɹ��Ĵ��� */

    hi_u32 ultx_memalloc_err;           /* �ڴ����ʧ�� */
    hi_u32 ultx_mic_calc_fail;          /* ���ڲ���������mic������� */
    /* hi_u32 ultx_drop_wai; */         /* wai֡drop�Ĵ��� */
    hi_u32 ultx_encrypt_ok;             /* ���ܳɹ��Ĵ��� */
    hi_u8  aucrx_pn[WAPI_PN_LEN];       /* ���ⷢ��ʱ����¼���շ���֡��PN,��pn����ʱ��ˢ�� */
}hmac_wapi_debug;

typedef struct {
    hi_u8   auc_wpi_ek[WAPI_KEY_LEN];
    hi_u8   auc_wpi_ck[WAPI_KEY_LEN];
    hi_u8   auc_pn_rx[WAPI_PN_LEN];
    hi_u8   auc_pn_tx[WAPI_PN_LEN];
    hi_u8   key_en;
    hi_u8   auc_rsv[3]; /* 3 �����ֽ� */
}hmac_wapi_key_stru;

typedef struct tag_hmac_wapi_stru {
    hi_u8              port_valid;                       /* wapi���ƶ˿� */
    hi_u8              keyidx;
    hi_u8              keyupdate_flg;                    /* key���±�־ */
    hi_u8              pn_inc;                           /* pn����ֵ */

    hmac_wapi_key_stru     ast_wapi_key[HMAC_WAPI_MAX_KEYID];   /* keyed: 0~1 */

#ifdef _PRE_WAPI_DEBUG
    hmac_wapi_debug        debug;                            /* ά�� */
#endif

    hi_u8               (*wapi_filter_frame)(struct tag_hmac_wapi_stru *pst_wapi, oal_netbuf_stru *pst_netbuff);
    hi_u8     (*wapi_is_pn_odd)(const hi_u8 *puc_pn);     /* �ж�pn�Ƿ�Ϊ���� */
    hi_u32              (*wapi_decrypt)(struct tag_hmac_wapi_stru *pst_wapi, oal_netbuf_stru *pst_netbuff);
    hi_u32              (*wapi_encrypt)(struct tag_hmac_wapi_stru *pst_wapi, oal_netbuf_stru  *pst_netbuf);
    oal_netbuf_stru        *(*wapi_netbuff_txhandle)(struct tag_hmac_wapi_stru *pst_wapi, oal_netbuf_stru  *pst_netbuf);
    oal_netbuf_stru        *(*wapi_netbuff_rxhandle)(struct tag_hmac_wapi_stru *pst_wapi, oal_netbuf_stru  *pst_netbuf);
}hmac_wapi_stru;

#endif

#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
/* ҵ��ʶ��-��Ԫ��ṹ��: ����Ψһ�ر�ʶҵ���� */
typedef struct {
    hi_u32                          sip;                         /* ip */
    hi_u32                          dip;

    hi_u16                          us_sport;                       /* �˿� */
    hi_u16                          us_dport;

    hi_u32                          proto;                       /* Э�� */
}hmac_tx_flow_info_stru;

/* ҵ��ʶ��-��ʶ����нṹ��: */
typedef struct {
    hmac_tx_flow_info_stru              flow_info;

    hi_u32                          len;                        /* �������� */
    hi_u8                           flag;                       /* ��Чλ�����ڼ��� */

    hi_u8                           udp_flag;                   /* udp flagΪ1��ΪUDP֡ */
    hi_u8                           tcp_flag;                   /* tcp flagΪ1��ΪTCP֡ */

    hi_u8                           rtpver;                     /* RTP version */
    hi_u32                          rtpssrc;                    /* RTP SSRC */
    hi_u32                          payload_type;               /* RTP:���1bit����Ч�غ�����(PT)7bit */
}hmac_tx_judge_info_stru;

/* ҵ��ʶ��-��ʶ�������Ҫҵ��ṹ��: */
typedef struct {
    hmac_tx_flow_info_stru              flow_info;

    hi_u32                          average_len;                /* ҵ������ƽ������ */
    hi_u8                           flag;                       /* ��Чλ */

    hi_u8                           udp_flag;                   /* udp flagΪ1��ΪUDP֡ */
    hi_u8                           tcp_flag;                   /* tcp flagΪ1��ΪTCP֡ */

    hi_u8                           rtpver;                     /* RTP version */
    hi_u32                          rtpssrc;                    /* RTP SSRC */
    hi_u32                          payload_type;               /* ���1bit����Ч�غ�����(PT)7bit */

    hi_u32                          wait_check_num;             /* ������б��д�ҵ������� */
}hmac_tx_major_flow_stru;

/* ҵ��ʶ��-�û���ʶ��ṹ��: */
typedef struct {
    hmac_tx_flow_info_stru              cfm_flow_info;               /* ��ʶ��ҵ�����Ԫ����Ϣ */

    hi_u32                          last_jiffies;                /* ��¼��ʶ��ҵ�����������ʱ�� */
    hi_u16                          us_cfm_tid;                     /* ��ʶ��ҵ��tid */

    hi_u16                          us_cfm_flag;                        /* ��Чλ */
}hmac_tx_cfm_flow_stru;

/* ҵ��ʶ��-�û���ʶ��ҵ�����: */
typedef struct {
    hi_u32                          jiffies_st;                    /* ��¼��ʶ��ҵ����е���ʼʱ������������ʱ�� */
    hi_u32                          jiffies_end;
    hi_u32                          to_judge_num;                  /* �û���ʶ��ҵ����г��� */

    hmac_tx_judge_info_stru             ast_judge_cache[MAX_JUDGE_CACHE_LENGTH];     /* ��ʶ�������� */
}hmac_tx_judge_list_stru;
#endif

typedef struct {
    hi_u8                       amsdu_supported;             /* ÿ��λ����ĳ��TID�Ƿ�֧��AMSDU */
    mac_user_stats_flag_stru    user_stats_flag;             /* 1byte ��user��staʱ��ָʾuser�Ƿ�ͳ�Ƶ���Ӧ�� */
    hi_u16                      us_amsdu_maxsize;            /* amsdu��󳤶� */

    hmac_amsdu_stru            *past_hmac_amsdu[WLAN_WME_MAX_TID_NUM];     /* amsduָ������ */
    hmac_tid_stru               ast_tid_info[WLAN_TID_MAX_NUM];            /* ������TID��ص���Ϣ */
    hi_u8                       *ch_text;                                  /* WEP�õ���ս���� */
    frw_timeout_stru            mgmt_timer;                              /* ��֤�����ö�ʱ�� */
    frw_timeout_stru            defrag_timer;                            /* ȥ��Ƭ��ʱ��ʱ�� */
    oal_netbuf_stru            *defrag_netbuf;
#ifdef _PRE_WLAN_FEATURE_PMF
    mac_sa_query_stru           sa_query_info;                      /* sa query���̵Ŀ�����Ϣ */
#endif
    mac_rate_stru               op_rates;                           /* user��ѡ���� AP�ౣ��STA���ʣ�STA�ౣ��AP���� */
    hmac_user_cap_info_stru     hmac_cap_info;                      /* hmac���û�������־λ */
    hi_u32                      assoc_req_ie_len;
    hi_u8                      *puc_assoc_req_ie_buff;

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    /* ����/���� tcp/udp be,bk,vi,vo���� ������HMAC_EDCA_OPT_PKT_NUM u16�㹻 */
    hi_u16                      txrx_data_stat[WLAN_WME_AC_BUTT][WLAN_TXRX_DATA_BUTT];
#endif
#ifdef _PRE_WLAN_FEATURE_WAPI
    hmac_wapi_stru              wapi;
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_u32                      rssi_last_timestamp;                /* ��ȡuser rssi����ʱ���, 1s������һ��rssi */
#endif
#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
    hi_u8                       cfm_num;                            /* �û��ѱ�ʶ��ҵ����� */
    hi_u8                       auc_resv2[3]; /* 3 �����ֽ� */
    hmac_tx_cfm_flow_stru       ast_cfm_flow_list[MAX_CONFIRMED_FLOW_NUM];  /* ��ʶ��ҵ�� */
    hmac_tx_judge_list_stru     judge_list;                                 /* ��ʶ�������� */
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
    /* ��־��ǰMesh�û�AMPE�����׶��Ƿ��Ѿ��յ����ϱ�Confirm֡,�����ɹ�ʱ���� */
    hi_u8                       has_rx_mesh_confirm;
    hi_u8                       mesh_resv[3];   /* 3:Ԥ�� 4�ֽڶ��� */
#endif
    /* ����������ܴ���HMAC USER�ṹ���ڵ����һ�� �Ҳ����޸ĺ��ͷ� ��ģ���ʼ��ʱ��mac userָ��һһ��Ӧ */
    mac_user_stru              *base_user;
}hmac_user_stru;

/* SA Query ��ʱ��ʱ�� �� �����ʱ�� �ĳ�ʱ������νṹ */
typedef struct {
    mac_vap_stru     *mac_vap;                  /* ����SA Query request��mac vap��Ϣ */
    hmac_user_stru   *hmac_user;                /* Ŀ��user */
}hmac_maxtimeout_timer_stru;
typedef struct {
    mac_vap_stru       *mac_vap;                  /* ����SA Query request��mac vap��Ϣ */
    hmac_user_stru     *hmac_user;                /* Ŀ��user */
    hi_u16              us_trans_id;              /* SA Query request֡��trans id */
    hi_u8               is_protected;             /* SA Query����֡���ܵ�ʹ�ܿ��� */
    hi_u8               resv;
}hmac_interval_timer_stru;

/* �洢AP��������֡��ie��Ϣ�������ϱ��ں� */
typedef struct {
    hi_u32                      assoc_req_ie_len;
    hi_u8                      *puc_assoc_req_ie_buff;
    hi_u8                       auc_user_mac_addr[WLAN_MAC_ADDR_LEN];
    hi_u8                       uc_resv[2]; /* 2 �����ֽ� */
}hmac_asoc_user_req_ie_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : hmac_user_ht_support
 ��������  : �Ƿ�ΪHT�û�
 �������  : ��
 �������  : ��
 �� �� ֵ  : HI_TRUE�ǣ�HI_FALSE����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��4��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static inline hi_u8 hmac_user_ht_support(const hmac_user_stru *hmac_user)
{
    if (hmac_user->base_user->ht_hdl.ht_capable == HI_TRUE) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : �Ƿ�֧��ht/vht�ۺ�
 �������  : hmac_user_stru *pst_hmac_user
 �� �� ֵ  : static inline hi_u8
 �޸���ʷ      :
  1.��    ��   : 2013��12��12��,������
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 hmac_user_xht_support(const hmac_user_stru *hmac_user)
{
    if ((hmac_user->base_user->cur_protocol_mode >= WLAN_HT_MODE)
        && (hmac_user->base_user->cur_protocol_mode < WLAN_PROTOCOL_BUTT)) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_void hmac_user_res_exit(hi_void);
hi_u32 hmac_user_res_init(hi_void);
hi_u32 hmac_user_alloc(hi_u8 *puc_user_idx);
hi_u8 *hmac_user_get_user_stru(hi_u8 idx);
hi_u32  hmac_user_free(hi_u8 idx);
hi_u32  hmac_user_set_avail_num_space_stream(mac_user_stru *mac_user, wlan_nss_enum_uint8 vap_nss);
hi_u32  hmac_send_del_user_event(const mac_vap_stru *mac_vap, const hi_u8 *da_mac_addr, hi_u8 user_idx);
hi_u32  hmac_user_del(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user);
hi_u32 hmac_user_add(mac_vap_stru *mac_vap, const hi_u8 *mac_addr, hi_u8 mac_addr_len, hi_u8 *puc_user_index);
hi_u32  hmac_user_add_multi_user(const mac_vap_stru *mac_vap, hi_u8 *puc_user_index);
hi_u32  hmac_user_del_multi_user(hi_u8 idx);
hi_u32 hmac_user_add_notify_alg(const mac_vap_stru *mac_vap, hi_u8 user_idx);
hi_u32 hmac_update_user_last_active_time(mac_vap_stru *mac_vap, hi_u8 len, hi_u8 *puc_param);
hi_void hmac_tid_clear(mac_vap_stru *mac_vap, hmac_user_stru *hmac_user);
hmac_user_stru  *mac_vap_get_hmac_user_by_addr(mac_vap_stru *mac_vap, const hi_u8  *mac_addr, hi_u8 addr_len);

#ifdef _PRE_WLAN_FEATURE_WAPI
hmac_wapi_stru *hmac_user_get_wapi_ptr(const mac_vap_stru *mac_vap, hi_bool pairwise, hi_u8 pairwise_idx);
hi_u8  hmac_user_is_wapi_connected(hi_void);
#endif
hi_u32  hmac_user_asoc_info_report(mac_vap_stru *mac_vap, const mac_user_stru *mac_user, hi_u8 asoc_state);
#ifdef _PRE_WLAN_FEATURE_MESH
hi_u32 hmac_set_multicast_user_whitelist(const mac_vap_stru *mac_vap, const hi_u8 *mac_addr, hi_u8 mac_addr_len);
hi_u32 hmac_del_multicast_user_whitelist(const mac_vap_stru *mac_vap, const hi_u8 *mac_addr, hi_u8 mac_addr_len);
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* _HMAC_USER_H__ */
