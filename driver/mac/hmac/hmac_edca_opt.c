/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hmac_edca_opt.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "frw_event.h"
#include "hmac_edca_opt.h"
#include "hmac_ext_if.h"
#include "hmac_vap.h"
#include "hcc_hmac_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 �궨��
*****************************************************************************/
#define HMAC_EDCA_OPT_ADJ_STEP      2

/* (3-a)/3*X + a/3*Y */
#define wlan_edca_opt_mod(x, y, a) (((x) * (WLAN_EDCA_OPT_MAX_WEIGHT_STA - (a)) + (y) * (a)) / WLAN_EDCA_OPT_MAX_WEIGHT_STA);

/*****************************************************************************
  4 �ڲ���̬��������
*****************************************************************************/
static hi_void hmac_edca_opt_stat_traffic_num(const hmac_vap_stru *hmac_vap,
                                              hi_u8(*ppuc_traffic_num)[WLAN_TXRX_DATA_BUTT]);
/*****************************************************************************
  5 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : edca����ͳ����/���У�TCP/UDP����Ŀ
 �޸���ʷ      :
  1.��    ��   : 2014��12��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_edca_opt_stat_traffic_num(const hmac_vap_stru *hmac_vap,
                                              hi_u8(*ppuc_traffic_num)[WLAN_TXRX_DATA_BUTT])
{
    mac_user_stru *user = HI_NULL;
    hmac_user_stru *hmac_user = HI_NULL;
    hi_u8 ac_idx;
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    hi_list *list_pos = HI_NULL;

    list_pos = mac_vap->mac_user_list_head.next;

    for (; list_pos != &(mac_vap->mac_user_list_head); list_pos = list_pos->next) {
        user = hi_list_entry(list_pos, mac_user_stru, user_dlist);
        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru((hi_u8)user->us_assoc_id);
        if (hmac_user == HI_NULL) {
            continue;
        }

        for (ac_idx = 0; ac_idx < WLAN_WME_AC_BUTT; ac_idx++) {
            /* �������е��������� Ƕ�׳�4������ɾ��forѭ�� */
            if (hmac_user->txrx_data_stat[ac_idx][WLAN_TX_TCP_DATA] > HMAC_EDCA_OPT_PKT_NUM) {
                ppuc_traffic_num[ac_idx][WLAN_TX_TCP_DATA]++;
            }
            if (hmac_user->txrx_data_stat[ac_idx][WLAN_RX_TCP_DATA] > HMAC_EDCA_OPT_PKT_NUM) {
                ppuc_traffic_num[ac_idx][WLAN_RX_TCP_DATA]++;
            }
            if (hmac_user->txrx_data_stat[ac_idx][WLAN_TX_UDP_DATA] > HMAC_EDCA_OPT_PKT_NUM) {
                ppuc_traffic_num[ac_idx][WLAN_TX_UDP_DATA]++;
            }
            if (hmac_user->txrx_data_stat[ac_idx][WLAN_RX_UDP_DATA] > HMAC_EDCA_OPT_PKT_NUM) {
                ppuc_traffic_num[ac_idx][WLAN_RX_UDP_DATA]++;
            }
            /* ͳ�������0 */
            hmac_user->txrx_data_stat[ac_idx][WLAN_TX_TCP_DATA] = 0;
            hmac_user->txrx_data_stat[ac_idx][WLAN_RX_TCP_DATA] = 0;
            hmac_user->txrx_data_stat[ac_idx][WLAN_TX_UDP_DATA] = 0;
            hmac_user->txrx_data_stat[ac_idx][WLAN_RX_UDP_DATA] = 0;
        }
    }
}

/*****************************************************************************
 ��������  : edca������ʱ�����ڴ�����
 �޸���ʷ      :
  1.��    ��   : 2014��12��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �������¼��������������µ���alg

*****************************************************************************/
hi_u32  hmac_edca_opt_timeout_fn(hi_void *arg)
{
    hi_u8        aast_uc_traffic_num[WLAN_WME_AC_BUTT][WLAN_TXRX_DATA_BUTT] = {{0}};
    hmac_vap_stru   *hmac_vap       = HI_NULL;

    frw_event_mem_stru   *event_mem = HI_NULL;
    frw_event_stru       *event = HI_NULL;

    hmac_vap = (hmac_vap_stru *)arg;

    /* ��ȫ��̹���6.6����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(aast_uc_traffic_num, sizeof(aast_uc_traffic_num), 0, sizeof(aast_uc_traffic_num));

    /* ͳ��device�������û���/���� TPC/UDP����Ŀ */
    hmac_edca_opt_stat_traffic_num(hmac_vap, aast_uc_traffic_num);

    /***************************************************************************
        ���¼���dmacģ��,��ͳ����Ϣ����dmac
    ***************************************************************************/
    event_mem = frw_event_alloc(sizeof(aast_uc_traffic_num));
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANTI_INTF,
                       "{hmac_edca_opt_timeout_fn::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event = (frw_event_stru *)event_mem->puc_data;

    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPR_EDCA_OPT,
                       sizeof(aast_uc_traffic_num),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       hmac_vap->base_vap->vap_id);

    /* �������� */
    /* event->auc_event_data, �ɱ����� */
    if (memcpy_s(frw_get_event_payload(event_mem), sizeof(aast_uc_traffic_num), (hi_u8 *)aast_uc_traffic_num,
                 sizeof(aast_uc_traffic_num)) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CFG, "hmac_edca_opt_timeout_fn:: aast_uc_traffic_num memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(aast_uc_traffic_num));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : edca��������ͳ�ƽ��ձ�������
 �޸���ʷ      :
  1.��    ��   : 2014��12��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_edca_opt_rx_pkts_stat(hmac_user_stru *hmac_user, hi_u8 tidno, const mac_ip_header_stru *ip)
{
    /* ����IP_LEN С�� HMAC_EDCA_OPT_MIN_PKT_LEN�ı��� */
    if (oal_net2host_short(ip->us_tot_len) < HMAC_EDCA_OPT_MIN_PKT_LEN) {
        return;
    }

    if (ip->protocol == MAC_UDP_PROTOCAL) {
        hmac_user->txrx_data_stat[wlan_wme_tid_to_ac(tidno)][WLAN_RX_UDP_DATA]++;
    } else if (ip->protocol == MAC_TCP_PROTOCAL) {
        hmac_user->txrx_data_stat[wlan_wme_tid_to_ac(tidno)][WLAN_RX_TCP_DATA]++;
    }
}

/*****************************************************************************
 ��������  : edca��������ͳ�Ʒ��ͱ�������
 �޸���ʷ      :
  1.��    ��   : 2014��12��1��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_edca_opt_tx_pkts_stat(const hmac_tx_ctl_stru *tx_ctl, hi_u8 tidno, const mac_ip_header_stru *ip)
{
    hmac_user_stru *hmac_user = HI_NULL;
    hmac_vap_stru  *hmac_vap = HI_NULL;

    hmac_user = (hmac_user_stru *) hmac_user_get_user_stru(tx_ctl->us_tx_user_idx);
    if (oal_unlikely(hmac_user == HI_NULL)) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_edca_opt_rx_pkts_stat::hmac_user is null[%d].}", tx_ctl->us_tx_user_idx);
        return;
    }
    hmac_vap = hmac_vap_get_vap_stru(tx_ctl->tx_vap_index);
    if (hmac_vap == HI_NULL || hmac_vap->base_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_TX, "{hmac_tx_classify_ipv4_data::get hmac_vap[%d] fail.}", tx_ctl->tx_vap_index);
        return;
    }
    /* APģʽ�ҿ���EDCA�Ż�������ά��ͳ�� */
    if ((hmac_vap->edca_opt_flag_ap != HI_TRUE) || (hmac_vap->base_vap->vap_mode != WLAN_VAP_MODE_BSS_AP)) {
        return;
    }

    /* mips�Ż�:�������ҵ��ͳ�����ܲ�10M���� */
    if (((ip->protocol == MAC_UDP_PROTOCAL) &&
        (hmac_user->txrx_data_stat[wlan_wme_tid_to_ac(tidno)][WLAN_TX_UDP_DATA] <
            (HMAC_EDCA_OPT_PKT_NUM + 10))) || ((ip->protocol == MAC_TCP_PROTOCAL) && /* 10��ƫ��λ */
        (hmac_user->txrx_data_stat[wlan_wme_tid_to_ac(tidno)][WLAN_TX_TCP_DATA] < /* 10��ƫ��λ */
            (HMAC_EDCA_OPT_PKT_NUM + 10)))) {
        /* ����IP_LEN С�� HMAC_EDCA_OPT_MIN_PKT_LEN�ı��� */
        if (oal_net2host_short(ip->us_tot_len) < HMAC_EDCA_OPT_MIN_PKT_LEN) {
            return;
        }
        if (ip->protocol == MAC_UDP_PROTOCAL) {
            hmac_user->txrx_data_stat[wlan_wme_tid_to_ac(tidno)][WLAN_TX_UDP_DATA]++;
        } else if (ip->protocol == MAC_TCP_PROTOCAL) {
            hmac_user->txrx_data_stat[wlan_wme_tid_to_ac(tidno)][WLAN_TX_TCP_DATA]++;
        }
    }
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
