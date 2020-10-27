/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HMAC BSS AP TX master file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_net.h"
#include "hmac_tx_data.h"
#include "hmac_tx_amsdu.h"
#include "mac_frame.h"
#include "mac_data.h"
#include "hmac_frag.h"
#include "hmac_ext_if.h"
#ifdef _PRE_WLAN_FEATURE_WAPI
#include "hmac_wapi.h"
#endif
#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
#include "hmac_traffic_classify.h"
#endif
#include "hmac_crypto_tkip.h"
#include "hmac_device.h"
#include "hcc_hmac_if.h"
#include "wal_customize.h"
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
#include "hmac_edca_opt.h"
#endif
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC != _PRE_MULTI_CORE_MODE)
static hi_u16 g_us_noqos_frag_seqnum = 0; /* �����qos��Ƭ֡seqnum */
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
hi_u32 hmac_tx_data(hmac_vap_stru *hmac_vap, oal_netbuf_stru *netbuf);
#endif
/*****************************************************************************
 �� �� ��  : free_netbuf_list
 ��������  : �ͷ�һ��netbuf���������е�skb���߶�����lan�����߶�����wlan
 �������  : pst_buf��SKB�ṹ�嵥���������һ��nextָ�����ΪNULL���������쳣
 �������  :
 �� �� ֵ  : �ͷŵ�buf��Ŀ
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u16 hmac_free_netbuf_list(oal_netbuf_stru  *netbuf)
{
    oal_netbuf_stru     *buf_tmp = HI_NULL;
    hmac_tx_ctl_stru     *tx_cb = HI_NULL;
    hi_u16           us_buf_num = 0;

    if (netbuf != HI_NULL) {
        while (netbuf != HI_NULL) {
            buf_tmp = oal_netbuf_list_next(netbuf);
            us_buf_num++;
            oal_netbuf_next(netbuf) = HI_NULL;
            tx_cb = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
            /* ���frame_header�������ڴ������ĲŴ��ڴ���ͷţ�����skb�ڲ�����ģ��Ͳ���Ҫ���ͷ� */
            if ((tx_cb->mac_head_type == 0) && (tx_cb->frame_header != HI_NULL)) {
                oal_free(tx_cb->frame_header);
                tx_cb->frame_header = HI_NULL;
            }

            oal_netbuf_free(netbuf);

            netbuf = buf_tmp;
        }
    } else {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_free_netbuf_list::pst_buf is null}");
    }

    return us_buf_num;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 �� �� ��  : hmac_tid_num_set
 ��������  : �������ȼ�����tid��
 �޸���ʷ      :
  1.��    ��   : 2019��09��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_tid_num_set(hi_u32 buf_prio, hi_u8 *tid)
{
    switch (buf_prio) {
        case 0: /* 0:���ȼ� */
            *tid = WLAN_TIDNO_BEST_EFFORT;
            break;
        case 1: /* 1:���ȼ� */
            *tid = WLAN_TIDNO_BACKGROUND;
            break;
        case 2: /* 2:���ȼ� */
            *tid = WLAN_TIDNO_VIDEO;
            break;
        default:
            *tid = WLAN_TIDNO_VOICE;
            break;
    }
}
#endif

#ifdef _PRE_WLAN_FEATURE_CLASSIFY
/*****************************************************************************
 ��������  : ��lan������IP����ҵ��ʶ��
*****************************************************************************/
static hi_void hmac_tx_classify_ipv4_data(hmac_tx_ctl_stru *tx_ctl, mac_ether_header_stru *ether_header, hi_u8 *puc_tid)
{
    mac_ip_header_stru *ip = HI_NULL;
    hi_u8              tid;
#ifdef _PRE_WLAN_FEATURE_SCHEDULE
    mac_tcp_header_stru *tcp = HI_NULL;
#endif

#if defined(_PRE_WLAN_FEATURE_EDCA_OPT_AP) || defined(_PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN)
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(tx_ctl->tx_vap_index);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_TX, "{hmac_tx_classify_ipv4_data::get hmac_vap[%d] fail.}", tx_ctl->tx_vap_index);
        return;
    }
#endif
    /* ��IP TOS�ֶ�Ѱ�����ȼ� */
    /*----------------------------------------------------------------------
        tosλ����
     ----------------------------------------------------------------------
    | bit7~bit5 | bit4 |  bit3  |  bit2  |   bit1   | bit0 |
    | �����ȼ�  | ʱ�� | ������ | �ɿ��� | ����ɱ� | ���� |
     ----------------------------------------------------------------------*/
    ip = (mac_ip_header_stru *)(ether_header + 1);      /* ƫ��һ����̫��ͷ��ȡipͷ */
    tid = ip->tos >> WLAN_IP_PRI_SHIFT;
#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
    if (hmac_vap->tx_traffic_classify_flag == HI_SWITCH_ON) {
        if (tid != 0) {
            return;
        }
        hmac_tx_traffic_classify(tx_ctl, ip, &tid);
    }
#endif  /* _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN */

    /* �����DHCP֡�������VO���з��� */
    if (mac_is_dhcp_port(ip)) {
        tid = WLAN_DATA_VIP_TID;
        tx_ctl->is_vipframe  = HI_TRUE;
        tx_ctl->is_needretry = HI_TRUE;
    } else if (ip->protocol == MAC_ICMP_PROTOCAL) {
        tx_ctl->high_prio_sch = HI_TRUE;
        /* ����ping����ȡ����ش����� */
        tx_ctl->is_needretry = HI_TRUE;
#ifdef _PRE_WLAN_FEATURE_SCHEDULE
    } else if (ip->protocol == MAC_TCP_PROTOCAL) {
        /* ����chariot����Ľ������⴦����ֹ���� */
        tcp = (mac_tcp_header_stru *)(ip + 1);
        if ((oal_ntoh_16(tcp->us_dport) == MAC_CHARIOT_NETIF_PORT) ||
            (oal_ntoh_16(tcp->us_sport) == MAC_CHARIOT_NETIF_PORT)) {
            tid = WLAN_DATA_VIP_TID;
            tx_ctl->is_vipframe  = HI_TRUE;
            tx_ctl->is_needretry = HI_TRUE;
        }
#endif
    }

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    /* EDCA AP�Ż�ͳ����ˢ�� */
    hmac_edca_opt_tx_pkts_stat(tx_ctl, tid, ip);
#endif
    *puc_tid = tid;
}

/*****************************************************************************
 ��������  : ��lan������IPV6����ҵ��ʶ��
*****************************************************************************/
static hi_void hmac_tx_classify_ipv6_data(hmac_tx_ctl_stru *tx_ctl, mac_ether_header_stru *ether_header,
                                          hi_u32 buf_prio, hi_u8 *puc_tid)
{
    hi_u32 ipv6_hdr;
    hi_u32 pri;
    hi_u8  tid;

#if defined(_PRE_WLAN_FEATURE_MESH)
    hmac_vap_stru *hmac_vap   = hmac_vap_get_vap_stru(tx_ctl->tx_vap_index);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(0, OAM_SF_TX, "{hmac_tx_classify_ipv6_data::get hmac_vap[%d] fail.}", tx_ctl->tx_vap_index);
        return;
    }
#else
    hi_unref_param(buf_prio);
#endif
    /* ��IPv6 traffic class�ֶλ�ȡ���ȼ� */
    /*----------------------------------------------------------------------
        IPv6��ͷ ǰ32Ϊ����
     -----------------------------------------------------------------------
    | �汾�� | traffic class   | ������ʶ |
    | 4bit   | 8bit(ͬipv4 tos)|  20bit   |
    -----------------------------------------------------------------------*/
    ipv6_hdr = *((hi_u32 *)(ether_header + 1));  /* ƫ��һ����̫��ͷ��ȡipͷ */
    pri = (oal_net2host_long(ipv6_hdr) & WLAN_IPV6_PRIORITY_MASK) >> WLAN_IPV6_PRIORITY_SHIFT;
    tid = (hi_u8)(pri >> WLAN_IP_PRI_SHIFT);
    /* �����ND DHCPV6֡�������VO���з��� */
    if (mac_is_nd((oal_ipv6hdr_stru *)(ether_header + 1)) || mac_is_dhcp6((oal_ipv6hdr_stru *)(ether_header + 1))) {
        tid = WLAN_DATA_VIP_TID;
        tx_ctl->is_vipframe  = HI_TRUE;
        tx_ctl->is_needretry = HI_TRUE;
    } else {    /* ��ܱ�̹淶K&R��� else��if��� */
#ifdef _PRE_WLAN_FEATURE_MESH
        if (mac_is_rpl((oal_ipv6hdr_stru *)(ether_header + 1))) {
            oam_warning_log0(0, OAM_SF_TX, "{hmac_tx_classify_ipv6_data::ETHER_TYPE_RPL.}");
            tid = WLAN_DATA_VIP_TID;
            tx_ctl->is_vipframe  = HI_TRUE;
            tx_ctl->is_needretry = HI_TRUE;
        } else if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) {
            /* ��׮�����а�ͷѹ��ʱ��pbuf flag�ж� */
            /*
            uc_pbuf_flags:
            |BIT1       |BIT0           |
            |Ctrl PKT  |Compressed 6lo  |
            */
            if (tx_ctl->pbuf_flags & BIT1) {
                tid = WLAN_DATA_VIP_TID;
                tx_ctl->is_vipframe  = HI_TRUE;
            } else {
                /* ���ȼ���0-3,����3ͳһ��Ϊ��3һ�� */
                hmac_tid_num_set(buf_prio, &tid);
            }
        }
#endif
    }
    *puc_tid = tid;
}

/*****************************************************************************
 ��������  : ��lan�������ĵ�ҵ��ʶ��
 �޸���ʷ      :
  1.��    ��   : 2013��10��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2015��11��23��
    ��    ��   : Hisilicon
    �޸�����   : �����㷨����
*****************************************************************************/
static hi_void hmac_tx_classify_lan_to_wlan(oal_netbuf_stru *netbuf, hi_u8 *puc_tid)
{
    mac_ether_header_stru  *ether_header = HI_NULL;
    hmac_tx_ctl_stru       *tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
    hi_u32                  buf_prio = oal_netbuf_priority(netbuf);
    hi_u8                   tid = 0;

    /* ��ȡ��̫��ͷ */
    ether_header = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
    /* �������ĸ���Ϊif else��� */
    if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_IP)) {
        /* ipv4���Ĵ��� */
        hmac_tx_classify_ipv4_data(tx_ctl, ether_header, &tid);
    } else if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_IPV6)) {
        /* ipv6���Ĵ��� */
        hmac_tx_classify_ipv6_data(tx_ctl, ether_header, buf_prio, &tid);
    } else if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_PAE)) {
        /* �����EAPOL֡�������VO���з��� */
        tid = WLAN_DATA_VIP_TID;
        tx_ctl->is_vipframe  = HI_TRUE;
        tx_ctl->is_needretry = HI_TRUE;
        /* �����4 ���������õ�����Կ��������tx cb ��bit_is_eapol_key_ptk ��һ��dmac ���Ͳ����� */
        if (mac_is_eapol_key_ptk((mac_eapol_header_stru *)(ether_header + 1))) {
            tx_ctl->is_eapol_key_ptk = HI_TRUE;
        }
    } else if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_TDLS)) {
        /* TDLS֡��������������������ȼ�TID���� */
        tid = WLAN_DATA_VIP_TID;
        oam_info_log1(0, OAM_SF_TX, "{hmac_tx_classify_lan_to_wlan::TDLS tid=%d.}", tid);
    } else if ((ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_PPP_DISC)) ||
               (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_PPP_SES)) ||
               (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_WAI))) {
        /* PPPOE֡������������(���ֽ׶�, �Ự�׶�)��������ȼ�TID���� */
        tid = WLAN_DATA_VIP_TID;
        tx_ctl->is_vipframe  = HI_TRUE;
        tx_ctl->is_needretry = HI_TRUE;
        oam_info_log2(0, 0, "{hmac_tx_classify_lan_to_wlan::type=%d, tid=%d.}", ether_header->us_ether_type, tid);
    } else if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_ARP)) {
        /* �����ARP֡�������VO���з��� */
        tid = WLAN_DATA_VIP_TID;
        tx_ctl->is_vipframe  = HI_TRUE;
    } else if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_VLAN)) {
        /* ��ȡvlan tag�����ȼ� */
        oal_vlan_ethhdr_stru *vlan_ethhdr = (oal_vlan_ethhdr_stru *)oal_netbuf_data(netbuf);
        /*------------------------------------------------------------------
            802.1Q(VLAN) TCI(tag control information)λ����
         -------------------------------------------------------------------
        |Priority | DEI  | Vlan Identifier |
        | 3bit    | 1bit |      12bit      |
         ------------------------------------------------------------------*/
        hi_u16 vlan_tci = oal_net2host_short(vlan_ethhdr->h_vlan_tci);
        tid = vlan_tci >> OAL_VLAN_PRIO_SHIFT;    /* ����13λ����ȡ��3λ���ȼ� */
        oam_info_log1(0, OAM_SF_TX, "{hmac_tx_classify_lan_to_wlan::VLAN tid=%d.}", tid);
    } else {    /* ��ܱ�̹淶K&R��� else��if��� */
#ifdef _PRE_WLAN_FEATURE_MESH
        if (ether_header->us_ether_type == oal_host2net_short(ETHER_TYPE_6LO)) {
            if (tx_ctl->pbuf_flags & BIT0) {
                /* ���ȼ���0-3,����3ͳһ��Ϊ��3һ�� */
                hmac_tid_num_set(buf_prio, &tid);
            }
        }
#endif
    }
    /* ���θ�ֵ */
    *puc_tid = tid;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_update_tid
 ��������  : �����㷨����tid = 1, 3, 5, 7�ģ��ֱ����Ϊ0, 2, 4, 6
             ���WMM���ܹرգ�ֱ����ΪDMAC_WMM_SWITCH_TID
 �������  : puc_tid ע�⣬�˲���Ϊ�����
 �������  : puc_tid
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��3��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void hmac_tx_update_tid(hi_u8  wmm, hi_u8 *puc_tid)
{
    if (oal_likely(wmm == HI_TRUE)) { /* wmmʹ�� */
        *puc_tid = (*puc_tid < WLAN_TIDNO_BUTT) ? wlan_tos_to_tid(*puc_tid) : WLAN_TIDNO_BCAST;
    } else {
        /* wmm��ʹ�� */
        *puc_tid = MAC_WMM_SWITCH_TID;
    }
}

/*****************************************************************************
 �� �� ��  : hmac_tx_wmm_acm
 ��������  : �����ȵ�����ACM������ѡ�����
 �������  :
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��11��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_tx_wmm_acm(hi_u8 wmm, const hmac_vap_stru *hmac_vap, hi_u8 *puc_tid)
{
    hi_u8                   ac;
    hi_u8                   ac_new;

    if ((hmac_vap == HI_NULL) || (hmac_vap->base_vap->mib_info == HI_NULL) || (puc_tid == HI_NULL)) {
        return HI_FALSE;
    }

    if (wmm == HI_FALSE) {
        return HI_FALSE;
    }

    ac = wlan_wme_tid_to_ac(*puc_tid);
    ac_new = ac;
    while ((ac_new != WLAN_WME_AC_BK) &&
        (hmac_vap->base_vap->mib_info->wlan_mib_qap_edac[ac_new].dot11_qapedca_table_mandatory == HI_TRUE)) {
        switch (ac_new) {
            case WLAN_WME_AC_VO:
                ac_new = WLAN_WME_AC_VI;
                break;

            case WLAN_WME_AC_VI:
                ac_new = WLAN_WME_AC_BE;
                break;

            default:
                ac_new = WLAN_WME_AC_BK;
                break;
        }
    }

    if (ac_new != ac) {
        *puc_tid = wlan_wme_ac_to_tid(ac_new);
    }

    return HI_TRUE;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_classify
 ��������  : ��̫���� ҵ��ʶ��
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��5��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

  2.��    ��   : 2013��10��10��
    ��    ��   : Hisilicon
    �޸�����   : ����wlan to wlan��֧����

*****************************************************************************/
static hi_void  hmac_tx_classify(
                const hmac_vap_stru   *hmac_vap,
                const mac_user_stru   *user,
                oal_netbuf_stru *netbuf)
{
    hi_u8            tid = 0;
    hi_u8            ret;
    hmac_tx_ctl_stru *tx_ctl = HI_NULL;
    mac_device_stru  *mac_dev = HI_NULL;

    hmac_tx_classify_lan_to_wlan(netbuf, &tid);

    /* ��QoSվ�㣬ֱ�ӷ��� */
    if (oal_unlikely(user->cap_info.qos != HI_TRUE)) {
        /* ROM����ֹ���� */
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_TX, "{hmac_tx_classify::user is a none QoS station.}");
        return;
    }

    mac_dev = mac_res_get_dev();
    ret = hmac_tx_wmm_acm(mac_dev->wmm, hmac_vap, &tid);
    if (ret != HI_TRUE) {
        oam_info_log0(hmac_vap->base_vap->vap_id, OAM_SF_TX, "hmac_tx_wmm_acm return NON SUCCESS. ");
    }

    /* DTS2015120907139: ����1151֧��VO�ۺ�, VIP���ĺ�VO���Ķ�����tid 6�ۺϴ���, ����VIP�����޷��Ի������ʷ��͡�
       ���, ��VIP���ķ���tid 7, ��ʵ��VOҵ������, ��֤VIP���ĵĴ���ɿ��ԡ� */
    tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
    if ((tx_ctl->is_vipframe != HI_TRUE) || (mac_dev->wmm == HI_FALSE)) {
        hmac_tx_update_tid(mac_dev->wmm, &tid);
    }

    /* ����ac��tid��cb�ֶ� */
    tx_ctl->tid  = tid;
    tx_ctl->ac   = wlan_wme_tid_to_ac(tid);
    /* VO/VI����������֡���ó���Ҫ�ش� */
    if (tx_ctl->ac == WLAN_WME_AC_VI || tx_ctl->ac == WLAN_WME_AC_VO) {
        tx_ctl->is_needretry = HI_TRUE;
    }

    return;
}
#endif

/*****************************************************************************
 �� �� ��  : hmac_tx_filter_security
 ��������  : ���������̫��������֡����ȫ����
 �������  : hmac_vap_stru     *pst_hmac_vap
             oal_netbuf_stru  *pst_buf
             hmac_user_stru   *pst_hmac_user
             hmac_tx_ctl_stru  *pst_tx_ctl
 �������  : HI_TRUE
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��9��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 hmac_tx_filter_security(const hmac_vap_stru     *hmac_vap,
                                      const oal_netbuf_stru  *netbuf,
                                      const hmac_user_stru   *hmac_user)
{
    mac_ether_header_stru   *ether_header = HI_NULL;
    mac_user_stru           *mac_user     = HI_NULL;
    mac_vap_stru            *mac_vap      = HI_NULL;
    hi_u32               ret           = HI_SUCCESS;

    mac_vap  = hmac_vap->base_vap;
    mac_user = hmac_user->base_user;

    if (mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated == HI_TRUE) { /* �ж��Ƿ�ʹ��WPA/WPA2 */
        if (mac_user->port_valid != HI_TRUE) { /* �ж϶˿��Ƿ�� */
            /* ��ȡ��̫��ͷ */
            ether_header = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
            /* ��������ʱ����Է�EAPOL ������֡������ */
            if (hi_swap_byteorder_16(ETHER_TYPE_PAE) != ether_header->us_ether_type) {
                oam_info_log2(0, OAM_SF_TX, "{hmac_tx_filter_security::TYPE 0x%04x, 0x%04x.}",
                    hi_swap_byteorder_16(ether_header->us_ether_type), ETHER_TYPE_PAE);
                ret = HI_FAIL;
            }
        }
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_ba_setup
 ��������  : �Զ�����BA�Ự�Ľ���
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��4��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void  hmac_tx_ba_setup(
                hmac_vap_stru    *hmac_vap,
                hmac_user_stru   *hmac_user,
                hi_u8         tidno)
{
    mac_action_mgmt_args_stru   action_args;   /* ������дACTION֡�Ĳ��� */
    hi_u8         ampdu_support;
    hi_u32        ret = HI_SUCCESS;

    /* ����BA�Ự���Ƿ���Ҫ�ж�VAP��AMPDU��֧���������Ϊ��Ҫʵ�ֽ���BA�Ựʱ��һ����AMPDU */
    ampdu_support = hmac_user_xht_support(hmac_user);
    if (ampdu_support) {
        /*
        ����BA�Ựʱ��st_action_args�ṹ������Ա��������
        (1)uc_category:action�����
        (2)uc_action:BA action�µ����
        (3)ul_arg1:BA�Ự��Ӧ��TID
        (4)ul_arg2:BUFFER SIZE��С
        (5)ul_arg3:BA�Ự��ȷ�ϲ���
        (6)ul_arg4:TIMEOUTʱ��
        */
        action_args.category = MAC_ACTION_CATEGORY_BA;
        action_args.action   = MAC_BA_ACTION_ADDBA_REQ;
        action_args.arg1     = tidno;                                      /* ������֡��Ӧ��TID�� */
        action_args.arg2     = (hi_u32)hmac_vap->max_ampdu_num;        /* ADDBA_REQ�У�buffer_size��Ĭ�ϴ�С */
        action_args.arg3     = MAC_BA_POLICY_IMMEDIATE;                       /* BA�Ự��ȷ�ϲ��� */
        action_args.arg4     = 0;                                             /* BA�Ự�ĳ�ʱʱ������Ϊ0 */
        oam_warning_log1(0, OAM_SF_TX, "hisi_customize_wifi::[ba buffer size:%d]", action_args.arg2);
        /* ����BA�Ự */
        ret = hmac_mgmt_tx_action(hmac_vap, hmac_user, &action_args);
    } else {
        if (hmac_user->ast_tid_info[tidno].ba_tx_info != HI_NULL) {
            action_args.category = MAC_ACTION_CATEGORY_BA;
            action_args.action   = MAC_BA_ACTION_DELBA;
            action_args.arg1     = tidno;                                         /* ������֡��Ӧ��TID�� */
            action_args.arg2     = MAC_ORIGINATOR_DELBA;                             /* ���Ͷ�ɾ��ba */
            action_args.arg3     = MAC_UNSPEC_REASON;                                /* BA�Ựɾ��ԭ�� */
            action_args.puc_arg5     = hmac_user->base_user->user_mac_addr;   /* �û�mac��ַ */
            /* ɾ��BA�Ự */
            ret = hmac_mgmt_tx_action(hmac_vap, hmac_user, &action_args);
        }
    }

    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_TX, "hmac_mgmt_tx_action return NON SUCCESS. ");
    }
}

hi_void hmac_check_if_mgmt_tx_action(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, hi_u8 tidno)
{
    if (hmac_vap->ampdu_tx_on_switch == HI_FALSE) {
        mac_action_mgmt_args_stru action_args = {0}; /* ������дACTION֡�Ĳ��� */
        action_args.category = MAC_ACTION_CATEGORY_BA;
        action_args.action   = MAC_BA_ACTION_DELBA;
        action_args.arg1     = tidno;
        action_args.arg2     = MAC_ORIGINATOR_DELBA;
        action_args.arg3     = MAC_UNSPEC_REASON;
        action_args.puc_arg5 = hmac_user->base_user->user_mac_addr;

        if (hmac_mgmt_tx_action(hmac_vap,  hmac_user, &action_args) != HI_SUCCESS) {
            oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_CFG, "hmac_mgmt_tx_action return NON SUCCESS. ");
        }
    }
}
/*****************************************************************************
 �� �� ��  : hmac_tx_ba_check
 ��������  : �ж��Ƿ���Ҫ����BA�Ự
 �������  : ��
 �������  : ��
 �� �� ֵ  : HI_TRUE������Ҫ����BA�Ự
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��6��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

�޸���ʷ      :
  2.��    ��   : 2015��7��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u8 hmac_tid_need_ba_session(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user,
    hi_u8 tidno, const oal_netbuf_stru *netbuf)
{
    if ((hmac_vap == HI_NULL) || (hmac_user == HI_NULL) || (netbuf == HI_NULL) ||
        (hmac_user->base_user == HI_NULL)) {
        return HI_FALSE;
    }

    if (hmac_vap_ba_is_setup(hmac_user, tidno) == HI_TRUE) {
        hmac_check_if_mgmt_tx_action(hmac_vap, hmac_user, tidno);
        return HI_FALSE;
    }

    /* ��������������ۺ�ʱ���� */
    /* խ���������ۺ� */
    /* ���VOҵ��, ����VAP��־λȷ���Ƿ���BA�Ự */
    /* �ж�HMAC VAP���Ƿ�֧�־ۺ� */
    if ((hmac_vap->ampdu_tx_on_switch == HI_FALSE) || (hmac_user_xht_support(hmac_user) == HI_FALSE) ||
        ((wlan_wme_tid_to_ac(tidno) == WLAN_WME_AC_VO) && (hmac_vap->base_vap->voice_aggr == HI_FALSE)) ||
        (!((hmac_vap->tx_aggr_on) || (hmac_vap->base_vap->cap_flag.rifs_tx_on)))) {
        return HI_FALSE;
    }

#ifdef _PRE_WLAN_FEATURE_AMPDU_VAP
    if (hmac_vap->tx_ba_session_num >= WLAN_MAX_TX_BA) {
        return HI_FALSE;
    }
#else
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    if (hmac_dev->tx_ba_session_num >= WLAN_MAX_TX_BA) {
        return HI_FALSE;
    }
#endif

    /* ��Ҫ�ȷ���5������֡���ٽ���BA�Ự�Ľ��� */
    if ((hmac_user->base_user->cap_info.qos) && (hmac_user->ast_tid_info[tidno].ba_flag < DMAC_UCAST_TX_COMP_TIMES)) {
        hmac_user->ast_tid_info[tidno].ba_flag++;
        return HI_FALSE;
    } else if (hmac_user->base_user->cap_info.qos == HI_FALSE) {
        /* ��Թر�WMM����QOS֡���� */
        return HI_FALSE;
    }

    /* tx ba���Դ����������ֵ �������ٴν���BA */
    if ((hmac_user->ast_tid_info[tidno].ba_tx_info == HI_NULL) &&
        (hmac_user->ast_tid_info[tidno].tx_ba_attemps < HMAC_ADDBA_EXCHANGE_ATTEMPTS)) {
        hmac_user->ast_tid_info[tidno].tx_ba_attemps++;
    } else {
        return HI_FALSE;
    }

    return HI_TRUE;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_ucast_process
 ��������  : ��������
 �������  : pst_vap VAP�ṹ��; pst_buf netbuf�ṹ��;pst_user �û��ṹ��
 �������  :
 �� �� ֵ  :
 ���ú���  : hmac_tx_mpdu_process_ap
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2013��09��12��
    ��    ��   : Hisilicon
    �޸�����   : �޸ĺ��������Ӱ�ȫ����

*****************************************************************************/
hmac_tx_return_type_enum_uint8 hmac_tx_ucast_process(hmac_vap_stru     *hmac_vap,
                                                     oal_netbuf_stru   *netbuf,
                                                     hmac_user_stru    *hmac_user,
                                                     const hmac_tx_ctl_stru   *tx_ctl)
{
    hmac_tx_return_type_enum_uint8  ret = HMAC_TX_PASS;

   /* ��ȫ���� */
#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    if (oal_unlikely(hmac_tx_filter_security(hmac_vap, netbuf, hmac_user) != HI_SUCCESS)) {
        return HMAC_TX_DROP_SECURITY_FILTER;
    }
#endif

    /* ��̫��ҵ��ʶ�� */
#ifdef _PRE_WLAN_FEATURE_CLASSIFY
    hmac_tx_classify(hmac_vap, hmac_user->base_user, netbuf);
#endif

    /* �����EAPOL��DHCP֡����������������BA�Ự */
    if (tx_ctl->is_vipframe == HI_FALSE) {
#ifdef _PRE_WLAN_FEATURE_AMPDU
        if (hmac_tid_need_ba_session(hmac_vap, hmac_user, tx_ctl->tid, netbuf) == HI_TRUE) {
            /* �Զ���������BA�Ự������AMPDU�ۺϲ�����Ϣ��DMACģ��Ĵ���addba rsp֡��ʱ�̺��� */
            hmac_tx_ba_setup(hmac_vap, hmac_user, tx_ctl->tid);
        }
#endif
        ret = hmac_amsdu_notify(hmac_vap, hmac_user, netbuf);
        if (oal_unlikely(ret != HMAC_TX_PASS)) {
            return ret;
        }
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_is_need_frag
 ��������  : ���ñ����Ƿ���Ҫ��Ƭ
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��2��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u8  hmac_tx_is_need_frag(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
    const oal_netbuf_stru *netbuf, const hmac_tx_ctl_stru *tx_ctl)
{
    hi_u32        threshold;
    hi_u32        last_frag;
    hi_u32        netbuf_len;

    /* �жϱ����Ƿ���Ҫ���з�Ƭ */
    /* 1�����ȴ�������          */
    /* 2����legacЭ��ģʽ       */
    /* 3�����ǹ㲥֡            */
    /* 4�����Ǿۺ�֡            */
    /* 6��DHCP֡�����з�Ƭ      */
    /* 7��mesh����Ƭ */
    if (tx_ctl->is_vipframe == HI_TRUE) {
        return HI_FALSE;
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        return HI_FALSE;
    }
#endif

    threshold = hmac_vap->base_vap->mib_info->wlan_mib_operation.dot11_fragmentation_threshold;
    threshold = (threshold & (~(BIT0 | BIT1))) + 2; /* ��2 */
    /* ���1151Ӳ��bug,������Ƭ���ޣ�TKIP����ʱ�������һ����Ƭ��payload����
       С�ڵ���8ʱ���޷����м��� */
    if (WLAN_80211_CIPHER_SUITE_TKIP == hmac_user->base_user->key_info.cipher_type) {
        last_frag = (oal_netbuf_len(netbuf) + 8) % (threshold - tx_ctl->frame_header_length - /* ��8 */
            (WEP_IV_FIELD_SIZE + EXT_IV_FIELD_SIZE));
        if ((last_frag > 0) && (last_frag <= 8)) { /* 8 �߽� */
            threshold = threshold + 8; /* ���� 8 */
        }
    }

    netbuf_len = (tx_ctl->mac_head_type == 1) ?
                  oal_netbuf_len(netbuf) : (oal_netbuf_len(netbuf) + tx_ctl->frame_header_length);

    return (hi_u8)((netbuf_len > threshold) && (!tx_ctl->ismcast) &&
            (!tx_ctl->is_amsdu) &&
            (hmac_user->base_user->cur_protocol_mode < WLAN_HT_MODE || hmac_vap->base_vap->protocol < WLAN_HT_MODE) &&
            (HI_FALSE == hmac_vap_ba_is_setup(hmac_user, tx_ctl->tid)));
}

/*****************************************************************************
 �� �� ��  : hmac_tx_set_frame_ctrl
 ��������  : ����֡����
 �������  : ul_qos �Ƿ���QOSվ�� pst_tx_ctl CB�ֶ� pst_hdr 802.11ͷ
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void hmac_tx_set_frame_ctrl(hi_u32                             qos,
                                      const hmac_tx_ctl_stru             *tx_ctl,
                                      mac_ieee80211_qos_frame_addr4_stru *hdr_addr4)
{
    mac_ieee80211_qos_frame_stru *hdr = HI_NULL;
    hi_u8               is_amsdu;
    if (qos == HMAC_TX_BSS_QOS) {
        if (tx_ctl->netbuf_num == 1) {
            is_amsdu = HI_FALSE;
        } else {
            is_amsdu = tx_ctl->is_amsdu;
        }

        /* ����֡�����ֶ� */
        mac_hdr_set_frame_control((hi_u8 *)hdr_addr4, (WLAN_FC0_SUBTYPE_QOS | WLAN_FC0_TYPE_DATA));

        /* ����֡ͷ���� */
        if (tx_ctl->use_4_addr == HI_FALSE) {
            hdr = (mac_ieee80211_qos_frame_stru *)hdr_addr4;
            /* ����QOS�����ֶ� */
            hdr->qc_tid        = tx_ctl->tid;
            hdr->qc_eosp       = 0;
            hdr->qc_ack_polocy = tx_ctl->ack_policy;
            hdr->qc_amsdu      = is_amsdu;
            hdr->qos_control.qc_txop_limit = 0;
        } else {
            /* ����QOS�����ֶ� */
            hdr_addr4->qc_tid        = tx_ctl->tid;
            hdr_addr4->qc_eosp       = 0;
            hdr_addr4->qc_ack_polocy = tx_ctl->ack_policy;
            hdr_addr4->qc_amsdu      = is_amsdu;
            hdr_addr4->qos_control.qc_txop_limit = 0;
        }

        /* ��DMAC�����Ƿ���ҪHTC */
    } else {
        /* ����֡�����ֶ� */
        mac_hdr_set_frame_control((hi_u8 *)hdr_addr4, WLAN_FC0_TYPE_DATA | WLAN_FC0_SUBTYPE_DATA);
    }
}

/*****************************************************************************
 ��������  : 3��ַapģʽ����MACͷ��ַ
*****************************************************************************/
static hi_u32 hmac_tx_ap_set_addresses(const hmac_vap_stru *hmac_vap, const hmac_tx_ctl_stru *tx_ctl,
    mac_ieee80211_frame_addr4_stru *hdr, const hmac_set_addresses_info_stru *set_addresses_info)
{
    /* From DS��ʶλ���� */
    mac_hdr_set_from_ds((hi_u8 *)hdr, 1);
    /* to DS��ʶλ���� */
    mac_hdr_set_to_ds((hi_u8 *)hdr, 0);
    /* Set Address1 field in the WLAN Header with destination address */
    if (memcpy_s(hdr->auc_address1, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_daddr, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }
    /* Set Address2 field in the WLAN Header with the BSSID */
    if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN,
                 hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }
    /* AMSDU�������ַ3��дBSSID */
    if (tx_ctl->is_amsdu) {
        /* Set Address3 field in the WLAN Header with the BSSID */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN,
                     hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
            return HI_FAIL;
        }
    } else {
        /* Set Address3 field in the WLAN Header with the source address */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_saddr, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
    }
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  : 3��ַmeshģʽ����MACͷ��ַ
*****************************************************************************/
static hi_u32 hmac_tx_mesh_set_addresses(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
                                         const hmac_tx_ctl_stru *tx_ctl, mac_ieee80211_frame_addr4_stru *hdr,
                                         const hmac_set_addresses_info_stru *set_addresses_info)
{
    if (hmac_user->base_user->is_mesh_user == HI_TRUE) {
        /* From DS��ʶλ���� */
        mac_hdr_set_from_ds((hi_u8 *)hdr, 0);
        /* to DS��ʶλ���� */
        mac_hdr_set_to_ds((hi_u8 *)hdr, 0);
        /* Set Address3 field in the WLAN Header with the BSSID */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
        /* AMSDU�������ַ2��дBSSID */
        if (tx_ctl->is_amsdu) {
            /* Set Address3 field in the WLAN Header with the BSSID */
            if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) !=
                EOK) {
                return HI_FAIL;
            }
        } else {
            /* Set Address3 field in the WLAN Header with the source address */
            if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_saddr, WLAN_MAC_ADDR_LEN) !=
                EOK) {
                return HI_FAIL;
            }
        }
    } else {
        /* From DS��ʶλ���� */
        mac_hdr_set_from_ds((hi_u8 *)hdr, 1);
        /* to DS��ʶλ���� */
        mac_hdr_set_to_ds((hi_u8 *)hdr, 0);
        /* Set Address2 field in the WLAN Header with the BSSID */
        if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
        /* AMSDU�������ַ3��дBSSID */
        if (tx_ctl->is_amsdu) {
            /* Set Address3 field in the WLAN Header with the BSSID */
            if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) !=
                EOK) {
                return HI_FAIL;
            }
        } else {
            /* Set Address3 field in the WLAN Header with the source address */
            if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_saddr, WLAN_MAC_ADDR_LEN) !=
                EOK) {
                return HI_FAIL;
            }
        }
    }

    /* Set Address1 field in the WLAN Header with destination address */
    if (memcpy_s(hdr->auc_address1, WLAN_MAC_ADDR_LEN,  set_addresses_info->puc_daddr, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : staģʽ����MACͷ��ַ
*****************************************************************************/
static hi_u32 hmac_tx_sta_set_addresses(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
                                        const hmac_tx_ctl_stru *tx_ctl, mac_ieee80211_frame_addr4_stru *hdr,
                                        const hmac_set_addresses_info_stru *set_addresses_info)
{
    /* From DS��ʶλ���� */
    mac_hdr_set_from_ds((hi_u8 *)hdr, 0);
    /* to DS��ʶλ���� */
    mac_hdr_set_to_ds((hi_u8 *)hdr, 1);
    /* Set Address1 field in the WLAN Header with BSSID */
    if (memcpy_s(hdr->auc_address1, WLAN_MAC_ADDR_LEN,
                 hmac_user->base_user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }
    if (set_addresses_info->us_ether_type == hi_swap_byteorder_16(ETHER_LLTD_TYPE)) {
        /* Set Address2 field in the WLAN Header with the source address */
        if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_saddr, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
    } else {
        /* Set Address2 field in the WLAN Header with the source address */
        if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN,
            hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id,
            WLAN_MAC_ADDR_LEN) != EOK) {
            return HI_FAIL;
        }
    }
    if (tx_ctl->is_amsdu) /* AMSDU�������ַ3��дBSSID */ {
        /* Set Address3 field in the WLAN Header with the BSSID */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN,
            hmac_user->base_user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            return HI_FAIL;
        }
    } else {
        /* Set Address3 field in the WLAN Header with the destination address */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_daddr, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : 4��ַwdsģʽ����MACͷ��ַ
*****************************************************************************/
static hi_u32 hmac_tx_wds_set_addresses(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
                                        const hmac_tx_ctl_stru *tx_ctl, mac_ieee80211_frame_addr4_stru *hdr,
                                        const hmac_set_addresses_info_stru *set_addresses_info)
{
    /* TO DS��ʶλ���� */
    mac_hdr_set_to_ds((hi_u8 *)hdr, 1);
    /* From DS��ʶλ���� */
    mac_hdr_set_from_ds((hi_u8 *)hdr, 1);
    /* ��ַ1�� RA */
    if (memcpy_s(hdr->auc_address1, WLAN_MAC_ADDR_LEN,
                 hmac_user->base_user->user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }
    /* ��ַ2�� TA (��ǰֻ��BSSID) */
    if (memcpy_s(hdr->auc_address2, WLAN_MAC_ADDR_LEN,
                 hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }

    /* AMSDU�������ַ3�͵�ַ4��дBSSID */
    if (tx_ctl->is_amsdu) {
        /* ��ַ3�� BSSID */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }

        /* ��ַ4Ҳ�� BSSID */
        if (memcpy_s(hdr->auc_address4, WLAN_MAC_ADDR_LEN, hmac_vap->base_vap->auc_bssid, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
    } else {
        /* ��ַ3�� DA */
        if (memcpy_s(hdr->auc_address3, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_daddr, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
        /* ��ַ4�� SA */
        if (memcpy_s(hdr->auc_address4, WLAN_MAC_ADDR_LEN, set_addresses_info->puc_saddr, WLAN_MAC_ADDR_LEN) !=
            EOK) {
            return HI_FAIL;
        }
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����֡��ַ����
 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_tx_set_addresses(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
                                    const hmac_tx_ctl_stru *tx_ctl, mac_ieee80211_frame_addr4_stru *hdr,
                                    const hmac_set_addresses_info_stru *set_addresses_info)
{
    /* ��Ƭ���ó�0��������Ƭ������Ҫ���¸�ֵ */
    hdr->frag_num    = 0;
    hdr->seq_num     = 0;

    /* From AP */
    if ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) && (!(tx_ctl->use_4_addr))) {
        return hmac_tx_ap_set_addresses(hmac_vap, tx_ctl, hdr, set_addresses_info);
#ifdef _PRE_WLAN_FEATURE_MESH
    } else if ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) && (!(tx_ctl->use_4_addr))) {
        return hmac_tx_mesh_set_addresses(hmac_vap, hmac_user, tx_ctl, hdr, set_addresses_info);
#endif
    } else if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        return hmac_tx_sta_set_addresses(hmac_vap, hmac_user, tx_ctl, hdr, set_addresses_info);
    } else {  /* WDS */
        return hmac_tx_wds_set_addresses(hmac_vap, hmac_user, tx_ctl, hdr, set_addresses_info);
    }
}

/*****************************************************************************
 �� �� ��  : hmac_tx_encap
 ��������  : 802.11֡ͷ��װ APģʽ
 �������  : pst_vap��vap�ṹ��
             pst_user���û��ṹ��
             pst_buf��BUF�ṹ��
 �������  : pst_ret_hdr�����ص�ͷ��
 �� �� ֵ  : HI_NULL ���� 802.11֡ͷָ��
 ���ú���  : AMSDUģ���Լ����ļ�
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
/* ��̹淶����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������: ֡��װ���������ܾۺ��������������� */
hi_u32 hmac_tx_encap(const hmac_vap_stru    *hmac_vap,
                     const hmac_user_stru   *hmac_user,
                     oal_netbuf_stru  *netbuf)
{
    mac_ieee80211_qos_frame_addr4_stru       *hdr = HI_NULL;             /* 802.11ͷ */
    mac_ieee80211_qos_htc_frame_addr4_stru   *hdr_max = HI_NULL;         /* ����802.11ͷ������ռ�ʹ�� */
    hi_u32                                   qos = HMAC_TX_BSS_NOQOS;
    hi_u16                                   us_ether_type = 0;
    hi_u8                                    auc_saddr[ETHER_ADDR_LEN];   /* ԭ��ַָ�� */
    hi_u8                                    auc_daddr[ETHER_ADDR_LEN];   /* Ŀ�ĵ�ַָ�� */
    hi_u32                                   ret;
    hmac_set_addresses_info_stru             set_addresses_info;

    /* ��ȡCB */
    hmac_tx_ctl_stru                         *tx_ctl = (hmac_tx_ctl_stru *)(oal_netbuf_cb(netbuf));

    /* ���ӳ���У�� ��ֹ�ϲ��·������쳣�ı��� */
    if (oal_netbuf_len(netbuf) < sizeof(mac_ether_header_stru)) {
        oam_error_log1(0, 0, "{hmac_tx_encap::netbuff len is invalid: %d!}", oal_netbuf_len(netbuf));
        return HI_FAIL;
    }
    /* ��ȡ��̫��ͷ, ԭ��ַ��Ŀ�ĵ�ַ, ��̫������ */
    mac_ether_header_stru *ether_hdr = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
    if (memcpy_s((hi_u8 *)auc_daddr, ETHER_ADDR_LEN, ether_hdr->auc_ether_dhost, ETHER_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }
    if (memcpy_s((hi_u8 *)auc_saddr, ETHER_ADDR_LEN, ether_hdr->auc_ether_shost, ETHER_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }

    /* ���skb��dataָ��ǰԤ���Ŀռ����802.11 mac head len������Ҫ���������ڴ���802.11ͷ */
    if (oal_netbuf_headroom(netbuf) >=  MAC_80211_QOS_HTC_4ADDR_FRAME_LEN) {
        tx_ctl->mac_head_type = 1;  /* ָʾmacͷ����skb�� */
    } else {
        /* ��������80211ͷ */
        hdr_max = (mac_ieee80211_qos_htc_frame_addr4_stru *)oal_memalloc(MAC_80211_QOS_HTC_4ADDR_FRAME_LEN);
        if (oal_unlikely(hdr_max == HI_NULL)) {
            oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_TX, "{hmac_tx_encap::pst_hdr null.}");
            return HI_ERR_CODE_PTR_NULL;
        }

        hdr = (mac_ieee80211_qos_frame_addr4_stru *)hdr_max;
        tx_ctl->mac_head_type = 0;  /* ָʾmacͷ������skb�У������˶����ڴ��ŵ� */
    }

    /* ��amsdu֡ */
    if (tx_ctl->is_amsdu == HI_FALSE) {
        us_ether_type = ether_hdr->us_ether_type;
    } else {
       /* �����AMSDU�ĵ�һ����֡����Ҫ��snapͷ�л�ȡ��̫�����ͣ��������̫��֡������
          ֱ�Ӵ���̫��ͷ�л�ȡ */
        mac_llc_snap_stru *snap_hdr  = (mac_llc_snap_stru *)((hi_u8 *)ether_hdr + ETHER_HDR_LEN);
        us_ether_type = snap_hdr->us_ether_type;
    }

    /* ���鲥֡����ȡ�û���QOS����λ��Ϣ */
    if (tx_ctl->ismcast == HI_FALSE) {
        /* �����û��ṹ���cap_info���ж��Ƿ���QOSվ�� */
        qos                      = hmac_user->base_user->cap_info.qos;
        tx_ctl->is_qosdata   = hmac_user->base_user->cap_info.qos;
    }

    /* ����LAN to WLAN�ķ�AMSDU�ۺ�֡�����LLC SNAPͷ */
    if (tx_ctl->is_amsdu == HI_FALSE) {
        mac_set_snap(netbuf, us_ether_type, (ETHER_HDR_LEN - SNAP_LLC_FRAME_LEN));
        /* ����frame���� */
        tx_ctl->us_mpdu_len = (hi_u16) oal_netbuf_len(netbuf);

        /* ��amsdu�ۺ�֡����¼mpdu�ֽ�����������snap */
        tx_ctl->us_mpdu_bytes = (hi_u16)(tx_ctl->us_mpdu_len - SNAP_LLC_FRAME_LEN);
    }

    tx_ctl->frame_header_length = hmac_get_frame_header_len(qos, tx_ctl);

    /* macͷ����skb��ʱ��netbuf��dataָ��ָ��macͷ������mac_set_snap�������Ѿ���dataָ��ָ����llcͷ��
       �������Ҫ����push��macͷ��  */
    if (tx_ctl->mac_head_type == 1) {
        oal_netbuf_push(netbuf, tx_ctl->frame_header_length);
        hdr = (mac_ieee80211_qos_frame_addr4_stru *)oal_netbuf_data(netbuf);
    }

    /* ����֡���� */
    hmac_tx_set_frame_ctrl(qos, tx_ctl, hdr);

    /* ���õ�ַ */
    set_addresses_info.puc_saddr = auc_saddr;
    set_addresses_info.puc_daddr = auc_daddr;
    set_addresses_info.us_ether_type = us_ether_type;
    ret = hmac_tx_set_addresses(hmac_vap, hmac_user, tx_ctl, (mac_ieee80211_frame_addr4_stru *)hdr,
        &set_addresses_info);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        if (tx_ctl->mac_head_type == 0) {
            oal_free(hdr_max);
        }
        oam_error_log1(hmac_vap->base_vap->vap_id, OAM_SF_TX,
            "{hmac_tx_encap::hmac_tx_set_addresses failed[%d].}", ret);
        return ret;
    }

    /* �ҽ�802.11ͷ */
    tx_ctl->frame_header = (mac_ieee80211_frame_stru *)hdr;
    /* �Է�Qos ֡���� ���seq num��ά����DTS2014082610148 */
    /* ��Ƭ���� */
    if (HI_TRUE == hmac_tx_is_need_frag(hmac_vap, hmac_user, netbuf, tx_ctl)) {
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC != _PRE_MULTI_CORE_MODE)
        hmac_nonqos_frame_set_sn(tx_ctl);
#endif
        ret = hmac_frag_process_proc(hmac_vap, hmac_user, netbuf, tx_ctl);
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_mpdu_process
 ��������  : ����MPDU������
 �������  : pst_event���¼��ṹ��
             pst_vap��vap�ṹ��
             pst_buf��BUF�ṹ��
             pst_tx_ctl��CB�ṹ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hmac_tx_return_type_enum_uint8 hmac_tx_lan_mpdu_process_sta(hmac_vap_stru *hmac_vap,
                                                                   oal_netbuf_stru *netbuf,
                                                                   hmac_tx_ctl_stru *tx_ctl)
{
    hmac_user_stru                  *hmac_user = HI_NULL;      /* Ŀ��STA�ṹ�� */
    mac_ether_header_stru           *ether_hdr = HI_NULL; /* ��̫��ͷ */
    hi_u32                           ret;
    hmac_tx_return_type_enum_uint8   hmac_tx_ret;
    hi_u8                            user_idx;
    hi_u8                           *puc_ether_payload = HI_NULL;

    ether_hdr  = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
    tx_ctl->tx_vap_index = hmac_vap->base_vap->vap_id;

    user_idx = hmac_vap->base_vap->assoc_vap_id;

    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
    if (hmac_user == HI_NULL) {
        return HMAC_TX_DROP_USER_NULL;
    }

    if (hi_swap_byteorder_16(ETHER_TYPE_ARP) == ether_hdr->us_ether_type) {
        ether_hdr++;
        puc_ether_payload = (hi_u8 *)ether_hdr;
        /* The source MAC address is modified only if the packet is an   */
        /* ARP Request or a Response. The appropriate bytes are checked. */
        /* Type field (2 bytes): ARP Request (1) or an ARP Response (2)  */
        if ((puc_ether_payload[6] == 0x00) && /* 6 Ԫ������ */
          (puc_ether_payload[7] == 0x02 || puc_ether_payload[7] == 0x01)) { /* 7 Ԫ������ */
            /* Set Address2 field in the WLAN Header with source address */
            if (memcpy_s(puc_ether_payload + 8, WLAN_MAC_ADDR_LEN, /* 8 ƫ���� */
                hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id,
                WLAN_MAC_ADDR_LEN) != EOK) {
                return HMAC_TX_DROP_80211_ENCAP_FAIL;
            }
        }
    }

    tx_ctl->us_tx_user_idx = user_idx;

    hmac_tx_ret = hmac_tx_ucast_process(hmac_vap, netbuf, hmac_user, tx_ctl);
    if (oal_unlikely(hmac_tx_ret != HMAC_TX_PASS)) {
        return hmac_tx_ret;
    }

    /* ��װ802.11ͷ */
    ret = hmac_tx_encap(hmac_vap, hmac_user, netbuf);
    if (oal_unlikely((ret != HI_SUCCESS))) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_TX,
            "{hmac_tx_lan_mpdu_process_sta::hmac_tx_encap failed[%d].}", ret);
        return HMAC_TX_DROP_80211_ENCAP_FAIL;
    }

    return HMAC_TX_PASS;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_mpdu_process
 ��������  : ����MPDU������
 �������  : pst_event���¼��ṹ��
             pst_vap��vap�ṹ��
             pst_buf��BUF�ṹ��
             pst_tx_ctl��CB�ṹ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hmac_tx_return_type_enum_uint8 hmac_tx_lan_mpdu_process_ap(hmac_vap_stru *hmac_vap,
                                                                  oal_netbuf_stru *netbuf,
                                                                  hmac_tx_ctl_stru *tx_ctl)
{
    hmac_user_stru *hmac_user = HI_NULL;      /* Ŀ��STA�ṹ�� */
    hi_u8           user_idx = 0;

    /* �ж����鲥�򵥲�,����lan to wlan�ĵ���֡��������̫����ַ */
    mac_ether_header_stru *ether_hdr = (mac_ether_header_stru *)oal_netbuf_data(netbuf);
    hi_u8                 *mac_addr = ether_hdr->auc_ether_dhost; /* Ŀ�ĵ�ַ */

    /* ��������֡ */
    if (oal_likely(!ether_is_multicast(mac_addr))) {
        hi_u32 ret = mac_vap_find_user_by_macaddr(hmac_vap->base_vap, mac_addr, ETHER_ADDR_LEN, &user_idx);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_info_log3(hmac_vap->base_vap->vap_id, OAM_SF_TX,
                "{hmac_tx_lan_mpdu_process_ap::hmac_tx_find_user failed xx:xx:xx:%2x:%2x:%2x}",
                mac_addr[3], mac_addr[4], mac_addr[5]); /* 3 4 5 Ԫ������ */
            return HMAC_TX_DROP_USER_UNKNOWN;
        }

        /* ת��HMAC��USER�ṹ�� */
        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(user_idx);
        if (oal_unlikely((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL))) {
            return HMAC_TX_DROP_USER_NULL;
        }

        /* �û�״̬�ж� */
        if (oal_unlikely(hmac_user->base_user->user_asoc_state != MAC_USER_STATE_ASSOC)) {
            return HMAC_TX_DROP_USER_INACTIVE;
        }

        /* Ŀ��userָ�� */
        tx_ctl->us_tx_user_idx = user_idx;

        hmac_tx_return_type_enum_uint8 hmac_tx_ret = hmac_tx_ucast_process(hmac_vap, netbuf, hmac_user, tx_ctl);
        if (oal_unlikely(hmac_tx_ret != HMAC_TX_PASS)) {
            return hmac_tx_ret;
        }
    } else { /* �鲥 or �㲥 */
        /* �����鲥��ʶλ */
        tx_ctl->ismcast = HI_TRUE;

        /* ����ACK���� */
        tx_ctl->ack_policy = WLAN_TX_NO_ACK;

        /* ��ȡ�鲥�û� */
        hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(hmac_vap->base_vap->multi_user_idx);
        if (oal_unlikely(hmac_user == HI_NULL)) {
            oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_TX,
                             "{hmac_tx_lan_mpdu_process_ap::get multi user failed[%d].}",
                             hmac_vap->base_vap->multi_user_idx);
            return HMAC_TX_DROP_MUSER_NULL;
        }

        tx_ctl->us_tx_user_idx = hmac_vap->base_vap->multi_user_idx;
        tx_ctl->tid  = WLAN_TIDNO_BCAST;
        tx_ctl->ac   = wlan_wme_tid_to_ac(tx_ctl->tid);
    }

    /* ��װ802.11ͷ */
    hi_u32 rst = hmac_tx_encap(hmac_vap, hmac_user, netbuf);
    if (oal_unlikely((rst != HI_SUCCESS))) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_TX,
            "{hmac_tx_lan_mpdu_process_ap::hmac_tx_encap failed[%d].}", rst);
        return HMAC_TX_DROP_80211_ENCAP_FAIL;
    }

    return HMAC_TX_PASS;
}

static hi_u32 hmac_tx_lan_to_wlan_no_tcp_opt_vap(const mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf,
    hmac_vap_stru *hmac_vap, hmac_tx_ctl_stru **tx_ctl_ptr, hmac_tx_return_type_enum_uint8* hmac_tx_ret)
{
    hmac_tx_ctl_stru *tx_ctl = *tx_ctl_ptr;
    if ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        || (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
    ) {
        /*  ����ǰ MPDU */
        if (mac_vap->mib_info->wlan_mib_sta_config.dot11_qos_option_implemented == HI_FALSE) {
            tx_ctl->ac                     = WLAN_WME_AC_VO;            /* APģʽ ��WMM ��VO���� */
            tx_ctl->tid =  wlan_wme_ac_to_tid(tx_ctl->ac);
        }

        *hmac_tx_ret = hmac_tx_lan_mpdu_process_ap(hmac_vap, netbuf, tx_ctl);
    } else if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        /* ����ǰMPDU */
        /* DTS2014060507028 */
        tx_ctl->ac                     = WLAN_WME_AC_VO;                  /* STAģʽ ��qos֡��VO���� */
        /* DTS2015012401608, AC��tid����Ҫ����һ�� */
        tx_ctl->tid =  wlan_wme_ac_to_tid(tx_ctl->ac);

        *hmac_tx_ret = hmac_tx_lan_mpdu_process_sta(hmac_vap, netbuf, tx_ctl);
#ifdef _PRE_WLAN_FEATURE_WAPI
        if (*hmac_tx_ret == HMAC_TX_PASS) {
            hmac_user_stru *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(mac_vap->assoc_vap_id);
            if ((hmac_user == HI_NULL) || (hmac_user->base_user == HI_NULL)) {
                oam_warning_log1(0, 0, "hmac_tx_lan_to_wlan_no_tcp_opt_vap::usrid==%u !}", mac_vap->assoc_vap_id);
                return HMAC_TX_DROP_USER_NULL;
            }

            /* ��ȡwapi���� �鲥/���� */
            mac_ieee80211_frame_stru *mac_hdr = ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf))->frame_header;
            hi_bool pairwise = !ether_is_multicast(mac_hdr->auc_address1);
            hmac_wapi_stru *wapi = hmac_user_get_wapi_ptr(mac_vap, pairwise, (hi_u8)hmac_user->base_user->us_assoc_id);
            if (wapi == HI_NULL) {
                oam_error_log0(0, 0, "{hmac_tx_lan_to_wlan_no_tcp_opt_vap::pst_wapi null.}");
                return HI_FAIL;
            }
            if ((wapi_is_port_valid(wapi) == HI_TRUE) && (wapi->wapi_netbuff_txhandle != HI_NULL)) {
                netbuf = wapi->wapi_netbuff_txhandle(wapi, netbuf);
                /*  ����wapi�����޸�netbuff���˴���Ҫ���»�ȡһ��cb */
                tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
                *tx_ctl_ptr = tx_ctl;
            }
        }

#endif /* #ifdef _PRE_WLAN_FEATURE_WAPI */
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_tx_lan_to_wlan_no_tcp_opt_vap_mode(mac_vap_stru *mac_vap, const hmac_vap_stru *hmac_vap)
{
    /* VAPģʽ�ж� */
    if (mac_vap->vap_mode != WLAN_VAP_MODE_BSS_AP && mac_vap->vap_mode != WLAN_VAP_MODE_BSS_STA
#ifdef _PRE_WLAN_FEATURE_MESH
    && (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)
#endif
    ) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_TX, "{hmac_tx_lan_to_wlan_no_tcp_opt_vap_mode::en_vap_mode=%d.}",
            mac_vap->vap_mode);
        return HI_ERR_CODE_CONFIG_UNSUPPORT;
    }

    /* ��������û�����Ϊ0���������� */
    if (oal_unlikely(hmac_vap->base_vap->user_nums == 0)) {
        return HI_FAIL;
    }
#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
    /* �����ݣ�ֻ��һ�Σ����ⷴ������tx��������ַ */
    if (mac_vap->al_tx_flag == HI_SWITCH_ON) {
        if (mac_vap->first_run != HI_FALSE) {
            return HI_SUCCESS;
        }
        mac_vap_set_al_tx_first_run(mac_vap, HI_TRUE);
    }
#endif

    return HI_CONTINUE;
}

static hi_u32 hmac_tx_lan_to_wlan_no_tcp_opt_to_dmac(const mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf,
    const hmac_tx_ctl_stru *tx_ctl, hmac_tx_return_type_enum_uint8 hmac_tx_ret)
{
    hi_u32 ret = (hi_u32)hmac_tx_ret;

    if (oal_likely(hmac_tx_ret == HMAC_TX_PASS)) {
        /* ���¼�������DMAC */
        frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(dmac_tx_event_stru));
        if (oal_unlikely(event_mem == HI_NULL)) {
            oam_error_log0(0, OAM_SF_TX, "{hmac_tx_lan_to_wlan_no_tcp_opt_to_dmac::frw_event_alloc failed.}");
            return HI_ERR_CODE_ALLOC_MEM_FAIL;
        }

        frw_event_stru *event = (frw_event_stru *)event_mem->puc_data; /* �¼��ṹ�� */

        /* ��д�¼�ͷ */
        frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_HOST_DRX, DMAC_TX_HOST_DRX,
            sizeof(dmac_tx_event_stru), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);

        dmac_tx_event_stru *dtx_stru = (dmac_tx_event_stru *)event->auc_event_data;
        dtx_stru->netbuf = netbuf;
        dtx_stru->us_frame_len = tx_ctl->us_mpdu_len;

        /* �����¼� */
        ret = hcc_hmac_tx_data_event(event_mem, netbuf, HI_FALSE);
         /* �ͷ��¼� */
        frw_event_free(event_mem);
    } else if ((oal_unlikely(hmac_tx_ret == HMAC_TX_BUFF)) || (hmac_tx_ret == HMAC_TX_DONE)) {
        hmac_free_netbuf_list(netbuf);
        ret = HI_SUCCESS;
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_wlan_to_wlan_ap
 ��������  : (1)WLAN TO WLAN����tx��ں���������rx�����׹�����netbuf����netbuf����
             ����ÿһ��netbuf������һ��MSDU��ÿһ��MSDU��������һ����̫����ʽ��
             ֡�������netbuf������һ��netbuf��prevָ��Ϊ�գ����һ��netbuf��
             nextָ��Ϊ�ա�
             (2)����ѭ������LAN TO WLAN����ں���������ÿһ��MSDU�������Ͱ�
             WLAN TO WLAN����ͳһ����LAN TO WLAN����
 �������  : pst_event_mem���¼��ڴ��
 �������  : ��
 �� �� ֵ  : HI_SUCCESS������������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  hmac_tx_wlan_to_wlan_ap(oal_mem_stru *event_mem)
{
    frw_event_stru         *event = HI_NULL;        /* �¼��ṹ�� */
    mac_vap_stru           *mac_vap = HI_NULL;
    oal_netbuf_stru        *netbuf = HI_NULL;          /* ��netbuf����ȡ������ָ��netbuf��ָ�� */
    oal_netbuf_stru        *buf_tmp = HI_NULL;      /* �ݴ�netbufָ�룬����whileѭ�� */
    hmac_tx_ctl_stru       *tx_ctl = HI_NULL;
    hi_u32                  ret;
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_WOW, "{hmac_wow_proc_dev_ready_slp_event::event_mem is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ�¼� */
    event = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡPAYLOAD�е�netbuf�� */
    netbuf = (oal_netbuf_stru *)(*((uintptr_t *)(event->auc_event_data)));

    ret = hmac_tx_get_mac_vap(event->event_hdr.vap_id, &mac_vap);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log1(0, OAM_SF_TX, "{hmac_tx_wlan_to_wlan_ap::hmac_tx_get_mac_vap failed[%d].}", ret);
        hmac_free_netbuf_list(netbuf);
        return ret;
    }

    /* ѭ������ÿһ��netbuf��������̫��֡�ķ�ʽ���� */
    while (netbuf != HI_NULL) {
        buf_tmp = oal_netbuf_next(netbuf);

        oal_netbuf_next(netbuf) = HI_NULL;
        oal_netbuf_prev(netbuf) = HI_NULL;

        /* ���ڴ�netbuf���Խ������̣��Ǵ��ڴ������ģ�����̫��������netbuf�Ǵ�
           ����ϵͳ����ģ����ߵ��ͷŷ�ʽ��һ��������Ҫͨ���¼������ֶ���ѡ����ȷ
           ���ͷŷ�ʽ
        */
        tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
        if (memset_s(tx_ctl, sizeof(hmac_tx_ctl_stru), 0, sizeof(hmac_tx_ctl_stru)) != EOK) {
            hmac_free_netbuf_list(netbuf);
            netbuf = buf_tmp;
            continue;
        }

        tx_ctl->event_type = FRW_EVENT_TYPE_WLAN_DTX;
        tx_ctl->event_sub_type = DMAC_TX_WLAN_DTX;

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
        /* set the queue map id when wlan to wlan */
        oal_skb_set_queue_mapping(netbuf, WLAN_NORMAL_QUEUE);
#endif

        ret = hmac_tx_lan_to_wlan(mac_vap, netbuf);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            hmac_free_netbuf_list(netbuf);
        }
        netbuf = buf_tmp;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : hmac APģʽ ����HOST DRX�¼���ע�ᵽ�¼�����ģ����
             PAYLOAD��һ��NETBUF
 �������  : pst_vap: vapָ��
             pst_buf: netbufָ��
 �� �� ֵ  : HI_SUCCESS������������
*****************************************************************************/
hi_u32 hmac_tx_lan_to_wlan(mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf)
{
    hmac_tx_return_type_enum_uint8 hmac_tx_ret = HMAC_TX_PASS;

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id); /* VAP�ṹ�� */
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(mac_vap->vap_id, OAM_SF_TX, "{hmac_tx_lan_to_wlan::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    hi_u32 ret = hmac_tx_lan_to_wlan_no_tcp_opt_vap_mode(mac_vap, hmac_vap);
    if (ret != HI_CONTINUE) {
        return ret;
    }

    /* ��ʼ��CB tx rx�ֶ� , CB�ֶ���ǰ���Ѿ������㣬 �����ﲻ��Ҫ�ظ���ĳЩ�ֶθ���ֵ */
    hmac_tx_ctl_stru* tx_ctl = (hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf);
    tx_ctl->mpdu_num               = 1;
    tx_ctl->netbuf_num             = 1;
    tx_ctl->frame_type             = WLAN_DATA_BASICTYPE;
    tx_ctl->is_probe_data          = DMAC_USER_ALG_NON_PROBE;
    tx_ctl->ack_policy             = WLAN_TX_NORMAL_ACK;
#ifdef _PRE_WLAN_FEATURE_ALWAYS_TX
    /* ������ʼ����ֵ */
    tx_ctl->ack_policy             = hmac_vap->ack_policy;
#endif
    tx_ctl->tx_vap_index           = mac_vap->vap_id;
    tx_ctl->us_tx_user_idx         = MAC_INVALID_USER_ID;
    tx_ctl->ac                     = WLAN_WME_AC_BE;                  /* ��ʼ����BE���� */

    /* ����LAN TO WLAN��WLAN TO WLAN��netbuf�������������Ϊ�����֣���Ҫ���ж�
       ��������������netbufȻ���ٶ�CB���¼������ֶθ�ֵ
    */
    if (tx_ctl->event_type != FRW_EVENT_TYPE_WLAN_DTX) {
        tx_ctl->event_type          = FRW_EVENT_TYPE_HOST_DRX;
        tx_ctl->event_sub_type      = DMAC_TX_HOST_DRX;
    }

    /* �˴����ݿ��ܴ��ں˶�����Ҳ�п�����dev��������ͨ���տ�ת��ȥ��ע��һ�� */
    hi_u8 data_type =  mac_get_data_type_from_8023((hi_u8 *)oal_netbuf_data(netbuf), MAC_NETBUFF_PAYLOAD_ETH);
    /* ά�⣬���һ���ؼ�֡��ӡ */
    if ((data_type <= MAC_DATA_DHCP_ACK) || (data_type == MAC_DATA_ARP_REQ) ||
        (data_type == MAC_DATA_ARP_RSP) || (data_type == MAC_DATA_EAPOL)) {
        tx_ctl->is_vipframe = HI_TRUE;
        oam_warning_log2(mac_vap->vap_id, OAM_SF_TX,
            "{hmac_tx_lan_to_wlan:type:%u,len:%u}[0~3:dhcp 4:arp_req 5:arp_rsp 6:eapol]",
            data_type, oal_netbuf_len(netbuf));
    }
#ifdef _PRE_WLAN_FEATURE_MESH
    if (data_type == MAC_DATA_RPL) {
        oam_warning_log1(0, OAM_SF_TX, "{hmac_tx_lan_to_wlan:Mesh rpl msg,len=%u}", oal_netbuf_len(netbuf));
    }
#endif

    ret = hmac_tx_lan_to_wlan_no_tcp_opt_vap(mac_vap, netbuf, hmac_vap, &tx_ctl, &hmac_tx_ret);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    return hmac_tx_lan_to_wlan_no_tcp_opt_to_dmac(mac_vap, netbuf, tx_ctl, hmac_tx_ret);
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 �� �� ��  : hmac_unicast_data_tx_event_info
 ��������  : ����dmac�ϱ���������֡������Ϣ,�ϱ�WAL
 �������  : [1]pst_mac_vap
             [2]uc_len
             [3]puc_param
 �� �� ֵ  : hi_u32
*****************************************************************************/
hi_u32  hmac_unicast_data_tx_event_info(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hi_unref_param(len);

    return hmac_send_event_to_host(mac_vap, puc_param,
        sizeof(dmac_tx_info_report_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_TX_DATA_INFO);
}
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
