/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL flow ctrl file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_FLOWCTL

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : wal_netdev_select_queue
 ��������  : kernel��skbѡ����ʵ�tx subqueue;
 �������  :
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��3��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u16  wal_netdev_select_queue(oal_net_device_stru *netdev, oal_netbuf_stru *netbuf, hi_void *accel_priv,
    select_queue_fallback_t fallback)
{
    oal_ether_header_stru   *ether_header   = HI_NULL;
    mac_vap_stru            *mac_vap            = HI_NULL;
    hi_u8                assoc_id        = 0;
    hi_u8                tos             = 0;
    hi_u8                ac;
    hi_u16               us_subq;
    hi_u32               ret;

    /* ��ȡ��̫��ͷ */
    ether_header = (oal_ether_header_stru *)oal_netbuf_data(netbuf);

    mac_vap = (mac_vap_stru *) oal_net_dev_priv(netdev);
    /* û���û����٣���ȫ����index = 0 ��subq, ��ֱ�ӷ��� */
    if (mac_vap->has_user_bw_limit == HI_FALSE) {
        return 0;
    }

    ret = mac_vap_find_user_by_macaddr(mac_vap, ether_header->auc_ether_dhost, ETHER_ADDR_LEN, &assoc_id);
    if (ret != HI_SUCCESS) {
        /* û���ҵ��û��ı��ģ���ͳһ����subq = 0�Ķ����� */
        oam_info_log0(mac_vap->vap_id, OAM_SF_ANY, "{mac_vap_find_user_by_macaddr::failed!}\r\n");
        return 0;
    }

    /* ��ȡskb��tos�ֶ� */
    oal_netbuf_get_txtid(netbuf, &tos);

    /* ����tos�ֶ�ѡ����ʵĶ��� */
    ac = mac_tos_to_subq(tos);

    us_subq = (hi_u16)((assoc_id * WAL_NETDEV_SUBQUEUE_PER_USE) + ac);
    if (us_subq >= WAL_NETDEV_SUBQUEUE_MAX_NUM) {
        return 0;
    }
    return us_subq;
}

/*****************************************************************************
 �� �� ��  : wal_flowctl_backp_event_handler
 ��������  : stop����wakeĳ���û���ĳ��subqueue
 �������  :
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��3��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_flowctl_backp_event_handler(frw_event_mem_stru *event_mem)
{
    frw_event_stru             *event               = (frw_event_stru *)event_mem->puc_data;
    mac_ioctl_queue_backp_stru *flowctl_backp_event = (mac_ioctl_queue_backp_stru *)(event->auc_event_data);
    hi_u8                       vap_id              = flowctl_backp_event->vap_id;

    /* ��ȡnet_device */
    oal_net_device_stru *netdev = hmac_vap_get_net_device(vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(vap_id, OAM_SF_ANY, "{wal_flowctl_backp_event_handler::failed!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���������VAP stop����wake */
    if (flowctl_backp_event->us_assoc_id == 0xFFFF) {
        if (flowctl_backp_event->is_stop == 1) {
            oal_net_tx_stop_all_queues(netdev);
        } else {
            oal_net_tx_wake_all_queues();
        }
        oam_info_log3(vap_id, OAM_SF_ANY,
            "{wal_flowctl_backp_event_handler::oal_net_tx_queues,stop_flag=%d,vap_id=%d,assoc_id=%d,tid=%d}",
            flowctl_backp_event->is_stop, flowctl_backp_event->vap_id, flowctl_backp_event->us_assoc_id,
            flowctl_backp_event->tidno);

        return HI_SUCCESS;
    }

    /* �����ĳ��user stop����wake */
    if (flowctl_backp_event->tidno == WLAN_TID_MAX_NUM) {
        for (hi_u8 ac = 0; ac <= MAC_LINUX_SUBQ_VO; ac++) {
            if (flowctl_backp_event->is_stop == 1) {
                oal_net_stop_subqueue(netdev);
            } else {
                oal_net_wake_subqueue(netdev);
            }
            oam_info_log3(vap_id, OAM_SF_ANY,
                "{wal_flowctl_backp_event_handler::oal_net_subqueue,stop=%d,vap_id=%d,assoc_id=%d,tid=%d}",
                flowctl_backp_event->is_stop, flowctl_backp_event->vap_id, flowctl_backp_event->us_assoc_id,
                flowctl_backp_event->tidno);
        }
        return HI_SUCCESS;
    }

    if (flowctl_backp_event->is_stop == 1) {
        oal_net_stop_subqueue(netdev);
    } else {
        oal_net_wake_subqueue(netdev);
    }
    oam_info_log3(vap_id, OAM_SF_ANY,
        "{wal_flowctl_backp_event_handler::oal_net_subqueue,stop_flag=%d,vap_id=%d,assoc_id=%d,tid=%d}",
        flowctl_backp_event->is_stop, flowctl_backp_event->vap_id, flowctl_backp_event->us_assoc_id,
        flowctl_backp_event->tidno);

    return HI_SUCCESS;
}

#endif /* endif of _PRE_WLAN_FEATURE_FLOWCTL */
#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
/*****************************************************************************
 �� �� ��  : wal_netdev_select_queue
 ��������  : kernel��skbѡ����ʵ�tx subqueue;
 �������  :
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��3��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u16  wal_netdev_select_queue(oal_net_device_stru *netdev, oal_netbuf_stru *netbuf, hi_void *accel_priv,
    select_queue_fallback_t fallback)
{
    return oal_netbuf_select_queue(netbuf);
}

#endif /* endif of _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL */

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

