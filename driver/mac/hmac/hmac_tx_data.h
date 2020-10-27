/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_tx_bss_ap.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_TX_DATA_H__
#define __HMAC_TX_DATA_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "mac_frame.h"
#include "dmac_ext_if.h"
#include "hmac_ext_if.h"
#include "hmac_vap.h"
#include "hmac_user.h"
#include "hmac_main.h"
#include "hmac_mgmt_classifier.h"
#include "mac_resource.h"
#include "hmac_config.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* ����������Ϣ�й����Ƿ���QOS������λ */
#define HMAC_CAP_INFO_QOS_MASK 0x0200

#define wlan_tos_to_tid(_tos)   \
    ((((_tos) == 0) || ((_tos) == 3)) ? WLAN_TIDNO_BEST_EFFORT : \
    (((_tos) == 1) || ((_tos) == 2)) ? WLAN_TIDNO_BACKGROUND : \
    (((_tos) == 4) || ((_tos) == 5)) ? WLAN_TIDNO_VIDEO : WLAN_TIDNO_VOICE)

#define WLAN_BA_CNT_INTERVAL 100

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    HMAC_TX_BSS_NOQOS = 0,
    HMAC_TX_BSS_QOS   = 1,

    HMAC_TX_BSS_QOS_BUTT
}hmac_tx_bss_qos_type_enum;

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
typedef struct hmac_set_addresses_info_stru {
    hi_u8 *puc_saddr;
    hi_u8 *puc_daddr;

    hi_u16 us_ether_type;
    hi_u16 us_rsvd;
}hmac_set_addresses_info_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_u32  hmac_tx_wlan_to_wlan_ap(frw_event_mem_stru *event_mem);
hi_u32  hmac_tx_lan_to_wlan(mac_vap_stru *mac_vap, oal_netbuf_stru *netbuf);
#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
hi_u32 hmac_tx_post_event(mac_vap_stru *mac_vap);
hi_u32 hmac_tx_event_process(oal_mem_stru *event_mem);
#endif
hi_u16 hmac_free_netbuf_list(oal_netbuf_stru  *netbuf);
hi_u32 hmac_tx_encap(const hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user, oal_netbuf_stru *netbuf);
hmac_tx_return_type_enum_uint8 hmac_tx_ucast_process(hmac_vap_stru   *hmac_vap, oal_netbuf_stru *netbuf,
    hmac_user_stru  *hmac_user, const hmac_tx_ctl_stru    *tx_ctl);
hi_void  hmac_tx_ba_setup(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user, hi_u8 tidno);

#ifdef _PRE_WLAN_FEATURE_MESH
hi_u32  hmac_unicast_data_tx_event_info(mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param);
#endif
hi_u8 hmac_tx_wmm_acm(hi_u8 wmm, const hmac_vap_stru *hmac_vap, hi_u8 *puc_tid);
hi_u8 hmac_tid_need_ba_session(hmac_vap_stru   *hmac_vap, hmac_user_stru  *hmac_user, hi_u8        tidno,
    const oal_netbuf_stru *netbuf);

/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : hmac_get_frame_header_len
 ��������  : ��ȡ֡ͷ����
*****************************************************************************/
static inline hi_u8 hmac_get_frame_header_len(hi_u32 qos, const hmac_tx_ctl_stru *tx_ctl)
{
    if (qos == HMAC_TX_BSS_QOS) {
        return (tx_ctl->use_4_addr) ? MAC_80211_QOS_4ADDR_FRAME_LEN : MAC_80211_QOS_FRAME_LEN;
    } else {
        return (tx_ctl->use_4_addr) ? MAC_80211_4ADDR_FRAME_LEN : MAC_80211_FRAME_LEN;
    }
}

/*****************************************************************************
 ��������  : �жϸ��û���Ӧ��TID�Ƿ��Ѿ�����BA�Ự
 �� �� ֵ  : HI_TRUE�����Ѿ�������BA�Ự
 �޸���ʷ      :
  1.��    ��   : 2013��4��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 hmac_vap_ba_is_setup(const hmac_user_stru *hmac_user, hi_u8 tidno)
{
    if ((hmac_user->ast_tid_info[tidno].ba_tx_info != HI_NULL) &&
        (hmac_user->ast_tid_info[tidno].ba_tx_info->ba_status == DMAC_BA_COMPLETE)) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_TX_DATA_H__ */
