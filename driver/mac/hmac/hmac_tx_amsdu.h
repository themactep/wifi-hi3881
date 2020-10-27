/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_tx_amsdu.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_TX_AMSDU_H__
#define __HMAC_TX_AMSDU_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_tx_data.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* HT������Ϣ��amsdu����λ */
#define HT_CAP_AMSDU_LEN 0x0800
/* amsdu��������15ms FPGA 1500 */
#define HMAC_AMSDU_LIFE_TIME    15
#define hmac_amsdu_init_msdu_head(_pst_amsdu) \
do { \
    (_pst_amsdu)->msdu_head.next = (oal_netbuf_stru *)&((_pst_amsdu)->msdu_head); \
    (_pst_amsdu)->msdu_head.prev = (oal_netbuf_stru *)&((_pst_amsdu)->msdu_head); \
} while (0)
/* �̰��ۺ������� */
#define HMAC_AMSDU_SHORT_PACKET_NUM     0x02

/*****************************************************************************
 ��������  : ����amsdu��֡������
 �޸���ʷ      :
  1.��    ��   : 2013��2��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void  hmac_amsdu_set_maxnum(hmac_amsdu_stru *amsdu, hi_u8 max_num)
{
    if (max_num > WLAN_AMSDU_MAX_NUM) {
        amsdu->amsdu_maxnum = WLAN_AMSDU_MAX_NUM;
    } else {
        amsdu->amsdu_maxnum = max_num;
    }
}

/*****************************************************************************
  ��������
*****************************************************************************/
hmac_tx_return_type_enum_uint8 hmac_amsdu_notify(hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user,
                                                 oal_netbuf_stru *netbuf);
hi_void hmac_amsdu_mem_free(hmac_user_stru *hmac_user);
hi_void hmac_amsdu_mem_alloc(hmac_user_stru *hmac_user, hi_u8 tid_num, hi_u8 max_num);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_TX_AMSDU_H__ */
