/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Frame filtering processing file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hmac_rx_filter.h"
#include "wlan_types.h"
#include "mac_device.h"
#include "dmac_ext_if.h"
#include "hcc_hmac_if.h"
#include "frw_event.h"
#include "hmac_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �����Ƿ����Ѿ�UP��STA
 �޸���ʷ      :
  1.��    ��   : 2015��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_find_is_sta_up(const mac_device_stru *mac_dev)
{
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u8 vap_idx;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            continue;
        }
        if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) && (mac_vap->vap_state == MAC_VAP_STATE_UP)) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

/*****************************************************************************
 ��������  : �����Ƿ����Ѿ�UP��AP
 �޸���ʷ      :
  1.��    ��   : 2015��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_find_is_ap_up(const mac_device_stru *mac_dev)
{
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u8 vap_idx;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            continue;
        }
        if ((mac_vap->vap_state != MAC_VAP_STATE_INIT) && (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)) {
            return HI_TRUE;
        }
#ifdef _PRE_WLAN_FEATURE_MESH
        if ((mac_vap->vap_state != MAC_VAP_STATE_INIT) && (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)) {
            return HI_TRUE;
        }
#endif
    }
    return HI_FALSE;
}


/*****************************************************************************
 ��������  : �����Ƿ�������AP
*****************************************************************************/
hi_u8 hmac_find_is_ap(const mac_device_stru *mac_device)
{
    mac_vap_stru *vap = HI_NULL;
    hi_u8 vap_idx;

    for (vap_idx = 0; vap_idx < mac_device->vap_num; vap_idx++) {
        vap = mac_vap_get_vap_stru(mac_device->auc_vap_id[vap_idx]);
        if (vap == HI_NULL) {
            continue;
        }
        if (vap->vap_mode == WLAN_VAP_MODE_BSS_AP) {
            return HI_TRUE;
        }
#ifdef _PRE_WLAN_FEATURE_MESH
        if (vap->vap_mode == WLAN_VAP_MODE_MESH) {
            return HI_TRUE;
        }
#endif
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ���㲻����inti״̬��VAP����
 �޸���ʷ      :
  1.��    ��   : 2014��7��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_calc_up_vap_num(const mac_device_stru *mac_dev)
{
    mac_vap_stru *mac_vap = HI_NULL;
    hi_u8 vap_idx;
    hi_u8 up_ap_num = 0;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            continue;
        }

        if ((mac_vap->vap_state != MAC_VAP_STATE_INIT) && ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
                                                              || (mac_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
            )) {
            up_ap_num++;
        } else if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) && (mac_vap->vap_state == MAC_VAP_STATE_UP)) {
            up_ap_num++;
        }
    }

    return up_ap_num;
}

/*****************************************************************************
 ��������  : ��vapģʽ�¸���ģʽ��״̬��ȡ��Ӧ�Ľ��չ���ֵ
 �޸���ʷ      :
  1.��    ��   : 2019��6��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
 *****************************************************************************/
/********************************************** SINGLE VAP ******************************************************
    WLAN_VAP_MODE_CONFIG  ����ģʽ                        WLAN_VAP_MODE_BSS_STA              BSS STAģʽ
  +-----------------------------+-----------------+      +----------------------------------+-----------------+
  | FSM State                   | RX FILTER VALUE |      | FSM State                        | RX FILTER VALUE |
  +-----------------------------+-----------------+      +----------------------------------+-----------------+
  | All states                  | 0x37BDEEFA      |      | MAC_VAP_STATE_INIT               | 0x37BDEEFA      |
  +-----------------------------+----- -----------+      | MAC_VAP_STATE_UP                 | 0x37BDEADA      |
                                                         | MAC_VAP_STATE_STA_FAKE_UP        | 0x37BDEEFA      |
   WLAN_VAP_MODE_BSS_AP             BSS APģʽ           | MAC_VAP_STATE_STA_WAIT_SCAN      | 0x37BDCEEA      |
  +-----------------------------+-----------------+      | MAC_VAP_STATE_STA_SCAN_COMP      | 0x37BDEEDA      |
  | FSM State                   | RX FILTER VALUE |      | MAC_VAP_STATE_STA_WAIT_JOIN      | 0x37BDEEDA      |
  +-----------------------------+-----------------+      | MAC_VAP_STATE_STA_JOIN_COMP      | 0x37BDEEDA      |
  | MAC_VAP_STATE_INIT          | 0xF7B9EEFA      |      | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2 | 0x37BDEEDA      |
  | MAC_VAP_STATE_UP            | 0x73B9EAEA      |      | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4 | 0x37BDEEDA      |
  | MAC_VAP_STATE_PAUSE         | 0x73B9EAEA      |      | MAC_VAP_STATE_STA_AUTH_COMP      | 0x37BDEEDA      |
  | MAC_VAP_STATE_AP_WAIT_START | 0x73B9EAEA      |      | MAC_VAP_STATE_STA_WAIT_ASOC      | 0x37BDEEDA      |
  +-----------------------------+-----------------+      | MAC_VAP_STATE_STA_OBSS_SCAN      | 0x37BDCEEA      |
                                                         | MAC_VAP_STATE_STA_BG_SCAN        | 0x37BDCEEA      |
   WLAN_VAP_MODE_MONITOER           ����ģʽ             | MAC_VAP_STATE_STA_LISTEN         | 0x33A9EECA      |
  +-----------------------------+-----------------+      +----------------------------------+-----------------+
  | FSM State                   | RX FILTER VALUE |
  +-----------------------------+-----------------+
  | all status                  | 0x1             |
  +-----------------------------+-----------------+
*********************************************** MULTI  VAP *****************************************************/
hi_u32 hmac_get_single_vap_rx_filter(const mac_vap_stru *mac_vap)
{
    hi_u32  def_value = (BIT0 << 21);          /* Ĭ�Ͽ���FCS ERROR���� 21: ����21λ */

    if (mac_vap->vap_mode == WLAN_VAP_MODE_CONFIG) {
        return 0x37B9FEFA;                      /* ����vap��ʹ��0x37B9FEFA */
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        switch (mac_vap->vap_state) {    /* STA��״̬�µĹ��˼Ĵ������� */
            case MAC_VAP_STATE_INIT:
            case MAC_VAP_STATE_STA_FAKE_UP:
                return 0xF7B9FEFA;
            case MAC_VAP_STATE_STA_WAIT_SCAN:
                return 0x37B9DECA;
            case MAC_VAP_STATE_STA_OBSS_SCAN:
            case MAC_VAP_STATE_STA_BG_SCAN:
                return 0x37B9DEEA;
            case MAC_VAP_STATE_STA_LISTEN:
                return 0x33A9FECA;
            default :
                return 0x73B9FADA;
        }
    } else if (is_ap(mac_vap)) {
        switch (mac_vap->vap_state) {    /* AP�Լ�MESH AP��״̬�µĹ��˼Ĵ������� */
            case MAC_VAP_STATE_INIT:
                return 0xF7B9FEFA;
            case MAC_VAP_STATE_UP:
                return 0xF7B9FAEA;
            case MAC_VAP_STATE_PAUSE:
            case MAC_VAP_STATE_AP_WAIT_START:
                return 0x73B9FAEA;
            default :                           /* AP���쳣״̬����Ĭ��ֵ */
                return def_value;
        }
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_MONITOER) {
        return def_value | BIT0;             /* ����ģʽ��Ҫ��BIT0 ��FCS ERROR */
    } else {
        return def_value;                    /* ����ģʽ�¾�����Ĭ��ֵ */
    }
}

/*****************************************************************************
 ��������  : �����Ѿ�UP��STA����ǰ��vapģʽΪAP/MESHʱ��������״̬��ȡ��Ӧ�Ľ��չ���ֵ
       WLAN_VAP_MODE_BSS_AP/MESH               BSS APģʽ              BSS MESHģʽ
     +----------------------------------+--------------------------+--------------------------+
     | FSM State                        | RX FILTER VALUE          | RX FILTER VALUE          |
     +----------------------------------+--------------------------+--------------------------+
     | MAC_VAP_STATE_INIT               | ����ԭ��ֵ������         | ����ԭ��ֵ������         |
     | MAC_VAP_STATE_UP                 | 0x73B9EACA               | 0x73B9EADA               |
     | MAC_VAP_STATE_PAUSE              | 0x73B9EACA               | 0x73B9EADA               |
     | MAC_VAP_STATE_AP_WAIT_START      | 0x73B9EACA               | 0x73B9EADA               |
     +----------------------------------+--------------------------+--------------------------+
 �޸���ʷ      :
  1.��    ��   : 2019��6��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_staup_ap_rx_filter(const mac_vap_stru *mac_vap)
{
    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_INIT:
            return 0;
        default :
            return 0x73B9FACA;
    }
}

/*****************************************************************************
 ��������  : �����Ѿ�UP��STA����ǰ��vapģʽΪSTAʱ��������״̬��ȡ��Ӧ�Ľ��չ���ֵ
    /  ��STAģʽ    WLAN_VAP_MODE_BSS_STA          BSS STAģʽ        /
    / +----------------------------------+--------------------------+ /
    / | FSM State                        | RX FILTER VALUE          | /
    / +----------------------------------+--------------------------+ /
    / | MAC_VAP_STATE_STA_WAIT_SCAN      | 0x33B9CACA               | /
    / | MAC_VAP_STATE_STA_OBSS_SCAN      | 0x33B9CACA               | /
    / | MAC_VAP_STATE_STA_BG_SCAN        | 0x33B9CACA               | /
    / | MAC_VAP_STATE_STA_LISTEN         | 0x33A9EACA               | /
    / | ALL OTHER STATE                  | 0x73B9EADA               | /
    / +----------------------------------+--------------------------+ /
 �޸���ʷ:
  1.��    ��   : 2019��6��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_staup_sta_rx_filter(const mac_vap_stru *mac_vap)
{
    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_STA_WAIT_SCAN:
        case MAC_VAP_STATE_STA_OBSS_SCAN:
        case MAC_VAP_STATE_STA_BG_SCAN:
            return 0x33B9DACA;
        case MAC_VAP_STATE_STA_LISTEN:
            return 0x33A9FACA;
        default:
            return 0x73B9FADA;
    }
}

/*****************************************************************************
 ��������  : �����Ѿ�UP��AP����ǰ��vapģʽΪSTAʱ��������״̬��ȡ��Ӧ�Ľ��չ���ֵ
    / ��AP UPʱ,STA���ó���:  WLAN_VAP_MODE_BSS_STA   BSS STAģʽ     /
    / +----------------------------------+--------------------------+ /
    / | FSM State                        | RX FILTER VALUE          | /
    / +----------------------------------+--------------------------+ /
    / | MAC_VAP_STATE_INIT               | ����ԭ��ֵ������         | /
    / | MAC_VAP_STATE_UP                 | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_FAKE_UP        | ����ԭ��ֵ������         | /
    / | MAC_VAP_STATE_STA_WAIT_SCAN      | 0x33B9CACA               | /
    / | MAC_VAP_STATE_STA_SCAN_COMP      | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_WAIT_JOIN      | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_JOIN_COMP      | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ2 | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_WAIT_AUTH_SEQ4 | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_AUTH_COMP      | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_WAIT_ASOC      | 0x73B9FACA               | /
    / | MAC_VAP_STATE_STA_OBSS_SCAN      | 0x33B9CACA               | /
    / | MAC_VAP_STATE_STA_BG_SCAN        | 0x33B9CACA               | /
    / | MAC_VAP_STATE_STA_LISTEN         | 0x33A9EACA               | /
    / +----------------------------------+--------------------------+ /
 �޸���ʷ:
  1.��    ��   : 2019��6��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_get_apup_sta_rx_filter(const mac_vap_stru *mac_vap)
{
    switch (mac_vap->vap_state) {
        case MAC_VAP_STATE_STA_WAIT_SCAN:
        case MAC_VAP_STATE_STA_OBSS_SCAN:
        case MAC_VAP_STATE_STA_BG_SCAN:
            return 0x33B9DACA;
        case MAC_VAP_STATE_STA_LISTEN:
            return 0x33A9FACA;
        case MAC_VAP_STATE_INIT:
        case MAC_VAP_STATE_STA_FAKE_UP:
            return 0;
        default :
            return 0x73B9FACA;
    }
}

#ifndef _PRE_WLAN_PHY_PERFORMANCE
hi_u32 hmac_send_rx_filter_event(const mac_vap_stru *mac_vap, hi_u32 rx_filter_val)
{
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_set_rx_filter_value::hmac_vap is null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if ((hmac_vap->hmac_al_rx_flag == HI_TRUE) && (hmac_vap->mac_filter_flag == HI_FALSE)) {
        /* ���չرչ��� */
        rx_filter_val |= (BIT0);
    }

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifdef _PRE_WLAN_FEATURE_PROMIS
    if (mac_res_get_dev()->promis_switch) {
        hi_u32 filter = hwal_get_promis_filter();
        if ((filter & 0x1) == HI_TRUE) {        /* bit 0 :�ϱ��鲥(�㲥)����֡ʹ�ܱ�־ */
            rx_filter_val = rx_filter_val & (~BIT3) & (~BIT12);
        }
        if (((filter >> 1) & 0x1) == HI_TRUE) { /* bit 1 :�ϱ��������ݰ�ʹ�ܱ�־ */
            rx_filter_val = rx_filter_val & (~BIT11);
        }
        if (((filter >> 2) & 0x1) == HI_TRUE) { /* bit 2 :�ϱ��鲥(�㲥)����֡ʹ�ܱ�־ */
            rx_filter_val = rx_filter_val & (~BIT4);
        }
        if (((filter >> 3) & 0x1) == HI_TRUE) { /* bit 3 :�ϱ���������֡ʹ�ܱ�־ */
            rx_filter_val = rx_filter_val & (~BIT13);
        }
    }
#endif
#endif

    /* ���¼���DMAC, �����¼��ڴ� */
    frw_event_mem_stru *event_mem = frw_event_alloc(sizeof(hi_u32));
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_set_rx_filter_value::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_SET_RX_FILTER,
                       sizeof(hi_u32), FRW_EVENT_PIPELINE_STAGE_1, mac_vap->vap_id);
    /* �������� */
    hi_u32 *event_data = (hi_u32 *)((hi_void *)event->auc_event_data);
    *event_data = rx_filter_val;

    if (hcc_hmac_tx_control_event(event_mem, sizeof(hi_u32)) != HI_SUCCESS) {
        frw_event_free(event_mem);
        return HI_FAIL;
    }

    frw_event_free(event_mem);

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : AP����յ���ӦSTA�Ĺ���������Ϣ
             ���޶�Ϊdmac_set_rx_filter_value
 �޸���ʷ      :
  1.��    ��   : 2014��4��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_set_rx_filter_value(const mac_vap_stru *mac_vap)
{
#ifndef _PRE_WLAN_PHY_PERFORMANCE
    hi_u32           rx_filter_val;
    mac_device_stru *mac_dev = mac_res_get_dev();

    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_set_rx_filter_value::pst_mac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->vap_state == MAC_VAP_STATE_PAUSE) {
        return HI_SUCCESS;
    }

    if (hmac_find_is_ap_up(mac_dev)) {   /* ��VAPģʽ��AP�Ѿ�UP */
        if ((mac_vap->vap_state == MAC_VAP_STATE_INIT) || (mac_vap->vap_state == MAC_VAP_STATE_STA_FAKE_UP)) {
            return HI_SUCCESS;
        }

        /* ��VAPģʽ��STA����(��STA�Ѿ�up��û��STA up������£�����APģʽ��ʹ�ø�����) */
        /* ����AP UP,����APʱʹ�õ�vap����ֵ */
        rx_filter_val = (!is_ap(mac_vap)) ? hmac_get_apup_sta_rx_filter(mac_vap) :
            ((hmac_find_is_sta_up(mac_dev) && mac_vap->vap_state < MAC_VAP_AP_STATE_BUTT) ?
            hmac_get_staup_ap_rx_filter(mac_vap) : hmac_get_single_vap_rx_filter(mac_vap));
    } else if (hmac_find_is_sta_up(mac_dev)) {   /* ��VAPģʽ��STA�Ѿ�UP */
        /* ��VAPģʽ��STA����(��STA�Ѿ�up��û��STA up������£�����APģʽ��ʹ�ø�����) */
        if ((mac_vap->vap_state == MAC_VAP_STATE_INIT) || (mac_vap->vap_state == MAC_VAP_STATE_STA_FAKE_UP)) {
            return HI_SUCCESS;
        }

        /* STA�Ѿ�UP��״̬�£�STA������ */
        if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            rx_filter_val = hmac_get_staup_sta_rx_filter(mac_vap);
        } else if (is_ap(mac_vap)) {
            rx_filter_val = hmac_get_staup_ap_rx_filter(mac_vap);
        } else {
            return HI_SUCCESS;
        }
    } else {
        /* û���κ��豸����UP״̬������VAP���� */
        rx_filter_val = hmac_get_single_vap_rx_filter(mac_vap);
    }

    /* ֧��ANY���豸(STA & AP��)��Ҫ�ܹ��յ���������BSS�Ĺ㲥����֡��������probe req, �������ò����ˣ�����BIT4 */
    rx_filter_val = (mac_vap->support_any == HI_TRUE) ? (rx_filter_val & (~BIT4)) : rx_filter_val;

    /* ����ֵΪ0ʱ ��ʾά��ԭ��ֵ���� ����Ҫ���� */
    if (rx_filter_val == 0) {
        return HI_SUCCESS;
    }

    hi_u32 ret = hmac_send_rx_filter_event(mac_vap, rx_filter_val);
    if (ret != HI_SUCCESS) {
        return ret;
    }

#endif  /* #ifndef _PRE_WLAN_PHY_PERFORMANCE */

    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
