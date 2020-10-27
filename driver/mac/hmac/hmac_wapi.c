/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Wpi data encryption and decryption
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oal_err_wifi.h"
#include "oal_mem.h"
#include "mac_frame.h"
#include "hmac_wapi.h"
#include "mac_data.h"
#include "hmac_tx_data.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
const hi_u8 g_auc_wapi_pn_init[WAPI_PN_LEN] = {0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36,
                                               0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c};

const hi_u8 g_auc_wapi_oui[WAPI_IE_OUI_SIZE] = { 0x00, 0x14, 0x72 };

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ��PN��תһ��
 �������  : UWORD8 *pucPn - PNֵ����洢�ĵط�
             UWORD8 ucLen - PNֵ�ĳ���
*****************************************************************************/
static inline hi_void hmac_wpi_swap_pn(hi_u8 *puc_pn, hi_u8 len)
{
    hi_u8 index;
    hi_u8 temp;

    for (index = 0; index < len / 2; index++) { /* 2 ���ڼ��� */
        temp = puc_pn[index];
        puc_pn[index] = puc_pn[len - 1 - index];
        puc_pn[len - 1 - index] = temp;
    }
}

/*****************************************************************************
 ��������  : �ж��Ƿ�Ϊqos֡
 �޸���ʷ      :
  1.��    ��   : 2015��5��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 hmac_wapi_is_qos(const mac_ieee80211_frame_stru *mac_hdr)
{
    if ((mac_hdr->frame_control.type == WLAN_DATA_BASICTYPE) &&
        (WLAN_QOS_DATA & mac_hdr->frame_control.sub_type)) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ����mic���ݣ���Ϊ����mic֮��
 �������  : mic���ݻ������ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
    ��    ��   :hmac_rx_get_mac_hdr_len�Ѿ�����4��ַ��������˴����ٿ���
                mic���ݾ��幹�ɼ�<wapiʵʩָ��>5.2.2.3
*****************************************************************************/
hi_u32 hmac_wapi_calc_mic_data(const mac_ieee80211_frame_stru *mac_hdr, hi_u8 keyidx,
                               const hi_u8 *puc_payload, hi_u16 us_pdu_len, const mic_date_stru *mac_date)
{
    hi_u8 us_is_qos;
    hi_u8 *puc_mic_oringin = HI_NULL;
    hi_u8 *puc_mic = mac_date->puc_mic;
    hi_u16 us_mic_len = mac_date->us_mic_len;

    if (memset_s(puc_mic, us_mic_len, 0, us_mic_len) != EOK) {
        return HI_FAIL;
    }

    puc_mic_oringin = puc_mic;

    /* frame control */
    if (memcpy_s(puc_mic, sizeof(mac_hdr->frame_control), (hi_u8 *)&(mac_hdr->frame_control),
                 sizeof(mac_hdr->frame_control)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_calc_mic_data:: st_frame_control memcpy_s fail.");
        return HI_FAIL;
    }
    puc_mic[0] &= ~(BIT4 | BIT5 | BIT6);        /* sub type */
    puc_mic[1] &= ~(BIT3 | BIT4 | BIT5);        /* retry, pwr Mgmt, more data */
    puc_mic[1] |= BIT6;

    puc_mic += sizeof(mac_hdr->frame_control);

    /* addr1 */
    mac_get_address1((hi_u8 *)mac_hdr, WLAN_MAC_ADDR_LEN, puc_mic, WLAN_MAC_ADDR_LEN);
    puc_mic += OAL_MAC_ADDR_LEN;

    /* addr2 */
    mac_get_address2((hi_u8 *)mac_hdr, WLAN_MAC_ADDR_LEN, puc_mic, WLAN_MAC_ADDR_LEN);
    puc_mic += OAL_MAC_ADDR_LEN;

    /* ���п��� */
    if (memset_s(puc_mic, WAPI_MIC_SEQ_CONTROL_LEN, 0, WAPI_MIC_SEQ_CONTROL_LEN) != EOK) {
        return HI_FAIL;
    }
    puc_mic[0] = (hi_u8) (mac_hdr->frag_num);
    puc_mic += 2; /* ����λ����2 */

    /* addr3 */
    mac_get_address3((hi_u8 *)mac_hdr, WLAN_MAC_ADDR_LEN, puc_mic, WLAN_MAC_ADDR_LEN);
    puc_mic += OAL_MAC_ADDR_LEN;

    /* ����addr4 */
    puc_mic += OAL_MAC_ADDR_LEN;

    /* qos ctrl */
    us_is_qos = hmac_wapi_is_qos(mac_hdr);
    if (us_is_qos == HI_TRUE) {
        mac_get_qos_ctrl((hi_u8 *)mac_hdr, puc_mic);
        puc_mic += MAC_QOS_CTL_LEN;
    }

    /* keyidx + reserve�ܹ�2���ֽ� */
    *puc_mic = keyidx;
    puc_mic += 2; /* ����λ����2 */

    /* ���pdulen Э��д������ֽ��� */
    *puc_mic = (hi_u8) ((us_pdu_len & 0xff00) >> 8); /* ����8λ */
    *(puc_mic + 1) = (hi_u8) (us_pdu_len & 0x00ff);

    /************����2����*******************/
    puc_mic_oringin += (HI_TRUE == hmac_wapi_is_qos(mac_hdr)) ? SMS4_MIC_PART1_QOS_LEN : SMS4_MIC_PART1_NO_QOS_LEN;
    if (memcpy_s(puc_mic_oringin, us_pdu_len, puc_payload, us_pdu_len) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_calc_mic_data:: puc_payload memcpy_s fail.");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ռ䣬���ڴ��mic
 �� �� ֵ  : ���뵽�Ŀռ�ָ��
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
static inline hi_u8 *hmac_wapi_mic_alloc(hi_u8 is_qos, hi_u16 us_pdu_len, hi_u16 *pus_mic_len)
{
    hi_u16 us_mic_part1_len;
    hi_u16 us_mic_part2_len;
    hi_u16 us_mic_len;

    us_mic_part1_len = (HI_TRUE == is_qos) ? SMS4_MIC_PART1_QOS_LEN : SMS4_MIC_PART1_NO_QOS_LEN;
    /* ����Э�飬���벻��λ��16�ֽڶ��� */
    us_mic_part2_len = padding(us_pdu_len, SMS4_PADDING_LEN);
    us_mic_len = us_mic_part1_len + us_mic_part2_len;
    *pus_mic_len = us_mic_len;

    return oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, us_mic_len);
}

/*****************************************************************************
 ��������  : �ͷ������mic�ռ�
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
    ��    ��
*****************************************************************************/
static inline hi_u32 hmac_wapi_mic_free(const hi_u8 *puc_mic)
{
    if (puc_mic != HI_NULL) {
        oal_mem_free(puc_mic);
        return HI_SUCCESS;
    }
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : �ж�keyidx�Ƿ�Ϸ�
 �޸���ʷ      :
  1.��    ��   : 2012��5��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_wapi_is_keyidx_valid(hmac_wapi_stru *wapi, hi_u8 keyidx_rx)
{
    if (wapi->keyidx != keyidx_rx && wapi->keyupdate_flg != HI_TRUE) {
        oam_warning_log3(0, OAM_SF_ANY, "{hmac_wapi_is_keyidx_valid::keyidx==%u, uc_keyidx_rx==%u, update==%u.}",
                         wapi->keyidx, keyidx_rx, wapi->keyupdate_flg);
        wapi_rx_idx_update_err(wapi);
        return HI_FALSE;
    }

    wapi->keyupdate_flg = HI_FALSE;     /* �������ȡ����־ */

    /* keyû������ */
    if (wapi->ast_wapi_key[keyidx_rx].key_en != HI_TRUE) {
        oam_warning_log1(0, OAM_SF_ANY, "{hmac_wapi_is_keyidx_valid::keyen==%u.}",
                         wapi->ast_wapi_key[keyidx_rx].key_en);
        wapi_rx_idx_update_err(wapi);
        return HI_FALSE;
    }

    return HI_TRUE;
}

/*****************************************************************************
 ��������  : ����֡�ж�������ż��ȷ��
 �� �� ֵ  : ���Ϊż���򷵻�false
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
    ��    ��
*****************************************************************************/
static inline hi_u8 hmac_wapi_is_pn_odd_ucast(const hi_u8 *puc_pn)
{
    return (hi_u8) (((*puc_pn & BIT0) == 0) ? HI_FALSE : HI_TRUE);
}

/*****************************************************************************
 ��������  : �жϽ��յ���pn�Ƿ���ڼ�¼��pn,���һ����ֵ��λ���С��AP���¼��ֵ�����Բ��ü��
 �޸���ʷ      :

  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_u8 hmac_wapi_is_pn_bigger(const hi_u8 *puc_pn, const hi_u8 *puc_pn_rx)
{
    hi_u8 pnidx;

    for (pnidx = SMS4_PN_LEN - 1; pnidx > 0; pnidx--) {
        if ((puc_pn[pnidx] != puc_pn_rx[pnidx])) {
            if (puc_pn[pnidx] > puc_pn_rx[pnidx]) {
                oam_warning_log2(0, OAM_SF_ANY, "{hmac_wapi_is_pn_bigger::err! puc_pn==%u, puc_pn_rx==%u.}",
                                 puc_pn[pnidx], puc_pn_rx[pnidx]);
                return HI_FALSE;
            }

            return HI_TRUE;
        }
    }

    return HI_TRUE;
}

/*****************************************************************************
 ��������  : �鲥֡�ж�������ż��
 �޸���ʷ      :

  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
static inline hi_u8 hmac_wapi_is_pn_odd_bcast(const hi_u8 *puc_pn)
{
    hi_unref_param(puc_pn);
    return HI_TRUE;
}

/*****************************************************************************
 ��������  : ÿ�յ�һ��֡������pn
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_void hmac_wapi_pn_update(hi_u8 *puc_pn, hi_u8 inc)
{
    hi_u32 loop;
    hi_u32 loop_num;
    hi_u32 overlow;      /* ��λ */
    hi_u32 *pul_pn = HI_NULL;

    pul_pn = (hi_u32 *)puc_pn;
    loop_num = WAPI_PN_LEN / sizeof(hi_u32);
    overlow = inc;

    for (loop = 0; loop < loop_num; loop++) {
        if (*pul_pn > (*pul_pn + overlow)) {
            *pul_pn += overlow;
            overlow = 1;     /* �����λ��1 */
        } else {
            *pul_pn += overlow;
            break;
        }
        pul_pn++;
    }
}

/*****************************************************************************
 ��������  : �����Ѿ���Ƭ���߲����Ƭ��netbuff��
             1)����Ѿ���Ƭ�����������������������netbuff�ϵ����ݽ��м��ܴ���
             2)���û�з�Ƭ��������netbuff,�����netbuff�ϵ����ݽ��м��ܴ���
 �޸���ʷ      :

  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
oal_netbuf_stru *hmac_wapi_netbuff_tx_handle(hmac_wapi_stru *wapi, oal_netbuf_stru *netbuf)
{
    hi_u32 ret;
    oal_netbuf_stru *netbuf_tmp = HI_NULL;    /* ָ����Ҫ�ͷŵ�netbuff */
    oal_netbuf_stru *netbuf_prev = HI_NULL;   /* ָ���Ѿ����ܵ�netbuff */
    oal_netbuf_stru *buf_first = HI_NULL;     /* ָ��δ���ܵ�netbuff */

    /* ������wai֡ */
    if (MAC_DATA_WAPI == mac_get_data_type_from_80211(netbuf, MAC_80211_QOS_HTC_4ADDR_FRAME_LEN)) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_wapi_netbuff_tx_handle::wai, dont encrypt!.}");
        return netbuf;
    }

    ret = wapi->wapi_encrypt(wapi, netbuf);
    if (ret != HI_SUCCESS) {
        hmac_free_netbuf_list(netbuf);
        return HI_NULL;
    }

    netbuf_tmp = netbuf;

    /* ʹnetbuffָ��ָ����һ����Ҫ���ܵķ�Ƭ֡ */
    netbuf_prev = oal_netbuf_next(netbuf);
    if (netbuf_prev == HI_NULL) {
        return HI_NULL;
    }
    buf_first = netbuf_prev;
    netbuf = oal_netbuf_next(netbuf_prev);

    oal_netbuf_free(netbuf_tmp);

    while (netbuf != HI_NULL) {
        ret = wapi->wapi_encrypt(wapi, netbuf);
        if (ret != HI_SUCCESS) {
            hmac_free_netbuf_list(buf_first);
            return HI_NULL;
        }
        oal_netbuf_next(netbuf_prev) = oal_netbuf_next(netbuf);
        netbuf_tmp = netbuf;
        netbuf_prev = oal_netbuf_next(netbuf);
        if (netbuf_prev == HI_NULL) {
            return HI_NULL;
        }
        netbuf = oal_netbuf_next(netbuf_prev);

        oal_netbuf_free(netbuf_tmp);
    }
    return buf_first;
}

/*****************************************************************************
 ��������  : ���մ���ȷ���Ҫ�򵥣���Ϊÿ��ֻ����һ��netbuff��Ҫ����
             ������ܵ�netbuffΪ1�����ܺ��Ϊ0����ô����Ϊ1,������ɺ��Ϊ
             1->0 ��������1ɾ����Ȼ���Ѿ����ܵ�0������
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
oal_netbuf_stru *hmac_wapi_netbuff_rx_handle(hmac_wapi_stru *wapi, oal_netbuf_stru *netbuf)
{
    hi_u32 ret;
    oal_netbuf_stru *netbuf_tmp = HI_NULL;    /* ָ����Ҫ�ͷŵ�netbuff */

    /* �Ǽ���֡�������н��� */
    if (!((oal_netbuf_data(netbuf))[1] & 0x40)) {
        return netbuf;
    }

    ret = wapi->wapi_decrypt(wapi, netbuf);
    if (ret != HI_SUCCESS) {
        return HI_NULL;
    }

    netbuf_tmp = netbuf;
    netbuf = oal_netbuf_next(netbuf);
    oal_netbuf_free(netbuf_tmp);

    return netbuf;
}

/*****************************************************************************
 ��������  : ����/���� key
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_u32 hmac_wapi_add_key(hmac_wapi_stru *wapi, hi_u8 key_index, const hi_u8 *puc_key)
{
    hmac_wapi_key_stru *key = HI_NULL;

    wapi_is_port_valid(wapi) = HI_TRUE;
    wapi->keyidx = key_index;
    wapi->keyupdate_flg = HI_TRUE;
    key = &(wapi->ast_wapi_key[key_index]);

    if (memcpy_s(key->auc_wpi_ek, WAPI_KEY_LEN, puc_key, WAPI_KEY_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_add_key:: puc_key memcpy_s fail.");
        return HI_FAIL;
    }
    if (memcpy_s(key->auc_wpi_ck, WAPI_KEY_LEN, puc_key + WAPI_KEY_LEN, WAPI_KEY_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_add_key:: puc_key memcpy_s fail.");
        return HI_FAIL;
    }
    key->key_en = HI_TRUE;

    /* ����PN */
    if (memcpy_s(key->auc_pn_rx, WAPI_PN_LEN, g_auc_wapi_pn_init, WAPI_PN_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_add_key:: g_auc_wapi_pn_init memcpy_s fail.");
        return HI_FAIL;
    }
    if (memcpy_s(key->auc_pn_tx, WAPI_PN_LEN, g_auc_wapi_pn_init, WAPI_PN_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_add_key:: g_auc_wapi_pn_init memcpy_s fail.");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����wpiͷ�ĺϷ���
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_u8 hmac_wapi_is_wpihdr_valid(hmac_wapi_stru *wapi, const hi_u8 *puc_wapi_hdr)
{
    hi_u8 keyidx_rx;
    const hi_u8 *puc_pn_rx = HI_NULL;

    keyidx_rx = *puc_wapi_hdr;

    if (hmac_wapi_is_keyidx_valid(wapi, keyidx_rx) != HI_TRUE) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_wapi_is_wpihdr_valid::hmac_wapi_is_keyidx_valid==false.}");
        return HI_FALSE;
    }

    puc_pn_rx = puc_wapi_hdr + SMS4_KEY_IDX + SMS4_WAPI_HDR_RESERVE;
    if (wapi->wapi_is_pn_odd(puc_pn_rx) != HI_TRUE) {
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_wapi_is_wpihdr_valid::wapi_is_pn_odd==false.}");
        return HI_FALSE;
    }
    return HI_TRUE;
}

/*****************************************************************************
 ��������  : �����ݽ��н���
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
    ��    ��   : �˺���������ش�����Ҫ��netbuff�ͷŵ�������Ҫ���͵�������д���
*****************************************************************************/
/* ����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������:�����ݽ��н��ܵ��㷨�����������ھۣ��������� */
hi_u32 hmac_wapi_decrypt(hmac_wapi_stru *wapi, oal_netbuf_stru *netbuf)
{
    hi_u8  auc_calc_mic[SMS4_MIC_LEN];
    hi_u16 us_mic_len;
    hmac_wapi_crypt_stru wpi_key_ek = {0};
    hmac_wapi_crypt_stru wpi_key_ck = {0};
    mic_date_stru mac_date;

    wapi_rx_port_valid(wapi);

    /************ 1. ����ǰ������׼��,��ȡ��ͷָ������ݳ��� ************/
    hi_u16 netbuff_len = (hi_u16)oal_netbuf_len(netbuf);

    /* ��ȡmacͷ */
    mac_ieee80211_frame_stru *mac_hdr = (mac_ieee80211_frame_stru *)oal_netbuf_data(netbuf); /* for ut,del temprarily */

    /* wapi������֡һ��ΪQOS֡  */
    hmac_rx_ctl_stru *rx_ctl_in = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuf);
    hi_u8  mac_hdr_len  = rx_ctl_in->mac_header_len;
    hi_u8 *puc_wapi_hdr = (hi_u8 *)mac_hdr + mac_hdr_len;
    hi_u8 *puc_pn       = puc_wapi_hdr + SMS4_KEY_IDX + SMS4_WAPI_HDR_RESERVE;

    oam_warning_log1(0, OAM_SF_ANY, "{hmac_wpi_decrypt::uc_mac_hdr_len %u!.}", mac_hdr_len);

    if (netbuff_len < (hi_u16) (mac_hdr_len + HMAC_WAPI_HDR_LEN + SMS4_MIC_LEN)) {
        oam_error_log2(0, OAM_SF_ANY, "{hmac_wpi_decrypt::netbuff_len %u,machdr len %u err}", netbuff_len, mac_hdr_len);
        oal_netbuf_free(netbuf);
        wapi_rx_netbuf_len_err(wapi);
        return HI_FAIL;
    }

    hi_u16 us_pdu_len = netbuff_len - mac_hdr_len - HMAC_WAPI_HDR_LEN - SMS4_MIC_LEN;
    hi_u8  key_index  = *puc_wapi_hdr;

    if (key_index >= HMAC_WAPI_MAX_KEYID) {
        wapi_rx_idx_err(wapi);
        oam_error_log1(0, OAM_SF_ANY, "{hmac_wpi_decrypt::uc_key_index %u err!.}", key_index);
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    if (hmac_wapi_is_wpihdr_valid(wapi, puc_wapi_hdr) != HI_TRUE) {
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    /************ 2. ׼���µ�netbuff,������Ž��ܺ������, ��дcb�ֶ� ************/
    oal_netbuf_stru *netbuff_des = oal_netbuf_alloc(WLAN_MGMT_NETBUF_SIZE, 0, 4);   /* align 4 */
    if (netbuff_des == HI_NULL) {
        wapi_rx_memalloc_err(wapi);
        oal_netbuf_free(netbuf);
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* �ȿ���macͷ */
    oal_netbuf_init(netbuff_des, mac_hdr_len);

    hi_u32 wapi_result = oal_netbuf_copydata(netbuf, 0, oal_netbuf_data(netbuff_des),
                                             oal_netbuf_len(netbuff_des), mac_hdr_len);
    if (wapi_result != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_decrypt:: ul_wapi_result fail.");
        oal_netbuf_free(netbuf);
        oal_netbuf_free(netbuff_des);
        return wapi_result;
    }

    /* ����cb */
    hmac_rx_ctl_stru *rx_ctl = (hmac_rx_ctl_stru *)oal_netbuf_cb(netbuff_des);
    if (memcpy_s(rx_ctl, sizeof(hmac_rx_ctl_stru), oal_netbuf_cb(netbuf), sizeof(hmac_rx_ctl_stru)) != EOK) {
        oal_netbuf_free(netbuff_des);
        oal_netbuf_free(netbuf);
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_decrypt:: pst_netbuf memcpy_s fail.");
        return HI_FAIL;
    }

    /************ 3. ����ǰ����Կ׼����PN׼�� ************/
    hmac_wpi_swap_pn(puc_pn, SMS4_PN_LEN);

    /******************** 4. ����**************************/
    wpi_key_ek.puc_iv  = puc_pn;
    wpi_key_ek.iv_len  = SMS4_PN_LEN; /* iv key len 16 */
    wpi_key_ek.puc_key = wapi->ast_wapi_key[key_index].auc_wpi_ek;
    wpi_key_ek.key_len = 16; /* ck key len 16 */
    wapi_result = hmac_wpi_decrypt(wpi_key_ek, puc_pn + SMS4_PN_LEN, (us_pdu_len + SMS4_MIC_LEN), /* ����ܵĳ��� */
                                   (oal_netbuf_data(netbuff_des) + mac_hdr_len));
    if (wapi_result != HI_SUCCESS) {
        oal_netbuf_free(netbuff_des);
        /* ����֮ǰע�����netbuff�Ƿ������汻�ͷ� */
        oal_netbuf_free(netbuf);
        return HI_ERR_CODE_WAPI_DECRYPT_FAIL;
    }

    /* mic��ΪУ����������Ҫput */
    oal_netbuf_put(netbuff_des, us_pdu_len);

    /************ 5. ����mic��������У�� ************/
    hi_u8 *puc_mic_data = hmac_wapi_mic_alloc(hmac_wapi_is_qos(mac_hdr), us_pdu_len, &us_mic_len);
    if (puc_mic_data == HI_NULL) {
        wapi_rx_memalloc_err(wapi);
        oal_netbuf_free(netbuff_des);
        /* ע��netbuff�����Ƿ����ͷŴ��� */
        oal_netbuf_free(netbuf);
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* ����micԤ������ */
    mac_date.puc_mic = puc_mic_data;
    mac_date.us_mic_len = us_mic_len;
    if (hmac_wapi_calc_mic_data(mac_hdr, key_index, oal_netbuf_data(netbuff_des) + mac_hdr_len,
        us_pdu_len, &mac_date) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "hmac_wapi_calc_mic_data return NON SUCCESS. ");
    }

    wpi_key_ck.puc_iv  = puc_pn;
    wpi_key_ck.iv_len  = 16; /* iv key len 16 */
    wpi_key_ck.puc_key = wapi->ast_wapi_key[key_index].auc_wpi_ck;
    wpi_key_ck.key_len = 16; /* ck key len 16 */
    wapi_result = hmac_wpi_pmac(wpi_key_ck, puc_mic_data, (us_mic_len >> 4), auc_calc_mic, SMS4_MIC_LEN); /* ����4λ */

    /* ������mic���ͷ�mic data */
    if (hmac_wapi_mic_free(puc_mic_data) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "hmac_wapi_mic_free return NON SUCCESS. ");
    }

    if (wapi_result != HI_SUCCESS) {
        oal_netbuf_free(netbuff_des);
        oal_netbuf_free(netbuf);
        return HI_ERR_CODE_WAPI_MIC_CALC_FAIL;
    }

    hi_u8 *puc_mic = oal_netbuf_data(netbuff_des) + mac_hdr_len + us_pdu_len;
    if (memcmp(puc_mic, auc_calc_mic, SMS4_MIC_LEN) != 0) { /* �Ƚ�MIC */
        oam_warning_log0(0, OAM_SF_ANY, "{hmac_wpi_decrypt::mic check fail!.}");
        wapi_rx_mic_err(wapi);
        oal_netbuf_free(netbuff_des);
        oal_netbuf_free(netbuf);
        return HI_ERR_CODE_WAPI_MIC_CMP_FAIL;
    }

    /* ����ǰ��protected */
    (oal_netbuf_data(netbuff_des))[1] &= ~0x40;

    /* ��дcb */
    rx_ctl->pul_mac_hdr_start_addr = (hi_u32 *)oal_netbuf_header(netbuff_des);
    rx_ctl->mac_header_len         = mac_hdr_len;
    rx_ctl->us_frame_len           = (hi_u16)oal_netbuf_len(netbuff_des);

    oal_netbuf_next(netbuff_des) = oal_netbuf_next(netbuf);
    oal_netbuf_next(netbuf) = netbuff_des;

    hmac_wapi_pn_update(wapi->ast_wapi_key[wapi->keyidx].auc_pn_rx, wapi->pn_inc);

    oam_warning_log0(0, OAM_SF_ANY, "{hmac_wpi_decrypt::OK!.}");
    wapi_rx_decrypt_ok(wapi);

    return HI_SUCCESS;
}

static hi_u32 hmac_wapi_encrypt_mic(hmac_wapi_stru *wapi, hmac_wapi_encrypt_stru* hmac_wapi,
    const mac_ieee80211_frame_stru *mac_hdr, const hi_u8 *puc_payload)
{
    mic_date_stru mac_date;
    /************ 2. ����mic,wapi������֡һ��ΪQOS֡  ************/
    hi_u8 *puc_mic_data = hmac_wapi_mic_alloc(hmac_wapi_is_qos(mac_hdr), hmac_wapi->pdu_len, &hmac_wapi->us_mic_len);
    if (puc_mic_data == HI_NULL) {
        wapi_tx_memalloc_err(wapi);
        oam_error_log0(0, OAM_SF_ANY, "{hmac_wapi_encrypt::hmac_wapi_mic_alloc err!");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* ����micԤ������ */
    mac_date.puc_mic = puc_mic_data;
    mac_date.us_mic_len = hmac_wapi->us_mic_len;
    if (hmac_wapi_calc_mic_data(mac_hdr, hmac_wapi->key_index, puc_payload, hmac_wapi->pdu_len, puc_mic_data,
        hmac_wapi->us_mic_len) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_CFG, "hmac_wapi_calc_mic_data return NON SUCCESS. ");
    }

    if (memcpy_s(hmac_wapi->auc_pn_swap, SMS4_PN_LEN, wapi->ast_wapi_key[hmac_wapi->key_index].auc_pn_tx,
        SMS4_PN_LEN) != EOK) {
        if (hmac_wapi_mic_free(puc_mic_data) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_CFG, "hmac_wapi_mic_free return NON SUCCESS. ");
        }

        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_encrypt:: auc_pn_tx memcpy_s fail.");
        return HI_FAIL;
    }
    hmac_wpi_swap_pn(hmac_wapi->auc_pn_swap, SMS4_PN_LEN);
    /* ����mic */
    hmac_wapi->wpi_key_ck.puc_iv = hmac_wapi->auc_pn_swap;
    hmac_wapi->wpi_key_ck.iv_len = SMS4_PN_LEN; /* iv key len 16 */
    hmac_wapi->wpi_key_ck.puc_key = wapi->ast_wapi_key[hmac_wapi->key_index].auc_wpi_ck;
    hmac_wapi->wpi_key_ck.key_len = 16; /* ck key len 16 */
    hi_u32 ret = hmac_wpi_pmac(hmac_wapi->wpi_key_ck, puc_mic_data,
        (hmac_wapi->us_mic_len >> 4), hmac_wapi->auc_calc_mic, SMS4_MIC_LEN); /* ����4λ */

    if (hmac_wapi_mic_free(puc_mic_data) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_CFG, "hmac_wapi_mic_free return NON SUCCESS. ");
    }
    if (ret == HI_FAIL) {
        wapi_tx_mic_err(wapi);
        oam_error_log0(0, OAM_SF_ANY, "{hmac_wapi_encrypt::hmac_wpi_pmac mic calc err!");
        return HI_ERR_CODE_WAPI_MIC_CALC_FAIL;
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_wapi_encrypt_action(hmac_wapi_stru *wapi, oal_netbuf_stru *netbuf, hmac_wapi_encrypt_stru* hmac_wapi,
    hi_u8 *puc_datain, oal_netbuf_stru *netbuf_des)
{
    /************************ 4. ���� ************************/
    hmac_wapi->wpi_key_ek.puc_iv = hmac_wapi->auc_pn_swap;
    hmac_wapi->wpi_key_ek.iv_len = SMS4_PN_LEN;
    hmac_wapi->wpi_key_ek.puc_key = wapi->ast_wapi_key[hmac_wapi->key_index].auc_wpi_ek;
    hmac_wapi->wpi_key_ek.key_len = WAPI_KEY_LEN;
    hi_u32 ret = hmac_wpi_encrypt(hmac_wapi->wpi_key_ek, puc_datain, hmac_wapi->pdu_len + SMS4_MIC_LEN,
        oal_netbuf_data(netbuf_des) + HMAC_WAPI_HDR_LEN + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN);

    oal_free(puc_datain);
    if (ret != HI_SUCCESS) {
        oal_netbuf_free(netbuf_des);
        oam_error_log1(0, OAM_SF_ANY, "{hmac_wapi_encrypt::hmac_wpi_encrypt err==%u!", ret);
        return HI_ERR_CODE_WAPI_ENRYPT_FAIL;
    }
    /* �˴�put��֮��netbuff��lenΪmacͷ+pdulen+sms4+wapi�ĳ��� */
    oal_netbuf_put(netbuf_des, hmac_wapi->pdu_len + SMS4_MIC_LEN + HMAC_WAPI_HDR_LEN);

    /***************** 5. ��дwapiͷ *****************/
    hi_u8 *puc_wapi_hdr = oal_netbuf_data(netbuf_des) + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN;

    /* ��дWPIͷ -- keyIndex */
    *(puc_wapi_hdr) = hmac_wapi->key_index;
    /* ����λ���� */
    *(puc_wapi_hdr + SMS4_KEY_IDX) = 0;
    /* ��дPN */
    if (memcpy_s((puc_wapi_hdr + SMS4_KEY_IDX + SMS4_WAPI_HDR_RESERVE), SMS4_PN_LEN,
                 wapi->ast_wapi_key[hmac_wapi->key_index].auc_pn_tx, SMS4_PN_LEN) != EOK) {
        oal_netbuf_free(netbuf_des);
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_encrypt:: auc_pn_tx memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ٴ���дcb */
    ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf_des))->frame_header =
        (mac_ieee80211_frame_stru *)oal_netbuf_data(netbuf_des);

    /* ������mac hdr */
    ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf_des))->us_mpdu_len =
        (hi_u16)(HMAC_WAPI_HDR_LEN + hmac_wapi->pdu_len + SMS4_MIC_LEN);

    oal_netbuf_next(netbuf_des) = oal_netbuf_next(netbuf);
    oal_netbuf_next(netbuf) = netbuf_des;
    /* ����pn */
    hmac_wapi_pn_update(wapi->ast_wapi_key[wapi->keyidx].auc_pn_tx, wapi->pn_inc);
    oam_warning_log0(0, OAM_SF_ANY, "{hmac_wapi_encrypt::hmac_wpi_encrypt OK!");

    wapi_tx_encrypt_ok(wapi);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �����ݽ��м���,�������֮�������Ƿ��Ƭ��
            ��һ��netbuffΪ����ǰ��û�м��ܵ�netbuff��
            ����ҵ�netbuffΪ���ܹ���netbuff,��ע��!
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_u32 hmac_wapi_encrypt(hmac_wapi_stru *wapi, oal_netbuf_stru *netbuf)
{
    hmac_wapi_encrypt_stru hmac_wapi = {0};
    hmac_wapi.key_index = wapi->keyidx;

    /************ 1. ����ǰ������׼��,��ȡ��ͷָ������ݳ��� ************/
    /* ��ȡmacͷ */
    mac_ieee80211_frame_stru *mac_hdr = ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf))->frame_header;
    hmac_wapi.mac_hdr_len = ((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf))->frame_header_length;

    /* ���ü���λ ע�⣬macͷ�漰���ܣ�������Ҫ���ʼ���� */
    mac_set_protectedframe((hi_u8 *)mac_hdr);

    oam_warning_log2(0, OAM_SF_ANY, "{hmac_wapi_encrypt:len %u!fra %u}", hmac_wapi.mac_hdr_len,
        mac_hdr->frame_control.more_frag);
    hmac_wapi.pdu_len = (hi_u16)(((hmac_tx_ctl_stru *)oal_netbuf_cb(netbuf))->us_mpdu_len);
    hi_u8 *puc_payload = oal_netbuf_data(netbuf) + MAC_80211_QOS_HTC_4ADDR_FRAME_LEN;

    /************ 2. ����mic,wapi������֡һ��ΪQOS֡  ************/
    hi_u32 ret = hmac_wapi_encrypt_mic(wapi, &hmac_wapi, mac_hdr, puc_payload);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /************ 3. ׼���µ�netbuff,������ż��ܺ������, ��дcb,��׼������ǰ������ ************/
    oal_netbuf_stru *netbuf_des = oal_netbuf_alloc(WLAN_LARGE_NETBUF_SIZE, 0, 4);   /* align 4 */
    if (netbuf_des == HI_NULL) {
        wapi_tx_memalloc_err(wapi);
        oam_error_log0(0, OAM_SF_ANY, "{hmac_wapi_encrypt::pst_netbuff_des alloc err!");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* ��дcb */
    if (memcpy_s(oal_netbuf_cb(netbuf_des), oal_netbuf_cb_size(), oal_netbuf_cb(netbuf), oal_netbuf_cb_size()) != EOK) {
        oal_netbuf_free(netbuf_des);
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_encrypt:: pst_netbuf memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ȿ���macͷ,Ϊ�˺���hcc�����˴���д���Ŀռ� */
    oal_netbuf_init(netbuf_des, MAC_80211_QOS_HTC_4ADDR_FRAME_LEN);
    if (memcpy_s(oal_netbuf_data(netbuf_des), hmac_wapi.mac_hdr_len, mac_hdr, hmac_wapi.mac_hdr_len) != EOK) {
        oal_netbuf_free(netbuf_des);
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_encrypt:: pst_mac_hdr memcpy_s fail.");
        return HI_FAIL;
    }

    hi_u8 *puc_datain = (hi_u8 *)oal_memalloc(hmac_wapi.pdu_len + SMS4_MIC_LEN);
    if (puc_datain == HI_NULL) {
        oal_netbuf_free(netbuf_des);
        oam_error_log0(0, OAM_SF_ANY, "{hmac_wapi_encrypt::puc_datain alloc err!");
        wapi_tx_memalloc_err(wapi);
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    if ((memcpy_s(puc_datain, hmac_wapi.pdu_len, puc_payload, hmac_wapi.pdu_len) != EOK) ||
        (memcpy_s(puc_datain + hmac_wapi.pdu_len, SMS4_MIC_LEN, hmac_wapi.auc_calc_mic, SMS4_MIC_LEN) != EOK)) {
        oal_free(puc_datain);
        oal_netbuf_free(netbuf_des);
        oam_error_log0(0, OAM_SF_CFG, "hmac_wapi_encrypt:: puc_payload memcpy_s fail.");
        return HI_FAIL;
    }

    /************************ 4. ���� ************************/
    /********************** 5. ��дwapiͷ ********************/
    return hmac_wapi_encrypt_action(wapi, netbuf, &hmac_wapi, puc_datain, netbuf_des);
}

/*****************************************************************************
 ��������  : ȥ��ʼ��wapi����
 �޸���ʷ      :
  1.��    ��   : 2015��5��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_wapi_deinit(hmac_wapi_stru *wapi)
{
    if (memset_s(wapi, sizeof(hmac_wapi_stru), 0, sizeof(hmac_wapi_stru)) != EOK) {
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼ��wapi����
 �޸���ʷ      :
  1.��    ��   : 2015��5��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_wapi_init(hmac_wapi_stru *wapi, hi_u8 pairwise)
{
    hi_u32 loop, ret;

    ret = hmac_wapi_deinit(wapi);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_UM, "hmac_wapi_deinit return NON SUCCESS. ");
    }

    if (pairwise == HI_TRUE) {
        wapi->pn_inc = WAPI_UCAST_INC;
        wapi->wapi_is_pn_odd = hmac_wapi_is_pn_odd_ucast;
    } else {
        wapi->pn_inc = WAPI_BCAST_INC;
        wapi->wapi_is_pn_odd = hmac_wapi_is_pn_odd_bcast;
    }

    for (loop = 0; loop < HMAC_WAPI_MAX_KEYID; loop++) {
        wapi->ast_wapi_key[loop].key_en = HI_FALSE;
    }

    wapi->port_valid = HI_FALSE;
    wapi->wapi_decrypt = hmac_wapi_decrypt;
    wapi->wapi_encrypt = hmac_wapi_encrypt;
    wapi->wapi_netbuff_txhandle = hmac_wapi_netbuff_tx_handle;
    wapi->wapi_netbuff_rxhandle = hmac_wapi_netbuff_rx_handle;
    return HI_SUCCESS;
}

#ifdef _PRE_WAPI_DEBUG
/*****************************************************************************
 ��������  : ��ӡ֡����
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_void hmac_wapi_dump_frame(hi_u8 *puc_info, hi_u8 *puc_data, hi_u32 len)
{
    hi_u32 loop;
    for (loop = 0; loop < len; loop += 4) { /* ѭ������Ϊ4 */
        oal_io_print("%2x ", loop / 4);  /* ѭ������Ϊ4 */
        oal_io_print("%2x %2x %2x %2x \r\n", puc_data[loop], puc_data[loop + 1],
                     puc_data[loop + 2], puc_data[loop + 3]); /* 2 3 ����λ������ */
    }
}

/*****************************************************************************
 ��������  : ��ӡ�û�wapi����
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_u32 hmac_wapi_display_usr_info(hmac_user_stru *hmac_user)
{
    hi_u32 loop = 0;
    hmac_wapi_stru *wapi = HI_NULL;
    hmac_wapi_key_stru *key = HI_NULL;
    hmac_wapi_debug *debug = HI_NULL;

    oam_warning_log1(0, OAM_SF_ANY, "wapi port is %u!", wapi_is_port_valid(&hmac_user->wapi));
    if (wapi_is_port_valid(&hmac_user->wapi != HI_TRUE)) {
        oal_io_print("Err! wapi port is not valid!\n");

        return HI_FAILURE;
    }

    wapi = &(hmac_user->wapi);
    oam_warning_log0(0, OAM_SF_ANY, "keyidx\tupdate\t\tpn_inc\t\n");
    oam_warning_log3(0, OAM_SF_ANY, "%u\t%08x%04x\t\n",
                     wapi->keyidx, wapi->keyupdate_flg, wapi->pn_inc);

    for (loop = 0; loop < HMAC_WAPI_MAX_KEYID; loop++) {
        key = &wapi->ast_wapi_key[loop];
        hmac_wapi_dump_frame("ek :", key->auc_wpi_ek, WAPI_KEY_LEN);
        hmac_wapi_dump_frame("ck :", key->auc_wpi_ck, WAPI_KEY_LEN);
        hmac_wapi_dump_frame("pn_local_rx :", key->auc_pn_rx, WAPI_PN_LEN);
        hmac_wapi_dump_frame("pn_local_tx :", key->auc_pn_tx, WAPI_PN_LEN);
        oam_warning_log1(0, OAM_SF_ANY, "key_en: %u\n", key->key_en);
    }

    debug = &wapi->debug;
    oam_warning_log0(0, OAM_SF_ANY, "TX DEBUG INFO:");
    hmac_wapi_dump_frame("pn_rx :", debug->aucrx_pn, WAPI_PN_LEN);
    oam_warning_log4(0, OAM_SF_ANY, "tx_drop==%u, tx_wai==%u, tx_port_valid==%u, tx_memalloc_fail==%u",
                     debug->ultx_ucast_drop,
                     debug->ultx_wai, debug->ultx_port_valid, debug->ultx_memalloc_err);
    oam_warning_log3(0, OAM_SF_ANY, "tx_mic_calc_fail==%u, tx_encrypt_ok==%u, tx_memalloc_err==%u",
                     debug->ultx_mic_calc_fail,
                     debug->ultx_encrypt_ok, debug->ultx_memalloc_err);

    oam_warning_log0(0, OAM_SF_ANY, "RX DEBUG INFO:");
    oam_warning_log4(0, OAM_SF_ANY, "rx_port_valid==%u, rx_idx_err==%u, rx_netbuff_len_err==%u, rx_idx_update_err==%u",
                     debug->ulrx_port_valid,
                     debug->ulrx_idx_err, debug->ulrx_netbuff_len_err, debug->ulrx_idx_update_err);

    oam_warning_log4(0, OAM_SF_ANY, "rx_key_en_err==%u, rx_pn_odd_err==%u, rx_pn_replay_err==%u, rx_decrypt_ok==%u",
                     debug->ulrx_key_en_err,
                     debug->ulrx_pn_odd_err, debug->ulrx_pn_replay_err, debug->ulrx_decrypt_ok);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ӡwapi����
 �޸���ʷ      :
  1.��    ��   : 2015��5��21��
    ��    ��   : Hisilicon
    �޸�����   : ����
*****************************************************************************/
hi_u32 hmac_wapi_display_info(mac_vap_stru *mac_vap, hi_u16 us_usr_idx)
{
    hmac_user_stru *hmac_user = HI_NULL;
    hmac_user_stru *hmac_multi_user = HI_NULL;
    hi_u32 ret;

    hmac_multi_user = (hmac_user_stru *)hmac_user_get_user_stru(mac_vap->multi_user_idx);
    if (hmac_multi_user == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "Err! multi usr %u does not exist!", mac_vap->multi_user_idx);
        return HI_ERR_CODE_PTR_NULL;
    }

    oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "*****************multi usr info start****************");
    ret = hmac_wapi_display_usr_info(hmac_multi_user);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "hmac_wapi_display_usr_info return NON SUCCESS. ");
    }

    oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "*****************multi usr info end****************");

    hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(us_usr_idx);
    if (hmac_user == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_ANY, "Err! ucast usr %u does not exist!", us_usr_idx);
        return HI_ERR_CODE_PTR_NULL;
    }

    oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "*****************ucast usr info start****************");
    ret = hmac_wapi_display_usr_info(hmac_user);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "hmac_wapi_display_usr_info return NON SUCCESS. ");
    }
    oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "*****************ucast usr info end****************");

    return HI_SUCCESS;
}
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

