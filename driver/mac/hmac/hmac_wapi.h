/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Hmac_wapi.c header file
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_WAPI_H__
#define __HMAC_WAPI_H__
/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_net.h"
#include "mac_resource.h"
#include "hmac_vap.h"
#include "hmac_user.h"
#include "hmac_wapi_wpi.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define WAPI_UCAST_INC                  2       /* ���ͻ��߽��յ���֡,pn�Ĳ���ֵ */
#define WAPI_BCAST_INC                  1       /* ���ͻ��߽����鲥֡,pn�Ĳ���ֵ */
#define WAPI_WAI_TYPE                  (hi_u16)0x88B4 /* wapi����̫���� */

#define WAPI_BCAST_KEY_TYPE             1
#define WAPI_UCAST_KEY_TYPE             0

#define SMS4_MIC_LEN                    (hi_u8)16     /* SMS4���MIC�ĳ��� */

#define SMS4_PN_LEN                     16     /* wapi pn�ĳ��� */
#define SMS4_KEY_IDX                    1      /* WAPIͷ�� keyidxռ1���ֽ� */
#define SMS4_WAPI_HDR_RESERVE           1      /* WAPIͷ�б����ֶ� */
#define HMAC_WAPI_HDR_LEN               (hi_u8)(SMS4_PN_LEN + SMS4_KEY_IDX + SMS4_WAPI_HDR_RESERVE)
#define WAPI_PDU_LEN                    2      /* wapiͷ�У�wapi pdu len�ֶ���ռ�ֽ��� */
#define SMS4_PADDING_LEN                16     /* mic data����16�ֽڶ��� */

#define SMS4_MIC_PART1_QOS_LEN          48 /* ����Э�飬�����qos�ֶΣ�mic��һ����16�ֽڶ����ĳ��� */
#define SMS4_MIC_PART1_NO_QOS_LEN       32 /* ����Э�飬���û��qos�ֶΣ�mic��һ����16�ֽڶ����ĳ��� */

#define WAPI_IE_VERSION                     1   /* wapi��version */
#define WAPI_IE_VER_SIZE                    2   /* wapi ver-ie ��ռ�ֽ��� */
#define WAPI_IE_SUIT_TYPE_SIZE              1   /* suit type size */
#define WAPI_IE_WAPICAP_SIZE                2   /* wapi cap�ֶ���ռ�ֽ��� */
#define WAPI_IE_BKIDCNT_SIZE                2   /* wapi bkid���ֶ���ռ�ֽ��� */
#define WAPI_IE_BKID_SIZE                   16  /* һ��bkid��ռ�ֽ��� */
#define WAPI_IE_OUI_SIZE                    3   /* wapi oui�ֽ��� */
#define WAPI_IE_SMS4                        1   /* wapi��������Ϊsms4 */
#define WAPI_IE_SUITCNT_SIZE                2   /* wapi suit count��ռ�ֽ��� */
/* wapi key len */
#define WAPI_MIC_SEQ_CONTROL_LEN            2

#define wapi_is_port_valid(wapi) ((wapi)->port_valid)

#define wapi_is_work(pst_hmac_vap)   ((pst_hmac_vap)->wapi)
#define padding(x, size)           (((x) + (size) - 1) & (~ ((size) - 1)))

#ifdef _PRE_WAPI_DEBUG
#define wapi_tx_drop_inc(pst_wapi)              pst_wapi->debug.ultx_ucast_drop++
#define wapi_tx_wai_inc(pst_wapi)               pst_wapi->debug.ultx_wai++
#define wapi_tx_port_valid(pst_wapi)            pst_wapi->debug.ultx_port_valid++
#define wapi_rx_port_valid(wapi)            wapi->debug.ulrx_port_valid++
#define wapi_rx_idx_err(wapi)               wapi->debug.ulrx_idx_err++
#define wapi_rx_netbuf_len_err(wapi)        wapi->debug.ulrx_netbuff_len_err++
#define wapi_rx_idx_update_err(wapi)        wapi->debug.ulrx_idx_update_err++
#define wapi_rx_key_en_err(pst_wapi)            pst_wapi->debug.ulrx_key_en_err++
#define wapi_rx_memalloc_err(wapi)          wapi->debug.ulrx_memalloc_err++
#define wapi_rx_mic_err(wapi)               wapi->debug.ulrx_mic_calc_fail++
#define wapi_rx_decrypt_ok(wapi)            wapi->debug.ulrx_decrypt_ok++
#define wapi_tx_memalloc_err(wapi)          wapi->debug.ultx_memalloc_err++
#define wapi_tx_mic_err(wapi)               wapi->debug.ultx_mic_calc_fail++
#define wapi_tx_encrypt_ok(wapi)            wapi->debug.ultx_encrypt_ok++
#else
#define wapi_tx_drop_inc(pst_wapi)
#define wapi_tx_wai_inc(pst_wapi)
#define wapi_tx_port_valid(pst_wapi)
#define wapi_rx_port_valid(pst_wapi)
#define wapi_rx_idx_err(pst_wapi)
#define wapi_rx_netbuf_len_err(pst_wapi)
#define wapi_rx_idx_update_err(pst_wapi)
#define wapi_rx_key_en_err(pst_wapi)
#define wapi_rx_memalloc_err(pst_wapi)
#define wapi_rx_mic_err(pst_wapi)
#define wapi_rx_decrypt_ok(pst_wapi)
#define wapi_tx_memalloc_err(pst_wapi)
#define wapi_tx_mic_err(pst_wapi)
#define wapi_tx_wai_drop_inc(pst_wapi)
#define wapi_tx_encrypt_ok(pst_wapi)
#endif /* #ifdef WAPI_DEBUG_MODE */

/*****************************************************************************
  3 STRUCT����
*****************************************************************************/
typedef struct {
    hi_u8   auc_framectl[2];        /* ֡���� 2: Ԫ�ظ��� */
    hi_u8   auc_adress1[OAL_MAC_ADDR_LEN];         /* ��ַ1 */
    hi_u8   auc_adress2[OAL_MAC_ADDR_LEN];         /* ��ַ2 */
    hi_u8   auc_seqctl[2];          /* ���п��� 2: Ԫ�ظ��� */
    hi_u8   auc_adress3[OAL_MAC_ADDR_LEN];         /* ��ַ3 */
    hi_u8   auc_adress4[OAL_MAC_ADDR_LEN];         /* ��ַ4 */
}wapi_mic_hdr_stru;

typedef struct {
    hi_u16 us_mic_len;
    hi_u16 pdu_len;
    hi_u8  auc_calc_mic[SMS4_MIC_LEN];
    hi_u8  auc_pn_swap[SMS4_PN_LEN];      /* ����任���pn,��������mic�ͼ��� */
    hmac_wapi_crypt_stru wpi_key_ck;
    hmac_wapi_crypt_stru wpi_key_ek;
    hi_u8 key_index;
    hi_u8 mac_hdr_len;
} hmac_wapi_encrypt_stru;

typedef struct {
    hi_u8 *puc_mic;
    hi_u16 us_mic_len;
    hi_u8 rsv[2]; /* 2 �ֽڲ��� */
} mic_date_stru;

/*****************************************************************************
  4 ��������
*****************************************************************************/
hi_u32 hmac_wapi_deinit(hmac_wapi_stru *wapi);
hi_u32 hmac_wapi_init(hmac_wapi_stru *wapi, hi_u8 pairwise);
#ifdef _PRE_WAPI_DEBUG
hi_u32 hmac_wapi_display_info(mac_vap_stru *mac_vap, hi_u16 us_usr_idx);
#endif /* #ifdef _PRE_DEBUG_MODE */
hi_u32 hmac_wapi_add_key(hmac_wapi_stru *wapi, hi_u8 key_index, const hi_u8 *puc_key);

/*****************************************************************************
 ��������  : ��port����
 �޸���ʷ      :
  1.��    ��   : 2015��5��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_void hmac_wapi_reset_port(hmac_wapi_stru *wapi)
{
    wapi->port_valid = HI_FALSE;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_WAPI_H__ */

