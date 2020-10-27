/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_regdomain.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_REGDOMAIN_H__
#define __MAC_REGDOMAIN_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "wlan_types.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* Ĭ�Ϲ���������͹��� */
#define MAC_RC_DEFAULT_MAX_TX_PWR   20      /* 20dBm */
#define MAC_INVALID_RC              255     /* ��Ч�Ĺ���������ֵ */

#define MAC_AFFECTED_CHAN_OFFSET_START_FREQ_5        0
#define MAC_AFFECTED_CHAN_OFFSET_START_FREQ_2        3

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/* һ�����������ʼƵ��ö�� */
typedef enum {
    MAC_RC_START_FREQ_2  = WLAN_BAND_2G,  /* 2.407 */
    MAC_RC_START_FREQ_BUTT,
}mac_rc_start_freq_enum;
typedef hi_u8 mac_rc_start_freq_enum_uint8;

/* �������ŵ���� */
typedef enum {
    MAC_CH_SPACING_5MHZ = 0,
    MAC_CH_SPACING_10MHZ,
    MAC_CH_SPACING_20MHZ,
    MAC_CH_SPACING_25MHZ,
    MAC_CH_SPACING_40MHZ,

    MAC_CH_SPACING_BUTT
}mac_ch_spacing_enum;
typedef hi_u8 mac_ch_spacing_enum_uint8;

/* �״���֤��׼ö�� */
typedef enum {
    MAC_DFS_DOMAIN_NULL  = 0,
    MAC_DFS_DOMAIN_FCC   = 1,
    MAC_DFS_DOMAIN_ETSI  = 2,
    MAC_DFS_DOMAIN_MKK   = 3,
    MAC_DFS_DOMAIN_KOREA = 4,

    MAC_DFS_DOMAIN_BUTT
}mac_dfs_domain_enum;
typedef hi_u8 mac_dfs_domain_enum_uint8;

/* 5GHzƵ��: �ŵ��Ŷ�Ӧ���ŵ�����ֵ */
typedef enum {
    MAC_CHANNEL36  = 0,
    MAC_CHANNEL40  = 1,
    MAC_CHANNEL44  = 2,
    MAC_CHANNEL48  = 3,
    MAC_CHANNEL52  = 4,
    MAC_CHANNEL56  = 5,
    MAC_CHANNEL60  = 6,
    MAC_CHANNEL64  = 7,
    MAC_CHANNEL100 = 8,
    MAC_CHANNEL104 = 9,
    MAC_CHANNEL108 = 10,
    MAC_CHANNEL112 = 11,
    MAC_CHANNEL116 = 12,
    MAC_CHANNEL120 = 13,
    MAC_CHANNEL124 = 14,
    MAC_CHANNEL128 = 15,
    MAC_CHANNEL132 = 16,
    MAC_CHANNEL136 = 17,
    MAC_CHANNEL140 = 18,
    MAC_CHANNEL144 = 19,
    MAC_CHANNEL149 = 20,
    MAC_CHANNEL153 = 21,
    MAC_CHANNEL157 = 22,
    MAC_CHANNEL161 = 23,
    MAC_CHANNEL165 = 24,
    MAC_CHANNEL184 = 25,
    MAC_CHANNEL188 = 26,
    MAC_CHANNEL192 = 27,
    MAC_CHANNEL196 = 28,
    MAC_CHANNEL_FREQ_5_BUTT = 29,
}mac_channel_freq_5_enum;
typedef hi_u8 mac_channel_freq_5_enum_uint8;

/* 2.4GHzƵ��: �ŵ��Ŷ�Ӧ���ŵ�����ֵ */
typedef enum {
    MAC_CHANNEL1  = 0,
    MAC_CHANNEL2  = 1,
    MAC_CHANNEL3  = 2,
    MAC_CHANNEL4  = 3,
    MAC_CHANNEL5  = 4,
    MAC_CHANNEL6  = 5,
    MAC_CHANNEL7  = 6,
    MAC_CHANNEL8  = 7,
    MAC_CHANNEL9  = 8,
    MAC_CHANNEL10 = 9,
    MAC_CHANNEL11 = 10,
    MAC_CHANNEL12 = 11,
    MAC_CHANNEL13 = 12,
    MAC_CHANNEL14 = 13,
    MAC_CHANNEL_FREQ_2_BUTT = 14,
}mac_channel_freq_2_enum;
typedef hi_u8 mac_channel_freq_2_enum_uint8;

typedef enum {
    MAC_RC_DFS      = BIT0,
}mac_behaviour_bmap_enum;

#define MAC_MAX_SUPP_CHANNEL    MAC_CHANNEL_FREQ_2_BUTT

/*****************************************************************************
  STRUCT����
*****************************************************************************/
/* ������ṹ��: ÿ�������ౣ�����Ϣ */
typedef struct {
    mac_rc_start_freq_enum_uint8    start_freq;          /* ��ʼƵ�� */
    mac_ch_spacing_enum_uint8       ch_spacing;          /* �ŵ���� */
    hi_u8                       behaviour_bmap;      /* �������Ϊλͼ λͼ�����mac_behaviour_bmap_enum */
    hi_u8                       coverage_class;      /* ������ */
    hi_u8                       max_reg_tx_pwr;      /* ������涨������͹���, ��λdBm */
    /* ʵ��ʹ�õ�����͹���, ��λdBm����ֵ������䣬���Աȹ�����涨���ʴ�TPC�㷨�ô�ֵ��Ϊ����͹��� */
    hi_u8                       max_tx_pwr;
    hi_u8                       auc_resv[2];         /* 2 BYTE�����ֶ� */
    hi_u32                      channel_bmap;        /* ֧���ŵ�λͼ���� 0011��ʾ֧�ֵ��ŵ���indexΪ0 1 */
}mac_regclass_info_stru;

/* ��������Ϣ�ṹ�� */
/* ������ֵ��������λͼ���������Ϣ �����±�Ĺ�ϵ
    ������ȡֵ        : .... 7  6  5  4  3  2  1  0
    ������λͼ        : .... 1  1  0  1  1  1  0  1
    ��������Ϣ�����±�: .... 5  4  x  3  2  1  x  0
*/
typedef struct {
    hi_char                   ac_country[WLAN_COUNTRY_STR_LEN];       /* �����ַ��� */
    hi_u8                     dfs_domain:4;                   /* DFS �״��׼ mac_dfs_domain_enum_uint8 */
    hi_u8                     regclass_num:4;                 /* ��������� */
    mac_regclass_info_stru    ast_regclass[WLAN_MAX_RC_NUM];  /* ����������Ĺ�������Ϣ��ע�� �˳�Աֻ�ܷ������һ��! */
}mac_regdomain_info_stru;

/* channel info�ṹ�� */
typedef struct {
    hi_u8       chan_number;     /* �ŵ��� */
    hi_u8       reg_class;       /* �������ڹ������е������� */
}mac_channel_info_stru;

/*****************************************************************************
  ��������
*****************************************************************************/
hi_void mac_init_channel_list(hi_void);
hi_void mac_init_regdomain(hi_void);
hi_void mac_regdomain_set_max_power(hi_u8 pwr, hi_u8 exceed_reg);
hi_void mac_get_channel_num_from_idx(hi_u8 band, hi_u8 idx, hi_u8 *puc_channel_num);
hi_void mac_set_country_ie_2g(mac_regdomain_info_stru *rd_info, hi_u8 *puc_buffer, hi_u8 *puc_len);
hi_char* mac_regdomain_get_country(hi_void);
hi_u32 mac_is_channel_idx_valid(hi_u8 band, hi_u8 ch_idx, hi_u8 *reg_class);
hi_u32 mac_is_channel_num_valid(hi_u8 band, hi_u8 ch_num);
hi_u32 mac_get_channel_idx_from_num(hi_u8 band, hi_u8 channel_num, hi_u8 *puc_channel_idx);
mac_regdomain_info_stru* mac_get_regdomain_info(hi_void);
mac_regclass_info_stru* mac_get_channel_num_rc_info(hi_u8 band, hi_u8 ch_num);

/*****************************************************************************
 ��������  : ͨ���ŵ����ҵ�Ƶ�Σ��ɵ����߱�֤������ŵ��źϷ����Ӷ����ͱ��ӿڵĸ����ԣ����Ч��
 �������  : hi_u8 uc_channel_num
 �� �� ֵ  : wlan_channel_band_enum_uint8
 �޸���ʷ      :
  1.��    ��   : 2015��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline wlan_channel_band_enum_uint8 mac_get_band_by_channel_num(hi_u8 channel_num)
{
    return (wlan_channel_band_enum_uint8)((channel_num <= MAC_CHANNEL_FREQ_2_BUTT) ? WLAN_BAND_2G : WLAN_BAND_BUTT);
}

/*****************************************************************************
 ��������  : ��ȡ��ǰƵ����֧�ֵ�����ŵ���Ŀ
 �������  : en_band: Ƶ��
 �� �� ֵ  : ��ǰƵ����֧�ֵ�����ŵ���Ŀ
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_get_num_supp_channel(wlan_channel_band_enum_uint8 band)
{
    switch (band) {
        case WLAN_BAND_2G:   /* 2.4GHz */
            return (hi_u8)MAC_CHANNEL_FREQ_2_BUTT;
        default:
            return 0;
    }
}

/*****************************************************************************
 ��������  : ��ȡ��Ӱ����ŵ�ƫ��ֵ
*****************************************************************************/
static inline hi_u8  mac_get_affected_ch_idx_offset(wlan_channel_band_enum_uint8 band)
{
    switch (band) {
        case WLAN_BAND_2G:   /* 2.4GHz */
            return (hi_u8)MAC_AFFECTED_CHAN_OFFSET_START_FREQ_2;
        default:
            return 0;
    }
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __MAC_REGDOMAIN_H__ */
