/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Regulatory domain information definition.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "mac_regdomain.h"
#include "mac_device.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/* ��������Ϣȫ�ֱ��� */
mac_regdomain_info_stru g_mac_regdomain;

mac_channel_info_stru g_ast_channel_list_2g[MAC_CHANNEL_FREQ_2_BUTT] = {
    {1,  MAC_INVALID_RC}, {2,  MAC_INVALID_RC}, {3,  MAC_INVALID_RC},
    {4,  MAC_INVALID_RC}, {5,  MAC_INVALID_RC}, {6,  MAC_INVALID_RC},
    {7,  MAC_INVALID_RC}, {8,  MAC_INVALID_RC}, {9,  MAC_INVALID_RC},
    {10, MAC_INVALID_RC}, {11, MAC_INVALID_RC}, {12, MAC_INVALID_RC},
    {13, MAC_INVALID_RC}, {14, MAC_INVALID_RC},
};

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ��ȡ��������Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��9��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
mac_regdomain_info_stru* mac_get_regdomain_info(hi_void)
{
    return &g_mac_regdomain;
}

/*****************************************************************************
 ��������  : ��ʼ��Ĭ�Ϲ�����2.4G��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2019��7��28��
    ��    ��   : Hisilicon
*****************************************************************************/
hi_void mac_init_regdomain_2g(hi_void)
{
    mac_regclass_info_stru *regclass = HI_NULL;

    regclass = &(g_mac_regdomain.ast_regclass[0]);
    regclass->start_freq     = MAC_RC_START_FREQ_2;
    regclass->ch_spacing     = MAC_CH_SPACING_5MHZ;
    regclass->behaviour_bmap = 0;
    regclass->coverage_class = 0;
    regclass->max_reg_tx_pwr = MAC_RC_DEFAULT_MAX_TX_PWR;
    regclass->max_tx_pwr     = MAC_RC_DEFAULT_MAX_TX_PWR;
    regclass->channel_bmap = bit(MAC_CHANNEL1) |
                                    bit(MAC_CHANNEL2) |
                                    bit(MAC_CHANNEL3) |
                                    bit(MAC_CHANNEL4) |
                                    bit(MAC_CHANNEL5) |
                                    bit(MAC_CHANNEL6) |
                                    bit(MAC_CHANNEL7) |
                                    bit(MAC_CHANNEL8) |
                                    bit(MAC_CHANNEL9) |
                                    bit(MAC_CHANNEL10) |
                                    bit(MAC_CHANNEL11) |
                                    bit(MAC_CHANNEL12) |
                                    bit(MAC_CHANNEL13);
}

/*****************************************************************************
 ��������  : ��ʼ��Ĭ�Ϲ�������Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_init_regdomain(hi_void)
{
    hi_char                 ac_default_country[WLAN_COUNTRY_STR_LEN] = "99";

    if (memcpy_s(g_mac_regdomain.ac_country, WLAN_COUNTRY_STR_LEN, ac_default_country,
                 WLAN_COUNTRY_STR_LEN) != EOK) {
        return;
    }
    /* ��ʼĬ�ϵĹ��������Ϊ1 */
    g_mac_regdomain.regclass_num = 1;

    /*************************************************************************
        ��ʼ��������1 2.4G
    *************************************************************************/
    mac_init_regdomain_2g();
}

/*****************************************************************************
 ��������  : ���ݹ������ʼ���ŵ��б�
 �޸���ʷ      :
  1.��    ��   : 2013��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_init_channel_list(hi_void)
{
    hi_u8                ch_idx;
    hi_u8                rc_num;
    hi_u8                rc_idx;
    mac_regdomain_info_stru *rd_info = HI_NULL;
    mac_regclass_info_stru  *rc_info = HI_NULL;

    rd_info = &g_mac_regdomain;
    /* �ȳ�ʼ�������ŵ��Ĺ�����Ϊ��Ч */
    for (ch_idx = 0; ch_idx < MAC_CHANNEL_FREQ_2_BUTT; ch_idx++) {
        g_ast_channel_list_2g[ch_idx].reg_class = MAC_INVALID_RC;
    }

    /* Ȼ����ݹ���������ŵ��Ĺ�������Ϣ */
    rc_num = rd_info->regclass_num;
    /* ����2GƵ�����ŵ��Ĺ�������Ϣ */
    for (rc_idx = 0; rc_idx < rc_num; rc_idx++) {
        rc_info = &(rd_info->ast_regclass[rc_idx]);
        if (rc_info->start_freq != MAC_RC_START_FREQ_2) {
            continue;
        }
        for (ch_idx = 0; ch_idx < MAC_CHANNEL_FREQ_2_BUTT; ch_idx++) {
            if (rc_info->channel_bmap & bit(ch_idx)) {
                g_ast_channel_list_2g[ch_idx].reg_class = rc_idx;
            }
        }
    }
}

/*****************************************************************************
 ��������  : ��ȡ1���ŵ������Ĺ�������Ϣ
 �������  : uc_band: Ƶ�Σ�0-2.4G, 1-5G
             uc_ch_idx: �ŵ�������
 �޸���ʷ      :
  1.��    ��   : 2013��10��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
mac_regclass_info_stru* mac_get_channel_idx_rc_info(hi_u8 band, hi_u8 ch_idx)
{
    hi_u8 reg_class;

    if (mac_is_channel_idx_valid(band, ch_idx, &reg_class) != HI_SUCCESS) {
        return HI_NULL;
    }

    return &(g_mac_regdomain.ast_regclass[reg_class]);
}

/*****************************************************************************
 ��������  : ���ŵ�����ֵ�����ŵ���
 �޸���ʷ      :
  1.��    ��   : 2013��4��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_get_channel_num_from_idx(hi_u8 band, hi_u8 idx, hi_u8 *puc_channel_num)
{
    if (band == MAC_RC_START_FREQ_2) {
        if (idx >= MAC_CHANNEL_FREQ_2_BUTT) {
            return;
        }
        *puc_channel_num = g_ast_channel_list_2g[idx].chan_number;
    }
}

/*****************************************************************************
 ��������  : ͨ���ŵ����ҵ��ŵ�������
 �޸���ʷ      :
  1.��    ��   : 2013��7��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_get_channel_idx_from_num(hi_u8 band, hi_u8 channel_num, hi_u8 *puc_channel_idx)
{
    mac_channel_info_stru       *channel = HI_NULL;
    hi_u8                    total_channel_num  = 0;
    hi_u8                    idx;

    /* ����Ƶ�λ�ȡ�ŵ���Ϣ */
    switch (band) {
        case MAC_RC_START_FREQ_2:
            channel = g_ast_channel_list_2g;
            total_channel_num = (hi_u8)MAC_CHANNEL_FREQ_2_BUTT;
            break;
        default:
            return HI_ERR_CODE_INVALID_CONFIG;
    }
    /* ����ŵ������� */
    for (idx = 0; idx < total_channel_num; idx++) {
        if (channel[idx].chan_number == channel_num) {
            *puc_channel_idx = idx;
            return HI_SUCCESS;
        }
    }
    return HI_ERR_CODE_INVALID_CONFIG;
}

/*****************************************************************************
 ��������  : ���ݹ������ж��ŵ��������Ƿ���Ч
 �޸���ʷ      :
  1.��    ��   : 2013��9��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_is_channel_idx_valid(hi_u8 band, hi_u8 ch_idx, hi_u8 *reg_class)
{
    hi_u8               max_ch_idx;
    mac_channel_info_stru  *ch_info = HI_NULL;

    switch (band) {
        case MAC_RC_START_FREQ_2:
            max_ch_idx = MAC_CHANNEL_FREQ_2_BUTT;
            ch_info   = &(g_ast_channel_list_2g[ch_idx]);
            break;
        default:
            return HI_ERR_CODE_INVALID_CONFIG;
    }

    if (ch_idx >= max_ch_idx) {
        return HI_ERR_CODE_ARRAY_OVERFLOW;
    }
    if (ch_info->reg_class != MAC_INVALID_RC) {
        if (reg_class != HI_NULL) {
            *reg_class = ch_info->reg_class;
        }
        return HI_SUCCESS;
    }
    return HI_ERR_CODE_INVALID_CONFIG;
}

/*****************************************************************************
 ��������  : ����ŵ����Ƿ�Ϸ�
 �������  : en_band  : Ƶ��
             uc_ch_num: �ŵ���
 �� �� ֵ  : HI_TRUE��HI_FALSE
 �޸���ʷ      :
  1.��    ��   : 2013��4��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_is_channel_num_valid(hi_u8 band, hi_u8 ch_num)
{
    hi_u8  ch_idx;
    hi_u32 ret;

    ret = mac_get_channel_idx_from_num(band, ch_num, &ch_idx);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    ret = mac_is_channel_idx_valid(band, ch_idx, HI_NULL);
    return ret;
}

/*****************************************************************************
 ��������  : ��ȡ�ŵ��Ź�������Ϣ
 �������  : uc_band: Ƶ�Σ�0-2.4G, 1-5G
             uc_ch_num: �ŵ�������
 �޸���ʷ      :
  1.��    ��   : 2013��10��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
mac_regclass_info_stru* mac_get_channel_num_rc_info(hi_u8 band, hi_u8 ch_num)
{
    hi_u8   channel_idx;

    if (HI_SUCCESS != mac_get_channel_idx_from_num(band, ch_num, &channel_idx))  {
        oam_warning_log2(0, OAM_SF_ANY,
            "{mac_get_channel_num_rc_info::mac_get_channel_idx_from_num failed. band:%d, ch_num:%d",
            band, ch_num);
        return HI_NULL;
    }
    return mac_get_channel_idx_rc_info(band, channel_idx);
}

/*****************************************************************************
 ��������  : ���ù���������͹���
 �������  : uc_pwr       : ����
             en_exceed_reg: �Ƿ���Գ�������������
 �޸���ʷ      :
  1.��    ��   : 2014��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_regdomain_set_max_power(hi_u8 pwr, hi_u8 exceed_reg)
{
    hi_u8 rc_idx;
    hi_u8 reg_pwr;

    for (rc_idx = 0; rc_idx < g_mac_regdomain.regclass_num; rc_idx++) {
        reg_pwr = g_mac_regdomain.ast_regclass[rc_idx].max_reg_tx_pwr;
        if (pwr <= reg_pwr || exceed_reg) {
            g_mac_regdomain.ast_regclass[rc_idx].max_tx_pwr = pwr;
        } else {
            oam_warning_log3(0, OAM_SF_TPC, "uc_pwr[%d] exceed reg_tx_pwr[%d], rc_idx[%d]", pwr, reg_pwr, rc_idx);
        }
    }
}

/*****************************************************************************
 ��������  : 2GƵ����д������
 �������  : pst_rd_info: ��������Ϣ
             puc_buffer : ��дƵ����Ԫ����ʼbuffer��ַ
 �������  : puc_len    : ����д��Ԫ��ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��11��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void mac_set_country_ie_2g(mac_regdomain_info_stru *rd_info, hi_u8 *puc_buffer, hi_u8 *puc_len)
{
    hi_u8                rc_idx;
    hi_u8                lsb_bit_position;
    mac_regclass_info_stru  *reg_class = HI_NULL;
    hi_u8                len = 0;

    for (rc_idx = 0; rc_idx < rd_info->regclass_num; rc_idx++) {
        /* ��ȡ Regulatory Class */
        reg_class = &(rd_info->ast_regclass[rc_idx]);
        /* ���Ƶ�β�ƥ�� */
        if (MAC_RC_START_FREQ_2 != reg_class->start_freq) {
            continue;
        }
        /* �쳣��飬�ŵ�λͼΪ0��ʾ�˹�����û���ŵ����ڣ������� */
        if (reg_class->channel_bmap == 0) {
            continue;
        }
        /* ��ȡ�ŵ�λͼ�����һλ, ����0����bit0��1 */
        lsb_bit_position = oal_bit_find_first_bit_four_byte(reg_class->channel_bmap);
        /* ��ȡ�ŵ��ţ�����Channel_MapΪ1100�����Ӧ������ֵΪ2��3����������ֵ�ҵ��ŵ��� */
        mac_get_channel_num_from_idx(MAC_RC_START_FREQ_2, lsb_bit_position, &puc_buffer[len++]);
        /* ��ȡ�ŵ��� */
        puc_buffer[len++] = (hi_u8)oal_bit_get_num_four_byte(reg_class->channel_bmap);
        /* ��ȡ����� */
        puc_buffer[len++] = reg_class->max_reg_tx_pwr;
    }
    *puc_len = len;
    return;
}

/*****************************************************************************
 ��������  : ��ȡ�����ַ�
 �޸���ʷ      :
  1.��    ��   : 2013��10��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_char* mac_regdomain_get_country(hi_void)
{
    return g_mac_regdomain.ac_country;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
