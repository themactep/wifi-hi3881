/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL layer external API interface implementation.
 * Author: shichongfu
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "stdio.h"
#include "stdlib.h"
#include <hi_at.h>
#include "at.h"
#include "hi_wifi_mfg_test_if.h"
#include "hi_wifi_api.h"
#include "string.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
hi_u32 at_hi_wifi_al_tx(hi_s32 argc, const hi_char *argv[])
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    hi_u32 ret = hi_wifi_at_start(argc, argv, HISI_AT_AL_TX);
    return ret;
}

hi_u32 at_hi_wifi_al_rx(hi_s32 argc, const hi_char *argv[])
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
            return HI_ERR_FAILURE;
    }
    hi_u32 ret = hi_wifi_at_start(argc, argv, HISI_AT_AL_RX);
    return ret;
}

hi_u32 at_hi_wifi_rx_info(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret = hi_wifi_at_start(argc, argv, HISI_AT_RX_INFO);
    return ret;
}

hi_u32 at_hi_wifi_set_country(hi_s32 argc, const hi_char *argv[])
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    hi_u32 ret = hi_wifi_at_start(argc, argv, HISI_AT_SET_COUNTRY);
    return ret;
}

hi_u32 at_hi_wifi_get_country(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret = hi_wifi_at_start(argc, argv, HISI_AT_GET_COUNTRY);
    return ret;
}

hi_u32 at_hi_wifi_set_tpc(hi_s32 argc, const hi_char *argv[])
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    hi_u32 ret = hi_wifi_at_start(argc, argv, HISI_AT_SET_TPC);
    return ret;
}

hi_u32 at_hi_wifi_set_rate_power_sub(hi_s32 argc, const hi_char *argv[], hi_bool tuning)
{
    hi_u8  protol, rate;
    hi_s32 val;
    hi_u8  ofs = tuning ? 1 : 0;
    hi_u8  protol_ofs = tuning ? 10 : 0; /* 10:�������ƫ��,�Ա�������at_hi_wifi_set_rate_power������ */
    hi_s32 low_limit = tuning ? -100 : -8; /* -100:������������,-8:������������ */
    hi_s32 up_limit = tuning ? 40 : 7; /* 40:������������,7:������������ */

    if ((at_param_null_check(argc, argv) == HI_ERR_FAILURE) || (argc != 3)) { /* ������̶�3������ */
        return HI_ERR_FAILURE;
    }

    /* get protol */
    if ((integer_check(argv[0]) != HI_ERR_SUCCESS) ||
        (atoi(argv[0]) < HI_WIFI_PHY_MODE_11BGN) || (atoi(argv[0]) > HI_WIFI_PHY_MODE_11B)) { /* ��Χ0~2 */
        return HI_ERR_FAILURE;
    }
    protol = (hi_u8)atoi(argv[0]);

    /* get rate */
    if (integer_check(argv[1]) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
    if (((protol == HI_WIFI_PHY_MODE_11BGN) && ((atoi(argv[1]) < 0) || (atoi(argv[1]) > 7 + ofs))) || /* 11n��Χ0~7 */
        ((protol == HI_WIFI_PHY_MODE_11BG) && ((atoi(argv[1]) < 0) || (atoi(argv[1]) > 7 + ofs))) ||  /* 11g��Χ0~7 */
        ((protol == HI_WIFI_PHY_MODE_11B) && ((atoi(argv[1]) < 0) || (atoi(argv[1]) > 3 + ofs)))) { /* 11b��Χ0~3 */
        return HI_ERR_FAILURE;
    }
    rate = (hi_u8)atoi(argv[1]);

    /* get val */
    if (argv[2][0] == '-') { /* ����2 */
        if (((argv[2][1] != '\0') && (integer_check(&argv[2][1]) != HI_ERR_SUCCESS)) || /* ����2 */
            (argv[2][1] == '\0')) { /* ����2 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (integer_check(argv[2]) != HI_ERR_SUCCESS) { /* ����2 */
            return HI_ERR_FAILURE;
        }
    }
    if ((atoi(argv[2]) < low_limit) || (atoi(argv[2]) > up_limit)) { /* 2:�±� */
        return HI_ERR_FAILURE;
    }
    val = atoi(argv[2]); /* ����2 */
    protol += protol_ofs; /* Э������ƫ���������з����Ի��ǲ������� */

    hi_u32 ret = wal_set_cal_rate_power(protol, rate, val);
    if (ret == HI_ERR_SUCCESS) {
        return ret;
    }

    return ret;
}

/*****************************************************************************
 ��������  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ��������ͻ��з�������,��дefuse
 �������  : [1]argc �����������
             [2]argv ����ָ��
 �������  : ��
 �� �� ֵ  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ�����at������в�������У�� �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 at_hi_wifi_set_rate_power(hi_s32 argc, const hi_char *argv[])
{
    return at_hi_wifi_set_rate_power_sub(argc, argv, HI_TRUE);
}

/*****************************************************************************
 ��������  : ���г���Ƶƫ���ʲ�����at������в�������У��
 �������  : [1]argc �����������
             [2]argv ����ָ��
 �������  : ��
 �� �� ֵ  : ���г���Ƶƫ���ʲ�����at������в�������У�� �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 at_hi_wifi_set_cal_freq(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 freq_offset;

    if ((at_param_null_check(argc, argv) == HI_ERR_FAILURE) || (argc != 1)) { /* ������̶�1������ */
        return HI_ERR_FAILURE;
    }

    /* get freq offset */
    if (argv[0][0] == '-') {
        if (((argv[0][1] != '\0') && (integer_check(&argv[0][1]) != HI_ERR_SUCCESS)) ||
            (argv[0][1] == '\0')) {
            return HI_ERR_FAILURE;
        }
    } else {
        if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }
    if ((atoi(argv[0]) < -128) || (atoi(argv[0]) > 127)) { /* ��Χ-128~127 */
        return HI_ERR_FAILURE;
    }
    freq_offset = atoi(argv[0]);

    hi_u32 ret = wal_set_cal_freq(freq_offset);
    if (ret == HI_ERR_SUCCESS) {
        return ret;
    }

    return ret;
}

/*****************************************************************************
 ��������  : �Ը�band��ƽ�����ʲ�����at������в�������У��
 �������  : [1]argc �����������
             [2]argv ����ָ��
 �������  : ��
 �� �� ֵ  : �Ը�band��ƽ�����ʲ�����at������в�������У�� �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 at_hi_wifi_set_cal_band_power(hi_s32 argc, const hi_char *argv[])
{
    hi_u8  band_num;
    hi_s32 offset;

    if ((at_param_null_check(argc, argv) == HI_ERR_FAILURE) || (argc != 2)) { /* ������̶�2������ */
        return HI_ERR_FAILURE;
    }

    /* get band num */
    if ((integer_check(argv[0]) != HI_ERR_SUCCESS) || (atoi(argv[0]) < 0) || (atoi(argv[0]) > 2)) { /* ��Χ0~2 */
        return HI_ERR_FAILURE;
    }
    band_num = (hi_u8)atoi(argv[0]);

    /* get power offset */
    if (argv[1][0] == '-') {
        if (((argv[1][1] != '\0') && (integer_check(&argv[1][1]) != HI_ERR_SUCCESS)) ||
            (argv[1][1] == '\0')) {
            return HI_ERR_FAILURE;
        }
    } else {
        if (integer_check(argv[1]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }
    if ((atoi(argv[1]) < -60) || (atoi(argv[1]) > 60)) { /* ������Χ-60~60 */
        return HI_ERR_FAILURE;
    }
    offset = atoi(argv[1]);

    hi_u32 ret = wal_set_cal_band_power(band_num, offset);
    if (ret == HI_ERR_SUCCESS) {
        return ret;
    }

    return ret;
}

/*****************************************************************************
 ��������  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ�����at������в�������У��.��������
 �������  : [1]argc �����������
             [2]argv ����ָ��
 �������  : ��
 �� �� ֵ  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ�����at������в�������У�� �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 at_hi_wifi_set_cal_rate_power(hi_s32 argc, const hi_char *argv[])
{
    return at_hi_wifi_set_rate_power_sub(argc, argv, HI_FALSE);
}

hi_u32 at_hi_wifi_get_customer_mac(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argc);
    hi_unref_param(argv);

    hi_u32 ret = wal_get_efuse_mac();
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 at_hi_wifi_set_customer_mac(hi_s32 argc, const hi_char *argv[])
{
    hi_uchar mac_addr[6]; /* 6:�±� */
    hi_u8    type = 0; /* Ĭ��Ϊ0,�����浽efuse */
    if ((argc < 1) || (argc > 2) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) { /* 2:�������� */
        return HI_ERR_FAILURE;
    }

    if (strlen(argv[0]) != 17) { /* 17:MAC_ADDR_LEN */
        return HI_ERR_FAILURE;
    }

    hi_u32 ret = cmd_strtoaddr(argv[0], mac_addr, 6);  /* 6:lenth */
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
    if (argc == 2) { /* 2:����������type���� */
        /* get type */
        if (integer_check(argv[1]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        type = (hi_u8)atoi(argv[1]);
        if ((type != 0) && (type != 1)) { /* ��Χ0,1 */
            return HI_ERR_FAILURE;
        }
    }
    if (wal_set_efuse_mac((hi_char*)mac_addr, type) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 at_hi_wifi_set_dataefuse(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 type = 0; /* Ĭ��Ϊ0,�����浽efuse */

    if ((argc == 1) && (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    if (argc == 1) { /* ����������type���� */
        /* get type */
        if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        type = (hi_u32)atoi(argv[0]);
        if ((type != 0) && (type != 1)) { /* ��Χ0,1 */
            return HI_ERR_FAILURE;
        }
    }

    hi_u32 ret = wal_set_dataefuse(type);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 at_hi_wifi_get_cal_data(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argc);
    hi_unref_param(argv);

    hi_u32 ret = wal_get_cal_data();
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 at_hi_wifi_ftm_mode(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argc);
    hi_unref_param(argv);
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 at_hi_wifi_ftm_ok(hi_void)
{
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 at_hi_wifi_ftm_erase(hi_void)
{
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 at_wifi_ifconfig(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    if (argc == 2) { /* 2:�������� */
        if (strcmp(argv[0], "wlan0") != 0) {
            return HI_ERR_FAILURE;
        }
        if ((strcmp(argv[1], "down") != 0) && (strcmp(argv[1], "up") != 0)) {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 at_wifi_get_tx_params(hi_s32 argc, const hi_char **argv)
{
    hi_unref_param(argc);
    hi_unref_param(argv);

    hi_wifi_get_tx_params("wlan0", strlen("wlan0"));
    return HI_ERR_SUCCESS;
}

const at_cmd_func g_at_factory_test_func_tbl[] = {
#ifdef CONFIG_MFG_TEST
    {"+CALBPWR", 8, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_set_cal_band_power, HI_NULL},
    {"+CALRPWR", 8, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_set_cal_rate_power, HI_NULL},
    {"+EFUSEMAC", 9, HI_NULL, (at_call_back_func)at_hi_wifi_get_customer_mac,
        (at_call_back_func)at_hi_wifi_set_customer_mac, HI_NULL},
    {"+WCALDATA", 9, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_set_dataefuse,
        (at_call_back_func)at_hi_wifi_set_dataefuse},
#endif
    {"+ALTX", 5, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_al_tx, HI_NULL},
    {"+ALRX", 5, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_al_rx, HI_NULL},
    {"+CALFREQ", 8, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_set_cal_freq, HI_NULL},
    {"+SETRPWR", 8, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_set_rate_power, HI_NULL},
    {"+RCALDATA", 9, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_get_cal_data},
    {"+RXINFO", 7, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_rx_info},
    {"+CC", 3, HI_NULL, (at_call_back_func)at_hi_wifi_get_country, (at_call_back_func)at_hi_wifi_set_country, HI_NULL},
    {"+TPC", 4, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_set_tpc, HI_NULL},
    {"+FTM", 4, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_ftm_mode, HI_NULL},
    {"+FTMOK", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_ftm_ok},
    {"+FTMERASE", 9, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_hi_wifi_ftm_erase},
    {"+IFCFG", 6, HI_NULL, HI_NULL, (at_call_back_func)at_wifi_ifconfig, (at_call_back_func)at_wifi_ifconfig},
    {"+GETTP", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_wifi_get_tx_params}
};
#define AT_HIPRIV_FACTORY_TEST_FUNC_NUM (sizeof(g_at_factory_test_func_tbl) / sizeof(g_at_factory_test_func_tbl[0]))

void hi_at_factory_test_cmd_register(void)
{
    hi_at_register_cmd(g_at_factory_test_func_tbl, AT_HIPRIV_FACTORY_TEST_FUNC_NUM);
}

void hi_at_factory_shell_cmd_register(void)
{
    hi_at_factory_test_cmd_register();
}


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

