/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL layer external API interface implementation.
 * Author: Hisilicon
 * Create: 2019-11-11
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "stdio.h"
#include "stdlib.h"
#include "hi_stdlib.h"
#include "hi_wifi_api.h"
#include "at_wifi.h"
#include <hi_at.h>
#include "at_general.h"
#include "at.h"
#ifndef CONFIG_FACTORY_TEST_MODE
#include "lwip/netifapi.h"
#endif
#include "hi_wifi_mfg_test_if.h" /* 本文件中hi_wifi_mfg_test_if.h有使用 */
#include "hi_wifi_csi_api.h"
#include "plat_pm_wlan.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_wifi_bw g_bw_setup_value = HI_WIFI_BW_LEGACY_20M;

#define HI3881_VAP_TYPE_NUM 2
typedef enum {
    AT_VAP_UNKNOWN,
    AT_VAP_STA,
    AT_VAP_AP,

    AT_VAP_BUTT
} at_ifname_vaptype;

typedef struct {
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1];
    at_ifname_vaptype type;
} at_ifname_stru;

at_ifname_stru g_ifname[HI3881_VAP_TYPE_NUM] = {{{0}, AT_VAP_UNKNOWN}, {{0}, AT_VAP_UNKNOWN}};

hi_u32 ssid_prefix_scan(hi_s32 argc, const hi_char *argv[], hi_u32 prefix_flag)
{
    hi_s32  ret;
    errno_t rc;
    char   *tmp = HI_NULL;
    size_t  ssid_len = 0;
    hi_wifi_scan_params scan_params = {0};

    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }
    /* ssid hex to string */
    tmp = at_parse_string(argv[0], &ssid_len);
    scan_params.ssid_len = (unsigned char)ssid_len;
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((scan_params.ssid_len > HI_WIFI_MAX_SSID_LEN) || (scan_params.ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }
    rc = memcpy_s(scan_params.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }

    scan_params.ssid[scan_params.ssid_len] = '\0';

    scan_params.scan_type = (prefix_flag == 1) ? HI_WIFI_SSID_PREFIX_SCAN : HI_WIFI_SSID_SCAN;

    ret = hi_wifi_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}


/*****************************************************************************
* Func description: wpa ssid scan
*****************************************************************************/
hi_u32 cmd_wpa_ssid_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret = ssid_prefix_scan(argc, argv, 0);
    return ret;
}

/*****************************************************************************
* Func description: wpa  channel scan
*****************************************************************************/
hi_u32 cmd_wpa_channel_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_wifi_scan_params scan_params = {0};

    if ((argc != 1) || (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    scan_params.channel = (hi_uchar)atoi(argv[0]);
    if ((scan_params.channel < 1) || (scan_params.channel > 14)) { /* 信道范围1~14 */
        return HI_ERR_FAILURE;
    }
    scan_params.scan_type = HI_WIFI_CHANNEL_SCAN;
    ret = hi_wifi_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: wpa scan
*****************************************************************************/
hi_u32 cmd_wpa_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;

    hi_unref_param(argc);
    hi_unref_param(argv);

    ret = hi_wifi_sta_scan();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: ssid prefix scan
* example: AT+SCANPRSSID="hisi"
*****************************************************************************/
hi_u32 cmd_ssid_prefix_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret = ssid_prefix_scan(argc, argv, 1);
    return ret;
}

hi_u32 at_check_ccharacter(const hi_char *tmp)
{
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    for (; *tmp != '\0'; tmp++) {
        if (*tmp == '\\') {
            if (*(tmp + 1) == '\\') {
                tmp++;
                continue;
            } else if (*(tmp + 1) == 'x') {
                return HI_ERR_SUCCESS;
            }
        }
    }
    return HI_ERR_FAILURE;
}

/*****************************************************************************
* Func description: wpa get scan results
*****************************************************************************/
hi_u32 cmd_wpa_scan_results(hi_s32 argc, const hi_char *argv[])
{
    hi_u32  num = WIFI_SCAN_AP_LIMIT ;
    hi_char ssid_str[HI_WIFI_MAX_SSID_LEN * 4 + 4]; /* ssid length should less 32*4+4 */

    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_wifi_ap_info *results = malloc(sizeof(hi_wifi_ap_info) * WIFI_SCAN_AP_LIMIT);
    if (results == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    /* 安全编程规则6.6例外（3）从堆中分配内存后，赋予初值 */
    memset_s(results, sizeof(hi_wifi_ap_info) * WIFI_SCAN_AP_LIMIT, 0, sizeof(hi_wifi_ap_info) * WIFI_SCAN_AP_LIMIT);

    hi_s32 ret = hi_wifi_sta_scan_results(results, &num);
    if (ret != HISI_OK) {
        free(results);
        return HI_ERR_FAILURE;
    }

    hi_at_printf("%32s,%17s,%3s,%4s,%s\r\n", "SSID", "Mac Addr", "Chn", "RSSI", "Auth");
    for (hi_u32 ul_loop = 0; (ul_loop < num) && (ul_loop < WIFI_SCAN_AP_LIMIT); ul_loop++) {
        if ((results[ul_loop].auth < HI_WIFI_SECURITY_OPEN) || (results[ul_loop].auth > HI_WIFI_SECURITY_UNKNOWN)) {
            results[ul_loop].auth = HI_WIFI_SECURITY_UNKNOWN;
        }

        hi_u32 auth_type = results[ul_loop].auth;
        hi_u32 service_flag = 0;
        if (results[ul_loop].wps_flag) {
            service_flag = 1;
        } else if (results[ul_loop].hisi_mesh_flag) {
            service_flag = 2; /* 2:Mesh场景 */
        }

        size_t ssid_len = strlen(results[ul_loop].ssid);
        const char* tmp = at_ssid_txt((unsigned char*)results[ul_loop].ssid, ssid_len);
        if (at_check_ccharacter(tmp) == HI_ERR_SUCCESS) {
            ret = sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 4, "P\"%s\"", tmp); /* ssid len should less 32*4+4 */
        } else {
            ret = sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 4, "%s", results[ul_loop].ssid); /* less 32*4+4 */
        }
        if (ret < 0) {
            free(results);
            return HI_ERR_FAILURE;
        }

        if (service_flag != 0) {
            hi_at_printf("%32s,"AT_MACSTR",%3d,%4d,%2d,%d\r\n", ssid_str, at_mac2str(results[ul_loop].bssid),
                results[ul_loop].channel, results[ul_loop].rssi / 100, auth_type, service_flag);
        } else {
            hi_at_printf("%32s,"AT_MACSTR",%3d,%4d,%2d\r\n", ssid_str, at_mac2str(results[ul_loop].bssid),
                results[ul_loop].channel, results[ul_loop].rssi / 100, auth_type);
        }
    }

    free(results);

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start sta
*****************************************************************************/
hi_u32 cmd_sta_start(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);
#ifndef CONFIG_FACTORY_TEST_MODE
    hi_s32  ret;
    hi_s32  i = 0;
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;
    hi_s32  len = sizeof(ifname);

    ret = hi_wifi_sta_start(ifname_point, &len);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_UNKNOWN) {
            if (memcpy_s(g_ifname[i].ifname, WIFI_IFNAME_MAX_SIZE + 1,
                ifname_point, WIFI_IFNAME_MAX_SIZE + 1) != EOK) {
                return HI_ERR_FAILURE;
            }
            g_ifname[i].type = AT_VAP_STA;
            break;
        }
    }
#else
    if (wal_add_cfg_vap() != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
#endif
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 sta_start_adv_param(hi_s32 argc, const hi_char *argv[], hi_wifi_bw *bw)
{
    hi_s32  ret, value, i;
    for (i = 0; i < argc; i++) {
        if ((argv[i] != HI_NULL) && (integer_check(argv[i]) != HI_ERR_SUCCESS)) {
            return HI_ERR_FAILURE;
        }
        switch (i) {
            case 0: /* 第0个参数: 协议类型 */
                value = (argv[i] != HI_NULL) ? atoi(argv[i]) : HI_WIFI_PHY_MODE_11BGN;
                if ((value == HI_WIFI_PHY_MODE_11B) && (argv[1] != HI_NULL) && (strcmp(argv[1], "20"))) { /* 20:bw */
                    return HI_ERR_FAILURE;
                }
#ifndef CONFIG_FACTORY_TEST_MODE
                ret = hi_wifi_sta_set_protocol_mode((hi_wifi_protocol_mode)value);
#endif
                break;
            case 1: /* 第1个参数: 带宽 */
                if ((argv[i] == HI_NULL) || !(strcmp(argv[i], "20"))) { /* bw 20M */
                    *bw = HI_WIFI_BW_LEGACY_20M;
                } else if (!(strcmp(argv[i], "10"))) { /* bw 10M */
                    *bw = HI_WIFI_BW_HIEX_10M;
                } else if (!(strcmp(argv[i], "5"))) { /* bw 5M */
                    *bw = HI_WIFI_BW_HIEX_5M;
                } else {
                    return HI_ERR_FAILURE;
                }
                ret = HISI_OK;
                break;
            case 2: /* 第2个参数: pmf */
#ifndef CONFIG_FACTORY_TEST_MODE
                value = (argv[i] != HI_NULL) ? atoi(argv[i]) : HI_WIFI_MGMT_FRAME_PROTECTION_OPTIONAL;
                ret = hi_wifi_set_pmf((hi_wifi_pmf_options)value);
#endif
                break;
            default:
                return HI_ERR_FAILURE;
        }
#ifndef CONFIG_FACTORY_TEST_MODE
        if (ret != HISI_OK) {
            return HI_ERR_FAILURE;
        }
#endif
    }
    hi_unref_param(ret);
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_start_adv(hi_s32 argc, const hi_char *argv[])
{
    hi_s32  ret;
    hi_wifi_bw bw = HI_WIFI_BW_LEGACY_20M;
    hi_s32  i = 0;

    if (argc != 3) { /* "+STARTSTA"命令固定3个命令参数 */
        return HI_ERR_FAILURE;
    }

    ret = (hi_s32)sta_start_adv_param(argc, argv, &bw);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
#ifndef CONFIG_FACTORY_TEST_MODE
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;
    hi_s32 len = sizeof(ifname);

    ret = hi_wifi_sta_start(ifname_point, &len);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
#endif
    ret = hi_wifi_set_bandwidth(ifname_point, strlen(ifname_point) + 1, bw);
    if (ret != HI_ERR_SUCCESS) {
#ifndef CONFIG_FACTORY_TEST_MODE
        hi_wifi_sta_stop();
#endif
        return HI_ERR_FAILURE;
    }

#ifndef CONFIG_FACTORY_TEST_MODE
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_UNKNOWN) {
            memcpy_s(g_ifname[i].ifname, WIFI_IFNAME_MAX_SIZE + 1, ifname_point, WIFI_IFNAME_MAX_SIZE + 1);
            g_ifname[i].type = AT_VAP_STA;
            break;
        }
    }
#endif
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: stop station
*****************************************************************************/
hi_u32 cmd_sta_stop(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);
    hi_s32 i;
#ifndef CONFIG_FACTORY_TEST_MODE
    hi_u8 is_found = HI_FALSE;
    struct netif *sta_netif = NULL;
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_STA) {
            is_found = HI_TRUE;
            break;
        }
    }
    if (is_found == HI_FALSE) {
        return HI_ERR_FAILURE;
    }
    sta_netif = netif_find(g_ifname[i].ifname);

    netifapi_dhcp_stop(sta_netif);

    hi_s32 ret = hi_wifi_sta_stop();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
#endif
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_STA) {
            memset_s(g_ifname[i].ifname, WIFI_IFNAME_MAX_SIZE + 1, 0, WIFI_IFNAME_MAX_SIZE + 1);
            g_ifname[i].type = AT_VAP_UNKNOWN;
        }
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_connect_get_ssid(const hi_char *argv[], hi_wifi_assoc_request *assoc_req,
    hi_wifi_fast_assoc_request *fast_assoc_req, hi_u32 fast_flag)
{
    size_t ssid_len = 0;
    errno_t rc;

    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }

    /* ssid hex to string */
    hi_char *tmp = at_parse_string(argv[0], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((ssid_len > HI_WIFI_MAX_SSID_LEN) || (ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }

    if ((fast_flag == 0) && (assoc_req != HI_NULL)) {
        rc = memcpy_s(assoc_req->ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
        at_free(tmp);
        if (rc != EOK) {
            return HI_ERR_FAILURE;
        }
    } else if ((fast_flag == 1) && (fast_assoc_req != HI_NULL)) {
        rc = memcpy_s(fast_assoc_req->req.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
        at_free(tmp);
        if (rc != EOK) {
            return HI_ERR_FAILURE;
        }
    } else {
        at_free(tmp);
    }
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_connect_get_key(hi_s32 argc, const hi_char *argv[], hi_wifi_fast_assoc_request *fast_assoc_req)
{
    if ((fast_assoc_req->req.auth != HI_WIFI_SECURITY_OPEN) && (argc == 5)) { /* 5:命令参数个数 */
        if (argv[4] == HI_NULL) { /* 4:key */
            return HI_ERR_FAILURE;
        }
        const hi_char *buf = argv[4]; /* 4:key */

        size_t len = strlen(argv[4]); /* 4:key */
        if ((atoi(argv[3]) == HI_WIFI_SECURITY_WEP) && (len != 9) && (len != 17) && /* 3:加密方式 9:17:密码长度 */
            (len != 12) && (len != 28)) { /* 12:28 密码长度 */
            return HI_ERR_FAILURE;
        } else if ((atoi(argv[3]) != HI_WIFI_SECURITY_WEP) && ((len > HI_WIFI_AP_KEY_LEN_MAX + 2) || /* 2:引号长度3 */
            (len < HI_WIFI_AP_KEY_LEN_MIN + 2))) { /* 2:引号长度 */
            return HI_ERR_FAILURE;
        }
        if ((buf == HI_NULL) || (*buf != '\"') || (*(buf + strlen(argv[4]) - 1) != '\"') || /* 4 */
            (memcpy_s(fast_assoc_req->req.key, HI_WIFI_MAX_KEY_LEN + 1, buf + 1, strlen(argv[4]) - 2)  /* 4 2 */
            != EOK)) {
            return HI_ERR_FAILURE;
        }
    }

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: station connect network
* example: AT+CONN="hisilicon",,3,"123456789"
*****************************************************************************/
hi_u32 cmd_sta_connect(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_assoc_request assoc_req = {0};

    if ((argc < 3) || (argc > 4)) { /* "+CONN"命令的参数个数固定为3或4 */
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if ((argv[0] != HI_NULL) && (cmd_sta_connect_get_ssid(argv, &assoc_req, HI_NULL, 0) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    /* get bssid */
    if (argv[1] == HI_NULL) {
        /* 安全编程规则6.6例外（2）结构体赋予初值 */
        memset_s(assoc_req.bssid, sizeof(assoc_req.bssid), 0, sizeof(assoc_req.bssid));
    } else if (strlen(argv[1]) == HI_WIFI_TXT_ADDR_LEN) {
        if (cmd_strtoaddr(argv[1], assoc_req.bssid, HI_WIFI_MAC_LEN) != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }

    /* get auth_type */
    if ((integer_check(argv[2]) != HI_ERR_SUCCESS) || (atoi(argv[2]) < HI_WIFI_SECURITY_OPEN) || /* 2认证方式 */
        (atoi(argv[2]) > HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX) || ((atoi(argv[2]) == HI_WIFI_SECURITY_OPEN) && /* 2 */
        (argc != 3)) || ((atoi(argv[2]) != HI_WIFI_SECURITY_OPEN) && (argc != 4))) { /* 2认证方式34密码 */
        return HI_ERR_FAILURE;
    }
    assoc_req.auth = (hi_wifi_auth_mode)atoi(argv[2]); /* 2 */

    /* encipher mode 默认设置为0，即HI_WIFI_PARIWISE_UNKNOWN */
    assoc_req.pairwise = HI_WIFI_PARIWISE_UNKNOWN;

    /* get key */
    if (argc == 4) { /* 4:命令参数个数 */
        const hi_char *buf = argv[3]; /* 3:最后一个参数不能为空 */
        if (buf == HI_NULL) {
            return HI_ERR_FAILURE;
        }
        size_t len = strlen(argv[3]); /* 3:key */
        if ((atoi(argv[2]) == HI_WIFI_SECURITY_WEP) && (len != 9) && (len != 17) && /* 2:加密方式 9:17:密码长度 */
            (len != 12) && (len != 28)) { /* 12:28 密码长度 */
            return HI_ERR_FAILURE;
        } else if ((atoi(argv[2]) != HI_WIFI_SECURITY_WEP) && ((len > HI_WIFI_AP_KEY_LEN_MAX + 2) || /* 2:引号长度 */
            (len < HI_WIFI_AP_KEY_LEN_MIN + 2))) { /* 2:引号长度 */
            return HI_ERR_FAILURE;
        }
        if ((*buf != '\"') || (*(buf + strlen(argv[3]) - 1) != '\"') || /* 3:参数4 */
            (memcpy_s(assoc_req.key, HI_WIFI_MAX_KEY_LEN + 1, buf + 1, strlen(argv[3]) - 2) != EOK)) { /* 3 2 */
            return HI_ERR_FAILURE;
        }
    }

    if (hi_wifi_sta_connect(&assoc_req) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: station quick connect
* example: AT+FCONN="hisilicon",,6,2,"123456789"
           AT+FCONN=,90:2B:D2:E4:CE:28,6,2,"123456789"
*****************************************************************************/
hi_u32 cmd_sta_quick_connect(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_fast_assoc_request fast_assoc_req = {0};
    hi_u32 ret;

    if ((argc < 4) || (argc > 5)) { /* "+FCONN"命令参数个数固定为4或5 */
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0] != HI_NULL) {
        ret = cmd_sta_connect_get_ssid(argv, HI_NULL, &fast_assoc_req, 1);
        if (ret != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }

    /* get bssid */
    if (argv[1] == HI_NULL) {
        /* 结构体赋初值 */
        memset_s(fast_assoc_req.req.bssid, sizeof(fast_assoc_req.req.bssid), 0, sizeof(fast_assoc_req.req.bssid));
    } else if (strlen(argv[1]) == HI_WIFI_TXT_ADDR_LEN) {
        if (cmd_strtoaddr(argv[1], fast_assoc_req.req.bssid, HI_WIFI_MAC_LEN) != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }

    /* get channel,范围1~14 */
    if ((integer_check(argv[2]) != HI_ERR_SUCCESS) || (atoi(argv[2]) <= 0) || (atoi(argv[2]) > 14)) { /* 2 14 */
        return HI_ERR_FAILURE;
    }
    fast_assoc_req.channel = (hi_uchar)atoi(argv[2]); /* 2 */

    /* get auth_type */
    if ((integer_check(argv[3]) != HI_ERR_SUCCESS) || (atoi(argv[3]) < HI_WIFI_SECURITY_OPEN) || /* 3认证方式 */
        (atoi(argv[3]) > HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX) || ((atoi(argv[3]) == HI_WIFI_SECURITY_OPEN) && /* 3 */
        (argc != 4)) || ((atoi(argv[3]) != HI_WIFI_SECURITY_OPEN) && (argc != 5))) { /* 3认证方式45密码 */
        return HI_ERR_FAILURE;
    }

    fast_assoc_req.req.auth = (hi_wifi_auth_mode)atoi(argv[3]); /* 3 */

    /* get encipher mode 0，即HI_WIFI_PARIWISE_UNKNOWN */
    fast_assoc_req.req.pairwise = HI_WIFI_PARIWISE_UNKNOWN;

    /* get key */
    ret = cmd_sta_connect_get_key(argc, argv, &fast_assoc_req);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_sta_fast_connect(&fast_assoc_req) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: sta disconnect network
*****************************************************************************/
hi_u32 cmd_sta_disconnect(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_s32 ret = hi_wifi_sta_disconnect();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: get station connection status
*****************************************************************************/
hi_u32 cmd_sta_status(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_wifi_status wifi_status;

    hi_unref_param(argv);
    hi_unref_param(argc);

    /* 安全编程规则6.6例外（2）结构体赋予初值 */
    memset_s(&wifi_status, sizeof(hi_wifi_status), 0, sizeof(hi_wifi_status));

    ret = hi_wifi_sta_get_connect_info(&wifi_status);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    if (wifi_status.status == HI_WIFI_CONNECTED) {
        const hi_char *tmp = at_ssid_txt((unsigned char*)wifi_status.ssid, strlen(wifi_status.ssid));
        if (at_check_ccharacter(tmp) == HI_ERR_SUCCESS) {
            hi_at_printf("+STASTAT:1,P\"%s\","AT_MACSTR",%d\r\n", tmp, at_mac2str(wifi_status.bssid),
                wifi_status.channel);
        } else {
            hi_at_printf("+STASTAT:1,%s,"AT_MACSTR",%d\r\n", wifi_status.ssid, at_mac2str(wifi_status.bssid),
                wifi_status.channel);
        }
    } else {
        hi_at_printf("+STASTAT:0,0,0,0\r\n");
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: show sta ifname
* example: AT+SHOWSTAIF
*****************************************************************************/
hi_u32 cmd_show_sta_ifname(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 i;
    hi_u8 is_found = HI_FALSE;
    hi_unref_param(argc);
    hi_unref_param(argv);

    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_STA) {
            hi_at_printf("+SHOWSTAIF:%s", g_ifname[i].ifname);
            hi_at_printf("\r\n");
            is_found = HI_TRUE;
        }
    }

    if (is_found == HI_TRUE) {
        hi_at_printf("OK\r\n");
        return HI_ERR_SUCCESS;
    } else {
        return HI_ERR_FAILURE;
    }
}

hi_u32 arp_offload_parse_ipv4_check(char *ip_str, unsigned int *ip_result)
{
    char           *ip_str_cpy = ip_str;
    const char      delim = '.';
    unsigned char   count = 0;
    char           *str_value = NULL;
    hi_u32          value;
    char           *pos = NULL;

    if ((ip_str == NULL) || (ip_result == NULL)) {
        return HI_ERR_FAILURE;
    }

    if (strlen(ip_str) > 15) { /* IPV4 字符串长度最大 15 字节 */
        return HI_ERR_FAILURE;
    }

    pos = strchr(ip_str_cpy, delim);
    while (pos != NULL && pos < (ip_str + 15)) { /* IPV4 字符串长度最大 15 字节 */
        *pos = '\0';
        str_value = ip_str_cpy;
        ip_str_cpy = pos + 1;
        if ((strlen(str_value) < 1 || strlen(str_value) > 3) || /* 子字符串长度最小 1 个字节，最大 3 个字节 */
            (integer_check(str_value) != HI_ERR_SUCCESS)) {
            return HI_ERR_FAILURE;
        }
        value = (hi_u32)atoi(str_value);
        value <<= count * 8; /* 移位3次，每次8比特。 */
        count++;
        *ip_result += value;
        pos = strchr(ip_str_cpy, delim);
    }
    if (count != 3) { /* IPV4 字符串由 3 个点号分隔 */
        return HI_ERR_FAILURE;
    }

    if ((strlen(ip_str_cpy) < 1 || strlen(ip_str_cpy) > 3) || /* 子字符串长度最小 1 个字节，最大 3 个字节 */
        (integer_check(ip_str_cpy) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }
    value = (hi_u32)atoi(ip_str_cpy);
    value <<= 3 * 8; /* 3: 移位第4次，每次8比特。 */
    *ip_result += value;

    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_set_dhcpoffload(hi_s32 argc, const hi_char **argv)
{
    const char    *ifname = "wlan0";
    unsigned char  enable;
    unsigned int   ip_addr = 0;

    if ((argc < 1) || (argc > 2) || (argv == NULL)) { /* 2:命令参数个数 */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, argv) == HI_ERR_FAILURE) || (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    enable = (unsigned char)atoi(argv[0]);
    if (argc == 1) {
        if (enable != 0) {
            return HI_ERR_FAILURE;
        }
    } else { /* 命令参数个数2个 */
        if (enable != 1) {
            return HI_ERR_FAILURE;
        }

        if (arp_offload_parse_ipv4_check((char *)argv[1], &ip_addr) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }

#ifdef _PRE_WLAN_FEATURE_DHCP_OFFLOAD
    if (hi_wifi_dhcp_offload_setting(ifname, enable, ip_addr) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
#endif

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_set_arpoffload(hi_s32 argc, const hi_char **argv)
{
    unsigned char  enable;
    unsigned int   ip_addr = 0;
    hi_u8 is_found = HI_FALSE;
    hi_u8 i = 0;

    if ((argc < 1) || (argc > 2) || (argv == NULL)) { /* 2:命令参数个数 */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, argv) == HI_ERR_FAILURE) || (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    enable = (unsigned char)atoi(argv[0]);
    if (argc == 1) {
        if (enable != 0) {
            return HI_ERR_FAILURE;
        }
    } else { /* 命令参数个数2个 */
        if (enable != 1) {
            return HI_ERR_FAILURE;
        }

        if (arp_offload_parse_ipv4_check((char *)argv[1], &ip_addr) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }

    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_STA) {
            is_found = HI_TRUE;
            break;
        }
    }
    if (is_found == HI_FALSE) {
        return HI_ERR_FAILURE;
    }
#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
    if (hi_wifi_arp_offload_setting(g_ifname[i].ifname, enable, ip_addr) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
#endif

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_set_powersave(hi_s32 argc, const hi_char **argv)
{
    unsigned char  ps_switch;
    int   ret;

    if ((argc != 1) || (argv == NULL)) { /* 2:命令参数个数 */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, (const hi_char **)argv) != HI_ERR_SUCCESS) ||
        (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    ps_switch = (unsigned char)atoi(argv[0]);
    if ((ps_switch != 0) && (ps_switch != 1)) {
        return HI_ERR_FAILURE;
    }

    ret = (hi_u32)hi_wifi_set_pm_switch(ps_switch);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_setup_sleep(hi_s32 argc, hi_char *argv[])
{
    hi_u8 sleep_mode;

    if (argc != 1 || argv == HI_NULL) { /* just support sleep mode param */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, (const hi_char **)argv) != HI_ERR_SUCCESS) ||
        (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    sleep_mode = (hi_u8)atoi(argv[0]);
    if (sleep_mode > HI_DEEP_SLEEP) { /* 0:wake up; 1:light sleep; 2:deep sleep */
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_set_plat_ps_mode(sleep_mode) != HI_ERR_SUCCESS) {
        hi_at_printf(" hi_wifi_set_plat_ps_mode err\r\n");
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_device_platform_pm_enable(hi_s32 argc, hi_char *argv[])
{
    hi_u8 status;
    hi_u32 ret;
    if (argc != 1 || argv == HI_NULL) { /* just support sleep mode param */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, (const hi_char **)argv) != HI_ERR_SUCCESS) ||
        (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    status = (hi_u8)atoi(argv[0]);
    if (status == 0) { /* 0: disable device sleep */
        ret = hi_wifi_plat_pm_disable();
    } else if (status == 1) { /* 1: enable device sleep */
        ret = hi_wifi_plat_pm_enable();
    } else {
        ret = HI_ERR_FAILURE;
    }
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    hi_at_printf("OK\r\n");
    return ret;
}

hi_u32 cmd_host_notify_device_sleep_status(hi_s32 argc, hi_char *argv[])
{
    hi_u8 status;
    hi_u32 ret;
    if (argc != 1 || argv == HI_NULL) { /* just support sleep mode param */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, (const hi_char **)argv) != HI_ERR_SUCCESS) ||
        (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    status = (hi_u8)atoi(argv[0]);
    if (status == 0) { /* 0: host work */
        ret = (hi_u32)hi_wifi_host_request_sleep(0);
    } else if (status == 1) { /* 1: host sleep */
        ret = (hi_u32)hi_wifi_host_request_sleep(1);
    } else {
        ret = HI_ERR_FAILURE;
    }
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    hi_at_printf("OK\r\n");
    return ret;
}

hi_u32 cmd_dump_platform_pm_info(hi_s32 argc, hi_char *argv[])
{
    hi_u8 is_host;
    if (argc != 1 || argv == HI_NULL) { /* just support sleep mode param */
        return HI_ERR_FAILURE;
    }

    if ((at_param_null_check(argc, (const hi_char **)argv) != HI_ERR_SUCCESS) ||
        (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }
    is_host = (hi_u8)oal_atoi(argv[0]);
    if (is_host > 1) { /* > 1: 无效参数 */
        hi_at_printf("parameter error, host:1, device:0 \r\n");
        return HI_FAIL;
    }
    hi_wlan_dump_pm_info(is_host);
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

#ifdef CONFIG_WPS_SUPPORT
/*****************************************************************************
* Func description: using wps pbc to connect network
* example: sta wps_pbc <bssid>
*****************************************************************************/
hi_u32 cmd_wpa_wps_pbc(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_s32 ret = hi_wifi_sta_wps_pbc(HI_NULL);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: get wps pin value
*****************************************************************************/
hi_u32 cmd_wpa_wps_pin_get(hi_s32 argc, const hi_char *argv[])
{
    hi_char pin_txt[WIFI_WPS_PIN_LEN + 1] = {0};
    hi_u32  len = WIFI_WPS_PIN_LEN + 1;
    hi_s32  ret;

    hi_unref_param(argv);
    hi_unref_param(argc);

    ret = hi_wifi_sta_wps_pin_get(pin_txt, len);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    pin_txt[WIFI_WPS_PIN_LEN] = '\0';

    hi_at_printf("+PINSHOW:%s\r\n", pin_txt);
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: using wps pin to connect network
* example: AT+PIN=03882368
*****************************************************************************/
hi_u32 cmd_wpa_wps_pin(hi_s32 argc, const hi_char *argv[])
{
    hi_char  pin[WIFI_WPS_PIN_LEN + 1] = {0};
    hi_char *ppin = pin;

    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    hi_u32 len = strlen(argv[0]);
    if ((len != WIFI_WPS_PIN_LEN) || (memcpy_s(pin, WIFI_WPS_PIN_LEN + 1, argv[0], len) != EOK)) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_sta_wps_pin(ppin, HI_NULL) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}
#endif /* LOSCFG_APP_WPS */

hi_u32 cmd_set_reconn(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 enable;
    hi_s32 seconds = RECONN_TIMEOUT_MIN;
    hi_u32 period = RECONN_PERIOD_MIN;
    hi_u32 max_try_count = RECONN_COUNT_MIN;
    if ((argc != 1) && (argc != 4)) { /* 4:参数个数 */
        return HI_ERR_FAILURE;
    }
    if (argc == 1) {
        if ((integer_check(argv[0]) != HI_ERR_SUCCESS) || (atoi(argv[0]) != 0)) {
            return HI_ERR_FAILURE;
        }
        enable = 0; /* 使能位 */
    } else {
        for (hi_s32 i = 0; i < argc - 1; i++) {
            if (integer_check(argv[i]) != HI_ERR_SUCCESS) {
                return HI_ERR_FAILURE;
            }
        }
        enable = atoi(argv[0]); /* 使能位 */
        if (enable == 0) {
            return HI_ERR_FAILURE;
        }
        period = (hi_u32)atoi(argv[1]); /* 重连周期 */
        max_try_count = (hi_u32)atoi(argv[2]); /* 2:重连最大次数 */
        if (argv[3] != HI_NULL) { /* 3:单次重连超时时间为可选参数,不配置则使用默认值 */
            if (integer_check(argv[3]) != HI_ERR_SUCCESS) { /* 3:单次重连超时时间 */
                return HI_ERR_FAILURE;
            }
            seconds = atoi(argv[3]); /* 3:单次重连超时时间 */
        }

        if (seconds < RECONN_TIMEOUT_MIN || period < RECONN_PERIOD_MIN || period > RECONN_PERIOD_MAX ||
            max_try_count < RECONN_COUNT_MIN || max_try_count > RECONN_COUNT_MAX) {
            return HI_ERR_FAILURE;
        }
    }
    hi_s32 ret = hi_wifi_sta_set_reconnect_policy(enable, seconds, period, max_try_count);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");

    return HI_ERR_SUCCESS;
}

const at_cmd_func g_sta_func_tbl[] = {
    {"+STARTSTA", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_start_adv, (at_call_back_func)cmd_sta_start},
    {"+STOPSTA", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_stop},
    {"+SCAN", 5, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_scan},
    {"+SCANCHN", 8, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_channel_scan, HI_NULL},
    {"+SCANSSID", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_ssid_scan, HI_NULL},
    {"+SCANPRSSID", 11, HI_NULL, HI_NULL, (at_call_back_func)cmd_ssid_prefix_scan, HI_NULL},
    {"+SCANRESULT", 11, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_scan_results},
    {"+CONN", 5, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_connect, HI_NULL},
    {"+FCONN", 6, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_quick_connect, HI_NULL},
    {"+DISCONN", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_disconnect},
    {"+STASTAT", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_status},
    {"+RECONN", 7, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_reconn, HI_NULL},
    {"+SHOWSTAIF", 10, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_show_sta_ifname},
#ifdef CONFIG_WPS_SUPPORT
    {"+PBC", 4, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_wps_pbc},
    {"+PIN", 4, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_wps_pin, HI_NULL},
    {"+PINSHOW", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_wps_pin_get},
#endif /* LOSCFG_APP_WPS */
    {"+ARP", 4, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_set_arpoffload, HI_NULL},
    {"+DHCP", 5, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_set_dhcpoffload, HI_NULL},
    {"+PS", 3, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_set_powersave, HI_NULL},
    {"+SLP", 4, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_setup_sleep, HI_NULL},
    {"+SLPEN", 6, HI_NULL, HI_NULL, (at_call_back_func)cmd_device_platform_pm_enable, HI_NULL},
    {"+HSLP", 5, HI_NULL, HI_NULL, (at_call_back_func)cmd_host_notify_device_sleep_status, HI_NULL},
    {"+PMINFO", 7, HI_NULL, HI_NULL, (at_call_back_func)cmd_dump_platform_pm_info, HI_NULL},
};

#define AT_STA_FUNC_NUM (sizeof(g_sta_func_tbl) / sizeof(g_sta_func_tbl[0]))

hi_void hi_at_sta_cmd_register(hi_void)
{
    hi_at_register_cmd(g_sta_func_tbl, AT_STA_FUNC_NUM);
}

/*****************************************************************************
* Func description: show mesh or softap connected sta information
*****************************************************************************/
hi_u32 cmd_softap_show_sta(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_u32 sta_index;
    hi_u32 sta_num = WIFI_DEFAULT_MAX_NUM_STA;
    hi_wifi_ap_sta_info  sta_list[WIFI_DEFAULT_MAX_NUM_STA];
    hi_wifi_ap_sta_info *sta_list_node = HI_NULL;

    hi_unref_param(argc);
    hi_unref_param(argv);

    ret = hi_wifi_softap_get_connected_sta(sta_list, &sta_num);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    sta_list_node = sta_list;
    for (sta_index = 0; sta_index < sta_num; sta_index++, sta_list_node++) {
        hi_at_printf("+SHOWSTA:" AT_MACSTR, at_mac2str(sta_list_node->mac));
        hi_at_printf("\r\n");
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start softap
* example: AT+STARTAP="hisilicon",0,6,1,"123456789"
           AT+STARTAP="hisilicon",0,6,0
*****************************************************************************/
hi_u32 cmd_start_softap(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_softap_config hapd_conf          = {0};
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;
    hi_s32 len = sizeof(ifname);
    hi_s32 i;
    if (((argc != 4) && (argc != 5)) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) { /* 参数长度为4 或 5 */
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if ((argv[0][0] != '\"') || (*(argv[0] + strlen(argv[0]) - 1) != '\"') ||
        (memcpy_s(hapd_conf.ssid, HI_WIFI_MAX_SSID_LEN + 1, argv[0] + 1, strlen(argv[0]) - 2) != EOK)) { /* 2 两双引号 */
        return HI_ERR_FAILURE;
    }

    /* get ssid_hidden,范围0~1 */
    if ((integer_check(argv[1]) != HI_ERR_SUCCESS) || (atoi(argv[1]) < 0) || (atoi(argv[1]) > 1)) {
        return HI_ERR_FAILURE;
    }
    hapd_conf.ssid_hidden = atoi(argv[1]);

    /* get channel,信道号范围1~14 */
    if ((integer_check(argv[2]) != HI_ERR_SUCCESS) || (atoi(argv[2]) <= 0) || (atoi(argv[2]) > 14)) { /* 2 14 */
        return HI_ERR_FAILURE;
    }
    hapd_conf.channel_num = (hi_uchar)atoi(argv[2]); /* 2 */

    /* get 加密方式 */
    if ((integer_check(argv[3]) == HI_ERR_FAILURE) || /* 3 */
        ((atoi(argv[3]) != HI_WIFI_SECURITY_OPEN) && (atoi(argv[3]) != HI_WIFI_SECURITY_WPA2PSK) && /* 3 */
        (atoi(argv[3]) != HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX)) || /* 3 */
        ((atoi(argv[3]) == HI_WIFI_SECURITY_OPEN) && (argc != 4))) { /* 参数3为open场景时，只有4个参数 */
        return HI_ERR_FAILURE;
    }
    hapd_conf.authmode = (hi_wifi_auth_mode)atoi(argv[3]); /* 3 */

    /* get authmode */
    if ((hapd_conf.authmode != HI_WIFI_SECURITY_OPEN)) {
        if ((argc != 5) || (strlen(argv[4]) > HI_WIFI_AP_KEY_LEN_MAX + 2) || /* 4:输入密码 双引号占的2字节 5参数个数 */
            (strlen(argv[4]) < HI_WIFI_AP_KEY_LEN_MIN + 2)) { /* 4:输入密码 双引号占的2字节 */
            return HI_ERR_FAILURE;
        }
        const hi_char *buf = argv[4]; /* 参数4 */
        len = (int)strlen(argv[4]); /* 参数4 */
        if ((*buf != '\"') || (*(buf + len - 1) != '\"') ||
            (memcpy_s((hi_char*)hapd_conf.key, HI_WIFI_AP_KEY_LEN + 1, buf + 1, len - 2) != EOK)) { /* 2去掉双引号 */
            return HI_ERR_FAILURE;
        }
    }
    if (hi_wifi_softap_start(&hapd_conf, ifname_point, &len) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_set_bandwidth(ifname_point, strlen(ifname_point) + 1, g_bw_setup_value) != HI_ERR_SUCCESS) {
        hi_wifi_softap_stop();
        return HI_ERR_FAILURE;
    }
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_UNKNOWN) {
            memcpy_s(g_ifname[i].ifname, WIFI_IFNAME_MAX_SIZE + 1, ifname_point, WIFI_IFNAME_MAX_SIZE + 1);
            g_ifname[i].type = AT_VAP_AP;
            break;
        }
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start softap
* example: AT+SETAPADV=2,10,100,2,3600,0
*****************************************************************************/
hi_u32 cmd_set_softap_advance(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret, value, i;

    if ((argc != 6) || (argv == HI_NULL)) { /* "+SETAPADV"命令固定6个命令参数 */
        return HI_ERR_FAILURE;
    }
    for (i = 0; i < argc; i++) {
        if ((argv[i] != HI_NULL) && (integer_check(argv[i]) != HI_ERR_SUCCESS)) {
            return HI_ERR_FAILURE;
        }

        if (i == 0) {
            value = (argv[i] != HI_NULL) ? atoi(argv[i]) : HI_WIFI_PHY_MODE_11BGN;
            if ((value == HI_WIFI_PHY_MODE_11B) && (argv[1] != HI_NULL) && (strcmp(argv[1], "20"))) { /* 20:bw */
                return HI_ERR_FAILURE;
            }
            ret = hi_wifi_softap_set_protocol_mode((hi_wifi_protocol_mode)value);
        } else if (i == 1) {
            if ((argv[i] == HI_NULL) || !(strcmp(argv[i], "20"))) { /* 20M */
                g_bw_setup_value = HI_WIFI_BW_LEGACY_20M;
            } else if (!(strcmp(argv[i], "10"))) { /* 10M */
                g_bw_setup_value = HI_WIFI_BW_HIEX_10M;
            } else if (!(strcmp(argv[i], "5"))) { /* 5M */
                g_bw_setup_value = HI_WIFI_BW_HIEX_5M;
            } else {
                return HI_ERR_FAILURE;
            }
            ret = HISI_OK;
        } else if (i == 2) { /* 2:参数 */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_beacon_period(atoi(argv[i])) : HISI_OK; /* 周期默认100ms */
        } else if (i == 3) { /* 3:参数 */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_dtim_period(atoi(argv[i])) : HISI_OK;
        } else if (i == 4) { /* 4:参数 */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_group_rekey(atoi(argv[i])) : HISI_OK;
        } else if (i == 5) { /* 5:参数 */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_shortgi(atoi(argv[i])) : HISI_OK;
        } else {
            return HI_ERR_FAILURE;
        }
        if (ret != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: stop softap
*****************************************************************************/
hi_u32 cmd_stop_softap(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argc);
    hi_unref_param(argv);
    hi_s32 i;
    struct netif *pwifi = NULL;
    /* 停掉DHCPS */
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_AP) {
            pwifi = netif_find(g_ifname[i].ifname);
            if (pwifi == NULL) {
                break;
            }
            netifapi_dhcps_stop(pwifi);
            hi_at_printf("stop dhcps ok\r\n");
        }
    }
    if (hi_wifi_softap_stop() != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_AP) {
            memset_s(g_ifname[i].ifname, WIFI_IFNAME_MAX_SIZE + 1, 0, WIFI_IFNAME_MAX_SIZE + 1);
            g_ifname[i].type = AT_VAP_UNKNOWN;
        }
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: softap disconnect station
* example: AT+DEAUTHSTA=90:2B:D2:E4:CE:28
*****************************************************************************/
hi_u32 cmd_softap_deauth_sta(hi_s32 argc, const hi_char *argv[])
{
    hi_uchar mac_addr[HI_WIFI_MAC_LEN + 1] = {0};
    hi_s32 ret;

    if ((argc != 1) || (argv == HI_NULL) || (argv[0] == HI_NULL) ||
        (strlen(argv[0]) != HI_WIFI_TXT_ADDR_LEN)) {
        return HI_ERR_FAILURE;
    }

    if (cmd_strtoaddr(argv[0], mac_addr, HI_WIFI_MAC_LEN) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    ret = hi_wifi_softap_deauth_sta(mac_addr, HI_WIFI_MAC_LEN);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: show softap ifname
* example: AT+SHOWAPIF
*****************************************************************************/
hi_u32 cmd_show_softap_ifname(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 i;
    hi_u8 is_found = HI_FALSE;
    hi_unref_param(argc);
    hi_unref_param(argv);

    for (i = 0; i < HI3881_VAP_TYPE_NUM; i++) {
        if (g_ifname[i].type == AT_VAP_AP) {
            hi_at_printf("+SHOWAPIF:%s", g_ifname[i].ifname);
            hi_at_printf("\r\n");
            is_found = HI_TRUE;
        }
    }

    if (is_found == HI_TRUE) {
        hi_at_printf("OK\r\n");
        return HI_ERR_SUCCESS;
    } else {
        return HI_ERR_FAILURE;
    }
}

hi_u32 at_ap_scan(hi_void)
{
    hi_at_printf("ERROR:TBD\r\n");
    return HI_ERR_SUCCESS;
}

const at_cmd_func g_at_ap_func_tbl[] = {
    {"+STARTAP", 8, HI_NULL, HI_NULL, (at_call_back_func)cmd_start_softap, HI_NULL},
    {"+SETAPADV", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_softap_advance, HI_NULL},
    {"+STOPAP", 7, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_stop_softap},
    {"+SHOWSTA", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_softap_show_sta},
    {"+DEAUTHSTA", 10, HI_NULL, HI_NULL, (at_call_back_func)cmd_softap_deauth_sta, HI_NULL},
    {"+APSCAN", 7, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_ap_scan},
    {"+SHOWAPIF", 9, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_show_softap_ifname},
};

#define AT_AP_FUNC_NUM (sizeof(g_at_ap_func_tbl) / sizeof(g_at_ap_func_tbl[0]))

hi_void hi_at_softap_cmd_register(void)
{
    hi_at_register_cmd(g_at_ap_func_tbl, AT_AP_FUNC_NUM);
}

void hi_at_wifi_shell_cmd_register(void)
{
    hi_at_sta_cmd_register();
    hi_at_softap_cmd_register();
}


#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
