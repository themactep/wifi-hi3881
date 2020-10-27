/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wlan sta.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "wlan_sm.h"
#include "wlan_util.h"
#include "wlan_hal.h"
#include "hi_wlan.h"
#include "securec.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
#define CMD_REPLY_SIZE  256

hi_u32 g_assignable_chan[SCAN_CHAN_NUM_MIX] = {
    2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484
};

/*****************************************************************************
  3 函数实现
*****************************************************************************/
hi_s32 hi_wlan_sta_init(hi_void)
{
    return wlan_sm_init();
}

hi_void hi_wlan_sta_deinit(hi_void)
{
    wlan_sm_deinit();
}

hi_s32 hi_wlan_sta_open(hi_char *ifname, hi_u32 nameBufSize, hi_wlan_sta_config_s *pstStaCfg)
{
    hi_s32 ret;
    hi_char reply[CMD_REPLY_SIZE] = {0};
    hi_s32 len = sizeof(reply);

    if (ifname == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    ret = wlan_sm_send_message(CMD_STA_OPEN, pstStaCfg, reply, &len);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = strcpy_s(ifname, nameBufSize, reply);
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }

    return HI_SUCCESS;
}

hi_s32 hi_wlan_sta_close(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_STA_CLOSE, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_sta_start(const hi_char *ifname, hi_wlan_sta_event_callback pfnEventCb)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    wlan_sm_register_callback(pfnEventCb);

    return wlan_sm_send_message(CMD_STA_START, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_sta_stop(const hi_char *ifname)
{
    hi_s32 ret;

    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    ret = wlan_sm_send_message(CMD_STA_STOP, (hi_void *)ifname, NULL, NULL);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    wlan_sm_unregister_callback();

    return HI_SUCCESS;
}

hi_s32 hi_wlan_sta_start_scan(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_STA_SCAN, (hi_void *)ifname, NULL, NULL);
}

extern hi_u32 g_assignable_chan[SCAN_CHAN_NUM_MIX];
static hi_s32 scan_chan_tostr(hi_char *chan_scan_cmd, hi_u32 cmd_len, const hi_wlan_sta_scan_cfg_e *scan_cfg)
{
    if (scan_cfg == NULL || chan_scan_cmd == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    hi_s32 results;
    hi_u32 init_len = strlen("SCAN freq=");
    hi_char *pscan_cmd = chan_scan_cmd + init_len;
    hi_u8 i = 0;

    results = strcpy_s(chan_scan_cmd, cmd_len, "SCAN freq=");
    if (results < EOK) {
        DBGPRINT(("WiFi: CHANNEL SCAN strcpy_s fail!\n"));
        return results;
    }
    for (i = 0; i < scan_cfg->scan_chan_len; i++) {
        if (i < scan_cfg->scan_chan_len - 1) {
            results = sprintf_s(pscan_cmd, (cmd_len - init_len), "%d,", g_assignable_chan[scan_cfg->scan_chan[i] - 1]);
        } else {
            results = sprintf_s(pscan_cmd, (cmd_len - init_len), "%d", g_assignable_chan[scan_cfg->scan_chan[i] - 1]);
        }
        if (results < 0) {
            DBGPRINT(("WiFi: channel scan sprintf_s combination cmd fail!\n"));
            return results;
        }
        pscan_cmd += 5; /* pscan cmd offset 5 */
    }
    return results;
}

hi_s32 hi_wlan_sta_start_chan_scan(hi_wlan_sta_scan_cfg_e *scan_cfg)
{
    hi_char scan_cfg_str[128] = {0};    /* array scan_cfg_str max len 128 */
    hi_s32 ret;
    if (scan_cfg == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }
    ret = scan_chan_tostr(scan_cfg_str, sizeof(scan_cfg_str), scan_cfg);
    if (ret < HI_SUCCESS) {
        DBGPRINT(("WiFi: hi_wlan_sta_start_chan_scan cmd Encapsulation fial!\n"));
        return ret;
    }
    return wlan_sm_send_message(CMD_STA_SCANCHAN, (hi_void *)scan_cfg_str, NULL, NULL);
}

static
hi_wlan_security_e sta_parse_security(const hi_char *capability)
{
    hi_wlan_security_e sec;

    if (capability == NULL) {
        return HI_WLAN_SECURITY_BUTT;
    }

    if (strstr(capability, "WEP")) {
        sec = HI_WLAN_SECURITY_WEP;
    } else if (strstr(capability, "WPA-PSK") || strstr(capability, "WPA2-PSK")) {
        sec = HI_WLAN_SECURITY_WPA_WPA2_PSK;
    } else if (strstr(capability, "WPA-EAP") || strstr(capability, "WPA2-EAP")) {
        sec = HI_WLAN_SECURITY_WPA_WPA2_EAP;
    } else {
        sec = HI_WLAN_SECURITY_OPEN;
    }

    return sec;
}

static hi_s32 sta_parse_scan_result(hi_char *line, hi_u32 lineSize, hi_wlan_sta_access_point_e *ap)
{
    hi_unused(lineSize);
    hi_s32 results;
    hi_char *result[5] = { NULL };  /* array result max len 5 */

    if (line == NULL || ap == NULL) {
        return HI_FAILURE;
    }

    wlan_util_string_split(line, '\t', result);
    if (!result[0] || !result[1] || !result[2] || /* 0:bssid 1:channel 2:signal level */
        !result[3] || !result[4]) { /* 3:security 4:ssid */
        DBGPRINT(("WiFi: results is null file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
        return HI_FAILURE;
    }
    results = strncpy_s(ap->bssid, sizeof(ap->bssid), result[0], strlen(result[0]) + 1);    /* 0:bssid */
    if (results < 0) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    ap->channel = (hi_u32)wlan_util_frequency_to_channel(atoi(result[1]));                              /* 1:channel */
    ap->level = atoi(result[2]);                                                                /* 2:signal level */
    ap->security = sta_parse_security(result[3]);                                               /* 3:security */

    if (strlen(result[4]) > MAX_SSID_LEN) {                                /* 4:ssid */
        return HI_FAILURE;
    }
    results = strncpy_s(ap->ssid, sizeof(ap->ssid), result[4], strlen(result[4]) + 1);          /* 4:ssid */
    if (results < 0) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    if (ap->ssid[0] == '\0') {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 hi_wlan_sta_get_scan_results(const hi_char *ifname, hi_wlan_sta_access_point_e *pstApList, hi_u32 *pstApNum)
{
    hi_s32 ret;
    hi_s32 results_len = STRING_REPLY_SIZE;
    hi_s32 size;
    hi_wlan_sta_access_point_e ap;
    hi_char line[256];              /* array line max len 256 */
    hi_u32 i = 0;

    if (ifname == NULL || *ifname == '\0' || pstApList == NULL || pstApNum == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if (*pstApNum == 0) {
        return HI_SUCCESS;
    }
    hi_char *results = (hi_char *)malloc(STRING_REPLY_SIZE);
    if (results == NULL) {
        DBGPRINT(("WiFi: malloc results mem fail in %s\n", __func__));
        return HI_FAILURE;
    }
    memset_s(results, STRING_REPLY_SIZE, 0, STRING_REPLY_SIZE);
    hi_char *pos = results;
    /* Request stirng of scan results from wpa_supplicant */
    ret = wlan_sm_sta_scan_results(results, &results_len);
    if (ret != HI_SUCCESS) {
        free(results);
        results = NULL;
        return HI_FAILURE;
    }

    /* The first line is "bssid / frequency / signal level / flags / ssid"
     * ignore this line */
    size = wlan_util_read_line(pos, line, sizeof(line));
    if (size == 0) {
        DBGPRINT(("WiFi: anything read for wlan_util_read_line in %s\n", __func__));
    }
    pos += size;

    /* parse scan results, one line a AP */
    while ((size = wlan_util_read_line(pos, line, sizeof(line)))) {
        pos += size;
        if (!sta_parse_scan_result(line, sizeof(line), &ap)) {
            pstApList[i++] = ap;
        }
        if (i >= *pstApNum) {
            break;
        }
    }
    *pstApNum = i;
    free(results);
    results = NULL;
    return ret;
}

hi_s32 hi_wlan_sta_connect(const hi_char *ifname, hi_wlan_sta_config_s *pstStaCfg)
{
    hi_s32 ret;
    hi_wlan_sta_conn_status_e con;
    hi_u32 delay_count = 0;
    hi_u32 sem_thread;
    hi_u32 dispatch_flag = 0;

    if (ifname == NULL || *ifname == '\0' || pstStaCfg == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* check connection, if connected, disconnect to AP firstly */
    ret = hi_wlan_sta_get_connection_status(ifname, &con);
    if (ret == HI_SUCCESS) {
        if (con.state == HI_WLAN_STA_CONN_STATUS_CONNECTED) {
            thread_optimizatioin_variable_set(1); /* 1 表示准备接收事件并等待状态机切换 */
            hi_wlan_sta_disconnect(ifname);
            dispatch_flag = 1;
        }
    }
    if (dispatch_flag) {
        while (1) {
            sem_thread = thread_optimizatioin_variable_get();
            if ((sem_thread == 0) || (delay_count++ > 99)) { /* 0 状态机已切换，99 超时时间 */
                break;
            }
            usleep(1);
        }
    }

    return wlan_sm_send_message(CMD_STA_CONNECT, pstStaCfg, NULL, NULL);
}

hi_s32 hi_wlan_sta_disconnect(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_STA_DISCONNECT, NULL, NULL, NULL);
}

hi_s32 hi_wlan_sta_get_connection_status(const hi_char *ifname, hi_wlan_sta_conn_status_e *pstConnStatus)
{
    if (ifname == NULL || *ifname == '\0' || pstConnStatus == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_sta_connection_status(pstConnStatus);
}

hi_s32 hi_wlan_sta_start_wps(const hi_char *ifname, hi_wlan_sta_config_s *pststacfg)
{
    hi_s32 ret = HI_WLAN_INVALID_PARAMETER;

    if (ifname == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if (pststacfg->wps_method == HI_WLAN_WPS_PIN && pststacfg->wps_pin == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if (pststacfg->wps_method == HI_WLAN_WPS_PBC) {
        ret = wlan_sm_start_wps_pbc(pststacfg->bssid);
    }

    if (pststacfg->wps_method == HI_WLAN_WPS_PIN) {
        ret = wlan_sm_start_wps_pin_keypad(pststacfg->bssid, pststacfg->wps_pin);
    }

    return ret;
}

hi_s32 hi_wlan_sta_get_mac_address(const hi_char *ifname, hi_char *mac, hi_u8 mac_buf_size)
{
    hi_s32 ret = HI_FAILURE;
    hi_s32 results;
    struct ifreq ifr;

    if (ifname == NULL || *ifname == '\0' || mac == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    hi_s32 s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return HI_FAILURE;
    }

    results = memset_s(&ifr, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    if (ioctl(s, SIOCGIFHWADDR, &ifr) >= 0) {
        results = sprintf_s(mac, mac_buf_size, MACSTR, MAC2STR(ifr.ifr_hwaddr.sa_data));
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = HI_SUCCESS;
    }

    close(s);
    return ret;
}
