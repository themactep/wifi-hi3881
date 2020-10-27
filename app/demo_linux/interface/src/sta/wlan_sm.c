/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wlan sm.
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
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "wlan_sm.h"
#include "wlan_hal.h"
#include "wlan_util.h"
#include "securec.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
#define MAX_CALLBACK_NUM 2

static const hi_char g_driver[] = "nl80211";
static const hi_char g_dev_wifi_dir[] = "/etc/Wireless";
static const hi_char g_supp_config_dir[] = "/etc/Wireless";
static const hi_char g_supp_config_file[] = "/etc/Wireless/wpa_supplicant.conf";
static const hi_char g_p2p_config_file[] = "/etc/Wireless/p2p_supplicant.conf";
static const hi_char g_ctrl_iface_dir[] = "/etc/Wireless/wpa_supplicant";

static hi_char              g_wlan_sm_ifname[IFNAMSIZ + 1];

static hi_bool              g_sm_inited = HI_FALSE;
/* thread for monitor socket wlan0/p2p0 */
static pthread_t            g_wlan_ethread = 0;
static pthread_t            g_wlan_ethread_p2p = 0;
/* thread for monitor socket p2p-p2p0-0/p2p-wlan0-0 */
static pthread_t            g_wlan_ethread2 = 0;
/* thread for timer of GO negotiate */
static pthread_t            g_wlan_timer_thread = 0;
static pthread_mutex_t      g_wlan_sm_mut;

static hi_wlan_sta_event_callback g_wlan_event_cbs[MAX_CALLBACK_NUM] = { NULL };

static hi_wpa_socket_s     *g_mon_conn = NULL;
static hi_wpa_socket_s     *g_mon_conn_p2p = NULL;
static hi_wpa_socket_s     *g_mon_conn2 = NULL;

static hi_wpa_message_s     g_wpa_message;
static hi_wpa_message_s     g_wpa_message_p2p;
static hi_wpa_message_s     g_wpa_message_p2p2;

static hi_wlan_p2p_device_s g_p2p_peers[100];       /* max p2p peers 100 */
static hi_u32               g_p2p_peers_num = 0;
static hi_wlan_p2p_config_s g_p2p_saved_config;
static hi_wlan_p2p_group_s  g_p2p_group;

static wlan_state_e         g_wlan_state = WLAN_STATE_CLOSED;
static wlan_state_e         g_wlan_state_p2p = WLAN_STATE_CLOSED;
static hi_wlan_pmf_mode     g_pmf_mode = HI_WLAN_PROTECTION_OPTIONAL;
hi_u32 g_sem_thread;

static wlan_sm_s g_sm[] = {
    {WLAN_STATE_CLOSED,                             wlan_state_closed},
    {WLAN_STATE_DRIVER_LOADDED,                     wlan_state_driver_loadded},
    {WLAN_STATE_STA_STARTED,                        wlan_state_sta_started},
    {WLAN_STATE_STA_CONNECTED,                      wlan_state_sta_connected},
    {WLAN_STATE_P2P_STARTED,                        wlan_state_p2p_started},
    {WLAN_STATE_P2P_USER_AUTHORIZING_INVITATION,    wlan_state_p2p_user_authorizing_invitation},
    {WLAN_STATE_P2P_USER_AUTHORIZING_JOIN,          wlan_state_p2p_user_authorizing_join},
    {WLAN_STATE_P2P_GROUP_NEGOTIATION,              wlan_state_p2p_group_negotiation},
    {WLAN_STATE_P2P_GROUP_CREATED,                  wlan_state_p2p_group_created}
};

/*****************************************************************************
  3 函数实现
*****************************************************************************/
hi_s32 wlan_sm_init(hi_void)
{
    if (g_sm_inited == HI_TRUE) {
        return HI_SUCCESS;
    }

    if (wlan_hal_init() == HI_FAILURE) {
        return HI_FAILURE;
    }

    if (pthread_mutex_init(&g_wlan_sm_mut, NULL) != 0) {
        DBGPRINT(("WiFi: 'g_wlan_sm_mut' pthread_mutex_init fail in %s!\n", __func__));
    }

    g_sm_inited = HI_TRUE;

    return HI_SUCCESS;
}

hi_void wlan_sm_deinit(hi_void)
{
    if (g_sm_inited == HI_FALSE) {
        return;
    }

    if (pthread_mutex_destroy(&g_wlan_sm_mut) != 0) {
        DBGPRINT(("WiFi: 'g_wlan_sm_mut' pthread_mutex_destroy fail in %s\n", __func__));
    }

    wlan_hal_deinit();

    g_sm_inited = HI_FALSE;
}

hi_s32 wlan_sm_send_message(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_s32 ret = HI_FALSE;
    hi_s32 i;
    wlan_state_e state;

    if (pthread_mutex_lock(&g_wlan_sm_mut) != 0) {
        DBGPRINT(("WiFi: 'g_wlan_sm_mut' pthread_mutex_lock fail in %s!\n", __func__));
    }
    if (msg <= CMD_STA_DISCONNECT || (msg >= CMD_STA_P2P_CLOSE && msg < CMD_END)
        || (msg >= SCAN_RESULTS_EVENT && msg <= STA_DISCONNECTED_EVENT) || msg == CMD_STA_SCANCHAN) {
        state = g_wlan_state;
    } else {
        state = g_wlan_state_p2p;
    }
    if (pthread_mutex_unlock(&g_wlan_sm_mut) != 0) {
        DBGPRINT(("WiFi: 'g_wlan_sm_mut' pthread_mutex_unlock fail in %s!\n", __func__));
    }
    DBGPRINT(("WiFi: msg [0x%x] in state %d\n", msg, state));

    for (i = 0; i < WLAN_STATE_BUTT; i++)
        if (state == g_sm[i].state) {
            ret = g_sm[i].process(msg, data, reply, len);
            break;
        }

    return ret;
}

hi_s32 wlan_sm_register_callback(hi_wlan_sta_event_callback event_cb)
{
    hi_u32 tmp_index = 0;

    while (tmp_index < MAX_CALLBACK_NUM) {
        if (g_wlan_event_cbs[tmp_index] == NULL) {
            g_wlan_event_cbs[tmp_index] = event_cb;
            break;
        }
        tmp_index++;
    }
    DBGPRINT(("WiFi:register callback: tmp_index=%d\n", tmp_index));
    return HI_SUCCESS;
}

hi_s32 wlan_sm_unregister_callback_given(hi_wlan_sta_event_callback event_cb)
{
    hi_u32 tmp_index = 0;

    while (tmp_index < MAX_CALLBACK_NUM) {
        if (g_wlan_event_cbs[tmp_index] == event_cb) {
            g_wlan_event_cbs[tmp_index] = NULL;
            break;
        }
        tmp_index++;
    }
    DBGPRINT(("WiFi:unregister callback given: tmp_index=%d\n", tmp_index));
    return HI_SUCCESS;
}


hi_s32 wlan_sm_unregister_callback(hi_void)
{
    hi_u32 tmp_index = 0;

    while (tmp_index < MAX_CALLBACK_NUM) {
        if (g_wlan_event_cbs[tmp_index] != NULL) {
            g_wlan_event_cbs[tmp_index] = NULL;
        }
        tmp_index++;
    }
    DBGPRINT(("WiFi:unregister callback: tmp_index=%d\n", tmp_index));
    return HI_SUCCESS;
}

static hi_void wlan_sm_broadcast_event(hi_wlan_sta_event_e event, hi_void *data)
{
    hi_u32 tmp_index = 0;

    while (tmp_index < MAX_CALLBACK_NUM) {
        if (g_wlan_event_cbs[tmp_index] != NULL) {
            g_wlan_event_cbs[tmp_index](event, data, 0);
        }
        tmp_index++;
    }
}

static hi_void wlan_sm_transfer_state(wlan_state_e *state, wlan_state_e newstate)
{
    DBGPRINT(("WiFi: Transfer state to %d\n", newstate));
    if (pthread_mutex_lock(&g_wlan_sm_mut) != 0) {
        DBGPRINT(("WiFi: g_wlan_sm_mut lock fail in '%s'!\n", __func__));
    }
    *state = newstate;
    if (pthread_mutex_unlock(&g_wlan_sm_mut) != 0) {
        DBGPRINT(("WiFi: g_wlan_sm_mut unlock fail in '%s'!\n", __func__));
    }
}

static hi_s32 wlan_sm_parse_p2p_device(const hi_char *buf, hi_u32 bufSize, hi_wlan_p2p_device_s *device)
{
    hi_unused(bufSize);
    hi_char *pos = NULL;
    hi_char *begin = NULL;
    hi_char *end = NULL;
    hi_char tmp[256] = {0}; /* array tmp max len 256 */
    hi_s32 ret;

    if (buf == NULL || device == NULL) {
        return HI_FAILURE;
    }

    ret = memset_s(device, sizeof(hi_wlan_p2p_device_s), 0, sizeof(hi_wlan_p2p_device_s));
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }
    /* parse device into */
    if ((pos = strstr(buf, "p2p_dev_addr="))) {
        ret = strncpy_s(device->bssid, sizeof(device->bssid), pos + 13, BSSID_LEN);     /* pos offset 13 */
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "name="))) {
        /* the first and last character is "'", ignore it */
        pos += 6;       /* pos offset 6 */
        begin = pos;
        while (*pos != '\0' && *pos != '\'') {
            pos++;
        }
        end = pos;
        ret = strncpy_s(device->name, sizeof(device->name), begin, end - begin);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "pri_dev_type="))) {
        begin = pos + 13;   /* pos offset 13 */
        while (*pos != '\0' && *pos != ' ') {
            pos++;
        }
        end = pos;
        ret = strncpy_s(device->pri_dev_type, sizeof(device->pri_dev_type), begin, end - begin);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "config_methods="))) {
        begin = pos + 15;   /* pos offset 15 */
        while (*pos != '\0' && *pos != ' ') {
            pos++;
        }
        end = pos;
        ret = memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(tmp, sizeof(tmp), begin, end - begin);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = sscanf_s(tmp, "%x", &device->config_method);
        if (ret == -1) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "dev_capab="))) {
        begin = pos + 10;   /* pos offset 10 */
        while (*pos != '\0' && *pos != ' ') {
            pos++;
        }
        end = pos;
        ret = memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(tmp, sizeof(tmp), begin, end - begin);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = sscanf_s(tmp, "%x", &device->dev_capab);
        if (ret == -1) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "group_capab="))) {
        begin = pos + 12;   /* pos offset 12 */
        while (*pos != '\0' && *pos != ' ') {
            pos++;
        }
        end = pos;
        ret = memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(tmp, sizeof(tmp), begin, end - begin);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = sscanf_s(tmp, "%x", &device->group_capab);
        if (ret == -1) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "wfd_dev_info="))) {
        begin = pos + 13;   /* pos offset 13 */
        while (*pos != '\0' && *pos != ' ') {
            pos++;
        }
        end = pos;
        ret = memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(tmp, sizeof(tmp), end - 4, 4);  /* end offset:-4 len:4 */
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = sscanf_s(tmp, "%x", &device->wfd_info.maxThroughput);
        if (ret == -1) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(tmp, sizeof(tmp), end - 8, 4);  /* end offset:-8 len:4 */
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = sscanf_s(tmp, "%x", &device->wfd_info.ctrlPort);
        if (ret == -1) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(tmp, sizeof(tmp), end - 12, 4); /* end offset:-12 len:4 */
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = sscanf_s(tmp, "%x", &device->wfd_info.deviceInfo);
        if (ret == -1) {
            DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    return HI_SUCCESS;
}

static hi_s32 wlan_sm_parse_p2p_group(hi_char *buf, hi_wlan_p2p_group_s *gp)
{
    hi_char *pos = NULL;
    hi_char *begin = NULL;
    hi_char *end = NULL;
    hi_s32 results;

    if (buf == NULL || gp == NULL) {
        return HI_FAILURE;
    }

    results = memset_s(gp, sizeof(hi_wlan_p2p_group_s), 0, sizeof(hi_wlan_p2p_group_s));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    /* interface for example: p2p0 */
    pos = buf;
    begin = pos;
    while (*pos != '\0' && *pos != ' ') {
        pos++;
    }
    end = pos;
    results = strncpy_s(gp->iface, sizeof(gp->iface), begin, end - begin);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    /* GO or Client */
    pos++;
    if (memcmp(pos, "GO", 2) == 0) {    /* string GO len 2 */
        gp->is_group_owner = HI_TRUE;
    } else {
        gp->is_group_owner = HI_FALSE;
    }

    if ((pos = strstr(buf, "ssid="))) {
        pos += 6;   /* pos offset 6 */
        begin = pos;
        while (*pos != '\0' && *pos != '\"') {
            pos++;
        }
        end = pos;
        results = strncpy_s(gp->network_name, sizeof(gp->network_name), begin, end - begin);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if ((pos = strstr(buf, "go_dev_addr="))) {
        pos += 12;  /* pos offset 12 */
        begin = pos;
        while (*pos != '\0' && *pos != ' ') {
            pos++;
        }
        end = pos;
        results = strncpy_s(gp->go.bssid, sizeof(gp->go.bssid), begin, end - begin);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    return HI_SUCCESS;
}

static hi_s32 wlan_sm_parse_provdisc_request(hi_char *buf, hi_u32 buf_size, hi_wlan_p2p_provdisc_s *request)
{
    hi_char *pos = NULL;
    hi_s32 results;

    if (buf == NULL || request == NULL) {
        return HI_FAILURE;
    }

    results = memset_s(request, sizeof(hi_wlan_p2p_provdisc_s), 0, sizeof(hi_wlan_p2p_provdisc_s));
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    if ((pos = strstr(buf, "P2P-PROV-DISC-PBC-REQ"))) {
        request->wps_method = WPS_PBC;
    } else if ((pos = strstr(buf, "P2P-PROV-DISC-SHOW-PIN"))) {
        request->wps_method = WPS_PIN_DISPLAY;
    } else if ((pos = strstr(buf, "P2P-PROV-DISC-ENTER-PIN"))) {
        request->wps_method = WPS_PIN_KEYPAD;
    } else {
        return HI_FAILURE;
    }

    if (wlan_sm_parse_p2p_device(buf, buf_size, &request->device)) {
        return HI_FAILURE;
    }

    if (request->wps_method == WPS_PIN_DISPLAY) {
        pos += 41;  /* pos offset 41 */
        results = memcpy_s(request->pin, sizeof(request->pin), pos, 8); /* pos copy len 8 */
        if (results != EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    return HI_SUCCESS;
}

static hi_s32 wlan_ifc_up(const hi_char *ifname)
{
    struct ifreq ifr;
    hi_s32 s = -1;
    hi_s32 ret = HI_FAILURE;
    hi_s32 results;

    results = memset_s(&ifr, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifname, strlen(ifname) + 1);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(s, SIOCGIFFLAGS, &ifr) >= 0) {
            ifr.ifr_flags = (ifr.ifr_flags | IFF_UP);
            if (ioctl(s, SIOCSIFFLAGS, &ifr) >= 0) {
                ret = HI_SUCCESS;
            }
        }
        close(s);
    }
    return ret;
}

hi_s32 wlan_open(hi_wifi_mode_e mode, hi_char *ifname, hi_u32 ifnameSize, hi_wlan_sta_config_s *pstStaCfg)
{
    hi_s32 ret;
    hi_char iface[IFNAMSIZ + 1];
    hi_s32 count;
    hi_s32 results;

    if (ifname == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    results = memset_s(g_wlan_sm_ifname, sizeof(g_wlan_sm_ifname), 0, sizeof(g_wlan_sm_ifname));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = memset_s(iface, sizeof(iface), 0, sizeof(iface));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    /* ensure supplicant is closed */
    wlan_stop_supplicant();
    /* read usb ID, find supported WiFi device, then load it's driver */
    ret = wlan_unload_driver();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: No driver rmmod!\n"));
    }
    ret = wlan_load_driver(pstStaCfg);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    DBGPRINT(("WiFi: Driver loaded successfully\n"));

    g_pmf_mode = pstStaCfg->pmf_mode;

    /* For MT7601U, ifconfig wlan0 up to create p2p0 */
    if (wlan_ifc_up("wlan0")) {
        DBGPRINT(("WiFi: Failed to up wlan0\n"));
    }

    /* when driver startup, a new wlan network interface will be
     * created, wait 5s for the interface created successfully */
    for (count = 0; count < 50; count++) {  /* loop 50th */
        ret = wlan_util_get_interface(mode, PROC_NET_WIRELESS, iface, sizeof(iface));
        if (ret == HI_FAILURE) {
            ret = wlan_util_get_interface(mode, PROC_NET_DEV, iface, sizeof(iface));
        }
        if (ret == HI_SUCCESS) {
            DBGPRINT(("WiFi: Get interface '%s'\n", iface));
            if (strncpy_s(ifname, ifnameSize, iface, strlen(iface) + 1) != 0) {
                DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
            }
            if (strncpy_s(g_wlan_sm_ifname, sizeof(g_wlan_sm_ifname), iface, strlen(iface) + 1) != 0) {
                DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
            }
            return HI_SUCCESS;
        }
        usleep(100000); /* sleep 100000us=100ms */
    }
    DBGPRINT(("WiFi: Failed to get interface, driver initialized fail!\n"));

    return HI_FAILURE;
}

hi_s32 wlan_common_close(const hi_char *ifname)
{
    hi_s32 ret;
    hi_s32 results;
    struct ifreq ifr;
    hi_s32 s = -1;

    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* configure WiFi interface down, wait 200ms for it down */
    results = memset_s(&ifr, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifname, strlen(ifname) + 1);
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(s, SIOCGIFFLAGS, &ifr) >= 0) {
            ifr.ifr_flags = (ifr.ifr_flags & (~IFF_UP));
            ioctl(s, SIOCSIFFLAGS, &ifr);
        }
        close(s);
    }

    usleep(200000); /* sleep 200000us=200ms */

    DBGPRINT(("WiFi: Unloading driver\n"));
    /* unload WiFi driver */
    ret = wlan_unload_driver();

    return ret;
}
hi_void thread_optimizatioin_variable_set(hi_u32 val)
{
    g_sem_thread = val;
}
hi_u32 thread_optimizatioin_variable_get(hi_void)
{
    return g_sem_thread;
}
static hi_void *wpa_event_receiver_thread(hi_void *args)
{
#define EVENT_BUF_SIZE    2048
    hi_s32 ret = 0;
    hi_s32 results = 0;
    hi_char buf[EVENT_BUF_SIZE] = {0};
    hi_s32 size = 0;
    hi_char priv[1024] = {0};   /* priv max len 1024 */
    hi_char *pos = NULL;
    hi_wpa_message_s *wpa_message = (hi_wpa_message_s *)args;
    hi_wpa_socket_s *mon = wpa_message->mon_conn;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    while (1) {
        results = memset_s(buf, sizeof(buf), 0, sizeof(buf));
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
        size = sizeof(buf);
        ret = wlan_wpa_read(mon, buf, &size);
        if (ret) {
            continue;
        }

        if (!strstr(buf, "CTRL-EVENT-BSS-REMOVED")) {
            DBGPRINT(("WiFi: WPA Event \"%s\"\n", buf));
        }
        if (strstr(buf, "CTRL-EVENT-SCAN-RESULTS")) {
            wlan_sm_send_message(SCAN_RESULTS_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "CTRL-EVENT-CONNECTED")) {
            if (strncmp(wpa_message->ifname, "wlan0", 5) == 0) {  /* wlan0 string len 5 */
                results = memset_s(priv, sizeof(priv), 0, sizeof(priv));
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
                pos = strstr(buf, "Connection to ");
                if (pos) {
                    results = strncpy_s(priv, sizeof(priv), pos + 14, BSSID_LEN);   /* pos offset 14 */
                    if (results < 0) {
                        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                            results, __FILE__, __LINE__, __FUNCTION__));
                    }
                }
                wlan_sm_send_message(STA_CONNECTED_EVENT, priv, NULL, NULL);
            }
        } else if (strstr(buf, "CTRL-EVENT-DISCONNECTED")) {
            results = memset_s(priv, sizeof(priv), 0, sizeof(priv));
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            pos = strstr(buf, "bssid=");
            if (pos) {
                results = strncpy_s(priv, sizeof(priv), pos + 6, BSSID_LEN);    /* pos offset 6 */
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
            }
            wlan_sm_send_message(STA_DISCONNECTED_EVENT, priv, NULL, NULL);
            g_sem_thread = 0;
        } else if ((pos = strstr(buf, "Trying to associate with "))) {
            results = memset_s(priv, sizeof(priv), 0, sizeof(priv));
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            results = strncpy_s(priv, sizeof(priv), pos + 25, BSSID_LEN);       /* pos offset 25 */
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            wlan_sm_send_message(STA_CONNECTING_EVENT, priv, NULL, NULL);
        } else if (strstr(buf, "P2P-DEVICE-FOUND")) {
            /* P2P-DEVICE-FOUND 02:e0:4c:01:e1:79 p2p_dev_addr=02:e0:4c:01:e1:79
             * pri_dev_type=10-0050F204-5 name='Android_7c35' config_methods=0x188
             * dev_capab=0x20 group_capab=0x2b wfd_dev_info=0x00000600111c440032
             */
            hi_wlan_p2p_device_s device;

            if (wlan_sm_parse_p2p_device(buf, sizeof(buf), &device) == HI_SUCCESS) {
                wlan_sm_send_message(P2P_DEVICE_FOUND_EVENT, &device, NULL, NULL);
            }
        } else if (strstr(buf, "P2P-DEVICE-LOST")) {
            /* P2P-DEVICE-LOST p2p_dev_addr=02:e0:4c:01:e1:79 */
            results = memset_s(priv, sizeof(priv), 0, sizeof(priv));
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            pos = strstr(buf, "p2p_dev_addr=");
            if (pos) {
                results = strncpy_s(priv, sizeof(priv), pos + 13, BSSID_LEN);   /* pos offset 13 */
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
            }
            wlan_sm_send_message(P2P_DEVICE_LOST_EVENT, priv, NULL, NULL);
        } else if (strstr(buf, "P2P-FIND-STOPPED")) {
            wlan_sm_send_message(P2P_FIND_STOPPED_EVENT, priv, NULL, NULL);
        } else if (strstr(buf, "P2P-GO-NEG-REQUEST")) {
            /* P2P-GO-NEG-REQUEST a2:0b:ba:db:15:e5 dev_passwd_id=1 */
            hi_wlan_p2p_config_s config;

            results = memset_s(&config, sizeof(config), 0, sizeof(config));
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            if ((pos = strstr(buf, "P2P-GO-NEG-REQUEST"))) {
                results = memcpy_s(config.bssid, sizeof(config.bssid), pos + 19, BSSID_LEN);    /* pos offset 19 */
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
            }

            if ((pos = strstr(buf, "dev_passwd_id="))) {
                pos += 14;  /* pos offset 14 */
                switch (*pos) {
                    case '1':
                        config.wps_method = WPS_PIN_DISPLAY;
                        break;
                    case '5':
                        config.wps_method = WPS_PIN_KEYPAD;
                        break;
                    case '4':
                    default:
                        config.wps_method = WPS_PBC;
                        break;
                }
            }

            wlan_sm_send_message(P2P_GO_NEGOTIATION_REQUEST_EVENT, &config, NULL, NULL);
        } else if (strstr(buf, "P2P-GO-NEG-SUCCESS")) {
            wlan_sm_send_message(P2P_GO_NEGOTIATION_SUCCESS_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "P2P-GO-NEG-FAILURE")) {
            wlan_sm_send_message(P2P_GO_NEGOTIATION_FAILURE_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "P2P-GROUP-FORMATION-SUCCESS")) {
            wlan_sm_send_message(P2P_GROUP_FORMATION_SUCCESS_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "P2P-GROUP-FORMATION-FAILURE")) {
            wlan_sm_send_message(P2P_GROUP_FORMATION_FAILURE_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "P2P-GROUP-STARTED")) {
            /* P2P-GROUP-STARTED p2p0 [client|GO] ssid="DIRECT-n4" freq=2412
             * [psk=2182b2e50e53f260d04f3c7b25ef33c965a3291b9b36b455a82d77fd82ca15bc|
             * passphrase="Pjczy10R"] go_dev_addr=02:e0:4c:01:e1:79
             */
            results = memset_s(priv, sizeof(priv), 0, sizeof(priv));
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            pos = strstr(buf, "P2P-GROUP-STARTED");
            if (pos) {
                results = strncpy_s(priv, sizeof(priv), pos + 18, strlen(pos + 18) + 1);    /* pos offset 18 */
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
            }
            wlan_sm_send_message(P2P_GROUP_STARTED_EVENT, priv, NULL, NULL);
        } else if (strstr(buf, "P2P-GROUP-REMOVED")) {
            /* P2P-GROUP-REMOVED p2p-wlan0-0 [client|GO] reason=REQUESTED */
            wlan_sm_send_message(P2P_GROUP_REMOVED_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "P2P-PROV-DISC-PBC-REQ")) {
            /* P2P-PROV-DISC-PBC-REQ a2:0b:ba:db:15:e5 p2p_dev_addr=a2:0b:ba:db:15:e5
             * pri_dev_type=10-0050F204-5 name='Android_a7b8' config_methods=0x188
             * dev_capab=0x24 group_capab=0x0
             */
            hi_wlan_p2p_provdisc_s request;
            if (wlan_sm_parse_provdisc_request(buf, sizeof(buf), &request) == HI_SUCCESS) {
                wlan_sm_send_message(P2P_PROV_DISC_PBC_REQ_EVENT, &request, NULL, NULL);
            }
        } else if (strstr(buf, "P2P-PROV-DISC-SHOW-PIN")) {
            /* P2P-PROV-DISC-SHOW-PIN a2:0b:ba:db:15:e5 50816750 p2p_dev_addr=a2:0b:ba:db:15:e5
             *  pri_dev_type=10-0050F204-5 name='Android_a7b8' config_methods=0x188
             *  dev_capab=0x24 group_capab=0x0
             */
            hi_wlan_p2p_provdisc_s request;
            if (wlan_sm_parse_provdisc_request(buf, sizeof(buf), &request) == HI_SUCCESS) {
                wlan_sm_send_message(P2P_PROV_DISC_SHOW_PIN_EVENT, &request, NULL, NULL);
            }
        } else if (strstr(buf, "P2P-INVITATION-RECEIVED")) {
            /* P2P-INVITATION-RECEIVED sa=02:e0:4c:01:e1:79 go_dev_addr=02:e0:4c:01:e1:79
             *  bssid=02:e0:4c:01:e1:79 unknown-network
             */
            wlan_sm_send_message(P2P_INVITATION_RECEIVED_EVENT, priv, NULL, NULL);
        } else if (strstr(buf, "AP-STA-CONNECTED")) {
            /* AP-STA-CONNECTED 02:e0:4c:01:e1:79 p2p_dev_addr=02:e0:4c:01:e1:79 */
            /* After group created, wpa_supplicant send event to wlan0 and p2p0 socket,
               so here receive two AP-STA-CONNECTED. */
            if ((g_mon_conn2 == NULL) || (g_mon_conn2 == mon)) {
                wlan_sm_send_message(AP_STA_CONNECTED_EVENT, priv, NULL, NULL);
            }
        } else if (strstr(buf, "AP-STA-DISCONNECTED")) {
            /* AP-STA-DISCONNECTED 02:e0:4c:01:e1:79 p2p_dev_addr=02:e0:4c:01:e1:79 */
            /* After group created, wpa_supplicant send event to wlan0 and p2p0 socket,
               so here receive two AP-STA-DISCONNECTED. */
            if ((g_mon_conn2 == NULL) || (g_mon_conn2 == mon)) {
                wlan_sm_send_message(AP_STA_DISCONNECTED_EVENT, priv, NULL, NULL);
            }
        } else if (strstr(buf, "CTRL-EVENT-TERMINATING")) {
            wlan_sm_send_message(SUPP_STOPPED_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "CTRL-EVENT-g_driver-STATE STOPPED")) {
            wlan_sm_send_message(DRIVER_STOPPED_EVENT, NULL, NULL, NULL);
        } else if (strstr(buf, "WPS-TIMEOUT")) {
            wlan_sm_send_message(WPS_EVENT_TIMEOUT, NULL, NULL, NULL);
        } else if (strstr(buf, "WPS-OVERLAP-DETECTED")) {
            wlan_sm_send_message(WPS_EVENT_OVERLAP, NULL, NULL, NULL);
        } else {
            continue;
        }
    }
    return NULL;
}

static hi_s32 wlan_update_supplicant_config_file(const hi_char *config_file)
{
    hi_s32 ret = HI_SUCCESS;
    hi_char *wbuf = NULL;
    DIR *dir = NULL;
    hi_char file_path[PATH_MAX + 1] = {0};

    /* ensure /dev/wifi exist */
    dir = opendir(g_dev_wifi_dir);
    if (!dir) {
        if (mkdir(g_dev_wifi_dir, 0666) < 0) {      /* dev_wifi_dir mode 0666 */
            DBGPRINT(("WiFi: Create '%s' fail\n", g_dev_wifi_dir));
            return HI_FAILURE;
        }
    }
    closedir(dir);

    /* ensure configure file directory exist */
    dir = opendir(g_supp_config_dir);
    if (!dir) {
        if (mkdir(g_supp_config_dir, 0666) < 0) {   /* supp_config_dir mode 0666 */
            DBGPRINT(("WiFi: Create '%s' fail\n", g_supp_config_dir));
            return HI_FAILURE;
        }
    }
    closedir(dir);

    /* update sta configure file, if not exist, create it */
    if (realpath(config_file, file_path) == NULL) {
        DBGPRINT(("WiFi: file path '%s' not exist and create it [%s]!\n", file_path, __func__));
    }
    hi_s32 fd = open(file_path, O_CREAT | O_TRUNC | O_WRONLY, 0666);   /* file_path mode 0666 */
    if (fd < 0) {
        DBGPRINT(("WiFi: Cann't open configure file '%s'\n", file_path));
        return HI_FAILURE;
    }

    if (strcmp(file_path, g_supp_config_file) == 0) {
        if (asprintf(&wbuf, "ctrl_interface=%s\n"
                     "pmf=%d\n"
                     "config_methods=virtual_display virtual_push_button keypad\n",
                     g_ctrl_iface_dir,
                     g_pmf_mode) < 0) {
            DBGPRINT(("WiFi: asprintf g_supp_config_file failure\n"));
            close(fd);
            free(wbuf);
            return HI_FAILURE;
        }
    } else if (strcmp(file_path, g_p2p_config_file) == 0) {
        if (asprintf(&wbuf, "ctrl_interface=%s\n"
                     "device_name=hisi_5118\n"
                     "manufacturer=hisilicon\n"
                     "device_type=10-0050F204-5\n"
                     "config_methods=virtual_display virtual_push_button"
                     "p2p_listen_reg_class=81\n"
                     "p2p_listen_channel=1\n"
                     "p2p_oper_reg_class=81\n"
                     "p2p_oper_channel=1\n"
                     "persistent_reconnect=1\n",
                     g_ctrl_iface_dir) < 0) {
            DBGPRINT(("WiFi: asprintf g_p2p_config_file failure\n"));
            close(fd);
            free(wbuf);
            return HI_FAILURE;
        }
    } else {
        close(fd);
        return HI_FAILURE;
    }

    if (write(fd, wbuf, strlen(wbuf)) < 0) {
        DBGPRINT(("WiFi: Cann't write configuration to '%s'\n", file_path));
        ret = HI_FAILURE;
    }
    close(fd);
    free(wbuf);

    if (chmod(file_path, 0666) < 0) {                       /* file_path mode 0666 */
        DBGPRINT(("WiFi: Failed to change '%s' to 0666\n", file_path));
        unlink(file_path);
        ret = HI_FAILURE;
    }

    return ret;
}

hi_s32 wlan_ethread_cancel(hi_void)
{
    hi_s32 ret = 0;

    if (g_wlan_ethread) {
        pthread_cancel(g_wlan_ethread);
        pthread_join(g_wlan_ethread, (void *)&ret);
        g_wlan_ethread = 0;
    }

    if (g_wlan_ethread_p2p) {
        pthread_cancel(g_wlan_ethread_p2p);
        pthread_join(g_wlan_ethread_p2p, (void *)&ret);
        g_wlan_ethread_p2p = 0;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_ethread2_cancel(hi_void)
{
    hi_s32 ret = 0;

    if (g_wlan_ethread2) {
        pthread_cancel(g_wlan_ethread2);
        pthread_join(g_wlan_ethread2, (void *)&ret);
        g_wlan_ethread2 = 0;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_timer_thread_cancel(hi_void)
{
    hi_s32 ret = 0;

    if (g_wlan_timer_thread) {
        pthread_cancel(g_wlan_timer_thread);
        pthread_join(g_wlan_timer_thread, (void *)&ret);
        g_wlan_timer_thread = 0;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_common_start(hi_char *sta_ifname, hi_char *p2p_ifname, hi_wifi_mode_e mode)
{
    hi_s32 ret;
    hi_s32 results = 0;
    hi_s32 i;
    DIR *dirptr = NULL;

    if ((mode == WIFI_MODE_STA || mode == WIFI_MODE_STA_P2P) && (sta_ifname == NULL || *sta_ifname == '\0')) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if ((mode == WIFI_MODE_STA_P2P || mode == WIFI_MODE_P2P) && (p2p_ifname == NULL || *p2p_ifname == '\0')) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* ensure /dev/wifi exist */
    dirptr = opendir(g_dev_wifi_dir);
    if (dirptr == NULL) {
        if (mkdir(g_dev_wifi_dir, 0666) != 0) {     /* dev_wifi_dir mode 0666 */
            DBGPRINT(("WiFi: Create '%s' fail\n", g_dev_wifi_dir));
            return HI_FAILURE;
        }
        if (chmod(g_dev_wifi_dir, 0666) != 0) {     /* dev_wifi_dir mode 0666 */
            DBGPRINT(("WiFi: '%s' chmod fail in %s\n", g_dev_wifi_dir, __func__));
        }
    } else {
        closedir(dirptr);
    }

    if (access(g_ctrl_iface_dir, F_OK) == 0) {
        hi_char *wbuf = NULL;

        if (asprintf(&wbuf, "rm -rf %s\n", g_ctrl_iface_dir) < 0) {
            DBGPRINT(("WiFi: asprintf rm g_ctrl_iface_dir failure\n"));
            free(wbuf);
            return HI_FAILURE;
        }
        ret = system(wbuf);
        free(wbuf);
    }

    if (mode == WIFI_MODE_STA) {
        wlan_update_supplicant_config_file(g_supp_config_file);
    } else if (mode == WIFI_MODE_P2P) {
        wlan_update_supplicant_config_file(g_p2p_config_file);
    } else {
        wlan_update_supplicant_config_file(g_supp_config_file);
        wlan_update_supplicant_config_file(g_p2p_config_file);
    }

    /* start wpa_supplicant daemon */
    ret = wlan_start_supplicant(mode, sta_ifname, p2p_ifname, g_driver, g_supp_config_file, g_p2p_config_file);
    if (ret) {
        DBGPRINT(("WiFi: start wpa_supplicant fail\n"));
        return HI_WLAN_START_SUPPLICANT_FAIL;
    }

    DBGPRINT(("WiFi: wpa_supplicant is running, connect to it\n"));

    /* connect to wpa_supplicant, try 50 times, if failed, kill wpa_supplicant */
    if (mode == WIFI_MODE_STA || mode == WIFI_MODE_STA_P2P) {
        for (i = 0; ; i++) {
            if (i == 50) {  /* 50th */
                DBGPRINT(("WiFi: Connect to wpa_supplicant timeout, "
                          "stop wpa_supplicant and return fail\n"));
                wlan_stop_supplicant();
                return HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL;
            }

            g_mon_conn = wlan_wpa_open_connection(sta_ifname, g_ctrl_iface_dir);
            if (g_mon_conn != NULL) {
                DBGPRINT(("WiFi: Connected to wpa_supplicant with '%s'\n", sta_ifname));
                break;
            }
            usleep(100000); /* sleep 100000us=100ms */
        }
        results = sprintf_s(g_wpa_message.ifname, sizeof(g_wpa_message.ifname), "%s", sta_ifname);
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
        g_wpa_message.mon_conn = g_mon_conn;

        /* create thread to receive wpa_supplicant events */
        if (g_wlan_ethread == 0) {
            ret = pthread_create(&g_wlan_ethread, NULL, wpa_event_receiver_thread, &g_wpa_message);
            if (ret != HI_SUCCESS) {
                DBGPRINT(("WiFi: Cann't create monitor thread, "
                          "stop wpa_supplicant and return fail\n"));
                wlan_wpa_close_connection(1, g_mon_conn);
                g_mon_conn = NULL;
                wlan_stop_supplicant();
                return HI_FAILURE;
            }
        }
    }

    if (mode == WIFI_MODE_P2P || mode == WIFI_MODE_STA_P2P) {
        for (i = 0; ; i++) {
            if (i == 50) {  /* 50th */
                DBGPRINT(("WiFi: Connect to wpa_supplicant timeout, "
                          "stop wpa_supplicant and return fail\n"));
                wlan_stop_supplicant();
                return HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL;
            }

            g_mon_conn_p2p = wlan_wpa_open_p2p_connection(p2p_ifname, g_ctrl_iface_dir);
            if (g_mon_conn_p2p != NULL) {
                DBGPRINT(("WiFi: Connected to wpa_supplicant with '%s'\n", p2p_ifname));
                break;
            }
            usleep(100000); /* sleep 100000us=100ms */
        }
        results = sprintf_s(g_wpa_message_p2p.ifname, sizeof(g_wpa_message_p2p.ifname), "%s", p2p_ifname);
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
        g_wpa_message_p2p.mon_conn = g_mon_conn_p2p;

        /* create thread to receive wpa_supplicant events */
        if (g_wlan_ethread_p2p == 0) {
            ret = pthread_create(&g_wlan_ethread_p2p, NULL, wpa_event_receiver_thread, &g_wpa_message_p2p);
            if (ret != HI_SUCCESS) {
                DBGPRINT(("WiFi: Cann't create monitor thread, "
                          "stop wpa_supplicant and return fail\n"));
                wlan_wpa_close_p2p_connection(1, g_mon_conn_p2p);
                g_mon_conn_p2p = NULL;
                wlan_stop_supplicant();
                return HI_FAILURE;
            }
        }
    }

    DBGPRINT(("WiFi: started\n"));
    return HI_SUCCESS;
}

hi_s32 wlan_common_stop(const hi_char *ifname)
{
    hi_s32 ret;

    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    ret = wlan_ethread2_cancel();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_ethread2_cancel fail!\n"));
    }
    ret = wlan_ethread_cancel();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_ethread_cancel fail!\n"));
    }
    ret = wlan_timer_thread_cancel();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_timer_thread_cancel fail!\n"));
    }

    if (g_mon_conn) {
        wlan_wpa_close_connection(1, g_mon_conn);
        g_mon_conn = NULL;
    }
    if (g_mon_conn2) {
        wlan_wpa_close_p2p_connection(1, g_mon_conn2);
        g_mon_conn2 = NULL;
    }

    if (g_mon_conn_p2p) {
        wlan_wpa_close_p2p_connection(1, g_mon_conn_p2p);
        g_mon_conn_p2p = NULL;
    }

    DBGPRINT(("WiFi: Stop wpa_supplicant\n"));
    /* stop wpa_supplicant */
    if (wlan_stop_supplicant()) {
        DBGPRINT(("WiFi: Kill wpa_supplicant fail\n"));
        return HI_FAILURE;
    }

    DBGPRINT(("WiFi: Stopped\n"));
    return HI_SUCCESS;
}

hi_s32 wlan_sta_scan(hi_void)
{
    hi_s32 ret;

    /* send "SCAN" to wpa_supplicant */
    ret = wlan_wpa_request("SCAN", NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_sta_chan_scan(hi_char *chan_cmd)
{
    hi_s32 ret;

    /* send "SCAN" to wpa_supplicant */
    ret = wlan_wpa_request(chan_cmd, NULL, 0);
    if (ret != HI_SUCCESS) {
        printf("wlan_sta_chan_scan: chan_cmd err!\n");
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }
    return ret;
}

hi_s32 wlan_sm_sta_scan_results(hi_char *results, hi_s32 *len)
{
    hi_s32 ret;

    if (results == NULL) {
        return HI_FAILURE;
    }

    /* Request stirng of scan results from wpa_supplicant */
    ret = wlan_wpa_request("SCAN_RESULTS", results, len);
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

hi_s32 wlan_sta_connect(hi_wlan_sta_config_s *pConfig)
{
    hi_char reply[REPLY_SIZE] = {0};
    hi_s32 len = sizeof(reply);
    hi_s32 netId;
    hi_char cmd[256];   /* arr cmd max len 256 */
    hi_s32 ret;
    hi_s32 results = 0;

    DBGPRINT(("WiFi: wlan_sta_connect: ssid=%s, bssid=%s, psk=%s\n",
              pConfig->ssid, pConfig->bssid, pConfig->psswd));

    if (pConfig->security == HI_WLAN_SECURITY_OPEN) {
        DBGPRINT(("WiFi: wlan_sta_connect: security is OPEN\n"));
    }

    /* add_network to wpa_supplicant, and remove all other networks */
    if (wlan_wpa_request("ADD_NETWORK", reply, &len)) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }
    netId = atoi(reply);
    if (netId > 0) {
        hi_s32 i;
        for (i = 0; i <= netId; i++) {
            results = sprintf_s(cmd, sizeof(cmd), "REMOVE_NETWORK %d", i);
            if (results < EOK) {
                DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            if (wlan_wpa_request(cmd, NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: '%s' request fail in %s!\n", cmd, __func__));
            }
        }
        if (wlan_wpa_request("ADD_NETWORK", reply, &len)) {
            return HI_FAILURE;
        }
        netId = atoi(reply);
    }

    /* set network variables into wpa_supplicant, include ssid, bssid,
     * security, password etc.
     * when send "SELECT_NETWORK", connect start
     */
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d ssid P\"%s\"", netId, pConfig->ssid);
    if (ret < 0) {
        DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
    }
    if (wlan_wpa_request(cmd, NULL, 0)) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d bssid %s", netId, pConfig->bssid);
    if (ret < 0) {
        DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
    }
    if (wlan_wpa_request(cmd, NULL, 0)) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    if (pConfig->security == HI_WLAN_SECURITY_OPEN
        || pConfig->security == HI_WLAN_SECURITY_WEP) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d key_mgmt NONE", netId);
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
    }

    if (pConfig->security == HI_WLAN_SECURITY_WEP) {
        hi_s32 pwd_len = (hi_s32)strlen(pConfig->psswd);

        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d auth_alg %s", netId, "SHARED");
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
        if (pwd_len == 5 || pwd_len == 13) {            /* pwd len eual 5 or 13 */
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d wep_key0 \"%s\"", netId, pConfig->psswd);
            if (ret < 0) {
                DBGPRINT(("WiFi: snprintf_s return %d pwd_len=%d cmd=%s\n", ret, pwd_len, cmd));
            }
        } else if (pwd_len == 10 || pwd_len == 26) {    /* pwd len eual 10 or 26 */
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d wep_key0 %s", netId, pConfig->psswd);
            if (ret < 0) {
                DBGPRINT(("WiFi: snprintf_s return %d pwd_len=%d cmd=%s\n", ret, pwd_len, cmd));
            }
        } else {
            return HI_FAILURE;
        }

        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
    }

    if (pConfig->security == HI_WLAN_SECURITY_WPA_WPA2_PSK) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d proto %s", netId, "WPA RSN");
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
        if (g_pmf_mode >= HI_WLAN_PROTECTION_OPTIONAL) {
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d key_mgmt %s",
                             netId, "WPA-PSK WPA-PSK-SHA256");
        } else {
            ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d key_mgmt %s", netId, "WPA-PSK");
        }
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d pairwise %s", netId, "CCMP TKIP");
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d group %s", netId, "CCMP TKIP");
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d psk \"%s\"", netId, pConfig->psswd);
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
    }

    if (pConfig->hidden_ssid == HI_TRUE) {
        ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SET_NETWORK %d scan_ssid 1", netId);
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
        }
        if (wlan_wpa_request(cmd, NULL, 0)) {
            return HI_WLAN_SEND_COMMAND_FAIL;
        }
    }

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "SELECT_NETWORK %d", netId);
    if (ret < 0) {
        DBGPRINT(("WiFi: snprintf_s return %d cmd=%s\n", ret, cmd));
    }
    if (wlan_wpa_request(cmd, NULL, 0)) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_sta_disconnect(hi_void)
{
    if (wlan_wpa_request("DISCONNECT", NULL, 0)) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_sm_sta_connection_status(hi_wlan_sta_conn_status_e *con)
{
    hi_s32 ret;
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 reply_len = sizeof(reply);
    hi_char *pos = NULL;
    hi_s32 results;

    if (con == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* Get string of connection status from wpa_supplicant */
    ret = wlan_wpa_request("STATUS", reply, &reply_len);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    /* Parse string of status, string likes bellow:
     *  1. bssid=ec:23:3d:81:84:95
     *  2. ssid=SSID-HISI
     *  3. id=0
     *  4. mode=station
     *  5. pairwise_cipher=WEP-40
     *  6. group_cipher=WEP-40
     *  7. key_mgmt=NONE
     *  8. wpa_state=COMPLETED
     * while wpa_state=COMPLETED means connected
     */
    if (!(pos = strstr(reply, "wpa_state="))) {
        return HI_FAILURE;
    }

    results = memset_s(con, sizeof(hi_wlan_sta_conn_status_e), 0, sizeof(hi_wlan_sta_conn_status_e));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    pos += 10;  /* pos offset 10 */
    if (strncmp(pos, "COMPLETED", 9) == 0) {    /* string COMPLETED len 9 */
        hi_s32 len;
        hi_char line[128] = {0};    /* array line max len 128 */
        pos = reply;
        hi_s32 i = 0;

        con->state = HI_WLAN_STA_CONN_STATUS_CONNECTED;

        while ((len = wlan_util_read_line(pos, line, sizeof(line)))) {
            if (strncmp(line, "ssid=", 5) == 0) {   /* string ssid= len 5 */
                for (i = 0; i < len - 5; i++) {     /* string ssid= len 5 */
                    con->ap.ssid[i] = line[i + 5];  /* string ssid= len 5 */
                }
            } else if (strncmp(line, "bssid=", 6) == 0) {   /* string bssid= len 6 */
                for (i = 0; i < len - 6; i++) {             /* string bssid= len 6 */
                    con->ap.bssid[i] = line[i + 6];         /* string bssid= len 6 */
                }
            } else if (strncmp(line, "key_mgmt=", 9) == 0) {    /* string key_mgmt= len 9 */
                if (strncmp(line + 9, "NONE", 4) == 0) {        /* line offset 9, string NONE len 4 */
                    con->ap.security = HI_WLAN_SECURITY_OPEN;
                } else if (strncmp(line + 9, "WEP", 3) == 0) {  /* line offset 9, string WEP len 3 */
                    con->ap.security = HI_WLAN_SECURITY_WEP;
                } else if (strncmp(line + 9, "WPA-PSK", 7) == 0) {  /* line offset 9, string WPA-PSK len 7 */
                    con->ap.security = HI_WLAN_SECURITY_WPA_WPA2_PSK;
                }
            }
            pos += len;
        }
    } else {
        con->state = HI_WLAN_STA_CONN_STATUS_DISCONNECTED;
    }

    return ret;
}

hi_s32 wlan_sm_remove_network(hi_void)
{
    hi_s32 ret;

    ret = wlan_wpa_request("REMOVE_NETWORK all", NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_p2p_init(hi_void)
{
    hi_s32 ret;

    ret = wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = wlan_wpa_request_p2p("P2P_SERVICE_FLUSH", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    DBGPRINT(("WiFi: P2P initialized successfully\n"));
    return ret;
}

hi_s32 wlan_p2p_add_device(const hi_wlan_p2p_device_s *device)
{
    hi_bool exist = HI_FALSE;
    hi_u32 i;

    if (device == NULL) {
        return HI_FAILURE;
    }

    for (i = 0; i < g_p2p_peers_num; i++)
        if (strcmp(device->bssid, g_p2p_peers[i].bssid) == 0) {
            /* the device has been in device list, ignore it */
            exist = HI_TRUE;
            break;
        }

    if (exist == HI_FALSE) {
        g_p2p_peers[g_p2p_peers_num] = *device;
        g_p2p_peers_num++;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_p2p_remove_device(const hi_char *buf)
{
    hi_s32 index = HI_FAILURE;
    hi_u32 i;
    hi_s32 results = 0;

    for (i = 0; i < g_p2p_peers_num; i++) {
        if (strcmp(buf, g_p2p_peers[i].bssid) == 0) {
            /* the device has been in device list, delete it */
            index = i;
            break;
        }
    }

    if (index >= 0) {
        while ((hi_u32)index < g_p2p_peers_num - 1) {
            g_p2p_peers[index] = g_p2p_peers[index + 1];
            index++;
        }
        results = memset_s(&g_p2p_peers[index], sizeof(hi_wlan_p2p_device_s), 0, sizeof(hi_wlan_p2p_device_s));
        if (results != EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }

        g_p2p_peers_num--;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_p2p_remove_all_device(hi_void)
{
    hi_u32 i;
    hi_s32 results = 0;

    for (i = 0; i < g_p2p_peers_num; i++) {
        results = memset_s(&g_p2p_peers[i], sizeof(hi_wlan_p2p_device_s), 0, sizeof(hi_wlan_p2p_device_s));
        if (results != EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    g_p2p_peers_num = 0;

    return HI_SUCCESS;
}

hi_s32 wlan_sm_p2p_get_peers(hi_wlan_p2p_device_s *list, hi_u32 *num)
{
    hi_u32 i;

    *num = (g_p2p_peers_num < *num) ? g_p2p_peers_num : *num;

    for (i = 0; i < *num; i++) {
        list[i] = g_p2p_peers[i];
    }

    return HI_SUCCESS;
}

hi_s32 wlan_sm_p2p_get_persistent_groupid(void)
{
    hi_s32 ret;
    hi_s32 i = 10;              /* i init value 10 */
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 len = sizeof(reply);
    hi_char line[256] = { 0 };  /* array line max len 256 */
    hi_char *pos = NULL;
    hi_s32 size;
    hi_s32 networkId = -1;
    hi_char ssid[NETWORK_NAME_LEN] = {0};
    hi_char bssid[BSSID_LEN] = {0};
    hi_char flags[1024] = {0};  /* array flags max len 1024 */

    ret = wlan_wpa_request_p2p("LIST_NETWORKS", reply, &len);
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }
    DBGPRINT(("WiFi: LIST_NETWORKS reply::\n\n"));
    DBGPRINT(("%s\n", reply));

    while (strncmp(reply, "network id", 10) != 0) { /* string <network id> len 10 */
        DBGPRINT(("WiFi: FAILED to receive LIST_NETWORKS reply, send again, left %d\n", i));
        len = STRING_REPLY_SIZE;
        ret = wlan_wpa_request_p2p("LIST_NETWORKS", reply, &len);
        if (ret != HI_SUCCESS) {
            return HI_FAILURE;
        }
        DBGPRINT(("WiFi: LIST_NETWORKS reply::\n\n"));
        DBGPRINT(("%s\n", reply));
        i--;
        if (i <= 0) {
            break;
        }
    }

    pos = reply;
    /* The first line is "network id / ssid / bssid / flags"
     * ignore this line */
    size = wlan_util_read_line(pos, line, sizeof(line));
    if (size == 0) {
        DBGPRINT(("WiFi: anything read for wlan_util_read_line in %s\n", __func__));
    }
    pos += size;

    /* one line a network, p2p group with [P2P-PERSISTENT] */
    while ((size = wlan_util_read_line(pos, line, sizeof(line)))) {
        pos += size;
        if (!strstr(line, "P2P-PERSISTENT")) {
            continue;
        }
        DBGPRINT(("WiFi: line=%s\n", line));
        ret = sscanf_s(line, "%d\t%s\t%s\t%s", &networkId, ssid, sizeof(ssid),
                       bssid, sizeof(bssid), flags, sizeof(flags));
        if (ret < 4) {  /* sscanf_s get len less 4 */
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }

        break;
    }
    DBGPRINT(("WiFi: networkid = %d, ssid=%s,bssid=%s, flag=%s\n", networkId, ssid, bssid, flags));
    return networkId;
}

hi_s32 wlan_sm_p2p_get_persistent_groups(hi_wlan_p2p_group_s *grouplist, hi_u32 *num)
{
    hi_s32 ret;
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 len = sizeof(reply);
    hi_char line[256] = {0};    /* array line max len 256 */
    hi_char *pos = NULL;
    hi_s32 size;
    hi_u32 i = 0;
    hi_s32 networkId = 0;
    hi_char ssid[NETWORK_NAME_LEN] = {0};
    hi_char bssid[BSSID_LEN] = {0};
    hi_char flags[1024] = {0};  /* array flags max len 1024 */

    ret = wlan_wpa_request_p2p("LIST_NETWORKS", reply, &len);
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }

    pos = reply;
    /* The first line is "network id / ssid / bssid / flags"
     * ignore this line */
    size = wlan_util_read_line(pos, line, sizeof(line));
    if (size == 0) {
        DBGPRINT(("WiFi: anything read for wlan_util_read_line in %s\n", __func__));
    }
    pos += size;

    /* one line a network, p2p group with [P2P-PERSISTENT] */
    while ((size = wlan_util_read_line(pos, line, sizeof(line)))) {
        pos += size;
        if (!strstr(line, "P2P-PERSISTENT")) {
            continue;
        }

        ret = sscanf_s(line, "%d\t%s\t%s\t%s", &networkId, ssid, sizeof(ssid),
                       bssid, sizeof(bssid), flags, sizeof(flags));
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = memset_s(grouplist, sizeof(hi_wlan_p2p_group_s), 0, sizeof(hi_wlan_p2p_group_s));
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(grouplist->network_name, sizeof(grouplist->network_name), ssid, strlen(ssid) + 1);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        ret = strncpy_s(grouplist->go.bssid, sizeof(grouplist->go.bssid), bssid, strlen(bssid) + 1);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        i++;
        grouplist++;
        if (i >= *num) {
            break;
        }
    }
    *num = i;
    return HI_SUCCESS;
}

hi_s32 wlan_sm_p2p_delete_persistent_group(const hi_wlan_p2p_group_s *group)
{
    hi_s32 ret;
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 len = sizeof(reply);
    hi_char line[256];          /* array line max len 256 */
    hi_char *pos = NULL;
    hi_s32 size;
    hi_s32 networkId = 0;
    hi_char ssid[NETWORK_NAME_LEN] = {0};
    hi_char bssid[BSSID_LEN] = {0};
    hi_char flags[1024] = {0};  /* array flags max len 1024 */
    hi_char command[256] = {0}; /* array command max len 256 */

    ret = wlan_wpa_request_p2p("LIST_NETWORKS", reply, &len);
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }

    pos = reply;
    /* The first line is "network id / ssid / bssid / flags"
     * ignore this line */
    size = wlan_util_read_line(pos, line, sizeof(line));
    pos += size;

    while ((size = wlan_util_read_line(pos, line, sizeof(line)))) {
        pos += size;
        ret = sscanf_s(line, "%d\t%s\t%s\t%s", &networkId, ssid, sizeof(ssid),
                       bssid, sizeof(bssid), flags, sizeof(flags));
        if (ret < 4) {  /* sscanf_s get len less 4 */
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        if (strcmp(ssid, group->network_name) == 0) {
            ret = snprintf_s(command, sizeof(command), sizeof(command), "REMOVE_NETWORK %d", networkId);
            if (ret < 0) {
                DBGPRINT(("WiFi: snprintf_s return %d command=%s\n", ret, command));
            }
            ret = wlan_wpa_request_p2p(command, NULL, 0);
            break;
        }
    }

    return ret;
}

hi_s32 wlan_p2p_find(const hi_s32 *timeout)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */
    hi_s32 results;

    /* first remove all saved devices */
    ret = wlan_p2p_remove_all_device();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_p2p_remove_all_device fail!\n"));
    }

    /* P2P_FIND [timeout] */
    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    if (timeout) {
        results = sprintf_s(command, sizeof(command), "P2P_FIND %d", *timeout);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    } else {
        results = sprintf_s(command, sizeof(command), "P2P_FIND");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_p2p_connect(hi_wlan_p2p_config_s *pConfig)
{
    hi_s32 ret;
    hi_s32 results;
    hi_char command[256] = {0}; /* array command max len 256 */
    hi_char tmp[256] = {0};     /* array tmp max len 256 */
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 len = sizeof(reply);

    if (pConfig == NULL) {
        return HI_FAILURE;
    }

    /* Stop discovery before issuing connect */
    ret = wlan_wpa_request_p2p("P2P_STOP_FIND", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    /* P2P_CONNECT <peer device address> <pbc|pin|PIN#> [label|display|keypad]
     * [persistent] [join|auth] [go_intent=<0..15>] [freq=<in MHz>]
     */
    results = memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results != EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }

    results = sprintf_s(tmp, sizeof(tmp), "P2P_CONNECT %s", pConfig->bssid);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    switch (pConfig->wps_method) {
        case WPS_PBC:
            results = strcat_s(tmp, sizeof(tmp), " pbc");
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            break;

        case WPS_PIN_DISPLAY:
            results = strcat_s(tmp, sizeof(tmp), " pin");
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            break;

        case WPS_PIN_KEYPAD:
            results = strcat_s(tmp, sizeof(tmp), " ");
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            results = strcat_s(tmp, sizeof(tmp), pConfig->pin);
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            results = strcat_s(tmp, sizeof(tmp), " keypad");
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            break;

        case WPS_PIN_LABEL:
            results = strcat_s(tmp, sizeof(tmp), " ");
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            results = strcat_s(tmp, sizeof(tmp), pConfig->pin);
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            results = strcat_s(tmp, sizeof(tmp), " label");
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            break;

        default:
            return HI_FAILURE;
    }

    ret = snprintf_s(command, sizeof(command), sizeof(command), "%s", tmp);
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }

    ret = wlan_wpa_request_p2p(command, reply, &len);
    if (ret == HI_SUCCESS) {
        if (pConfig->wps_method == WPS_PIN_DISPLAY) {
            len = len < PIN_CODE_LEN ? len : PIN_CODE_LEN;
            if (memcpy_s(pConfig->pin, sizeof(pConfig->pin), reply, len) < 0) {
                DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
            }
            pConfig->pin[sizeof(pConfig->pin) - 1] = '\0';
        }
    }

    return ret;
}

hi_s32 wlan_p2p_cancel_connect(hi_char *ifname)
{
    hi_unused(ifname);
    hi_s32 ret;

    ret = wlan_wpa_request_p2p("P2P_CANCEL", NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_p2p_remove_group(hi_char *ifname)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */
    hi_s32 results;

    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = sprintf_s(command, sizeof(command), "P2P_GROUP_REMOVE %s", ifname);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_p2p_set_wfd_info(hi_wlan_wfd_info_s *pConfig)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */
    hi_s32 results;

    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = sprintf_s(command, sizeof(command), "SET wifi_display %d", pConfig->wfdEnabled);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    DBGPRINT(("WiFi: force to maxThroughput to 30M\n"));
    pConfig->maxThroughput = 30;    /* maxThroughput 30M */
    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = sprintf_s(command, sizeof(command), "WFD_SUBELEM_SET 0 %04x%04x%04x%04x", 6,  /* get first 6 char */
                        pConfig->deviceInfo, pConfig->ctrlPort, pConfig->maxThroughput);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_p2p_set_device_name(hi_char *name)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */
    hi_s32 results;

    if (name == NULL) {
        DBGPRINT(("WiFi:set device name is null\n"));
        return HI_WLAN_INVALID_PARAMETER;
    }
    DBGPRINT(("WiFi:set device name is %s\n", name));
    results = sprintf_s(command, sizeof(command), "SET device_name %s", name);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = wlan_wpa_request_p2p("SAVE_CONFIG", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_p2p_set_device_info(hi_wlan_p2p_device_s *device)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */

    if (device == NULL) {
        return HI_FAILURE;
    }

    ret = wlan_wpa_request_p2p("SET persistent_reconnect 1", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = snprintf_s(command, sizeof(command), sizeof(command), "SET device_name %s", device->name);
    if (ret < 0) {
        DBGPRINT(("WiFi: snprintf_s return %d command=%s\n", ret, command));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = sprintf_s(command, sizeof(command), "SET device_type %s", device->pri_dev_type);
    if (ret < 0) {
        DBGPRINT(("WiFi: snprintf_s return %d command=%s\n", ret, command));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    DBGPRINT(("WiFi: set config_methods to ONLY WPS_PBC(0x80)\n"));
    ret = sprintf_s(command, sizeof(command), "SET config_methods 0x80");
    if (ret < EOK) {
        DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = wlan_p2p_set_wfd_info(&device->wfd_info);
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_p2p_set_wfd_info fail!\n"));
    }

    ret = wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    ret = wlan_wpa_request_p2p("P2P_SERVICE_FLUSH", NULL, 0);
    if (ret != HI_SUCCESS) {
        return HI_WLAN_SEND_COMMAND_FAIL;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_sm_start_wps_pbc(hi_char *bssid)
{
    hi_s32 ret;
    hi_s32 results;
    hi_char command[256] = {0}; /* array command max len 256 */

    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < 0) {
        DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    if (strlen(bssid) == 0) {
        results = strncpy_s(command, sizeof(command), "WPS_PBC", strlen("WPS_PBC") + 1);
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    } else {
        results = snprintf_s(command, sizeof(command), sizeof(command), "WPS_PBC %s", bssid);
        if (results == -1) {
            DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
        }
    }

    ret = wlan_wpa_request(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_sm_start_wps_pbc_p2p(hi_char *bssid)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */
    hi_s32 results;

    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    if (bssid == NULL) {
        results = strcpy_s(command, sizeof(command), "WPS_PBC");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    } else {
        results = sprintf_s(command, sizeof(command), "WPS_PBC %s", bssid);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_sm_start_wps_pin_keypad(hi_char *bssid, hi_char *pin)
{
    hi_s32 ret;
    hi_char command[256] = {0}; /* array command max len 256 */
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 size = STRING_REPLY_SIZE;

    ret = memset_s(command, sizeof(command), 0, sizeof(command));
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = snprintf_s(command, sizeof(command), sizeof(command), "WPS_PIN %s", strlen(bssid) != 0 ? bssid : "any");
    if (ret <= 0) {
        DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
    }
    if (strlen(pin) != 0) {
        ret = snprintf_s(command, sizeof(command), sizeof(command), "%s %s", command, pin);
        if (ret <= 0) {
            DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
        }
    }

    ret = wlan_wpa_request(command, reply, &size);
    if (ret != HI_SUCCESS || size != PIN_CODE_LEN) {
        DBGPRINT(("WiFi: file=%s, line=%d, func=%s ret=%d size=%d\n", __FILE__, __LINE__, __FUNCTION__, ret, size));
        return HI_FAILURE;
    }
    printf("\n\tPIN_CODE:%s\n\n", reply);

    return ret;
}

hi_s32 wlan_sm_start_wps_pin_keypad_p2p(hi_char *pin)
{
    hi_s32 ret;
    hi_char command[256];   /* array command max len 256 */
    hi_s32 results;

    results = memset_s(command, sizeof(command), 0, sizeof(command));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = sprintf_s(command, sizeof(command), "WPS_PIN any %s", pin);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

hi_s32 wlan_p2p_invite(hi_wlan_p2p_group_s *gp, hi_char *bssid, size_t size)
{
    hi_s32 ret;
    hi_char command[256] = {0}; /* array command max len 256 */

    if (bssid == NULL) {
        return HI_FAILURE;
    }

    ret = memset_s(command, sizeof(command), 0, sizeof(command));
    if (ret != 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }
    if (gp == NULL) {
        ret = snprintf_s(command, sizeof(command), 17 + size, "P2P_INVITE peer=%s", bssid); /* 字符串长度17 */
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d command=%s\n", ret, command));
        }
    } else {
        ret = snprintf_s(command, sizeof(command), 37 + sizeof(gp->iface) + size + sizeof(gp->go.bssid), /* 字符串长度37 */
            "P2P_INVITE group=%s peer=%s go_dev_addr=%s", gp->iface, bssid, gp->go.bssid);
        if (ret < 0) {
            DBGPRINT(("WiFi: snprintf_s return %d command=%s\n", ret, command));
        }
    }

    ret = wlan_wpa_request_p2p(command, NULL, 0);
    if (ret != HI_SUCCESS) {
        ret = HI_WLAN_SEND_COMMAND_FAIL;
    }

    return ret;
}

static hi_void *wlan_go_negotiation_timer_thread(hi_void *args)
{
    hi_unused(args);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    /* wait at least 120s for GO negotiation, because WPS needs 120s */
    sleep(20);  /* sleep 20s */
    DBGPRINT(("WiFi: P2P GO negotiate timeout\n"));
    wlan_sm_send_message(CMD_P2P_DISCONNECT, NULL, NULL, NULL);
    return NULL;
}

hi_s32 wlan_start_go_negotiation_timer(hi_void)
{
    hi_s32 ret;

    ret = wlan_timer_thread_cancel();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_timer_thread_cancel fail!\n"));
    }

    ret = pthread_create(&g_wlan_timer_thread, NULL, wlan_go_negotiation_timer_thread, NULL);
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: Cann't create timer thread\n"));
        g_wlan_timer_thread = 0;
    }

    return ret;
}

static hi_s32 wlan_p2p_process_group_started(hi_void *data)
{
    hi_s32 ret;
    hi_s32 results = 0;

    DBGPRINT(("WiFi: P2P group created\n"));
    (hi_void)wlan_sm_parse_p2p_group(data, &g_p2p_group);
    DBGPRINT(("ssid: %s\n", g_p2p_group.network_name));
    DBGPRINT(("role of this device: %s\n", g_p2p_group.is_group_owner ? "GO" : "Client"));
    wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_CREATED);
    wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_GROUP_STARTED, &g_p2p_group);

    ret = wlan_timer_thread_cancel();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: call wlan_timer_thread_cancel fail!\n"));
    }

    /* if interface changed, create a new monitor thread based on this interface */
    if (strcmp(g_p2p_group.iface, g_wlan_sm_ifname)) {
        g_mon_conn2 = wlan_wpa_open_p2p_connection(g_p2p_group.iface, g_ctrl_iface_dir);
        if (g_mon_conn2 != NULL) {
            DBGPRINT(("WiFi: Connected to wpa_supplicant with '%s'\n", g_p2p_group.iface));
        } else {
            DBGPRINT(("WiFi: Connect to wpa_supplicant with '%s' failed\n", g_p2p_group.iface));
            return HI_FAILURE;
        }
        results = sprintf_s(g_wpa_message_p2p2.ifname, sizeof(g_wpa_message_p2p2.ifname), "%s", g_p2p_group.iface);
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
        g_wpa_message_p2p2.mon_conn = g_mon_conn2;

        /* create thread to receive wpa_supplicant events */
        if (g_wlan_ethread2 == 0) {
            ret = pthread_create(&g_wlan_ethread2, NULL, wpa_event_receiver_thread, &g_wpa_message_p2p2);
            if (ret != HI_SUCCESS) {
                DBGPRINT(("WiFi: Cann't create monitor thread\n"));
                wlan_wpa_close_connection(0, g_mon_conn2);
                g_mon_conn2 = NULL;
            }
        }
    }

    /* GC role, send CONNECTED event */
    wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_CONNECTED, &g_p2p_group);

    return HI_SUCCESS;
}

hi_s32 wlan_state_closed(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_s32 ret = HI_FALSE;
    hi_char ifname[IFNAMSIZ + 1] = {0};
    hi_s32 results = 0;
    hi_wlan_sta_config_s *pstStaCfg = (hi_wlan_sta_config_s *)data;

    switch (msg) {
        case CMD_STA_OPEN:
            ret = wlan_util_interface_exist(WIFI_MODE_AP);
            if (ret == HI_SUCCESS) {
                ret = HI_INVALID_HANDLE;
                break;
            }
            ret = wlan_util_interface_exist(WIFI_MODE_STA);
            if (ret == HI_SUCCESS) {
                ret = HI_INVALID_HANDLE;
                break;
            }
            ret = wlan_open(WIFI_MODE_STA, ifname, sizeof(ifname), pstStaCfg);
            if (ret == HI_SUCCESS) {
                if (reply != NULL && len != NULL) {
                    results = strcpy_s(reply, sizeof(ifname), ifname);
                    if (results < EOK) {
                        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n",
                            results, __FILE__, __LINE__, __FUNCTION__));
                    }
                    *len = strlen(reply) + 1;
                }
                wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_P2P_OPEN:
            ret = wlan_util_interface_exist(WIFI_MODE_AP);
            if (ret == HI_SUCCESS) {
                ret = HI_INVALID_HANDLE;
                break;
            }
            ret = wlan_util_interface_exist(WIFI_MODE_P2P);
            if (ret == HI_SUCCESS) {
                ret = HI_INVALID_HANDLE;
                break;
            }
            ret = wlan_open(WIFI_MODE_P2P, ifname, sizeof(ifname), pstStaCfg);
            if (ret == HI_SUCCESS) {
                if (reply != NULL && len != NULL) {
                    results = strcpy_s(reply, sizeof(ifname), ifname);
                    if (results < EOK) {
                        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n",
                            results, __FILE__, __LINE__, __FUNCTION__));
                    }
                    *len = strlen(reply) + 1;
                }
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_driver_loadded(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;
    hi_s32 results = 0;

    switch (msg) {
        case CMD_STA_CLOSE:
        case CMD_P2P_CLOSE:
            ret = wlan_common_close(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_CLOSED);
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_CLOSED);
            }
            break;

        case CMD_STA_START:
            ret = wlan_common_start(data, NULL, WIFI_MODE_STA);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_STA_STARTED);
            }
            break;

        case CMD_P2P_START:
            ret = wlan_common_start(NULL, data, WIFI_MODE_P2P);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
                wlan_p2p_init();
                g_p2p_peers_num = 0;
                memset_s(&g_p2p_peers, sizeof(g_p2p_peers), 0, sizeof(g_p2p_peers));
            }
            break;
        case CMD_STA_P2P_START:
            ret = wlan_common_start("wlan0", "p2p0", WIFI_MODE_STA_P2P);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_STA_STARTED);
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
                wlan_p2p_init();
                g_p2p_peers_num = 0;
                results = memset_s(&g_p2p_peers, sizeof(g_p2p_peers), 0, sizeof(g_p2p_peers));
                if (results < EOK) {
                    DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
                }
            }

            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_sta_started(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;

    switch (msg) {
        case CMD_STA_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_STA_SCAN:
            ret = wlan_sta_scan();
            break;

        case CMD_STA_SCANCHAN:
            ret = wlan_sta_chan_scan((hi_char *)data);
            break;

        case CMD_STA_CONNECT:
            ret = wlan_sta_connect(data);
            break;

        case CMD_STA_DISCONNECT:
            ret = wlan_sta_disconnect();
            break;

        case SCAN_RESULTS_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SCAN_RESULTS_AVAILABLE, NULL);
            break;

        case STA_CONNECTING_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_CONNECTING, data);
            break;

        case STA_CONNECTED_EVENT:
            wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_STA_CONNECTED);
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_CONNECTED, data);
            break;

        case STA_DISCONNECTED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DISCONNECTED, NULL);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        case CMD_P2P_SET_DEVICE_NAME:
            ret = wlan_p2p_set_device_name(data);
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_sta_connected(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;

    switch (msg) {
        case CMD_STA_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_STA_SCAN:
            ret = wlan_sta_scan();
            break;

        case CMD_STA_SCANCHAN:
            ret = wlan_sta_chan_scan((hi_char *)data);
            break;

        case CMD_STA_DISCONNECT:
            ret = wlan_sta_disconnect();
            break;

        case SCAN_RESULTS_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SCAN_RESULTS_AVAILABLE, NULL);
            break;

        case STA_DISCONNECTED_EVENT:
            wlan_sm_transfer_state(&g_wlan_state, WLAN_STATE_STA_STARTED);
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DISCONNECTED, NULL);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        case CMD_P2P_SET_DEVICE_NAME:
            ret = wlan_p2p_set_device_name(data);
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_p2p_started(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;
    hi_s32 results = 0;
    hi_s32 networkId = -1;
    hi_char command[256] = {0}; /* array command max len 256 */

    switch (msg) {
        case CMD_P2P_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_P2P_FIND:
            ret = wlan_p2p_find(data);
            break;

        case CMD_P2P_CONNECT:
            ret = wlan_p2p_connect((hi_wlan_p2p_config_s *)data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_NEGOTIATION);
                wlan_start_go_negotiation_timer();
            }
            break;

        case CMD_P2P_SET_DEVICE_INFO:
            ret = wlan_p2p_set_device_info(data);
            break;

        case CMD_P2P_SET_DEVICE_NAME:
            ret = wlan_p2p_set_device_name(data);
            break;

        case CMD_P2P_LISTEN:
            DBGPRINT(("WiFi: received cmd_p2p_listen, BUT ignore!\n"));
            break;

        case CMD_P2P_FLUSH:
            if (wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: CMD_P2P_FLUSH-'P2P_FLUSH' request fail in '%s'!\n", __func__));
            }
            break;

        case CMD_P2P_GROUP_ADD:
            if (wlan_wpa_request_p2p("WFD_SUBELEM_SET 0 000600111c44001e", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: FAILED to send WFD_SUBELEM_SET 0 000600111c44001e\n"));
            }
            networkId = wlan_sm_p2p_get_persistent_groupid();
            DBGPRINT(("WiFi: CMD_P2P_GROUP_ADD:networkId=%d\n", networkId));
            if (networkId >= 0) {
                results = memset_s(command, sizeof(command), 0, sizeof(command));
                if (results != EOK) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
                results = sprintf_s(command, sizeof(command), "P2P_GROUP_ADD persistent=%d", networkId);
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
                if (wlan_wpa_request_p2p(command, NULL, 0) == HI_FAILURE) {
                    DBGPRINT(("WiFi: P2P_GROUP_ADD persistent=x request fail in '%s'!\n", __func__));
                }
            } else {
                if (wlan_wpa_request_p2p("REMOVE_NETWORK all", NULL, 0) == HI_FAILURE) {
                    DBGPRINT(("WiFi: REMOVE_NETWORK all fail in '%s'!\n", __func__));
                }

                if (wlan_wpa_request_p2p("P2P_GROUP_ADD persistent", NULL, 0) == HI_FAILURE) {
                    DBGPRINT(("WiFi: P2P_GROUP_ADD request fail in '%s'!\n", __func__));
                }
            }
            break;

        case P2P_DEVICE_FOUND_EVENT:
            ret = wlan_p2p_add_device((hi_wlan_p2p_device_s *)data);
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DEVICE_FOUND, data);
            break;

        case P2P_DEVICE_LOST_EVENT:
            ret = wlan_p2p_remove_device(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            }
            if (g_mon_conn2) {
                wlan_wpa_close_connection(0, g_mon_conn2);
                g_mon_conn2 = NULL;
            }
            wlan_ethread2_cancel();
            break;

        case P2P_GO_NEGOTIATION_REQUEST_EVENT: {
            hi_wlan_p2p_config_s *pConfig = (hi_wlan_p2p_config_s *) data;

            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_USER_AUTHORIZING_INVITATION);

            if (pConfig->wps_method == WPS_PIN_DISPLAY) {
                results = strncpy_s(pConfig->pin, sizeof(pConfig->pin),
                    g_p2p_saved_config.pin, sizeof(g_p2p_saved_config.pin));
                if (results < EOK) {
                    DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
                }
            }
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_CONNECTION_REQUESTED, pConfig);
        }
        break;

        case P2P_INVITATION_RECEIVED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_INVITATION, data);
            break;

        case P2P_PROV_DISC_PBC_REQ_EVENT:
        case P2P_PROV_DISC_ENTER_PIN_EVENT:
        case P2P_PROV_DISC_SHOW_PIN_EVENT: {
            /* We let the supplicant handle the provision discovery response
             * and wait instead for the GO_NEGOTIATION_REQUEST_EVENT.
             * Handling provision discovery and issuing a p2p_connect before
             * group negotiation comes through causes issues
             */
            hi_wlan_p2p_provdisc_s *pd = (hi_wlan_p2p_provdisc_s *) data;

            results = strncpy_s(g_p2p_saved_config.bssid, sizeof(g_p2p_saved_config.bssid),
                pd->device.bssid, sizeof(pd->device.bssid));
            if (results != EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }

            g_p2p_saved_config.wps_method = pd->wps_method;
            if (pd->wps_method == WPS_PIN_DISPLAY) {
                results = strncpy_s(g_p2p_saved_config.pin, sizeof(g_p2p_saved_config.pin), pd->pin, sizeof(pd->pin));
                if (results != EOK) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n",
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
            }
        }
        break;

        case P2P_FIND_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            break;

        case STA_CONNECTING_EVENT:
            /* When the group info is stored in peer, peer request connection,
             * this event will be received firstly, then start GO negotiation
             * automatically */
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_NEGOTIATION);
            break;

        case P2P_GROUP_STARTED_EVENT:
            ret = wlan_p2p_process_group_started(data);
            break;

        case AP_STA_DISCONNECTED_EVENT:
            /* Disconnect by self, receive P2P-GROUP-REMOVED then AP-STA-DISCONNECTED,
             * after receive P2P-GROUP-REMOVED, transfer state to P2P_STARTED, so
             * AP-STA-DISCONNECTED is received in P2P_STARTED state. */
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DISCONNECTED, NULL);
            break;

        case P2P_GROUP_REMOVED_EVENT:
            if (wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0)  == HI_FAILURE) {
                DBGPRINT(("WiFi: P2P_GROUP_REMOVED_EVENT-'P2P_FLUSH' request fail in '%s'!\n", __func__));
            }
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_GROUP_REMOVED, NULL);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_p2p_user_authorizing_invitation(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;
    hi_s32 results = 0;

    switch (msg) {
        case CMD_P2P_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_P2P_CONNECT:
            /* User accept the connection request */
            DBGPRINT(("WiFi: User accept the connection request\n"));
            ret = wlan_p2p_connect((hi_wlan_p2p_config_s *) data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_NEGOTIATION);
                wlan_start_go_negotiation_timer();
            } else {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
            }
            break;

        case CMD_P2P_DISCONNECT:
            /* User reject the connection request */
            DBGPRINT(("WiFi: User reject the connection request\n"));
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
            break;

        case CMD_P2P_FIND:
            ret = wlan_p2p_find(data);
            break;

        case CMD_P2P_SET_DEVICE_INFO:
            ret = wlan_p2p_set_device_info(data);
            break;

        case CMD_P2P_SET_DEVICE_NAME:
            ret = wlan_p2p_set_device_name(data);
            break;

        case P2P_DEVICE_FOUND_EVENT:
            ret = wlan_p2p_add_device((hi_wlan_p2p_device_s *)data);
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DEVICE_FOUND, data);
            break;

        case P2P_DEVICE_LOST_EVENT:
            ret = wlan_p2p_remove_device(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            }
            break;
        case P2P_INVITATION_RECEIVED_EVENT:
            break;

        case P2P_PROV_DISC_PBC_REQ_EVENT:
        case P2P_PROV_DISC_ENTER_PIN_EVENT:
        case P2P_PROV_DISC_SHOW_PIN_EVENT: {
            /* We let the supplicant handle the provision discovery response
             * and wait instead for the GO_NEGOTIATION_REQUEST_EVENT.
             * Handling provision discovery and issuing a p2p_connect before
             * group negotiation comes through causes issues
             */
            hi_wlan_p2p_provdisc_s *pd = (hi_wlan_p2p_provdisc_s *) data;

            results = strncpy_s(g_p2p_saved_config.bssid, sizeof(g_p2p_saved_config.bssid),
                pd->device.bssid, strlen(pd->device.bssid) + 1);
            if (results < 0) {
                DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
            }
            g_p2p_saved_config.wps_method = pd->wps_method;
            if (pd->wps_method == WPS_PIN_DISPLAY) {
                results = strncpy_s(g_p2p_saved_config.pin, sizeof(g_p2p_saved_config.pin),
                    pd->pin, strlen(pd->pin) + 1);
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", \
                        results, __FILE__, __LINE__, __FUNCTION__));
                }
            }
        }
        break;

        case P2P_FIND_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_p2p_user_authorizing_join(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;

    switch (msg) {
        case CMD_P2P_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_P2P_CONNECT: {
            /* User accept the connection request */
            hi_wlan_p2p_config_s *pConfig = (hi_wlan_p2p_config_s *) data;

            DBGPRINT(("WiFi: User accept the connection request\n"));
            if (pConfig->wps_method == WPS_PBC) {
                ret = wlan_sm_start_wps_pbc_p2p(NULL);
            } else if (pConfig->wps_method == WPS_PIN_KEYPAD) {
                ret = wlan_sm_start_wps_pin_keypad_p2p(pConfig->pin);
            } else {
                ret = HI_SUCCESS;
            }
            DBGPRINT(("WiFi: count 20s for WPS\n"));
            wlan_start_go_negotiation_timer();
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_CREATED);
        }
        break;

        case CMD_P2P_DISCONNECT:
            /* User reject the connection request */
            DBGPRINT(("WiFi: User reject the connection request\n"));
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_CREATED);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        case P2P_DEVICE_LOST_EVENT:
            ret = wlan_p2p_remove_device(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            }
            DBGPRINT(("WiFi: P2P_DEVICE_LOST, back to STATE_P2P_GROUP_CREATED\n"));
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_GROUP_CREATED);
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_p2p_group_negotiation(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_FALSE;

    switch (msg) {
        case CMD_P2P_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_P2P_DISCONNECT:
            ret = wlan_p2p_cancel_connect(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
            }
            break;

        case P2P_GO_NEGOTIATION_SUCCESS_EVENT:
            DBGPRINT(("WiFi: P2P group owner negotiation success\n"));
            break;

        case P2P_GO_NEGOTIATION_FAILURE_EVENT:
        case P2P_GROUP_FORMATION_FAILURE_EVENT:
            DBGPRINT(("WiFi: P2P group owner negotiation fail\n"));
            ret = wlan_p2p_remove_group("p2p0");
            if (wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: P2P_GO_NEGOTIATION_FAILURE_EVENT-'P2P_FLUSH' \
                    request fail for 'P2P_GROUP_FORMATION_FAILURE_EVENT' in '%s'!\n", __func__));
            }
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
            if (msg == P2P_GO_NEGOTIATION_FAILURE_EVENT) {
                wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_NEGOTIATION_FAILURE, data);
            } else {
                wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_FORMATION_FAILURE, data);
            }
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DISCONNECTED, &g_p2p_group);
            break;

        case P2P_GROUP_FORMATION_SUCCESS_EVENT:
            DBGPRINT(("WiFi: P2P group formation success\n"));
            break;

        case P2P_GROUP_STARTED_EVENT:
            ret = wlan_p2p_process_group_started(data);
            break;

        case P2P_GROUP_REMOVED_EVENT:
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
            if (wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: P2P_GROUP_REMOVED_EVENT-'P2P_FLUSH' request fail in '%s'!\n", __func__));
            }
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_GROUP_REMOVED, NULL);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        case WPS_EVENT_TIMEOUT:
            wlan_sm_broadcast_event(HI_WLAN_WPS_EVENT_TIMEOUT, NULL);
            break;

        case WPS_EVENT_OVERLAP:
            wlan_sm_broadcast_event(HI_WLAN_WPS_EVENT_OVERLAP, NULL);
            break;

        default:
            break;
    }

    return ret;
}

hi_s32 wlan_state_p2p_group_created(hi_s32 msg, hi_void *data, hi_char *reply, hi_s32 *len)
{
    hi_unused(reply);
    hi_unused(len);
    hi_s32 ret = HI_SUCCESS;

    switch (msg) {
        case CMD_P2P_STOP:
            ret = wlan_common_stop(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_DRIVER_LOADDED);
            }
            break;

        case CMD_P2P_CONNECT: {
            hi_wlan_p2p_config_s *pConfig = (hi_wlan_p2p_config_s *)data;

            ret = memcpy_s(&g_p2p_saved_config, sizeof(hi_wlan_p2p_config_s), pConfig, sizeof(hi_wlan_p2p_config_s));
            if (ret != 0) {
                DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
            }
            ret = wlan_p2p_invite(&g_p2p_group, g_p2p_saved_config.bssid, sizeof(g_p2p_saved_config.bssid));
            if (ret == HI_SUCCESS) {
            }
        }
        break;

        case CMD_P2P_DISCONNECT:
            ret = wlan_p2p_remove_group("p2p0");
            break;

        case CMD_P2P_FIND:
            ret = wlan_p2p_find(data);
            break;

        case P2P_DEVICE_FOUND_EVENT:
            ret = wlan_p2p_add_device((hi_wlan_p2p_device_s *)data);
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DEVICE_FOUND, data);
            break;

        case P2P_DEVICE_LOST_EVENT:
            ret = wlan_p2p_remove_device(data);
            if (ret == HI_SUCCESS) {
                wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            }
            break;

        case P2P_FIND_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_PEERS_CHANGED, NULL);
            break;

        case P2P_PROV_DISC_PBC_REQ_EVENT:
        case P2P_PROV_DISC_ENTER_PIN_EVENT:
        case P2P_PROV_DISC_SHOW_PIN_EVENT: {
            /* We let the supplicant handle the provision discovery response
             * and wait instead for the GO_NEGOTIATION_REQUEST_EVENT.
             * Handling provision discovery and issuing a p2p_connect before
             * group negotiation comes through causes issues
             */
            DBGPRINT(("WiFi: set wfd session unavailable\n"));
            if (wlan_wpa_request_p2p("WFD_SUBELEM_SET 0 000600011c44001e", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: FAILED to send WFD_SUBELEM_SET 0 000600011c44001e\n"));
            }
            hi_wlan_p2p_provdisc_s *pd = (hi_wlan_p2p_provdisc_s *) data;

            ret = strncpy_s(g_p2p_saved_config.bssid, sizeof(g_p2p_saved_config.bssid),
                pd->device.bssid, strlen(pd->device.bssid) + 1);
            if (ret != 0) {
                DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
            }
            g_p2p_saved_config.bssid[sizeof(g_p2p_saved_config.bssid) - 1] = '\0';
            g_p2p_saved_config.wps_method = pd->wps_method;
            if (pd->wps_method == WPS_PIN_DISPLAY) {
                ret = strncpy_s(g_p2p_saved_config.pin, sizeof(g_p2p_saved_config.pin), pd->pin, strlen(pd->pin) + 1);
                if (ret != 0) {
                    DBGPRINT(("WiFi: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__));
                }
            }
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_USER_AUTHORIZING_JOIN);
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_CONNECTION_REQUESTED, &g_p2p_saved_config);
        }
        break;

        case AP_STA_DISCONNECTED_EVENT:
            /* GO mode, disconnect event */
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DISCONNECTED, NULL);
            wlan_p2p_remove_group("p2p0");
            break;

        case STA_DISCONNECTED_EVENT:
            /* GC mode, disconnect event */
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_DISCONNECTED, NULL);
            wlan_p2p_remove_group("*");
            break;

        case P2P_GROUP_REMOVED_EVENT:
            wlan_sm_transfer_state(&g_wlan_state_p2p, WLAN_STATE_P2P_STARTED);
            if (wlan_wpa_request_p2p("P2P_FLUSH", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: P2P_GROUP_REMOVED_EVENT-'P2P_FLUSH' request fail in '%s'!\n", __func__));
            }
            wlan_sm_broadcast_event(HI_WLAN_P2P_EVENT_GROUP_REMOVED, NULL);
            break;

        case SUPP_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_SUPP_STOPPED, NULL);
            break;

        case DRIVER_STOPPED_EVENT:
            wlan_sm_broadcast_event(HI_WLAN_STA_EVENT_DRIVER_STOPPED, NULL);
            break;

        case WPS_EVENT_TIMEOUT:
            wlan_sm_broadcast_event(HI_WLAN_WPS_EVENT_TIMEOUT, NULL);
            break;

        case WPS_EVENT_OVERLAP:
            wlan_sm_broadcast_event(HI_WLAN_WPS_EVENT_OVERLAP, NULL);
            break;

        case CMD_P2P_SET_DEVICE_NAME:
            ret = wlan_p2p_set_device_name(data);
            break;

        case AP_STA_CONNECTED_EVENT:
            DBGPRINT(("WiFi: p2p_connected, cancel 20s timer, and set wfd session unavailable\n"));
            wlan_timer_thread_cancel();
            if (wlan_wpa_request_p2p("WFD_SUBELEM_SET 0 000600011c44001e", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: FAILED to send WFD_SUBELEM_SET 0 000600011c44001e\n"));
            }
            DBGPRINT(("WiFi: cancel already wps-active\n"));
            if (wlan_wpa_request_p2p("WPS_CANCEL", NULL, 0) == HI_FAILURE) {
                DBGPRINT(("WiFi: FAILED to send WPS_CANCEL\n"));
            }
            break;
        default:
            break;
    }

    return ret;
}

