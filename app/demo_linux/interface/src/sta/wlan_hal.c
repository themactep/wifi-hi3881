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
#include <sys/wait.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>

#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>

#include "wlan_hal.h"
#include "wlan_util.h"
#include "securec.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
static const hi_char g_wpa_supplicant[] = "wpa_supplicant";

/** struct of global data */
typedef struct hi_sta_data_s {
    hi_s32 device_id;
    hi_wpa_socket_s ctrl_s;
    pthread_mutex_t ctrl_req_mut;
} hi_sta_data_s;

static hi_sta_data_s *g_sta = NULL;
static hi_sta_data_s *g_p2p = NULL;
static hi_s32         g_count = 0;

/*****************************************************************************
  4 函数实现
*****************************************************************************/
hi_s32 wlan_hal_init(hi_void)
{
    hi_s32 results;

    g_sta = malloc(sizeof(hi_sta_data_s));
    if (g_sta == NULL) {
        return HI_FAILURE;
    }

    results = memset_s(g_sta, sizeof(hi_sta_data_s), 0, sizeof(hi_sta_data_s));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    g_sta->device_id = -1;

    if (pthread_mutex_init(&g_sta->ctrl_req_mut, NULL) != 0) {
        DBGPRINT(("WiFi: 'g_sta->ctrl_req_mut' pthread_mutex_init fail in %s!\n", __func__));
    }

    g_p2p = malloc(sizeof(hi_sta_data_s));
    if (g_p2p == NULL) {
        return HI_FAILURE;
    }

    results = memset_s(g_p2p, sizeof(hi_sta_data_s), 0, sizeof(hi_sta_data_s));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    g_p2p->device_id = -1;

    if (pthread_mutex_init(&g_p2p->ctrl_req_mut, NULL) != 0) {
        DBGPRINT(("WiFi: 'g_p2p->ctrl_req_mut' pthread_mutex_init fail in %s!\n", __func__));
    }

    return HI_SUCCESS;
}

hi_void wlan_hal_deinit(hi_void)
{
    if (g_sta) {
        if (pthread_mutex_destroy(&g_sta->ctrl_req_mut) != 0) {
            DBGPRINT(("WiFi: 'g_sta->ctrl_req_mut' pthread_mutex_destroy fail in %s!\n", __func__));
        }
        free(g_sta);
        g_sta = NULL;
    }

    if (g_p2p) {
        if (pthread_mutex_destroy(&g_p2p->ctrl_req_mut) != 0) {
            DBGPRINT(("WiFi: 'g_p2p->ctrl_req_mut' pthread_mutex_destroy fail in %s!\n", __func__));
        }
        free(g_p2p);
        g_p2p = NULL;
    }
}

hi_s32 wlan_load_driver(const hi_wlan_sta_config_s *pstStaCfg)
{
    hi_s32 ret = HI_SUCCESS;
    hi_char bw_cmd[16] = {0};   /* array bw_cmd max len 16 */
    hi_char pro_cmd[16] = {0};  /* array pro_cmd max len 16 */
    hi_s32 results = 0;

    /* get device id */
    g_sta->device_id = wlan_util_get_wifi_device();
    g_p2p->device_id = g_sta->device_id;
    if (g_sta->device_id < 0) {
        DBGPRINT(("WiFi: Cann't find supported device\n"));
        return HI_WLAN_DEVICE_NOT_FOUND;
    }
    DBGPRINT(("WiFi: Find device %d\n", g_sta->device_id));
    /* insmod driver */
    switch (g_sta->device_id) {
        case WIFI_HISILICON_HI3881:
            if (pstStaCfg->bw_sta_config.bw_enable) {
                /* configure BW Mode */
                results = sprintf_s(bw_cmd, sizeof(bw_cmd), "g_bw=%d", pstStaCfg->bw_sta_config.bw_bandwidth);
                if (results < EOK) {
                    DBGPRINT(("WiFi: set Narrow band cmd sprintf_s failure!\n"));
                }
            } else {
                results = sprintf_s(bw_cmd, sizeof(bw_cmd), "g_bw=0");
                if (results < EOK) {
                    DBGPRINT(("WiFi: not set Narrow band cmd sprintf_s failure!\n"));
                }
            }
            results = sprintf_s(pro_cmd, sizeof(pro_cmd), "g_proto=%d", pstStaCfg->hw_mode);
            if (results < EOK) {
                DBGPRINT(("WiFi: set Rate protocol mode sprintf_s failure!\n"));
            }

            if (wlan_util_insmod_module("/kmod/cfg80211.ko", "cfg80211 ", NULL, NULL, NULL)
                || wlan_util_insmod_module("/kmod/hi3881.ko", "hi3881 ", "g_mode=2", bw_cmd, pro_cmd)) {
                ret = HI_WLAN_LOAD_DRIVER_FAIL;
            }
            break;
        default:
            DBGPRINT(("WiFi: device %d is not supported, "
                      "cann't load driver\n", g_sta->device_id));
            ret = HI_WLAN_DEVICE_NOT_FOUND;
            break;
    }

    if (ret == HI_WLAN_LOAD_DRIVER_FAIL) {
        DBGPRINT(("WiFi: Load driver fail\n"));
    }

    return ret;
}

hi_s32 wlan_unload_driver(hi_void)
{
    hi_s32 ret = HI_FAILURE;

    DBGPRINT(("WiFi: Unloading driver\n"));
    g_sta->device_id = wlan_util_get_wifi_device();
    g_p2p->device_id = g_sta->device_id;
    /* rmmod driver */
    switch (g_sta->device_id) {
        case WIFI_HISILICON_HI3881:
            if ((wlan_util_rmmod_module("hi3881") == 0) && (wlan_util_rmmod_module("cfg80211") == 0)) {
                ret = HI_SUCCESS;
            }
            break;
        default:
            DBGPRINT(("WiFi: device %d is not supported, "
                      "cann't unload driver\n", g_sta->device_id));
            break;
    }

    if (ret == HI_SUCCESS) {
        g_p2p->device_id = g_sta->device_id = -1;
    }

    return ret;
}

hi_s32 wlan_start_supplicant(hi_wifi_mode_e mode, const hi_char *sta_ifname, const hi_char *p2p_ifname,
    const hi_char *driver, const hi_char *sta_config_file, const hi_char *p2p_config_file)
{
    hi_s32 ret = 0;
    hi_unused(ret);
    hi_s32 results;
    hi_char cmd[256];                   /* array cmd max len 256 */
    hi_char param[9][128] = { {0} };    /* array param max len 9*128 */
    hi_char *environment_path = NULL;
    hi_s32 num = 0;
    hi_s32 i = 0;
    hi_char *spawn_args[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

    results = sprintf_s(param[0], sizeof(param[0]), "%s", g_wpa_supplicant);    /* param[0] */
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }

    if (mode == WIFI_MODE_STA) {
        results = sprintf_s(param[1], sizeof(param[1]), "-i%s", sta_ifname);    /* param[1] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[2], sizeof(param[2]), "-D%s", driver);        /* param[2] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[3], sizeof(param[3]), "-c%s", sta_config_file); /* param[3] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        num = 4;    /* num equal 4 */
    } else if (mode == WIFI_MODE_P2P) {
        results = sprintf_s(param[1], sizeof(param[1]), "-i%s", p2p_ifname);    /* param[1] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[2], sizeof(param[2]), "-D%s", driver);        /* param[2] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[3], sizeof(param[3]), "-c%s", p2p_config_file); /* param[3] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        num = 4;    /* num equal 4 */
    } else {
        results = sprintf_s(param[1], sizeof(param[1]), "-i%s", p2p_ifname);    /* param[1] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[2], sizeof(param[2]), "-D%s", driver);        /* param[2] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[3], sizeof(param[3]), "-c%s", p2p_config_file); /* param[3] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[4], sizeof(param[4]), "-N");                  /* param[4] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[5], sizeof(param[5]), "-i%s", sta_ifname);    /* param[5] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[6], sizeof(param[6]), "-D%s", driver);        /* param[6] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        results = sprintf_s(param[7], sizeof(param[7]), "-c%s", sta_config_file); /* param[7] */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        num = 8;    /* num equal 8 */
    }
    environment_path = getenv("WPA_SUPPLICANT_DEBUG");
    if (environment_path == NULL) {
        DBGPRINT(("WiFi: getenv 'WPA_SUPPLICANT_DEBUG'no message!\n"));
        results = sprintf_s(param[num], sizeof(param[num]), "-B");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    } else {
        DBGPRINT(("WiFi: getenv WPA_SUPPLICANT_DEBUG=%s\n", environment_path));
        results = sprintf_s(param[num], sizeof(param[num]), "-f%s -t -ddd&", environment_path);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    }

    for (i = 0; i <= num; i++) {
        spawn_args[i] = param[i];
    }

    if (mode == WIFI_MODE_STA_P2P) {
        results = sprintf_s(cmd, sizeof(cmd), "%s %s %s %s %s %s %s %s %s",
            spawn_args[0], spawn_args[1], spawn_args[2], spawn_args[3], spawn_args[4],  /* spawn_args 0/1/2/3/4 */
            spawn_args[5], spawn_args[6], spawn_args[7], spawn_args[8]);                /* spawn_args 5/6/7/8 */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    } else {
        results = sprintf_s(cmd, sizeof(cmd), "%s %s %s %s %s",
            spawn_args[0], spawn_args[1], spawn_args[2], spawn_args[3], spawn_args[4]); /* spawn_args 0/1/2/3/4 */
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    }
    DBGPRINT(("WiFi: system cmd = '%s'\n", cmd));
    ret = system(cmd);
    if (ret == -1) {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 wlan_stop_supplicant(hi_void)
{
    hi_s32 ret = 0;
    hi_unused(ret);
    hi_s32 results;
    hi_char cmd[256] = { 0 };   /* array cmd max len 256 */
    hi_char param[128] = { 0 }; /* array param max len 128 */
    hi_char *spawn_args[] = {"killall -9", NULL, NULL};

    /* get device id */
    g_sta->device_id = wlan_util_get_wifi_device();
    g_p2p->device_id = g_sta->device_id;
    results = sprintf_s(param, sizeof(param), "%s", g_wpa_supplicant);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }

    spawn_args[1] = param;
    results = sprintf_s(cmd, sizeof(cmd), "%s %s", spawn_args[0], spawn_args[1]);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    DBGPRINT(("WiFi: system cmd = '%s'\n", cmd));
    ret = system(cmd);
    if (ret == -1) {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 wlan_wpa_send_command(const hi_wpa_socket_s *wpa_s, const hi_char *cmd, hi_char *reply, hi_s32 *reply_len)
{
    hi_s32 ret;
    hi_s32 i = 0;

    if (wpa_s == NULL || cmd == NULL) {
        return HI_FAILURE;
    }

    /* Send command to wpa_supplicant, if failed, try 50 times */
    do {
        ret = send(wpa_s->s, cmd, strlen(cmd), 0);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EBUSY || errno == EWOULDBLOCK) {
                i++;
                if (i >= 50) {  /* try 50th */
                    ret = HI_FAILURE;
                    goto exit;
                }

                usleep(100000); /* sleep 100000us */
                continue;
            } else {
                ret = HI_FAILURE;
                goto exit;
            }
        } else {
            break;
        }
    } while (1);

    if (reply == NULL || reply_len == NULL) {
        ret = HI_SUCCESS;
        goto exit;
    }

    /* Receive command's reply */
    for (i = 0; i < 100; i++) { /* loop 100th */
        fd_set rfd;
        struct timeval tv;

        FD_ZERO(&rfd);
        FD_SET(wpa_s->s, &rfd);
        tv.tv_sec = 10; /* 10s */
        tv.tv_usec = 0;

        ret = select(wpa_s->s + 1, &rfd, NULL, NULL, &tv);
        if (ret < 0) {
            ret = HI_FAILURE;
            goto exit;
        }

        if (FD_ISSET(wpa_s->s, &rfd)) {
            ret = recv(wpa_s->s, reply, *reply_len, 0);
            if (ret < 0) {
                ret = HI_FAILURE;
                goto exit;
            }

            if (ret > 0 && reply[0] == '<') {
                continue;
            }

            *reply_len = ret;
            break;
        } else {
            ret = HI_FAILURE;
            goto exit;
        }
    }

    ret = HI_SUCCESS;
exit:
    return ret;
}

hi_s32 wlan_wpa_request(const hi_char *cmd, hi_char *cbuf, hi_s32 *size)
{
    hi_s32 reply_len = STRING_REPLY_SIZE;
    hi_s32 ret;

    if (cmd == NULL) {
        return HI_FAILURE;
    }

    hi_char *reply = (hi_char *)malloc(reply_len);
    if (reply == NULL) {
        DBGPRINT(("WiFi: malloc reply mem fail in %s\n", __func__));
        return HI_FAILURE;
    }
    memset_s(reply, STRING_REPLY_SIZE, 0, reply_len);
    ret = wlan_wpa_send_command(&g_sta->ctrl_s, cmd, reply, &reply_len);
    if (ret == HI_FAILURE || strncmp(reply, "FAIL", 4) == 0) {  /* string FAIL len 4 */
        DBGPRINT(("WiFi: '%s' command fail!\n", cmd));
        free(reply);
        reply = NULL;
        return HI_FAILURE;
    }

    if (cbuf != NULL && size != NULL) {
        if (*size < reply_len) {
            reply_len = *size;
        }

        if (memcpy_s(cbuf, STRING_REPLY_SIZE, reply, reply_len) != EOK) {
            free(reply);
            reply = NULL;
            return HI_FAILURE;
        }
        *size = reply_len;
    }
    free(reply);
    reply = NULL;
    return HI_SUCCESS;
}

hi_s32 wlan_wpa_read(const hi_wpa_socket_s *wpa_s, hi_char *event, hi_s32 *size)
{
    hi_s32 ret;
    hi_s32 results;
    struct pollfd rfds[1];

    if (wpa_s == NULL) {
        return -1;
    }

    if (event == NULL || size == NULL) {
        return -1;
    }

    results = memset_s(rfds, sizeof(struct pollfd), 0, 1 * sizeof(struct pollfd));
    if (results < 0) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    rfds[0].fd = wpa_s->s;
    rfds[0].events |= POLLIN;

    ret = poll(rfds, 1, -1);
    if (ret < 0) {
        return ret;
    }

    if (rfds[0].revents & POLLIN) {
        hi_char buf[256] = {0};     /* array buf max len 256 */
        size_t len = sizeof(buf) - 1;

        ret = recv(wpa_s->s, buf, len, 0);
        if (ret >= 0) {
            len = ret;
            buf[len] = '\0';
            if ((hi_s32)(len + 1) > *size) {
                if (memcpy_s(event, *size, buf, *size) != 0) {
                    DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
                }
            } else {
                if (memcpy_s(event, *size, buf, len + 1) != 0) {
                    DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
                }
                *size = len + 1;
            }
        } else {
            return -1;
        }
    }
    return 0;
}

hi_wpa_socket_s *wlan_wpa_open_connection(const hi_char *ifname, const hi_char *ctrl_iface_dir)
{
    hi_char *cfile = NULL;
    hi_s32 flen;
    hi_s32 ret;
    hi_wpa_socket_s *mon_s = NULL;
    hi_s32 flags = 0;
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 reply_len = sizeof(reply);

    if (ifname == NULL || ctrl_iface_dir == NULL) {
        return NULL;
    }

    if (access(ctrl_iface_dir, F_OK) < 0) {
        return NULL;
    }

    flen = strlen(ctrl_iface_dir) + strlen(ifname) + 2; /* add 2 */
    cfile = malloc(flen);
    if (cfile == NULL) {
        return NULL;
    }
    ret = snprintf_s(cfile, flen, flen, "%s/%s", ctrl_iface_dir, ifname);
    if (ret < 0 || ret >= flen) {
        free(cfile);
        return NULL;
    }

    /* Open control socket to send command to wpa_supplicant,
     * only open once. */
    if (g_sta->ctrl_s.s == 0) {
        /* Open socket to send command to wpa_supplicant */
        g_sta->ctrl_s.s = socket(PF_UNIX, SOCK_DGRAM, 0);
        if (g_sta->ctrl_s.s < 0) {
            goto fail;
        }

        g_sta->ctrl_s.local.sun_family = AF_UNIX;
        ret = snprintf_s(g_sta->ctrl_s.local.sun_path, sizeof(g_sta->ctrl_s.local.sun_path),
                         sizeof(g_sta->ctrl_s.local.sun_path), "%s/wpa_%d_%d",
                         ctrl_iface_dir, (int) getpid(), g_count++);
        if (ret < 0 || ret >= (hi_s32)sizeof(g_sta->ctrl_s.local.sun_path)) {
            goto fail;
        }

        if (bind(g_sta->ctrl_s.s, (struct sockaddr *) &g_sta->ctrl_s.local,
                 sizeof(g_sta->ctrl_s.local)) < 0) {
            goto fail;
        }

        g_sta->ctrl_s.remote.sun_family = AF_UNIX;
        ret = strncpy_s(g_sta->ctrl_s.remote.sun_path, sizeof(g_sta->ctrl_s.remote.sun_path),
                        cfile, strlen(cfile) + 1);
        if (ret < 0) {
            DBGPRINT(("WiFi: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__));
        }
        if (connect(g_sta->ctrl_s.s, (struct sockaddr *) &g_sta->ctrl_s.remote,
                    sizeof(g_sta->ctrl_s.remote)) < 0) {
            goto fail;
        }

        flags = fcntl(g_sta->ctrl_s.s, F_GETFL);
        if (flags >= 0) {
            flags = (hi_u32)flags | O_NONBLOCK;
            if (fcntl(g_sta->ctrl_s.s, F_SETFL, flags) < 0) {
                DBGPRINT(("WiFi: fcntl fail\n"));
            }
        }
    }

    /* Open monitor socket to receive wpa_supplicant's event */
    mon_s = (hi_wpa_socket_s *)malloc(sizeof(hi_wpa_socket_s));
    if (mon_s == NULL) {
        goto fail;
    }

    mon_s->s = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (mon_s->s < 0) {
        goto fail;
    }

    mon_s->local.sun_family = AF_UNIX;
    ret = snprintf_s(mon_s->local.sun_path, sizeof(mon_s->local.sun_path), sizeof(mon_s->local.sun_path),
                     "%s/wpa_%d_%d", ctrl_iface_dir, (int)getpid(), g_count++);
    if (ret < 0 || ret >= (hi_s32)sizeof(mon_s->local.sun_path)) {
        goto fail;
    }

    if (bind(mon_s->s, (struct sockaddr *) &mon_s->local,
             sizeof(mon_s->local)) < 0) {
        goto fail;
    }

    mon_s->remote.sun_family = AF_UNIX;
    ret = strncpy_s(mon_s->remote.sun_path, sizeof(mon_s->remote.sun_path),
                    cfile, strlen(cfile) + 1);
    if (ret != 0) {
        DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
    }
    if (connect(mon_s->s, (struct sockaddr *) &mon_s->remote,
                sizeof(mon_s->remote)) < 0) {
        goto fail;
    }

    flags = fcntl(mon_s->s, F_GETFL);
    if (flags >= 0) {
        flags = (hi_u32)flags | O_NONBLOCK;
        if (fcntl(mon_s->s, F_SETFL, flags) < 0) {
            DBGPRINT(("WiFi: fcntl fail\n"));
        }
    }

    /* Attach mon_s socket to wpa_supplicant */
    ret = wlan_wpa_send_command(mon_s, "ATTACH", reply, &reply_len);
    if (ret == HI_FAILURE || strncmp(reply, "OK", 2) != 0) {    /* string OK len 2 */
        DBGPRINT(("WiFi: Attach to wpa_supplicant fail\n"));
        goto fail;
    }

    free(cfile);

    return mon_s;
fail:
    if (cfile) {
        free(cfile);
    }

    unlink(g_sta->ctrl_s.local.sun_path);
    if (g_sta->ctrl_s.s >= 0) {
        close(g_sta->ctrl_s.s);
    }

    ret = memset_s(&g_sta->ctrl_s, sizeof(hi_wpa_socket_s), 0, sizeof(hi_wpa_socket_s));
    if (ret != 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__));
    }

    if (mon_s) {
        unlink(mon_s->local.sun_path);
        if (mon_s->s >= 0) {
            close(mon_s->s);
        }

        free(mon_s);
    }

    return NULL;
}

hi_void wlan_wpa_close_connection(hi_s32 control, hi_wpa_socket_s *wpa_s)
{
    /* close control socket */
    if (control && g_sta->ctrl_s.s > 0) {
        unlink(g_sta->ctrl_s.local.sun_path);
        close(g_sta->ctrl_s.s);
        memset_s(&g_sta->ctrl_s, sizeof(hi_wpa_socket_s), 0, sizeof(hi_wpa_socket_s));
    }

    if (wpa_s) {
        if (wlan_wpa_send_command(wpa_s, "DETACH", NULL, NULL) == HI_FAILURE) {
            DBGPRINT(("WiFi: 'DETACH' wlan_wpa_send_command fail in %s!\n", __func__));
        }

        unlink(wpa_s->local.sun_path);
        if (wpa_s->s > 0) {
            close(wpa_s->s);
        }
        free(wpa_s);
    }
}

hi_wpa_socket_s *wlan_wpa_open_p2p_connection(const hi_char *ifname, const hi_char *ctrl_iface_dir)
{
    hi_char *cfile = NULL;
    hi_s32 flen, ret;
    hi_wpa_socket_s *mon_s = NULL;
    hi_s32 flags;
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 reply_len = sizeof(reply);
    hi_s32 results = 0;

    if (ifname == NULL || ctrl_iface_dir == NULL) {
        return NULL;
    }

    if (access(ctrl_iface_dir, F_OK) < 0) {
        return NULL;
    }

    flen = strlen(ctrl_iface_dir) + strlen(ifname) + 2; /* add 2 */
    cfile = malloc(flen);
    if (cfile == NULL) {
        return NULL;
    }
    ret = sprintf_s(cfile, flen, "%s/%s", ctrl_iface_dir, ifname);
    if (ret < 0 || ret >= flen) {
        free(cfile);
        return NULL;
    }

    /* Open control socket to send command to wpa_supplicant,
     * only open once. */
    if (g_p2p->ctrl_s.s == 0) {
        /* Open socket to send command to wpa_supplicant */
        g_p2p->ctrl_s.s = socket(PF_UNIX, SOCK_DGRAM, 0);
        if (g_p2p->ctrl_s.s < 0) {
            goto fail;
        }

        g_p2p->ctrl_s.local.sun_family = AF_UNIX;
        ret = sprintf_s(g_p2p->ctrl_s.local.sun_path, sizeof(g_p2p->ctrl_s.local.sun_path),
                        "%s/wpa_%d_%d", ctrl_iface_dir, (int) getpid(), g_count++);
        if (ret < 0 || ret >= (hi_s32)sizeof(g_p2p->ctrl_s.local.sun_path)) {
            goto fail;
        }

        if (bind(g_p2p->ctrl_s.s, (struct sockaddr *) &g_p2p->ctrl_s.local,
                 sizeof(g_p2p->ctrl_s.local)) < 0) {
            goto fail;
        }

        g_p2p->ctrl_s.remote.sun_family = AF_UNIX;
        ret = strcpy_s(g_p2p->ctrl_s.remote.sun_path, sizeof(g_p2p->ctrl_s.remote.sun_path), cfile);
        if (ret != EOK) {
            DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
        }
        if (connect(g_p2p->ctrl_s.s, (struct sockaddr *)&(g_p2p->ctrl_s.remote), sizeof(g_p2p->ctrl_s.remote)) < 0) {
            goto fail;
        }

        flags = fcntl(g_p2p->ctrl_s.s, F_GETFL);
        if (flags >= 0) {
            flags = (hi_u32)flags | O_NONBLOCK;
            if (fcntl(g_p2p->ctrl_s.s, F_SETFL, flags) < 0) {
                DBGPRINT(("WiFi: fcntl fail\n"));
            }
        }
    }

    /* Open monitor socket to receive wpa_supplicant's event */
    mon_s = (hi_wpa_socket_s *)malloc(sizeof(hi_wpa_socket_s));
    if (mon_s == NULL) {
        goto fail;
    }

    mon_s->s = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (mon_s->s < 0) {
        goto fail;
    }

    mon_s->local.sun_family = AF_UNIX;
    ret = sprintf_s(mon_s->local.sun_path, sizeof(mon_s->local.sun_path),
                    "%s/wpa_%d_%d", ctrl_iface_dir, (int) getpid(), g_count++);
    if (ret < 0 || ret >= (hi_s32)sizeof(mon_s->local.sun_path)) {
        goto fail;
    }

    if (bind(mon_s->s, (struct sockaddr *) &mon_s->local,
             sizeof(mon_s->local)) < 0) {
        goto fail;
    }

    mon_s->remote.sun_family = AF_UNIX;
    ret = strcpy_s(mon_s->remote.sun_path, sizeof(mon_s->remote.sun_path), cfile);
    if (ret != EOK) {
        DBGPRINT(("WiFi: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
    }

    if (connect(mon_s->s, (struct sockaddr *) &mon_s->remote,
                sizeof(mon_s->remote)) < 0) {
        goto fail;
    }

    flags = fcntl(mon_s->s, F_GETFL);
    if (flags >= 0) {
        flags = (hi_u32)flags | O_NONBLOCK;
        if (fcntl(mon_s->s, F_SETFL, flags) < 0) {
            DBGPRINT(("WiFi: fcntl fail\n"));
        }
    }

    /* Attach mon_s socket to wpa_supplicant */
    ret = wlan_wpa_send_command(mon_s, "ATTACH", reply, &reply_len);
    if (ret == HI_FAILURE || strncmp(reply, "OK", 2) != 0) {    /* string OK len 2 */
        DBGPRINT(("WiFi: Attach to wpa_supplicant fail\n"));
        goto fail;
    }

    free(cfile);

    return mon_s;
fail:
    if (cfile) {
        free(cfile);
    }

    unlink(g_p2p->ctrl_s.local.sun_path);
    if (g_p2p->ctrl_s.s >= 0) {
        close(g_p2p->ctrl_s.s);
    }

    results = memset_s(&g_p2p->ctrl_s, sizeof(hi_wpa_socket_s), 0, sizeof(hi_wpa_socket_s));
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }

    if (mon_s) {
        unlink(mon_s->local.sun_path);
        if (mon_s->s >= 0) {
            close(mon_s->s);
        }

        free(mon_s);
    }

    return NULL;
}

hi_void wlan_wpa_close_p2p_connection(hi_s32 control, hi_wpa_socket_s *wpa_s)
{
    hi_s32 results = 0;

    /* close control socket */
    if (control && g_p2p->ctrl_s.s > 0) {
        unlink(g_p2p->ctrl_s.local.sun_path);
        close(g_p2p->ctrl_s.s);
        results = memset_s(&g_p2p->ctrl_s, sizeof(hi_wpa_socket_s), 0, sizeof(hi_wpa_socket_s));
        if (results != EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, line=%d, func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
        }
    }

    if (wpa_s) {
        if (wlan_wpa_send_command(wpa_s, "DETACH", NULL, NULL) == HI_FAILURE) {
            DBGPRINT(("WiFi: 'DETACH' wlan_wpa_send_command fail in %s!\n", __func__));
        }

        unlink(wpa_s->local.sun_path);
        if (wpa_s->s > 0) {
            close(wpa_s->s);
        }
        free(wpa_s);
    }
}


hi_s32 wlan_wpa_request_p2p(const hi_char *cmd, hi_char *cbuf, hi_s32 *size)
{
    hi_char reply[STRING_REPLY_SIZE] = {0};
    hi_s32 reply_len;
    hi_s32 ret;
    hi_s32 results = 0;

    if (cmd == NULL) {
        return HI_FAILURE;
    }

    reply_len = sizeof(reply);
    ret = wlan_wpa_send_command(&g_p2p->ctrl_s, cmd, reply, &reply_len);
    if (ret == HI_FAILURE || strncmp(reply, "FAIL", 4) == 0) {  /* string FAIL len 4 */
        DBGPRINT(("WiFi: '%s' command fail!\n", cmd));
        return HI_FAILURE;
    }

    if (cbuf != NULL && size != NULL) {
        if (*size < reply_len) {
            reply_len = *size;
        }

        results = strncpy_s(cbuf, *size, reply, reply_len);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        *size = reply_len;
    }

    return HI_SUCCESS;
}
