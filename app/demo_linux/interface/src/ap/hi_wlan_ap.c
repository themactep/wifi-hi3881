/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wlan ap.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/wireless.h>

#include "hi_wlan.h"
#include "wlan_util.h"
#include "securec.h"

/*****************************************************************************
  2 全局变量
*****************************************************************************/
static const hi_char g_dev_wifi_dir[] = "/etc/Wireless";
static const hi_char g_hostapd_config_dir[] = "/etc/Wireless/";
static const hi_char g_hostapd_config_file[] = "/etc/Wireless/hostapd.conf";
static const hi_char g_entropy_file[] = "/etc/Wireless/entropy.bin";

static hi_s32            g_device_id = -1;

/*****************************************************************************
  3 函数实现
*****************************************************************************/
/* For Broadcom's WiFi, after loading driver, before startup SoftAP, must
 * set SoftAP's firmware path to /sys/module/bcmdhd/paramters/firmware_path.
 * The name of firmware file should contain '_apsta'. */
hi_s32 ap_update_firmware_path(hi_s32 device)
{
    hi_unused(device);
    hi_s32 fd;

    fd = open("/sys/module/bcmdhd/parameters/firmware_path", O_TRUNC | O_WRONLY);
    if (fd < 0) {
        DBGPRINT(("WiFi: '/sys/module/bcmdhd/parameters/firmware_path' open fail in %s!\n", __func__));
        return -1;
    }

    if (fd >= 0) {
        close(fd);
    }

    return 0;
}

static hi_s32 ap_load_driver(hi_wlan_bandwith_e bw)
{
    hi_s32 ret = HI_SUCCESS;
    hi_char bw_cmd[16] = {0};   /* array bw_cmd len 16 */
    hi_s32 results = 0;

    g_device_id = wlan_util_get_wifi_device();
    if (g_device_id < 0) {
        DBGPRINT(("WiFi: Cann't find supported device\n"));
        return HI_WLAN_DEVICE_NOT_FOUND;
    }
    DBGPRINT(("WiFi: Find device %d\n", g_device_id));

    /* insmod driver */
    switch (g_device_id) {
        case WIFI_HISILICON_HI3881:
            /* configure BW Mode */
            results = sprintf_s(bw_cmd, sizeof(bw_cmd), "g_bw=%d", bw);
            if (results < EOK) {
                DBGPRINT(("WiFi: ap Narrow band config saprintf_s failure!\n"));
            }
            if (wlan_util_insmod_module("/kmod/cfg80211.ko", "cfg80211 ", NULL, NULL, NULL)
                || wlan_util_insmod_module("/kmod/hi3881.ko", "hi3881 ", "g_mode=2", bw_cmd, NULL)) {
                ret = HI_WLAN_LOAD_DRIVER_FAIL;
            }
            break;
        default:
            DBGPRINT(("WiFi: device %d is not supported, "
                      "cann't load driver\n", g_device_id));
            ret = HI_WLAN_DEVICE_NOT_FOUND;
            break;
    }

    if (ret == HI_WLAN_LOAD_DRIVER_FAIL) {
        DBGPRINT(("WiFi: Load driver fail\n"));
    }

    return ret;
}

static hi_s32 ap_unload_driver(hi_void)
{
    hi_s32 ret = HI_FAILURE;

    DBGPRINT(("WiFi: Unloading driver\n"));
    /* rmmod driver */
    switch (g_device_id) {
        case WIFI_HISILICON_HI3881:
            if ((wlan_util_rmmod_module("hi3881") == 0)
                && (wlan_util_rmmod_module("cfg80211") == 0)) {
                ret = HI_SUCCESS;
            }
            break;
        default:
            DBGPRINT(("WiFi: device %d is not supported, "
                      "cann't unload driver\n", g_device_id));
            break;
    }

    if (ret == HI_SUCCESS) {
        g_device_id = -1;
    }

    return ret;
}

/* configure softap by sending private ioctls to driver directly */
hi_s32 ap_config_with_iwpriv_cmd(hi_s32 s, const hi_char *ifname,
                                 hi_wlan_ap_config_s *ap_cfg)
{
    char tbuf[4096];    /* array tbuf len 4096 */
    struct iwreq wrq;
    struct iw_priv_args *priv_ptr = NULL;
    hi_s32 i;
    hi_s32 j;
    hi_s32 cmd = 0;
    hi_s32 sub_cmd = 0;
    hi_char mbuf[256];  /* array mbuf len 256 */
    hi_s32 results;

    /* get all private commands that driver supported */
    results = strncpy_s(wrq.ifr_name, sizeof(wrq.ifr_name), ifname, strlen(ifname) + 1);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    wrq.u.data.pointer = tbuf;
    wrq.u.data.length = sizeof(tbuf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    if (ioctl(s, SIOCGIWPRIV, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* if driver don't support 'set' command, return failure */
    priv_ptr = (struct iw_priv_args *)wrq.u.data.pointer;
    for (i = 0; i < wrq.u.data.length; i++) {
        if (strcmp(priv_ptr[i].name, "set") == 0) {
            cmd = priv_ptr[i].cmd;
            break;
        }
    }
    if (i == wrq.u.data.length) {
        return HI_FAILURE;
    }

    /* get the 'set' command's ID */
    if (cmd < SIOCDEVPRIVATE) {
        for (j = 0; j < i; j++) {
            if ((priv_ptr[j].set_args == priv_ptr[i].set_args)
                && (priv_ptr[j].get_args == priv_ptr[i].get_args)
                && (priv_ptr[j].name[0] == '\0')) {
                break;
            }
        }
        if (j == i) {
            return HI_FAILURE;
        }
        sub_cmd = cmd;
        cmd = priv_ptr[j].cmd;
    }

    /* configure AP, order should be as follow
     *   0. WirelessMode
     *   1. Channel
     *   2. AuthMode
     *   3. EncrypType
     * for WPAPSK/WPA2PSK:
     *   4. SSID (must after AuthMode and before Password)
     *   5. Password
     * for WEP:
     *   4. Password
     *   5. SSID (must set lastly)
     */
    results = strncpy_s(wrq.ifr_name, sizeof(wrq.ifr_name), ifname, strlen(ifname) + 1);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    wrq.u.data.pointer = mbuf;
    wrq.u.data.flags = sub_cmd;

    /* configure WirelessMode */
    results = sprintf_s(mbuf, sizeof(mbuf), "WirelessMode=9");
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }

    wrq.u.data.length = strlen(mbuf) + 1;
    if (ioctl(s, cmd, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* configure Channel */
    results = sprintf_s(mbuf, sizeof(mbuf), "Channel=%d", ap_cfg->channel);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    wrq.u.data.length = strlen(mbuf) + 1;
    if (ioctl(s, cmd, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* configure AuthMode */
    if (ap_cfg->security == HI_WLAN_SECURITY_OPEN) {
        results = sprintf_s(mbuf, sizeof(mbuf), "AuthMode=OPEN");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    } else if (ap_cfg->security == HI_WLAN_SECURITY_WEP) {
        results = sprintf_s(mbuf, sizeof(mbuf), "AuthMode=WEPAUTO");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    } else if (ap_cfg->security == HI_WLAN_SECURITY_WPA_WPA2_PSK) {
        results = sprintf_s(mbuf, sizeof(mbuf), "AuthMode=WPA2PSK");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    }
    wrq.u.data.length = strlen(mbuf) + 1;
    if (ioctl(s, cmd, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* configure EncrypType */
    if (ap_cfg->security == HI_WLAN_SECURITY_OPEN) {
        results = sprintf_s(mbuf, sizeof(mbuf), "EncrypType=NONE");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    } else if (ap_cfg->security == HI_WLAN_SECURITY_WEP) {
        results = sprintf_s(mbuf, sizeof(mbuf), "EncrypType=WEP");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    } else if (ap_cfg->security == HI_WLAN_SECURITY_WPA_WPA2_PSK) {
        results = sprintf_s(mbuf, sizeof(mbuf), "EncrypType=AES");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
    }
    wrq.u.data.length = strlen(mbuf) + 1;
    if (ioctl(s, cmd, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* configure password of WEP */
    if (ap_cfg->security == HI_WLAN_SECURITY_WEP) {
        results = sprintf_s(mbuf, sizeof(mbuf), "DefaultKeyID=1");
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        wrq.u.data.length = strlen(mbuf) + 1;
        if (ioctl(s, cmd, &wrq) < 0) {
            return HI_FAILURE;
        }

        results = sprintf_s(mbuf, sizeof(mbuf), "Key1=%s", ap_cfg->psswd);
        if (results < EOK) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        wrq.u.data.length = strlen(mbuf) + 1;
        if (ioctl(s, cmd, &wrq) < 0) {
            return HI_FAILURE;
        }
    }

    /* configure hide SSID */
    results = sprintf_s(mbuf, sizeof(mbuf), "HideSSID=%d", ap_cfg->hidden_ssid ? 1 : 0);
    if (results < EOK) {
        DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
    }
    wrq.u.data.length = strlen(mbuf) + 1;
    if (ioctl(s, cmd, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* configure SSID */
    if (snprintf_s(mbuf, sizeof(mbuf), sizeof(mbuf), "SSID=%s", ap_cfg->ssid) < 0) {
        DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
    }
    wrq.u.data.length = strlen(mbuf) + 1;
    if (ioctl(s, cmd, &wrq) < 0) {
        return HI_FAILURE;
    }

    /* configure password of WPAPSK/WPA2PSK */
    if (ap_cfg->security == HI_WLAN_SECURITY_WPA_WPA2_PSK) {
        results = snprintf_s(mbuf, sizeof(mbuf), sizeof(ap_cfg->psswd), "WPAPSK=%s", ap_cfg->psswd);
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }
        wrq.u.data.length = strlen(mbuf) + 1;
        if (ioctl(s, cmd, &wrq) < 0) {
            return HI_FAILURE;
        }
    }

    return HI_SUCCESS;
}

static hi_s32 ap_start_hostapd(const hi_char *config_file, const hi_char *entropy_file)
{
    hi_s32 ret;
    hi_s32 results;
    hi_char cmd[256] = {0};     /* array cmd len 256 */
    char param[2][256] = {{0}}; /* array param len 2*256 */
    char *spawn_args[] = {"hostapd", NULL, NULL, NULL, NULL};

    results = snprintf_s(param[0], sizeof(param[0]), sizeof(param[0]), "%s", config_file);
    if (results == -1) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    results = snprintf_s(param[1], sizeof(param[1]), sizeof(param[1]), "-e%s", entropy_file);
    if (results == -1) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    spawn_args[1] = "-B";       /* 0:hostapd  1:-B  2:entropy  3:config */
    spawn_args[2] = param[1];   /* 0:hostapd  1:-B  2:entropy  3:config */
    spawn_args[3] = param[0];   /* 0:hostapd  1:-B  2:entropy  3:config */

    results = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "%s %s %s %s", \
        spawn_args[0], spawn_args[1], spawn_args[2],  spawn_args[3]);  /* 0:hostapd  1:-B  2:entropy  3:config */
    if (results == -1) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    DBGPRINT(("WiFi: system cmd = '%s'\n", cmd));
    ret = system(cmd);

    return ret;
}

static hi_s32 ap_kill_hostapd(hi_void)
{
    hi_s32 ret;
    hi_char cmd[256] = {0}; /* array cmd len 256 */
    hi_char *spawn_args[] = {"killall -9", NULL, NULL};

    spawn_args[1] = "hostapd";

    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "%s %s", spawn_args[0], spawn_args[1]);
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__));
    }
    DBGPRINT(("WiFi: system cmd = '%s'\n", cmd));
    ret = system(cmd);

    return ret;
}

static hi_s32 ap_update_hostapd_config_file(const hi_char *ifname, hi_wlan_ap_config_s *ap_cfg,
    const hi_char *config_file)
{
    hi_s32 ret = 0;
    hi_s32 results;
    hi_char *fbuf = NULL;
    hi_char *wbuf = NULL;
    DIR *dir = NULL;
    hi_char hw_mode = 0;
    hi_unused(hw_mode);
    hi_s32 broadcast_ssid = 0;
    hi_char ht40[32];   /* array ht40 len 32 */
    hi_char file_path[PATH_MAX + 1] = {0};

    /* ensure /dev/wifi exist */
    dir = opendir(g_dev_wifi_dir);
    if (!dir) {
        if (mkdir(g_dev_wifi_dir, 0666) < 0) {                  /* dev_wifi_dir mode 0666 */
            DBGPRINT(("WiFi: Create '%s' fail\n", g_dev_wifi_dir));
            return -1;
        }
    }
    closedir(dir);

    /* ensure hostapd configure file directory exist */
    dir = opendir(g_hostapd_config_dir);
    if (!dir) {
        if (mkdir(g_hostapd_config_dir, 0666) < 0) {            /* hostapd_config_dir mode 0666 */
            DBGPRINT(("WiFi: Create '%s' fail\n", g_hostapd_config_dir));
            return -1;
        }
    }
    closedir(dir);

    /* open configure file, if not exist, create it */
    if (realpath(config_file, file_path) == NULL) {
        DBGPRINT(("WiFi: file path '%s' no exist and create it [%s]!\n", file_path, __func__));
    }
    hi_s32 fd = open(file_path, O_CREAT | O_TRUNC | O_WRONLY, 0666);   /* file_path mode 0666 */
    if (fd < 0) {
        DBGPRINT(("WiFi: Cann't open configure file '%s'\n", file_path));
        return -1;
    }

    /* set broadcast ssid */
    if (ap_cfg->hidden_ssid == HI_TRUE) {
        DBGPRINT(("WiFi: Enable hidden SSID\n"));
        broadcast_ssid = 1;     /* send empty (length 0) SSID */
    }

    /* set HT40 capability */
    results = memset_s(ht40, sizeof(ht40), 0, sizeof(ht40));
    if (results < 0) {
        DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
    }
    if (ap_cfg->channel >= 36) {    /* channel bigger than 36 */
        hi_u32 i;
        hi_u32 ht40plus[] = {36, 44, 52, 60, 100, 108, 116, 124, 132, 149, 157};
        hi_u32 ht40minus[] = {40, 48, 56, 64, 104, 112, 120, 128, 136, 153, 161};

        hw_mode = 'a';

        for (i = 0; i < sizeof(ht40plus) / sizeof(ht40plus[0]); i++)
            if (ap_cfg->channel == (hi_s32)ht40plus[i]) {
                results = strcpy_s(ht40, sizeof(ht40), "[SHORT-GI-40][HT40+]");
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
                }
                break;
            }

        for (i = 0; i < sizeof(ht40minus) / sizeof(ht40minus[0]); i++)
            if (ap_cfg->channel == (hi_s32)ht40minus[i]) {
                results = strcpy_s(ht40, sizeof(ht40), "[SHORT-GI-40][HT40-]");
                if (results < 0) {
                    DBGPRINT(("WiFi: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__));
                }
                break;
            }
    } else {
        hw_mode = 'g';
        if (ap_cfg->channel > 7) {  /* channel bigger than 7 */
            results = strcpy_s(ht40, sizeof(ht40), "[SHORT-GI-40][HT40-]");
            if (results < EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
            }
        } else {
            results = strcpy_s(ht40, sizeof(ht40), "[SHORT-GI-40][HT40+]");
            if (results < EOK) {
                DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
            }
        }
    }
    /* set common paramters */
    if (ap_cfg->security == HI_WLAN_SECURITY_WEP) {
        /* WEP is not supported in 802.11n */
        if (ap_cfg->hw_mode == 'n') {
            DBGPRINT(("WiFi: n mode does not support WEP encryption\n"));
            close(fd);
            return -1;
        }
        if (asprintf(&wbuf, "interface=%s\n"
                     "driver=%s\n"
                     "ctrl_interface=/var/hostapd\n"
                     "ssid=%s\n"
                     "channel=%d\n"
                     "beacon_int=%d\n"
                     "ignore_broadcast_ssid=%d\n"
                     "hw_mode=%c\n",
                     ifname, "nl80211", ap_cfg->ssid, ap_cfg->channel, ap_cfg->beacon_int,
                     broadcast_ssid, (ap_cfg->hw_mode == 'b' ? 'b' : 'g')) < 0) {
            DBGPRINT(("WiFi: asprintf ap_cfg->security HI_WLAN_SECURITY_WEP failure\n"));
            close(fd);
            free(wbuf);
            return -1;
        }
    } else {
        if (asprintf(&wbuf, "interface=%s\n"
                     "driver=%s\n"
                     "ctrl_interface=/var/hostapd\n"
                     "ssid=%s\n"
                     "channel=%d\n"
                     "beacon_int=%d\n"
                     "ignore_broadcast_ssid=%d\n"
                     "hw_mode=%c\n"
                     "ieee80211n=%d\n"
                     "ht_capab=[SHORT-GI-20]\n",
                     ifname, "nl80211", ap_cfg->ssid, ap_cfg->channel, ap_cfg->beacon_int, broadcast_ssid,
                     (ap_cfg->hw_mode == 'b' ? 'b' : 'g'), ap_cfg->hw_mode == 'n' ? 1 : 0) < 0) {
            DBGPRINT(("WiFi: asprintf ap_cfg->security failure\n"));
            close(fd);
            free(wbuf);
            return -1;
        }
    }

    /* set auth mode */
    if (ap_cfg->security == HI_WLAN_SECURITY_WEP) {
        hi_s32 pwd_len = (hi_s32)strlen(ap_cfg->psswd);
        if (pwd_len == WEP_PSSWD_LEN_5 || pwd_len == WEP_PSSWD_LEN_13) {
            if (asprintf(&fbuf, "%swep_default_key=0\n"
                         "wep_key0=\"%s\"\n", wbuf, ap_cfg->psswd) < 0) {
                DBGPRINT(("WiFi: asprintf HI_WLAN_SECURITY_WEP pwd_len failure\n"));
                close(fd);
                free(wbuf);
                free(fbuf);
                return -1;
            }
        } else {
            if (asprintf(&fbuf, "%swep_default_key=0\n"
                         "wep_key0=%s\n", wbuf, ap_cfg->psswd) < 0) {
                DBGPRINT(("WiFi: asprintf HI_WLAN_SECURITY_WEP pwd failure\n"));
                close(fd);
                free(wbuf);
                free(fbuf);
                return -1;
            }
        }
    } else if (ap_cfg->security == HI_WLAN_SECURITY_WPA_WPA2_PSK) {
        if (asprintf(&fbuf, "%swpa=3\n"
                     "wpa_key_mgmt=WPA-PSK\n"
                     "wpa_pairwise=TKIP CCMP\n"
                     "wpa_passphrase=%s\n", wbuf, ap_cfg->psswd) < 0) {
            DBGPRINT(("WiFi: asprintf HI_WLAN_SECURITY_WPA_WPA2_PSK failure\n"));
            close(fd);
            free(wbuf);
            free(fbuf);
            return -1;
        }
    } else {
        if (asprintf(&fbuf, "%s", wbuf) < 0) {
            DBGPRINT(("WiFi: asprintf ap_cfg->security failure\n"));
            close(fd);
            free(wbuf);
            free(fbuf);
            return -1;
        }
    }

    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        DBGPRINT(("WiFi: Cann't write configuration to '%s'\n", file_path));
        ret = -1;
    }
    close(fd);
    free(wbuf);
    free(fbuf);

    if (chmod(file_path, 0666) < 0) {   /* file_path mode 0666 */
        DBGPRINT(("WiFi: Failed to change '%s' to 0666\n", file_path));
        unlink(file_path);
        ret = -1;
    }

    return ret;
}

int ensure_entropy_file_exists(const hi_char *entropy_file)
{
    hi_s32 ret = HI_SUCCESS;
    char *fbuf = NULL;
    char file[PATH_MAX + 1] = {0};
    static unsigned char dummy_key[21] = { 0x02, 0x11, 0xbe, 0x33, 0x43, 0x35,  /* dummy_key arry len 21 */
                                           0x68, 0x47, 0x84, 0x99, 0xa9, 0x2b,
                                           0x1c, 0xd3, 0xee, 0xff, 0xf1, 0xe2,
                                           0xf3, 0xf4, 0xf5};

    if (realpath(entropy_file, file) != NULL) {
        DBGPRINT(("WiFi: entropy file already exists\n"));
        return HI_SUCCESS;
    }

    DBGPRINT(("WiFi: errno=%d errmsg=%s\n", errno, strerror(errno)));
    hi_s32 fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, 0666);    /* file mode 0666 */
    if (fd < 0) {
        DBGPRINT(("WiFi: Cann't open entropy file '%s'\n", file));
        return HI_FAILURE;
    }
    if (asprintf(&fbuf, "%s", dummy_key) < 0) {
        DBGPRINT(("WiFi: asprintf dummy_key '%s' failure!\n", dummy_key));
        close(fd);
        free(fbuf);
        return HI_FAILURE;
    }

    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        DBGPRINT(("WiFi: Cann't write configuration to '%s'\n", file));
        ret = HI_FAILURE;
    }
    close(fd);
    free(fbuf);

    if (chmod(file, 0666) < 0) {    /* file mode 0666 */
        DBGPRINT(("WiFi: Failed to change '%s' to 0666\n", file));
        unlink(file);
        ret = HI_FAILURE;
    }

    return ret;
}

hi_s32 hi_wlan_ap_init(hi_void)
{
    return HI_SUCCESS;
}

hi_void hi_wlan_ap_deinit(hi_void)
{
}

hi_s32 hi_wlan_ap_open(hi_char *ifname, hi_u32 name_buf_size, hi_wlan_bandwith_e bw)
{
    hi_s32 ret;
    char iface[IFNAMSIZ + 1];
    hi_s32 count;

    if (ifname == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }
    ret = wlan_util_interface_exist(WIFI_MODE_STA);
    if (ret == HI_SUCCESS) {
        return HI_INVALID_HANDLE;
    }
    ret = wlan_util_interface_exist(WIFI_MODE_AP);
    if (ret == HI_SUCCESS) {
        return HI_INVALID_HANDLE;
    }
    ret = ap_load_driver(bw);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    DBGPRINT(("WiFi: Driver loaded successfully\n"));

    /* when driver startup, a new wireless network interface will be
     * created, wait 5s for the interface created successfully */
    for (count = 0; count < 50; count++) {  /* loop 50th */
        ret = wlan_util_get_interface(WIFI_MODE_AP, PROC_NET_DEV, iface, sizeof(iface));
        if (ret == HI_FAILURE) {
            ret = wlan_util_get_interface(WIFI_MODE_AP, PROC_NET_WIRELESS, iface, sizeof(iface));
        }
        if (ret == HI_SUCCESS) {
            DBGPRINT(("WiFi: Get interface '%s'\n", iface));
            ret = strncpy_s(ifname, name_buf_size, iface, strlen(iface) + 1);
            if (ret < 0) {
                DBGPRINT(("WiFi: ret=%d file=%s,line=%d,func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__));
            }

            return HI_SUCCESS;
        }
        usleep(100000); /* sleep 100000 */
    }
    DBGPRINT(("WiFi: Failed to get interface, driver initialized fail!\n"));

    ret = ap_unload_driver();
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: ap unload driver fail!\n"));
    }

    return HI_FAILURE;
}

hi_s32 hi_wlan_ap_close(const hi_char *ifname)
{
    hi_s32 ret;

    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* unload WiFi driver */
    ret = ap_unload_driver();

    return ret;
}

hi_s32 hi_wlan_ap_start(const hi_char *ifname, hi_wlan_ap_config_s *ap_cfg)
{
    hi_s32 ret;

    if (ifname == NULL || *ifname == '\0' || ap_cfg == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* check configures */
    if (strlen(ap_cfg->ssid) == 0) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* channel, 11bg: 1 - 14, 11a: 36 - 165 */
    if (ap_cfg->channel < 1 || ap_cfg->channel > 165) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if (ap_cfg->security >= HI_WLAN_SECURITY_BUTT) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* startup AP by hostapd. hostapd will configure WiFi to AP mode, then
     * start it */
    ret = ap_update_hostapd_config_file(ifname, ap_cfg, g_hostapd_config_file);
    if (-1 == ret) {
        DBGPRINT(("WiFi: update hostapd config file fail\n"));
        return ret;
    }

    ret = ensure_entropy_file_exists(g_entropy_file);
    if (-1 == ret) {
        DBGPRINT(("WiFi: creat entropy file fail\n"));
    }

    ret = ap_start_hostapd(g_hostapd_config_file, g_entropy_file);
    if (ret < 0) {
        DBGPRINT(("WiFi: start hostapd fail\n"));
        return HI_WLAN_START_HOSTAPD_FAIL;
    }

    DBGPRINT(("WiFi: SoftAP started\n"));

    return HI_SUCCESS;
}

hi_s32 hi_wlan_ap_stop(const hi_char *ifname)
{
    struct ifreq ifr;
    hi_s32 s = -1;
    hi_s32 ret;

    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    /* configure WiFi interface down */
    ret = memset_s(&ifr, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__));
    }
    ret = strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifname, strlen(ifname) + 1);
    if (ret < 0) {
        DBGPRINT(("WiFi: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__));
    }

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
        if (ioctl(s, SIOCGIFFLAGS, &ifr) >= 0) {
            ifr.ifr_flags = (ifr.ifr_flags & (~IFF_UP));
            ioctl(s, SIOCSIFFLAGS, &ifr);
        }
        close(s);
    }
    usleep(200000); /* sleep 200000 */

    if (ap_kill_hostapd() < 0) {
        DBGPRINT(("WiFi: Kill hostapd fail\n"));
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 hi_wlan_ap_setsoftap(const hi_char *ifname, hi_wlan_ap_config_s *ap_cfg)
{
    hi_s32 ret;
    hi_char iface[IFNAMSIZ + 1] = {0};

    if (ifname == NULL || *ifname == '\0' || ap_cfg == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    DBGPRINT(("WiFi: Must stop SoftAP and close WiFi before setting it\n"));
    /* to set AP, we must restart it */
    ret = hi_wlan_ap_stop(ifname);
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: Stop SoftAP fail\n"));
        return HI_FAILURE;
    }

    ret = hi_wlan_ap_close(ifname);
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: Close WiFi fail\n"));
        return HI_FAILURE;
    }

    /* wait for driver deinitialization */
    sleep(1);
    DBGPRINT(("WiFi: Closed, then restart it\n"));

    ret = memset_s(iface, sizeof(iface), 0, sizeof(iface));
    if (ret != 0) {
        DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
    }
    ret = hi_wlan_ap_open(iface, sizeof(iface), ap_cfg->bw_bandwidth);
    if (ret != HI_SUCCESS) {
        DBGPRINT(("WiFi: Open SoftAP fail\n"));
        return HI_FAILURE;
    }
    if (strcmp(iface, ifname) != 0) {
        DBGPRINT(("WiFi: Fail, new interface is '%s', expect for '%s'\n",
                  ifname, iface));
        return HI_FAILURE;
    }

    return hi_wlan_ap_start(ifname, ap_cfg);
}

hi_s32 hi_wlan_ap_getmacaddress(const hi_char *ifname, hi_char *mac, hi_u8 mac_buf_size)
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
