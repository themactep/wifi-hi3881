/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wlan util.
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

#include "wlan_util.h"
#include "securec.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
#define DRIVER_MODULE_LEN_MAX    256

static const hi_char g_sdio_dir[] = "/sys/bus/sdio/devices";
static const hi_char g_module_file[] = "/proc/modules";

static hi_wifi_device_info g_dev[] = {
    {WIFI_ID_HISILICON_HI3881, WIFI_HISILICON_HI3881}
};

/*****************************************************************************
  3 函数实现
*****************************************************************************/
hi_s32 wlan_util_get_sdio_wifi_device(hi_void)
{
    hi_s32 ret = -1;
    hi_s32 results = 0;
    DIR *dir = NULL;
    struct dirent *next = NULL;
    FILE *fp = NULL;
    char file_path[PATH_MAX + 1] = {0};

    dir = opendir(g_sdio_dir);
    if (!dir) {
        return -1;
    }

    while ((next = readdir(dir)) != NULL) {
        hi_char line[MAX_LEN_OF_LINE];
        hi_char uevent_file[256] = {0}; /* uevent_file max len 256 */

        /* read uevent file, uevent's data like below:
         * 1.g_driver=oal_sdio
         * 2.SDIO_CLASS=07
         * 3.SDIO_ID=0296:5347
         * 4.MODALIAS=sdio:c07v0296d5347
         */
        results = snprintf_s(uevent_file, sizeof(uevent_file), sizeof(uevent_file),
                             "%s/%s/uevent", g_sdio_dir, next->d_name);
        if (results < 0) {
            DBGPRINT(("WiFi: results=%d file=%s, func=%s, line=%d\n", results, __FILE__, __FUNCTION__, __LINE__));
        }

        if (realpath(uevent_file, file_path) == NULL) {
            continue;
        }

        fp = fopen(file_path, "r");
        if (fp == NULL) {
            continue;
        }

        while (fgets(line, sizeof(line), fp)) {
            hi_char *pos = NULL;
            hi_s32 product_vid;
            hi_s32 product_did;
            hi_char device_id[10] = {0};    /* device_id max len 10 */

            pos = strstr(line, "SDIO_ID=");
            if (pos != NULL) {
                hi_u32 i;
                results = sscanf_s(pos + 8, "%x:%x", &product_vid, &product_did);   /* pos offset 8 */
                if (results <= 0) {
                    DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
                    continue;
                }

                results = snprintf_s(device_id, sizeof(device_id), sizeof(device_id), "%04x:%04x",
                    product_vid, product_did);
                if (results == -1) {
                    DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
                }

                for (i = 0; i < sizeof(g_dev) / sizeof(hi_wifi_device_info); i++) {
                    if (strncmp(device_id, g_dev[i].usb_id, 9) == 0) {              /* compare first 9th */
                        ret = g_dev[i].id;
                        break;
                    }
                }
            }
            if (ret != -1) {
                break;
            }
        }
        fclose(fp);
        if (ret != -1) {
            break;
        }
    }

    closedir(dir);

    return ret;
}

hi_s32 wlan_util_get_wifi_device(hi_void)
{
    hi_s32 ret;

    ret = wlan_util_get_sdio_wifi_device();
    if (ret == -1) {
#ifdef WIFI_DEVICE_HI3881
    DBGPRINT(("No supported usb or pcie device found, set id to chosen HI3881\n"));
    ret = WIFI_HISILICON_HI3881;
#endif
    }
    return ret;
}

hi_s32 wlan_util_insmod_module(hi_char *module, const hi_char *module_tag,
                               hi_char *param, hi_char *bw_conf, hi_char *rate)
{
    hi_s32 ret;
    hi_char cmd[256] = {0}; /* cmd array len 256 */
    hi_char *spawn_args[] = {"insmod", module, NULL, NULL, NULL, NULL};
    FILE *proc = NULL;
    hi_char line[DRIVER_MODULE_LEN_MAX + 10] = {0}; /* add 10 */

    /* if module is loaded, return ok */
    if ((proc = fopen(g_module_file, "r")) == NULL) {
        DBGPRINT(("Could not open %s\n", g_module_file));
        return -1;
    }

    while ((fgets(line, sizeof(line), proc)) != NULL) {
        if (strncmp(line, module_tag, strlen(module_tag)) == 0) {
            fclose(proc);
            return 0;
        }
    }

    fclose(proc);

    /* insmod module */
    if (param != NULL) {
        spawn_args[2] = param;      /* 0:insmod 1:module 2:module 3:bw 4:rate */
    } else {
        spawn_args[2] = "\0";       /* 0:insmod 1:module 2:module 3:bw 4:rate */
    }
    /* insmod bw conf */
    if (bw_conf != NULL) {
        spawn_args[3] = bw_conf;    /* 0:insmod 1:module 2:module 3:bw 4:rate */
    } else {
        spawn_args[3] = "\0";       /* 0:insmod 1:module 2:module 3:bw 4:rate */
    }
    if (rate != NULL) {
        spawn_args[4] = rate;       /* 0:insmod 1:module 2:module 3:bw 4:rate */
    } else {
        spawn_args[4] = "\0";       /* 0:insmod 1:module 2:module 3:bw 4:rate */
    }
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "%s %s %s %s %s",
        spawn_args[0], spawn_args[1], spawn_args[2], spawn_args[3], spawn_args[4]); /* 2:module 3:bw 4:rate */
    if (ret == -1) {
        DBGPRINT(("WiFi: insmod cmd snprintf_s err!\n"));
    }
    DBGPRINT(("WiFi: system cmd = '%s'\n", cmd));
    ret = system(cmd);

    return ret;
}

hi_s32 wlan_util_rmmod_module(hi_char *module)
{
    hi_s32 ret;
    hi_char cmd[256] = {0}; /* cmd array len 256 */
    hi_char *spawn_args[] = {"rmmod", module, NULL, NULL};

    /* rmmod module */
    ret = snprintf_s(cmd, sizeof(cmd), sizeof(cmd), "%s %s", spawn_args[0], spawn_args[1]);
    if (ret == -1) {
        DBGPRINT(("WiFi: file=%s, func=%s, line=%d\n", __FILE__, __FUNCTION__, __LINE__));
    }
    DBGPRINT(("WiFi: system cmd = '%s'\n", cmd));
    ret = system(cmd);
    if (ret == -1) {
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

hi_s32 wlan_util_interface_exist(hi_wifi_mode_e mode)
{
    hi_char ifname[IFNAMSIZ + 1] = {0};
    hi_s32 ret;
    ret = wlan_util_get_interface(mode, PROC_NET_WIRELESS, ifname, sizeof(ifname));
    if (ret == HI_SUCCESS) {
        DBGPRINT(("WiFi: exist interface '%s'\n", ifname));
    }
    return ret;
}

hi_s32 wlan_util_get_interface(hi_wifi_mode_e mode, const hi_char *dev_file, hi_char *ifname, hi_u32 nameBufSize)
{
    hi_s32 ret = HI_FAILURE;
    hi_char buff[1024] = {0};       /* buff array len 1024 */
    FILE *fh = NULL;
    hi_char *begin = NULL;
    hi_char *end = NULL;
    hi_char if_prefix[10] = {0};    /* if_prefix array len 10 */
    hi_s32 len;
    char file[PATH_MAX] = {0};
    hi_s32 results = HI_FAILURE;

    if (ifname == NULL || dev_file == NULL) {
        return HI_FAILURE;
    }

    /* STA and AP mode - 'wlan0', P2P mode - 'p2p0' */
    if (mode == WIFI_MODE_P2P) {
        results = strncpy_s(if_prefix, sizeof(if_prefix), "p2p", 4);    /* p2p string len 4 */
        if (results != 0) {
            DBGPRINT(("WiFi: snprintf_s return %d\n", results));
        }
    } else if (mode == WIFI_MODE_AP) {
        results = strncpy_s(if_prefix, sizeof(if_prefix), "ap", 3);     /* ap string len 3 */
        if (results != 0) {
            DBGPRINT(("WiFi: snprintf_s return %d\n", results));
        }
    } else {
        results = strncpy_s(if_prefix, sizeof(if_prefix), "wlan", 5);   /* wlan string len 5 */
        if (results != 0) {
            DBGPRINT(("WiFi: snprintf_s return %d\n", results));
        }
    }
    len = (hi_s32)strlen(if_prefix);

    if (NULL == realpath(dev_file, file)) {
        DBGPRINT(("WiFi: file path '%s' not exist!\n", file));
        return HI_FAILURE;
    }

    fh = fopen(file, "r");
    if (fh != NULL) {
        /* Eat 2 lines of header */
        if (fgets(buff, sizeof(buff), fh) == NULL) {
            if (fclose(fh) != 0) {
                DBGPRINT(("WiFi: %s close fail in first fgets!\n", file));
            }
            fh = NULL;
            return ret;
        }
        if (fgets(buff, sizeof(buff), fh) == NULL) {
            if (fclose(fh) != 0) {
                DBGPRINT(("WiFi: %s close fail in second fgets!\n", file));
            }
            fh = NULL;
            return ret;
        }

        /* Read each device line */
        while (fgets(buff, sizeof(buff), fh)) {
            /* Skip empty or almost empty lines. It seems that in some
             * cases fgets return a line with only a newline. */
            if ((buff[0] == '\0') || (buff[1] == '\0')) {
                continue;
            }

            begin = buff;
            while (*begin == ' ' && (begin - buff) < (hi_s32)sizeof(buff)) {
                begin++;
            }

            end = strstr(begin, ": ");
            /* Not found ??? To big ??? */
            if ((end == NULL) || (((end - begin) + 1) > (IFNAMSIZ + 1))) {
                continue;
            }
            if (strncmp(begin, if_prefix, len) != 0) {
                continue;
            }

            /* Copy */
            ret = memcpy_s(ifname, nameBufSize, begin, (end - begin));
            if (ret != 0) {
                DBGPRINT(("WiFi: memcpy_s return %d in '%s'\n", ret, __func__));
            }
            ifname[end - begin] = '\0';
            ret = HI_SUCCESS;
            break;
        }
        if (fclose(fh) != 0) {
            DBGPRINT(("WiFi: %s close fail!\n", file));
        }
        fh = NULL;
    }

    return ret;
}

hi_s32 wlan_util_frequency_to_channel(hi_s32 freq)
{
    hi_s32 chn;

    if (freq == 2484) {                         /* freq is 2484 */
        chn = 14;                               /* chanel 14 */
    } else if (freq < 2484) {                   /* freq range (2484 4910) */
        chn = (freq - 2407) / 5;                /* freq equal (freq - 2407) / 5 */
    } else if (freq >= 4910 && freq <= 4980) {  /* freq range [4910 4980] */
        chn = (freq - 4000) / 5;                /* freq equal (freq - 4000) / 5 */
    } else {                                    /* freq range (4980 +) */
        chn = (freq - 5000) / 5;                /* freq equal (freq - 5000) / 5 */
    }

    return chn;
}

hi_s32 wlan_util_read_line(const hi_char *buf, hi_char *line, hi_u32 lineSize)
{
    hi_s32 i = 0;
    hi_char *pos = line;

    if (line == NULL || buf == NULL) {
        return 0;
    }

    while (*buf != '\0') {
        i++;
        if (*buf == '\n') {
            break;
        }

        if ((hi_u32)(line - pos) < (lineSize - 1)) {
            *line++ = *buf++;
        } else {
            break;
        }
    }
    *line = '\0';

    return i;
}

hi_void wlan_util_string_split(hi_char *src, hi_char sym, hi_char *ss[])
{
    if (src == NULL || ss == NULL) {
        return;
    }

    *ss++ = src;
    while (*src) {
        if (*src == sym) {
            *src++ = '\0';
            *ss++ = src;
        } else {
            src++;
        }
    }
}

