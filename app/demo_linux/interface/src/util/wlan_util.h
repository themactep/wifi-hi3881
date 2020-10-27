/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wlan_util.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WLAN_UTIL_H__
#define __WLAN_UTIL_H__

#include "hi_type.h"

#define MAX_LEN_OF_LINE 256
#define IFNAMSIZ        16

#define PROC_NET_WIRELESS "/proc/net/wireless"
#define PROC_NET_DEV "/proc/net/dev"

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifdef DEBUG
#define DBGPRINT(Fmt)   printf Fmt
#else
#define DBGPRINT(Fmt)
#endif

/* USB ID information */
typedef struct {
    hi_char usb_id[9];  /* usb id max len 9 */
    hi_s32 id;
} hi_wifi_device_info;

/* USB ID of WiFi device */
#define WIFI_ID_HISILICON_HI3881   "0296:5347"

/* ID of WiFi device */
enum wifi_id {
    WIFI_HISILICON_HI3881 = 0,
    INVALID_DEVICE,
};

/* WiFi mode */
typedef enum hi_wifi_mode_e {
    WIFI_MODE_STA = 0,
    WIFI_MODE_AP = 1,
    WIFI_MODE_P2P = 2,
    WIFI_MODE_STA_P2P = 3,
    WIFI_MODE_INVALID,
} hi_wifi_mode_e;

/* wlan_util_get_wifi_device
 * brief: get the ID of WiFi device
 * return  id   ID of WiFi device
 *         -1   cann't find supported device
 */
hi_s32 wlan_util_get_wifi_device(hi_void);

/* wlan_util_insmod_module
 * brief: insmod kernel module
 * param   module   module file
 * param   module_tag   module tag
 * param   param    paramters with module
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_util_insmod_module(hi_char *module, const hi_char *module_tag,
                               hi_char *param, hi_char *bw_conf, hi_char *rate);

/* wlan_util_rmmod_module
 * brief: rmmod kernel module
 * param   module   module name
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_util_rmmod_module(hi_char *module);

/* wlan_util_get_interface
 * brief: get wlan interface name
 * param[out]   ifname   wlan interface name
 * param[in]   nameBufSize   ifname buffer size
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_util_get_interface(hi_wifi_mode_e mode, const hi_char *dev_file,
                               hi_char *ifname, hi_u32 nameBufSize);

/* wlan_util_frequency_to_channel
 * brief: change 80211 frequency to channel number
 * param   80211 frequency (MHz)
 * return  channel number
 */
hi_s32 wlan_util_interface_exist(hi_wifi_mode_e mode);

hi_s32 wlan_util_frequency_to_channel(hi_s32 freq);

/* wlan_util_read_line
 * brief: read the first line from the buf
 * param     buf    buffer
 * param[out]   line   the first line
 * param[in]    lineSize   the line buffer size
 * return  size  size of the line
 */
hi_s32 wlan_util_read_line(const hi_char *buf, hi_char *line, hi_u32 lineSize);

/* wlan_util_string_split
 * brief: split string
 * param[in]    src    buffer
 * param[in]    sym    symbol to split
 * param[out]   ss  splited strings
 * return
 */
hi_void wlan_util_string_split(hi_char *src, hi_char sym, hi_char *ss[]);
#endif /* __WLAN_UTIL_H__ */
