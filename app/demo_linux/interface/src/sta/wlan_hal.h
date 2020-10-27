/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wlan sm.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WLAN_STA_H__
#define __WLAN_STA_H__

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <sys/socket.h>
#include <sys/un.h>

#include "hi_wlan.h"
#include "wlan_util.h"

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define REPLY_SIZE          256   /** the max size of wpa_supplicant event */
#define STRING_REPLY_SIZE   4096  /** the max size of command reply */

/*****************************************************************************
  3 枚举定义、结构体定义
*****************************************************************************/
/** struct of socket information */
typedef struct hi_wpa_socket_s {
    hi_s32 s;
    struct sockaddr_un local;
    struct sockaddr_un remote;
} hi_wpa_socket_s;

typedef struct hi_wpa_message_s {
    hi_char ifname[IFNAMSIZ + 1];
    hi_wpa_socket_s *mon_conn;
} hi_wpa_message_s;


/* wlan_hal_init
 * brief: Init hal layer
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_hal_init(hi_void);

/* wlan_hal_deinit
 * brief: Deinit hal layer
 */
hi_void wlan_hal_deinit(hi_void);

/* wlan_load_driver
 * brief: Find WiFi device then load it's driver
 * return  0    successfull
 *         -1   cann't find supported device
 *         -2   failed to load driver
 */
hi_s32 wlan_load_driver(const hi_wlan_sta_config_s *pstStaCfg);

/* wlan_unload_driver
 * brief: Unload WiFi driver
 * param   VOID
 * return  HI_SUCCESS    successfull
 *         HI_FAILURE    failed to unload driver
 */
hi_s32 wlan_unload_driver(hi_void);

/* wlan_start_supplicant
 * brief: start wpa_supplicant process
 * param   mode    sta ro p2p or sta&p2p
 * param   sta_ifname    wlan interface name
 * param   p2p_ifname    p2p interface name
 * param   driver    interface of wpa_supplicant and driver, wext, nl80211 etc.
 * param   sta_config_file    directory of wpa_supplicant.conf
 * param   p2p_config_file    directory of p2p_supplicant.conf
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_start_supplicant(hi_wifi_mode_e mode, const hi_char *sta_ifname, const hi_char *p2p_ifname,
    const hi_char *driver, const hi_char *sta_config_file, const hi_char *p2p_config_file);

/* wlan_stop_supplicant
 * brief: stop wpa_supplicant process
 * param   VOID
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_stop_supplicant(hi_void);

/* wlan_wpa_open_connection
 * brief: connect to wpa_supplicant
 * param   ifname    wlan interface name
 * param   ctrl_iface_dir    directory of control interface
 * return  monitor channel
 *         NULL   fail
 */
hi_wpa_socket_s *wlan_wpa_open_connection(const hi_char *ifname, const hi_char *ctrl_iface_dir);

/* wlan_wpa_close_connection
 * brief: close connection to wpa_supplicant
 * param   control   1 - close control channel
 * param   wpa_s     monitor channel
 * return  VOID
 */
hi_void wlan_wpa_close_connection(hi_s32 control, hi_wpa_socket_s *wpa_s);

/* wlan_wpa_request
 * brief: send command to wpa_supplicant
 * param   cmd     command string that send to wpa_supplicant
 * param   cbuf    buffer wpa_supplicant returned
 * param   size    size of buffer returned
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_wpa_request(const hi_char *cmd, hi_char *cbuf, hi_s32 *size);

/* wlan_wpa_read
 * brief: read event from wpa_supplicant
 * param   wpa_s   monitor channel
 * param   event   buffer wpa_supplicant returned
 * param   size    size of buffer returned
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_wpa_read(const hi_wpa_socket_s *wpa_s, hi_char *event, hi_s32 *size);

/* wlan_wpa_open_p2p_connection
 * brief: connect to wpa_supplicant
 * param   ifname    wlan interface name
 * param   ctrl_iface_dir    directory of control interface
 * return  monitor channel
 *         NULL   fail
 */
hi_wpa_socket_s *wlan_wpa_open_p2p_connection(const hi_char *ifname, const hi_char *ctrl_iface_dir);

/* wlan_wpa_close_p2p_connection
 * brief: close connection to wpa_supplicant
 * param   control   1 - close control channel
 * param   wpa_s     monitor channel
 * return  VOID
 */
hi_void wlan_wpa_close_p2p_connection(hi_s32 control, hi_wpa_socket_s *wpa_s);

/* wlan_wpa_request_p2p
 * brief: send command to wpa_supplicant
 * param   cmd     command string that send to wpa_supplicant
 * param   cbuf    buffer wpa_supplicant returned
 * param   size    size of buffer returned
 * return  0    successfull
 *         -1   fail
 */
hi_s32 wlan_wpa_request_p2p(const hi_char *cmd, hi_char *cbuf, hi_s32 *size);

#endif /* __WLAN_STA_H__ */
