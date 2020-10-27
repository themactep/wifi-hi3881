/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wlan p2p.
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "wlan_sm.h"
#include "wlan_util.h"
#include "hi_wlan_p2p.h"
#include "securec.h"

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define CMD_REPLY_SIZE  256

/*****************************************************************************
  3 函数实现
*****************************************************************************/
hi_s32 hi_wlan_p2p_init(hi_void)
{
    return wlan_sm_init();
}

hi_void hi_wlan_p2p_deinit(hi_void)
{
    wlan_sm_deinit();
}

hi_s32 hi_wlan_p2p_open(hi_char *ifname, hi_u32 name_buf_size)
{
    hi_s32 ret;
    hi_char reply[CMD_REPLY_SIZE];
    hi_s32 len = sizeof(reply);

    if (ifname == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    ret = wlan_sm_send_message(CMD_P2P_OPEN, NULL, reply, &len);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = strncpy_s(ifname, name_buf_size, reply, len);
    if (ret < 0) {
        printf("SAMPLE_P2P: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__);
    }

    return HI_SUCCESS;
}

hi_s32 hi_wlan_p2p_close(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_CLOSE, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_p2p_start(const hi_char *ifname, hi_wlan_sta_event_callback event_cb)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    wlan_sm_register_callback(event_cb);

    return wlan_sm_send_message(CMD_P2P_START, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_p2p_stop(const hi_char *ifname)
{
    hi_s32 ret;

    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    ret = wlan_sm_send_message(CMD_P2P_STOP, (hi_void *)ifname, NULL, NULL);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    wlan_sm_unregister_callback();

    return HI_SUCCESS;
}

hi_s32 hi_wlan_p2p_find(const hi_char *ifname, hi_s32 timeout)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_FIND, &timeout, NULL, NULL);
}

hi_s32 hi_wlan_p2p_get_peers(const hi_char *ifname, hi_wlan_p2p_device_s *devlist, hi_u32 *devnum)
{
    if (ifname == NULL || *ifname == '\0' || devlist == NULL || devnum == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_p2p_get_peers(devlist, devnum);
}

hi_s32 hi_wlan_p2p_connect(const hi_char *ifname, hi_wlan_p2p_config_s *p2p_cfg)
{
    if (ifname == NULL || *ifname == '\0' || p2p_cfg == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_CONNECT, p2p_cfg, NULL, NULL);
}

hi_s32 hi_wlan_p2p_disconnect(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_DISCONNECT, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_p2p_set_device_info(const hi_char *ifname, hi_wlan_p2p_device_s *p2p_dev)
{
    if (ifname == NULL || *ifname == '\0' || p2p_dev == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_SET_DEVICE_INFO, p2p_dev, NULL, NULL);
}

hi_s32 hi_wlan_p2p_set_device_name(const hi_char *ifname, hi_char *name)
{
    if (ifname == NULL || *ifname == '\0' || name == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_SET_DEVICE_NAME, name, NULL, NULL);
}

hi_s32 hi_wlan_p2p_get_persistent_groups(const hi_char *ifname, hi_wlan_p2p_group_s *group_list, hi_s32 *group_num)
{
    if (ifname == NULL || *ifname == '\0' || group_list == NULL || group_num == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_p2p_get_persistent_groups(group_list, (unsigned int *)group_num);
}

hi_s32 hi_wlan_p2p_delete_persistent_group(const hi_char *ifname, hi_wlan_p2p_group_s *group)
{
    if (ifname == NULL || *ifname == '\0' || group == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_p2p_delete_persistent_group(group);
}

hi_s32 hi_wlan_p2p_get_mac_address(const hi_char *ifname, hi_char *mac, hi_u8 mac_buf_size)
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

hi_s32 hi_wlan_sta_p2p_open(hi_char *sta_ifname, hi_u8 sta_ifname_size, hi_char *p2p_ifname, hi_u8 p2p_ifname_size)
{
    hi_s32 ret;
    hi_char reply[CMD_REPLY_SIZE];
    hi_s32 len = sizeof(reply);

    if (sta_ifname == NULL || p2p_ifname == NULL) {
        return HI_WLAN_INVALID_PARAMETER;
    }

    ret = wlan_sm_send_message(CMD_STA_OPEN, NULL, reply, &len);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = strncpy_s(sta_ifname, sta_ifname_size, reply, len);
    if (ret < 0) {
        printf("SAMPLE_P2P: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__);
    }

    ret = wlan_sm_send_message(CMD_P2P_OPEN, NULL, reply, &len);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    ret = strncpy_s(p2p_ifname, p2p_ifname_size, reply, len);
    if (ret < 0) {
        printf("SAMPLE_P2P: ret=%d file=%s, func=%s, line=%d\n", ret, __FILE__, __FUNCTION__, __LINE__);
    }

    return HI_SUCCESS;
}

hi_s32 hi_wlan_sta_p2p_start(const hi_char *sta_ifname, const hi_char *p2p_ifname,
                             hi_wlan_sta_event_callback event_cb)
{
    if (sta_ifname == NULL || *sta_ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if (p2p_ifname == NULL || *p2p_ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    wlan_sm_register_callback(event_cb);

    return wlan_sm_send_message(CMD_STA_P2P_START, (hi_void *)sta_ifname, NULL, NULL);
}

hi_s32 hi_wlan_sta_p2p_close(const hi_char *sta_ifname, const hi_char *p2p_ifname)
{
    if (sta_ifname == NULL || *sta_ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    if (p2p_ifname == NULL || *p2p_ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_STA_P2P_CLOSE, (hi_void *)sta_ifname, NULL, NULL);
}

hi_s32 hi_wlan_p2p_listen(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_LISTEN, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_p2p_flush(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_FLUSH, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_p2p_group_add(const hi_char *ifname)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_send_message(CMD_P2P_GROUP_ADD, (hi_void *)ifname, NULL, NULL);
}

hi_s32 hi_wlan_event_register(const hi_char *ifname, hi_wlan_sta_event_callback event_cb)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_register_callback(event_cb);
}

hi_s32 hi_wlan_event_unregister(const hi_char *ifname, hi_wlan_sta_event_callback event_cb)
{
    if (ifname == NULL || *ifname == '\0') {
        return HI_WLAN_INVALID_PARAMETER;
    }

    return wlan_sm_unregister_callback_given(event_cb);
}

