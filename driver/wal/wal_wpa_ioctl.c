/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wal wpa ioctl file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "wal_wpa_ioctl.h"
#include "wal_net.h"
#include "wal_cfg80211.h"
#include "wal_ioctl.h"
#include "wal_event_msg.h"
#include "hmac_ext_if.h"
#include "wal_cfg80211.h"
#include "wal_cfg80211_apt.h"
#include "lwip/netifapi.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 全局变量定义
*****************************************************************************/
const hwal_ioctl_handler g_ast_hwal_ioctl_handlers[] = {
    (hwal_ioctl_handler) hwal_ioctl_set_ap,             /* HISI_IOCTL_SET_AP     */
    (hwal_ioctl_handler) hwal_ioctl_new_key,            /* HISI_IOCTL_NEW_KEY    */
    (hwal_ioctl_handler) hwal_ioctl_del_key,            /* HISI_IOCTL_DEL_KEY    */
    (hwal_ioctl_handler) hwal_ioctl_set_key,            /* HISI_IOCTL_SET_KEY    */
    (hwal_ioctl_handler) hwal_ioctl_send_mlme,          /* HISI_IOCTL_SEND_MLME  */
    (hwal_ioctl_handler) hwal_ioctl_send_eapol,         /* HISI_IOCTL_SEND_EAPOL */
    (hwal_ioctl_handler) hwal_ioctl_receive_eapol,      /* HISI_IOCTL_RECEIVE_EAPOL */
    (hwal_ioctl_handler) hwal_ioctl_enable_eapol,       /* HISI_IOCTL_ENALBE_EAPOL */
    (hwal_ioctl_handler) hwal_ioctl_disable_eapol,      /* HISI_IOCTL_DISABLE_EAPOL */
    (hwal_ioctl_handler) hwal_ioctl_get_addr,           /* HIIS_IOCTL_GET_ADDR */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    (hwal_ioctl_handler) hwal_ioctl_set_power,          /* HISI_IOCTL_SET_POWER */
#endif
    (hwal_ioctl_handler) hwal_ioctl_set_mode,           /* HISI_IOCTL_SET_MODE */
    (hwal_ioctl_handler) hwal_ioctl_get_hw_feature,     /* HIIS_IOCTL_GET_HW_FEATURE */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    (hwal_ioctl_handler) hwal_ioctl_stop_ap,            /* HIIS_IOCTL_STOP_AP */
    (hwal_ioctl_handler) hwal_ioctl_del_virtual_intf,   /* HISI_IOCTL_DEL_VIRTUAL_INTF */
#endif
    (hwal_ioctl_handler) hwal_ioctl_scan,               /* HISI_IOCTL_SCAN */
    (hwal_ioctl_handler) hwal_ioctl_disconnect,         /* HISI_IOCTL_DISCONNET */
    (hwal_ioctl_handler) hwal_ioctl_assoc,              /* HISI_IOCTL_ASSOC */
    (hwal_ioctl_handler) hwal_ioctl_set_netdev,         /* HISI_IOCTL_SET_NETDEV */
    (hwal_ioctl_handler) hwal_ioctl_change_beacon,      /* HISI_IOCTL_CHANGE_BEACON */
#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
    (hwal_ioctl_handler) hwal_ioctl_set_rekey_info,     /* HISI_IOCTL_SET_REKEY_INFO */
#else
    HI_NULL,
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    (hwal_ioctl_handler) hwal_ioctl_set_pm_switch,      /* HISI_IOCTL_SET_PM_ON */
    (hwal_ioctl_handler) hwal_ioctl_ip_notify,          /* HISI_IOCTL_IP_NOTIFY_DRIVER */
    (hwal_ioctl_handler) hwal_ioctl_set_max_sta,        /* HISI_IOCTL_SET_MAX_STA */
#endif
    (hwal_ioctl_handler) hwal_ioctl_sta_remove,         /* HISI_IOCTL_STA_REMOVE */
    (hwal_ioctl_handler) hwal_ioctl_send_action,        /* HISI_IOCTL_SEND_ACTION */
#ifdef _PRE_WLAN_FEATURE_MESH
    (hwal_ioctl_handler) hwal_ioctl_set_mesh_user,      /* HISI_IOCTL_SET_MESH_USER */
    (hwal_ioctl_handler) hwal_ioctl_set_mesh_gtk,       /* HISI_IOCTL_SET_MESH_GTK */
    (hwal_ioctl_handler) hwal_ioctl_set_accept_peer,    /* HISI_IOCTL_EN_ACCEPT_PEER */
    (hwal_ioctl_handler) hwal_ioctl_set_accept_sta,     /* HISI_IOCTL_EN_ACCEPT_STA */
#else
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    (hwal_ioctl_handler) hwal_ioctl_add_if,             /* HISI_IOCTL_ADD_IF */
    (hwal_ioctl_handler) hwal_ioctl_probe_req_report,   /* HISI_IOCTL_PROBE_REQUEST_REPORT */
    (hwal_ioctl_handler) hwal_ioctl_remain_on_channel,  /* HISI_IOCTL_REMAIN_ON_CHANNEL */
    (hwal_ioctl_handler) hwal_ioctl_cancel_remain_on_channel,    /* HISI_IOCTL_CANCEL_REMAIN_ON_CHANNEL */
    (hwal_ioctl_handler) hwal_ioctl_set_p2p_noa,        /* HISI_IOCTL_SET_P2P_NOA */
    (hwal_ioctl_handler) hwal_ioctl_set_p2p_powersave,  /* HISI_IOCTL_SET_P2P_POWERSAVE */
    (hwal_ioctl_handler) hwal_ioctl_set_ap_wps_p2p_ie,  /* HISI_IOCTL_SET_AP_WPS_P2P_IE */
    (hwal_ioctl_handler) hwal_ioctl_remove_if,          /* HISI_IOCTL_REMOVE_IF */
    (hwal_ioctl_handler) hwal_ioctl_get_p2p_addr,       /* HISI_IOCTL_GET_P2P_MAC_ADDR */
#else
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
    HI_NULL,
#endif
    (hwal_ioctl_handler) hwal_ioctl_get_drv_flags,      /* HISI_IOCTL_GET_DRIVER_FLAGS */
    HI_NULL,                                            /* HISI_IOCTL_SET_USR_APP_IE */
    (hwal_ioctl_handler) hwal_ioctl_set_delay_report    /* HISI_IOCTL_DELAY_REPORT */
};

/*****************************************************************************
  3 函数实现
*****************************************************************************/
/*****************************************************************************
 函 数 名  : hwal_ioctl_set_key
 功能描述  : set key数据传递至WAL层
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月20日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_key(const hi_char *puc_ifname, hi_void *buf)
{
    hi_u8                    key_index;
    hi_bool                  unicast = HI_TRUE;
    hi_bool                  multicast = HI_FALSE;
    hisi_key_ext_stru       *key_ext = HI_NULL;
    oal_net_device_stru     *netdev = HI_NULL;

    netdev   = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_set_key:input param is NULL.");
        return -HISI_EFAIL;
    }

    key_ext      = (hisi_key_ext_stru *)buf;
    key_index     = (hi_u8)key_ext->key_idx;

    if (key_ext->def == HISI_TRUE) {
        unicast = HI_TRUE;
        multicast = HI_TRUE;
    }

    if (key_ext->defmgmt == HISI_TRUE) {
        multicast = HI_TRUE;
    }

    if (key_ext->default_types == HISI_KEY_DEFAULT_TYPE_UNICAST) {
        unicast = HI_TRUE;
    } else if (key_ext->default_types == HISI_KEY_DEFAULT_TYPE_MULTICAST) {
        multicast = HI_TRUE;
    }

    return (hi_s32)wal_cfg80211_set_default_key(HI_NULL, netdev, key_index, unicast, multicast);
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_new_key
 功能描述  : set key数据传递至WAL层
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年3月21日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_new_key(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru     *netdev = HI_NULL;
    hisi_key_ext_stru       *key_ext = HI_NULL;
    oal_key_params_stru      params = {0};
    cfg80211_add_key_info_stru cfg80211_add_key_info;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_new_key:param is NULL.");
        return -HISI_EFAIL;
    }

    key_ext  = (hisi_key_ext_stru *)buf;

    cfg80211_add_key_info.key_index = (hi_u8)key_ext->key_idx;
    cfg80211_add_key_info.pairwise  = (HISI_KEYTYPE_PAIRWISE == key_ext->type);

    params.key       = (hi_u8 *)(key_ext->key);
    params.key_len   = (hi_s32)key_ext->key_len;
    params.seq_len   = (hi_s32)key_ext->seq_len;
    params.seq       = key_ext->seq;
    params.cipher    = key_ext->cipher;

    return (hi_s32)wal_cfg80211_add_key(HI_NULL, netdev, &cfg80211_add_key_info, key_ext->addr, &params);
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_del_key
 功能描述  : del key数据传递至WAL层
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年3月21日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_del_key(const hi_char *puc_ifname, hi_void *buf)
{
    hi_bool                  pairwise;
    oal_net_device_stru     *netdev = HI_NULL;
    hisi_key_ext_stru       *key_ext = HI_NULL;

    netdev   = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_del_key:param is NULL.");
        return -HISI_EFAIL;
    }

    key_ext  = (hisi_key_ext_stru *)buf;
    pairwise  = (HISI_KEYTYPE_PAIRWISE == key_ext->type);

    return (hi_s32)wal_cfg80211_remove_key(HI_NULL, netdev, (hi_u8)key_ext->key_idx, pairwise, key_ext->addr);
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_setap
 功能描述  : set ap数据传递至WAL层
 输入参数  : struct wt_param *iwtp
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年3月21日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_ap(const hi_char *puc_ifname, hi_void *buf)
{
    oal_ap_settings_stru oal_apsettings = {0};

    oal_net_device_stru *netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_ap :pst_netdev is NULL.");
        return -HISI_EFAIL;
    }

    hisi_ap_settings_stru *apsettings = (hisi_ap_settings_stru *)buf;

    oal_apsettings.ssid_len        = apsettings->ssid_len;
    oal_apsettings.beacon_interval = apsettings->l_beacon_interval;
    oal_apsettings.dtim_period     = apsettings->l_dtim_period;
    oal_apsettings.hidden_ssid     = (enum nl80211_hidden_ssid)(apsettings->hidden_ssid);
    oal_apsettings.beacon.head_len = apsettings->beacon_data.head_len;
    oal_apsettings.beacon.tail_len = apsettings->beacon_data.tail_len;

    oal_apsettings.ssid          = apsettings->puc_ssid;
    oal_apsettings.beacon.head   = apsettings->beacon_data.head;
    oal_apsettings.beacon.tail   = apsettings->beacon_data.tail;
    oal_apsettings.auth_type     = (enum nl80211_auth_type)(apsettings->auth_type);

    if (netdev->ieee80211_ptr == HI_NULL) {
        netdev->ieee80211_ptr = (oal_wireless_dev*)malloc(sizeof(struct wireless_dev));
        if (netdev->ieee80211_ptr == HI_NULL) {
            oam_error_log0(0, 0, "ieee80211_ptr parameter NULL.");
            return -HISI_EFAIL;
        }
        /* 安全编程规则6.6例外(3)从堆中分配内存后，赋予初值 */
        memset_s(netdev->ieee80211_ptr, sizeof(struct wireless_dev), 0, sizeof(struct wireless_dev));
    }

    if (netdev->ieee80211_ptr->preset_chandef.chan == HI_NULL) {
        netdev->ieee80211_ptr->preset_chandef.chan = (oal_ieee80211_channel*)malloc(sizeof(oal_ieee80211_channel));
        if (netdev->ieee80211_ptr->preset_chandef.chan == HI_NULL) {
            free(netdev->ieee80211_ptr);
            netdev->ieee80211_ptr = HI_NULL;

            oam_error_log0(0, 0, "chan parameter NULL.");
            return -HISI_EFAIL;
        }
        /* 安全编程规则6.6例外(3)从堆中分配内存后，赋予初值 */
        memset_s(netdev->ieee80211_ptr->preset_chandef.chan, sizeof(oal_ieee80211_channel), 0,
            sizeof(oal_ieee80211_channel));
    }

    netdev->ieee80211_ptr->preset_chandef.width = (enum nl80211_channel_type)apsettings->freq_params.l_bandwidth;
    netdev->ieee80211_ptr->preset_chandef.center_freq1   = apsettings->freq_params.l_center_freq1;
    netdev->ieee80211_ptr->preset_chandef.chan->hw_value = (hi_u16)apsettings->freq_params.l_channel;
    netdev->ieee80211_ptr->preset_chandef.chan->band     = IEEE80211_BAND_2GHZ;

    hi_s32 ret = (hi_s32)wal_cfg80211_start_ap(HI_NULL, netdev, &oal_apsettings);
    (hi_void)netifapi_netif_set_link_up(netdev->lwip_netif);

    return ret;
}

/*****************************************************************************
 功能描述  : 修改beacon帧参数
 修改历史      :
  1.日    期   : 2016年7月6日
    作    者   : Hisilicon
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_change_beacon(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru     *netdev = HI_NULL;
    oal_beacon_data_stru     beacon = {0};
    hisi_ap_settings_stru   *apsettings = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_change_beacon: param is NULL.");
        return -HISI_EFAIL;
    }
    apsettings       = (hisi_ap_settings_stru *)buf;

    /* 获取修改beacon帧参数的结构体 */
    beacon.head       = apsettings->beacon_data.head;
    beacon.tail       = apsettings->beacon_data.tail;
    beacon.head_len   = apsettings->beacon_data.head_len;
    beacon.tail_len   = apsettings->beacon_data.tail_len;

    return (hi_s32)wal_cfg80211_change_beacon(HI_NULL, netdev, &beacon);
}
/*****************************************************************************
 函 数 名  : hwal_ioctl_sendmlme
 功能描述  : send mlme数据传递至WAL层
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月20日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_send_mlme(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru         *netdev = HI_NULL;
    hisi_mlme_data_stru         *mlme_data = HI_NULL;
    oal_ieee80211_channel        chan = {0};
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    struct cfg80211_mgmt_tx_params params;
#endif

    netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_send_mlme:param is NULL.");
        return -HISI_EFAIL;
    }

    mlme_data = (hisi_mlme_data_stru *)buf;
    chan.center_freq = (hi_u16)mlme_data->freq;

    return (hi_s32)wal_cfg80211_mgmt_tx(HI_NULL, netdev->ieee80211_ptr,
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        &params,
#else
        &chan, mlme_data->data, mlme_data->data_len,
#endif
        mlme_data->send_action_cookie);
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_send_eapol
 功能描述  : 发送EAPOL报文
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月17日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_send_eapol(const hi_char *puc_ifname, hi_void *buf)
{
    hisi_tx_eapol_stru     *tx_eapol = HI_NULL;
    oal_net_device_stru    *netdev = HI_NULL;
    oal_netbuf_stru        *netbuf = HI_NULL;

    netdev      = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL))  {
        oam_error_log0(0, 0, "hwal_ioctl_send_eapol:param is NULL.");
        return -HISI_EFAIL;
    }
    tx_eapol    = (hisi_tx_eapol_stru *)buf;
    /* 增加EAPOL帧长度判断 */
    if ((tx_eapol->len > WLAN_LARGE_PAYLOAD_SIZE) || (tx_eapol->len < ETHER_HDR_LEN)) {
        oam_error_log1(0, 0, "hwal_ioctl_send_eapol length invalid: %d.", tx_eapol->len);
        return HI_FAIL;
    }
    /* 申请SKB内存内存发送 */
    netbuf      = hwal_lwip_skb_alloc(netdev, (hi_u16)tx_eapol->len);
    if (netbuf == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_send_eapol skb_alloc NULL.");
        return HI_FAIL;
    }

    oal_netbuf_put(netbuf, tx_eapol->len);
    if (tx_eapol->buf != HI_NULL) {
        if (memcpy_s(oal_netbuf_data(netbuf), tx_eapol->len,
            tx_eapol->buf, tx_eapol->len) != EOK) {
            oal_netbuf_free(netbuf);
            oam_error_log0(0, 0, "{hwal_ioctl_send_eapol::mem safe function err!}");
            return HI_FAIL;
        }
    }

    if ((netdev->netdev_ops == HI_NULL) || (netdev->netdev_ops->ndo_start_xmit == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_send_eapol netdev_ops NULL.");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    return netdev->netdev_ops->ndo_start_xmit(netbuf, netdev);
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_receive_eapol
 功能描述  : 处理接收EAPOL报文
 输入参数  :
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月17日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_receive_eapol(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru    *netdev = HI_NULL;
    oal_netbuf_stru        *skb_buf = HI_NULL;
    hisi_rx_eapol_stru     *rx_eapol = HI_NULL;

    rx_eapol    = (hisi_rx_eapol_stru *)buf;
    netdev      = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_receive_eapol:param is NULL.");
        return HI_FAIL;
    }

    if (HI_TRUE == oal_netbuf_list_empty(&netdev->hisi_eapol.eapol_skb_head)) {
        /* 此处hostapd在取链表数据时，会一直取到链表为空，所以每次都会打印，此时为正常打印 */
        /* 所以设置为info */
        oam_info_log0(0, 0, "hwal_ioctl_receive_eapol eapol pkt Q empty.");
        return HI_FAIL;
    }

    skb_buf     = oal_netbuf_delist(&netdev->hisi_eapol.eapol_skb_head);
    if (skb_buf == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_receive_eapol:: oal_netbuf_delist is NULL.");
        return HI_FAIL;
    }

    if (skb_buf->len > rx_eapol->len) {
        /* 如果收到EAPOL报文大小超过接收报文内存，返回失败 */
        oam_error_log2(0, 0, "hwal_ioctl_receive_eapol eapol pkt len(%d) > buf size(%d).", skb_buf->len,
            rx_eapol->len);
        oal_netbuf_free(skb_buf);
        return HI_FAIL;
    }

    if (skb_buf->data != HI_NULL) {
        if (memcpy_s(rx_eapol->buf, skb_buf->len, skb_buf->data, skb_buf->len) != EOK) {
            oam_error_log0(0, 0, "{hwal_ioctl_receive_eapol::mem safe function err!}");
            oal_netbuf_free(skb_buf);
            return HI_FAIL;
        }
    }
    rx_eapol->len = skb_buf->len;

    oal_netbuf_free(skb_buf);

    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_enable_eapol
 功能描述  : 向驱动注册处理接收EAPOL报文回调
 输入参数  :
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月17日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_enable_eapol(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru    *netdev = HI_NULL;
    hisi_enable_eapol_stru *enable_param = HI_NULL;

    enable_param    = (hisi_enable_eapol_stru *)buf;
    netdev          = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (enable_param == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_enable_eapol:pst_netdev is NULL.");
        return -HISI_EFAIL;
    }

    netdev->hisi_eapol.register_code       = HI_TRUE;
    netdev->hisi_eapol.notify_callback   = enable_param->callback;
    netdev->hisi_eapol.context           = enable_param->contex;

    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_disable_eapol
 功能描述  : 向驱动解注册处理EAPOL报文回调
 输入参数  :
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月17日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_disable_eapol(const hi_char *puc_ifname, const hi_void *buf)
{
    oal_net_device_stru    *netdev = HI_NULL;
    hi_unref_param(buf);

    netdev          = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_disable_eapol:pst_netdev is NULL.");
        return -HISI_EFAIL;
    }

    netdev->hisi_eapol.register_code       = HI_FALSE;
    netdev->hisi_eapol.notify_callback   = HI_NULL;
    netdev->hisi_eapol.context           = HI_NULL;

    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_get_addr
 功能描述  : 从驱动获取MAC地址
 输入参数  :
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月17日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_get_addr(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru    *netdev = HI_NULL;

    /* 调用获取MAC地址操作 */
    netdev  = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_get_addr:pst_netdev is NULL.");
        return -HISI_EFAIL;
    }
    if (memcpy_s(buf, ETH_ADDR_LEN, netdev->dev_addr, ETH_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hwal_ioctl_get_addr::mem safe function err!}");
        return -HISI_EFAIL;
    }

    return HI_SUCCESS;
}
/*****************************************************************************
 函 数 名  : hwal_ioctl_get_hw_feature
 功能描述  : 从驱动获取HW feature
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月23日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_get_hw_feature(const hi_char *puc_ifname, hi_void *buf)
{
    hi_u32 loop;

    hisi_hw_feature_data_stru *hw_feature_data = (hisi_hw_feature_data_stru *)buf;

    /* 调用获取HW feature */
    oal_net_device_stru *netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (hw_feature_data == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_get_hw_feature: param is NULL.");
        return -HISI_EFAIL;
    }

    oal_wireless_dev *iee80211 = netdev->ieee80211_ptr;
    if (iee80211 == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_get_hw_feature ieee80211_ptr NULL.");
        return -HISI_EFAIL;
    }

    oal_wiphy_stru *wiphy = oal_wiphy_get();
    if (wiphy == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_get_hw_feature pst_wiphy NULL.");
        return -HISI_EFAIL;
    }

    oal_ieee80211_supported_band *band = wiphy->bands[IEEE80211_BAND_2GHZ];
    if (band == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_get_hw_feature pst_band NULL.");
        return -HISI_EFAIL;
    }

    hw_feature_data->channel_num = band->n_channels;
    hw_feature_data->ht_capab   = band->ht_cap.cap;

    /* 数组越界判断 */
    if (band->n_channels > 14) { /* 14 数组边界 */
        oam_error_log1(0, 0, "error: n_channels = %d > 14.", band->n_channels);
        return -HISI_EFAIL;
    }
    for (loop = 0; loop < (hi_u32)band->n_channels; ++loop) {
        hw_feature_data->iee80211_channel[loop].flags      = band->channels[loop].flags;
        hw_feature_data->iee80211_channel[loop].freq       = band->channels[loop].center_freq;
        hw_feature_data->iee80211_channel[loop].channel = band->channels[loop].hw_value;
    }

    /* 数组越界判断 */
    if (band->n_bitrates > 12) {  /* 12 数组边界 */
        oam_error_log1(0, 0, "error: n_bitrates = %d > 12.", band->n_bitrates);
        return -HISI_EFAIL;
    }
    for (loop = 0; loop < (hi_u32) band->n_bitrates; ++loop) {
        hw_feature_data->bitrate[loop] = band->bitrates[loop].bitrate;
    }

    return HI_SUCCESS;
}
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 函 数 名  : hwal_ioctl_set_power
 功能描述  : wifi上电
 输入参数  : (hi_char *puc_ifname, hi_void *p_buf)
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月13日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_power(hi_char *puc_ifname, hi_void *buf)
{
    hi_unref_param(puc_ifname);
    hi_unref_param(buf);
    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_ip_notify
 功能描述  : 发送ip地址到WAL层
 输入参数  :
 输出参数  :
 返 回 值  :
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年10月13日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_ip_notify(const hi_char *puc_ifname, const hi_void *buf)
{
    oal_net_device_stru                *netdev = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_ip_notify:pst_netdev is NULL.");
        return -HISI_EFAIL;
    }

    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 设置最大 sta 用户数
 修改历史      :
  1.日    期   : 2019年05月20日
    作    者   : Hisilicon
    修改内容   : 删除,不提供wpa设置,通过定制化设置device支持的最大用户数
*****************************************************************************/
hi_s32 hwal_ioctl_set_max_sta(hi_char *puc_ifname, hi_void *max_sta_num)
{
    hi_unref_param(puc_ifname);
    hi_unref_param(max_sta_num);
    return HISI_SUCC;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_del_virtual_intf
 功能描述  : 删除对应VAP
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年3月21日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_del_virtual_intf(hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru     *netdev = HI_NULL;
    oal_wiphy_stru          *wiphy = HI_NULL;
    oal_wireless_dev        *wdev = HI_NULL;

    netdev          = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_del_virtual_intf:pst_netdev is NULL.\r\n");
        return -HISI_EFAIL;
    }

    wiphy           = oal_wiphy_get();

    wdev            = malloc(sizeof(oal_wireless_dev));
    if (wdev == HI_NULL) {
        oam_error_log0(0, 0, "pst_wdev is NULL\r\n");
        return -HISI_EFAIL;
    }
    /* 安全编程规则6.6例外(3)从堆中分配内存后，赋予初值 */
    memset_s(wdev, sizeof(oal_wireless_dev), 0, sizeof(oal_wireless_dev));

    wdev->netdev    = netdev;

    if (HI_SUCCESS != wal_cfg80211_del_virtual_intf(wiphy, wdev)) {
        oam_error_log0(0, 0, "hwal_ioctl_del_virtual_intf::wal_cfg80211_del_virtual_intf failed.\r\n");
        free(wdev);
        return -HISI_EFAIL;
    }
    free(wdev);
    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_stop_ap
 功能描述  : AP下电
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年3月21日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_stop_ap(hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru     *netdev = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_stop_ap:pst_netdev is NULL.");
        return -HISI_EFAIL;
    }

    if (HI_SUCCESS != wal_cfg80211_stop_ap(HI_NULL, netdev)) {
        oam_error_log0(0, 0, "hwal_ioctl_stop_ap::wal_cfg80211_stop_ap failed.\r\n");
        return -HISI_EFAIL;
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 函 数 名  : hwal_ioctl_set_mode
 功能描述  : AP STA p2p模式切换
 输入参数  : (hi_char *puc_ifname, hi_void *p_buf)
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月13日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_mode(const hi_char *puc_ifname, hi_void *buf)
{
    hi_u32               flags;
    oal_net_device_stru     *netdev = HI_NULL;
    oal_vif_params_stru      params = {0};
    hisi_set_mode_stru      *set_mode = HI_NULL;

    flags        = 0;
    set_mode    = (hisi_set_mode_stru *)buf;
    netdev      = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (set_mode == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_hapdinit pst_netdev NULL.\r\n");
        return -HISI_EFAIL;
    }

    params.use_4addr = 0;
    params.macaddr   = set_mode->bssid;

    return (hi_s32)wal_cfg80211_change_virtual_intf(HI_NULL, netdev, set_mode->iftype, &flags, &params);
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_set_netdev
 功能描述  : set_netdev
 输入参数  : (hi_char *puc_ifname, hi_void *p_buf)
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_netdev(const hi_char *puc_ifname, const hi_void *buf)
{
    hi_s32               l_ret;
    oal_net_device_stru *net_dev = HI_NULL;
    struct netif        *netif = HI_NULL;
    hi_u8                en_status;

    netif = netif_find(puc_ifname);
    if (netif == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_netdev cannot find netif");
        return -HISI_EFAIL;
    }

    net_dev = oal_get_netdev_by_name(puc_ifname);
    if ((net_dev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_set_netdev:: param is null.");
        return -HISI_EFAIL;
    }
    en_status  = *(hi_u8 *)buf;
    if (en_status == 0) {
        l_ret = (hi_s32)wal_netdev_stop(net_dev);
        if (netif->flags & NETIF_FLAG_UP) {
            (hi_void)netifapi_netif_set_down(netif);
        }
    } else if (en_status == 1) {
        l_ret = (hi_s32)wal_netdev_open(net_dev);
        if (!(netif->flags & NETIF_FLAG_UP)) {
            (hi_void)netifapi_netif_set_up(netif);
        }
    } else {
        oam_error_log1(0, 0, "hwal_ioctl_set_netdev en_netdev ERROR: %d\r\n", en_status);
        return -HISI_EFAIL;
    }

    return l_ret;
}

/*****************************************************************************
 函 数 名  : hwal_get_channel
 功能描述  : 获取信道
 输入参数  :
 输出参数  :
 返 回 值  :
 调用函数  :
 被调函数  :
 修改历史      :
  1.日    期   : 2016年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
oal_ieee80211_channel *hwal_get_channel(const oal_wiphy_stru *wiphy, hi_s32 l_freq)
{
    enum ieee80211_band             band;
    oal_ieee80211_supported_band   *sband = HI_NULL;
    hi_s32                       l_loop;

    for (band = (enum ieee80211_band)0; band < IEEE80211_NUM_BANDS; band++) {
        sband = wiphy->bands[band];

        if (sband == HI_NULL) {
            continue;
        }

        for (l_loop = 0; l_loop < sband->n_channels; l_loop++) {
            if (sband->channels[l_loop].center_freq == l_freq) {
                return &sband->channels[l_loop];
            }
        }
    }

    return HI_NULL;
}

hi_s32 hwal_ioctl_scan_set_channel(const oal_wiphy_stru *wiphy, const hisi_scan_stru *scan_params,
    oal_cfg80211_scan_request_stru *request)
{
    hi_u32 l_loop;
    hi_u32 count = 0;
    enum ieee80211_band band = IEEE80211_BAND_2GHZ; /* 仅支持2G带宽 */
    oal_ieee80211_channel_stru *chan = HI_NULL;

    if ((scan_params->freqs == HI_NULL) || (scan_params->num_freqs == 0)) {
        /* 不指定信道扫描，将支持的信道全部配置到request里 */
        if (wiphy->bands[band] == HI_NULL) {
            oam_error_log0(0, 0, "hwal_ioctl_scan_set_channel::bands is null, return.");
            free(request);
            return -HISI_EFAIL;
        }

        for (l_loop = 0; l_loop < (hi_u32) wiphy->bands[band]->n_channels; l_loop++) {
            chan = &wiphy->bands[band]->channels[l_loop];
            if ((chan->flags & HISI_CHAN_DISABLED) != 0) {
                continue;
            }

            request->channels[count++] = chan;
        }
    } else {
        /* 指定了信道扫描 */
        for (l_loop = 0; l_loop < scan_params->num_freqs; l_loop++) {
            chan = hwal_get_channel(wiphy, scan_params->freqs[l_loop]);
            if (chan == HI_NULL) {
                oam_error_log0(0, 0, "hwal_ioctl_scan_set_channel::skip one channel that not supported.");
                continue;
            }

            request->channels[count++] = chan;
        }
    }

    if (count == 0) {
        oam_error_log0(0, 0, "hwal_ioctl_scan_set_channel::can not find supported channel, return.");
        free(request);
        return -HISI_EFAIL;
    }
    request->n_channels = count;

    return HISI_SUCC;
}

hi_s32 hwal_ioctl_scan_set_ssid(const hisi_scan_stru *scan_params, oal_cfg80211_scan_request_stru *request)
{
    hi_u32 count = 0;
    hi_u32 l_loop;

    if ((scan_params->num_ssids == 0) || (scan_params->ssids == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_scan::ssid number is 0, return.");
        free(request);
        return -HISI_EFAIL;
    }

    request->ssids = (oal_cfg80211_ssid_stru *)malloc(scan_params->num_ssids * sizeof(oal_cfg80211_ssid_stru));
    if (request->ssids == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_scan::memory is too low, fail to alloc for scan ssid.");
        free(request);
        return -HISI_EFAIL;
    }

    /* 安全编程规则6.6例外（3）从堆中分配内存后，赋予初值 */
    memset_s(request->ssids, scan_params->num_ssids * sizeof(oal_cfg80211_ssid_stru), 0,
        scan_params->num_ssids * sizeof(oal_cfg80211_ssid_stru));

    for (l_loop = 0; l_loop < scan_params->num_ssids; l_loop++) {
        if (count >= HISI_WPAS_MAX_SCAN_SSIDS) {
            break;
        }

        if (scan_params->ssids[l_loop].ssid_len > IEEE80211_MAX_SSID_LEN) {
            oam_warning_log0(0, 0, "hwal_ioctl_scan::one ssid's length is wrong, skip it");
            continue;
        }

        request->ssids[count].ssid_len = (hi_u8)scan_params->ssids[l_loop].ssid_len;
        if (memcpy_s(request->ssids[count].ssid, OAL_IEEE80211_MAX_SSID_LEN,
            scan_params->ssids[l_loop].auc_ssid, scan_params->ssids[l_loop].ssid_len) != EOK) {
            oam_warning_log0(0, 0, "{hwal_ioctl_scan::mem safe function err!}");
            continue;
        }
        count++;
    }
    request->n_ssids = count;

    return HISI_SUCC;
}

hi_s32 hwal_ioctl_scan_set_user_ie(const hisi_scan_stru *scan_params, oal_cfg80211_scan_request_stru *request)
{
    if ((scan_params->extra_ies != HI_NULL) && (scan_params->extra_ies_len != 0)) {
        request->ie = (hi_u8 *)malloc(scan_params->extra_ies_len);
        if (request->ie == HI_NULL) {
            oam_error_log0(0, 0, "hwal_ioctl_scan::memory is too low, fail to alloc for scan ie.");
            goto scan_fail;
        }

        if (memcpy_s(request->ie, scan_params->extra_ies_len, scan_params->extra_ies,
                     scan_params->extra_ies_len) != EOK) {
            oam_warning_log0(0, 0, "{hwal_ioctl_scan::mem safe function err!}");
            goto scan_fail;
        }
        request->ie_len = scan_params->extra_ies_len;
    }

    return HISI_SUCC;

scan_fail:
    if (request->ie != HI_NULL) {
        free(request->ie);
    }

    if (request->ssids != HI_NULL) {
        free(request->ssids);
    }

    free(request);

    return -HISI_EFAIL;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_scan
 功能描述  : 发送扫描至WAL层
 输入参数  :
 输出参数  :
 返 回 值  :
 调用函数  :
 被调函数  :
 修改历史      :
  1.日    期   : 2016年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_scan(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru *netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_scan::param is null.");
        return -HISI_EFAIL;
    }

    oal_cfg80211_scan_request_stru *request =
        (oal_cfg80211_scan_request_stru *)malloc(sizeof(oal_cfg80211_scan_request_stru));
    if (request == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_scan::memory is too low, fail to alloc for scan request.");
        return -HISI_EFAIL;
    }

    /* 安全编程规则6.6例外（3）从堆中分配内存后，赋予初值 */
    memset_s(request, sizeof(oal_cfg80211_scan_request_stru), 0, sizeof(oal_cfg80211_scan_request_stru));

    hisi_scan_stru *scan_params = (hisi_scan_stru *)buf;
    oal_wiphy_stru *wiphy       = oal_wiphy_get();
    request->wiphy    = wiphy;
    request->dev      = netdev;
    request->wdev     = netdev->ieee80211_ptr;
    request->n_ssids  = scan_params->num_ssids;
    request->prefix_ssid_scan_flag = scan_params->prefix_ssid_scan_flag;

    /* 配置扫描信道 */
    hi_s32 ret = hwal_ioctl_scan_set_channel(wiphy, scan_params, request);
    if (ret != HISI_SUCC) {
        return ret;
    }

    /* 配置SSID */
    ret = hwal_ioctl_scan_set_ssid(scan_params, request);
    if (ret != HISI_SUCC) {
        return ret;
    }

    /* 配置user ie */
    ret = hwal_ioctl_scan_set_user_ie(scan_params, request);
    if (ret != HISI_SUCC) {
        return ret;
    }

    if (wal_cfg80211_scan(wiphy, request) != HI_SUCCESS) {
        if (request->ie != HI_NULL) {
            free(request->ie);
        }

        if (request->ssids != HI_NULL) {
            free(request->ssids);
        }

        free(request);

        return -HISI_EFAIL;
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_P2P
/*****************************************************************************
 功能描述  : 添加接口
 修改历史      :
  1.日    期   : 2019年4月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_add_if(const hi_char *puc_ifname, hi_void *buf)
{
    hisi_if_add_stru   *if_add = HI_NULL;
    hi_u8               ifname[IFNAMSIZ];
    hi_u32              len = (hi_u32)sizeof(ifname);
    hi_s32              ret;

    if_add = (hisi_if_add_stru *)buf;
    ret = wal_init_drv_wlan_netdev((nl80211_iftype_uint8)if_add->type, WAL_PHY_MODE_11N, (hi_char *)ifname, &len);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hwal_ioctl_add_if: wal_init_drv_wlan_netdev failed!");
        return -HISI_EFAIL;
    }
    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 删除接口
 修改历史      :
  1.日    期   : 2019年7月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_remove_if(const hi_char *puc_ifname, hi_void *buf)
{
    hisi_if_remove_stru             *if_remove = HI_NULL;
    hi_s32                           ret;

    if_remove = (hisi_if_remove_stru *)buf;

    ret = wal_deinit_drv_wlan_netdev((const hi_char *)if_remove->ifname);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hwal_ioctl_remove_if: wal_deinit_drv_wlan_netdev failed!");
        return -HISI_EFAIL;
    }
    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 获取P2P GO/GC的MAC地址
 修改历史      :
  1.日    期   : 2019年8月6日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_get_p2p_addr(const hi_char *puc_ifname, hi_void *buf)
{
    hisi_get_p2p_addr_stru          *get_p2p_addr = HI_NULL;
    hi_u32                           ret;

    get_p2p_addr = (hisi_get_p2p_addr_stru *)buf;

    ret = wal_get_dev_addr(get_p2p_addr->mac_addr, ETH_ADDR_LEN, (hi_u8)get_p2p_addr->type);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hwal_ioctl_get_p2p_addr: wal_get_dev_addr failed!");
        return -HISI_EFAIL;
    }
    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 发送探测请求帧上报命令到驱动层
 修改历史      :
  1.日    期   : 2019年4月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_probe_req_report(const hi_char *puc_ifname, const hi_void *buf)
{
    oal_net_device_stru   *netdev = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_probe_req_report::pst_netdev null!}");
        return -HISI_EFAIL;
    }

    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 保持在指定信道
 修改历史      :
  1.日    期   : 2019年4月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_remain_on_channel(const hi_char *puc_ifname, hi_void *buf)
{
    oal_wiphy_stru        *wiphy = HI_NULL;
    oal_net_device_stru   *netdev = HI_NULL;
    oal_wireless_dev      *wdev = HI_NULL;
    hi_u64                 pull_cookie = 0;
    hi_u8                  channel_idx;
    hisi_on_channel_stru  *param = HI_NULL;
    oal_ieee80211_channel* wifi_2ghz_channels = wal_get_g_wifi_2ghz_channels();

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_ioctl_remain_on_channel::pst_netdev null!}");
        return -HISI_EFAIL;
    }
    wdev = netdev->ieee80211_ptr;
    wiphy = oal_wiphy_get();

    /* 接收由wpa下发的参数 pst_param[0] = freq, pst_param[1] = duration */
    param = (hisi_on_channel_stru *)buf;
    channel_idx = (hi_u8)oal_ieee80211_frequency_to_channel(param->freq);

    return (hi_s32)wal_cfg80211_remain_on_channel(wiphy, wdev, &(wifi_2ghz_channels[channel_idx - 1]),
                                                  (hi_u32)param->duration, &pull_cookie);
}

/*****************************************************************************
 功能描述  : 取消在指定信道
 修改历史      :
  1.日    期   : 2019年4月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_cancel_remain_on_channel(const hi_char *puc_ifname, const hi_void *buf)
{
    oal_net_device_stru   *netdev = HI_NULL;
    oal_wireless_dev      *wdev = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_cancel_remain_on_channel: pst_netdev NULL.");
        return -HISI_EFAIL;
    }
    wdev = netdev->ieee80211_ptr;

    /* 若为1表示当前操作为保持在指定信道，为0表示取消保持在指定信道 */
    return (hi_s32)wal_cfg80211_cancel_remain_on_channel(HI_NULL, wdev, (hi_u64)0);
}

/*****************************************************************************
 功能描述  : 下发p2p的noa参数到驱动
 修改历史      :
  1.日    期   : 2019年5月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_set_p2p_noa(const hi_char *puc_ifname, hi_void *buf)
{
    mac_cfg_p2p_noa_param_stru mac_cfg_p2p_noa;
    oal_net_device_stru       *netdev = HI_NULL;
    hisi_p2p_noa_stru         *p2p_noa = HI_NULL;
    mac_device_stru           *mac_dev = HI_NULL;
    hi_u32                     ret;

    mac_dev = mac_res_get_dev();
    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_ioctl_set_p2p_noa::pst_netdev NULL!}");
        return -HISI_EFAIL;
    }
    p2p_noa = (hisi_p2p_noa_stru *)buf;

    mac_cfg_p2p_noa.count = p2p_noa->count;
    mac_cfg_p2p_noa.start_time = (hi_u32)p2p_noa->start;
    mac_cfg_p2p_noa.duration = (hi_u32)p2p_noa->duration;
    mac_cfg_p2p_noa.interval = mac_dev->beacon_interval;

    ret = wal_ioctl_set_p2p_noa(netdev, &mac_cfg_p2p_noa);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hwal_ioctl_set_p2p_noa: wal_ioctl_set_p2p_noa failed!");
        return -HISI_EFAIL;
    }
    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 下发p2p的powersave参数到驱动
 修改历史      :
  1.日    期   : 2019年5月20日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_set_p2p_powersave(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru       *netdev = HI_NULL;
    hisi_p2p_power_save_stru  *p2p_power_save = HI_NULL;
    mac_cfg_p2p_ops_param_stru p2p_ops_param;
    hi_u32                     ret;

    /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
    memset_s(&p2p_ops_param, sizeof(mac_cfg_p2p_ops_param_stru), 0, sizeof(mac_cfg_p2p_ops_param_stru));

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_ioctl_set_p2p_powersave::pst_netdev null!}");
        return -HISI_EFAIL;
    }
    p2p_power_save = (hisi_p2p_power_save_stru *)buf;
    p2p_ops_param.ct_window = (hi_u8)p2p_power_save->ctwindow;

    if (p2p_power_save->opp_ps != -1) {
        p2p_ops_param.ops_ctrl = (hi_s8)p2p_power_save->opp_ps;
    }

    ret = wal_ioctl_set_p2p_ops(netdev, &p2p_ops_param);
    if (ret != HI_SUCCESS) {
        oam_error_log0(0, 0, "hwal_ioctl_set_p2p_powersave: wal_ioctl_set_p2p_ops failed!");
        return -HISI_EFAIL;
    }

    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 设置app ie 到wifi驱动
 修改历史      :
  1.日    期   : 2016年7月6日
    作    者   : Hisilicon
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_set_ap_wps_p2p_ie(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru *netdev = HI_NULL;
    hisi_app_ie_stru    *app_ie = HI_NULL;
    oal_app_ie_stru      wps_p2p_ie;

    if (memset_s(&wps_p2p_ie, sizeof(oal_app_ie_stru), 0, sizeof(oal_app_ie_stru)) != EOK) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_ap_wps_p2p_ie::mem safe function err!}");
        return -HISI_EFAIL;
    }
    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_ap_wps_p2p_ie parameter NULL.");
        return -HISI_EFAIL;
    }
    app_ie = (hisi_app_ie_stru *)buf;
    wps_p2p_ie.ie_len = app_ie->ie_len;
    wps_p2p_ie.app_ie_type = app_ie->app_ie_type;

    if (wps_p2p_ie.ie_len > WLAN_WPS_IE_MAX_SIZE) {
        oam_error_log0(0, 0, "app ie length is too large!");
        return -HISI_EFAIL;
    }
    if (memcpy_s(wps_p2p_ie.auc_ie, WLAN_WPS_IE_MAX_SIZE, app_ie->puc_ie, app_ie->ie_len) != EOK) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_ap_wps_p2p_ie::mem safe function err!}");
        return -HISI_EFAIL;
    }

    return (hi_s32)wal_ioctl_set_wps_p2p_ie(netdev, wps_p2p_ie.auc_ie, wps_p2p_ie.ie_len,
                                            wps_p2p_ie.app_ie_type);
}
#endif


/*****************************************************************************
 功能描述  : 设置协议低功耗启动
*****************************************************************************/
hi_s32 hwal_ioctl_set_pm_switch(const hi_char *puc_ifname, const hi_void *buf)
{
    oal_net_device_stru                *cfg_net_dev = HI_NULL;
    mac_vap_stru                       *mac_vap = HI_NULL;
    hi_u32                              pm_cfg;
    hi_u32                              ret;
    wal_msg_write_stru                  write_msg;

    if (buf == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_pm_switch:p_buf parameter NULL.");
        return -HISI_EFAIL;
    }

    if (puc_ifname == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_pm_switch:puc_ifname parameter NULL.");
        return -HISI_EFAIL;
    }

    cfg_net_dev = oal_get_netdev_by_name(puc_ifname);
    if (cfg_net_dev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_pm_switch:pst_cfg_net_dev NULL.");
        return -HISI_EFAIL;
    }

    mac_vap = oal_net_dev_priv(cfg_net_dev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, 0, "hwal_ioctl_set_pm_switch:pst_mac_vap NULL.");
        return -HISI_EFAIL;
    }

    /***************************************************************************
                             抛事件到wal层处理
    ***************************************************************************/
    pm_cfg = *(hi_u32 *)buf;
    /* 缓存低功耗标志 */
    set_under_ps(pm_cfg == 1);
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_PM_SWITCH, sizeof(hi_u32));
    *((hi_u32 *)(write_msg.auc_value)) = pm_cfg;

    ret = wal_send_cfg_event(cfg_net_dev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hwal_ioctl_set_pm_switch::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HISI_SUCC;
}

/*****************************************************************************
 功能描述  : 获取驱动相关标志位
 修改历史      :
  1.日    期   : 2019年8月6日
    修改内容   : 新生成函数
*****************************************************************************/
hi_s32 hwal_ioctl_get_drv_flags(const hi_char *puc_ifname, hi_void *buf)
{
    hisi_get_drv_flags_stru *get_drv_flag = HI_NULL;
    oal_net_device_stru *netdev = HI_NULL;

    if (buf == HI_NULL) {
        return -HISI_EFAIL;
    }
    get_drv_flag = (hisi_get_drv_flags_stru *)buf;

    /* 获取下发的ifname对应的type类型 */
    netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (netdev->ieee80211_ptr == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_ioctl_scan::fail to acquire netdev from ifname, return.");
        return -HISI_EFAIL;
    }
    switch (netdev->ieee80211_ptr->iftype) {
        case NL80211_IFTYPE_P2P_GO:
            get_drv_flag->drv_flags = (hi_u64)(HISI_DRIVER_FLAGS_AP);
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            get_drv_flag->drv_flags = (hi_u64)(HISI_DRIVER_FLAGS_DEDICATED_P2P_DEVICE |
                                               HISI_DRIVER_FLAGS_P2P_DEDICATED_INTERFACE |
                                               HISI_DRIVER_FLAGS_P2P_CONCURRENT |
                                               HISI_DRIVER_FLAGS_P2P_CAPABLE);
            break;
        default:
            get_drv_flag->drv_flags = 0;
    }

    return HISI_SUCC;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_disconnect
 功能描述  : 发送去关联至WAL层
 输入参数  :
 输出参数  :
 返 回 值  :
 调用函数  :
 被调函数  :
 修改历史      :
  1.日    期   : 2016年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_disconnect(const hi_char *puc_ifname, const hi_void *buf)
{
    oal_net_device_stru         *netdev = HI_NULL;
    hi_u16                       us_reason_code;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (buf == HI_NULL)) {
        return -HISI_EFAIL;
    }
    us_reason_code  = *(hi_u16 *)buf;

    return (hi_s32)wal_cfg80211_disconnect(HI_NULL, netdev, us_reason_code);
}
/*****************************************************************************
 函 数 名  : hwal_is_valid_ie_attr
 功能描述  : 判断是否为无效ie
 输入参数  :
 输出参数  :
 返 回 值  :
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_u8 hwal_is_valid_ie_attr(const hi_u8 *puc_ie, hi_u32 ie_len)
{
    hi_u8 elemlen;

    /* ie可以为空 */
    if (puc_ie == HI_NULL) {
        return HI_TRUE;
    }

    while (ie_len != 0) {
        if (ie_len < 2) { /* 2 无效ie */
            oam_error_log0(0, 0, "puc_ie parameter FALSE.");
            return HI_FALSE;
        }
        ie_len -= 2; /* 2 步长 */

        elemlen = puc_ie[1];
        if (elemlen > ie_len) {
            oam_error_log0(0, 0, "puc_ie parameter FALSE.");
            return HI_FALSE;
        }
        ie_len -= elemlen;
        puc_ie += 2 + elemlen; /* 2 步长 */
    }

    return HI_TRUE;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_assoc
 功能描述  : 发送关联至WAL层
 输入参数  :
 输出参数  :
 返 回 值  :
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_assoc(const hi_char *puc_ifname, hi_void *buf)
{
    oal_cfg80211_connect_params_stru sme = {0};
    oal_net_device_stru *netdev       = oal_get_netdev_by_name(puc_ifname);
    oal_wiphy_stru *wiphy             = oal_wiphy_get();
    hisi_associate_params_stru *assoc = (hisi_associate_params_stru *)buf;

    if ((assoc == HI_NULL) || (assoc->ssid == HI_NULL) || (assoc->ssid_len == 0)) {
        oam_error_log0(0, 0, "assoc parameter NULL.");
        return -HISI_EFAIL;
    }

    sme.ssid        = assoc->ssid;
    sme.ssid_len    = assoc->ssid_len;
    if (hwal_is_valid_ie_attr(assoc->ie, assoc->ie_len) == HI_FALSE) {
        return -HISI_EFAIL;
    }
    sme.ie          = assoc->ie;
    sme.ie_len      = assoc->ie_len;

    if ((assoc->auth_type > NL80211_AUTHTYPE_AUTOMATIC) || (assoc->auth_type == NL80211_AUTHTYPE_SAE)) {
        oam_error_log0(0, 0, "assoc->uc_auth_type ERROR.");
        return -HISI_EFAIL;
    } else {
        sme.auth_type = assoc->auth_type;
    }

    sme.channel = hwal_get_channel(wiphy, (hi_s32)assoc->freq);
    if ((sme.channel == HI_NULL) || (sme.channel->flags & HISI_CHAN_DISABLED)) {
        oam_error_log0(0, 0, "st_sme.channel ERROR.");
        return -HISI_EFAIL;
    }

    if (assoc->bssid != HI_NULL) {
        sme.bssid = assoc->bssid;
    }

    sme.privacy = assoc->privacy;

    if ((assoc->mfp != HISI_MFP_REQUIRED) && (assoc->mfp != HISI_MFP_NO) && (assoc->mfp != HISI_MFP_OPTIONAL)) {
        oam_error_log1(0, 0, "assoc->uc_mfp ERROR. uc_mfp = %d", assoc->mfp);
        return -HISI_EFAIL;
    }

    sme.mfp = (enum nl80211_mfp)assoc->mfp;

    if (assoc->key != HI_NULL) {
        sme.key     = assoc->key;
        sme.key_len = assoc->key_len;
        sme.key_idx = assoc->key_idx;
    }

    if (memcpy_s(&sme.crypto, sizeof(hisi_crypto_settings_stru),
        assoc->crypto, sizeof(hisi_crypto_settings_stru)) != EOK) {
        oam_error_log0(0, 0, "{hwal_ioctl_assoc::mem safe function err!}");
        return -HISI_EFAIL;
    }
    /* 设置自动重关联标志 */
    wal_set_auto_conn_status(assoc->auto_conn);

    return (hi_s32)wal_cfg80211_connect(wiphy, netdev, &sme);
}

#ifdef _PRE_WLAN_FEATURE_REKEY_OFFLOAD
/*****************************************************************************
 函 数 名  : hwal_ioctl_set_rekey_info
 功能描述  : set rekey info数据传递至WAL层
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年8月2日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_rekey_info(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru     *netdev = HI_NULL;
    hisi_rekey_offload_stru *rekey_offload = HI_NULL;

    netdev          = oal_get_netdev_by_name(puc_ifname);
    rekey_offload   = (hisi_rekey_offload_stru *)buf;

    return (hi_s32)wal_cfg80211_set_rekey_info(netdev, (mac_rekey_offload_stru *)rekey_offload);
}
#endif

/*****************************************************************************
 函 数 名  : hwal_ioctl_sta_remove
 功能描述  : 删除station命令下发至wal层
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2017年3月23日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_sta_remove(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru                  *netdev = HI_NULL;
    hi_u8                                *mac_addr = HI_NULL;

    netdev      = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_sta_remove:pst_netdev is NULL.}");
        return HI_FAIL;
    }

    mac_addr         = (hi_u8*)buf;

    return (hi_s32)wal_cfg80211_del_station(HI_NULL, netdev, mac_addr);
}

hi_u32 hwal_ioctl_init_msg_hdr(wal_msg_write_stru *write_msg, const hisi_action_data_stru *action_data)
{
    hi_unref_param(write_msg);

    if (action_data->data[0] == MAC_ACTION_CATEGORY_SELF_PROTECTED) {
#ifdef _PRE_WLAN_FEATURE_MESH
        wal_write_msg_hdr_init(write_msg, WLAN_CFGID_SEND_MESH_ACTION, sizeof(mac_action_data_stru));
#else
        return HI_FAIL;
#endif
    } else if (action_data->data[0] == MAC_ACTION_CATEGORY_PUBLIC) {
#ifdef _PRE_WLAN_FEATURE_P2P
        wal_write_msg_hdr_init(write_msg, WLAN_CFGID_SEND_P2P_ACTION, sizeof(mac_action_data_stru));
#endif
    } else {
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hwal_ioctl_send_action
 功能描述  : WPA 发送Action帧,在已组好的帧体前加入Action帧帧头
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 输出参数  : 无
 返 回 值  : hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2019年1月7日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_send_action(const hi_char *puc_ifname, hi_void *buf)
{
    wal_msg_write_stru write_msg;

    oal_net_device_stru *netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_send_action:pst_netdev is NULL.}");
        return HI_FAIL;
    }

    hisi_action_data_stru *action_data = (hisi_action_data_stru *)buf;

    /***************************************************************************
                             抛事件到wal层处理
    ***************************************************************************/
    if (hwal_ioctl_init_msg_hdr(&write_msg, action_data) == HI_FAIL) {
        return HI_FAIL;
    }

    /* 设置命令参数 */
    mac_action_data_stru *action_param = (mac_action_data_stru *)(write_msg.auc_value);

    if ((memcpy_s(action_param->dst, WLAN_MAC_ADDR_LEN, action_data->dst, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(action_param->src, WLAN_MAC_ADDR_LEN, action_data->src, WLAN_MAC_ADDR_LEN) != EOK) ||
        (memcpy_s(action_param->bssid, WLAN_MAC_ADDR_LEN, action_data->bssid, WLAN_MAC_ADDR_LEN) != EOK)) {
        oam_error_log0(0, 0, "{hwal_ioctl_send_action::mem safe function err!}");
        return HI_FAIL;
    }

    action_param->data = HI_NULL;
    if (action_data->data_len > 0) {
        action_param->data  = malloc(action_data->data_len * sizeof(hi_u8));
        if (oal_unlikely(action_param->data  == HI_NULL)) {
            oam_error_log0(0, OAM_SF_CFG, "{hwal_ioctl_send_action::puc_data alloc mem return null ptr!}");
            return HI_FAIL;
        }

        if (memcpy_s(action_param->data, action_data->data_len, action_data->data, action_data->data_len) != EOK) {
            oam_error_log0(0, 0, "{hwal_ioctl_send_action::mem safe function err!}");
            free(action_param->data);
            return HI_FAIL;
        }
    }
    action_param->data_len = action_data->data_len;

    oam_warning_log4(0, 0, "hwal_ioctl_send_action send action frame(mac addr = %02X:XX:%02X:XX:%02X:%02X)",
        action_param->dst[0], action_param->dst[2],  /* 0 2 数组位数 */
        action_param->dst[4], action_param->dst[5]); /* 4 5 数组位数 */

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_action_data_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hwal_ioctl_send_action ::send action frame to driver failed[%d].}", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 功能描述  : Mesh中Wpa_supplicant负责整个关联过程，通过该接口设置Mesh 类型User状态
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 修改历史      :
  1.日    期   : 2019年2月1日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_mesh_user(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru *netdev = HI_NULL;
    hisi_set_mesh_user_data_stru *set_params = HI_NULL;
    hi_u32 ret;
    wal_msg_write_stru write_msg;
    mac_cfg_set_mesh_user_param_stru *drv_user_param = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_mesh_user:pst_netdev is NULL.}");
        return HI_FAIL;
    }

    set_params = (hisi_set_mesh_user_data_stru *)buf;
    if (set_params->set == HI_SWITCH_OFF) {
        /***************************************************************************
            抛事件到wal层处理
        ***************************************************************************/
        wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ADD_MESH_USER, sizeof(mac_cfg_set_mesh_user_param_stru));

        oam_warning_log4(0, 0, "hwal_ioctl_set_mesh_user add mesh user(mac addr = %02X:XX:%02X:XX:%02X:%02X)",
            set_params->puc_addr[0], set_params->puc_addr[2],   /* 0 2 数组位数 */
            set_params->puc_addr[4], set_params->puc_addr[5]);  /* 4 5 数组位数 */
    } else {
        /***************************************************************************
                                 抛事件到wal层处理
        ***************************************************************************/
        wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MESH_STA, sizeof(mac_cfg_set_mesh_user_param_stru));

        oam_warning_log4(0, 0,
            "hwal_ioctl_set_mesh_user set mesh-sta state,state = %d, bcn_prio = %d, \
            uc_is_mbr = %d(mac addr = XX:XX:XX:XX:XX:%02X)", set_params->plink_state, set_params->bcn_prio,
            set_params->is_mbr, set_params->puc_addr[5]);  /* 5 数组位数 */
    }

    /* 设置配置命令参数 */
    drv_user_param = (mac_cfg_set_mesh_user_param_stru *)(write_msg.auc_value);
    if (memcpy_s(drv_user_param->auc_addr, WLAN_MAC_ADDR_LEN,
                 set_params->puc_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_mesh_user::mem safe function err!}");
        return HI_FAIL;
    }
    drv_user_param->plink_sta = set_params->plink_state;
    drv_user_param->set = set_params->set;
    drv_user_param->bcn_prio = set_params->bcn_prio;
    drv_user_param->is_mbr = set_params->is_mbr;
    drv_user_param->mesh_initiative_peering = set_params->mesh_initiative_peering;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_set_mesh_user_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hwal_ioctl_set_mesh_user::add_sta failed[%d].}", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 功能描述  : wpa通过该接口使能mesh自动关联
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 返 回 值  : hi_s32
 修改历史      :
  1.日    期   : 2019年6月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_enable_auto_peer(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru         *netdev = HI_NULL;
    hisi_enable_auto_peer_stru  *auto_en = HI_NULL;
    hi_u32                       ret;
    wal_msg_write_stru           write_msg;
    hi_u8                       *puc_en_auto_peer_param = HI_NULL;
    wal_msg_stru                *rsp_msg = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_enable_auto_peer:pst_netdev is NULL.}");
        return HI_FAIL;
    }

    auto_en = (hisi_enable_auto_peer_stru *)buf;
    if (auto_en->enable_auto_peer > 1) {
        oam_error_log0(0, 0, "{hwal_ioctl_enable_auto_peer::invalid en value.}");
        return HI_FAIL;
    }
    /***************************************************************************
        抛事件到wal层处理
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_NEW_PEER_CONFIG_EN, sizeof(hi_u8));

    /* 设置配置命令参数 */
    puc_en_auto_peer_param = (hi_u8 *)(write_msg.auc_value);
    *puc_en_auto_peer_param = auto_en->enable_auto_peer;

    oam_warning_log1(0, 0, "hwal_ioctl_enable_auto_peer::[Mesh]Auto peer switch = %d", auto_en->enable_auto_peer);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_TRUE,
                             &rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hwal_ioctl_enable_auto_peer::en_auto_peer failed[%d].}", ret);
        return HI_FAIL;
    }
    if (wal_check_and_release_msg_resp(rsp_msg) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_ioctl_enable_auto_peer::wal_check_and_release_msg_resp fail.}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 功能描述  : Mesh中Wpa_supplicant负责整个关联过程，通过该接口设置Mesh用户的组播密钥
 输入参数  : hi_char *puc_ifname, oal_void *p_buf
 返 回 值  : oal_int32
 修改历史      :
  1.日    期   : 2019年5月20日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_mesh_gtk(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru *netdev = HI_NULL;
    hisi_set_mesh_user_gtk_stru *gtk_params = HI_NULL;
    hi_u32 ret;
    wal_msg_write_stru write_msg;
    mac_set_mesh_user_gtk_stru *user_gtk = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_mesh_gtk:pst_netdev is NULL.}");
        return -HISI_EFAIL;
    }

    gtk_params = (hisi_set_mesh_user_gtk_stru *)buf;

    /* 只支持ccmp-128 */
    if (gtk_params->gtk_len != WLAN_CCMP_KEY_LEN) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_mesh_gtk::wrong gtk len,only ccmp-128.}");
        return -HISI_EFAIL;
    }
    /***************************************************************************
        抛事件到wal层处理
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MESH_USER_GTK, sizeof(mac_set_mesh_user_gtk_stru));

    /* 设置配置命令参数 */
    user_gtk = (mac_set_mesh_user_gtk_stru *)(write_msg.auc_value);
    if (memcpy_s(user_gtk->auc_addr, WLAN_MAC_ADDR_LEN, gtk_params->puc_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_warning_log0(0, 0, "{hwal_ioctl_set_mesh_gtk::memcpy_s fail!.}");
        return -HISI_EFAIL;
    }
    if (memcpy_s(user_gtk->auc_gtk, gtk_params->gtk_len, gtk_params->puc_gtk, gtk_params->gtk_len) != EOK) {
        oam_warning_log0(0, 0, "{hwal_ioctl_set_mesh_gtk::memcpy_s fail!.}");
        return -HISI_EFAIL;
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_set_mesh_user_gtk_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hwal_ioctl_set_mesh_gtk::set gtk failed[%d].}", ret);
        return -HISI_EFAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 功能描述  : wpa通过该接口设置Accept Peer的值
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 返 回 值  : hi_s32
 修改历史      :
  1.日    期   : 2019年7月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_accept_peer(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru             *netdev = HI_NULL;
    hisi_enable_accept_peer_stru    *accept_peer = HI_NULL;
    hi_u32                           ret;
    wal_msg_write_stru               write_msg;
    hi_u8                           *puc_accept_peer_params = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_accept_peer:pst_netdev is NULL.}");
        return HI_FAIL;
    }

    accept_peer = (hisi_enable_accept_peer_stru *)buf;

    if (accept_peer->enable_accept_peer > 1) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_accept_peer::invalid accept peer value.}");
        return HI_FAIL;
    }
    /***************************************************************************
        抛事件到wal层处理
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ACCEPT_PEER, sizeof(hi_u8));

    /* 设置配置命令参数 */
    puc_accept_peer_params = (hi_u8 *)(write_msg.auc_value);
    *puc_accept_peer_params = accept_peer->enable_accept_peer;

    oam_warning_log1(0, 0, "hwal_ioctl_set_accept_peer::[Mesh]Set Accept Peer[%d]", accept_peer->enable_accept_peer);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hwal_ioctl_set_accept_peer::wal_send_cfg_event failed[%d].}", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 功能描述  : wpa通过该接口设置Accept Sta的值
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 返 回 值  : hi_s32
 修改历史      :
  1.日    期   : 2019年7月29日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hwal_ioctl_set_accept_sta(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru         *netdev = HI_NULL;
    hisi_enable_accept_sta_stru *accept_sta = HI_NULL;
    hi_u32                       ret;
    wal_msg_write_stru           write_msg;
    hi_u8                       *puc_accept_sta_params = HI_NULL;

    netdev = oal_get_netdev_by_name(puc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_accept_sta:pst_netdev is NULL.}");
        return HI_FAIL;
    }

    accept_sta = (hisi_enable_accept_sta_stru *)buf;

    if (accept_sta->enable_accept_sta > 1) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_accept_sta::invalid accept peer value.}");
        return HI_FAIL;
    }
    /***************************************************************************
        抛事件到wal层处理
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MESH_ACCEPT_STA, sizeof(hi_u8));

    /* 设置配置命令参数 */
    puc_accept_sta_params = (hi_u8 *)(write_msg.auc_value);
    *puc_accept_sta_params = accept_sta->enable_accept_sta;

    oam_warning_log1(0, 0, "hwal_ioctl_set_accept_sta::[Mesh]Set Accept sta[%d]", accept_sta->enable_accept_sta);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{hwal_ioctl_set_accept_sta::wal_send_cfg_event failed[%d].}", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

#endif

/*****************************************************************************
 功能描述  : wpa通过该接口设置延时上报机制参数
 输入参数  : hi_char *puc_ifname, hi_void *p_buf
 返 回 值  : hi_s32
*****************************************************************************/
hi_s32 hwal_ioctl_set_delay_report(const hi_char *puc_ifname, hi_void *buf)
{
    oal_net_device_stru  *netdev = HI_NULL;
    hisi_delay_report_stru *delay_report = HI_NULL;

    if (buf == HI_NULL) {
        return HI_FAIL;
    }
    netdev = oal_get_netdev_by_name(puc_ifname);
    if ((netdev == HI_NULL) || (netdev->ieee80211_ptr == HI_NULL)) {
        oam_error_log0(0, 0, "{hwal_ioctl_set_delay_report:pst_netdev is NULL.}");
        return HI_FAIL;
    }
    /* 仅STA支持配置 */
    if (netdev->ieee80211_ptr->iftype != NL80211_IFTYPE_STATION) {
        oam_error_log1(0, 0, "{hwal_ioctl_set_delay_report:type[%d] isn't support this feature.}",
            netdev->ieee80211_ptr->iftype);
        return HI_FAIL;
    }
    delay_report = (hisi_delay_report_stru *)buf;
    wal_set_delay_report_config(delay_report->enable, delay_report->timeout);

    return HI_SUCCESS;
}

/*****************************************************************************
 函 数 名  : hisi_hwal_wpa_ioctl
 功能描述  : 驱动对wpa提供统一调用接口
 输入参数  :
 输出参数  : 无
 返 回 值  : static hi_s32
 调用函数  :
 被调函数  :

 修改历史      :
  1.日    期   : 2016年6月17日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
hi_s32 hisi_hwal_wpa_ioctl(hi_char *pc_ifname, hisi_ioctl_command_stru *cmd)
{
    oal_net_device_stru *netdev = HI_NULL;

    if ((pc_ifname == HI_NULL) || (cmd == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "hwal_wpa_ioctl::puc_ifname = %p,p_buf = %p",
                       (uintptr_t)pc_ifname, (uintptr_t)cmd);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* 根据dev_name找到dev */
    netdev = oal_get_netdev_by_name(pc_ifname);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_wpa_ioctl::oal_get_netdev_by_name return null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    if (((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) &&
        ((cmd->cmd == HISI_IOCTL_SEND_MLME) || (cmd->cmd == HISI_IOCTL_SEND_EAPOL) ||
        (cmd->cmd == HISI_IOCTL_RECEIVE_EAPOL) ||
#ifdef _PRE_WLAN_FEATURE_MESH
        (cmd->cmd == HISI_IOCTL_SEND_ACTION) ||
#endif
        (cmd->cmd == HISI_IOCTL_SCAN) || (cmd->cmd == HISI_IOCTL_ASSOC))) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_wpa_ioctl::pst_net_dev is down.}\r\n");
        return -HISI_EFAIL;
    }

    if ((cmd->cmd < HWAL_EVENT_BUTT) && (g_ast_hwal_ioctl_handlers[cmd->cmd] != HI_NULL) && (cmd->buf != HI_NULL)) {
        return g_ast_hwal_ioctl_handlers[cmd->cmd](pc_ifname, cmd->buf);
    }

    oam_error_log1(0, 0, "hwal_wpa_ioctl ::The CMD[%d] handlers is NULL", cmd->cmd);

    return -HISI_EFAIL;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

