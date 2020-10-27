/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: OAL module initialization.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_net.h"
#include "oal_cfg80211.h"

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "wal_cfg80211_apt.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
static oal_kobj_uevent_env_stru g_env;
#endif

/*****************************************************************************
 ��������  : �ϱ�����ɨ����
*****************************************************************************/
hi_void  oal_cfg80211_sched_scan_result(oal_wiphy_stru *pst_wiphy)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if LINUX_VERSION_CODE < kernel_version(4,14,0)
    return cfg80211_sched_scan_results(pst_wiphy);
#else
    return cfg80211_sched_scan_results(pst_wiphy, 0);
#endif
#else
    hi_unref_param(pst_wiphy);
#endif
}

/*****************************************************************************
 ��������  : �ϱ�linux �ں��Ѿ�����ָ���ŵ�
*****************************************************************************/
hi_void oal_cfg80211_ready_on_channel(
#if (LINUX_VERSION_CODE >= kernel_version(3, 10, 0)) || (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
                                      oal_wireless_dev       *wdev,
#else
                                      oal_net_device_stru         *net_dev,
#endif
                                      hi_u64 cookie,
                                      oal_ieee80211_channel_stru *chan,
                                      hi_u32                  duration,
                                      oal_gfp_enum_uint8          en_gfp)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 10, 0))
    cfg80211_ready_on_channel(wdev, cookie, chan, duration, en_gfp);
#else
    enum nl80211_channel_type   en_channel_type;
    en_channel_type = NL80211_CHAN_HT20;
    cfg80211_ready_on_channel(pst_net_dev, cookie, chan, en_channel_type, duration, en_gfp);
#endif
#else
    hi_unref_param(wdev);
    hi_unref_param(cookie);
    hi_unref_param(chan);
    hi_unref_param(duration);
    hi_unref_param(en_gfp);
#endif
}

hi_void oal_kobject_uevent_env_sta_join(oal_net_device_stru *net_device, const hi_u8 *mac_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    memset_s(&g_env, sizeof(g_env), 0, sizeof(g_env));
    /* Android�ϲ���ҪSTA_JOIN��mac��ַ���м������Ч�����Ǳ�����4������ */
    add_uevent_var(&g_env, "SOFTAP=STA_JOIN wlan0 wlan0 %02x:%02x:%02x:%02x:%02x:%02x",
        mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]); /* mac addr 0:1:2:3:4:5 */
#if (LINUX_VERSION_CODE >= kernel_version(4,1,0))
    kobject_uevent_env(&(net_device->dev.kobj), KOBJ_CHANGE, g_env.envp);
#else
    kobject_uevent_env(&(net_device->dev.kobj), KOBJ_CHANGE, (char**)&g_env);
#endif
#else
    hi_unref_param(net_device);
    hi_unref_param(mac_addr);
#endif /*#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)*/
}

hi_void oal_kobject_uevent_env_sta_leave(oal_net_device_stru *net_device, const hi_u8 *mac_addr)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    memset_s(&g_env, sizeof(g_env), 0, sizeof(g_env));
    /* Android�ϲ���ҪSTA_LEAVE��mac��ַ���м������Ч�����Ǳ�����4������ */
    add_uevent_var(&g_env, "SOFTAP=STA_LEAVE wlan0 wlan0 %02x:%02x:%02x:%02x:%02x:%02x",
        mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]); /* mac addr 0:1:2:3:4:5 */
    kobject_uevent_env(&(net_device->dev.kobj), KOBJ_CHANGE, g_env.envp);
#else
    hi_unref_param(net_device);
    hi_unref_param(mac_addr);
#endif /*#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)*/
}

hi_void oal_cfg80211_mgmt_tx_status(
#if (LINUX_VERSION_CODE >= kernel_version(3, 10, 0))|| (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
                                    oal_wireless_dev *wdev,
#else
                                    oal_net_device_stru *pst_net_dev,
#endif
                                    hi_u64 cookie,
                                    const hi_u8 *buf,
                                    size_t               len,
                                    hi_u8  ack,
                                    oal_gfp_enum_uint8   gfp)

{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_unref_param(cookie);
    hi_unref_param(gfp);
    cfg80211_mgmt_tx_status(wdev, buf, len, ack);
#elif (LINUX_VERSION_CODE >= kernel_version(3, 10, 0))
    cfg80211_mgmt_tx_status(wdev, cookie, buf, len, ack, gfp);
#else   /* linux vs 3.4.5 */
    cfg80211_mgmt_tx_status(pst_net_dev, cookie, buf, len, ack, gfp);
#endif
}

/*****************************************************************************
 ��������  : �ϱ�ɨ����ɽ��
*****************************************************************************/
hi_void oal_cfg80211_scan_done(oal_cfg80211_scan_request_stru *pst_cfg80211_scan_request, hi_s8 c_aborted)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(4, 8, 0))
    oal_cfg80211_scan_info_stru scan_info = { .aborted = c_aborted };
    cfg80211_scan_done(pst_cfg80211_scan_request, &scan_info);
#else
    cfg80211_scan_done(pst_cfg80211_scan_request, c_aborted);
#endif
#else /* (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */
    if (pst_cfg80211_scan_request != HI_NULL) {
        cfg80211_scan_done(pst_cfg80211_scan_request->dev, (hisi_scan_status_enum)c_aborted);
    }
#endif
}

/*****************************************************************************
 ��������  : STA�ϱ�����������ṹ��
*****************************************************************************/
hi_u32 oal_cfg80211_connect_result(oal_net_device_stru *net_device, const oal_connet_result_stru *connect_result)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    cfg80211_connect_result(net_device, connect_result->auc_bssid, connect_result->puc_req_ie,
                            connect_result->req_ie_len, connect_result->puc_rsp_ie, connect_result->rsp_ie_len,
                            connect_result->us_status_code, GFP_ATOMIC);
#else
    cfg80211_connect_result(net_device, connect_result);
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : STA�ϱ����ں�ȥ�������
*****************************************************************************/
hi_u32 oal_cfg80211_disconnected(oal_net_device_stru    *pst_net_device,
                                 hi_u16                  us_reason,
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) && (LINUX_VERSION_CODE < kernel_version(3, 18, 0))
                                 hi_u8            *puc_ie,
#else
                                 const hi_u8            *puc_ie,
#endif
                                 hi_u32                  ul_ie_len,
                                 hi_bool                 locally_generated)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(3, 18, 0))
    cfg80211_disconnected(pst_net_device, us_reason, puc_ie, ul_ie_len, locally_generated, GFP_ATOMIC);
#else
    hi_unref_param(locally_generated);
    cfg80211_disconnected(pst_net_device, us_reason, puc_ie, ul_ie_len, GFP_ATOMIC);
#endif
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    cfg80211_disconnected(pst_net_device, us_reason, puc_ie, ul_ie_len);
    hi_unref_param(locally_generated);
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : AP�ϱ�ȥ����ĳ��STA���
*****************************************************************************/
hi_u32  oal_cfg80211_del_sta(oal_net_device_stru *net_device,
                             const hi_u8      *mac_addr,
                             hi_u8             addr_len,
                             oal_gfp_enum_uint8    en_gfp)
{
    hi_unref_param(addr_len);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    cfg80211_del_sta(net_device, mac_addr, en_gfp);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    cfg80211_del_sta(net_device, mac_addr, WLAN_MAC_ADDR_LEN);
    hi_unref_param(en_gfp);
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : AP�ϱ��¹���ĳ��STA���
*****************************************************************************/
hi_u32 oal_cfg80211_new_sta(oal_net_device_stru     *net_device,
                            const hi_u8         *mac_addr,
                            hi_u8                addr_len,
                            oal_station_info_stru   *station_info,
                            oal_gfp_enum_uint8      en_gfp)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    cfg80211_new_sta(net_device, mac_addr, station_info, en_gfp);
    hi_unref_param(addr_len);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    cfg80211_new_sta(net_device, mac_addr, addr_len, station_info);
    hi_unref_param(en_gfp);
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ϱ�mic����
*****************************************************************************/
hi_void oal_cfg80211_mic_failure(oal_net_device_stru     *net_device,
                                 const hi_u8         *mac_addr,
                                 enum nl80211_key_type    key_type,
                                 hi_s32               key_id,
                                 const hi_u8         *tsc,
                                 oal_gfp_enum_uint8       en_gfp)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    cfg80211_michael_mic_failure(net_device, mac_addr, key_type, key_id, tsc, en_gfp);
#else
    hi_unref_param(net_device);
    hi_unref_param(mac_addr);
    hi_unref_param(key_type);
    hi_unref_param(key_id);
    hi_unref_param(tsc);
    hi_unref_param(en_gfp);
#endif
}

/*****************************************************************************
 ��������  : �ϱ����յ��Ĺ���֡
*****************************************************************************/
hi_u32 oal_cfg80211_rx_mgmt(oal_net_device_stru *pst_dev,
                            hi_s32               l_freq,
                            const hi_u8        *puc_buf,
                            hi_u32              ul_len,
                            oal_gfp_enum_uint8      en_gfp)
{
    oal_wireless_dev   *pst_wdev = HI_NULL;
    pst_wdev = pst_dev->ieee80211_ptr;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    cfg80211_rx_mgmt(pst_wdev, l_freq, 0, puc_buf, ul_len, en_gfp);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    cfg80211_rx_mgmt(pst_wdev->netdev, l_freq, 0, puc_buf, (size_t)ul_len);
    hi_unref_param(en_gfp);
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
�ϱ��ں�bss��Ϣ
*****************************************************************************/
oal_cfg80211_bss_stru *oal_cfg80211_inform_bss_frame(oal_wiphy_stru              *pst_wiphy,
                                                     oal_ieee80211_channel_stru  *pst_ieee80211_channel,
                                                     oal_ieee80211_mgmt_stru     *pst_mgmt,
                                                     hi_u32                       ul_len,
                                                     hi_s32                       l_signal,
                                                     oal_gfp_enum_uint8           en_ftp)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return cfg80211_inform_bss_frame(pst_wiphy, pst_ieee80211_channel, pst_mgmt, ul_len, l_signal, en_ftp);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_unref_param(pst_wiphy);
    hi_unref_param(pst_ieee80211_channel);
    hi_unref_param(pst_mgmt);
    hi_unref_param(ul_len);
    hi_unref_param(l_signal);
    hi_unref_param(en_ftp);
    return NULL;
#endif
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_void oal_cfg80211_put_bss(oal_wiphy_stru *pst_wiphy, oal_cfg80211_bss_stru *pst_cfg80211_bss)
{
    cfg80211_put_bss(pst_wiphy, pst_cfg80211_bss);
}
#endif

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

