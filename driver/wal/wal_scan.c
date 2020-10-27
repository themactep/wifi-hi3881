/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Scan function associated with the kernel interface.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "wal_scan.h"
#include "wal_cfg80211.h"
#include "wal_main.h"
#include "wal_event.h"
#include "hmac_ext_if.h"
#include "frw_timer.h"
#include "wal_cfg80211_apt.h"
#include "hi_task.h"

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <net/cfg80211.h>
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifndef U64
 #define U64    UINT64
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_void wal_free_scan_mgmt_resource(hmac_scan_stru *scan_mgmt)
{
    if (scan_mgmt->request->ssids != HI_NULL) {
        free(scan_mgmt->request->ssids);
        scan_mgmt->request->ssids = HI_NULL;
    }
    if (scan_mgmt->request->ie != HI_NULL) {
        free(scan_mgmt->request->ie);
        scan_mgmt->request->ie = HI_NULL;
    }
    free(scan_mgmt->request);
    scan_mgmt->request = HI_NULL;
}
#endif

/*****************************************************************************
 �� �� ��  : wal_inform_bss_frame
 ��������  : ����ϱ�ssid��Ϣ���ں�
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void  wal_inform_bss_frame(const oal_net_device_stru   *netdev,
    wal_scanned_bss_info_stru *scanned_bss_info, hi_void *data)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_cfg80211_bss_stru        *cfg80211_bss = HI_NULL;
#endif
    oal_wiphy_stru               *wiphy = HI_NULL;
    oal_ieee80211_channel_stru   *ieee80211_channel = HI_NULL;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    struct timespec ts;
#endif

    if ((scanned_bss_info == HI_NULL) || (data == HI_NULL)) {
        oam_error_log2(0, OAM_SF_SCAN,
                       "{wal_inform_bss_frame::input param pointer is null, pst_scanned_bss_info[%p], p_data[%p]!}",
                       (uintptr_t)scanned_bss_info, (uintptr_t)data);
        return;
    }

    wiphy = (oal_wiphy_stru *)data;

    ieee80211_channel = oal_ieee80211_get_channel(wiphy, (hi_s32)scanned_bss_info->s_freq);
    if (ieee80211_channel == HI_NULL) {
        oam_warning_log1(0, OAM_SF_SCAN, "{wal_inform_bss_frame::get channel failed, wrong s_freq[%d]}",
                         (hi_s32)scanned_bss_info->s_freq);
        return;
    }

    scanned_bss_info->l_signal = scanned_bss_info->l_signal * 100; /* 100 ����100�� */

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/* ������������ɨ����������cts��֤2��ɨ���bss��timestampʱ��һ��(��һ��û��ɨ�赽) */
    get_monotonic_boottime(&ts);
    scanned_bss_info->mgmt->u.probe_resp.timestamp = ((hi_u64)ts.tv_sec * 1000000) /* 1000000 ʱ�����λת��Ϊs */
        + ts.tv_nsec / 1000; /* 1000 ʱ�����λת��Ϊs */
#endif
    /* ɨ��ά�� */
    oam_info_log3(0, OAM_SF_SCAN, "{wal_inform_bss_frame::bssid:0x%x:XX:XX:XX:0x%x:0x%x}",
        scanned_bss_info->mgmt->bssid[0], scanned_bss_info->mgmt->bssid[4], scanned_bss_info->mgmt->bssid[5]); /* 4 5 */

    /* ����ϱ��ں�bss ��Ϣ */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    cfg80211_inform_bss_frame(netdev, wiphy, ieee80211_channel, scanned_bss_info);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    cfg80211_bss = oal_cfg80211_inform_bss_frame(wiphy, ieee80211_channel, scanned_bss_info->mgmt,
                                                 scanned_bss_info->mgmt_len, scanned_bss_info->l_signal, GFP_ATOMIC);
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (cfg80211_bss != NULL) {
        /* cfg80211_put_bss(struct wiphy *wiphy, struct cfg80211_bss *pub) */
        oal_cfg80211_put_bss(wiphy, cfg80211_bss);
    }
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        /* liteos has no cfg80211_put_bss */
#endif

    return;
}

/*****************************************************************************
 �� �� ��  : wal_inform_all_bss
 ��������  : �ϱ����е�bss���ں�
 �������  : oal_wiphy_stru  *pst_wiphy,
             hmac_bss_mgmt_stru  *pst_bss_mgmt,
             hi_u8   uc_vap_id
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_inform_all_bss(const oal_net_device_stru *netdev, oal_wiphy_stru *wiphy,
                           hmac_bss_mgmt_stru *bss_mgmt, hi_u8 vap_id)
{
    hi_list                   *entry = HI_NULL;
    wal_scanned_bss_info_stru  scanned_bss_info;
    hi_u32                     bss_num_not_in_regdomain = 0;

#ifdef _PRE_WLAN_FEATURE_MESH
    mac_vap_stru *mac_vap = mac_vap_get_vap_stru(vap_id);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_inform_all_bss::mac_vap_get_vap_stru failed}");
        return;
    }
#else
    hi_unref_param(vap_id);
#endif
    /* ��ȡ�� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock(&(bss_mgmt->st_lock));
#endif
    /* ����ɨ�赽��bss��Ϣ */
    hi_list_for_each(entry, &(bss_mgmt->bss_list_head)) {
        hmac_scanned_bss_info *scanned_bss = hi_list_entry(entry, hmac_scanned_bss_info, dlist_head);
        hi_u8                  chan        = scanned_bss->bss_dscr_info.channel.chan_number;
        enum ieee80211_band    band        = (enum ieee80211_band)scanned_bss->bss_dscr_info.channel.band;

        /* �ж��ŵ��ǲ����ڹ������ڣ�������ڣ����ϱ��ں� */
        if (mac_is_channel_num_valid(band, chan) != HI_SUCCESS) {
            oam_warning_log2(vap_id, OAM_SF_SCAN, "{wal_inform_all_bss::chan=%d,band=%d not in regdomain}", chan, band);
            bss_num_not_in_regdomain++;
            continue;
        }

#ifdef _PRE_WLAN_FEATURE_ANY
        /* ֧��ANY���豸����ɨ���ʱ�򣬻��֧��ANY������STA�豸Ҳɨ�赽,��ʱ��ЩSTA��Ӧ���ϱ��ںˣ�ֻ�ϱ�AP */
        if ((scanned_bss->bss_dscr_info.supp_any == HI_TRUE) && (scanned_bss->bss_dscr_info.is_any_sta == HI_TRUE)) {
            continue;
        }
#endif

        /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
        memset_s(&scanned_bss_info, sizeof(wal_scanned_bss_info_stru), 0, sizeof(wal_scanned_bss_info_stru));
        scanned_bss_info.l_signal = scanned_bss->bss_dscr_info.rssi;

        /* ��bss�����ŵ�������Ƶ�� */
        scanned_bss_info.s_freq = (hi_s16)oal_ieee80211_channel_to_frequency(chan, band);

        /* �����ָ֡��ͳ��� */
        scanned_bss_info.mgmt     = (oal_ieee80211_mgmt_stru *)(scanned_bss->bss_dscr_info.auc_mgmt_buff);
        scanned_bss_info.mgmt_len = scanned_bss->bss_dscr_info.mgmt_len;

        /* ��ȡ�ϱ���ɨ�����Ĺ���֡��֡ͷ */
        mac_ieee80211_frame_stru *frame_hdr = (mac_ieee80211_frame_stru *)scanned_bss->bss_dscr_info.auc_mgmt_buff;

        /* ���ɨ��������յ���֡������beacon���ͣ�ͳһ�޸�Ϊprobe rsp�����ϱ���
           Ϊ�˽���ϱ��ں˵�ɨ����beacon֡�������е����⣬�����⣬��01���ֹ� */
        frame_hdr->frame_control.sub_type = (frame_hdr->frame_control.sub_type == WLAN_BEACON) ?
            WLAN_PROBE_RSP : frame_hdr->frame_control.sub_type;

        /* �ϱ�ɨ�������ں� */
        /* �����mesh ap�����ɨ�裬ֻ�ϱ�mesh ap */
#ifdef _PRE_WLAN_FEATURE_MESH
        if (((mac_vap->vap_mode == WLAN_VAP_MODE_MESH) && (scanned_bss->bss_dscr_info.is_hisi_mesh == HI_TRUE)) ||
            (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)) {
            wal_inform_bss_frame(netdev, &scanned_bss_info, wiphy);
        }
#else
        wal_inform_bss_frame(netdev, &scanned_bss_info, wiphy);
#endif
    }

    /* ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_unlock(&(bss_mgmt->st_lock));
#endif

    oam_warning_log2(vap_id, OAM_SF_SCAN, "{wal_inform_all_bss::%d bss not in regdomain,inform kernal bss num=%d}",
                     bss_num_not_in_regdomain, (bss_mgmt->bss_num - bss_num_not_in_regdomain));
}

/*****************************************************************************
 �� �� ��  : wal_free_scan_resource
 ��������  : �ͷ�������ŵ���Ϣ��Դ
 �������  : mac_cfg80211_scan_param_stru *
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void wal_free_scan_resource(mac_cfg80211_scan_param_stru *scan_param)
{
    if (scan_param->pul_channels_2_g != HI_NULL) {
        oal_free(scan_param->pul_channels_2_g);
        scan_param->pul_channels_2_g = HI_NULL;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (scan_param->puc_ie != HI_NULL) {
        oal_free((hi_u8 *)(scan_param->puc_ie));
        scan_param->puc_ie = HI_NULL;
    }
#endif
    oal_mem_free(scan_param);
}

/*****************************************************************************
 �� �� ��  : wal_set_scan_channel
 ��������  : ��ȡ�ں��·�ɨ���ŵ���ز���
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_set_scan_channel(const oal_cfg80211_scan_request_stru    *request,
                                    mac_cfg80211_scan_param_stru      *scan_param)

{
    hi_u32  loop;
    hi_u32  num_chan_2g = 0;

    if (request->n_channels == 0) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_get_scan_channel_num::channel number is 0 in scan request, is wrong!}");
        return HI_FAIL;
    }

    scan_param->pul_channels_2_g = (hi_u32 *)oal_memalloc(request->n_channels * sizeof(hi_u32));
    if (oal_unlikely(scan_param->pul_channels_2_g == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_scan_work_func::memory is too low, fail to alloc for 2.4G channel!}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    for (loop = 0; loop < request->n_channels; loop++) {
        hi_u16  us_center_freq;
        hi_u32  chn;

        us_center_freq = request->channels[loop]->center_freq;

        /* ��������Ƶ�ʣ������ŵ��� */
        chn = (hi_u32)oal_ieee80211_frequency_to_channel((hi_s32)us_center_freq);

        if (us_center_freq <= WAL_MAX_FREQ_2G) {
            scan_param->pul_channels_2_g[num_chan_2g++] = chn;
        }
    }

    scan_param->num_channels_2_g = (hi_u8)num_chan_2g;

    if (num_chan_2g == 0) {
        oal_free(scan_param->pul_channels_2_g);
        scan_param->pul_channels_2_g = HI_NULL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ɨ���SSID

 �޸���ʷ      :
  1.��    ��   : 2013��8��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void wal_set_scan_ssid(const oal_cfg80211_scan_request_stru *request,
    mac_cfg80211_scan_param_stru *scan_param)
{
    hi_u32   loop;
    hi_u32   index = 0;
    hi_u32   ssid_num;

    scan_param->l_ssid_num = 0;
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (request->prefix_ssid_scan_flag == HI_TRUE) {
        scan_param->l_ssid_num = request->n_ssids;
        return;
    }
#endif

    /* ȡ�ں��·���ssid�ĸ��� */
    ssid_num = (request->n_ssids > WLAN_SCAN_REQ_MAX_BSS) ? WLAN_SCAN_REQ_MAX_BSS : request->n_ssids;

    /* ���û��·���ssid��Ϣ��������Ӧ�Ľṹ���� */
    if ((ssid_num == 0) || (request->ssids == HI_NULL)) {
        return;
    }

    for (loop = 0; loop < ssid_num; loop++) {
        if (scan_param->ssids[index].ssid_len > OAL_IEEE80211_MAX_SSID_LEN) {
            oam_warning_log2(0, OAM_SF_SCAN, "{wal_set_scan_ssid::ssid length [%d] is larger than %d, skip it.}",
                             scan_param->ssids[loop].ssid_len, OAL_IEEE80211_MAX_SSID_LEN);
            continue;
        }
        scan_param->ssids[index].ssid_len = request->ssids[loop].ssid_len;
        if (memcpy_s(scan_param->ssids[index].auc_ssid, OAL_IEEE80211_MAX_SSID_LEN,
                     request->ssids[loop].ssid, scan_param->ssids[loop].ssid_len) != EOK) {
            oam_warning_log0(0, OAM_SF_SCAN, "{wal_set_scan_ssid::fail to copy ssid to scan_param, skip it!}");
            continue;
        }
        index++;
    }

    scan_param->l_ssid_num = index;
}

/*****************************************************************************
 ��������  : �ȴ�ɨ����ɳ�ʱ������

 �޸���ʷ      :
  1.��    ��   : 2015��5��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_wait_for_scan_timeout_fn(hi_void *arg)
{
    hmac_vap_stru                  *hmac_vap = (hmac_vap_stru *)arg;
    mac_vap_stru                   *mac_vap  = hmac_vap->base_vap;
    hmac_device_stru               *hmac_dev = HI_NULL;
    mac_device_stru                *mac_dev = HI_NULL;
    hmac_bss_mgmt_stru             *bss_mgmt = HI_NULL;
    hmac_scan_stru                 *scan_mgmt = HI_NULL;
    oal_wiphy_stru                 *wiphy = HI_NULL;
    oal_net_device_stru            *netdev = HI_NULL;

    oam_warning_log0(mac_vap->vap_id, OAM_SF_SCAN, "{wal_wait_for_scan_timeout_fn:: 5 seconds scan timeout proc.}");

    /* ���ݵ�ǰɨ������ͺ͵�ǰvap��״̬�������л�vap��״̬��ɨ���쳣�����У��ϱ��ں�ɨ��״̬Ϊɨ����� */
    if ((mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        (mac_vap->vap_state == MAC_VAP_STATE_STA_WAIT_SCAN)) {
        /* �ı�vap״̬��SCAN_COMP */
        mac_vap_state_change(mac_vap, MAC_VAP_STATE_STA_SCAN_COMP);
    }

    /* ��ȡhmac device */
    hmac_dev   = hmac_get_device_stru();
    mac_dev = mac_res_get_dev();
    scan_mgmt  = &(hmac_dev->scan_mgmt);
    wiphy      = mac_dev->wiphy;

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(mac_vap->vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ASSOC,
            "{wal_mesh_close_peer_inform::get net device ptr is null!}\r\n");
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        hi_task_lock();
        wal_free_scan_mgmt_resource(scan_mgmt);
        hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        scan_mgmt->request = HI_NULL;
#endif
        scan_mgmt->complete = HI_TRUE;
        scan_mgmt->is_scanning = HI_FALSE;
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡɨ�����Ĺ���ṹ��ַ */
    bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);

    /* �����ں��·���ɨ��request��Դ���� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock(&(scan_mgmt->st_scan_request_spinlock));
#endif

    if (scan_mgmt->request != HI_NULL) {
        /* �ϱ�ɨ�赽�����е�bss */
        wal_inform_all_bss(netdev, wiphy, bss_mgmt, mac_vap->vap_id);

        /* ֪ͨ kernel scan �Ѿ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        cfg80211_scan_done(netdev, HISI_SCAN_TIMEOUT);
        wal_free_scan_mgmt_resource(scan_mgmt);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_cfg80211_scan_done(scan_mgmt->request, 0);
        scan_mgmt->request = HI_NULL;
#endif
        scan_mgmt->complete = HI_TRUE;
        scan_mgmt->is_scanning = HI_FALSE;
    }

    /* ֪ͨ���ںˣ��ͷ���Դ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_unlock(&(scan_mgmt->st_scan_request_spinlock));
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_process_timer_for_scan
 ��������  : �ر�ɨ�����ϻ���ʱ��������ɨ�趨ʱ����ɨ�賬ʱ��������

 �޸���ʷ      :
  1.��    ��   : 2015��5��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_void  wal_process_timer_for_scan(hi_u8 vap_id)
{
    hmac_vap_stru           *hmac_vap = HI_NULL;

    /* ��ȡhmac vap */
    hmac_vap = hmac_vap_get_vap_stru(vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(vap_id, OAM_SF_SCAN, "{wal_process_timer_for_scan::pst_hmac_vap is null!}");
        return;
    }
    /* �ر�ɨ�����ϻ���ʱ�� */
    if (hmac_vap->scan_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->scanresult_clean_timeout));
    }
    /* ����ɨ�豣����ʱ������ָ��ʱ��û���ϱ�ɨ�����������ϱ�ɨ����� */
    frw_timer_create_timer(&(hmac_vap->scan_timeout), wal_wait_for_scan_timeout_fn,
                           WAL_MAX_SCAN_TIME_PER_SCAN_REQ, hmac_vap, HI_FALSE);

    return;
}

/*****************************************************************************
 �� �� ��  : wal_start_scan_req
 ��������  : �����ں��·�ɨ��������ز���������ɨ��
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_start_scan_req(oal_net_device_stru *netdev, hmac_scan_stru *scan_mgmt)
{
    mac_cfg80211_scan_param_stru *scan_param = HI_NULL;
    hi_u32                        ret;
    mac_vap_stru                 *mac_vap = oal_net_dev_priv(netdev);
    hi_u8                         vap_id = mac_vap->vap_id;
    oal_cfg80211_scan_request_stru *request = scan_mgmt->request;

    scan_param =
        (mac_cfg80211_scan_param_stru *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(mac_cfg80211_scan_param_stru));
    if (scan_param == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_start_scan_req::memory is too low, fail to alloc scan param memory!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(scan_param, sizeof(mac_cfg80211_scan_param_stru), 0, sizeof(mac_cfg80211_scan_param_stru));

    /* �����ں��·���ɨ���ŵ��б� */
    if (wal_set_scan_channel(request, scan_param) != HI_SUCCESS) {
        wal_free_scan_resource(scan_param);
        return HI_FAIL;
    }

    /* �����ں��·���ssid */
    wal_set_scan_ssid(request, scan_param);

    /* �����ں��·���ie,        Mesh IDЯ����IE���� */
    if ((request->ie_len > 0) && (request->ie != HI_NULL)) {
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        scan_param->puc_ie = (hi_u8 *)malloc(request->ie_len);
        if (oal_unlikely(scan_param->puc_ie == HI_NULL)) {
            oam_error_log0(0, OAM_SF_SCAN, "{wal_start_scan_req::memory is too low, fail to alloc for scan ie!}");
            wal_free_scan_resource(scan_param);
            return HI_FAIL;
        }

        if (memcpy_s((hi_void *)(scan_param->puc_ie), request->ie_len, request->ie, request->ie_len) != EOK) {
            oam_error_log0(0, OAM_SF_SCAN, "{wal_start_scan_req::fail to copy scan ie, return!}");
            wal_free_scan_resource(scan_param);
            return HI_FAIL;
        }
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        scan_param->puc_ie = request->ie;
#endif

        scan_param->ie_len = request->ie_len;
    } else {
        scan_param->puc_ie = HI_NULL;
        scan_param->ie_len = 0;
    }

    scan_param->scan_type = OAL_ACTIVE_SCAN; /* active scan */

    /* P2P WLAN/P2P ��������£�����ɨ���ssid �ж��Ƿ�Ϊp2p device �����ɨ�裬
     * ssid Ϊ"DIRECT-"����Ϊ��p2p device �����ɨ������·�ɨ���device �Ƿ�Ϊp2p device(p2p0)
     */
    if (is_p2p_scan_req(request)) {
        scan_param->is_p2p0_scan = HI_TRUE;
    }

    /* ���¼�ǰ��ֹ�첽�������ɨ���,����ͬ������ */
    scan_mgmt->complete = HI_FALSE;

    /* ���¼���֪ͨ��������ɨ�� */
    ret = wal_cfg80211_start_req(netdev, &scan_param, sizeof(uintptr_t), WLAN_CFGID_CFG80211_START_SCAN, HI_TRUE);
    if (ret != HI_SUCCESS) {
        wal_free_scan_resource(scan_param);
        oal_cfg80211_scan_done(scan_mgmt->request, 0);
        scan_mgmt->complete = HI_TRUE;
        return HI_FAIL;
    }
    wal_free_scan_resource(scan_param);
    /* �ر�ɨ�����ϻ���ʱ��,����ɨ�賬ʱ��ʱ�� */
    wal_process_timer_for_scan(vap_id);

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_send_scan_abort_msg
 ��������  : ��ֹɨ��
 �������  : oal_net_device_stru   *pst_net_dev
 �������  : ��
 �� �� ֵ  : hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_send_scan_abort_msg(oal_net_device_stru   *netdev)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          pedding_data = 0;       /* ������ݣ���ʹ�ã�ֻ��Ϊ�˸��ýӿ� */
    hi_u32                          ret;
    wal_msg_stru                    *rsp_msg = HI_NULL;

    /* ���¼�֪ͨdevice����ֹɨ�� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SCAN_ABORT, sizeof(pedding_data));

    if (memcpy_s(write_msg.auc_value, sizeof(pedding_data),
        (hi_s8 *)&pedding_data, sizeof(pedding_data)) != EOK) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_send_scan_abort_msg::mem safe function err!}");
        return HI_FAIL;
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(pedding_data),
                             (hi_u8 *)&write_msg,
                             HI_TRUE,
                             &rsp_msg);
    if (HI_SUCCESS != wal_check_and_release_msg_resp(rsp_msg)) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_send_scan_abort_msg::wal_check_and_release_msg_resp fail.}");
    }

    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_SCAN, "{wal_send_scan_abort_msg::fail to stop scan, error[%u]}", ret);
    }

    return ret;
}

/*************** **************************************************************
 �� �� ��  : wal_force_scan_complete
 ��������  : ֪ͨɨ�����
 �������  : oal_net_device_stru   *pst_net_dev,
             hi_bool          en_is_aborted
 �������  : ��
 �� �� ֵ  : hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_force_scan_complete(oal_net_device_stru *netdev)
{
    mac_device_stru *mac_dev = mac_res_get_dev();

    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_warning_log0(0, OAM_SF_SCAN, "{wal_force_scan_complete::Cannot find mac_vap by net_dev!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡhmac device */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    /* stop��vap������ɨ���vap����ͬ��ֱ�ӷ��� */
    if (mac_vap->vap_id != hmac_dev->scan_mgmt.scan_record_mgmt.vap_id) {
        oam_warning_log2(mac_vap->vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete::stop_vap[%d] is different scan_vap[%d]!}",
                         mac_vap->vap_id, hmac_dev->scan_mgmt.scan_record_mgmt.vap_id);
        return HI_SUCCESS;
    }

    hmac_scan_stru *scan_mgmt = &(hmac_dev->scan_mgmt);

    /* ����ɨ���ʱ�����ñ�־Ϊ��ANYɨ�� */
    scan_mgmt->scan_record_mgmt.is_any_scan = HI_FALSE;

    /* ����������ڲ���ɨ�� */
    if (scan_mgmt->request == HI_NULL) {
        /* �ж��Ƿ�����ڲ�ɨ�裬������ڣ�Ҳ��Ҫֹͣ */
        if ((hmac_dev->scan_mgmt.is_scanning == HI_TRUE) &&
            (mac_vap->vap_id == hmac_dev->scan_mgmt.scan_record_mgmt.vap_id)) {
            oam_warning_log0(mac_vap->vap_id, OAM_SF_SCAN, "{wal_force_scan_complete::maybe internal scan,stop scan}");
            /* ��ֹɨ�� */
            wal_send_scan_abort_msg(netdev);
        }

        return HI_SUCCESS;
    }

    /* ��ȡhmac vap */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log1(mac_vap->vap_id, OAM_SF_SCAN,
                         "{wal_force_scan_complete::hmac_vap is null, vap_id[%d]!}", mac_vap->vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ɾ���ȴ�ɨ�賬ʱ��ʱ�� */
    if (hmac_vap->scan_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->scan_timeout));
    }

    /* ������ϲ��·���ɨ��������֪ͨ�ں�ɨ��������ڲ�ɨ�費��֪ͨ */
    if (scan_mgmt->request != HI_NULL) {
        /* �����ں��·���ɨ��request��Դ���� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        hi_task_lock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_spin_lock(&(scan_mgmt->st_scan_request_spinlock));
#endif

        /* �ϱ��ں�ɨ���� */
        wal_inform_all_bss(netdev, mac_dev->wiphy, &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt), mac_vap->vap_id);

        /* ֪ͨ�ں�ɨ����ֹ */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        cfg80211_scan_done(netdev, HISI_SCAN_SUCCESS);
        wal_free_scan_mgmt_resource(scan_mgmt);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_cfg80211_scan_done(scan_mgmt->request, 0);
        scan_mgmt->request = HI_NULL;
#endif
        scan_mgmt->complete = HI_TRUE;
        /* ֪ͨ���ںˣ��ͷ���Դ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_spin_unlock(&(scan_mgmt->st_scan_request_spinlock));
#endif
        /* �·�device��ֹɨ�� */
        wal_send_scan_abort_msg(netdev);

        oam_info_log1(mac_vap->vap_id, OAM_SF_SCAN,
            "{wal_force_scan_complete::force to stop scan of vap_id[%d]}", mac_vap->vap_id);
    }

    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

