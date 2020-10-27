/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Receive the message reported by the driver and report it to the kernel.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_ext_if.h"
#include "wal_main.h"
#include "wal_scan.h"
#include "wal_cfg80211.h"
#include "wal_ioctl.h"
#include "wal_hipriv.h"
#include "wal_linux_flowctl.h"
#include "wal_cfg80211_apt.h"
#include "wal_net.h"
#ifdef _PRE_WLAN_FEATURE_ANY
#include "hmac_any.h"
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
#include "hmac_p2p.h"
#endif
#ifdef _PRE_WLAN_FEATURE_CSI
#include "hi_wifi_api.h"
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
#include "dmac_config.h"
#endif
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
#include "plat_firmware.h"
#endif

#include "hi_wifi_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_CSI
hi_wifi_csi_data_cb             g_csi_data_func;
hi_u32                          g_csi_tsf_tmp = 0;    /* �洢�����ϱ���CSI���ݵ�ʱ�������������һ��ʱ����Ƚ� */
hi_u32                          g_csi_tsf_val = 0;    /* �洢�ϱ���CSI���ݵ�ʱ�����ת���� */
#endif

hi_wifi_report_tx_params_callback g_wal_report_tx_params_callback = HI_NULL;

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
hi_u32 wal_scan_result_clean_timeout_fn(hi_void *arg)
{
    hi_u32 ret;
    wal_msg_write_stru  write_msg;

    oal_net_device_stru *netdev = (oal_net_device_stru *)arg;
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CLEAN_SCAN_RESULT, sizeof(hi_u32));
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_scan_result_clean_timeout_fn::return err code [%u]!}", ret);
    }

    return ret;
}

/*****************************************************************************
 �� �� ��  : wal_scan_comp_proc_sta
 ��������  : STA�ϱ�ɨ������¼�����
 �������  : event_mem: �¼��ڴ�
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��7��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2013��9��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ϱ��ں˲��ֺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_scan_comp_proc_sta(frw_event_mem_stru *event_mem)
{
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{wal_scan_comp_proc_sta::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_stru      *event  = (frw_event_stru *)event_mem->puc_data;
    oal_net_device_stru *netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC, "{wal_scan_comp_proc_sta::get net device ptr null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡhmac vap�ṹ�� */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (hmac_vap == HI_NULL) {
        oam_warning_log0(event->event_hdr.vap_id, OAM_SF_SCAN, "{wal_scan_comp_proc_sta::pst_hmac_vap is NULL!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ɾ���ȴ�ɨ�賬ʱ��ʱ�� */
    if (hmac_vap->scan_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(hmac_vap->scan_timeout));
    }

    /* ��ȡhmac device ָ�� */
    hmac_device_stru *hmac_dev  = hmac_get_device_stru();
    mac_device_stru  *mac_dev   = mac_res_get_dev();
    hmac_scan_stru   *scan_mgmt = &(hmac_dev->scan_mgmt);

    /* �����Ƿ���ANYɨ�裬ɨ�����ʱ��Ҫ�ָ���־Ϊ��ǰ��ANYɨ�� */
    scan_mgmt->scan_record_mgmt.is_any_scan = HI_FALSE;

    /* ��ȡɨ�����Ĺ���ṹ��ַ */
    hmac_bss_mgmt_stru *bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);

    /* ��ȡ�����ϱ���ɨ�����ṹ��ָ�� */
    hmac_scan_rsp_stru *scan_rsp = (hmac_scan_rsp_stru *)event->auc_event_data;

    /* ���ɨ�践�ؽ���ķǳɹ�����ӡά����Ϣ */
    if (scan_rsp->result_code != HMAC_MGMT_SUCCESS) {
        oam_warning_log1(event->event_hdr.vap_id, OAM_SF_SCAN, "wal_scan_comp_proc_sta:Err=%d", scan_rsp->result_code);
    }

    /* ɨ��ɹ�ʱ�ϱ�����ɨ�赽��bss */
    if (scan_rsp->result_code == HMAC_MGMT_SUCCESS) {
        wal_inform_all_bss(netdev, mac_dev->wiphy, bss_mgmt, event->event_hdr.vap_id);
    }

    /* �����ں��·���ɨ��request��Դ���� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock(&(scan_mgmt->st_scan_request_spinlock));
#endif

    /* �ϲ��·�����ͨɨ����ж�Ӧ���� */
    if (scan_mgmt->request != HI_NULL)  {
        /* ֪ͨ kernel scan �Ѿ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        cfg80211_scan_done(netdev, HISI_SCAN_SUCCESS);
        wal_free_scan_mgmt_resource(scan_mgmt);
#else
        oal_cfg80211_scan_done(scan_mgmt->request, 0);
        scan_mgmt->request = HI_NULL;
#endif
        scan_mgmt->complete = HI_TRUE;
    }

    if (scan_mgmt->sched_scan_req != HI_NULL) {
        /* �ϱ�����ɨ���� */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_cfg80211_sched_scan_result(mac_dev->wiphy);
#endif
        scan_mgmt->sched_scan_req     = HI_NULL;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        scan_mgmt->sched_scan_complete = HI_TRUE;
#endif
    }

    /* ֪ͨ���ںˣ��ͷ���Դ����� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_unlock(&(scan_mgmt->st_scan_request_spinlock));
#endif

    /* ����ɨ����������ʱ�� */
    frw_timer_create_timer(&(hmac_vap->scanresult_clean_timeout), wal_scan_result_clean_timeout_fn,
                           WLAN_SCANRESULT_CLEAN_TIME, netdev, HI_FALSE);
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_asoc_comp_proc_sta
 ��������  : STA�ϱ���������¼�����
 �������  : event_mem: �¼��ڴ�
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��7��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_asoc_comp_proc_sta(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *event = HI_NULL;
    oal_connet_result_stru       connet_result;
    oal_net_device_stru         *netdev = HI_NULL;
    hmac_asoc_rsp_stru          *asoc_rsp = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_asoc_comp_proc_sta::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event     = (frw_event_stru *)event_mem->puc_data;
    asoc_rsp  = (hmac_asoc_rsp_stru *)event->auc_event_data;

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oal_free(asoc_rsp->puc_asoc_rsp_ie_buff);
        asoc_rsp->puc_asoc_rsp_ie_buff = HI_NULL;
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_asoc_comp_proc_sta::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (memset_s(&connet_result, sizeof(oal_connet_result_stru), 0, sizeof(oal_connet_result_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_asoc_comp_proc_sta::mem safe function err!}");
        oal_free(asoc_rsp->puc_asoc_rsp_ie_buff);
        asoc_rsp->puc_asoc_rsp_ie_buff = HI_NULL;
        return HI_FAIL;
    }
    /* ׼���ϱ��ں˵Ĺ�������ṹ�� */
    if (memcpy_s(connet_result.auc_bssid, WLAN_MAC_ADDR_LEN,
                 asoc_rsp->auc_addr_ap, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_asoc_comp_proc_sta::mem safe function err!}");
        oal_free(asoc_rsp->puc_asoc_rsp_ie_buff);
        asoc_rsp->puc_asoc_rsp_ie_buff = HI_NULL;
        return HI_FAIL;
    }
    connet_result.puc_req_ie       = asoc_rsp->puc_asoc_req_ie_buff;
    connet_result.req_ie_len    = asoc_rsp->asoc_req_ie_len;
    connet_result.puc_rsp_ie       = asoc_rsp->puc_asoc_rsp_ie_buff;
    connet_result.rsp_ie_len    = asoc_rsp->asoc_rsp_ie_len;
    connet_result.us_status_code   = asoc_rsp->status_code;
    connet_result.us_freq          = asoc_rsp->us_freq;
    connet_result.us_connect_status = asoc_rsp->result_code;

    /* �����ں˽ӿڣ��ϱ�������� */
    oal_cfg80211_connect_result(netdev, &connet_result);

    /* �ͷŹ�������֡�ڴ� */
    oal_mem_free(asoc_rsp->puc_asoc_req_ie_buff);
    oal_free(asoc_rsp->puc_asoc_rsp_ie_buff);
    asoc_rsp->puc_asoc_rsp_ie_buff = HI_NULL;

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_disasoc_comp_event_proc
 ��������  : STA�ϱ�ȥ��������¼�����
 �������  : event_mem: �¼��ڴ�
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��7��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_disasoc_comp_proc_sta(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *event = HI_NULL;
    oal_disconnect_result_stru   disconnect_result;
    oal_net_device_stru         *netdev = HI_NULL;
    hi_u32                      *pul_reason_code = HI_NULL;
    hi_u16                       us_disass_reason_code;
    hi_u16                       us_dmac_reason_code;
    hi_u32                       ret;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_disasoc_comp_proc_sta::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_disasoc_comp_proc_sta::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡȥ����ԭ����ָ�� */
    pul_reason_code = (hi_u32 *)event->auc_event_data;
    us_disass_reason_code = (*pul_reason_code)&0x0000ffff;
    us_dmac_reason_code = ((*pul_reason_code)>>16)&0x0000ffff; /* ����16λ */

    if (memset_s(&disconnect_result, sizeof(oal_disconnect_result_stru), 0,
        sizeof(oal_disconnect_result_stru)) != EOK) {
        return HI_FAIL;
    }
    hi_bool locally_generated = (us_dmac_reason_code == DMAC_DISASOC_MISC_KICKUSER);

    /* ׼���ϱ��ں˵Ĺ�������ṹ�� */
    disconnect_result.us_reason_code = us_disass_reason_code;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (!locally_generated && (us_disass_reason_code == WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY ||
        us_disass_reason_code == WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA ||
        us_disass_reason_code == WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA)) {
        disconnect_result.us_reason_code = 0;
    }
#endif
    /* �����ں˽ӿڣ��ϱ�ȥ������� */
    ret = oal_cfg80211_disconnected(netdev, disconnect_result.us_reason_code, disconnect_result.pus_disconn_ie,
                                    disconnect_result.us_disconn_ie_len, locally_generated);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_disasoc_comp_proc_sta::cfg80211_disconnected fail[%d]!}", ret);
        return ret;
    }

    oam_warning_log3(event->event_hdr.vap_id, OAM_SF_ASSOC,
        "{wal_disasoc_comp_proc_sta reason_code[%d] ,dmac_reason_code[%d], locally[%d]OK!}",
        us_disass_reason_code, us_dmac_reason_code, locally_generated);

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_connect_new_sta_proc_ap
 ��������  : �����ϱ��ں�bss�������¼�����һ��STA
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��9��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_connect_new_sta_proc_ap(frw_event_mem_stru *event_mem)
{
    hi_u8                 user_mac_addr[WLAN_MAC_ADDR_LEN] = {0};
    oal_station_info_stru station_info;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_connect_new_sta_proc_ap::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡnet_device */
    oal_net_device_stru *netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC, "{wal_connect_new_sta_proc_ap::netdev is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&station_info, sizeof(oal_station_info_stru), 0, sizeof(oal_station_info_stru));

    /* ���ں˱������˹�������֡��ie��Ϣ */
#if (LINUX_VERSION_CODE >= kernel_version(4, 0, 0))
        /* Linux 4.0 �汾����ҪSTATION_INFO_ASSOC_REQ_IES ��ʶ */
#else
    station_info.filled |=  STATION_INFO_ASSOC_REQ_IES;
#endif

    hmac_asoc_user_req_ie_stru *asoc_user_req_info = (hmac_asoc_user_req_ie_stru *)(event->auc_event_data);
    station_info.assoc_req_ies = asoc_user_req_info->puc_assoc_req_ie_buff;
    if (station_info.assoc_req_ies == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC, "{wal_connect_new_sta_proc_ap::asoc ie is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    station_info.assoc_req_ies_len = asoc_user_req_info->assoc_req_ie_len;

    /* ��ȡ����user mac addr */
    if (memcpy_s(user_mac_addr, WLAN_MAC_ADDR_LEN,
        (hi_u8 *)asoc_user_req_info->auc_user_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_connect_new_sta_proc_ap::mem safe function err!}");
        return HI_FAIL;
    }

    /* �����ں˽ӿڣ��ϱ�STA������� */
    hi_u32 ret = oal_cfg80211_new_sta(netdev, user_mac_addr, WLAN_MAC_ADDR_LEN, &station_info, GFP_ATOMIC);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_connect_new_sta_proc_ap::oal_cfg80211_new_sta fail[%d]!}", ret);
        return ret;
    }

    oam_warning_log3(event->event_hdr.vap_id, OAM_SF_ASSOC,
        "{wal_connect_new_sta_proc_ap mac[XX:XX:XX:%02X:%02X:%02X]}",
        user_mac_addr[3], user_mac_addr[4], user_mac_addr[5]); /* 3/4/5 MAC��ַλ�� */

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_disconnect_sta_proc_ap
 ��������  : �����ϱ��ں�bss������ɾ����һ��STA
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��9��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_disconnect_sta_proc_ap(frw_event_mem_stru *event_mem)
{
    frw_event_stru            *event = HI_NULL;
    oal_net_device_stru       *netdev = HI_NULL;
    hi_u8                      user_mac_addr[WLAN_MAC_ADDR_LEN] = {0};
    hi_u32                     ret;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_disconnect_sta_proc_ap::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_disconnect_sta_proc_ap::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȡȥ����user mac addr */
    if (memcpy_s(user_mac_addr, WLAN_MAC_ADDR_LEN,
        (hi_u8 *)event->auc_event_data, WLAN_MAC_ADDR_LEN) != EOK) { /* event->auc_event_data: �ɱ����� */
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_disconnect_sta_proc_ap::mem safe function err!}");
        return HI_FAIL;
    }
    /* �����ں˽ӿڣ��ϱ�STAȥ������� */
    ret = oal_cfg80211_del_sta(netdev, user_mac_addr, WLAN_MAC_ADDR_LEN, GFP_ATOMIC);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_disconnect_sta_proc_ap::cfg80211_del_sta fail[%d]}", ret);
        return ret;
    }

    oam_warning_log3(event->event_hdr.vap_id, OAM_SF_ASSOC,
        "{wal_disconnect_sta_proc_ap mac[XX:XX:XX:%02x:%02x:%02x]}",
        user_mac_addr[3], user_mac_addr[4], user_mac_addr[5]); /* 3 4 5 ����λ�� */

    return HI_SUCCESS;
}

hi_void wal_set_tpc_mode(oal_net_device_stru *netdev, hi_u32 mode)
{
    wal_msg_write_stru  write_msg;
    mac_ioctl_alg_param_stru *alg_param = (mac_ioctl_alg_param_stru *)(write_msg.auc_value);
    hi_u32 ret;

    alg_param->alg_cfg = MAC_ALG_CFG_TPC_MODE;
    alg_param->is_negtive = HI_FALSE;
    alg_param->value = mode;

    /* ���¼���wal�㴦�� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_param_stru));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_at_set_tpc::wal_send_cfg_event return err code [%u]!}", ret);
        return;
    }

    return;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 �� �� ��  : wal_mic_failure_proc
 ��������  : �����ϱ��ں�mic����
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2013��12��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_mic_failure_proc(frw_event_mem_stru *event_mem)
{
    frw_event_stru               *event = HI_NULL;
    oal_net_device_stru          *netdev = HI_NULL;
    hmac_mic_event_stru          *mic_event = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_CRYPTO, "{wal_mic_failure_proc::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event       = (frw_event_stru *)event_mem->puc_data;
    mic_event   = (hmac_mic_event_stru *)(event->auc_event_data);

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_CRYPTO,
            "{wal_mic_failure_proc::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �����ں˽ӿڣ��ϱ�mic���� */
    oal_cfg80211_mic_failure(netdev, mic_event->auc_user_mac, mic_event->key_type, mic_event->l_key_id,
                             HI_NULL, GFP_ATOMIC);

    oam_warning_log3(event->event_hdr.vap_id, OAM_SF_CRYPTO, "{wal_mic_failure_proc::mac[%x %x %x] OK!}",
                     mic_event->auc_user_mac[3], mic_event->auc_user_mac[4], /* 3 4 ����λ�� */
                     mic_event->auc_user_mac[5]); /* 5 ����λ�� */

    return HI_SUCCESS;
}
#endif
/*****************************************************************************
 �� �� ��  : wal_send_mgmt_to_host
 ��������  : �����ϱ��ں˽��յ�����֡
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2014��5��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_send_mgmt_to_host(frw_event_mem_stru *event_mem)
{
    frw_event_stru               *event = HI_NULL;
    oal_net_device_stru          *netdev = HI_NULL;
    hi_s32                     l_freq;
    hi_u8                    *puc_buf = HI_NULL;
    hi_u16                    us_len;
    hi_u8                    ret;
    hmac_rx_mgmt_event_stru      *mgmt_frame = HI_NULL;
    oal_ieee80211_mgmt           *ieee80211_mgmt = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_send_mgmt_to_host::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event       = (frw_event_stru *)event_mem->puc_data;
    mgmt_frame  = (hmac_rx_mgmt_event_stru *)(event->auc_event_data);

    /* ��ȡnet_device */
    netdev = oal_get_netdev_by_name(mgmt_frame->ac_name);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ANY, "{wal_send_mgmt_to_host::get net device ptr is null!}");
        oal_free(mgmt_frame->puc_buf);
        return HI_ERR_CODE_PTR_NULL;
    }
    oal_dev_put(netdev);

    puc_buf = mgmt_frame->puc_buf;
    us_len  = mgmt_frame->us_len;
    l_freq  = mgmt_frame->l_freq;

    ieee80211_mgmt = (oal_ieee80211_mgmt *)puc_buf;
    /* �����ں˽ӿڣ��ϱ����յ�����֡ */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    ret = cfg80211_rx_mgmt(netdev, l_freq, 0, puc_buf, us_len);
#else
    ret = oal_cfg80211_rx_mgmt(netdev, l_freq, puc_buf, us_len, GFP_ATOMIC);
#endif
    if (ret != HI_TRUE) {
        oam_warning_log2(event->event_hdr.vap_id, OAM_SF_ANY, "{wal_send_mgmt_to_host::fc[0x%04x], if_type[%d]!}",
                         ieee80211_mgmt->frame_control, netdev->ieee80211_ptr->iftype);
        oam_warning_log3(event->event_hdr.vap_id, OAM_SF_ANY,
            "{wal_send_mgmt_to_host::cfg80211_rx_mgmt_ext fail[%d]!len[%d], freq[%d]}",
                         ret, us_len, l_freq);
        oal_free(puc_buf);
        return HI_FAIL;
    }
    oam_info_log3(event->event_hdr.vap_id, OAM_SF_ANY,
        "{wal_send_mgmt_to_host::freq = %d, len = %d, TYPE[%04X] OK!}", l_freq, us_len,
        ieee80211_mgmt->frame_control);
    oal_free(puc_buf);
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_P2P
/*****************************************************************************
 �� �� ��  : wal_p2p_listen_timeout
 ��������  : HMAC�ϱ�������ʱ
 �������  : frw_event_mem_stru *event_mem
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2014��11��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_p2p_listen_timeout(frw_event_mem_stru *event_mem)
{
    frw_event_stru               *event              = HI_NULL;
    oal_wireless_dev             *wdev               = HI_NULL;
    hmac_p2p_listen_expired_stru *p2p_listen_expired = HI_NULL;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    mac_device_stru              *mac_dev         = HI_NULL;
    hi_u64                        ull_cookie;
#endif
    oal_ieee80211_channel_stru    listen_channel;
    hi_u32                        ret;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_P2P, "{wal_p2p_listen_timeout::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event = (frw_event_stru *)event_mem->puc_data;
    p2p_listen_expired = (hmac_p2p_listen_expired_stru *)(event->auc_event_data);

    wdev = p2p_listen_expired->wdev;
    listen_channel = p2p_listen_expired->st_listen_channel;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    /* ��ȡmac_device_stru */
    mac_dev = mac_res_get_dev();
    ull_cookie = mac_dev->p2p_info.ull_last_roc_id;
    cfg80211_remain_on_channel_expired(wdev, ull_cookie, &listen_channel, GFP_ATOMIC);
#endif
    /* �����ں˽ӿڣ��ϱ���������ʱ */
    ret = cfg80211_cancel_remain_on_channel(wdev->netdev, listen_channel.center_freq);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_P2P,
                       "{wal_p2p_listen_timeout!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 �� �� ��  : wal_mesh_close_peer_inform
 ��������  : MESH �����ϱ�Wpa ֪ͨ���ָ��Զ�˽ڵ㷢��ȡ���������
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :
 �޸���ʷ      :
  1.��    ��   : 2019��1��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_mesh_close_peer_inform(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    oal_net_device_stru *netdev = HI_NULL;
    hi_u32 *pul_reason_code = HI_NULL;
    hi_u16 us_disass_reason_code;
    hi_u16 us_dmac_reason_code;
    hi_u32 ret;
    hi_u8  user_mac_addr[WLAN_MAC_ADDR_LEN] = {0};

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_mesh_close_peer_inform::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_mesh_close_peer_inform::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȡ��ȥ�������û���Mac��ַ */
    if (memcpy_s(user_mac_addr, WLAN_MAC_ADDR_LEN,
        (hi_u8 *)event->auc_event_data, WLAN_MAC_ADDR_LEN) != EOK) { /* event->auc_event_data, �ɱ����� */
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_mesh_close_peer_inform::mem safe function err!}");
        return HI_FAIL;
    }
    /* ��ȡȥ����ԭ����ָ�� */
    pul_reason_code = (hi_u32 *)(event->auc_event_data + WLAN_MAC_ADDR_LEN); // �ɱ������÷���lin_t e416�澯����
    us_disass_reason_code = (*pul_reason_code)&0x0000ffff;
    us_dmac_reason_code = ((*pul_reason_code)>>16)&0x0000ffff; /* 16 ����16λ */

    /* �����ں˽ӿڣ��ϱ�ȥ������� */
    ret = cfg80211_mesh_close(netdev, user_mac_addr, WLAN_MAC_ADDR_LEN, us_disass_reason_code);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_mesh_close_peer_inform::oal_cfg80211_mesh_close fail[%d]!}", ret);
        return ret;
    }

    oam_warning_log2(event->event_hdr.vap_id, OAM_SF_ASSOC,
        "{wal_mesh_close_peer_inform reason_code[%d] ,dmac_reason_code[%d]OK!}",
        us_disass_reason_code, us_dmac_reason_code);

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : MESH �����ϱ�Wpa ֪ͨ�з��Ϲ���������Զ�˽ڵ�
 �������  : frw_event_mem_stru *event_mem
 �� �� ֵ  :hi_u32
 �޸���ʷ      :
  1.��    ��   : 2019��3��21��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_mesh_new_peer_candidate(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    oal_net_device_stru *netdev = HI_NULL;
    hi_u32 ret;
    hmac_report_new_peer_candidate_stru *puc_new_peer = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_mesh_new_peer_candidate::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;
    puc_new_peer = (hmac_report_new_peer_candidate_stru *)(event->auc_event_data);

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_mesh_new_peer_candidate::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* �����ں˽ӿڣ��ϱ�ȥ������� */
    ret = cfg80211_mesh_new_peer_candidate(netdev, puc_new_peer);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_ASSOC,
            "{wal_mesh_new_peer_candidate::wal_mesh_new_peer_candidate fail[%d]!}", ret);
        return ret;
    }

    oam_info_log2(event->event_hdr.vap_id, OAM_SF_ASSOC, "{wal_mesh_new_peer_candidate:: mac addr = %x:%x!}",
        puc_new_peer->auc_mac_addr[4], puc_new_peer->auc_mac_addr[5]); /* 4 5 ��ַλ�� */

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_ANY
/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
static hi_wifi_any_callback         g_any_callback = {HI_NULL, HI_NULL};
static hi_wifi_any_scan_result_cb   g_scan_ret_cb = HI_NULL;
static hi_wifi_any_peer_info        g_peer_info;
static hi_u8                        g_query_completed_flag = HI_FALSE;
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ע��ANY�豸�ӿڵı��ķ��ͺͽ��ջص�������֮ǰע����Ļᱻ�����滻��
 �������  : send_cb���û��������ķ��ͻص�����
             recv_cb���û��������Ľ��ջص�����
 �� �� ֵ  : hi_void

 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void wal_any_set_callback(hi_wifi_any_send_complete_cb send_cb, hi_wifi_any_recv_cb recv_cb)
{
    g_any_callback.send_cb = send_cb;
    g_any_callback.recv_cb = recv_cb;
    return;
}

/*****************************************************************************
 ��������  : ����ɨ�跢��ANY�Զ��豸��Ϣ������MAC��ַ���ŵ��ͽ��յ���cookie����Ϣ
 �������  : hi_wifi_any_scan_result_cb ɨ�����֮��Ľ���ص�������
 �� �� ֵ  : hi_void

 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void wal_any_set_scan_callback(hi_wifi_any_scan_result_cb cb)
{
    g_scan_ret_cb = cb;
    return;
}

/*****************************************************************************
 ��������  : ANY WAL������HMAC�㹫���ӿڣ�������������ʹ��
 �������  : wlan_cfgid_enum_uint16 ���ò���ö��ֵ
 �� �� ֵ  : HI_SUCCESS �ϱ��ɹ������������� �ϱ�ʧ��

 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_s32 wal_any_global_config(wlan_cfgid_enum_uint16 wid, oal_net_device_stru *netdev)
{
    wal_msg_write_stru            write_msg;
    hi_u32                        ret;

    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "{wal_any_global_config:pst_netdev is NULL, need to initialize ANY.}");
        return HI_FAIL;
    }
    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, wid, 0);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_any_global_config::return err code [%u]!}", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : �ϱ����յ�ANY֡�¼�����
 �������  : event_mem: �¼��ڴ�
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ�������ֵ
 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_any_process_rx_data(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *event = HI_NULL;
    oal_any_peer_param_stru     *peer_param = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_any_process_rx_data::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡANY�û����ݽṹ��ָ�� */
    peer_param = (oal_any_peer_param_stru *)event->auc_event_data;

    if (g_any_callback.recv_cb != HI_NULL) {
        /* ֱ�Ӳ����û�ע��Ľ��ջص��������д��� */
        g_any_callback.recv_cb(peer_param->auc_mac, peer_param->puc_data, peer_param->us_len, peer_param->seq_num);
    }

    /* �ͷ���HMAC������ڴ� */
    oal_mem_free(peer_param->puc_data);
    peer_param->puc_data = HI_NULL;
    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : �ϱ�ANY֡����״̬�¼�����
 �������  : event_mem: �¼��ڴ�
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ�������ֵ
 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32  wal_any_process_tx_complete(frw_event_mem_stru *event_mem)
{
    frw_event_stru          *event = HI_NULL;
    hi_u8                   *puc_data = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC, "{wal_any_process_tx_complete::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡ֡����״̬���� */
    puc_data = (hi_u8 *)event->auc_event_data;

    /* lin_t -e415 */ /* lin_t -e416 */
    if (g_any_callback.send_cb != HI_NULL) {
        /* ֱ�Ӳ����û�ע��ķ��ͻص��������д��� */ /* �ɱ������÷���lin_t e415/e416�澯���� */
        g_any_callback.send_cb(puc_data, puc_data[ETH_ALEN], puc_data[ETH_ALEN + 1]);
    }
    /* lin_t +e415 */ /* lin_t +e416 */

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : ���û��ϱ�ɨ�赽��ANY�豸��Ϣ
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ�������ֵ
 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_any_process_scan_result(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *event = HI_NULL;
    hmac_any_device_list_stru   *puc_data = HI_NULL;
    hi_u8                        loop;

    if (oal_unlikely(event_mem == HI_NULL)) {
            oam_error_log0(0, OAM_SF_ASSOC, "{wal_any_process_scan_result::event_mem is null!}");
            return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡ����ָ�� */
    puc_data = *((hmac_any_device_list_stru **)(event->auc_event_data));
    if ((puc_data == HI_NULL) || (puc_data->dev_list == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ASSOC,
            "{wal_any_process_scan_result::puc_data or pst_dev_list is null, not initialized}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (g_scan_ret_cb != HI_NULL) {
        /* ֱ�Ӳ����û�ע��Ļص��������д��� */
        if (puc_data->dev_num != 0) {
            g_scan_ret_cb(puc_data->dev_list, puc_data->dev_num);
        } else {
            g_scan_ret_cb(HI_NULL, 0);
        }
    }

    /* ����ϱ����ͷ�ɨ���� */
    for (loop = 0; loop < puc_data->dev_num; loop++) {
        if (puc_data->dev_list[loop] != HI_NULL) {
            oal_mem_free(puc_data->dev_list[loop]);
            puc_data->dev_list[loop] = HI_NULL;
        }
    }
    puc_data->dev_num = 0;

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : ���û��ϱ�ɨ�赽��ANY�豸��Ϣ
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ�������ֵ
 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_any_process_peer_info(frw_event_mem_stru *event_mem)
{
    frw_event_stru                  *event = HI_NULL;
    hmac_vap_stru                   *hmac_vap = HI_NULL;
    hi_wifi_any_peer_info           *peer_info = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_any_process_peer_info::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;
    hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_any_process_peer_info::pst_hmac_vap null.vap_id[%d]}",
            event->event_hdr.vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    peer_info = (hi_wifi_any_peer_info *)(event->auc_event_data);  /* event->auc_event_data, �ɱ����� */
    memcpy_s(&g_peer_info, sizeof(hi_wifi_any_peer_info), peer_info, sizeof(hi_wifi_any_peer_info));

    g_query_completed_flag = HI_TRUE;
    hi_wait_queue_wake_up_interrupt(&(hmac_vap->query_wait_q));

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ȴ�HMAC��DMAC���ز�ѯANY�Զ˵Ľ��
 �� �� ֵ  : �ɹ�����HI_SUCCESS�������ڻ�ʧ�ܷ�������ֵ

 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_any_wait_query_result(hmac_vap_stru *hmac_vap, hi_wifi_any_peer_info *peer)
{
    hi_u32                   ret;
    hi_u8                    auc_mac[ETH_ALEN] = {0};

    if (g_query_completed_flag == HI_FALSE) {
        memset_s(&g_peer_info, sizeof(hi_wifi_any_peer_info), 0, sizeof(hi_wifi_any_peer_info));

        ret = (hi_u32)hi_wait_event_timeout(hmac_vap->query_wait_q,
            (HI_TRUE == g_query_completed_flag), (5 * HZ)); /* 5 Ƶ��,��wifiĿ¼����꺯��,�󱨸澯,lin_t e26�澯���� */
        if (ret == 0) {
            oam_warning_log1(0, OAM_SF_ANY, "wal_any_wait_query_result: query temp timeout. ret:%d", ret);
            return HI_FAIL;
        }
    }

    /* ��ѯ��ȡ�����֮��ָ���false,������һ��ʹ�� */
    g_query_completed_flag = HI_FALSE;

    /* �ײ�������صĶԶ���ϢMAC��ַΪȫ0��Լ��Ϊ�Զ˲����� */
    if (memcmp(g_peer_info.mac, auc_mac, ETH_ALEN) == 0) {
        oam_warning_log0(0, OAM_SF_ANY, "wal_any_wait_query_result: peer does not exist!");
        return HI_FAIL;
    }

    memcpy_s(peer, sizeof(hi_wifi_any_peer_info), &g_peer_info, sizeof(hi_wifi_any_peer_info));
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_CSI
/*****************************************************************************
 ��������  : ��CSI�����ϱ�����
 �� �� ֵ  : ������
*****************************************************************************/
hi_s32 wal_csi_switch(hi_u8 switch_flag)
{
    oal_net_device_stru              *netdev = HI_NULL;
    wal_msg_write_stru                write_msg;
    hi_u32                            ret;

    netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_CSI, "{wal_csi_switch::pst_cfg_net_dev is null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    write_msg.auc_value[0] = switch_flag;

    /***************************************************************************
     ���¼���hmac�㴦��
     ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CSI_SWITCH, sizeof(hi_u8));
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_CSI, "{wal_csi_switch::wal_send_cfg_event return err code [%d].}",
                       ret);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����CSI�����ϱ��Ļص�����ָ�뵽WAL��Ļ�ȡ�������¼�ע�ắ��
 �޸���ʷ      :
  1.��    ��   : 2019��2��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void wal_csi_register_data_report_cb(hi_wifi_csi_data_cb func)
{
    g_csi_data_func = func;
}

/*****************************************************************************
 ��������  : CSI��������
 �޸���ʷ      :
  1.��    ��   : 2019��2��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_s32 wal_csi_set_config(const hi_char *ifname, hi_u32 report_min_interval,
                          const hi_wifi_csi_entry *entry_list, hi_s32 entry_num)
{
    wal_msg_write_stru            write_msg;
    mac_csi_config_stru           csi_config;
    hi_u8 idx = 0;

    for (idx = 0; idx < (hi_u8)entry_num; idx++) {
        /* �жϲ��������Ƿ���Ϸ�Χ(0---2^15)���ɲο�CSI�ϱ����ݸ�ʽ�ĵ� */
        if (entry_list->sample_period >= CSI_REPORT_PERIOD_BUTT) {
            oam_error_log1(0, OAM_SF_CSI, "{wal_csi_set_config::sample period of the %d entry is illegal.}", idx);
            return HI_FAIL;
        }
        /* �ж�֡�����Ƿ���Ϸ�Χ */
        if (entry_list->frame_type > (CSI_FRAME_TYPE_DATA | CSI_FRAME_TYPE_MGMT | CSI_FRAME_TYPE_CTRL)) {
            oam_error_log1(0, OAM_SF_CSI, "{wal_csi_set_config::frame_type of the %d entry is illegal.}", idx);
            return HI_FAIL;
        }
        if (memcpy_s(csi_config.ast_csi_param[idx].mac_addr, WLAN_MAC_ADDR_LEN,
                     entry_list->mac, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_CSI, "{wal_csi_set_config::memcpy_s mac addr err!}");
            return HI_FAIL;
        }
        csi_config.ast_csi_param[idx].sample_period = entry_list->sample_period;
        csi_config.ast_csi_param[idx].frame_type = entry_list->frame_type;
        entry_list++;
    }
    csi_config.entry_num = idx;
    csi_config.report_min_interval = report_min_interval;

    oal_net_device_stru *netdev = oal_get_netdev_by_name(ifname);
    if (netdev == HI_NULL) {
        oam_warning_buf(0, OAM_SF_CSI, "{wal_csi_set_config::ifname [%s] len [%d]is not found.}",
                        (hi_char *)ifname, strlen(ifname));
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȫ����淶 ����6.6 ����(1)�Թ̶����ȵ�������г�ʼ��,��Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(csi_config.resv, sizeof(csi_config.resv), 0, sizeof(csi_config.resv));
    /* ���ṹ������mac_csi_param_stru��䵽�¼���ȥ */
    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value),
        &csi_config, sizeof(mac_csi_config_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CSI, "{wal_csi_set_config::mem safe function err!}");
        return HI_FAIL;
    }
    /***************************************************************************
                                ���¼���hmac�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CSI_SET_CONFIG, sizeof(mac_csi_config_stru));
    hi_u32 send_event_ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
                                sizeof(mac_csi_config_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (send_event_ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_CSI, "{wal_csi_set_config::wal_send_cfg_event err code [%d]!}", send_event_ret);
        return (hi_s32)send_event_ret;
    }
    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : ����HAMC���׵�WAL����ϱ�CSI�����¼�
 �޸���ʷ      :
  1.��    ��   : 2019��2��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_csi_data_report(frw_event_mem_stru *event_mem)
{
    frw_event_stru            *event = HI_NULL;
    mac_csi_data_stru         *csi_report_data = HI_NULL;
    hi_u8                      auc_csi_data[OAL_CSI_DATA_BUFF_SIZE + OAL_CSI_TSF_SIZE];
    hi_u32                     tsf_tmp;

    event = (frw_event_stru *)event_mem->puc_data;
    csi_report_data = (mac_csi_data_stru *)event->auc_event_data;

    /* �������ʼ��Ϊ0��������δ��ʼ���Ӷ��������������Ӱ�� */
    if (memset_s(auc_csi_data, sizeof(auc_csi_data), 0, sizeof(auc_csi_data)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_csi_data_report::memset_s err!}");
        return HI_FAIL;
    }

    /* ȡ����dmac�ϱ���CSI���ݵ�ǰ4�ֽڵ�32λʱ����浽tmp�����У���ǿת���10����ʱ��� */
    tsf_tmp = (hi_u32)(((csi_report_data->csi_data[3] & 0xFF) << 24) | /* 3 ����λ�� 24 ����24λ */
                       ((csi_report_data->csi_data[2] & 0xFF) << 16) | /* 2 ����λ�� 16 ����16λ */
                       ((csi_report_data->csi_data[1] & 0xFF) << 8) |  /* 8 ����8λ */
                       (csi_report_data->csi_data[0] & 0xFF));
    /* �����λ�ȡ��32λʱ������ϴ�ʱ����Ƚϣ���С���ϴ�ʱ�����˵���߼��ϱ���ʱ�����ת���¼�ʱ��
     * ��ʱ����ǰ��1�������33λ��1
     */
    if (tsf_tmp < g_csi_tsf_tmp) {
        g_csi_tsf_val++;
    }
    /* g_csi_tsf_val����ͳ��ʱ�����ת���� */
    auc_csi_data[3] = (hi_u8)(g_csi_tsf_val >> 24); /* 3 ����λ�� 24 ����24λ */
    auc_csi_data[2] = (hi_u8)(g_csi_tsf_val >> 16); /* 2 ����λ�� 16 ����16λ */
    auc_csi_data[1] = (hi_u8)(g_csi_tsf_val >> 8);  /* 8 ����8λ */
    auc_csi_data[0] = (hi_u8)(g_csi_tsf_val);

    /* ������ʱ����ŵ�ȫ�ֱ������Ա��ں���һ���ϱ���ʱ����Ƚ� */
    g_csi_tsf_tmp = tsf_tmp;

    /* ��ԭ��dmac�ϱ���184�ֽ�ʱ���ƴ��4���ֽڣ�����188�ֽ����ݣ�����ʱ���Ϊƴ�Ӻ�����ݿ�ͷ8�ֽڣ�
     * ��ԭ��32λ��Ϊ64λ
     */
    if (memcpy_s(auc_csi_data + OAL_CSI_TSF_SIZE, OAL_CSI_DATA_BUFF_SIZE,
                 csi_report_data->csi_data, csi_report_data->data_len) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_csi_data_report::memcpy_s err!}");
        return HI_FAIL;
    }

    /* �����û��������ĺ����������͸��û�:�ϱ���csi���ݣ��ϱ������ݳ��� */
    if (g_csi_data_func != HI_NULL) {
        g_csi_data_func(auc_csi_data, (hi_s32)(csi_report_data->data_len + OAL_CSI_TSF_SIZE));
    }
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_P2P
/*****************************************************************************
 ��������  : ����HAMC���׵�WAL��ķ���ACTION֡�¼�
 �޸���ʷ      :
  1.��    ��   : 2019��8��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_p2p_action_tx_status(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *tx_status_event   = HI_NULL;
    mac_p2p_tx_status_stru      *p2p_tx_status     = HI_NULL;
    struct wireless_dev         *wdev              = HI_NULL;
    mac_vap_stru                *mac_vap           = HI_NULL;
    mac_vap_stru                *tmp_mac_vap       = HI_NULL;
    hi_u32                       netdev_index;
    oal_net_device_stru         *netdev   = HI_NULL;
    hi_u8                        is_get_net_device = HI_FALSE;
    hi_u32                       ret               = HI_FAIL;

    tx_status_event = (frw_event_stru *)event_mem->puc_data;
    p2p_tx_status = (mac_p2p_tx_status_stru *)tx_status_event->auc_event_data;

    mac_vap = mac_vap_get_vap_stru(tx_status_event->event_hdr.vap_id);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_CSI, "{wal_p2p_action_tx_status::mac_vap is null.}");
        return HI_FAIL;
    }

    /* ��ȡ����ǰ����ACTION֡��net_device */
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev = oal_get_past_net_device_by_index(netdev_index);
        if (netdev != HI_NULL && netdev->ml_priv != HI_NULL) {
            tmp_mac_vap = (mac_vap_stru *)netdev->ml_priv;
            if (mac_vap->vap_id == tmp_mac_vap->vap_id) {
                is_get_net_device = HI_TRUE;
                break;
            }
        }
    }

    if (is_get_net_device == HI_TRUE) {
        wdev = netdev->ieee80211_ptr; /* past_net_device�����ǿ�ָ�룬��lint,-g- lin_t !e613 */
        cfg80211_mgmt_tx_status(wdev, p2p_tx_status->puc_buf, p2p_tx_status->len, p2p_tx_status->ack);
        ret = HI_SUCCESS;
    }

    return ret;
}
#endif

/*****************************************************************************
 ��������  : ����HAMC���׵�WAL���MAC��ַ
*****************************************************************************/
hi_u32 wal_get_efuse_mac_from_dev(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    hi_u32 ret;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_get_efuse_mac_from_dev::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;
    ret = wal_set_dev_addr_from_efuse((const hi_char *)event->auc_event_data, WLAN_MAC_ADDR_LEN);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_TX, "{wal_get_efuse_mac_from_dev::set dev_addr fail!}");
    }

    return HI_SUCCESS;
}

hi_void wal_register_tx_params_callback(hi_wifi_report_tx_params_callback func)
{
    g_wal_report_tx_params_callback = func;
}

hi_u32 wal_report_tx_params(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    hi_wifi_report_tx_params *data;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_get_efuse_mac_from_dev::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;
    data = (hi_wifi_report_tx_params *)event->auc_event_data;

    if (g_wal_report_tx_params_callback == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    return g_wal_report_tx_params_callback(data);
}

#ifdef _PRE_WLAN_FEATURE_MFG_TEST
hi_u32 wal_get_dbg_cal_data_from_dev(frw_event_mem_stru *event_mem)
{
    frw_event_stru *event = HI_NULL;
    const hi_u8 data_strlen = 77; /* 77:�����ַ����ĳ��� */
    hi_char data_str[data_strlen];
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_get_efuse_mac_from_dev::event_mem is null!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(data_str, data_strlen, '\0', data_strlen);
    event  = (frw_event_stru *)event_mem->puc_data;
    hi_u32 *cal_data = (hi_u32 *)event->auc_event_data;
    if (snprintf_s(data_str, data_strlen, data_strlen - 1, "0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x",
        cal_data[0], /* 0:6������ֵ֮һ */
        cal_data[1], /* 1:6������ֵ֮һ */
        cal_data[2], /* 2:6������ֵ֮һ */
        cal_data[3], /* 3:6������ֵ֮һ */
        cal_data[4], /* 4:6������ֵ֮һ */
        cal_data[5], /* 5:6������ֵ֮һ */
        cal_data[6]) == -1) { /* 6:6������ֵ֮һ */
        printk("ERROR\r\n");
        return HI_FAIL;
    }
    /* д��wifi_cfg */
    if (firmware_write_cfg((hi_u8 *)WIFI_CFG_DBB_PARAMS, (hi_u8 *)data_str, data_strlen - 1) != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "wal_get_dbg_cal_data_from_dev:: save to wifi_cfg failed!");
        printk("ERROR\r\n");
        return HI_FAIL;
    }
    printk("OK\r\n");
    return HI_SUCCESS;
}
#endif

#ifdef FEATURE_DAQ
/*****************************************************************************
 ��������  : ����HAMC���׵�WAL�������״̬�¼�
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_data_acq_status(frw_event_mem_stru *event_mem)
{
    frw_event_stru                  *event = HI_NULL;
    hmac_vap_stru                   *hmac_vap = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::pst_hmac_vap null.vap_id[%d]}",
            event->event_hdr.vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_vap->acq_status_filter = *(hi_u8 *)(event->auc_event_data);
    hmac_vap->station_info_query_completed_flag = HI_TRUE;
    hi_wait_queue_wake_up_interrupt(&(hmac_vap->query_wait_q));

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : ����HAMC���׵�WAL������ɽ���¼�
 �޸���ʷ      :
  1.��    ��   : 2019��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_data_acq_result(frw_event_mem_stru *event_mem)
{
    wlan_acq_result_addr_stru       *data_result_addr = HI_NULL;
    hmac_vap_stru                   *hmac_vap = HI_NULL;
    frw_event_stru                  *event = HI_NULL;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;
    hmac_vap = hmac_vap_get_vap_stru(event->event_hdr.vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log1(0, OAM_SF_TX, "{wal_cfg80211_mgmt_tx_status::pst_hmac_vap null.vap_id[%d]}",
            event->event_hdr.vap_id);
        return HI_ERR_CODE_PTR_NULL;
    }

    data_result_addr = (wlan_acq_result_addr_stru *)(event->auc_event_data);

    hmac_vap->acq_result_addr.start_addr = data_result_addr->start_addr;
    hmac_vap->acq_result_addr.middle_addr1 = data_result_addr->middle_addr1;
    hmac_vap->acq_result_addr.middle_addr2 = data_result_addr->middle_addr2;
    hmac_vap->acq_result_addr.end_addr = data_result_addr->end_addr;

    hmac_vap->station_info_query_completed_flag = HI_TRUE;
    hi_wait_queue_wake_up_interrupt(&(hmac_vap->query_wait_q));

    return HI_SUCCESS;
}
#endif

#if (_PRE_MULTI_CORE_MODE != _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
/*****************************************************************************
 ��������  : ����HAMC���׵�WAL����ŵ��л��¼�
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_channel_switch_report(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *event = HI_NULL;
    oal_net_device_stru         *netdev = HI_NULL;
    hi_s32                      l_freq;

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_TX, "{wal_channel_switch_report::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    /* ��ȡnet_device */
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_TX,
            "{wal_channel_switch_report::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    l_freq = *(hi_s32 *)event->auc_event_data;

    /* �����ں˽ӿڣ��ϱ�ȥ������� */
    hi_u32 ret = cfg80211_csa_channel_switch(netdev, l_freq);
    if (ret != HI_SUCCESS) {
        oam_error_log1(event->event_hdr.vap_id, OAM_SF_TX,
            "{wal_channel_switch_report::cfg80211_disconnected fail[%d]!}\r\n", ret);
        return ret;
    }

    hi_diag_log_msg_i1(0, "{wal_channel_switch_report new channel_freq %d!}", (hi_u32)l_freq);

    return HI_SUCCESS;
}
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
