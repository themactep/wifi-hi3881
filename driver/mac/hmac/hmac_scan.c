/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Scan module hmac function.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oam_ext_if.h"
#include "mac_ie.h"
#include "mac_regdomain.h"
#include "mac_device.h"
#include "mac_resource.h"
#include "hmac_fsm.h"
#include "hmac_sme_sta.h"
#include "hmac_device.h"
#include "hmac_scan.h"
#include "hmac_mgmt_sta.h"
#include "hmac_mgmt_ap.h"
#include "frw_timer.h"
#include "hmac_chan_mgmt.h"
#include "hmac_event.h"
#include "hcc_hmac_if.h"
#include "wal_customize.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �����ڴ棬�洢ɨ�赽��bss��Ϣ
 �������  : hi_u32 ul_mgmt_len, �ϱ��Ĺ���֡�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_scanned_bss_info *hmac_scan_alloc_scanned_bss(hi_u32 mgmt_len)
{
    hmac_scanned_bss_info *scanned_bss = HI_NULL;

    /* �����ڴ棬�洢ɨ�赽��bss��Ϣ */
    scanned_bss = oal_memalloc(sizeof(hmac_scanned_bss_info) + mgmt_len -
                                   sizeof(scanned_bss->bss_dscr_info.auc_mgmt_buff));
    if (oal_unlikely(scanned_bss == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_SCAN,
                         "{hmac_scan_alloc_scanned_bss::alloc memory failed for storing scanned result.}");
        return HI_NULL;
    }

    /* ��ȫ��̹���6.6����(3)�Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(scanned_bss, sizeof(hmac_scanned_bss_info) + mgmt_len - sizeof(scanned_bss->bss_dscr_info.auc_mgmt_buff),
        0, sizeof(hmac_scanned_bss_info) + mgmt_len - sizeof(scanned_bss->bss_dscr_info.auc_mgmt_buff));

    /* ��ʼ������ͷ�ڵ�ָ�� */
    hi_list_init(&(scanned_bss->dlist_head));

    return scanned_bss;
}

/*****************************************************************************
 ��������  : ��ɨ�赽��bss��ӵ�����
 �������  : hmac_scanned_bss_info *pst_scanned_bss,        ����ӵ������ϵ�ɨ�赽��bss�ڵ�
             hmac_device_stru *pst_hmac_device,             hmac device�ṹ��
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_scan_add_bss_to_list(hmac_scanned_bss_info *scanned_bss, hmac_device_stru *hmac_dev)
{
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;   /* ����ɨ�����Ľṹ�� */

    bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);
    scanned_bss->bss_dscr_info.new_scan_bss = HI_TRUE;

    /* ������д����ǰ���� */
    oal_spin_lock(&(bss_mgmt->st_lock));

    /* ���ɨ�����������У�������ɨ�赽��bss���� */
    hi_list_tail_insert_optimize(&(scanned_bss->dlist_head), &(bss_mgmt->bss_list_head));

    bss_mgmt->bss_num++;
    /* ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));
}

/*****************************************************************************
 ��������  : ɾ��ɨ���������е�bss�ڵ�
 �������  : hmac_scanned_bss_info *pst_scanned_bss,        ��ɾ����ɨ�赽��bss�ڵ�
             hmac_device_stru *pst_hmac_device,             hmac device�ṹ��
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_scan_del_bss_from_list_nolock(hmac_scanned_bss_info *scanned_bss,
                                                  hmac_device_stru *hmac_dev)
{
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;   /* ����ɨ�����Ľṹ�� */

    bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);

    /* ��������ɾ���ڵ㣬������ɨ�赽��bss���� */
    hi_list_delete_optimize(&(scanned_bss->dlist_head));

    bss_mgmt->bss_num--;
}

/*****************************************************************************
 ��������  : ����ϴ�ɨ��������ص�ɨ���¼��Ϣ: ����ɨ�赽��bss��Ϣ�����ͷ��ڴ�ռ䡢�Լ�������Ϣ����
 �������  : hmac_scan_record_stru  *pst_scan_record
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_scan_clean_scan_record(hmac_scan_record_stru *scan_record)
{
    hi_list *entry = HI_NULL;
    hmac_scanned_bss_info *scanned_bss = HI_NULL;
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;

    /* �����Ϸ��Լ�� */
    if (scan_record == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_clean_scan_record::pst_scan_record is null.}");
        return;
    }

    /* 1.һ��Ҫ�����ɨ�赽��bss��Ϣ���ٽ������㴦�� */
    bss_mgmt = &(scan_record->bss_mgmt);

    /* ������д����ǰ���� */
    oal_spin_lock(&(bss_mgmt->st_lock));

    /* ��������ɾ��ɨ�赽��bss��Ϣ */
    while (HI_FALSE == hi_is_list_empty_optimize(&(bss_mgmt->bss_list_head))) {
        entry = hi_list_delete_head_optimize(&(bss_mgmt->bss_list_head));
        scanned_bss = hi_list_entry(entry, hmac_scanned_bss_info, dlist_head);

        bss_mgmt->bss_num--;

        /* �ͷ�ɨ���������ڴ� */
        oal_free(scanned_bss);
    }

    /* ������д����ǰ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));

    /* 2.������Ϣ���� */
    if (memset_s(scan_record, sizeof(hmac_scan_record_stru), 0, sizeof(hmac_scan_record_stru)) != EOK) {
        return;
    }
    scan_record->scan_rsp_status = MAC_SCAN_STATUS_BUTT; /* ��ʼ��ɨ�����ʱ״̬��Ϊ��Чֵ */

    /* 3.���³�ʼ��bss������������� */
    bss_mgmt = &(scan_record->bss_mgmt);
    hi_list_init(&(bss_mgmt->bss_list_head));

    oam_info_log0(0, OAM_SF_SCAN, "{hmac_scan_clean_scan_record::cleaned scan record success.}");

    return;
}

/*****************************************************************************
 ��������  : �ж�����bssid�����Ƿ��ǹ�����AP��bssid,���ڲ��ϻ��Ѿ�������AP
 �������  : hi_u8 auc_bssid[WLAN_MAC_ADDR_LEN]
 �� �� ֵ  : HI_TRUE:��,HI_FALSE:��
 �޸���ʷ      :
  1.��    ��   : 2016��1��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_s32 hmac_is_connected_ap_bssid(const hi_u8 auc_bssid[WLAN_MAC_ADDR_LEN])
{
    hi_u8 vap_idx;
    mac_vap_stru *mac_vap = HI_NULL;
    mac_device_stru *mac_dev = HI_NULL;

    mac_dev = mac_res_get_dev();
    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (oal_unlikely(mac_vap == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_P2P, "{hmac_is_connected_ap_bssid::mac_vap_get_vap_stru fail! vap id is %d}",
                             mac_dev->auc_vap_id[vap_idx]);
            continue;
        }
        if ((is_legacy_vap(mac_vap) && (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA)) &&
            ((mac_vap->vap_state == MAC_VAP_STATE_UP) || (mac_vap->vap_state == MAC_VAP_STATE_PAUSE))) {
            if (0 == memcmp(auc_bssid, mac_vap->auc_bssid, WLAN_MAC_ADDR_LEN)) {
                /* ���ϻ���ǰ������AP */
                oam_info_log3(mac_vap->vap_id, OAM_SF_SCAN,
                              "{hmac_is_connected_ap_bssid::connected AP bssid:XX:XX:XX:%02X:%02X:%02X}",
                              auc_bssid[3], auc_bssid[4], auc_bssid[5]); /* 3 4 5 Ԫ������ */

                return HI_TRUE;
            }
        }
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : ����ɨ��������ʱ������ϴ�ɨ�����е��ڵ�bss��Ϣ
 �������  : hmac_scan_record_stru  *pst_scan_record
 �޸���ʷ      :
  1.��    ��   : 2015��8��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_scan_clean_expire_scanned_bss(hmac_scan_record_stru *scan_record, hi_u8 clean_flag)
{
    hi_list *entry = HI_NULL;
    hi_list *entry_tmp = HI_NULL;
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;
    hmac_scanned_bss_info *scanned_bss = HI_NULL;
    mac_bss_dscr_stru *bss_dscr = HI_NULL;
    hi_u32 curr_time_stamp = 0;

    /* �����Ϸ��Լ�� */
    if (scan_record == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_clean_expire_scanned_bss::scan record is null.}");
        return;
    }

    /* ����ɨ���bss����Ľṹ�� */
    bss_mgmt = &(scan_record->bss_mgmt);

    if (clean_flag != HI_TRUE) {
        curr_time_stamp = (hi_u32) hi_get_milli_seconds();
    }
    /* ������д����ǰ���� */
    oal_spin_lock(&(bss_mgmt->st_lock));

    /* ��������ɾ����һ��ɨ�����е��ڵ�bss��Ϣ */
    hi_list_for_each_safe(entry, entry_tmp, &(bss_mgmt->bss_list_head)) {
        scanned_bss = hi_list_entry(entry, hmac_scanned_bss_info, dlist_head);
        bss_dscr = &(scanned_bss->bss_dscr_info);
        if (clean_flag != HI_TRUE) {
            if (curr_time_stamp - bss_dscr->timestamp < HMAC_SCAN_MAX_SCANNED_BSS_EXPIRE) {
                continue;
            }
        }
        /* ���ϻ���ǰ���ڹ�����AP */
        if (hmac_is_connected_ap_bssid(bss_dscr->auc_bssid)) {
            continue;
        }

        /* ��������ɾ���ڵ㣬������ɨ�赽��bss���� */
        hi_list_delete_optimize(&(scanned_bss->dlist_head));
        bss_mgmt->bss_num--;
        /* �ͷŶ�Ӧ�ڴ� */
        oal_free(scanned_bss);
    }
    /* ������д����ǰ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));

    return;
}

#ifdef _PRE_DEBUG_MODE
/*****************************************************************************
 ��������  : ����bss index���Ҷ�Ӧ��bss dscr�ṹ��Ϣ
 �������  : hi_u32 ul_bss_index,        bss    index
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
mac_bss_dscr_stru *hmac_scan_find_scanned_bss_dscr_by_index(hi_u32 bss_index)
{
    hi_list *entry = HI_NULL;
    hmac_scanned_bss_info *scanned_bss = HI_NULL;
    hmac_device_stru *hmac_dev = HI_NULL;
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;
    hi_u8 loop;

    /* ��ȡhmac device �ṹ */
    hmac_dev = hmac_get_device_stru();
    bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);

    /* ������ɾ����ǰ���� */
    oal_spin_lock(&(bss_mgmt->st_lock));

    /* ������������ܹ�ɨ���bss�����������쳣 */
    if (bss_index >= bss_mgmt->bss_num) {
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_find_scanned_bss_by_index::no such bss in bss list!}");

        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));
        return HI_NULL;
    }

    loop = 0;
    /* �����������ض�Ӧindex��bss dscr��Ϣ */
    hi_list_for_each(entry, &(bss_mgmt->bss_list_head)) {
        scanned_bss = hi_list_entry(entry, hmac_scanned_bss_info, dlist_head);

        /* ��ͬ��bss index���� */
        if (bss_index == loop) {
            /* ���� */
            oal_spin_unlock(&(bss_mgmt->st_lock));
            return &(scanned_bss->bss_dscr_info);
        }

        loop++;
    }
    /* ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));

    return HI_NULL;
}
#endif

/*****************************************************************************
 ��������  : ������ͬ��bssid��bss�Ƿ���ֹ�
 �������  : hi_u8 *puc_bssid,          bssid��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_scanned_bss_info *hmac_scan_find_scanned_bss_by_bssid(const hmac_bss_mgmt_stru *bss_mgmt, const hi_u8 *puc_bssid)
{
    hi_list *entry = HI_NULL;
    hmac_scanned_bss_info *scanned_bss = HI_NULL;

    /* �������������������Ƿ��Ѿ�������ͬbssid��bss��Ϣ */
    hi_list_for_each(entry, &(bss_mgmt->bss_list_head)) {
        scanned_bss = hi_list_entry(entry, hmac_scanned_bss_info, dlist_head);
        /* ��ͬ��bssid��ַ */
        if (0 == oal_compare_mac_addr(scanned_bss->bss_dscr_info.auc_bssid, puc_bssid, WLAN_MAC_ADDR_LEN)) {
            return scanned_bss;
        }
    }

    return HI_NULL;
}

#if defined (_PRE_WLAN_FEATURE_WPA2)
/*****************************************************************************
 ��������  : STA ���´� scan�� probe response ֡���յ���AP RSN��ȫ��Ϣ
 �������  : [1]bss_dscr
             [2]puc_ie
 �� �� ֵ  : static hi_u8
*****************************************************************************/
static hi_u8 hmac_scan_update_bss_list_rsn(mac_bss_dscr_stru *bss_dscr, const hi_u8 *puc_ie)
{
    hi_u8 auc_oui[MAC_OUI_LEN] = {MAC_WLAN_OUI_RSN0, MAC_WLAN_OUI_RSN1, MAC_WLAN_OUI_RSN2};

    /*************************************************************************/
    /*                  RSN Element Format                                   */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length | Version | Group Cipher Suite | Pairwise Cipher */
    /* --------------------------------------------------------------------- */
    /* |     1     |    1   |    2    |         4          |       2         */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Suite Count| Pairwise Cipher Suite List | AKM Suite Count | AKM Suite List */
    /* --------------------------------------------------------------------- */
    /*            |         4*m                |     2           |   4*n     */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* |RSN Capabilities|PMKID Count|PMKID List|Group Management Cipher Suite */
    /* --------------------------------------------------------------------- */
    /* |        2       |    2      |   16 *s  |               4           | */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(bss_dscr->bss_sec_info.auc_rsn_pairwise_policy, MAC_PAIRWISE_CIPHER_SUITES_NUM, 0xFF,
        MAC_PAIRWISE_CIPHER_SUITES_NUM);
    memset_s(bss_dscr->bss_sec_info.auc_rsn_auth_policy, MAC_AUTHENTICATION_SUITE_NUM, 0xFF,
        MAC_AUTHENTICATION_SUITE_NUM);

    /* ���� RSN IE �� IE ���� */
    hi_u8 index = MAC_IE_HDR_LEN;

    /* ��ȡRSN �汾�� */
    hi_u16 us_ver = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    if (us_ver != MAC_RSN_IE_VERSION) {
        oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rsn::invalid us_ver[%d].}", us_ver);
        return HI_FALSE;
    }

    /* ���� RSN �汾�ų��� */
    index += 2;  /* 2 ���� RSN �汾�ų��� */

    /* ��ȡ�鲥��Կ�׼� */
    if (memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN) != 0) {
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rsn::invalid RSN group OUI.}");
        return HI_FALSE;
    }
    bss_dscr->bss_sec_info.rsn_grp_policy = puc_ie[index + MAC_OUI_LEN];

    /* ���� �鲥��Կ�׼� ���� */
    index += 4; /* 4 �����鲥��Կ�׼����� */

    /* ��ȡ�ɶ���Կ�׼� */
    hi_u16 us_suite_count = 0;
    hi_u16 us_pcip_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    index += 2; /* ��������2 */
    for (hi_u16 suite_temp = 0; suite_temp < us_pcip_num; suite_temp++, index += 4) { /* 4 ���ڲ�ʶ��ĳɶ���Կ�׼������Ա��� */
        if (memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN) != 0) {
            oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rsn:invalid RSN paerwise OUI,ignore this ie}");
            /* ���ڲ�ʶ��ĳɶ���Կ�׼������Ա��� */
            continue;
        }

        if (us_suite_count >= MAC_PAIRWISE_CIPHER_SUITES_NUM) {
            oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa:ignore this ie,pcip_num:%d}", us_pcip_num);
        } else {
            /* �ɶ���Կ�׼������������Ϊ2���������ټ������� */
            bss_dscr->bss_sec_info.auc_rsn_pairwise_policy[us_suite_count++] = puc_ie[index + MAC_OUI_LEN];
        }
    }

    us_suite_count = 0;
    /* ��ȡ��֤�׼����� */
    hi_u16 us_auth_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    index += 2; /* ��������2 */
    /* ��ȡ��֤���� */
    for (hi_u16 us_temp = 0; us_temp < us_auth_num; us_temp++, index += 4) { /* 4 ���ڲ�ʶ���AKM�׼������Ա��� */
        if (0 != memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN)) {
            oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rsn::invalid RSN auth OUI,ignore this ie.}");
            /* ���ڲ�ʶ���AKM�׼������Ա��� */
            continue;
        } else if (us_suite_count < WLAN_AUTHENTICATION_SUITES) {
            /* AKM�׼������������Ϊ2���������ټ������� */
            bss_dscr->bss_sec_info.auc_rsn_auth_policy[us_suite_count++] = puc_ie[index + MAC_OUI_LEN];
        } else {
            oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa:ignore this ie,auth_num:%d}", us_auth_num);
        }
    }

    /* ��ȡ RSN ���� */
    bss_dscr->bss_sec_info.auc_rsn_cap[0] = *(puc_ie + index++);
    bss_dscr->bss_sec_info.auc_rsn_cap[1] = *(puc_ie + index++);

    /* ���� RSNA */
    bss_dscr->bss_sec_info.bss_80211i_mode |= DMAC_RSNA_802_11I;
    return HI_TRUE;
}
#endif

#if defined (_PRE_WLAN_FEATURE_WPA)
/*****************************************************************************
 ��������  : STA ���´� scan�� probe response ֡���յ���AP WPA ��ȫ��Ϣ
 �������  : [1]bss_dscr
             [2]puc_ie
 ����ֵ  : static hi_u8
*****************************************************************************/
static hi_u8 hmac_scan_update_bss_list_wpa(mac_bss_dscr_stru *bss_dscr, const hi_u8 *puc_ie)
{
    hi_u16 us_suite_count = 0;
    hi_u8 auc_oui[MAC_OUI_LEN] = {(hi_u8)MAC_WLAN_OUI_MICRO0, (hi_u8)MAC_WLAN_OUI_MICRO1, (hi_u8)MAC_WLAN_OUI_MICRO2};
    mac_bss_80211i_info_stru *bss_80211i_info = &(bss_dscr->bss_sec_info);

    /*************************************************************************/
    /*                  WPA Element Format                                   */
    /* --------------------------------------------------------------------- */
    /* |Element ID | Length |    WPA OUI    |  Version |  Group Cipher Suite */
    /* --------------------------------------------------------------------- */
    /* |     1     |   1    |        4      |     2    |         4           */
    /* --------------------------------------------------------------------- */
    /* --------------------------------------------------------------------- */
    /* Pairwise Cipher |  Pairwise Cipher   |                 |              */
    /* Suite Count     |    Suite List      | AKM Suite Count |AKM Suite List */
    /* --------------------------------------------------------------------- */
    /*        2        |          4*m       |         2       |     4*n      */
    /* --------------------------------------------------------------------- */
    /*                                                                       */
    /*************************************************************************/
    /* ���� WPA IE(1 �ֽ�) ��IE ����(1 �ֽ�) ��WPA OUI(4 �ֽ�)  */
    hi_u8 index = 2 + 4; /* 2 4 ���� WPA IE(1 �ֽ�) ��IE ����(1 �ֽ�) ��WPA OUI(4 �ֽ�)  */

    /* �Ա�WPA �汾��Ϣ */
    if (hi_makeu16(puc_ie[index], puc_ie[index + 1]) != MAC_WPA_IE_VERSION) {
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa::invalid WPA version.}");
        return HI_FALSE;
    }

    /* ���� �汾�� ���� */
    index += 2; /* 2 ���� �汾�� ���� */

    /* ��ȡ�鲥��Կ�׼� */
    if (0 != memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN)) {
        oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa::invalid WPA group OUI.}");
        return HI_FALSE;
    }
    bss_80211i_info->wpa_grp_policy = puc_ie[index + MAC_OUI_LEN];

    /* �����鲥��Կ�׼����� */
    index += 4; /* 4 �����鲥��Կ�׼����� */

    /* ��ȡ�ɶ���Կ�׼� */
    hi_u16 us_pcip_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    index += 2; /* ��������2 */
    for (hi_u16 suite_temp = 0; suite_temp < us_pcip_num; suite_temp++) {
        if (0 != memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN)) {
            oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa::invalid WPA pairwise OUI,ignore ie.}");
            /* ���ڲ�ʶ��ĳɶ���Կ�׼������Ա��� */
            index += 4; /* 4 ���ڲ�ʶ��ĳɶ���Կ�׼������Ա��� */
            continue;
        }
        if (us_suite_count < MAC_PAIRWISE_CIPHER_SUITES_NUM) {
            /* �ɶ���Կ�׼������������Ϊ2���������ټ������� */
            bss_80211i_info->auc_wpa_pairwise_policy[us_suite_count++] = puc_ie[index + MAC_OUI_LEN];
        } else {
            oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa::ignore ie,pcip_num:%d.}", us_pcip_num);
        }

        index += 4; /* ��������4 */
    }

    /* ��ȡ��֤�׼����� */
    hi_u16 us_auth_num = hi_makeu16(puc_ie[index], puc_ie[index + 1]);
    index += 2; /* ��������2 */
    /* ��ȡ��֤���� */
    us_suite_count = 0;
    for (hi_u16 us_temp = 0; us_temp < us_auth_num; us_temp++) {
        if (0 != memcmp(auc_oui, puc_ie + index, MAC_OUI_LEN)) {
            oam_warning_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa::invalid WPA auth OUI,ignore this ie.}");
            /* ���ڲ�ʶ���AKM�׼������Ա��� */
            index += 4; /* 4 ���ڲ�ʶ���AKM�׼������Ա��� */
            continue;
        } else if (us_suite_count >= WLAN_AUTHENTICATION_SUITES) {
            oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_wpa::ignore ie,us_auth_num:%d.}", us_auth_num);
        } else {
            /* AKM�׼������������Ϊ2���������ټ������� */
            bss_80211i_info->auc_wpa_auth_policy[us_suite_count++] = puc_ie[index + MAC_OUI_LEN];
        }
        index += 4; /* ��������4 */
    }

    /* ���� WPA */
    bss_dscr->bss_sec_info.bss_80211i_mode |= DMAC_WPA_802_11I;

    return HI_TRUE;
}
#endif

#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
/*****************************************************************************
 ��������  : STA ���´� scan�� probe response ֡���յ���AP ��ȫ��Ϣ
 �������  : [1]bss_dscr
             [2]puc_frame_body
             [3]us_frame_len
             [4]us_offset
 �� �� ֵ  : ��
*****************************************************************************/
static hi_void hmac_scan_update_bss_list_security(mac_bss_dscr_stru *bss_dscr, hi_u8 *puc_frame_body,
                                                  hi_u16 us_frame_len, hi_u16 us_offset)
{
    hi_u8 *puc_ie = HI_NULL;

    /* ��ȫ�����ϢԪ�� */
    /* ��յ�ǰ bss_info �ṹ�еİ�ȫ��Ϣ */
    if (memset_s(&(bss_dscr->bss_sec_info), sizeof(mac_bss_80211i_info_stru), 0xff,
                 sizeof(mac_bss_80211i_info_stru)) != EOK) {
        return;
    }
    bss_dscr->bss_sec_info.bss_80211i_mode = 0;
    bss_dscr->bss_sec_info.auc_rsn_cap[0] = 0;
    bss_dscr->bss_sec_info.auc_rsn_cap[1] = 0;

#if defined (_PRE_WLAN_FEATURE_WPA2)
    if (us_frame_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_RSN, puc_frame_body + us_offset, (us_frame_len - us_offset));
        if (puc_ie != HI_NULL) {
            /* ���´�beacon ���յ��� RSN ��ȫ�����Ϣ�� pst_bss_dscr �� */
            hmac_scan_update_bss_list_rsn(bss_dscr, puc_ie);
        }
    }
#endif

#if defined (_PRE_WLAN_FEATURE_WPA)
    puc_ie = mac_find_vendor_ie(MAC_WLAN_OUI_MICROSOFT, MAC_OUITYPE_WPA, puc_frame_body + us_offset,
                                (hi_s32)(us_frame_len - us_offset));
    if (puc_ie != HI_NULL) {
        /* ���´�beacon ���յ��� WPA ��ȫ�����Ϣ�� pst_bss_dscr �� */
        hmac_scan_update_bss_list_wpa(bss_dscr, puc_ie);
    }
#endif
}
#endif /* defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2) */

/*****************************************************************************
 ��������  : ����wmm�����Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��10��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_scan_update_bss_list_wmm(mac_bss_dscr_stru *bss_dscr,
                                             hi_u8 *puc_frame_body, hi_u16 us_frame_len)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 offset;

    offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    bss_dscr->wmm_cap = HI_FALSE;
    bss_dscr->uapsd_cap = HI_FALSE;

    puc_ie =
        mac_get_wmm_ie(puc_frame_body, us_frame_len, offset);
    if (puc_ie != HI_NULL) {
        bss_dscr->wmm_cap = HI_TRUE;

        /* Check if Bit 7 is set indicating U-APSD capability */
        if (puc_ie[8] & BIT7) { /* wmm ie�ĵ�8���ֽ���QoS info�ֽ� */
            bss_dscr->uapsd_cap = HI_TRUE;
        }
    } else {
        if (us_frame_len > offset) {
            puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_frame_body + offset, us_frame_len - offset);
            if (puc_ie != HI_NULL) {
                bss_dscr->wmm_cap = HI_TRUE;
            }
        }
    }
}

#ifdef _PRE_WLAN_FEATURE_11D
/*****************************************************************************
 ��������  : ����country IE
 �޸���ʷ      :
  1.��    ��   : 2013��10��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_scan_update_bss_list_country(mac_bss_dscr_stru *bss_dscr,
                                                 hi_u8 *puc_frame_body, hi_u16 us_frame_len)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 offset;

    offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    /* ������Ĭ�ϱ��Ϊ0 */
    bss_dscr->ac_country[0] = 0;
    bss_dscr->ac_country[1] = 0;
    bss_dscr->ac_country[2] = 0; /* ��2���ֽ� */

    if (us_frame_len > offset) {
        puc_ie = mac_find_ie(MAC_EID_COUNTRY, puc_frame_body + offset, us_frame_len - offset);
        if (puc_ie != HI_NULL) {
            bss_dscr->ac_country[0] = (hi_s8) puc_ie[MAC_IE_HDR_LEN];
            bss_dscr->ac_country[1] = (hi_s8) puc_ie[MAC_IE_HDR_LEN + 1];
            bss_dscr->ac_country[2] = 0; /* ��2���ֽ� */
        }
    }
}
#endif

/*****************************************************************************
 ��������  : ����11n�����Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��10��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_scan_update_bss_list_11n(mac_bss_dscr_stru *bss_dscr,
                                             hi_u8 *puc_frame_body,
                                             hi_u16 us_frame_len, hi_u16 us_offset)
{
    hi_u8 *puc_ie = HI_NULL;
    mac_ht_opern_stru *ht_op = HI_NULL;
    hi_u8 sec_chan_offset;
    wlan_bw_cap_enum_uint8 ht_cap_bw = WLAN_BW_CAP_20M;
    wlan_bw_cap_enum_uint8 ht_op_bw = WLAN_BW_CAP_20M;

    /* 11n */
    if (us_frame_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_HT_CAP, puc_frame_body + us_offset, us_frame_len - us_offset);
        if ((puc_ie != HI_NULL) && (puc_ie[1] >= 2)) { /* ����ie�����쳣��� 2: ��2�Ƚ� */
            /* puc_ie[2]��HT Capabilities Info�ĵ�1���ֽ� */
            bss_dscr->ht_capable = HI_TRUE; /* ֧��ht */
            bss_dscr->ht_ldpc = (puc_ie[2] & BIT0);  /* ֧��ldpc 2: �����±� */
            ht_cap_bw = ((puc_ie[2] & BIT1) >> 1);       /* ȡ��֧�ֵĴ��� 2: �����±� */
            bss_dscr->ht_stbc = ((puc_ie[2] & BIT7) >> 7); /* ֧��stbc 2: �����±�,����7λ */
        }
    }

    /* Ĭ��20M,���֡����δЯ��HT_OPERATION�����ֱ�Ӳ���Ĭ��ֵ */
    bss_dscr->channel_bandwidth = WLAN_BAND_WIDTH_20M;

    if (us_frame_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_HT_OPERATION, puc_frame_body + us_offset, us_frame_len - us_offset);
    }
    if ((puc_ie != HI_NULL) && (puc_ie[1] >= 2)) {  /* ����ie�����쳣��� 2: ��2�Ƚ� */
        ht_op = (mac_ht_opern_stru *)(puc_ie + MAC_IE_HDR_LEN);

        /* ��ȡ���ŵ�ƫ�� */
        sec_chan_offset = ht_op->secondary_chan_offset;

        /* ��ֹap��channel width=0, ��channel offset = 1����3 ��ʱ��channel widthΪ�� */
        /* ht cap 20/40 enabled && ht operation 40 enabled */
        if ((ht_op->sta_chan_width != 0) && (ht_cap_bw > WLAN_BW_CAP_20M)) {  /* cap > 20M��ȡchannel bw */
            if (sec_chan_offset == MAC_SCB) {
                bss_dscr->channel_bandwidth = WLAN_BAND_WIDTH_40MINUS;
                ht_op_bw = WLAN_BW_CAP_40M;
            } else if (sec_chan_offset == MAC_SCA) {
                bss_dscr->channel_bandwidth = WLAN_BAND_WIDTH_40PLUS;
                ht_op_bw = WLAN_BW_CAP_40M;
            }
        }
    }

    /* ��AP��������ȡ������������Сֵ����ֹAP�쳣���ͳ��������������ݣ�������ݲ�ͨ */
    bss_dscr->bw_cap = oal_min(ht_cap_bw, ht_op_bw);

    if (us_frame_len > us_offset) {
        puc_ie = mac_find_ie(MAC_EID_EXT_CAPS, puc_frame_body + us_offset, us_frame_len - us_offset);
        if ((puc_ie != HI_NULL) && (puc_ie[1] >= 1)) {
            /* Extract 20/40 BSS Coexistence Management Support */
            bss_dscr->coex_mgmt_supp = (puc_ie[2] & BIT0);
        }
    }
}

/*****************************************************************************
 ��������  : ����Э���� bss��Ϣ
 �޸���ʷ      :
  1.��    ��   : 2013��6��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2013��8��21��
    ��    ��   : Hisilicon
    �޸�����   : ����11i ������Ϣ
*****************************************************************************/
static hi_void hmac_scan_update_bss_list_protocol(mac_bss_dscr_stru *bss_dscr,
                                                  hi_u8 *puc_frame_body, hi_u16 us_frame_len)
{
    hi_u16 us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /*************************************************************************/
    /*                       Beacon Frame - Frame Body                       */
    /* ---------------------------------------------------------------------- */
    /* |Timestamp|BcnInt|CapInfo|SSID|SupRates|DSParamSet|TIM  |CountryElem | */
    /* ---------------------------------------------------------------------- */
    /* |8        |2     |2      |2-34|3-10    |3         |6-256|8-256       | */
    /* ---------------------------------------------------------------------- */
    /* |PowerConstraint |Quiet|TPC Report|ERP |RSN  |WMM |Extended Sup Rates| */
    /* ---------------------------------------------------------------------- */
    /* |3               |8    |4         |3   |4-255|26  | 3-257            | */
    /* ---------------------------------------------------------------------- */
    /* |BSS Load |HT Capabilities |HT Operation |Overlapping BSS Scan       | */
    /* ---------------------------------------------------------------------- */
    /* |7        |28              |24           |16                         | */
    /* ---------------------------------------------------------------------- */
    /* |Extended Capabilities |                                              */
    /* ---------------------------------------------------------------------- */
    /* |3-8                   |                                              */
    /*************************************************************************/
    /* wmm */
    hmac_scan_update_bss_list_wmm(bss_dscr, puc_frame_body, us_frame_len);

#if defined(_PRE_WLAN_FEATURE_WPA) || defined(_PRE_WLAN_FEATURE_WPA2)
    /* 11i */
    hmac_scan_update_bss_list_security(bss_dscr, puc_frame_body, us_frame_len, us_offset);
#endif
#ifdef _PRE_WLAN_FEATURE_11D
    /* 11d */
    hmac_scan_update_bss_list_country(bss_dscr, puc_frame_body, us_frame_len);
#endif
    /* 11n */
    hmac_scan_update_bss_list_11n(bss_dscr, puc_frame_body, us_frame_len, us_offset);
}

/*****************************************************************************
 ��������  : �������
 �޸���ʷ      :
  1.��    ��   : 2016��04��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u8 hmac_scan_check_bss_supp_rates(mac_device_stru *mac_dev, const hi_u8 *puc_rate, hi_u8 bss_rate_num,
    hi_u8 *puc_update_rate, hi_u8 rate_len)
{
    mac_data_rate_stru *rates = HI_NULL;
    hi_u32 i, j;
    hi_u8 rate_num = 0;

    rates = &mac_dev->mac_rates_11g[0];

    if (puc_rate == HI_NULL) {
        return rate_num;
    }

    for (i = 0; i < bss_rate_num; i++) {
        for (j = 0; j < rate_len; j++) {
            if (((rates[j].mac_rate & 0x7f) == (puc_rate[i] & 0x7f)) &&
                (rate_num < MAC_DATARATES_PHY_80211G_NUM)) {
                puc_update_rate[rate_num] = puc_rate[i];
                rate_num++;
                break;
            }
        }
    }

    return rate_num;
}

/*****************************************************************************
 ��������  : ����ɨ�赽bss�����ʼ�
 �޸���ʷ      :
  1.��    ��   : 2013��7��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_scan_update_bss_list_rates(mac_bss_dscr_stru *bss_dscr,
                                              hi_u8 *puc_frame_body,
                                              hi_u16 us_frame_len, mac_device_stru *mac_dev)
{
    hi_u8 *puc_ie = HI_NULL;
    hi_u8 num_rates = 0;
    hi_u8 num_ex_rates;
    hi_u8 us_offset;
    hi_u8 auc_rates[MAC_DATARATES_PHY_80211G_NUM] = {0};

    /* ����Beacon֡��fieldƫ���� */
    us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    if (us_frame_len <= us_offset) {
        oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rates::frame_len[%d].}", us_frame_len);
        return HI_FAIL;
    }

    puc_ie = mac_find_ie(MAC_EID_RATES, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_ie != HI_NULL) {
        num_rates = hmac_scan_check_bss_supp_rates(mac_dev, puc_ie + MAC_IE_HDR_LEN, puc_ie[1],
            auc_rates, MAC_DATARATES_PHY_80211G_NUM);
        /* DTS2015032407334 �ѶFIR304����AP 11gģʽ�����͵�֧�����ʼ�����Ϊ12��������Э��涨��Ϊ���Ӽ����ԣ�
           �޸��жϷ�֧Ϊ12 */
        if (num_rates > WLAN_MAX_SUPP_RATES) {
            oam_warning_log1(0, OAM_SF_SCAN, "{hmac_scan_update_bss_list_rates::uc_num_rates=%d.}", num_rates);
            num_rates = WLAN_MAX_SUPP_RATES;
        }

        if (memcpy_s(bss_dscr->auc_supp_rates, WLAN_MAX_SUPP_RATES, auc_rates, num_rates) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_scan_update_bss_list_rates:: auc_rates memcpy_s fail.");
            return HI_FAIL;
        }

        bss_dscr->num_supp_rates = num_rates;
    }
    puc_ie = mac_find_ie(MAC_EID_XRATES, puc_frame_body + us_offset, us_frame_len - us_offset);
    if (puc_ie != HI_NULL) {
        num_ex_rates = hmac_scan_check_bss_supp_rates(mac_dev, puc_ie + MAC_IE_HDR_LEN, puc_ie[1],
            auc_rates, MAC_DATARATES_PHY_80211G_NUM);
        if (num_rates + num_ex_rates > WLAN_MAX_SUPP_RATES) {     /* ����֧�����ʸ��� */
            oam_warning_log2(0, OAM_SF_SCAN,
                "{hmac_scan_update_bss_list_rates::number of rates too large, num_rates=%d, num_ex_rates=%d.}",
                             num_rates, num_ex_rates);

            num_ex_rates = WLAN_MAX_SUPP_RATES - num_rates;
        }

        if (num_ex_rates > 0) {
            if (memcpy_s(&(bss_dscr->auc_supp_rates[num_rates]), WLAN_MAX_SUPP_RATES, auc_rates,
                         num_ex_rates) != EOK) {
                oam_error_log0(0, OAM_SF_CFG, "hmac_scan_update_bss_list_rates:: auc_rates memcpy_s fail.");
                return HI_FAIL;
            }
        }
        bss_dscr->num_supp_rates += num_ex_rates;
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_scan_update_bss_ssid(mac_bss_dscr_stru *bss_dscr, hmac_scanned_bss_info *scanned_bss,
    hi_u8 *puc_frame_body, hi_u16 us_frame_body_len)
{
    hi_unref_param(scanned_bss);
    hi_u8  ssid_len;
     /* ����������ssid */
    hi_u8 *puc_ssid = mac_get_ssid(puc_frame_body, (hi_s32) us_frame_body_len, &ssid_len);
    if ((puc_ssid != HI_NULL) && (ssid_len != 0)) {
        /* �����ҵ���ssid���浽bss�����ṹ���� */
        if (memcpy_s(bss_dscr->ac_ssid, WLAN_SSID_MAX_LEN, puc_ssid, ssid_len) != EOK) {
            oam_warning_log1(0, OAM_SF_SCAN, "hmac_scan_update_bss_ssid:memcpy_s fail, ssid=[%p]", (uintptr_t)puc_ssid);
            return HI_FAIL;
        }
        bss_dscr->ac_ssid[ssid_len] = '\0';
#ifdef _PRE_WLAN_FEATURE_MESH
    } else {
        /* ͬWPA��Mesh��beacon��probe rsp�Ὣssid�ظ���˽��meshid�ֶ��У���ȡ������meshid������䵽ssid�� */
        /* mac_get_meshid()��������ֵ���;���hi_u8*,��lin_t64�澯���������� */
        puc_ssid = mac_get_meshid(puc_frame_body, (hi_s32)us_frame_body_len, &ssid_len);
        /* �����ҵ���ssid���浽bss�����ṹ���� */
        if (puc_ssid != HI_NULL) {
            if (memcpy_s(bss_dscr->ac_ssid, WLAN_SSID_MAX_LEN, puc_ssid, ssid_len) != EOK) {
                oam_warning_log1(0, OAM_SF_SCAN,
                    "hmac_scan_update_bss_ssid:memcpy_s fail, ssid=[%p]", (uintptr_t)puc_ssid);
                return HI_FAIL;
            }
        } else {
            ssid_len = 0;
        }
        bss_dscr->ac_ssid[ssid_len] = '\0';
#endif
    }
#ifdef _PRE_WLAN_FEATURE_SCAN_BY_SSID
    /* ��鱾��ɨ�������Ƿ�Ϊָ��ssidɨ�裬�ж��Ƿ���Ҫ�������˷�ָ��ssid��ɨ����Ϣ */
    hmac_scan_proc_check_ssid(scanned_bss, puc_ssid, ssid_len);
#endif
    return HI_SUCCESS;
}

static hi_u32 hmac_scan_update_bss_bssid(mac_bss_dscr_stru *bss_dscr, const mac_ieee80211_frame_stru *frame_header)
{
    if (memcpy_s(bss_dscr->auc_mac_addr, WLAN_MAC_ADDR_LEN,  frame_header->auc_address2,
        WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_scan_update_bss_bssid::mem safe function err!}");
        return HI_FAIL;
    }
    if (memcpy_s(bss_dscr->auc_bssid, WLAN_MAC_ADDR_LEN, frame_header->auc_address3, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{hmac_scan_update_bss_bssid::mem safe function err!}");
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

static hi_void hmac_scan_update_bss_base(hmac_vap_stru *hmac_vap, const dmac_tx_event_stru *dtx_event,
    mac_bss_dscr_stru *bss_dscr, hi_u8 frame_channel)
{
    hi_unref_param(hmac_vap);

    oal_netbuf_stru *netbuf = dtx_event->netbuf;
    mac_scanned_result_extend_info_stru *scan_result_extend_info = HI_NULL;
    mac_device_stru *mac_dev = mac_res_get_dev();
    hi_u16 us_netbuf_len = (hi_u16)(dtx_event->us_frame_len + MAC_80211_FRAME_LEN);
    /* ��ȡdevice�ϱ���ɨ������Ϣ����������µ�bss�����ṹ���� */
    hi_u16 us_frame_len = us_netbuf_len - sizeof(mac_scanned_result_extend_info_stru);
    hi_u8 *puc_mgmt_frame = (hi_u8 *)oal_netbuf_data(netbuf);
    /* ָ��netbuf�е��ϱ���ɨ��������չ��Ϣ��λ�� */
    scan_result_extend_info = (mac_scanned_result_extend_info_stru *)(puc_mgmt_frame + us_frame_len);
    /* ��ȡ����֡��֡ͷ��֡��ָ�� */
    mac_ieee80211_frame_stru *frame_header = (mac_ieee80211_frame_stru *)puc_mgmt_frame;
    hi_u8 *puc_frame_body = (hi_u8 *)(puc_mgmt_frame + MAC_80211_FRAME_LEN);
    hi_u16 us_frame_body_len = us_frame_len - MAC_80211_FRAME_LEN;

    /* bss������Ϣ */
    bss_dscr->bss_type = scan_result_extend_info->bss_type;

    bss_dscr->us_cap_info = *((hi_u16 *)(puc_frame_body + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN));

    bss_dscr->rssi = (hi_s8) scan_result_extend_info->l_rssi;

    /* ����beacon���� */
    bss_dscr->us_beacon_period = mac_get_beacon_period(puc_frame_body);

    /* ���� TIM ���ڣ��� Beacon ֡�и�Ԫ�� */
    if (frame_header->frame_control.sub_type == WLAN_BEACON) {
        bss_dscr->dtim_period = mac_get_dtim_period(puc_frame_body, us_frame_body_len);
        bss_dscr->dtim_cnt = mac_get_dtim_cnt(puc_frame_body, us_frame_body_len);
    }

    /* �ŵ� */
    bss_dscr->channel.chan_number = frame_channel;
    bss_dscr->channel.band = mac_get_band_by_channel_num(frame_channel);

    /* ��¼���ʼ� */
    if (hmac_scan_update_bss_list_rates(bss_dscr, puc_frame_body, us_frame_body_len, mac_dev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_SCAN, "hmac_scan_update_bss_list_rates return NON SUCCESS. ");
    }

    /* Э���������ϢԪ�صĻ�ȡ */
    hmac_scan_update_bss_list_protocol(bss_dscr, puc_frame_body, us_frame_body_len);

#ifdef _PRE_WLAN_FEATURE_MESH
        /* Probe Rsp��Beacon֡��ǰ��ΪTimestamp,beacon interval,capability�ֶΣ���tlv�ṹ������ֱ������mac_find_ie������
        �˴�����ƫ�ƣ���Element IDΪ0��SSID��Ϊ��ʼ��ַ����ָ��IE */
        hi_u8 *puc_frame_ie_body = puc_frame_body + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

        if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) {
            /* ����Mesh Configuration Element������ȡAccepting Peer�ֶ�ֵ */
            if (us_frame_body_len > MAC_SSID_OFFSET) {
                mac_mesh_conf_ie_stru *puc_mesh_conf_ie = (mac_mesh_conf_ie_stru *)mac_find_ie(MAC_EID_MESH_CONF,
                    puc_frame_ie_body, us_frame_body_len - MAC_SSID_OFFSET);
                if (puc_mesh_conf_ie != HI_NULL) {
                    bss_dscr->is_mesh_accepting_peer =
                        (puc_mesh_conf_ie->mesh_capa.accepting_add_mesh_peerings == 1) ? HI_TRUE : HI_FALSE;
                }
            } else {
                bss_dscr->is_mesh_accepting_peer = HI_FALSE;
            }
        }
        /* ����Hisi-Mesh˽��IE�ֶ�,����ʹ�� */
        bss_dscr->is_hisi_mesh = mac_check_is_mesh_vap(puc_frame_ie_body, (hi_u8)(us_frame_body_len - MAC_SSID_OFFSET));
        if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) {
            oam_info_log4(0, OAM_SF_SCAN, "hmac_scan_update_bss_base:mac address: 0x%x::0x%x, peer = %d, mesh = %d",
                bss_dscr->auc_mac_addr[4], bss_dscr->auc_mac_addr[5], /* 4 5 Ԫ������ */
                bss_dscr->is_mesh_accepting_peer, bss_dscr->is_hisi_mesh);
        }
#endif
}

static hi_void hmac_scan_update_bss_any(mac_bss_dscr_stru *bss_dscr, hi_u8 *puc_frame_body, hi_u16 us_frame_body_len)
{
#ifdef _PRE_WLAN_FEATURE_ANY
    /* Probe Rsp��Beacon֡��ǰ��ΪTimestamp,beacon interval,capability�ֶΣ���tlv�ṹ������ֱ������mac_find_ie������
    �˴�����ƫ�ƣ���Element IDΪ0��SSID��Ϊ��ʼ��ַ����ָ��IE */
    hi_u8 *puc_frame_ie_start = puc_frame_body + MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;
    /* ���Ҷ�Ӧ��ANY IE */
    hi_u8 *puc_any_ie = mac_find_vendor_ie(MAC_WLAN_OUI_HUAWEI, MAC_OUITYPE_ANY, puc_frame_ie_start,
        us_frame_body_len - MAC_SSID_OFFSET);
    if ((puc_any_ie != HI_NULL) && ((puc_any_ie[6] == MAC_ANY_STA_TYPE) || /* 6Ԫ������ */
        (puc_any_ie[6] == MAC_ANY_AP_TYPE))) { /* 6Ԫ������ */
        bss_dscr->supp_any = HI_TRUE;
        bss_dscr->is_any_sta = HI_FALSE;
        if (puc_any_ie[6] == MAC_ANY_STA_TYPE) { /* 6 Ԫ������ */
            bss_dscr->is_any_sta = HI_TRUE;
        }
    }
#else
    hi_unref_param(bss_dscr);
    hi_unref_param(puc_frame_body);
    hi_unref_param(us_frame_body_len);
#endif
    return;
}

/*****************************************************************************
 ��������  : ��������ɨ��ṹ��bss dscr�ṹ��
 �������  : hmac_scanned_bss_info   *pst_scanned_bss,
             dmac_tx_event_stru      *pst_dtx_event,
             hi_u8                uc_vap_id
 �޸���ʷ      :
  1.��    ��   : 2015��2��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_scan_update_bss_dscr(hmac_scanned_bss_info *scanned_bss, const dmac_tx_event_stru *dtx_event, hi_u8 vap_id)
{
    oal_netbuf_stru *netbuf = dtx_event->netbuf;
    mac_scanned_result_extend_info_stru *scan_result_extend_info = HI_NULL;
    hi_u16 us_netbuf_len = (hi_u16)(dtx_event->us_frame_len + MAC_80211_FRAME_LEN);
    hi_u16 us_offset = MAC_TIME_STAMP_LEN + MAC_BEACON_INTERVAL_LEN + MAC_CAP_INFO_LEN;

    /* ��ȡhmac vap */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_update_bss_dscr::pst_hmac_vap is null.}");
        return HI_FAIL;
    }

    /* ��ȡdevice�ϱ���ɨ������Ϣ����������µ�bss�����ṹ���� */
    hi_u16 us_frame_len = us_netbuf_len - sizeof(mac_scanned_result_extend_info_stru);
    hi_u8 *puc_mgmt_frame = (hi_u8 *)oal_netbuf_data(netbuf);
    if (puc_mgmt_frame == HI_NULL) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_scan_update_bss_dscr:: puc_mgmt_frame fail.");
        return HI_FAIL;
    }

    /* ָ��netbuf�е��ϱ���ɨ��������չ��Ϣ��λ�� */
    scan_result_extend_info = (mac_scanned_result_extend_info_stru *)(puc_mgmt_frame + us_frame_len);
    /* ��ȡ����֡��֡ͷ��֡��ָ�� */
    mac_ieee80211_frame_stru *frame_header = (mac_ieee80211_frame_stru *)puc_mgmt_frame;
    hi_u8 *puc_frame_body = (hi_u8 *)(puc_mgmt_frame + MAC_80211_FRAME_LEN);
    hi_u16 us_frame_body_len = us_frame_len - MAC_80211_FRAME_LEN;

    /* ��ȡ����֡�е��ŵ� */
    hi_u8  frame_channel = mac_ie_get_chan_num(puc_frame_body, us_frame_body_len, us_offset, 0);
    /* ����ŵ��Ƿ���ֱ�ӷ��� */
    if (frame_channel == 0) {
        oam_info_log0(0, OAM_SF_SCAN, "hmac_scan_update_bss_dscr:: Received a frame from unregulated domain.");
        return HI_FAIL;
    }

    /* ����յ���֡�ŵ��͵�ǰɨ���ŵ���һ�£�����֡�ŵ��Ƿ���ɨ���ŵ��б���, ����������� */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    hmac_scan_stru *scan_mgmt = &(hmac_dev->scan_mgmt);
    if ((frame_channel != scan_result_extend_info->channel) &&
        (scan_mgmt->scan_2g_ch_list_map & (BIT0 << frame_channel)) == HI_FALSE) {
        scanned_bss->bss_dscr_info.need_drop = HI_TRUE;
    }

    /* ����bss��Ϣ */
    mac_bss_dscr_stru *bss_dscr = &(scanned_bss->bss_dscr_info);

    /*****************************************************************************
        ����beacon/probe rsp֡����¼��pst_bss_dscr
    *****************************************************************************/
    /* ����������ssid �� bssid */
    if ((hmac_scan_update_bss_ssid(bss_dscr, scanned_bss, puc_frame_body, us_frame_body_len) != HI_SUCCESS) ||
        (hmac_scan_update_bss_bssid(bss_dscr, frame_header) != HI_SUCCESS)) {
        return HI_FAIL;
    }

    /* bss������Ϣ */
    hmac_scan_update_bss_base(hmac_vap, dtx_event, bss_dscr, frame_channel);

    /* ����ʱ��� */
    bss_dscr->timestamp = (hi_u32)hi_get_milli_seconds();
    bss_dscr->mgmt_len = us_frame_len;
    /* ����any�����Ϣ */
    hmac_scan_update_bss_any(bss_dscr, puc_frame_body, us_frame_body_len);

    /* ��������֡���� */
    if (memcpy_s((hi_u8 *)scanned_bss->bss_dscr_info.auc_mgmt_buff, (hi_u32) us_frame_len, puc_mgmt_frame,
        (hi_u32) us_frame_len) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_scan_update_bss_dscr:: puc_mgmt_frame memcpy_s fail.");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

static hi_u32 hmac_scan_proc_scanned_bss_mgmt(hmac_device_stru *hmac_dev, hmac_scanned_bss_info *new_scanned_bss,
    oal_netbuf_stru *bss_mgmt_netbuf)
{
    /* ��ȡ����ɨ���bss����Ľṹ�� */
    hmac_bss_mgmt_stru *bss_mgmt = &(hmac_dev->scan_mgmt.scan_record_mgmt.bss_mgmt);
    /* ������ɾ����ǰ���� */
    oal_spin_lock(&(bss_mgmt->st_lock));

    /* �ж���ͬbssid��bss�Ƿ��Ѿ�ɨ�赽 */
    hmac_scanned_bss_info *old_scanned_bss =
        hmac_scan_find_scanned_bss_by_bssid(bss_mgmt, new_scanned_bss->bss_dscr_info.auc_bssid);
    if (old_scanned_bss == HI_NULL) {
        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));

        goto add_bss; /* goto���ʹ�ã�lin_t e801�澯���� */
    }

    /* ����ϵ�ɨ���bss���ź�ǿ�ȴ��ڵ�ǰɨ�赽��bss���ź�ǿ�ȣ����µ�ǰɨ�赽���ź�ǿ��Ϊ��ǿ���ź�ǿ�� */
    if (old_scanned_bss->bss_dscr_info.rssi > new_scanned_bss->bss_dscr_info.rssi) {
        /* 1s�����ھͲ���֮ǰ��BSS�����RSSI��Ϣ������Ͳ����µ�RSSI��Ϣ */
        if ((hi_get_milli_seconds() - old_scanned_bss->bss_dscr_info.timestamp) < HMAC_SCAN_MAX_SCANNED_RSSI_EXPIRE) {
            new_scanned_bss->bss_dscr_info.rssi = old_scanned_bss->bss_dscr_info.rssi;
        }
    }

    if ((new_scanned_bss->bss_dscr_info.ac_ssid[0] == '\0') && (old_scanned_bss->bss_dscr_info.ac_ssid[0] != '\0')) {
        /* ����SSID������������AP��Ϣ,��ssid��Ϊ�գ��˴�ͨ��BEACON֡ɨ�赽��AP��Ϣ,��SSIDΪ�գ��򲻽��и��� */
        oam_warning_log3(0, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::ssid:%.2x:%.2x:%.2x}",
            new_scanned_bss->bss_dscr_info.auc_bssid[3], new_scanned_bss->bss_dscr_info.auc_bssid[4], /* 3 4 Ԫ������ */
            new_scanned_bss->bss_dscr_info.auc_bssid[5]); /* 5 Ԫ������ */

        old_scanned_bss->bss_dscr_info.timestamp = (hi_u32) hi_get_milli_seconds();
        old_scanned_bss->bss_dscr_info.rssi = new_scanned_bss->bss_dscr_info.rssi;

        /* ���� */
        oal_spin_unlock(&(bss_mgmt->st_lock));

        /* �ͷ�����Ĵ洢bss��Ϣ���ڴ� */
        oal_free(new_scanned_bss);

        /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
        oal_netbuf_free(bss_mgmt_netbuf);

        return HI_SUCCESS;
    }

    /* �������н�ԭ��ɨ�赽����ͬbssid��bss�ڵ�ɾ�� */
    hmac_scan_del_bss_from_list_nolock(old_scanned_bss, hmac_dev);
    /* ���� */
    oal_spin_unlock(&(bss_mgmt->st_lock));

    /* �ͷ��ڴ� */
    oal_free(old_scanned_bss);

add_bss: /* lint_t e801�澯���� */
#ifdef _PRE_WLAN_FEATURE_QUICK_START
    hi_s8 *pc_ssid = new_scanned_bss->bss_dscr_info.ac_ssid;
    databk_quick_start_stru *quick_start_param = hisi_get_quick_start_param();
    if ((quick_start_param->ssid_len != 0) && (quick_start_param->ssid_len == strlen(pc_ssid)) &&
        (SSID_MAX_LEN >= strlen(pc_ssid)) && (memcmp(quick_start_param->auc_ssid, pc_ssid, strlen(pc_ssid)) == 0)) {
        hi_u16 bsslen = sizeof(hmac_scanned_bss_info) + mgmt_len - sizeof(new_scanned_bss->bss_dscr_info.auc_mgmt_buff);
        /* ����ɨ���� */
        if (memcpy_s(quick_start_param->auc_bss_frame, bsslen, new_scanned_bss, bsslen) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_scan_proc_scanned_bss:: pst_new_scanned_bss memcpy_s fail.");
            oal_free(new_scanned_bss);
            return HI_FAIL;
        }
        quick_start_param->us_bss_frame_len = mgmt_len;
        quick_start_param->uc_update_flag = PARAM_NEED_UPDATE;
    }
#endif

    /* ��ɨ������ӵ������� */
    hmac_scan_add_bss_to_list(new_scanned_bss, hmac_dev);

    /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
    oal_netbuf_free(bss_mgmt_netbuf);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ÿ���ŵ���ɨ������host����д���
 �޸���ʷ      :
  1.��    ��   : 2015��2��7��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_scan_proc_scanned_bss(frw_event_mem_stru *event_mem)
{
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ�¼�ͷ���¼��ṹ��ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_stru *event_hdr = &(event->event_hdr);
    dmac_tx_event_stru *dtx_event = (dmac_tx_event_stru *)event->auc_event_data;
    oal_netbuf_stru *bss_mgmt_netbuf = dtx_event->netbuf;

    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(event_hdr->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::pst_hmac_vap null.}");

        /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
        oal_netbuf_free(bss_mgmt_netbuf);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡhmac device �ṹ */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    /* ��dmac�ϱ���netbuf���ݽ��н���������������ʾ */
    /***********************************************************************************************/
    /*            netbuf data����ϱ���ɨ�������ֶεķֲ�                                        */
    /* ------------------------------------------------------------------------------------------  */
    /* beacon/probe rsp body  |     ֡����渽���ֶ�(mac_scanned_result_extend_info_stru)          */
    /* -----------------------------------------------------------------------------------------   */
    /* �յ���beacon/rsp��body | rssi(4�ֽ�) | channel num(1�ֽ�)| band(1�ֽ�)|bss_tye(1�ֽ�)|���  */
    /* ------------------------------------------------------------------------------------------  */
    /*                                                                                             */
    /***********************************************************************************************/
    /* ����֡�ĳ��ȵ����ϱ���netbuf�ĳ��ȼ�ȥ�ϱ���ɨ��������չ�ֶεĳ��� */
    hi_u16 us_mgmt_len =
        (hi_u16)(dtx_event->us_frame_len + MAC_80211_FRAME_LEN - sizeof(mac_scanned_result_extend_info_stru));

    /* ����洢ɨ�������ڴ� */
    hmac_scanned_bss_info *new_scanned_bss = hmac_scan_alloc_scanned_bss(us_mgmt_len);
    if (oal_unlikely(new_scanned_bss == HI_NULL)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::alloc memory failed }");

        /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
        oal_netbuf_free(bss_mgmt_netbuf);
        return HI_FAIL;
    }

    /* ��������ɨ������bss dscr�ṹ�� */
    if (oal_unlikely(hmac_scan_update_bss_dscr(new_scanned_bss, dtx_event, event_hdr->vap_id) != HI_SUCCESS)) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scanned_bss::hmac_scan_update fail}");

        /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
        oal_netbuf_free(bss_mgmt_netbuf);

        /* �ͷ�����Ĵ洢bss��Ϣ���ڴ� */
        oal_free(new_scanned_bss);
        return HI_FAIL;
    }

#ifdef _PRE_WLAN_FEATURE_MESH
    /* MESH VAP���˷�MESH VAP������Beacon/Probe Rsp
       ���˹���:1.en_is_hisi_meshΪFALSE 2.en_is_mesh_accepting_peerΪFALSE,
       ���ɨ����ANY�·���ɨ�裬�����ﲻ���� */
    if ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH) &&
        (((new_scanned_bss->bss_dscr_info.is_hisi_mesh == HI_FALSE) ||
        (new_scanned_bss->bss_dscr_info.is_mesh_accepting_peer == HI_FALSE)) &&
        (hmac_dev->scan_mgmt.scan_record_mgmt.is_any_scan == HI_FALSE))) {
            /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
            oal_netbuf_free(bss_mgmt_netbuf);

            /* �ͷ�����Ĵ洢bss��Ϣ���ڴ� */
            oal_free(new_scanned_bss);

            return HI_SUCCESS;
        }
#endif

    /* ���֮ǰ���ж���Ҫ���� */
    if (new_scanned_bss->bss_dscr_info.need_drop == HI_TRUE) {
        /* �ͷ��ϱ���bss��Ϣ��beacon����probe rsp֡���ڴ� */
        oal_netbuf_free(bss_mgmt_netbuf);

        /* �ͷ�����Ĵ洢bss��Ϣ���ڴ� */
        oal_free(new_scanned_bss);

        return HI_SUCCESS;
    }

    return hmac_scan_proc_scanned_bss_mgmt(hmac_dev, new_scanned_bss, bss_mgmt_netbuf);
}

static hi_void hmac_scan_proc_scan_comp_event_vap(const mac_device_stru *mac_dev, hmac_scan_stru *scan_mgmt,
    hmac_vap_stru *hmac_vap)
{
    if ((mac_is_dbac_running(mac_dev) != HI_TRUE) || (mac_dev->dbac_same_ch == HI_TRUE)) {
        /* ���ݵ�ǰɨ������ͺ͵�ǰvap��״̬�������л�vap��״̬�������ǰ��ɨ�裬����Ҫ�л�vap��״̬ */
        if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            if (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_STA_WAIT_SCAN) {
                /* �ı�vap״̬��SCAN_COMP */
                hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_SCAN_COMP);
            } else if (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_UP) {
                /* ����ɨ��ʱ��Ҫ����֡���˵����� */
                hmac_set_rx_filter_value(hmac_vap->base_vap);
            }
        }

        /* BEGIN:DTS2015072801307 1102 ��Ϊap ��40M ������ִ��ɨ�裬ɨ����ɺ�VAP ״̬�޸�Ϊɨ��ǰ��״̬ */
        if (((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) ||
            (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH)
            ) && (scan_mgmt->scan_record_mgmt.vap_last_state != MAC_VAP_STATE_BUTT)) {
            hmac_fsm_change_state(hmac_vap, scan_mgmt->scan_record_mgmt.vap_last_state);
            scan_mgmt->scan_record_mgmt.vap_last_state = MAC_VAP_STATE_BUTT;
        }
    }
}

/*****************************************************************************
 ��������  : DMACɨ������¼�����
 �޸���ʷ      :
  1.��    ��   : 2013��6��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_scan_proc_scan_comp_event(frw_event_mem_stru *event_mem)
{
    /* ��ȡ�¼�ͷ���¼��ṹ��ָ�� */
    frw_event_stru *event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_stru *event_hdr = &(event->event_hdr);

    /* ��ȡhmac device */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    mac_device_stru *mac_dev = mac_res_get_dev();
    mac_scan_rsp_stru *d2h_scan_rsp_info = (mac_scan_rsp_stru *)(event->auc_event_data);
    hmac_scan_stru *scan_mgmt = &(hmac_dev->scan_mgmt);

    /* ����·�����ANYɨ�裬����ɨ���ʱ������Ϊ��ANYɨ�裬�·�������ANYɨ�裬���︳��ֵ��Ӱ�� */
    hmac_dev->scan_mgmt.scan_record_mgmt.is_any_scan = HI_FALSE;

    /* DTS2015110908011 ��ֹcompete�¼������ڴ����ɨ�費һ�� */
    if ((event_hdr->vap_id != scan_mgmt->scan_record_mgmt.vap_id) ||
        (d2h_scan_rsp_info->ull_cookie != scan_mgmt->scan_record_mgmt.ull_cookie)) {
        oam_warning_log4(event_hdr->vap_id, OAM_SF_SCAN,
            "{hmac_scan_proc_scan_comp_event::vap(%d) Scancomplete(cookie %d), anoter vap(%d) scaning(cookie %d) !}",
            event_hdr->vap_id, d2h_scan_rsp_info->ull_cookie, scan_mgmt->scan_record_mgmt.vap_id,
            scan_mgmt->scan_record_mgmt.ull_cookie);
        return HI_SUCCESS;
    }

    /* ɾ��ɨ�賬ʱ������ʱ�� */
    if (scan_mgmt->scan_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(scan_mgmt->scan_timeout));
    }

    /* ��ȡhmac vap */
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(event_hdr->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(event_hdr->vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_comp_event::pst_hmac_vap null.}");

        /* ���õ�ǰ���ڷ�ɨ��״̬ */
        scan_mgmt->is_scanning = HI_FALSE;
        return HI_ERR_CODE_PTR_NULL;
    }

    hmac_scan_proc_scan_comp_event_vap(mac_dev, scan_mgmt, hmac_vap);

#ifdef _PRE_WLAN_FEATURE_ANY
    if ((hmac_vap->base_vap->support_any == HI_TRUE) &&
        (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) &&
        (mac_dev->vap_num == 1) &&
        (mac_dev->scan_params.scan_mode == WLAN_SCAN_MODE_FOREGROUND)) {
        oam_warning_log1(0, OAM_SF_SCAN, "{[ANY]switch to original channel %d.}",
            hmac_vap->base_vap->channel.chan_number);
        hmac_config_set_freq(hmac_vap->base_vap, 1, &hmac_vap->base_vap->channel.chan_number);
    }
#endif
    /* 1102 ��Ϊap ��40M ������ִ��ɨ�裬ɨ����ɺ�VAP ״̬�޸�Ϊɨ��ǰ��״̬ */
    /* ����device�ϱ���ɨ�������ϱ�sme */
    /* ��ɨ��ִ�����(ɨ��ִ�гɹ�������ʧ�ܵȷ��ؽ��)��¼��ɨ�����м�¼�ṹ���� */
    scan_mgmt->scan_record_mgmt.scan_rsp_status = d2h_scan_rsp_info->scan_rsp_status;
    scan_mgmt->scan_record_mgmt.ull_cookie = d2h_scan_rsp_info->ull_cookie;

    /* �ϱ�ɨ����ǰ������µ��ڵ�ɨ��bss����ֹ�ϱ����ൽ�ڵ�bss */
    hmac_scan_clean_expire_scanned_bss(&(scan_mgmt->scan_record_mgmt), HI_FALSE);
    /* ���ɨ��ص�������Ϊ�գ�����ûص����� */
    if (scan_mgmt->scan_record_mgmt.fn_cb != HI_NULL) {
        scan_mgmt->scan_record_mgmt.fn_cb(&(scan_mgmt->scan_record_mgmt));
    }

    /* ���õ�ǰ���ڷ�ɨ��״̬ */
    scan_mgmt->is_scanning = HI_FALSE;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �쳣ɨ������,���¼���wal �㣬ִ��ɨ�����
 �������  : pst_mac_device: ָ��device�ṹ��
             p_params: ����ɨ������Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2013��12��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_scan_proc_scan_req_event_exception(hmac_vap_stru *hmac_vap)
{
    hmac_scan_rsp_stru scan_rsp;

    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log1(0, OAM_SF_SCAN, "{hmac_mgmt_scan_req_exception::param null, %p.}", (uintptr_t)hmac_vap);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��֧�ַ���ɨ���״̬������ɨ�� */
    oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
                     "{hmac_mgmt_scan_req_exception::vap state is=%x.}", hmac_vap->base_vap->vap_state);

    if (memset_s(&scan_rsp, sizeof(hmac_scan_rsp_stru), 0, sizeof(hmac_scan_rsp_stru)) != EOK) {
        return HI_FAIL;
    }

    scan_rsp.result_code = HMAC_MGMT_REFUSED;
    scan_rsp.num_dscr = 0;

    return hmac_send_event_to_host(hmac_vap->base_vap, (const hi_u8*)(&scan_rsp),
        sizeof(hmac_scan_rsp_stru), HMAC_HOST_CTX_EVENT_SUB_TYPE_SCAN_COMP_STA);
}

/*****************************************************************************
 ��������  : ����probe req֡��Я����Դmac addr��������mac addr���Կ�������Я�����mac addr
 �������  : [1]pst_hmac_vap
             [2]puc_sour_mac_addr
             [3]is_rand_mac_addr_scan
             [4]is_p2p0_scan
 �� �� ֵ  : ��
*****************************************************************************/
hi_void hmac_scan_set_sour_mac_addr_in_probe_req(const hmac_vap_stru *hmac_vap, hi_u8 *sa_mac_addr, hi_u8 mac_addr_len,
    hi_u8 is_rand_mac_addr_scan, hi_u8 is_p2p0_scan)
{
#ifdef _PRE_WLAN_FEATURE_P2P
    /* WLAN/P2P ��������£�p2p0 ��p2p-p2p0 cl ɨ��ʱ����Ҫʹ�ò�ͬ�豸 */
    if (is_p2p0_scan == HI_TRUE) {
        if (memcpy_s(sa_mac_addr, mac_addr_len,
            hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_p2p0_dot11_station_id,
            WLAN_MAC_ADDR_LEN) != EOK) {
            return;
        }
    } else
#else
    hi_unref_param(is_p2p0_scan);
#endif /* _PRE_WLAN_FEATURE_P2P */
    {
        /* ������mac addrɨ�����Կ����ҷ�P2P�������������mac addr��probe req֡�� */
        if ((is_rand_mac_addr_scan == HI_TRUE) && (is_legacy_vap(hmac_vap->base_vap))) {
            oal_random_ether_addr(sa_mac_addr, mac_addr_len);
            sa_mac_addr[0] &= (~0x02);    /* wlan0 MAC[0] bit1 ��Ҫ����Ϊ0 */
            sa_mac_addr[1] = 0x11;
            sa_mac_addr[2] = 0x02; /* 2 Ԫ������ */

            oam_warning_log3(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
                             "{hmac_scan_set_sour_mac_addr_in_probe_req::rand_mac_addr[XX:XX:XX:%02X:%02X:%02X].}",
                             sa_mac_addr[3], /* 3 Ԫ������ */
                             sa_mac_addr[4], sa_mac_addr[5]); /* 4 5 Ԫ������ */
        } else {
            /* ���õ�ַΪ�Լ���MAC��ַ */
            if (memcpy_s(sa_mac_addr, mac_addr_len,
                hmac_vap->base_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id,
                WLAN_MAC_ADDR_LEN) != EOK) {
                return;
            }
        }
    }
    return;
}

/*****************************************************************************
 ��������  : ����device�����е�vap״̬�Լ�������Ϣ������ɨ�����:
             ��������ɨ���ߵ�vap id��ɨ��ģʽ��ÿ�ŵ�ɨ�������probe req֡Я����Դmac addr
 �������  : hmac_vap_stru *pst_hmac_vap,
             mac_scan_req_stru *pst_scan_params,
             hi_u8   en_is_random_mac_addr_scan,      �Ƿ�Ϊ���mac addrɨ��ı��
 �޸���ʷ      :
  1.��    ��   : 2015��2��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_scan_update_scan_params(const hmac_vap_stru *hmac_vap,
                                           mac_scan_req_stru *scan_params,
                                           hi_u8 is_random_mac_addr_scan)
{
    mac_device_stru *mac_dev = HI_NULL;
    mac_vap_stru *mac_vap_temp = HI_NULL;
    wlan_vap_mode_enum_uint8 vap_mode;

    /* ��ȡmac device */
    mac_dev = mac_res_get_dev();
    /* 1.��¼����ɨ���vap id��ɨ����� */
    scan_params->vap_id = hmac_vap->base_vap->vap_id;
    scan_params->scan_mode = WLAN_SCAN_MODE_FOREGROUND;
    scan_params->need_switch_back_home_channel = HI_FALSE;

    /* 2.�޸�ɨ��ģʽ���ŵ�ɨ�����: �����Ƿ����up״̬�µ�vap������ǣ����Ǳ���ɨ�裬������ǣ�����ǰ��ɨ�� */
    mac_device_find_up_vap(mac_dev, &mac_vap_temp);
    if (mac_vap_temp != HI_NULL) {
        /* �ж�vap�����ͣ������sta��Ϊsta�ı���ɨ�裬�����ap������ap�ı���ɨ�裬�������͵�vap�ݲ�֧�ֱ���ɨ�� */
        vap_mode = hmac_vap->base_vap->vap_mode;
        if (vap_mode == WLAN_VAP_MODE_BSS_STA) {
            /* �޸�ɨ�����Ϊsta�ı���ɨ�� */
            scan_params->scan_mode = WLAN_SCAN_MODE_BACKGROUND_STA;
        } else if (vap_mode == WLAN_VAP_MODE_BSS_AP
#ifdef _PRE_WLAN_FEATURE_MESH
                   || (vap_mode == WLAN_VAP_MODE_MESH)
#endif
            ) {
            /* �޸�ɨ�����Ϊsta�ı���ɨ�� */
            scan_params->scan_mode = WLAN_SCAN_MODE_BACKGROUND_AP;
        } else {
            oam_error_log1(0, OAM_SF_SCAN, "{hmac_scan_update_scan_params::vap mode[%d], not support bg scan.}",
                           vap_mode);
            return HI_FAIL;
        }
        scan_params->need_switch_back_home_channel = HI_TRUE;
    }
    /* 3.���÷��͵�probe req֡��Դmac addr */
    scan_params->is_random_mac_addr_scan = is_random_mac_addr_scan;
    hmac_scan_set_sour_mac_addr_in_probe_req(hmac_vap, scan_params->auc_sour_mac_addr, WLAN_MAC_ADDR_LEN,
                                             is_random_mac_addr_scan, scan_params->is_p2p0_scan);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����Ƿ��ܹ�����ɨ�裬������ԣ����¼ɨ�������ߵ���Ϣ���������һ��ɨ����
 �������  : hmac_vap_stru       *pst_hmac_vap,
             hmac_device_stru    *pst_hmac_device
 �޸���ʷ      :
  1.��    ��   : 2015��5��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_scan_check_is_dispatch_scan_req(const hmac_vap_stru *hmac_vap, const hmac_device_stru *hmac_dev)
{
#ifdef _PRE_WLAN_FEATURE_P2P
    hi_u32 ret;
    /* 1.�ȼ������vap��״̬�Ӷ��ж��Ƿ�ɽ���ɨ��״̬��ʹ��ɨ�辡��������������������� */
    ret = hmac_p2p_check_can_enter_state(hmac_vap->base_vap, HMAC_FSM_INPUT_SCAN_REQ);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
            "{hmac_scan_check_is_dispatch_scan_req::Because of err_code[%d], can't enter into scan state.}", ret);
        return ret;
    }
#else
    hi_unref_param(hmac_vap);
#endif
    /* 2.�жϵ�ǰɨ���Ƿ�����ִ�� */
    if (hmac_dev->scan_mgmt.is_scanning == HI_TRUE) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_scan_check_is_dispatch_scan_req::the scan request is rejected.}");
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ������һ�ε�ɨ���¼���ӿڷ�װ���Ӷ����ڿ���չ(δ������ʹ���ϻ������ж��Ƿ����)
 �������  : hmac_vap_stru       *pst_hmac_vap,
             hmac_device_stru    *pst_hmac_device
 �޸���ʷ      :
  1.��    ��   : 2015��5��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_void hmac_scan_proc_last_scan_record(hmac_device_stru *hmac_dev)
{
    oam_info_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event:: start clean last scan record.}");

    /* ����ɨ��������ʱ�������һ��ɨ�����й��ڵ�bss��Ϣ */
    hmac_scan_clean_expire_scanned_bss(&(hmac_dev->scan_mgmt.scan_record_mgmt), HI_FALSE);
    return;
}

/*****************************************************************************
 ��������  : host����ɨ������ʱ�䵽device�࣬��ֹ��˼�ͨ�š����¼����쳣�����host����ղ���
             ɨ����Ӧ�ĳ�ʱ�ص�������������ɨ��ģ���ڵĳ�ʱ����
 �޸���ʷ      :
  1.��    ��   : 2015��5��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 hmac_scan_proc_scan_timeout_fn(hi_void *arg)
{
    hmac_device_stru *hmac_dev = (hmac_device_stru *)arg;
    hmac_vap_stru *hmac_vap = HI_NULL;
    hmac_scan_record_stru *scan_record = HI_NULL;
    hi_u32 pedding_data = 0;

    /* ��ȡɨ���¼��Ϣ */
    scan_record = &(hmac_dev->scan_mgmt.scan_record_mgmt);

    /* ���·�����ANYɨ�裬����ɨ���ʱ��ָ���־Ϊ��ANYɨ�裬���·��ķ�ANYɨ�裬���︳��ֵ��Ӱ�� */
    scan_record->is_any_scan = HI_FALSE;

    /* ��ȡhmac vap */
    hmac_vap = hmac_vap_get_vap_stru(scan_record->vap_id);
    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(scan_record->vap_id, OAM_SF_SCAN, "{hmac_scan_proc_scan_timeout_fn::pst_hmac_vap null.}");

        /* ɨ��״̬�ָ�Ϊδ��ִ�е�״̬ */
        hmac_dev->scan_mgmt.is_scanning = HI_FALSE;
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���ݵ�ǰɨ������ͺ͵�ǰvap��״̬�������л�vap��״̬�������ǰ��ɨ�裬����Ҫ�л�vap��״̬ */
    if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        if (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_STA_WAIT_SCAN) {
            /* �ı�vap״̬��SCAN_COMP */
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_SCAN_COMP);
        } else if (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_UP) {
            /* ����ɨ��ʱ��Ҫ����֡���˵����� */
            hmac_set_rx_filter_value(hmac_vap->base_vap);
        }
    }

    /* 1102 ��Ϊap ��40M ������ִ��ɨ�裬ɨ����ɺ�VAP ״̬�޸�Ϊɨ��ǰ��״̬ */
    if (((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
         || (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
        ) && (scan_record->vap_last_state != MAC_VAP_STATE_BUTT)) {
        hmac_fsm_change_state(hmac_vap, scan_record->vap_last_state);
        scan_record->vap_last_state = MAC_VAP_STATE_BUTT;
    }
    /* 1102 ��Ϊap ��40M ������ִ��ɨ�裬ɨ����ɺ�VAP ״̬�޸�Ϊɨ��ǰ��״̬ */
    /* ����ɨ����Ӧ״̬Ϊ��ʱ */
    scan_record->scan_rsp_status = MAC_SCAN_TIMEOUT;
    oam_warning_log1(scan_record->vap_id, OAM_SF_SCAN,
                     "{hmac_scan_proc_scan_timeout_fn::scan time out cookie [%x].}", scan_record->ull_cookie);

    /* ���ɨ��ص�������Ϊ�գ�����ûص����� */
    if (scan_record->fn_cb != HI_NULL) {
        oam_warning_log0(scan_record->vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_scan_timeout_fn::scan callback func proc.}");
        scan_record->fn_cb(scan_record);
    }

    /* DMAC ��ʱδ�ϱ�ɨ����ɣ�HMAC �·�ɨ��������ֹͣDMAC ɨ�� */
    hmac_config_scan_abort(hmac_vap->base_vap, sizeof(hi_u32), (hi_u8 *)&pedding_data);

    /* ɨ��״̬�ָ�Ϊδ��ִ�е�״̬ */
    hmac_dev->scan_mgmt.is_scanning = HI_FALSE;

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��дɨ�������¼���֪ͨdmac����ɨ��
*****************************************************************************/
hi_u32 hmac_scan_dispatch_req_event(const hmac_vap_stru *hmac_vap, const mac_scan_req_stru *scan_params)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    mac_scan_req_stru *h2d_scan_req_params = HI_NULL; /* hmac���͵�dmac��ɨ��������� */
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    hi_u32 scan_timeout;

    /* ��ɨ�������¼���DMAC, �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(mac_scan_req_stru));
    if (event_mem == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event::event_mem null.}");
        /* �ָ�ɨ��״̬Ϊ������״̬ */
        hmac_dev->scan_mgmt.is_scanning = HI_FALSE;
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;
    frw_event_hdr_init(&(event->event_hdr), FRW_EVENT_TYPE_WLAN_CTX, DMAC_WLAN_CTX_EVENT_SUB_TYPE_SCAN_REQ,
                       sizeof(mac_scan_req_stru), FRW_EVENT_PIPELINE_STAGE_1, hmac_vap->base_vap->vap_id);
    h2d_scan_req_params = (mac_scan_req_stru *)(event->auc_event_data);
    /* ����ɨ������������¼�data���� */
    /* h2d_scan_req_params: event->auc_event_data, �ɱ����� */
    if (memcpy_s(h2d_scan_req_params, sizeof(mac_scan_req_stru), scan_params, sizeof(mac_scan_req_stru)) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CFG, "hmac_scan_proc_scan_req_event:: pst_scan_params memcpy_s fail.");
        return HI_FAIL;
    }

    /* �����P2P ���������������HMAC ɨ�賬ʱʱ��ΪP2P ����ʱ�� */
    if (MAC_SCAN_FUNC_P2P_LISTEN == scan_params->scan_func) {
        scan_timeout = scan_params->us_scan_time * 2; /* 2����������ʱ�� */
    } else {
        scan_timeout = WLAN_MAX_TIME_PER_SCAN;
    }

    oam_warning_log4(scan_params->vap_id, OAM_SF_SCAN,
                     "Scan_params::Now Scan channel_num[%d] p2p_scan[%d],scan_cnt_per_ch[%d],need back home_ch[%d]!",
                     scan_params->channel_nums, scan_params->is_p2p0_scan, scan_params->max_scan_cnt_per_channel,
                     scan_params->need_switch_back_home_channel);

    /* ����ɨ�豣����ʱ������ֹ���¼����˼�ͨ��ʧ�ܵ�����µ��쳣��������ʱ�������ĳ�ʱʱ��Ϊ4.5�� */
    frw_timer_create_timer(&(hmac_dev->scan_mgmt.scan_timeout), hmac_scan_proc_scan_timeout_fn,
                           scan_timeout, hmac_dev, HI_FALSE);
    /* �����p2p listen ��¼��listen���ŵ� */
    if (MAC_SCAN_FUNC_P2P_LISTEN == scan_params->scan_func) {
        hmac_dev->scan_mgmt.p2p_listen_channel = scan_params->ast_channel_list[0];
    }
    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(mac_scan_req_stru));
    frw_event_free(event_mem);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ɨ������������
 �������  : pst_mac_device: ָ��device�ṹ��
             p_params: ����ɨ������Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��2��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_scan_proc_scan_req_event(hmac_vap_stru *hmac_vap, mac_scan_req_stru *scan_params)
{
    hmac_device_stru *hmac_dev = hmac_get_device_stru();
    mac_device_stru *mac_dev = mac_res_get_dev();
    hmac_scan_record_stru *scan_record = &(hmac_dev->scan_mgmt.scan_record_mgmt);
    hi_u8 is_random_mac_addr_scan;

    /* �쳣�ж�: ɨ����ŵ�����Ϊ0 */
    if (scan_params->channel_nums == 0) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event::channel_nums=0.}");
        return HI_FAIL;
    }

    /* ���´˴�ɨ�������ɨ����� */
    is_random_mac_addr_scan = hmac_dev->scan_mgmt.is_random_mac_addr_scan;
    if (scan_params->scan_func == MAC_SCAN_FUNC_P2P_LISTEN) {
        /* DTS2017042708713:����״̬�²��������MAC��ַɨ�裬����wlan0 ����״̬�·��͹���֡ʧ�� */
        is_random_mac_addr_scan = HI_FALSE;
    }
    if (hmac_scan_update_scan_params(hmac_vap, scan_params, is_random_mac_addr_scan) != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_scan_req_event::update scan mode failed.}");
        return HI_FAIL;
    }

    /* ����Ƿ���Ϸ���ɨ���������������������ϣ�ֱ�ӷ��� */
    if (hmac_scan_check_is_dispatch_scan_req(hmac_vap, hmac_dev) != HI_SUCCESS) {
        if (scan_params->scan_func == MAC_SCAN_FUNC_P2P_LISTEN) {
            mac_vap_state_change(hmac_vap->base_vap, mac_dev->p2p_info.last_vap_state);
        }
        oam_warning_log0(0, OAM_SF_SCAN,  "{hmac_scan_proc_scan_req_event:: can't dispatch scan req.}");
        return HI_FAIL;
    }

    /* ����ɨ��ģ�鴦��ɨ��״̬������ɨ�����󽫶��� */
    hmac_dev->scan_mgmt.is_scanning = HI_TRUE;
    /* ������һ��ɨ���¼��Ŀǰֱ�������һ�ν��������������Ҫ�ϻ�ʱ�䴦�� */
    hmac_scan_proc_last_scan_record(hmac_dev);
    /* ��¼ɨ�跢���ߵ���Ϣ��ĳЩģ��ص�����ʹ�� */
    scan_record->vap_id = scan_params->vap_id;
    scan_record->chan_numbers = scan_params->channel_nums;
    scan_record->fn_cb = scan_params->fn_cb;

    if (is_ap(hmac_vap->base_vap)) {
        oam_warning_log1(0, 0, "{hmac_scan_proc_scan_req_event::save vap_state:%d}", hmac_vap->base_vap->vap_state);
        scan_record->vap_last_state = hmac_vap->base_vap->vap_state;
    }

    scan_record->ull_cookie = scan_params->ull_cookie;
    /* �������ɨ���vap��ģʽΪsta�����ң������״̬Ϊ��up״̬���ҷ�p2p����״̬�����л���ɨ��״̬ */
    if (is_sta(hmac_vap->base_vap) && (scan_params->scan_func != MAC_SCAN_FUNC_P2P_LISTEN)) {
        if (hmac_vap->base_vap->vap_state != MAC_VAP_STATE_UP) {
            /* �л�vap��״̬ΪWAIT_SCAN״̬ */
            hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_WAIT_SCAN);
        } else {
            /* ����ɨ��ʱ��Ҫ����֡���˵����� */
            hmac_vap->base_vap->vap_state = MAC_VAP_STATE_STA_WAIT_SCAN;
            hmac_set_rx_filter_value(hmac_vap->base_vap);
            hmac_vap->base_vap->vap_state = MAC_VAP_STATE_UP;
        }
    }

    /* AP������ɨ�������⴦����hostapd�·�ɨ������ʱ��VAP������INIT״̬ */
    if (is_ap(hmac_vap->base_vap) && (hmac_vap->base_vap->vap_state == MAC_VAP_STATE_INIT)) {
        hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_AP_WAIT_START);
    }

    return hmac_scan_dispatch_req_event(hmac_vap, scan_params);
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ����pno����ɨ����������
 �������  : pst_mac_device: ָ��device�ṹ��
             p_params: ����ɨ������Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2015��6��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_scan_proc_sched_scan_req_event(const hmac_vap_stru *hmac_vap, const mac_pno_scan_stru *pno_scan_params)
{
    frw_event_mem_stru *event_mem = HI_NULL;
    frw_event_stru *event = HI_NULL;
    hmac_device_stru *hmac_dev = HI_NULL;
    hmac_scan_record_stru *scan_record = HI_NULL;
    hi_u32 ret;

    /* �ж�PNO����ɨ���·��Ĺ��˵�ssid����С�ڵ���0 */
    if (pno_scan_params->l_ssid_count <= 0) {
        oam_warning_log0(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_sched_scan_req_event::ssid_count <=0.}");
        return HI_FAIL;
    }

    /* ��ȡhmac device */
    hmac_dev = hmac_get_device_stru();
    /* ����Ƿ���Ϸ���ɨ���������������������ϣ�ֱ�ӷ��� */
    ret = hmac_scan_check_is_dispatch_scan_req(hmac_vap, hmac_dev);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
                         "{hmac_scan_proc_sched_scan_req_event::Because of error[%d], can't dispatch scan req.}",
                         ret);
        return ret;
    }

    /* �����һ�ε�ɨ���� */
    hmac_scan_proc_last_scan_record(hmac_dev);

    /* ��¼ɨ�跢���ߵ���Ϣ��ĳЩģ��ص�����ʹ�� */
    scan_record = &(hmac_dev->scan_mgmt.scan_record_mgmt);
    scan_record->vap_id = hmac_vap->base_vap->vap_id;
    scan_record->fn_cb = pno_scan_params->fn_cb;

    /* ��ɨ�������¼���DMAC, �����¼��ڴ� */
    event_mem = frw_event_alloc(sizeof(uintptr_t));
    if (event_mem == HI_NULL) {
        oam_error_log0(hmac_vap->base_vap->vap_id, OAM_SF_SCAN,
                       "{hmac_scan_proc_sched_scan_req_event::event_mem null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д�¼� */
    event = (frw_event_stru *)event_mem->puc_data;

    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_WLAN_CTX,
                       DMAC_WLAN_CTX_EVENT_SUB_TYPE_SCHED_SCAN_REQ,
                       sizeof(uintptr_t),
                       FRW_EVENT_PIPELINE_STAGE_1,
                       hmac_vap->base_vap->vap_id);

    /* �¼�data����Я��PNOɨ��������� */
    if (memcpy_s(frw_get_event_payload(event_mem), sizeof(mac_pno_scan_stru *), (hi_u8 *)&pno_scan_params,
                 sizeof(mac_pno_scan_stru *)) != EOK) {
        frw_event_free(event_mem);
        oam_error_log0(0, OAM_SF_CFG, "hmac_scan_proc_sched_scan_req_event:: pst_pno_scan_params memcpy_s fail.");
        return HI_FAIL;
    }

    /* �ַ��¼� */
    hcc_hmac_tx_control_event(event_mem, sizeof(uintptr_t));
    frw_event_free(event_mem);

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ɨ��ģ���ʼ��
 �޸���ʷ      :
  1.��    ��   : 2015��5��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_scan_init(hmac_device_stru *hmac_dev)
{
    hmac_scan_stru *scan_mgmt = HI_NULL;
    hmac_bss_mgmt_stru *bss_mgmt = HI_NULL;

    /* ��ʼ��ɨ�����ṹ����Ϣ */
    scan_mgmt = &(hmac_dev->scan_mgmt);
    scan_mgmt->is_scanning = HI_FALSE;
    scan_mgmt->request = HI_NULL;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    scan_mgmt->sched_scan_req = HI_NULL;
#endif
    scan_mgmt->complete = HI_TRUE;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    scan_mgmt->sched_scan_complete = HI_TRUE;
    oal_spin_lock_init(&scan_mgmt->st_scan_request_spinlock);
#endif
    scan_mgmt->scan_record_mgmt.vap_last_state = MAC_VAP_STATE_BUTT;
    scan_mgmt->is_random_mac_addr_scan = HI_FALSE; /* ���mac ɨ�迪�أ�Ĭ�Ϲر� */
    scan_mgmt->scan_record_mgmt.is_any_scan = HI_FALSE;
    /* ��ʼ��bss������������� */
    bss_mgmt = &(scan_mgmt->scan_record_mgmt.bss_mgmt);
    hi_list_init(&(bss_mgmt->bss_list_head));
    oal_spin_lock_init(&bss_mgmt->st_lock);

    /* ��ʼ���ں��·�ɨ��request��Դ�� */
    return;
}

/*****************************************************************************
 ��������  : hmacɨ��ģ���˳�
 �޸���ʷ      :
  1.��    ��   : 2015��5��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_scan_exit(hmac_device_stru *hmac_dev)
{
    hmac_scan_stru *scan_mgmt = HI_NULL;

    scan_mgmt = &(hmac_dev->scan_mgmt);

    /* ���ɨ���¼��Ϣ */
    hmac_scan_clean_scan_record(&scan_mgmt->scan_record_mgmt);

    /* ɾ��ɨ�賬ʱ������ʱ�� */
    if (scan_mgmt->scan_timeout.is_registerd == HI_TRUE) {
        frw_timer_immediate_destroy_timer(&(scan_mgmt->scan_timeout));
    }

    /* ���ɨ�����ṹ����Ϣ */
    if (scan_mgmt->request == HI_NULL) {
        return;
    }
    if (scan_mgmt->request->ie != HI_NULL) {
        oal_free(scan_mgmt->request->ie);
        scan_mgmt->request->ie = HI_NULL;
    }
    if (scan_mgmt->request->ssids != HI_NULL) {
        oal_free(scan_mgmt->request->ssids);
        scan_mgmt->request->ssids = HI_NULL;
    }
    oal_free(scan_mgmt->request);

    scan_mgmt->request = HI_NULL;
    scan_mgmt->is_scanning = HI_FALSE;
    scan_mgmt->complete = HI_TRUE;
}
#ifdef _PRE_WLAN_FEATURE_SCAN_BY_SSID
static hi_void hmac_scan_proc_check_prefix_ssid(hmac_scanned_bss_info *scanned_bss,
                                                const oal_cfg80211_ssid_stru *req_ssid,
                                                const hi_u8 *puc_ssid,
                                                hi_u8 ssid_len)
{
    hi_u8 req_ssid_len;
    hi_u8 loop;

    if (oal_unlikely(puc_ssid == HI_NULL)) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_proc_check_prefix_ssid::puc_ssid null.}");
        return;
    }

    if (oal_unlikely(req_ssid == HI_NULL)) {
        return;
    }
    req_ssid_len = req_ssid[0].ssid_len;
    if (req_ssid_len <= ssid_len) {
        for (loop = 0; loop < req_ssid_len; loop++) {
            if (req_ssid[0].ssid[loop] != puc_ssid[loop]) {
                break;
            }
        }
        if (loop == req_ssid_len) {
            return;
        }
    }

    scanned_bss->bss_dscr_info.need_drop = HI_TRUE;
}

/*****************************************************************************
 ��������  : hmacɨ��ģ���ϱ�ǰ�ж�beacon/probe rsp�е�ssid��ָ��ssid��ɨ�������Ƿ�һ��
 �������  : hmac_scanned_bss_info *pst_scanned_bss :ɨ����Ϣ�ṹ��
                            hi_u8 *puc_ssid: ֡�е�ssid
                            hi_u8 uc_ssid_len:֡��ssid�ĳ���
 �޸���ʷ      :
  1.��    ��   : 2019��2��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void hmac_scan_proc_check_ssid(hmac_scanned_bss_info *scanned_bss, const hi_u8 *puc_ssid, hi_u8 ssid_len)
{
    hmac_scan_stru *scan_mgmt = HI_NULL;
    hmac_device_stru *hmac_dev = HI_NULL;
    hi_u32 l_index;
    hi_u8 req_ssid_len;
    oal_cfg80211_ssid_stru *ssids = HI_NULL;

    /* ��ȡhmac device �ṹ */
    hmac_dev = hmac_get_device_stru();
    scan_mgmt = &(hmac_dev->scan_mgmt);
    if (scan_mgmt->request == HI_NULL) {
        return;
    }

    /* ���·���ssid����ͨ��ssidʱ���������κι��� */
    for (l_index = 0; l_index < scan_mgmt->request->n_ssids; l_index++) {
        if (scan_mgmt->request->ssids[l_index].ssid[0] == '\0') {
            return;
        }
    }

    if (puc_ssid == HI_NULL) {
        scanned_bss->bss_dscr_info.need_drop = HI_TRUE;
        return;
    }

    ssids = scan_mgmt->request->ssids;
    hi_u32 l_ssid_num = scan_mgmt->request->n_ssids;

    /* �����ǰ׺ssidɨ��,��ִ��ǰ׺���˹��� */
    if (scan_mgmt->request->prefix_ssid_scan_flag == HI_TRUE) {
        hmac_scan_proc_check_prefix_ssid(scanned_bss, ssids, puc_ssid, ssid_len);
        return;
    }
    /* pst_request �������ж�ָ��ssidɨ��������֮ǰ��ֵ������������м�� */
    /* ���δָ��ssid,��ֱ�ӷ��� */
    if (l_ssid_num == 0) {
        return;
    }

    if (l_ssid_num > WLAN_SCAN_REQ_MAX_BSS) {
        /* ����û��·���ָ��ssid�ĸ�����������֧�ֵ�����������ȡ����֧�ֵ�ָ��ssid�������� */
        l_ssid_num = WLAN_SCAN_REQ_MAX_BSS;
    }

    for (l_index = 0; l_index < l_ssid_num; l_index++) {
        req_ssid_len = ssids[l_index].ssid_len;
        if (req_ssid_len > OAL_IEEE80211_MAX_SSID_LEN) {
            req_ssid_len = OAL_IEEE80211_MAX_SSID_LEN;
        }

        if (req_ssid_len != ssid_len) {
            continue;
        }

        if (memcmp(puc_ssid, ssids[l_index].ssid, req_ssid_len) != 0) {
            continue;
        } else {
            return;
        }
    }

    scanned_bss->bss_dscr_info.need_drop = HI_TRUE;
    return;
}
#endif /* #ifdef _PRE_WLAN_FEATURE_SCAN_BY_SSID */

hi_u32 hmac_scan_clean_result(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param)
{
    hmac_device_stru *hmac_dev  = hmac_get_device_stru();

    hi_unref_param(mac_vap);
    hi_unref_param(us_len);
    hi_unref_param(puc_param);

    if (hmac_dev == HI_NULL) {
        oam_error_log0(0, OAM_SF_SCAN, "{hmac_scan_clean_result::hmac_dev null.}");
        return HI_ERR_CODE_PTR_NULL;
    }
    oam_info_log0(0, OAM_SF_SCAN, "{hmac_scan_clean_result::clean driver scan results.}");
    hmac_scan_clean_expire_scanned_bss(&(hmac_dev->scan_mgmt.scan_record_mgmt), HI_TRUE);
    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
