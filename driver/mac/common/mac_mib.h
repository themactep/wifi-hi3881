/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for mac_mib.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __MAC_MIB_H__
#define __MAC_MIB_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "wlan_mib.h"
#include "oam_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  ������������
*****************************************************************************/
/*****************************************************************************
 ��������  : ����wep MIB��Ϣ
*****************************************************************************/
static inline hi_void mac_mib_set_wep(const mac_vap_stru *mac_vap, hi_u8 key_id)
{
    mac_vap->mib_info->ast_wlan_mib_wep_dflt_key[key_id].auc_dot11_wep_default_key_value[WLAN_WEP_SIZE_OFFSET] =
        40; /* ��ʼ��wep���MIB��ϢΪ40 */
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11_rsna_config_group_cipher ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_rsnacfggroupcipher(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11_rsna_config_group_cipher ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_rsnacfggroupcipher(const mac_vap_stru *mac_vap, hi_u8 group_cipher)
{
    mac_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_config_group_cipher = group_cipher;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11_wep_default_key_id ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_wep_default_keyid(const mac_vap_stru *mac_vap, hi_u8 default_key_id)
{
    mac_vap->mib_info->wlan_mib_privacy.dot11_wep_default_key_id = default_key_id;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11_wep_default_key_id ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_wep_default_keyid(const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->wlan_mib_privacy.dot11_wep_default_key_id);
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11_wep_default_key_id ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_wep_type(const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->wlan_mib_privacy.dot11_wep_default_key_id);
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11_rsna_config_group_cipher ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_privacyinvoked(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11_privacy_invoked ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_privacyinvoked(const mac_vap_stru *mac_vap, hi_u8 privacyinvoked)
{
    mac_vap->mib_info->wlan_mib_privacy.dot11_privacy_invoked = privacyinvoked;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11_rsna_activated ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_rsnaactivated(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11_rsna_activated ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_rsnaactivated(const mac_vap_stru *mac_vap, hi_u8 rsnaactivated)
{
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated = rsnaactivated;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11StationID ��ֵ
*****************************************************************************/
static inline hi_u8 *mac_mib_get_station_id(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11OBSSScanPassiveDwell ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_obssscan_passive_dwell(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_passive_dwell;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11OBSSScanPassiveDwell ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_obssscan_passive_dwell(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_passive_dwell = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11OBSSScanActiveDwell ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_obssscan_active_dwell(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_active_dwell;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11OBSSScanActiveDwell ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_obssscan_active_dwell(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_active_dwell = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11BSSWidthTriggerScanInterval ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_bsswidth_trigger_scan_interval(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_bss_width_trigger_scan_interval;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11BSSWidthTriggerScanInterval ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_bsswidth_trigger_scan_interval(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_bss_width_trigger_scan_interval = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11OBSSScanPassiveTotalPerChannel ��ֵ
 �޸���ʷ      :
  1.��    ��   : 2014��2��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u32 mac_mib_get_obssscan_passive_total_per_channel(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_passive_total_per_channel;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11OBSSScanPassiveTotalPerChannel ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_obssscan_passive_total_per_channel(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_passive_total_per_channel = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11OBSSScanActiveTotalPerChannel ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_obssscan_active_total_per_channel(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_active_total_per_channel;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11OBSSScanActiveTotalPerChannel ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_obssscan_active_total_per_channel(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_active_total_per_channel = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11BSSWidthChannelTransitionDelayFactor ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_bsswidth_channel_transition_delay_factor(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_bss_width_channel_transition_delay_factor;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11BSSWidthChannelTransitionDelayFactor ��ֵ
*****************************************************************************/
static inline hi_void  mac_mib_set_bsswidth_channel_transition_delay_factor(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_bss_width_channel_transition_delay_factor = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11OBSSScanActivityThreshold ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_obssscan_activity_threshold(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_activity_threshold;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11OBSSScanActivityThreshold ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_obssscan_activity_threshold(const mac_vap_stru *mac_vap, hi_u32 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_obss_scan_activity_threshold = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11HighThroughputOptionImplemented ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_high_throughput_option_implemented(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11HighThroughputOptionImplemented ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_high_throughput_option_implemented(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_sta_config.dot11_high_throughput_option_implemented = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11FortyMHzOperationImplemented ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_forty_mhz_operation_implemented(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->phy_ht.dot112_g_forty_m_hz_operation_implemented;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11FortyMHzOperationImplemented ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_forty_mhz_operation_implemented(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->phy_ht.dot112_g_forty_m_hz_operation_implemented = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11SpectrumManagementImplemented ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_spectrum_management_implemented(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_implemented;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11SpectrumManagementImplemented ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_spectrum_management_implemented(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_implemented = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11FortyMHzIntolerant ��ֵ
 �޸���ʷ      :
  1.��    ��   : 2014��2��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static inline hi_u8 mac_mib_get_forty_mhz_intolerant(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot11_forty_m_hz_intolerant;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11FortyMHzIntolerant ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_forty_mhz_intolerant(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_forty_m_hz_intolerant = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot112040BSSCoexistenceManagementSupport ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_2040bss_coexistence_management_support(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_operation.dot112040_bss_coexistence_management_support;
}
 /*****************************************************************************
 ��������  : ��ȡMIB�� dot11RSNAActivated ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_dot11_rsna_activated(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11RSNAActivated ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_dot11_rsnaactivated(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsna_activated = val;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11RSNAMFPC ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_dot11_rsnamfpc(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpc = val;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11RSNAMFPR��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_dot11_rsnamfpr(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_privacy.dot11_rsnamfpr = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11AssociationSAQueryMaximumTimeout ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_dot11_association_saquery_maximum_timeout(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_association_sa_query_maximum_timeout;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� dot11AssociationSAQueryRetryTimeout ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_dot11_association_saquery_retry_timeout(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_association_sa_query_retry_timeout;
}

/*****************************************************************************
 ��������  : ����MIB�� dot112040BSSCoexistenceManagementSupport ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_2040bss_coexistence_management_support(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_operation.dot112040_bss_coexistence_management_support = val;
}

/*****************************************************************************
 ��������  : ��ȡMIB�� ul_dot11DTIMPeriod ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_dot11dtimperiod(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_dtim_period;
}

/*****************************************************************************
 ��������  : ��ʼ��֧��2040����
*****************************************************************************/
static inline hi_void mac_mib_init_2040(const mac_vap_stru *mac_vap)
{
    mac_mib_set_forty_mhz_intolerant(mac_vap, HI_FALSE);
    mac_mib_set_spectrum_management_implemented(mac_vap, HI_TRUE);
    mac_mib_set_2040bss_coexistence_management_support(mac_vap, HI_FALSE);
}

/*****************************************************************************
 ��������  : ����MIB�� ul_dot11DTIMPeriod ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_dot11dtimperiod(const mac_vap_stru *mac_vap, hi_u32 val)
{
    if (val != 0) {
        mac_vap->mib_info->wlan_mib_sta_config.dot11_dtim_period = val;
    }
}

/*****************************************************************************
 ��������  : ��ȡMIB�� ul_dot11DTIMPeriod ��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_powermanagementmode(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_power_management_mode;
}

/*****************************************************************************
 ��������  : ����MIB�� ul_dot11DTIMPeriod ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_powermanagementmode(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_sta_config.dot11_power_management_mode = val;
}

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
/*****************************************************************************
 ��������  : ��ȡMIB�� dot11OperatingModeNotificationImplemented ��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_operating_mode_notification_implemented(mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_sta_config.dot11_operating_mode_notification_implemented;
}

/*****************************************************************************
 ��������  : ����MIB�� dot11OperatingModeNotificationImplemented ��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_operating_mode_notification_implemented(mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_sta_config.dot11_operating_mode_notification_implemented = val;
}
#endif

/*****************************************************************************
 ��������  : ��ȡLsigTxopFullProtectionActivatedֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_lsig_txop_full_protection_activated(const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->wlan_mib_operation.dot11_lsigtxop_full_protection_activated);
}

/*****************************************************************************
 ��������  : ����LsigTxopFullProtectionActivatedֵ
*****************************************************************************/
static inline hi_void mac_mib_set_lsig_txop_full_protection_activated(const mac_vap_stru *mac_vap,
    hi_u8 lsig_txop_full_protection_activated)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_lsigtxop_full_protection_activated =
        lsig_txop_full_protection_activated;
}

/*****************************************************************************
 ��������  : ��ȡNonGFEntitiesPresentֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_non_gfentities_present(const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->wlan_mib_operation.dot11_non_gf_entities_present);
}

/*****************************************************************************
 ��������  : ����NonGFEntitiesPresentֵ
*****************************************************************************/
static inline hi_void mac_mib_set_non_gfentities_present(const mac_vap_stru *mac_vap, hi_u8 non_gf_entities_present)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_non_gf_entities_present = non_gf_entities_present;
}

/*****************************************************************************
 ��������  : ��ȡRIFSModeֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_rifs_mode(const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->wlan_mib_operation.dot11_rifs_mode);
}

/*****************************************************************************
 ��������  : ����RIFSModeֵ
*****************************************************************************/
static inline hi_void mac_mib_set_rifs_mode(const mac_vap_stru *mac_vap, hi_u8 rifs_mode)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_rifs_mode = rifs_mode;
}

/*****************************************************************************
 ��������  : ��ȡhtProtectionֵ
*****************************************************************************/
static inline wlan_mib_ht_protection_enum_uint8 mac_mib_get_ht_protection(const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->wlan_mib_operation.dot11_ht_protection);
}

/*****************************************************************************
 ��������  : ����htProtectionֵ
*****************************************************************************/
static inline hi_void mac_mib_set_ht_protection(const mac_vap_stru *mac_vap,
    wlan_mib_ht_protection_enum_uint8 ht_protection)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_ht_protection = ht_protection;
}

/*****************************************************************************
 ��������  : ��ȡShortPreambleOptionImplementedֵ
*****************************************************************************/
static inline wlan_11b_mib_preamble_enum_uint8 mac_mib_get_short_preamble_option_implemented(
    const mac_vap_stru *mac_vap)
{
    return (mac_vap->mib_info->phy_hrdsss.dot11_short_preamble_option_implemented);
}

/*****************************************************************************
 ��������  : ����ShortPreambleOptionImplementedֵ
*****************************************************************************/
static inline hi_void mac_mib_set_short_preamble_option_implemented(const mac_vap_stru *mac_vap,
    wlan_11b_mib_preamble_enum_uint8 preamble)
{
    mac_vap->mib_info->phy_hrdsss.dot11_short_preamble_option_implemented = preamble;
}

/*****************************************************************************
 ��������  : ����en_dot11SpectrumManagementRequiredֵ
*****************************************************************************/
static inline hi_void mac_mib_set_spectrum_management_required(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_sta_config.dot11_spectrum_management_required = val;
}

/*****************************************************************************
 ��������  : ��ȡen_dot11ShortGIOptionInFortyImplementedֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_shortgi_option_in_forty_implemented(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->phy_ht.dot112_g_short_gi_option_in_forty_implemented;
}

/*****************************************************************************
 ��������  : ����en_dot11ShortGIOptionInFortyImplementedֵ
*****************************************************************************/
static inline hi_void mac_mib_set_shortgi_option_in_forty_implemented(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->phy_ht.dot112_g_short_gi_option_in_forty_implemented = val;
}

/*****************************************************************************
 ��������  : ���÷�Ƭ����ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_frag_threshold(const mac_vap_stru *mac_vap, hi_u32 frag_threshold)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_fragmentation_threshold = frag_threshold;
}

/*****************************************************************************
 ��������  : ����RTS����ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_rts_threshold(const mac_vap_stru *mac_vap, hi_u32 rts_threshold)
{
    mac_vap->mib_info->wlan_mib_operation.dot11_rts_threshold = rts_threshold;
}

#ifdef _PRE_WLAN_FEATURE_MESH_ROM
/*****************************************************************************
 ��������  : ����Mesh Privacyֵ
*****************************************************************************/
static inline hi_void mac_mib_set_mesh_security(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_security_activated = val;
}

/*****************************************************************************
 ��������  : ����Mesh Auth Protocolֵ
*****************************************************************************/
static inline hi_void mac_mib_set_mesh_auth_protocol(const mac_vap_stru *mac_vap, hi_u8 auth_protocol)
{
    mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol = auth_protocol;
}

/*****************************************************************************
 ��������  : ���Mesh Auth Protocolֵ
*****************************************************************************/
static inline hi_void mac_mib_clear_mesh_auth_protocol(const mac_vap_stru *mac_vap)
{
    mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_active_authentication_protocol = 0;
}

/*****************************************************************************
 ��������  : ����Accpeting Peerֵ
*****************************************************************************/
static inline hi_void mac_mib_set_accepting_peer(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_accepting_additional_peerings = val;
}

/*****************************************************************************
 ��������  : ��ȡAccpeting Peerֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_accepting_peer(const mac_vap_stru *mac_vap)
{
    return mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mesh_accepting_additional_peerings;
}

/*****************************************************************************
 ��������  : ����MBCAֵ
*****************************************************************************/
static inline hi_void mac_mib_set_mbca_en(const mac_vap_stru *mac_vap, hi_u8 val)
{
    mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mbca_activated = val;
}

/*****************************************************************************
 ��������  : ��ȡMBCAֵ
*****************************************************************************/
static inline hi_void mac_mib_get_mbca_en(const mac_vap_stru *mac_vap, hi_u8* val)
{
    *val = mac_vap->mib_info->wlan_mib_mesh_sta_cfg.dot11_mbca_activated;
}
#endif

/*****************************************************************************
 ��������  : ����StationIDֵ����mac��ַ
*****************************************************************************/
static inline hi_void mac_mib_set_station_id(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    mac_cfg_staion_id_param_stru  *param = HI_NULL;

    hi_unref_param(len);
    param = (mac_cfg_staion_id_param_stru *)puc_param;
    if (memcpy_s(mac_vap->mib_info->wlan_mib_sta_config.auc_dot11_station_id, WLAN_MAC_ADDR_LEN,
                 param->auc_station_id, WLAN_MAC_ADDR_LEN) != EOK) {
        return;
    }
}

/*****************************************************************************
 ��������  : ����bss type mibֵ
*****************************************************************************/
static inline hi_void mac_mib_set_bss_type(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hi_s32       l_value;
    hi_unref_param(len);
    l_value = *((hi_s32 *)puc_param);
    mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type = (hi_u8)l_value;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ����beacon interval��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_beacon_period(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hi_u32       value;
    hi_unref_param(len);
    value     = *((hi_u32 *)puc_param);
    mac_vap->mib_info->wlan_mib_sta_config.dot11_beacon_period = (hi_u32)value;
}

/*****************************************************************************
 ��������  : ����dtim period��ֵ
*****************************************************************************/
static inline hi_void mac_mib_set_dtim_period(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hi_s32       l_value;
    hi_unref_param(len);
    l_value     = *((hi_s32 *)puc_param);
    mac_vap->mib_info->wlan_mib_sta_config.dot11_dtim_period = (hi_u32)l_value;
}

/*****************************************************************************
 ��������  : ����short preamble MIBֵ
*****************************************************************************/
static inline hi_void mac_mib_set_shpreamble(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param)
{
    hi_s32       l_value;
    hi_unref_param(len);
    l_value     = *((hi_s32 *)puc_param);
    if (l_value != 0) {
        mac_mib_set_short_preamble_option_implemented(mac_vap, HI_TRUE);
    } else {
        mac_mib_set_short_preamble_option_implemented(mac_vap, HI_FALSE);
    }
}
#endif

/*****************************************************************************
 ��������  : ��ȡĬ����Կ�Ĵ�С
*****************************************************************************/
static inline hi_u8 mac_mib_get_wep_default_keysize(const mac_vap_stru *mac_vap)
{
    wlan_mib_dot11_wep_default_keys_entry_stru *pwlan_mib_wep_dflt_key =
        mac_vap->mib_info->ast_wlan_mib_wep_dflt_key;
    return (
        pwlan_mib_wep_dflt_key[mac_mib_get_wep_type(mac_vap)].auc_dot11_wep_default_key_value[WLAN_WEP_SIZE_OFFSET]);
}

/*****************************************************************************
 ��������  : ��ȡָ�����кŵ�wep key��ֵ
*****************************************************************************/
static inline hi_u8 mac_mib_get_wep_keysize(const mac_vap_stru *mac_vap, hi_u8 idx)
{
    return (mac_vap->mib_info->ast_wlan_mib_wep_dflt_key[idx].auc_dot11_wep_default_key_value[WLAN_WEP_SIZE_OFFSET]);
}

/*****************************************************************************
 ��������  : ��� RSN��֤�׼�
*****************************************************************************/
static inline hi_void mac_mib_clear_rsna_auth_suite(const mac_vap_stru *mac_vap)
{
    hi_u8   index = 0;

    for (index = 0; index < WLAN_AUTHENTICATION_SUITES; index++) {
        mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[index].dot11_rsna_config_authentication_suite_activated   \
            = HI_FALSE;
        mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[index].dot11_rsna_config_authentication_suite_implemented \
            = 0xff;
    }
}

/*****************************************************************************
 ��������  : ����RSN��֤�׼�
*****************************************************************************/
static inline hi_void mac_mib_set_rsnaconfig_authentication_suite_implemented(const mac_vap_stru *mac_vap,
    hi_u8 inp, hi_u8 idx)
{
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[idx].dot11_rsna_config_authentication_suite_activated = HI_TRUE;
    mac_vap->mib_info->ast_wlan_mib_rsna_cfg_auth_suite[idx].dot11_rsna_config_authentication_suite_implemented = inp;
}

/*****************************************************************************
 ��������  : ����RSN��֤�׼�
*****************************************************************************/
static inline hi_void mac_mib_set_rsnaclear_wpa_pairwise_cipher_implemented(const mac_vap_stru *mac_vap)
{
    hi_u8 index;
    wlan_mib_dot11_rsna_cfg_pwise_cpher_en_stru *wlan_mib_rsna_cfg_wpa_pairwise_cipher =
        mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa_pairwise_cipher;

    for (index = 0; index < WLAN_PAIRWISE_CIPHER_SUITES; index++) {
        wlan_mib_rsna_cfg_wpa_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_implemented = 0xFF;
        wlan_mib_rsna_cfg_wpa_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_activated = HI_FALSE;
    }
}

/*****************************************************************************
 ��������  : ����RSN WPA2��֤�׼�
*****************************************************************************/
static inline hi_void mac_mib_set_rsnaclear_wpa2_pairwise_cipher_implemented(const mac_vap_stru *mac_vap)
{
    hi_u8 index;
    wlan_mib_dot11_rsna_cfg_pwise_cpher_en_stru *wlan_mib_rsna_cfg_wpa2_pairwise_cipher =
        mac_vap->mib_info->ast_wlan_mib_rsna_cfg_wpa2_pairwise_cipher;

    for (index = 0; index < WLAN_PAIRWISE_CIPHER_SUITES; index++) {
        wlan_mib_rsna_cfg_wpa2_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_implemented = 0xFF;
        wlan_mib_rsna_cfg_wpa2_pairwise_cipher[index].dot11_rsna_config_pairwise_cipher_activated = HI_FALSE;
    }
}

/*****************************************************************************
 ��������  : ��ȡbss type mibֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_bss_type(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param)
{
    *((hi_s32 *)puc_param) = mac_vap->mib_info->wlan_mib_sta_config.dot11_desired_bss_type;
    *puc_len = sizeof(hi_s32);
    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ��ȡbeacon interval��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_beacon_period(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param)
{
    *((hi_u32 *)puc_param) = mac_vap->mib_info->wlan_mib_sta_config.dot11_beacon_period;
    *puc_len = sizeof(hi_u32);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡdtim period��ֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_dtim_period(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param)
{
    *((hi_u32 *)puc_param) = mac_vap->mib_info->wlan_mib_sta_config.dot11_dtim_period;
    *puc_len = sizeof(hi_u32);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡshort preamble MIBֵ
*****************************************************************************/
static inline hi_u32 mac_mib_get_shpreamble(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param)
{
    hi_s32       l_value;
    l_value = mac_mib_get_short_preamble_option_implemented(mac_vap);
    *((hi_s32 *)puc_param) = l_value;
    *puc_len = sizeof(l_value);
    return HI_SUCCESS;
}
#endif

static inline hi_u8 mac_is_wep_enabled(const mac_vap_stru *mac_vap)
{
    if (!mac_mib_get_privacyinvoked(mac_vap) || mac_mib_get_rsnaactivated(mac_vap)) {
        return HI_FALSE;
    }
    return HI_TRUE;
}

/*****************************************************************************
 ��������  : ��ȡwep type��ֵ
*****************************************************************************/
static inline wlan_ciper_protocol_type_enum_uint8 mac_get_wep_type(const mac_vap_stru *mac_vap, hi_u8 key_id)
{
    if (mac_mib_get_wep_keysize(mac_vap, key_id) == 104) { /* sizeλ104 */
        return WLAN_80211_CIPHER_SUITE_WEP_104;
    } else {
        return WLAN_80211_CIPHER_SUITE_WEP_40;
    }
}

/*****************************************************************************
  ��������
*****************************************************************************/
hi_u32 mac_mib_set_meshid(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param);
hi_u32 mac_mib_get_meshid(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param);
hi_void mac_mib_get_wpa_pairwise_cipher_suite(const mac_vap_stru *mac_vap, hi_u8 *puc_num);
hi_void mac_mib_get_wpa2_pairwise_cipher_suite(const mac_vap_stru *mac_vap, hi_u8 *puc_num);
hi_void mac_mib_get_authentication_suite(const mac_vap_stru *mac_vap, hi_u8 *puc_num);
hi_void mac_mib_get_wpa2_pairwise_cipher_suite_value(const mac_vap_stru *mac_vap, hi_u8 *puc_pairwise_value,
    hi_u8 pairwise_len);
hi_void mac_mib_get_wpa_pairwise_cipher_suite_value(const mac_vap_stru *mac_vap, hi_u8 *puc_pairwise_value,
                                                    hi_u8 pairwise_len);
hi_void mac_mib_set_rsna_auth_suite(const mac_vap_stru *mac_vap, hi_u8 auth_value);
hi_u32 mac_mib_set_ssid(const mac_vap_stru *mac_vap, hi_u8 len, const hi_u8 *puc_param);
hi_void mac_mib_set_rsnaconfig_wpa_pairwise_cipher_implemented(const mac_vap_stru *mac_vap, hi_u8 pairwise_value);
hi_void mac_mib_set_rsnaconfig_wpa2_pairwise_cipher_implemented(const mac_vap_stru *mac_vap, hi_u8 pairwise_value);
hi_u32  mac_mib_get_ssid(const mac_vap_stru *mac_vap, hi_u8 *puc_len, const hi_u8 *puc_param);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* __MAC_MIB_H__ */

