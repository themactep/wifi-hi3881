/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Wal_hipriv configuration command.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "hmac_ext_if.h"
#include "wal_main.h"
#include "wal_hipriv.h"
#include "wal_ioctl.h"
#include "wal_event_msg.h"
#include "wal_11d.h"
#include "wal_net.h"
#include "oal_util.h"
#include "oal_net.h"
#include "oal_kernel_file.h"
#include "plat_pm_wlan.h"
#include "wal_customize.h"
#include "wal_cfg80211_apt.h"
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "hi_wifi_mfg_test_if.h"
#endif
#include "hi_wifi_api.h"
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "lwip/netifapi.h"
#endif
#include "plat_firmware.h"
#include "hi_at.h"
#include "mac_pm_driver.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
static hi_bool g_under_ps = HI_FALSE; /* �Ƿ��ڵ͹���״̬ */
static hi_u32 g_under_mfg = HI_FALSE; /* �Ƿ��ڲ���״̬ */

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static oal_proc_dir_entry_stru *g_proc_entry = HI_NULL;
struct kobject *g_gp_sys_kobject = HI_NULL;
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
static hi_ssize_t  wal_hipriv_sys_write(oal_device_stru *dev, oal_device_attribute_stru *attr,
    const char *buf, hi_size_t count);
static hi_ssize_t  wal_hipriv_sys_read(oal_device_stru *dev, oal_device_attribute_stru *attr, char *buf);
static DEVICE_ATTR(hipriv, (S_IRUGO|S_IWUSR), wal_hipriv_sys_read, wal_hipriv_sys_write);

static struct attribute *g_hipriv_sysfs_entries[] = {
    &dev_attr_hipriv.attr,
    HI_NULL
};
static struct attribute_group hipriv_attribute_group = {
        .attrs = g_hipriv_sysfs_entries,
};
#endif
#endif
hi_u32 g_auto_rate_flag = 1;  /* �Զ����ʵ���Ĭ�ϴ� */

static const hi_char *g_pauc_bw_tbl[WLAN_BAND_ASSEMBLE_AUTO] = {
    "20",
    "rsv1",
    "rsv2",
    "rsv3",
    "rsv4",
    "rsv5",
    "rsv6",
    "rsv7",
    "rsv8",
    "rsv9",
    "rsv10",
    "rsv11",
    "rsv12",
    "rsv13",
    "rsv14",
    "rsv15",
    "5",
    "10"
};

static const hi_char *g_pauc_non_ht_rate_tbl[WLAN_LEGACY_RATE_VALUE_BUTT] = {
    "1",
    "2",
    "5.5",
    "11",
    "rsv0",
    "rsv1",
    "rsv2",
    "rsv3",
    "48",
    "24",
    "12",
    "6",
    "54",
    "36",
    "18",
    "9"
};

#ifdef _PRE_WLAN_FEATURE_HIPRIV
static const wal_ioctl_alg_cfg_stru g_ast_alg_cfg_map[] = {
    {"sch_vi_ctrl_ena",         MAC_ALG_CFG_SCHEDULE_VI_CTRL_ENA, {0}},
    {"sch_bebk_minbw_ena",      MAC_ALG_CFG_SCHEDULE_BEBK_MIN_BW_ENA, {0}},
    {"sch_mvap_sch_ena",        MAC_ALG_CFG_SCHEDULE_MVAP_SCH_ENA, {0}},
    {"sch_vi_sch_ms",           MAC_ALG_CFG_SCHEDULE_VI_SCH_LIMIT, {0}},
    {"sch_vo_sch_ms",           MAC_ALG_CFG_SCHEDULE_VO_SCH_LIMIT, {0}},
    {"sch_vi_drop_ms",          MAC_ALG_CFG_SCHEDULE_VI_DROP_LIMIT, {0}},
    {"sch_vi_ctrl_ms",          MAC_ALG_CFG_SCHEDULE_VI_CTRL_MS, {0}},
    {"sch_vi_life_ms",          MAC_ALG_CFG_SCHEDULE_VI_MSDU_LIFE_MS, {0}},
    {"sch_vo_life_ms",          MAC_ALG_CFG_SCHEDULE_VO_MSDU_LIFE_MS, {0}},
    {"sch_be_life_ms",          MAC_ALG_CFG_SCHEDULE_BE_MSDU_LIFE_MS, {0}},
    {"sch_bk_life_ms",          MAC_ALG_CFG_SCHEDULE_BK_MSDU_LIFE_MS, {0}},
    {"sch_vi_low_delay",        MAC_ALG_CFG_SCHEDULE_VI_LOW_DELAY_MS, {0}},
    {"sch_vi_high_delay",       MAC_ALG_CFG_SCHEDULE_VI_HIGH_DELAY_MS, {0}},
    {"sch_cycle_ms",            MAC_ALG_CFG_SCHEDULE_SCH_CYCLE_MS, {0}},
    {"sch_ctrl_cycle_ms",       MAC_ALG_CFG_SCHEDULE_TRAFFIC_CTRL_CYCLE, {0}},
    {"sch_cir_nvip_kbps",       MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS, {0}},
    {"sch_cir_nvip_be",         MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS_BE, {0}},
    {"sch_cir_nvip_bk",         MAC_ALG_CFG_SCHEDULE_CIR_NVIP_KBPS_BK, {0}},
    {"sch_cir_vip_kbps",        MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS, {0}},
    {"sch_cir_vip_be",          MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS_BE, {0}},
    {"sch_cir_vip_bk",          MAC_ALG_CFG_SCHEDULE_CIR_VIP_KBPS_BK, {0}},
    {"sch_cir_vap_kbps",        MAC_ALG_CFG_SCHEDULE_CIR_VAP_KBPS, {0}},
    {"sch_sm_delay_ms",         MAC_ALG_CFG_SCHEDULE_SM_TRAIN_DELAY, {0}},
    {"sch_drop_pkt_limit",      MAC_ALG_CFG_VIDEO_DROP_PKT_LIMIT, {0}},
    {"sch_flowctl_ena",         MAC_ALG_CFG_FLOWCTRL_ENABLE_FLAG, {0}},
    {"sch_log_start",           MAC_ALG_CFG_SCHEDULE_LOG_START, {0}},
    {"sch_log_end",             MAC_ALG_CFG_SCHEDULE_LOG_END, {0}},
    {"sch_vap_prio",            MAC_ALG_CFG_SCHEDULE_VAP_SCH_PRIO, {0}},
    /* ������ر���������Ӧ�㷨: sh hipriv.sh "vap0 alg_cfg ar_enable [1|0]" */
    {"ar_enable",               MAC_ALG_CFG_AUTORATE_ENABLE, {0}},
    /* ������ر�ʹ���������: sh hipriv.sh "vap0 alg_cfg ar_use_lowest [1|0]" */
    {"ar_use_lowest",           MAC_ALG_CFG_AUTORATE_USE_LOWEST_RATE, {0}},
    /* ���ö���ͳ�Ƶİ���Ŀ:sh hipriv.sh "vap0 alg_cfg ar_short_num [����Ŀ]" */
    {"ar_short_num",            MAC_ALG_CFG_AUTORATE_SHORT_STAT_NUM, {0}},
    /* ���ö���ͳ�Ƶİ�λ��ֵ:sh hipriv.sh "vap0 alg_cfg ar_short_shift [λ��ֵ]" */
    {"ar_short_shift",          MAC_ALG_CFG_AUTORATE_SHORT_STAT_SHIFT, {0}},
    /* ���ó���ͳ�Ƶİ���Ŀ:sh hipriv.sh "vap0 alg_cfg ar_long_num [����Ŀ]" */
    {"ar_long_num",             MAC_ALG_CFG_AUTORATE_LONG_STAT_NUM, {0}},
    /* ���ó���ͳ�Ƶİ�λ��ֵ:sh hipriv.sh "vap0 alg_cfg ar_long_shift [λ��ֵ]" */
    {"ar_long_shift",           MAC_ALG_CFG_AUTORATE_LONG_STAT_SHIFT, {0}},
    /* ������С̽������:sh hipriv.sh "vap0 alg_cfg ar_min_probe_no [����Ŀ]" */
    {"ar_min_probe_no",         MAC_ALG_CFG_AUTORATE_MIN_PROBE_INTVL_PKTNUM, {0}},
    /* �������̽������:sh hipriv.sh "vap0 alg_cfg ar_max_probe_no [����Ŀ]" */
    {"ar_max_probe_no",         MAC_ALG_CFG_AUTORATE_MAX_PROBE_INTVL_PKTNUM, {0}},
    /* ����̽�������ִ���:sh hipriv.sh "vap0 alg_cfg ar_keep_times [����]" */
    {"ar_keep_times",           MAC_ALG_CFG_AUTORATE_PROBE_INTVL_KEEP_TIMES, {0}},
    /* ����goodputͻ������(ǧ�ֱȣ���300):sh hipriv.sh "vap0 alg_cfg ar_delta_ratio [ǧ�ֱ�]" */
    {"ar_delta_ratio",          MAC_ALG_CFG_AUTORATE_DELTA_GOODPUT_RATIO, {0}},
    /* ����vi��per����(ǧ�ֱȣ���300):sh hipriv.sh "vap0 alg_cfg ar_vi_per_limit [ǧ�ֱ�]" */
    {"ar_vi_per_limit",         MAC_ALG_CFG_AUTORATE_VI_PROBE_PER_LIMIT, {0}},
    /* ����vo��per����(ǧ�ֱȣ���300):sh hipriv.sh "vap0 alg_cfg ar_vo_per_limit [ǧ�ֱ�]" */
    {"ar_vo_per_limit",         MAC_ALG_CFG_AUTORATE_VO_PROBE_PER_LIMIT, {0}},
    /* ����ampdu��durattionֵ:sh hipriv.sh "vap0 alg_cfg ar_ampdu_time [ʱ��ֵ]" */
    {"ar_ampdu_time",           MAC_ALG_CFG_AUTORATE_AMPDU_DURATION, {0}},
    /* ����mcs0�Ĵ���ʧ������:sh hipriv.sh "vap0 alg_cfg ar_cont_loss_num [����Ŀ]" */
    {"ar_cont_loss_num",        MAC_ALG_CFG_AUTORATE_MCS0_CONT_LOSS_NUM, {0}},
    /* ��������11b��rssi����:sh hipriv.sh "vap0 alg_cfg ar_11b_diff_rssi [��ֵ]" */
    {"ar_11b_diff_rssi",        MAC_ALG_CFG_AUTORATE_UP_PROTOCOL_DIFF_RSSI, {0}},
    /* ����rtsģʽ:sh hipriv.sh "vap0 alg_cfg ar_rts_mode [0(������)|1(����)|2(rate[0]��̬RTS, rate[1..3]
       ����RTS)|3(rate[0]����RTS, rate[1..3]����RTS)]" */
    {"ar_rts_mode",             MAC_ALG_CFG_AUTORATE_RTS_MODE, {0}},
    /* ����Legacy�װ�����������:sh hipriv.sh "vap0 alg_cfg ar_legacy_loss [��ֵ]" */
    {"ar_legacy_loss",          MAC_ALG_CFG_AUTORATE_LEGACY_1ST_LOSS_RATIO_TH, {0}},
    /* ����Legacy�װ�����������:sh hipriv.sh "vap0 alg_cfg ar_ht_vht_loss [��ֵ]" */
    {"ar_ht_vht_loss",          MAC_ALG_CFG_AUTORATE_HT_VHT_1ST_LOSS_RATIO_TH, {0}},
    /* ��ʼ����ͳ����־:sh hipriv.sh "vap0 alg_cfg ar_stat_log_do [mac��ַ] [ҵ�����] [����Ŀ]"
       ��: sh hipriv.sh "vap0 alg_cfg ar_stat_log_do 06:31:04:E3:81:02 1 1000" */
    {"ar_stat_log_do",          MAC_ALG_CFG_AUTORATE_STAT_LOG_START, {0}},
    /* ��ʼ����ѡ����־:sh hipriv.sh "vap0 alg_cfg ar_sel_log_do [mac��ַ] [ҵ�����] [����Ŀ]"
       ��: sh hipriv.sh "vap0 alg_cfg ar_sel_log_do 06:31:04:E3:81:02 1 200" */
    {"ar_sel_log_do",           MAC_ALG_CFG_AUTORATE_SELECTION_LOG_START, {0}},
    /* ��ʼ�̶�������־:sh hipriv.sh "vap0 alg_cfg ar_fix_log_do [mac��ַ] [tidno] [per����]"
       ��: sh hipriv.sh "vap0 alg_cfg ar_sel_log_do 06:31:04:E3:81:02 1 200" */
    {"ar_fix_log_do",           MAC_ALG_CFG_AUTORATE_FIX_RATE_LOG_START, {0}},
    /* ��ʼ�ۺ�����Ӧ��־:sh hipriv.sh "vap0 alg_cfg ar_fix_log_do [mac��ַ] [tidno]"
       ��: sh hipriv.sh "vap0 alg_cfg ar_sel_log_do 06:31:04:E3:81:02 1 " */
    {"ar_aggr_log_do",          MAC_ALG_CFG_AUTORATE_AGGR_STAT_LOG_START, {0}},
    /* ��ӡ����ͳ����־:sh hipriv.sh "vap0 alg_cfg ar_st_log_out 06:31:04:E3:81:02" */
    {"ar_st_log_out",           MAC_ALG_CFG_AUTORATE_STAT_LOG_WRITE, {0}},
    /* ��ӡ����ѡ����־:sh hipriv.sh "vap0 alg_cfg ar_sel_log_out 06:31:04:E3:81:02" */
    {"ar_sel_log_out",          MAC_ALG_CFG_AUTORATE_SELECTION_LOG_WRITE, {0}},
    /* ��ӡ�̶�������־:sh hipriv.sh "vap0 alg_cfg ar_fix_log_out 06:31:04:E3:81:02" */
    {"ar_fix_log_out",          MAC_ALG_CFG_AUTORATE_FIX_RATE_LOG_WRITE, {0}},
    /* ��ӡ�̶�������־:sh hipriv.sh "vap0 alg_cfg ar_fix_log_out 06:31:04:E3:81:02" */
    {"ar_aggr_log_out",         MAC_ALG_CFG_AUTORATE_AGGR_STAT_LOG_WRITE, {0}},
    /* ��ӡ���ʼ���:sh hipriv.sh "vap0 alg_cfg ar_disp_rateset 06:31:04:E3:81:02" */
    {"ar_disp_rateset",         MAC_ALG_CFG_AUTORATE_DISPLAY_RATE_SET, {0}},
    /* ���ù̶�����:sh hipriv.sh "vap0 alg_cfg ar_cfg_fix_rate 06:31:04:E3:81:02 0" */
    {"ar_cfg_fix_rate",         MAC_ALG_CFG_AUTORATE_CONFIG_FIX_RATE, {0}},
    /* ��ӡ�������ʼ���:sh hipriv.sh "vap0 alg_cfg ar_disp_rx_rate 06:31:04:E3:81:02" */
    {"ar_disp_rx_rate",         MAC_ALG_CFG_AUTORATE_DISPLAY_RX_RATE, {0}},
    /* ������ر���������Ӧ��־: sh hipriv.sh "vap0 alg_cfg ar_log_enable [1|0]" */
    {"ar_log_enable",           MAC_ALG_CFG_AUTORATE_LOG_ENABLE, {0}},
    /* ��������VO����: sh hipriv.sh "vap0 alg_cfg ar_max_vo_rate [����ֵ]" */
    {"ar_max_vo_rate",          MAC_ALG_CFG_AUTORATE_VO_RATE_LIMIT, {0}},
    /* ������˥����per����ֵ: sh hipriv.sh "vap0 alg_cfg ar_fading_per_th [per����ֵ(ǧ����)]" */
    {"ar_fading_per_th",        MAC_ALG_CFG_AUTORATE_JUDGE_FADING_PER_TH, {0}},
    /* ���þۺ�����Ӧ����: sh hipriv.sh "vap0 alg_cfg ar_aggr_opt [1|0]" */
    {"ar_aggr_opt",             MAC_ALG_CFG_AUTORATE_AGGR_OPT, {0}},
    /* ���þۺ�����Ӧ̽����: sh hipriv.sh "vap0 alg_cfg ar_aggr_pb_intvl [̽����]" */
    {"ar_aggr_pb_intvl",        MAC_ALG_CFG_AUTORATE_AGGR_PROBE_INTVL_NUM, {0}},
    /* ���õ����õ�VI״̬: sh hipriv.sh "vap0 alg_cfg ar_dbg_vi_status [0/1/2]" */
    {"ar_dbg_vi_status",        MAC_ALG_CFG_AUTORATE_DBG_VI_STATUS, {0}},
    /* �ۺ�����Ӧlog����: sh hipriv.sh "vap0 alg_cfg ar_dbg_aggr_log [0/1]" */
    {"ar_dbg_aggr_log",         MAC_ALG_CFG_AUTORATE_DBG_AGGR_LOG, {0}},
    /* �������ʱ仯ʱ�����оۺ�̽��ı�����: sh hipriv.sh "vap0 alg_cfg ar_aggr_pck_num [������]" */
    {"ar_aggr_pck_num",         MAC_ALG_CFG_AUTORATE_AGGR_NON_PROBE_PCK_NUM, {0}},
    /* ��С�ۺ�ʱ������: sh hipriv.sh "vap0 alg_cfg ar_aggr_min_idx [����ֵ]" */
    {"ar_min_aggr_idx",         MAC_ALG_CFG_AUTORATE_AGGR_MIN_AGGR_TIME_IDX, {0}},
    /* �������ۺ���Ŀ: sh hipriv.sh "vap0 alg_cfg ar_max_aggr_num [�ۺ���Ŀ]" */
    {"ar_max_aggr_num",         MAC_ALG_CFG_AUTORATE_MAX_AGGR_NUM, {0}},
    /* ������ͽ�MCS���ƾۺ�Ϊ1��PER����: sh hipriv.sh "vap0 alg_cfg ar_1mpdu_per_th [per����ֵ(ǧ����)]" */
    {"ar_1mpdu_per_th",         MAC_ALG_CFG_AUTORATE_LIMIT_1MPDU_PER_TH, {0}},

    /* ������رչ���̽�����: sh hipriv.sh "vap0 alg_cfg ar_btcoxe_probe [1|0]" */
    {"ar_btcoxe_probe",         MAC_ALG_CFG_AUTORATE_BTCOEX_PROBE_ENABLE, {0}},
    /* ������رչ���ۺϻ���: sh hipriv.sh "vap0 alg_cfg ar_btcoxe_aggr [1|0]" */
    {"ar_btcoxe_aggr",          MAC_ALG_CFG_AUTORATE_BTCOEX_AGGR_ENABLE, {0}},
    /* ���ù���ͳ��ʱ��������: sh hipriv.sh "vap0 alg_cfg ar_coxe_intvl [ͳ������ms]" */
    {"ar_coxe_intvl",           MAC_ALG_CFG_AUTORATE_COEX_STAT_INTVL, {0}},
    /* ���ù���abort�ͱ������޲���: sh hipriv.sh "vap0 alg_cfg ar_coxe_low_th [ǧ����]" */
    {"ar_coxe_low_th",          MAC_ALG_CFG_AUTORATE_COEX_LOW_ABORT_TH, {0}},
    /* ���ù���abort�߱������޲���: sh hipriv.sh "vap0 alg_cfg ar_coxe_high_th [ǧ����]" */
    {"ar_coxe_high_th",         MAC_ALG_CFG_AUTORATE_COEX_HIGH_ABORT_TH, {0}},
    /* ���ù���ۺ���ĿΪ1�����޲���: sh hipriv.sh "vap0 alg_cfg ar_coxe_agrr_th [ǧ����]" */
    {"ar_coxe_agrr_th",         MAC_ALG_CFG_AUTORATE_COEX_AGRR_NUM_ONE_TH, {0}},

    /* ��̬��������ʹ�ܿ���: sh hipriv.sh "vap0 alg_cfg ar_dyn_bw_en [0/1]" */
    {"ar_dyn_bw_en",            MAC_ALG_CFG_AUTORATE_DYNAMIC_BW_ENABLE, {0}},
    /* �����������Ż�����: sh hipriv.sh "vap0 alg_cfg ar_thpt_wave_opt [0/1]" */
    {"ar_thpt_wave_opt",        MAC_ALG_CFG_AUTORATE_THRPT_WAVE_OPT, {0}},
    /* �����ж�������������goodput�����������(ǧ����): sh hipriv.sh "vap0 alg_cfg ar_gdpt_diff_th [goodput���
       ��������(ǧ����)]" */
    {"ar_gdpt_diff_th",         MAC_ALG_CFG_AUTORATE_GOODPUT_DIFF_TH, {0}},
    /* �����ж�������������PER��������(ǧ����): sh hipriv.sh "vap0 alg_cfg ar_per_worse_th [PER�������(ǧ����)]" */
    {"ar_per_worse_th",         MAC_ALG_CFG_AUTORATE_PER_WORSE_TH, {0}},
    /* ���÷�RTS�յ�CTS����DATA������BA�ķ�������жϴ�������: sh hipriv.sh "vap0 alg_cfg ar_cts_no_ba_num [����]" */
    {"ar_cts_no_ack_num",       MAC_ALG_CFG_AUTORATE_RX_CTS_NO_BA_NUM, {0}},
    /* �����Ƿ�֧��voiceҵ��ۺ�: sh hipriv.sh "vap0 alg_cfg ar_vo_aggr [0/1]" */
    {"ar_vo_aggr",              MAL_ALG_CFG_AUTORATE_VOICE_AGGR, {0}},
    /* ���ÿ���ƽ��ͳ�Ƶ�ƽ������ƫ����: sh hipriv.sh "vap0 alg_cfg ar_fast_smth_shft [ƫ����]"
       (ȡ255��ʾȡ������ƽ��) */
    {"ar_fast_smth_shft",       MAC_ALG_CFG_AUTORATE_FAST_SMOOTH_SHIFT, {0}},
    /* ���ÿ���ƽ��ͳ�Ƶ���С�ۺ���Ŀ����: sh hipriv.sh "vap0 alg_cfg ar_fast_smth_aggr_num [��С�ۺ���Ŀ]" */
    {"ar_fast_smth_aggr_num",   MAC_ALG_CFG_AUTORATE_FAST_SMOOTH_AGGR_NUM, {0}},
    /* ����short GI�ͷ���PER����ֵ(ǧ����): sh hipriv.sh "vap0 alg_cfg ar_sgi_punish_per [PER����ֵ(ǧ����)]" */
    {"ar_sgi_punish_per",       MAC_ALG_CFG_AUTORATE_SGI_PUNISH_PER, {0}},
    /* ����short GI�ͷ��ĵȴ�̽����Ŀ: sh hipriv.sh "vap0 alg_cfg ar_sgi_punish_num [�ȴ�̽����Ŀ]" */
    {"ar_sgi_punish_num",       MAC_ALG_CFG_AUTORATE_SGI_PUNISH_NUM, {0}},
    /* ����VIҵ�񱣳����ʵ�RSSI��ֵ: sh hipriv.sh "vap0 alg_cfg ar_vi_hold_rate_rssi_th [RSSI��ֵ]" */
    {"ar_vi_hold_rate_rssi_th", MAC_ALG_CFG_AUTORATE_VI_HOLD_RATE_RSSI_TH, {0}},
    /* ����VIҵ��ı�������: sh hipriv.sh "vap0 alg_cfg ar_vi_holding_rate [��������]" */
    {"ar_vi_holding_rate",      MAC_ALG_CFG_AUTORATE_VI_HOLDING_RATE, {0}},
    /* ������������non-directʹ��: sh hipriv.sh "vap0 alg_cfg anti_inf_imm_en 0|1" */
    {"anti_inf_imm_en",         MAC_ALG_CFG_ANTI_INTF_IMM_ENABLE, {0}},
    /* ������������dynamic unlockʹ��: sh hipriv.sh "vap0 alg_cfg anti_inf_unlock_en 0|1" */
    {"anti_inf_unlock_en",      MAC_ALG_CFG_ANTI_INTF_UNLOCK_ENABLE, {0}},
    /* ������������rssiͳ������: sh hipriv.sh "vap0 anti_inf_stat_time [time]" */
    {"anti_inf_stat_time",      MAC_ALG_CFG_ANTI_INTF_RSSI_STAT_CYCLE, {0}},
    /* ������������unlock�ر�����: sh hipriv.sh "vap0 anti_inf_off_time [time]" */
    {"anti_inf_off_time",       MAC_ALG_CFG_ANTI_INTF_UNLOCK_CYCLE, {0}},
    /* ������������unlock�رճ���ʱ��: sh hipriv.sh "vap0 anti_inf_off_dur [time]" */
    {"anti_inf_off_dur",        MAC_ALG_CFG_ANTI_INTF_UNLOCK_DUR_TIME, {0}},
    /* ������nav����ʹ��: sh hipriv.sh "vap0 alg_cfg anti_inf_nav_en 0|1" */
    {"anti_inf_nav_en",         MAC_ALG_CFG_ANTI_INTF_NAV_IMM_ENABLE, {0}},
    /* ����������goodput�½�����: sh hipriv.sh "vap0 alg_cfg anti_inf_gd_th [num]" */
    {"anti_inf_gd_th",          MAC_ALG_CFG_ANTI_INTF_GOODPUT_FALL_TH, {0}},
    /* ����������̽�Ᵽ�����������: sh hipriv.sh "vap0 alg_cfg anti_inf_keep_max [num]" */
    {"anti_inf_keep_max",       MAC_ALG_CFG_ANTI_INTF_KEEP_CYC_MAX_NUM, {0}},
    /* ����������̽�Ᵽ�����������: sh hipriv.sh "vap0 alg_cfg anti_inf_keep_min [num]" */
    {"anti_inf_keep_min",       MAC_ALG_CFG_ANTI_INTF_KEEP_CYC_MIN_NUM, {0}},
    /* �����������Ƿ�ʹ��tx time̽��: sh hipriv.sh "vap0 anti_inf_tx_pro_en 0|1" */
    {"anti_inf_per_pro_en",     MAC_ALG_CFG_ANTI_INTF_PER_PROBE_EN, {0}},
    /* tx time�½�����: sh hipriv.sh "vap0 alg_cfg anti_inf_txtime_th [val]" */
    {"anti_inf_txtime_th",      MAC_ALG_CFG_ANTI_INTF_TX_TIME_FALL_TH, {0}},
    /* per�½�����: sh hipriv.sh "vap0 alg_cfg anti_inf_per_th [val]" */
    {"anti_inf_per_th",         MAC_ALG_CFG_ANTI_INTF_PER_FALL_TH, {0}},
    /* goodput��������: sh hipriv.sh "vap0 alg_cfg anti_inf_gd_jitter_th [val]" */
    {"anti_inf_gd_jitter_th",   MAC_ALG_CFG_ANTI_INTF_GOODPUT_JITTER_TH, {0}},
    /* ����������debug�Ĵ�ӡ��Ϣ: sh hipriv.sh "vap0 alg_cfg anti_inf_debug_mode 0|1|2" */
    {"anti_inf_debug_mode",     MAC_ALG_CFG_ANTI_INTF_DEBUG_MODE, {0}},

    /* ͬƵ���ż������: sh hipriv.sh "vap0 alg_cfg edca_opt_co_ch_time [time]" */
    {"edca_opt_co_ch_time",     MAC_ALG_CFG_EDCA_OPT_CO_CH_DET_CYCLE, {0}},
    /* apģʽ��edca�Ż�ʹ��ģʽ: sh hipriv.sh "vap0 alg_cfg edca_opt_en_ap 0|1|2" */
    {"edca_opt_en_ap",          MAC_ALG_CFG_EDCA_OPT_AP_EN_MODE, {0}},
    /* staģʽ��edca�Ż�ʹ��ģʽ: sh hipriv.sh "vap0 alg_cfg edca_opt_en_sta 0|1" */
    {"edca_opt_en_sta",         MAC_ALG_CFG_EDCA_OPT_STA_EN, {0}},
    /* staģʽ��edca�Ż���weightingϵ��: sh hipriv.sh "vap0 alg_cfg edca_opt_sta_weight 0~3" */
    {"edca_opt_sta_weight",     MAC_ALG_CFG_EDCA_OPT_STA_WEIGHT, {0}},
    /* non-direct��ռ�ձ����� sh hipriv.sh "vap0 alg_cfg edca_opt_nondir_th [val]" */
    {"edca_opt_nondir_th",      MAC_ALG_CFG_EDCA_OPT_NONDIR_TH, {0}},
    /* apģʽ��UDPҵ���Ӧ���б����� sh hipriv.sh "vap0 alg_cfg edca_opt_th_udp [val]" */
    {"edca_opt_th_udp",         MAC_ALG_CFG_EDCA_OPT_TH_UDP, {0}},
    /* apģʽ��tcPҵ���Ӧ���б����� sh hipriv.sh "vap0 alg_cfg edca_opt_th_tcp [val]" */
    {"edca_opt_th_tcp",         MAC_ALG_CFG_EDCA_OPT_TH_TCP, {0}},
    /* �Ƿ��ӡ�����Ϣ�������ڱ��ذ汾���� */
    {"edca_opt_debug_mode",     MAC_ALG_CFG_EDCA_OPT_DEBUG_MODE, {0}},

    /* CCA�Ż�����ʹ��: sh hipriv.sh "vap0 alg_cfg cca_opt_alg_en_mode 0|1" */
    {"cca_opt_alg_en_mode",         MAC_ALG_CFG_CCA_OPT_ALG_EN_MODE, {0}},
    /* CCA�Ż�DEBUGģʽ����: sh hipriv.sh "vap0 alg_cfg cca_opt_debug_mode 0|1" */
    {"cca_opt_debug_mode",          MAC_ALG_CFG_CCA_OPT_DEBUG_MODE, {0}},
    /* CCA�Ż�T1��ʱ����:sh hipriv.sh "vap0 alg_cfg cca_opt_set_t1_counter_time [time]" */
    {"cca_opt_set_t1_counter_time", MAC_ALG_CFG_CCA_OPT_SET_T1_COUNTER_TIME, {0}},
    {"tpc_mode",                MAC_ALG_CFG_TPC_MODE, {0}},                          /* ����TPC����ģʽ */
    {"tpc_dbg",                 MAC_ALG_CFG_TPC_DEBUG, {0}},                         /* ����TPC��debug���� */
    /* ����TPC���ʵȼ�(0,1,2,3), �ڹ̶�����ģʽ��ʹ�� */
    {"tpc_pow_lvl",             MAC_ALG_CFG_TPC_POWER_LEVEL, {0}},
    /* ����TPC��log����:sh hipriv.sh "vap0 alg_cfg tpc_log 1 */
    {"tpc_log",                 MAC_ALG_CFG_TPC_LOG, {0}},
    /* ��ʼ����ͳ����־:sh hipriv.sh "vap0 alg_tpc_log tpc_stat_log_do [mac��ַ] [ҵ�����] [����Ŀ]"
       ��: sh hipriv.sh "vap0 alg_tpc_log tpc_stat_log_do 06:31:04:E3:81:02 1 1000" */
    {"tpc_stat_log_do",         MAC_ALG_CFG_TPC_STAT_LOG_START, {0}},
    /* ��ӡ����ͳ����־:sh hipriv.sh "vap0 alg_tpc_log tpc_stat_log_out 06:31:04:E3:81:02" */
    {"tpc_stat_log_out",        MAC_ALG_CFG_TPC_STAT_LOG_WRITE, {0}},
    /* ��ʼÿ��ͳ����־:sh hipriv.sh "vap0 alg_tpc_log tpc_pkt_log_do [mac��ַ] [ҵ�����] [����Ŀ]"
       ��: sh hipriv.sh "vap0 alg_tpc_log tpc_pkt_log_do 06:31:04:E3:81:02 1 1000" */
    {"tpc_pkt_log_do",          MAC_ALG_CFG_TPC_PER_PKT_LOG_START, {0}},
    /* ��ȡ����֡����:sh hipriv.sh "vap0 alg_tpc_log tpc_get_frame_pow beacon_pow" */
    {"tpc_get_frame_pow",       MAC_ALG_CFG_TPC_GET_FRAME_POW, {0}},
    {"tpc_mag_frm_pow_lvl",     MAC_ALG_CFG_TPC_MANAGEMENT_MCAST_FRM_POWER_LEVEL, {0}}, /* TPC����֡�Ͷಥ֡���ʵȼ� */
    {"tpc_ctl_frm_pow_lvl",     MAC_ALG_CFG_TPC_CONTROL_FRM_POWER_LEVEL, {0}},          /* TPC����֡���ʵȼ� */
    {"tpc_reset_stat",          MAC_ALG_CFG_TPC_RESET_STAT, {0}},                    /* �ͷ�ͳ���ڴ� */
    {"tpc_reset_pkt",           MAC_ALG_CFG_TPC_RESET_PKT, {0}},                     /* �ͷ�ÿ���ڴ� */
    {"tpc_over_temp_th",        MAC_ALG_CFG_TPC_OVER_TMP_TH, {0}},                   /* TPC�������� */
    {"tpc_dpd_enable_rate",     MAC_ALG_CFG_TPC_DPD_ENABLE_RATE, {0}},               /* ����DPD��Ч������INDEX */
    {"tpc_target_rate_11b",     MAC_ALG_CFG_TPC_TARGET_RATE_11B, {0}},               /* 11bĿ���������� */
    {"tpc_target_rate_11ag",    MAC_ALG_CFG_TPC_TARGET_RATE_11AG, {0}},              /* 11agĿ���������� */
    {"tpc_target_rate_11n20",   MAC_ALG_CFG_TPC_TARGET_RATE_HT20, {0}},              /* 11n20Ŀ���������� */
    {"tpc_no_margin_pow",       MAC_ALG_CFG_TPC_NO_MARGIN_POW, {0}},                 /* 51����û���������� */
    {"tpc_power_amend",         MAC_ALG_CFG_TPC_POWER_AMEND, {0}},  /* tx power�ڴ��ڲ�ƽ̹��tpc���й���������Ĭ��Ϊ0 */
    {HI_NULL,0,{0}}
};
#endif

/* hipriv ���������ṹ�嶨�� */
typedef struct {
    hi_char  cmd_param1[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* �����һ�������ַ��� */
    hi_char  cmd_param2[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* ����ڶ��������ַ��� */
}wal_hipriv_two_param_stru;

typedef struct {
    hi_char  cmd_param1[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* �����һ�������ַ��� */
    hi_char  cmd_param2[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* ����ڶ��������ַ��� */
    hi_char  cmd_param3[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* ��������������ַ��� */
}wal_hipriv_three_param_stru;

typedef struct {
    hi_char  cmd_param1[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* �����һ�������ַ��� */
    hi_char  cmd_param2[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* ����ڶ��������ַ��� */
    hi_char  cmd_param3[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* ��������������ַ��� */
    hi_char  cmd_param4[WAL_HIPRIV_CMD_NAME_MAX_LEN];    /* ��������������ַ��� */
}wal_hipriv_four_param_stru;
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/* ����Э��͹���״̬ */
hi_bool is_under_ps()
{
    return g_under_ps;
}

hi_void set_under_ps(hi_bool under_ps)
{
    if (g_under_mfg) {
        g_under_ps = 0;   /* ����ģʽ�£������ڵ͹���ģʽ */
    } else {
        g_under_ps = under_ps;
    }
}

hi_void set_under_mfg(hi_u32 under_mfg)
{
    g_under_mfg = under_mfg;
}
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : hipriv����2��������������
 �������  : pc_param, ��������Ĳ����ַ���
 �������  : out_param, ��������2�����ò���
*****************************************************************************/
static hi_u32 wal_hipriv_two_param_parse(hi_char *pc_param, wal_hipriv_two_param_stru *out_param)
{
    hi_u32  ret;
    hi_u32  off_set = 0;
    /* ��ȡ��һ������ */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param1, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_two_param_parse::get first param failed!}");
        return ret;
    }
    /* ƫ�ƣ�ȡ��һ������ */
    pc_param = pc_param + off_set;
    /* ��ȡ�ڶ������� */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param2, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_two_param_parse::get second param failed!}");
        return ret;
    }
    return HI_SUCCESS;
}
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : hipriv����3��������������
 �������  : pc_param, ��������Ĳ����ַ���
 �������  : out_param, ��������3�����ò���
*****************************************************************************/
static hi_u32 wal_hipriv_three_param_parse(hi_char *pc_param, wal_hipriv_three_param_stru *out_param)
{
    hi_u32  ret;
    hi_u32  off_set = 0;
    /* ��ȡ��һ������ */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param1, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_three_param_parse::get first param failed!}");
        return ret;
    }
    /* ƫ�ƣ�ȡ��һ������ */
    pc_param = pc_param + off_set;
    /* ��ȡ�ڶ������� */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param2, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_three_param_parse::get second param failed!}");
        return ret;
    }
    pc_param = pc_param + off_set;
    /* ��ȡ���������� */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param3, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_three_param_parse::get third param failed!}");
        return ret;
    }
    return HI_SUCCESS;
}
#endif

#if defined(_PRE_WLAN_FEATURE_SIGMA) || defined(_PRE_WLAN_FEATURE_HIPRIV)
/*****************************************************************************
 ��������  : hipriv����4��������������
 �������  : pc_param, ��������Ĳ����ַ���
 �������  : out_param, ��������4�����ò���
*****************************************************************************/
static hi_u32 wal_hipriv_four_param_parse(hi_char *pc_param, wal_hipriv_four_param_stru *out_param)
{
    hi_u32  ret;
    hi_u32  off_set = 0;
    /* ��ȡ��һ������ */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param1, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_four_param_parse::get first param failed!}");
        return ret;
    }
    /* ƫ�ƣ�ȡ��һ������ */
    pc_param = pc_param + off_set;
    /* ��ȡ�ڶ������� */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param2, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_four_param_parse::get second param failed!}");
        return ret;
    }
    pc_param = pc_param + off_set;
    /* ��ȡ���������� */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param3, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_four_param_parse::get third param failed!}");
        return ret;
    }
    pc_param = pc_param + off_set;
    /* ��ȡ���ĸ����� */
    ret = wal_get_cmd_one_arg(pc_param, out_param->cmd_param4, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_four_param_parse::get fouth param failed!}");
        return ret;
    }
    return HI_SUCCESS;
}
#endif

/************************** API�ӿ� START *******************************/
/*****************************************************************************
 ��������  : ��ȡ������
*****************************************************************************/
hi_u32 wal_hipriv_getcountry(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_query_stru          query_msg;
    hi_u32                      ret;
    wal_msg_stru                *rsp_msg = HI_NULL;
    wal_msg_rsp_stru            *queue_rsp_msg = HI_NULL;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    query_msg.wid = WLAN_CFGID_COUNTRY;
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_QUERY, WAL_MSG_WID_LENGTH,
                             (hi_u8 *)&query_msg, HI_TRUE, &rsp_msg);
    if ((ret != HI_SUCCESS) || (rsp_msg == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_getcountry:: alloc_cfg_event failed!}");
        return ret;
    }
    /* ��������Ϣ */
    queue_rsp_msg = (wal_msg_rsp_stru *)(rsp_msg->auc_msg_data);
    pc_param[0] = (hi_char)queue_rsp_msg->auc_value[0];
    pc_param[1] = (hi_char)queue_rsp_msg->auc_value[1];
    pc_param[2] = 0; /* 2: ��3λ */

    oal_free(rsp_msg);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_at_printf("+CC:%c%c\r\n", pc_param[0], pc_param[1]);
    hi_at_printf("OK\r\n");
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��������vap״̬(UP/DOWN)
*****************************************************************************/
hi_u32 wal_hipriv_set_vap_state(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32      ret = HI_FAIL;
    hi_u32      state;

    if (pc_param == HI_NULL) {
        return HI_FAIL;
    }

    state = (hi_u32)oal_atoi(pc_param);
    if (state == 0) {
        ret = wal_netdev_stop(netdev);
    } else if (state == 1) {
        ret = wal_netdev_open(netdev);
    } else {
        oam_error_log1(0, 0, "wal_hipriv_set_vap_state en_netdev ERROR: %d\r\n", state);
        return HI_FAIL;
    }

    if (ret != HI_SUCCESS) {
        oam_error_log1(0, 0, "wal_hipriv_set_vap_state netdev start/stop fail![%d]\r\n", state);
        return HI_FAIL;
    }
    oam_warning_log0(0, OAM_SF_ANY, "OK\r\n");
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 ��������  : ��ȡMesh�ڵ���Ϣ
*****************************************************************************/
hi_u32 wal_hipriv_get_mesh_node_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(pc_param);
    wal_msg_query_stru          query_msg;
    hi_u32                      ret;
    wal_msg_stru                *rsp_msg = HI_NULL;
    wal_msg_rsp_stru            *queue_rsp_msg = HI_NULL;
    mac_cfg_mesh_nodeinfo_stru  *mesh_node_info = HI_NULL;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    query_msg.wid = WLAN_CFGID_GET_MESH_NODE_INFO;
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_QUERY, WAL_MSG_WID_LENGTH,
                             (hi_u8 *)&query_msg, HI_TRUE, &rsp_msg);
    if ((ret != HI_SUCCESS) || (rsp_msg == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_get_mesh_node_info:: alloc_cfg_event failed!}");
        return ret;
    }
    /* ��������Ϣ */
    queue_rsp_msg = (wal_msg_rsp_stru *)(rsp_msg->auc_msg_data);
    mesh_node_info = (mac_cfg_mesh_nodeinfo_stru *)queue_rsp_msg->auc_value;

#ifdef CUSTOM_AT_COMMAND
    if (mesh_node_info->node_type == MAC_HISI_MESH_UNSPEC) {
        hi_at_printf("+MeshNode Type:%d\r\n", mesh_node_info->node_type);
    } else {
        hi_at_printf("+MeshNode Type:%d\r\n", mesh_node_info->node_type);
        hi_at_printf("+MeshNode Info:%d,%d,%d,%d,%d\r\n", mesh_node_info->user_num, mesh_node_info->chan,
            mesh_node_info->privacy, mesh_node_info->priority, mesh_node_info->mesh_accept_sta);
    }
#endif

    oal_free(rsp_msg);

    return HI_SUCCESS;
}
#endif

/***************************** SIGMA ʹ�õĵ������� START ************************************/
/* ��������ʹ����Ҫ����SIGMA���Ժ���ߴ�DEBUG�����Ƴ� */
#if defined _PRE_WLAN_FEATURE_SIGMA
/*****************************************************************************
 ��������  : ����BA�Ự�ĵ�������
 �����ʽ  : hipriv wlan0 addba_req xx:xx:xx:xx:xx:xx(mac��ַ) tidno buffsize timeout
*****************************************************************************/
hi_u32 wal_hipriv_addba_req(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          ret;
    mac_cfg_addba_req_param_stru    addba_req_param_info;     /* ��ʱ�����ȡ��addba req����Ϣ */
    wal_hipriv_four_param_stru      cmd_param;
    hi_char*                        cmd_param1_ptr = HI_NULL;

    /* �������ò���Ϊ4�� */
    ret = wal_hipriv_four_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_addba_req::parse param failed!}");
        return ret;
    }
    cmd_param1_ptr = cmd_param.cmd_param1;
    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&addba_req_param_info, sizeof(mac_cfg_addba_req_param_stru), 0, sizeof(mac_cfg_addba_req_param_stru));
    /* MAC��ַ */
    oal_strtoaddr(cmd_param1_ptr, addba_req_param_info.auc_mac_addr, WLAN_MAC_ADDR_LEN);
    /* tid */
    addba_req_param_info.tidno = (hi_u8)oal_atoi(cmd_param.cmd_param2);
    if (addba_req_param_info.tidno >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_addba_req::tidno[%d] of addba req is invalid!}",
            addba_req_param_info.tidno);
        return HI_ERR_CODE_INVALID_CONFIG;
    }
    /* BA POLICY ֻ֧��������Ӧ,д�� */
    addba_req_param_info.ba_policy = MAC_BA_POLICY_IMMEDIATE;
    /* buffsize */
    addba_req_param_info.us_buff_size = (hi_u16)oal_atoi(cmd_param.cmd_param3);
    /* timeoutʱ�� */
    addba_req_param_info.us_timeout = (hi_u16)oal_atoi(cmd_param.cmd_param4);

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ADDBA_REQ, sizeof(mac_cfg_addba_req_param_stru));
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, sizeof(mac_cfg_addba_req_param_stru),
                 &addba_req_param_info, sizeof(mac_cfg_addba_req_param_stru)) != EOK) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_addba_req::memcpy_s param failed!}");
        return HI_FAIL;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_addba_req_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_addba_req::send event failed!}");
        return ret;
    }
    return HI_SUCCESS;
}
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ������ر������û���Ӧtid��amsdu���͹��ܲ�����amsdu����
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_amsdu_tx_on(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          ret;
    mac_cfg_ampdu_tx_on_param_stru  aggr_tx_on_param;
    wal_hipriv_three_param_stru     cmd_param;

    /* �����ʽ: hipriv wlan0 amsdu_tx_on 0|1 tidno max_num[1~12] */
    ret = wal_hipriv_three_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_amsdu_tx_on::parse cmd param failed.");
        return ret;
    }
    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&aggr_tx_on_param, sizeof(mac_cfg_ampdu_tx_on_param_stru), 0, sizeof(mac_cfg_ampdu_tx_on_param_stru));
    /* ��ȡ���ܱ�־ 0�ر�,1���� vap��־λ */
    aggr_tx_on_param.aggr_tx_on = (hi_u8)oal_atoi(cmd_param.cmd_param1);
    /* ��ȡtid no ����hmac����У��,�˴����ظ�У�� */
    aggr_tx_on_param.tid = (hi_u8)oal_atoi(cmd_param.cmd_param2);
    /* ��ȡmax num */
    aggr_tx_on_param.max_num = (hi_u8)oal_atoi(cmd_param.cmd_param3);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_AMSDU_TX_ON, sizeof(mac_cfg_ampdu_tx_on_param_stru));
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, sizeof(mac_cfg_ampdu_tx_on_param_stru),
                 &aggr_tx_on_param, sizeof(mac_cfg_ampdu_tx_on_param_stru)) != EOK) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_amsdu_tx_on::memcpy_s cmd param failed.");
        return HI_FAIL;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ampdu_tx_on_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_amsdu_tx_on::return err code [%u]!}", ret);
    }
    return ret;
}
#endif

/*****************************************************************************
 ��������  : ��ӡvap�����в�����Ϣ
*****************************************************************************/
hi_u32 wal_hipriv_vap_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;

    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_vap_info::cmd len error}");
        return HI_FAIL;
    }
    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_VAP_INFO, sizeof(hi_u32));
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_vap_info::return err code [%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/************************** SDV�����׶� ʹ�õĵ������� START *******************************/
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ���������������������� Ŀǰ��֧��rate����
*****************************************************************************/
static hi_u32 wal_hipriv_set_tx_dscr_param(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    mac_cfg_set_dscr_param_stru     *set_dscr_param = HI_NULL;
    mac_set_dscr_param_enum_uint8   index;
    wal_hipriv_three_param_stru     cmd_param;
    /* ֧��֡�������ò���,��������mac_set_dscr_frame_type_enum ö���е�˳���ϸ�һ��! */
    const hi_char                   *pauc_dscr_type_name[MAC_SET_DSCR_TYPE_BUTT] = {
        "ucast_data", "mcast_data", "bcast_data", "ucast_mgmt", "mbcast_mgmt"
    };
    /* �����������Ĳ���, ��������ο�mac_set_dscr_enum ����ö���е�˳���ϸ�һ��! */
    const hi_char                   *pauc_tx_dscr_param_name[MAC_SET_DSCR_PARAM_BUTT] = {
        "data0", "data1", "data2", "data3", "rate", "power", "shortgi"
    };

    /* ��ȡ������� */
    hi_u32 ret = wal_hipriv_three_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_tx_dscr_param::get parse cmd param failed!}");
        return ret;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_DSCR, sizeof(mac_cfg_set_dscr_param_stru));
    /* ��������������������� */
    set_dscr_param = (mac_cfg_set_dscr_param_stru *)(write_msg.auc_value);
    /* ������������һ��֡���� */
    for (index = 0; index < MAC_SET_DSCR_TYPE_BUTT; index++) {
        if (!strcmp(pauc_dscr_type_name[index], cmd_param.cmd_param1))  {
            break;
        }
    }
    if (index == MAC_SET_DSCR_TYPE_BUTT) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_tx_dscr_param::no such type for tx dscr!}");
        return HI_FAIL;
    }
    set_dscr_param->type = index;
    /* ������������һ���ֶ� */
    for (index = 0; index < MAC_SET_DSCR_PARAM_BUTT; index++) {
        if (!strcmp(pauc_tx_dscr_param_name[index], cmd_param.cmd_param2)) {
            break;
        }
    }
    if (index == MAC_SET_DSCR_PARAM_BUTT) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_tx_dscr_param::no such param for tx dscr!}");
        return HI_FAIL;
    }
    set_dscr_param->function_index = index;
    /* ����Ҫ����Ϊ����ֵ */
    set_dscr_param->l_value = oal_strtol(cmd_param.cmd_param3, HI_NULL, 0);

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_set_dscr_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_tx_dscr_param::return err code [%u]!}", ret);
    }
    return ret;
}


/*****************************************************************************
 ��������  : �ֶ���������BA�Ự
*****************************************************************************/
static hi_u32 wal_hipriv_ampdu_start(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru             write_msg;
    hi_u32                         ret;
    mac_cfg_ampdu_start_param_stru ampdu_start_param_info;  /* ��ʱ�����ȡ��use����Ϣ */
    wal_hipriv_two_param_stru      cmd_param;
    hi_char*                       cmd_param1_ptr = HI_NULL;

    /* ����AMPDU��������������: hipriv Hisilicon0 ampdu_start xx xx xx xx xx xx(mac��ַ) tidno */
    ret = wal_hipriv_two_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ampdu_start::parse cmd param failed!}");
        return ret;
    }
    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&ampdu_start_param_info, sizeof(mac_cfg_ampdu_start_param_stru), 0,
        sizeof(mac_cfg_ampdu_start_param_stru));

    cmd_param1_ptr = cmd_param.cmd_param1;
    /* ��ȡmac��ַ */
    oal_strtoaddr(cmd_param1_ptr, ampdu_start_param_info.auc_mac_addr, WLAN_MAC_ADDR_LEN);
    /* ��ȡtid */
    ampdu_start_param_info.tidno = (hi_u8)oal_atoi(cmd_param.cmd_param2);
    if (ampdu_start_param_info.tidno >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ampdu_start::tidno[%d] is invalid!}",
                         ampdu_start_param_info.tidno);
        return HI_ERR_CODE_INVALID_CONFIG;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_AMPDU_START, sizeof(mac_cfg_ampdu_start_param_stru));
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, sizeof(mac_cfg_ampdu_start_param_stru),
                 &ampdu_start_param_info, sizeof(mac_cfg_ampdu_start_param_stru)) != EOK) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ampdu_start::memcpy_s event msg failed!}");
        return HI_FAIL;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ampdu_start_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ampdu_start::return err code[%u]!}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ������ر�amsdu ampdu���Ϸ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_ampdu_amsdu_switch(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru      write_msg;
    hi_s32                  l_tmp;
    hi_u32                  off_set;
    hi_char                 ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                  ret;

    /* �����Զ���ʼBA�Ự�Ŀ���:hipriv "vap0  auto_ba 0 | 1" ���������ĳһ��VAP */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_hipriv_ampdu_amsdu_switch::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }
    /* ��Խ������Ĳ�ͬ�����AUTO BA���в�ͬ������ ��0������ */
    if (0 == (strcmp("0", ac_name))) {
        l_tmp = 0;
    } else {
        l_tmp = 1;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_AMSDU_AMPDU_SWITCH, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = l_tmp;  /* ��������������� */
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ampdu_amsdu_switch::return err code[%u]!}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ɾ��BA�Ự�ĵ�������
*****************************************************************************/
static hi_u32  wal_hipriv_delba_req(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          ret;
    mac_cfg_delba_req_param_stru    delba_req_param_info;     /* ��ʱ�����ȡ��delba req����Ϣ */
    wal_hipriv_four_param_stru      cmd_param;
    hi_char*                        cmd_param1_ptr = HI_NULL;

    /* ɾ����Ӧtid��ba��������: hipriv Hisilicon0 delba_req xx xx xx xx xx xx(mac��ַ) tidno direction
       direction:0ΪRX BA, 1ΪTX BA */
    ret = wal_hipriv_four_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_delba_req::parse cmd param failed!}");
        return ret;
    }
    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&delba_req_param_info, sizeof(mac_cfg_delba_req_param_stru), 0, sizeof(mac_cfg_delba_req_param_stru));

    cmd_param1_ptr = cmd_param.cmd_param1;
    /* ��ȡmac��ַ */
    oal_strtoaddr(cmd_param1_ptr, delba_req_param_info.auc_mac_addr, WLAN_MAC_ADDR_LEN);
    /* ��ȡtid */
    delba_req_param_info.tidno = (hi_u8)oal_atoi(cmd_param.cmd_param2);
    if (delba_req_param_info.tidno >= WLAN_TID_MAX_NUM) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_delba_req::tidno [%d] is invalid!}",
                         delba_req_param_info.tidno);
        return HI_ERR_CODE_INVALID_CONFIG;
    }
    /* ��ȡdirection */
    delba_req_param_info.direction = (hi_u8)oal_atoi(cmd_param.cmd_param3);
    if (delba_req_param_info.direction >= MAC_BUTT_DELBA) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_delba_req::the direction is not correct! direction is[%d]!}",
                         delba_req_param_info.direction);
        return HI_ERR_CODE_INVALID_CONFIG;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_DELBA_REQ, sizeof(mac_cfg_delba_req_param_stru));
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, sizeof(mac_cfg_delba_req_param_stru),
                 &delba_req_param_info, sizeof(mac_cfg_delba_req_param_stru)) != EOK) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_delba_req::memcpy_s cmd param failed.");
        return HI_FAIL;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_delba_req_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_delba_req::return err code[%u]!}", ret);
    }
    return ret;
}

#endif

/*****************************************************************************
 ��������  : ��ӡuser�����в�����Ϣ
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_user_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          ret;

    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&write_msg, sizeof(wal_msg_write_stru), 0, sizeof(wal_msg_write_stru));
    if (*pc_param == ' ') {
        pc_param++;
    }
    oal_strtoaddr(pc_param, write_msg.auc_value, WLAN_MAC_ADDR_LEN);

    /* ����5.5 ����ǿ������ת���᲻������� */
    if (wal_macaddr_check(write_msg.auc_value) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "wal_hipriv_user_info:: Mac address invalid!");
        return HI_FAIL;
    }

    pc_param += WLAN_MAC_ADDR_BYTE_LEN;
    /* �ж�������Ƿ������� */
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_user_info::cmd len error!}\r\n");
        return HI_FAIL;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_USER_INFO, WLAN_MAC_ADDR_LEN);
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + WLAN_MAC_ADDR_LEN,
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_user_info::return err code [%u]!}", ret);
        return ret;
    }
#ifdef AT_DEBUG_CMD_SUPPORT
    hi_at_printf("OK\r\n");
#endif

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ��ʾ�豸֧�ֵ��ŵ��б�

 �޸���ʷ      :
  1.��    ��   : 2013��12��27��,������
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_list_channel(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru        write_msg;
    hi_u32                    ret;

    hi_unref_param(pc_param);
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_LIST_CHAN, sizeof(hi_s32));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_list_channel::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_DEBUG_MODE
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ���ù���������͹���

 �޸���ʷ      :
  1.��    ��   : 2013��12��27��,������
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_regdomain_pwr(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32                   off_set;
    hi_char                  ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                   ret;
    hi_s32                   l_pwr;
    wal_msg_write_stru       write_msg;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "wal_hipriv_set_regdomain_pwr, get arg return err %u", ret);
        return ret;
    }

    l_pwr = oal_atoi(ac_name);
    if (l_pwr <= 0 || l_pwr > 100) { /* ����100Ϊ��Чֵ */
        oam_warning_log1(0, OAM_SF_CFG, "invalid value, %d", l_pwr);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_REGDOMAIN_PWR, sizeof(mac_cfg_regdomain_max_pwr_stru));

    ((mac_cfg_regdomain_max_pwr_stru *)write_msg.auc_value)->pwr        = (hi_u8)l_pwr;
    ((mac_cfg_regdomain_max_pwr_stru *)write_msg.auc_value)->exceed_reg = HI_FALSE;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{wal_hipriv_set_regdomain_pwr::wal_send_cfg_event fail.return err code [%u]}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ���ù���������͹���

 �޸���ʷ      :
  1.��    ��   : 2013��12��27��,������
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_regdomain_pwr_priv(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32                  off_set;
    hi_char                 ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                  ret;
    hi_u32                  pwr;
    wal_msg_write_stru      write_msg;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "wal_hipriv_set_regdomain_pwr, get arg return err %d", ret);
        return ret;
    }

    pwr = (hi_u32)oal_atoi(ac_name);

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_REGDOMAIN_PWR, sizeof(hi_s32));

    ((mac_cfg_regdomain_max_pwr_stru *)write_msg.auc_value)->pwr        = (hi_u8)pwr;
    ((mac_cfg_regdomain_max_pwr_stru *)write_msg.auc_value)->exceed_reg = HI_TRUE;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{wal_hipriv_set_regdomain_pwr::wal_send_cfg_event fail.return err code %u}", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����sta��ʼɨ��

 �޸���ʷ      :
  1.��    ��   : 2013��6��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_start_scan(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru        write_msg;
    hi_u32                    ret;
#ifdef _PRE_WLAN_FEATURE_P2P
    hi_u8                     is_p2p0_scan;
#endif

    hi_unref_param(pc_param);
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_START_SCAN, sizeof(hi_s32));

#ifdef _PRE_WLAN_FEATURE_P2P
    is_p2p0_scan = (memcmp(netdev->name, "p2p0", strlen("p2p0")) == 0) ? 1 : 0;
    write_msg.auc_value[0] = is_p2p0_scan;
#endif  /* _PRE_WLAN_FEATURE_P2P */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_start_scan::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����sta��ʼɨ��

 �޸���ʷ      :
  1.��    ��   : 2013��6��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_start_join(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru           write_msg;
    hi_u32                       ret;
    hi_u32                       off_set;
    hi_char                      ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_START_JOIN, sizeof(hi_s32));

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_start_join::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    /* ��Ҫ����AP�ı�Ÿ��Ƶ��¼�msg�У�AP��������ֵ�ASSCI�룬������4���ֽ� */
    if (memcpy_s((hi_s8 *)write_msg.auc_value, WAL_MSG_WRITE_MAX_LEN, (hi_s8 *)ac_name, sizeof(hi_s32)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_start_join::mem safe function err!}");
        return HI_FAIL;
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_start_join::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ȥ��֤

 �޸���ʷ      :
  1.��    ��   : 2013��6��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_start_deauth(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru        write_msg;
    hi_u32                    ret;

    hi_unref_param(pc_param);
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_START_DEAUTH, sizeof(hi_s32));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_start_deauth::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ɾ��1���û�

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_kick_user(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          off_set;
    hi_char                         ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                          ret;
    mac_cfg_kick_user_param_stru    *kick_user_param = HI_NULL;
    hi_u8                           mac_addr[WLAN_MAC_ADDR_LEN] = {0, 0, 0, 0, 0, 0};

    /* ȥ����1���û������� hipriv "vap0 kick_user xx:xx:xx:xx:xx:xx" */
    /* ��ȡmac��ַ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_kick_user::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    oal_strtoaddr(ac_name, mac_addr, WLAN_MAC_ADDR_LEN);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_KICK_USER, sizeof(mac_cfg_kick_user_param_stru));

    /* ��������������� */
    kick_user_param = (mac_cfg_kick_user_param_stru *)(write_msg.auc_value);
    if (memcpy_s(kick_user_param->auc_mac_addr, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_PWR, "{wal_hipriv_send_bar::mem safe function err!}");
        return HI_FAIL;
    }

    /* ��дȥ����reason code */
    kick_user_param->us_reason_code = MAC_UNSPEC_REASON;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_kick_user_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_kick_user::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ָ���û�ָ��tid ����bar

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_send_bar(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          off_set;
    hi_char                         ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                          ret;
    mac_cfg_pause_tid_param_stru    *pause_tid_param = HI_NULL;
    hi_u8                           mac_addr[WLAN_MAC_ADDR_LEN] = {0, 0, 0, 0, 0, 0};
    hi_u8                           tid;

    /* ��ȡmac��ַ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_send_bar::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    oal_strtoaddr(ac_name, mac_addr, WLAN_MAC_ADDR_LEN);
    /* ƫ�ƣ�ȡ��һ������ */
    pc_param = pc_param + off_set;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_send_bar::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    tid = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SEND_BAR, sizeof(mac_cfg_pause_tid_param_stru));

    /* ��������������� */
    pause_tid_param = (mac_cfg_pause_tid_param_stru *)(write_msg.auc_value);
    if (memcpy_s(pause_tid_param->auc_mac_addr, WLAN_MAC_ADDR_LEN, mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_PWR, "{wal_hipriv_send_bar::mem safe function err!}");
        return HI_FAIL;
    }
    pause_tid_param->tid = tid;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_pause_tid_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_send_bar::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���������/�ر�WMM
 �޸���ʷ      :
  1.��    ��   : 2014��1��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_wmm_switch(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    hi_u8                       open_wmm;
    hi_u8                       orig_dev_state = wal_dev_is_running();

    if (wal_netdev_stop(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_wmm_switch::wal_netdev_stop failed\r\n");
        return HI_FAIL;
    }

    /* �豸��up״̬���������ã�������down */
    if (wal_dev_is_running() == HI_TRUE) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_wmm_switch::device is busy,can not set wmm!}\r\n");
        return HI_ERR_CODE_CONFIG_BUSY;
    }

    /* ��ȡ�趨��ֵ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_wmm_switch::get_one_arg return err_code [%d]!}", ret);
        return ret;
    }

    open_wmm = (hi_u8)oal_atoi(ac_name);
    /* ���û�����ֵת����0 1 */
    open_wmm = (hi_u8)((open_wmm == 0) ? HI_FALSE : HI_TRUE);
    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    *(hi_u8 *)(write_msg.auc_value) = open_wmm;
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_WMM_SWITCH, sizeof(hi_u8));
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_wmm_switch::return err code [%u]!}", ret);
        return ret;
    }

    if (orig_dev_state == HI_TRUE) {
        if (wal_netdev_open(netdev) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_wmm_switch::wal_netdev_open failed\r\n");
            return HI_FAIL;
        }
    }
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_DEBUG_MODE
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ���������/�ر�����ssid

 �޸���ʷ      :
  1.��    ��   : 2014��1��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_hide_ssid(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_u16                      us_len;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    hi_u8                       hide_ssid;

    /* ��ȡ�趨��ֵ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_hide_ssid::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    hide_ssid = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    us_len = sizeof(hi_u8);
    *(hi_u8 *)(write_msg.auc_value) = hide_ssid;
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_HIDE_SSID, us_len);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_hide_ssid::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ���þۺ�������

 �޸���ʷ      :
  1.��    ��   : 2014��10��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_set_ampdu_aggr_num(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru      write_msg;
    hi_u32                  off_set;
    hi_char                 ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    mac_cfg_aggr_num_stru   aggr_num_ctl = {0};
    hi_u32                  ret;

    /* ��ȫ��̹���6.6����(1) �̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s((hi_u8*)&write_msg, sizeof(wal_msg_write_stru), 0, sizeof(wal_msg_write_stru));

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_ampdu_aggr_num::get switch error[%u]!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;

    aggr_num_ctl.aggr_num_switch = (hi_u8)oal_atoi(ac_name);
    if (aggr_num_ctl.aggr_num_switch == 0) {
        /* ��ָ���ۺϸ���ʱ���ۺϸ����ָ�Ϊ0 */
        aggr_num_ctl.aggr_num = 0;
    } else {
        /* ��ȡ�ۺϸ��� */
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_ampdu_aggr_num::get aggr_num error[%u]!}\r\n", ret);
            return ret;
        }

        aggr_num_ctl.aggr_num = (hi_u8)oal_atoi(ac_name);

        /* �����ۺ���������ж� */
        if (aggr_num_ctl.aggr_num > WLAN_AMPDU_TX_MAX_NUM) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_ampdu_aggr_num::num err[%d]!}\r\n", aggr_num_ctl.aggr_num);
            return ret;
        }
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_AGGR_NUM, sizeof(aggr_num_ctl));

    /* ��д��Ϣ�壬���� */
    if (memcpy_s(write_msg.auc_value, WAL_MSG_WRITE_MAX_LEN, &aggr_num_ctl, sizeof(aggr_num_ctl)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_set_ampdu_aggr_num::mem safe function err!}");
        return HI_FAIL;
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(aggr_num_ctl),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_ampdu_aggr_num::send event return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_DEBUG_MODE
#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_packet_xmit_send_event(oal_net_device_stru *netdev, hi_u8 *ra_mac_addr,
    hi_u8 tid, hi_u8 packet_num, hi_u16 packet_len)
{
    wal_msg_write_stru write_msg;
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_PACKET_XMIT, sizeof(mac_cfg_mpdu_ampdu_tx_param_stru));

    /* ��������������� */
    mac_cfg_mpdu_ampdu_tx_param_stru *aggr_tx_on_param = (mac_cfg_mpdu_ampdu_tx_param_stru *)(write_msg.auc_value);
    aggr_tx_on_param->packet_num    = packet_num;
    aggr_tx_on_param->tid           = tid;
    aggr_tx_on_param->us_packet_len = packet_len;

    if (memcpy_s(aggr_tx_on_param->auc_ra_mac, WLAN_MAC_ADDR_LEN, ra_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_PWR, "{wal_hipriv_packet_xmit::mem safe function err!}");
        return HI_FAIL;
    }

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
        sizeof(mac_cfg_mpdu_ampdu_tx_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_packet_xmit::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���ݰ�����

 �޸���ʷ      :
  1.��    ��   : 2013��9��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32 wal_hipriv_packet_xmit(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32             off_set;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u8              ra_mac_addr[WLAN_MAC_ADDR_LEN] = {0};
    hi_u8              *ra_mac_addr_ptr = ra_mac_addr;

    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_packet_xmit::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    hi_u8 tid = (hi_u8)oal_atoi(ac_name);
    if (tid >= WLAN_TID_MAX_NUM) {
        return HI_FAIL;
    }
    pc_param = pc_param + off_set;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_packet_xmit::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    pc_param = pc_param + off_set;

    hi_u8 packet_num = (hi_u8)oal_atoi(ac_name);

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_packet_xmit::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    hi_u16 packet_len = (hi_u16)oal_atoi(ac_name);
    if (packet_len < 30) { /* ���Ȳ���С��30 */
        return HI_FAIL;
    }
    pc_param += off_set;

    /* ��ȡMAC��ַ�ַ��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_packet_xmit::get mac err_code [%d]!}\r\n", ret);
        return ret;
    }
    /* ��ַ�ַ���ת��ַ���� */
    oal_strtoaddr(ac_name, ra_mac_addr_ptr, WLAN_MAC_ADDR_LEN);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_hipriv_packet_xmit_send_event(netdev, ra_mac_addr_ptr, tid, packet_num, packet_len);
    return ret;
}

/*****************************************************************************
 ��������  : ���ñ���ģʽ����

 �޸���ʷ      :
  1.��    ��   : 2014��2��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_set_auto_protection(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_u16                      us_len;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    hi_u32                      auto_protection_flag;

    /* ��ȡmib���� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_hipriv_set_auto_protection::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    auto_protection_flag = (hi_u32)oal_atoi(ac_name);

    us_len = sizeof(hi_u32);
    *(hi_u32 *)(write_msg.auc_value) = auto_protection_flag;
    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_AUTO_PROTECTION, us_len);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_auto_protection::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ֹͣ����ɨ������

 �޸���ʷ      :
  1.��    ��   : 2015��10��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_bgscan_enable(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32                off_set;
    hi_char               ac_stop[80] = {0}; /* ����Ԫ�ظ���Ϊ80 */
    hi_u32                ret;
    wal_msg_write_stru    write_msg;
    hi_u8                 *pen_bgscan_enable_flag = HI_NULL;

    ret = wal_get_cmd_one_arg(pc_param, ac_stop, 80, &off_set); /* �����������2---->80 */
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_SCAN, "wal_hipriv_scan_stop: get first arg fail.");
        return HI_FAIL;
    }

    /***************************************************************************
                            ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFIGD_BGSCAN_ENABLE, sizeof(hi_u8));

    /* ��������������� */
    pen_bgscan_enable_flag = (hi_u8 *)(write_msg.auc_value);

   *pen_bgscan_enable_flag = (hi_u8)oal_atoi(ac_stop);

    oam_warning_log1(0, OAM_SF_SCAN, "wal_hipriv_scan_stop:: bgscan_enable_flag= %d.", *pen_bgscan_enable_flag);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_packet_xmit::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_BW_HIEX
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������      : ����խ���л�������selfcts�Ĳ���
 �޸���ʷ      :
  1.��    ��   : 2019��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_hiex_config_selfcts(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru write_msg;
    hi_u32             off_set = 0;
    hi_char            ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_SELFCTS, sizeof(mac_cfg_tx_comp_stru));
    wlan_selfcts_param_stru *param = (wlan_selfcts_param_stru *)(write_msg.auc_value);

    /* ����selfctsʹ�� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::get selfcts error[%u]}\r\n", ret);
        return ret;
    }
    pc_param += off_set;

    param->selfcts = (hi_u8)oal_atoi(ac_arg);
    if ((param->selfcts != HI_TRUE) && (param->selfcts != HI_FALSE)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::invalid enable param!}\r\n");
        return HI_FAIL;
    }

    /* selfcts��ռ���ŵ�ʱ�� */
    ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::get duration error[%u]}\r\n", ret);
        return ret;
    }
    pc_param += off_set;

    param->duration = (hi_u8)oal_atoi(ac_arg);
    if (param->duration > WAL_HIPRIV_SELFCTS_DURATION_MAX) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::invalid duration param!}\r\n");
        return HI_FAIL;
    }

    /* ����selfcts��PER��ֵ */
    ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::get duration error[%u]}\r\n", ret);
        return ret;
    }

    param->us_per = (hi_u16)oal_atoi(ac_arg);
    if (param->us_per > WAL_HIPRIV_SELFCTS_PER_MAX) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::invalid PER param!}\r\n");
        return HI_FAIL;
    }

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(wlan_selfcts_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_hiex_config_selfcts::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����be,bk,vi,vo��ÿ�ε��ȱ��ĸ�����lowwater_line, high_waterline

 �޸���ʷ      :
  1.��    ��   : 2015��08��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_set_flowctl_param(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_u32                      off_set = 0;
    hi_char                     ac_param[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    mac_cfg_flowctl_param_stru  flowctl_param;
    mac_cfg_flowctl_param_stru *param = HI_NULL;

    /* sh hipriv.sh "Hisilicon0 set_flowctl_param 0/1/2/3 20 20 40" */
    /* 0/1/2/3 �ֱ����be,bk,vi,vo */
    /* ��ȡ�������Ͳ��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_param, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_flowctl_param::get queue_type error[%u]}\r\n", ret);
        return ret;
    }

    flowctl_param.queue_type = (hi_u8)oal_atoi(ac_param);

    /* ���ö��ж�Ӧ��ÿ�ε��ȱ��ĸ��� */
    pc_param += off_set;
    ret = wal_get_cmd_one_arg(pc_param, ac_param, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_flowctl_param::get burst_limit error[%d]}\r\n", ret);
        return (hi_u32)ret;
    }

    flowctl_param.us_burst_limit = (hi_u16)oal_atoi(ac_param);

    /* ���ö��ж�Ӧ������low_waterline */
    pc_param += off_set;
    ret = wal_get_cmd_one_arg(pc_param, ac_param, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_flowctl_param::get low_waterline error[%d]}\r\n", ret);
        return (hi_u32)ret;
    }

    flowctl_param.us_low_waterline = (hi_u16)oal_atoi(ac_param);

    /* ���ö��ж�Ӧ������high_waterline */
    pc_param += off_set;
    ret = wal_get_cmd_one_arg(pc_param, ac_param, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_flowctl_param::get high_waterline error[%d]}\r\n", ret);
        return (hi_u32)ret;
    }

    flowctl_param.us_high_waterline = (hi_u16)oal_atoi(ac_param);

    /* �����¼��ڴ� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_FLOWCTL_PARAM, sizeof(mac_cfg_flowctl_param_stru));
    param = (mac_cfg_flowctl_param_stru *)(write_msg.auc_value);

    param->queue_type = flowctl_param.queue_type;
    param->us_burst_limit = flowctl_param.us_burst_limit;
    param->us_low_waterline = flowctl_param.us_low_waterline;
    param->us_high_waterline = flowctl_param.us_high_waterline;

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_flowctl_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_flowctl_param:: return err_code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ�������״̬��Ϣ

 �޸���ʷ      :
  1.��    ��   : 2015��08��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_get_flowctl_stat(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              ret;

    /*  sh hipriv.sh "Hisilicon0 get_flowctl_stat" */
    /* �����¼��ڴ� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_GET_FLOWCTL_STAT, sizeof(hi_u8));

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_flowctl_stat:: return err_code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

/*****************************************************************************
 ��������  : ���ù����������

 �޸���ʷ      :
  1.��    ��   : 2015��1��16��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_setcountry(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32                        ret;
    hi_u32                        off_set;
    hi_char                       ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_char                      *puc_para = HI_NULL;

    /* �豸��up״̬���������ã�������down */
    if (wal_dev_is_running() == HI_TRUE) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_setcountry::device is busy,can not set country code!}\r\n");
        return HI_ERR_CODE_CONFIG_BUSY;
    }
    ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_setcountry::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    puc_para = &ac_arg[0];

    pc_param += off_set;
    /* �ж�������Ƿ������� */
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_user_info::cmd len error!}\r\n");
        return HI_FAIL;
    }
    if (strlen(puc_para) > (MAC_CONTRY_CODE_LEN - 1)) {
        return HI_FAIL;
    }
    ret = wal_regdomain_update(netdev, puc_para, MAC_CONTRY_CODE_LEN);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_setcountry::regdomain_update return err code %u!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ɾ��vap
*****************************************************************************/
hi_u32 wal_hipriv_del_vap(oal_net_device_stru *netdev)
{
    /* �豸��up״̬������ɾ����������down */
    if (oal_unlikely(0 != (OAL_IFF_RUNNING & oal_netdevice_flags(netdev)))) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_hipriv_del_vap::netdev status[%d] is busy, please down it first!}",
            oal_netdevice_flags(netdev));
        return HI_ERR_CODE_CONFIG_BUSY;
    }
    /* ȥע�� */
    oal_net_unregister_netdev(netdev);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_net_free_netdev(netdev);
#endif
    return HI_SUCCESS;
}

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������      : ʹ�ܵ͹���
 �����ʽ      : hipriv wlan0 pm_switch 1/0
 �޸���ʷ      :
  1.��    ��   : 2014��5��21��,������
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_set_pm_switch(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              ret;
    hi_u32              pm_cfg;

    if (pc_param == HI_NULL) {
        return HI_FAIL;
    }

    pm_cfg = (hi_u32)oal_atoi(pc_param);
    /* ����͹��ı�־ */
    set_under_ps(pm_cfg == 1);
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_PM_SWITCH, sizeof(hi_u32));
    *((hi_u32 *)(write_msg.auc_value)) = pm_cfg;
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_pm_switch::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������      : ����device ƽ̨�Ƿ��������͹���
 �����ʽ      : hipriv wlan0 pm_switch 1/0
 �޸���ʷ      :
  1.��    ��   : 2020��6��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_hipriv_set_wlan_pm_enable(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32              ret;
    hi_u32              pm_cfg;

    (void)netdev;
    if (pc_param == HI_NULL) {
        return HI_FAIL;
    }

    pm_cfg = (hi_u32)oal_atoi(pc_param);
    if (pm_cfg == 1) { /* 1: enable */
        ret = hi_wifi_plat_pm_enable();
    } else if (pm_cfg == 0) {  /* 0: disable */
        ret = hi_wifi_plat_pm_disable();
    } else {
        printk("parameter error, enbale:1, disable:0 \r\n");
        ret = HI_FAIL;
    }
    return ret;
}

hi_u32 wal_hipriv_setwk_fail_process(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_s32              pid;

    (void)netdev;

    if (pc_param == HI_NULL) {
        return HI_FAIL;
    }
    pid = (hi_u32)oal_atoi(pc_param);
    if (pid <= 0) {
        printk("[ERROR]pid less 0 \r\n");
        return HI_FAIL;
    }
    wlan_pm_set_wkfail_pid(pid);
    return HI_SUCCESS;
}

hi_u32 wal_hipriv_dump_pm_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u8   is_host;

    (void)netdev;

    if (pc_param == HI_NULL) {
        return HI_FAIL;
    }

    is_host = (hi_u8)oal_atoi(pc_param);
    if (is_host > 1) { /* > 1: ��Ч���� */
        printk("parameter error, host:1, device:0 \r\n");
        return HI_FAIL;
    }
    hi_wlan_dump_pm_info(is_host);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������      : ֪ͨdevice�࣬host˯��״̬
 �����ʽ      : hipriv wlan0 pm_switch 1/0
 �޸���ʷ      :
  1.��    ��   : 2020��6��4��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_hipriv_set_host_sleep_status(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32              ret;
    hi_u32              pm_cfg;

    (void)netdev;
    if (pc_param == HI_NULL) {
        return HI_FAIL;
    }

    pm_cfg = (hi_u32)oal_atoi(pc_param);
    if (pm_cfg == 1) { /* 1: enable */
        ret =  (hi_u32)hi_wifi_host_request_sleep(1);
    } else if (pm_cfg == 0) { /* 0: disable */
        ret = (hi_u32)hi_wifi_host_request_sleep(0);
    } else {
        printk("parameter error, sleep:1, wake:0 \r\n");
        ret = HI_FAIL;
    }
    return ret;
}

/*****************************************************************************
 ��������      :����device˯��ʱ���ر�TCXO
*****************************************************************************/
hi_u32 wal_hipriv_set_deepsleep_open_tcxo(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32  ret;
    hi_unref_param(netdev);
    hi_unref_param(pc_param);
    ret = hi_wifi_set_deepsleep_open_tcxo();
    return ret;
}

#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : �����·��Ķ�Ӧ���λ���ϱ���Ӧ��vap��Ϣ

 �޸���ʷ      :
  1.��    ��   : 2015��7��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_report_vap_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_u32                      flag_value;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_u32                      ret;

    /* sh hipriv.sh "wlan0 report_vap_info  flags_value" */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_report_vap_info::wal_get_cmd_one_arg return err_code [%u]!}\r\n",
            ret);
        return ret;
    }

    flag_value = (hi_u32)oal_atoi(ac_name);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_REPORT_VAP_INFO, sizeof(hi_s32));

    /* ��д��Ϣ�壬���� */
    *(hi_u32 *)(write_msg.auc_value) = flag_value;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_report_vap_info::wal_send_cfg_event return err code [%u]!}\r\n",
            ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : �������mac addrɨ���Ƿ�������
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_random_mac_addr_scan(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      ret;
    hi_u8                       rand_mac_addr_scan_switch;

    /* sh hipriv.sh "Hisilicon0 random_mac_addr_scan 0|1(����)" */
    /* ��ȡ֡���� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_random_mac_addr_scan::get switch return err_code[%d]!}", ret);
        return ret;
    }

    rand_mac_addr_scan_switch = (hi_u8)oal_atoi(ac_name);
    /* ���ص�ȡֵ��ΧΪ0|1,�������Ϸ����ж� */
    if (rand_mac_addr_scan_switch > 1) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_hipriv_set_random_mac_addr_scan::param is error, switch_value[%d]!}",
                       rand_mac_addr_scan_switch);
        return HI_FAIL;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_RANDOM_MAC_ADDR_SCAN, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = (hi_u32)rand_mac_addr_scan_switch;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_random_mac_addr_scan::return err code[%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_RF_110X_CALI_DPD
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����DPD

 �޸���ʷ      :
  1.��    ��   : 2014��6��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_start_dpd(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          ret;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_START_DPD, sizeof(wal_specific_event_type_param_stru));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(wal_specific_event_type_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_start_dpd::return err code[%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  :  ����UAPSD����

 �޸���ʷ      :
  1.��    ��   : 2016��1��30��,������
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32  wal_hipriv_set_uapsd_cap(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru       write_msg;
    hi_s32                   l_tmp;
    hi_u32                   off_set;
    hi_char                  ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                   ret;
    hi_u8                    orig_dev_state = wal_dev_is_running();

    if (wal_netdev_stop(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_cap::wal_netdev_stop failed\r\n");
        return HI_FAIL;
    }

    /* �˴���������"1"��"0"����ac_name */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_cap::wal_get_cmd_one_arg return err_code[%d]}\r\n", ret);
        return ret;
    }

    /* ��Խ������Ĳ�ͬ�����UAPSD���ؽ��в�ͬ������ */
    if (0 == (strcmp("0", ac_name))) {
        l_tmp = 0;
    } else if (0 == (strcmp("1", ac_name))) {
        l_tmp = 1;
    } else {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_cap::the log switch command is error [%p]!}\r\n",
                         (uintptr_t)ac_name);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_UAPSD_EN, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = l_tmp;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_cap::return err code [%u]!}\r\n", ret);
        return ret;
    }

    if (orig_dev_state == HI_TRUE) {
        if (wal_netdev_open(netdev) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_cap::wal_netdev_stop failed\r\n");
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ����non-HTģʽ�µ�����

 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32  wal_hipriv_set_rate(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru                  write_msg;
    hi_u32                              off_set;
    hi_u32                              ret;
    mac_cfg_non_ht_rate_stru           *set_rate_param = HI_NULL;
    wlan_legacy_rate_value_enum_uint8   rate_index;
    hi_char                             ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_RATE, sizeof(mac_cfg_non_ht_rate_stru));

    /* ��������������������� */
    set_rate_param = (mac_cfg_non_ht_rate_stru *)(write_msg.auc_value);

    /* ��ȡ����ֵ�ַ��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_rate::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    /* ����������Ϊ��һ������ */
    for (rate_index = 0; rate_index < WLAN_LEGACY_RATE_VALUE_BUTT; rate_index++) {
        if (!strcmp(g_pauc_non_ht_rate_tbl[rate_index], ac_arg)) {
            break;
        }
    }

    /* ������������TX�������е�Э��ģʽ */
    if (rate_index <= WLAN_SHORT_11B_11_M_BPS) {
        set_rate_param->protocol_mode = WLAN_11B_PHY_PROTOCOL_MODE;
    } else if (rate_index >= WLAN_LEGACY_OFDM_48M_BPS && rate_index <= WLAN_LEGACY_OFDM_9M_BPS) {
        set_rate_param->protocol_mode = WLAN_LEGACY_OFDM_PHY_PROTOCOL_MODE;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_rate::invalid rate!}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /* ����Ҫ����Ϊ����ֵ */
    set_rate_param->rate = rate_index;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_non_ht_rate_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_rate::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����HTģʽ�µ�����

 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32  wal_hipriv_set_mcs(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru            write_msg;
    hi_u32                        off_set;
    hi_u32                        ret;
    mac_cfg_tx_comp_stru          *set_mcs_param = HI_NULL;
    hi_s32                        l_mcs;
    hi_char                       ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_s32                        l_idx = 0;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MCS, sizeof(mac_cfg_tx_comp_stru));

    /* ��������������������� */
    set_mcs_param = (mac_cfg_tx_comp_stru *)(write_msg.auc_value);

    /* ��ȡ����ֵ�ַ��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mcs::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    /* ��������Ϸ��Լ�� */
    while (ac_arg[l_idx] != '\0') {
        if (isdigit(ac_arg[l_idx])) {
            l_idx++;
            continue;
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_mcs::input illegal!}\r\n");
            return HI_ERR_CODE_INVALID_CONFIG;
        }
    }

    /* ����Ҫ����Ϊ����ֵ */
    l_mcs = oal_atoi(ac_arg);
    if ((l_mcs < WAL_HIPRIV_HT_MCS_MIN) || (l_mcs > WAL_HIPRIV_HT_MCS_MAX)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mcs::input val out of range [%d]!}\r\n", l_mcs);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    set_mcs_param->param = (hi_u8)l_mcs;
    set_mcs_param->protocol_mode = WLAN_HT_PHY_PROTOCOL_MODE;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_tx_comp_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mcs::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ����

 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_hipriv_get_bw(oal_net_device_stru *netdev, hal_channel_assemble_enum_uint8  *pen_bw_index)
{
    hi_u32                         ret;
    wal_msg_query_stru             query_msg;
    wal_msg_stru                   *rsp_msg = HI_NULL;
    wal_msg_rsp_stru               *query_rsp_msg = HI_NULL;
    mac_cfg_tx_comp_stru           *set_bw_param = HI_NULL;

    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_hipriv_get_bw device NULL.");
        return HI_ERR_CODE_PTR_NULL;
    }

    query_msg.wid = WLAN_CFGID_SET_BW;
    /* ������Ϣ */
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_QUERY,
                             WAL_MSG_WID_LENGTH,
                             (hi_u8 *)&query_msg,
                             HI_TRUE,
                             &rsp_msg);
    if ((ret != HI_SUCCESS) || (rsp_msg == HI_NULL)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_bw::wal_alloc_cfg_event return err code %u!}\r\n", ret);
        return HI_FAIL;
    }

    /* ��������Ϣ */
    query_rsp_msg = (wal_msg_rsp_stru *)(rsp_msg->auc_msg_data);
    set_bw_param = (mac_cfg_tx_comp_stru *)(query_rsp_msg->auc_value);
    *pen_bw_index = (hal_channel_assemble_enum_uint8)set_bw_param->param;
    oal_free(rsp_msg);

    return ret;
}

/*****************************************************************************
 ��������  : ���ô���
 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_set_bw(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          off_set, ret;
    hal_channel_assemble_enum_uint8 bw_index = WLAN_BAND_ASSEMBLE_20M;
    hi_char                         ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_BW, sizeof(mac_cfg_tx_comp_stru));

    /* ��������������������� */
    mac_cfg_tx_comp_stru *set_bw_param = (mac_cfg_tx_comp_stru *)(write_msg.auc_value);

    /* ��ȡ����ֵ�ַ��� */
    if (wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_bw::wal_get_cmd_one_arg failed!}\r\n");
        return HI_FAIL;
    }

    if (strcmp(ac_arg, "info") == 0) {
        if (wal_hipriv_get_bw(netdev, &bw_index) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_bw::wal_hipriv_get_bw failed!}\r\n");
            return HI_FAIL;
        }
        if (bw_index == WLAN_BAND_ASSEMBLE_5M) {
            oam_info_log0(0, OAM_SF_ANY, "{wal_hipriv_set_bw::HIEX 5M.}\n");
        } else if (bw_index == WLAN_BAND_ASSEMBLE_10M) {
            oam_info_log0(0, OAM_SF_ANY, "{wal_hipriv_set_bw::HIEX 10M.}\n");
        } else if (bw_index == WLAN_BAND_ASSEMBLE_20M) {
            oam_info_log0(0, OAM_SF_ANY, "{wal_hipriv_set_bw::LEGACY 20M.}\n");
        }
        return HI_SUCCESS;
    } else if ((OAL_IFF_RUNNING & oal_netdevice_flags(netdev)) != 0) { /* �豸��up״̬���������ã�������down */
        oam_error_log1(0, OAM_SF_ANY, "{wal_hipriv_set_bw::device busy,down it first %d}", oal_netdevice_flags(netdev));
        return HI_FAIL;
    }

    /* ����Ҫ����Ϊ����ֵ */
    for (bw_index = 0; bw_index < WLAN_BAND_ASSEMBLE_AUTO; bw_index++) {
        if (strcmp(g_pauc_bw_tbl[bw_index], ac_arg) == 0) {
            break;
        }
    }

    /* ��������Ƿ��� */
    if (bw_index >= WLAN_BAND_ASSEMBLE_AUTO) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_bw::not support this bandwidth!}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    set_bw_param->param = (hi_u8)(bw_index);
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_tx_comp_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_bw::return err code [%u]!}\r\n", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ���ݳ���

 �޸���ʷ      :
  1.��    ��   : 2014��3��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_hipriv_always_tx(oal_net_device_stru *netdev, hi_u8 tx_flag)
{
    wal_msg_write_stru    write_msg;
    hi_u32                ret;
    mac_cfg_tx_comp_stru *set_bcast_param = HI_NULL;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_ALWAYS_TX, sizeof(mac_cfg_tx_comp_stru));

    /* ��������������������� */
    set_bcast_param = (mac_cfg_tx_comp_stru *)(write_msg.auc_value);
    set_bcast_param->param = tx_flag;
    if (tx_flag == 0) {
        set_bcast_param->payload_flag = RF_PAYLOAD_ALL_ZERO;
        set_bcast_param->payload_len = 0;
    } else {
        set_bcast_param->payload_flag = RF_PAYLOAD_RAND;
        set_bcast_param->payload_len = 2000; /* 2000:����payload���� */
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_tx_comp_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log2(0, OAM_SF_ANY, "{wal_hipriv_always_tx:: return Err=%u, tx_flag=%d}", ret, tx_flag);
    } else {
        if ((tx_flag == WAL_ALWAYS_TX_RF) || (tx_flag == WAL_ALWAYS_TX_DC)) {
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
            printk("OK\r\n");
#endif
        }
    }

    return ret;
}

/*****************************************************************************
 ��������  : ���ݳ���

 �޸���ʷ      :
  1.��    ��   : 2014��3��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_hipriv_always_rx(oal_net_device_stru *netdev, hi_u8 rx_flag, hi_u8 mac_filter_flag)
{
    wal_msg_write_stru    write_msg;
    hi_u32                ret;
    hi_u8                *param = write_msg.auc_value;

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&write_msg, sizeof(wal_msg_write_stru), 0, sizeof(wal_msg_write_stru));

    param[0] = rx_flag;
    param[1] = mac_filter_flag;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_ALWAYS_RX, 2); /* ���տ��غ͹��˿���ռ��2�ֽ� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + 2, /* ���տ��غ͹��˿���ռ��2�ֽ� */
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log2(0, OAM_SF_ANY, "{wal_hipriv_always_rx::return err code=%u, rx_flag=%d}", ret, rx_flag);
    } else {
        if (rx_flag == 1) {
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
            printk("OK\r\n");
#endif
        }
    }

    return ret;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
#if (LINUX_VERSION_CODE < kernel_version(3,4,35))
/*****************************************************************************
 ��������  : proc write����
 �������  : ��
 �������  : ��
 �� �� ֵ  : �����ֽڵĳ���
*****************************************************************************/
static hi_u32 wal_hipriv_proc_write(hi_s32 fd, const hi_char *pc_buffer, hi_u32 len, hi_void *data)
{
    hi_char  *pc_cmd = HI_NULL;
    hi_u32    ret;

    if (len > WAL_HIPRIV_CMD_MAX_LEN) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_hipriv_proc_write::ul_len>WAL_HIPRIV_CMD_MAX_LEN, ul_len [%d]!}\r\n", len);
        return HI_FAIL;
    }

    pc_cmd = oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, WAL_HIPRIV_CMD_MAX_LEN);
    if (oal_unlikely(pc_cmd == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_proc_write::alloc mem return null ptr!}\r\n");
        return HI_ERR_WIFI_WAL_MALLOC_FAIL;
    }
    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(pc_cmd, WAL_HIPRIV_CMD_MAX_LEN, 0, WAL_HIPRIV_CMD_MAX_LEN);

    ret = oal_copy_from_user((hi_void *)pc_cmd, len, pc_buffer, len);
    /* copy_from_user������Ŀ���Ǵ��û��ռ俽�����ݵ��ں˿ռ䣬ʧ�ܷ���û�б��������ֽ������ɹ�����0 */
    if (ret > 0) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_proc_write::oal_copy_from_user return ul_ret[%d]!}\r\n", ret);
        oal_mem_free(pc_cmd);
        return HI_ERR_WIFI_WAL_FAILURE;
    }

    pc_cmd[len - 1] = '\0';
    if (len == wal_hipriv_entry(pc_cmd, (hi_u32)len)) {
        oam_warning_log0(0, OAM_SF_ANY, "hipriv success!");
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "hipriv failed!");
    }
    oal_mem_free(pc_cmd);

    return len;
}
#endif
#endif
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
/*****************************************************************************
 ��������  : ����proc���
 �������  : p_proc_arg: ����proc�������˴���ʹ��
 �������  : ��
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 wal_hipriv_create_proc(hi_void *proc_arg)
{
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
    hi_u32           ret;
#endif

#if (LINUX_VERSION_CODE >= kernel_version(3,4,35)) || (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        g_proc_entry = HI_NULL;
#else

    /* 420ʮ���ƶ�Ӧ�˽�����0644 linuxģʽ���� S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH); */
    /* S_IRUSR�ļ������߾߿ɶ�ȡȨ��, S_IWUSR�ļ������߾߿�д��Ȩ��, S_IRGRP�û���߿ɶ�ȡȨ��, S_IROTH�����û��߿ɶ�ȡȨ�� */
    g_proc_entry = oal_create_proc_entry(WAL_HIPRIV_PROC_ENTRY_NAME, 420, NULL);    /* 420ʮ���ƶ�Ӧ�˽�����0644 */
    if (g_proc_entry == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_create_proc::oal_create_proc_entry return null ptr!}\r\n");
        return HI_FAIL;
    }

    g_proc_entry->data  = proc_arg;
    g_proc_entry->nlink = 1;        /* linux����procĬ��ֵ */
    g_proc_entry->read_proc  = HI_NULL;

    g_proc_entry->write_proc = (write_proc_t *)wal_hipriv_proc_write;

#endif
    /* hi1102-cb add sys for 51/02 */
#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
    g_gp_sys_kobject = oal_get_sysfs_root_object();
    if (g_gp_sys_kobject == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_create_proc::get sysfs root object failed!}");
        return HI_FALSE;
    }
    ret = (hi_u32)oal_debug_sysfs_create_group(g_gp_sys_kobject, &hipriv_attribute_group);
    return ret;
#else
    return HI_SUCCESS;
#endif
}

/*****************************************************************************
 ��������  : ɾ��proc
 �� �� ֵ  : HI_SUCCESS
*****************************************************************************/
hi_u32  wal_hipriv_remove_proc(hi_void)
{
/* ж��ʱɾ��sysfs */
    if (g_gp_sys_kobject != HI_NULL) {
        oal_debug_sysfs_remove_group(g_gp_sys_kobject, &hipriv_attribute_group);
        kobject_del(g_gp_sys_kobject);
        g_gp_sys_kobject = HI_NULL;
    }
    oal_conn_sysfs_root_obj_exit();
    oal_conn_sysfs_root_boot_obj_exit();
    if (g_proc_entry) {
        oal_remove_proc_entry(WAL_HIPRIV_PROC_ENTRY_NAME, HI_NULL);
        g_proc_entry = HI_NULL;
    }

    return HI_SUCCESS;
}
#endif
#endif

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ��ѯ�Ĵ���ֵ(hipriv "Hisilicon0 reginfo regtype(soc/mac/phy) startaddr endaddr")

 �޸���ʷ      :
  1.��    ��   : 2013��5��29��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_reg_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru           write_msg;
    hi_u32                       ret;
    hi_u16                       us_len;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    if (memcpy_s(write_msg.auc_value, sizeof(write_msg.auc_value), pc_param, strlen(pc_param)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_reg_info::mem safe function err!}");
        return HI_FAIL;
    }
    write_msg.auc_value[strlen(pc_param)] = '\0';
    us_len = (hi_u16)(strlen(pc_param) + 1);
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_REG_INFO, us_len);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_reg_info::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_WOW
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : hipriv host sleep function

 �޸���ʷ      :
  1.��    ��   : 2016��3��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_host_sleep_switch(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru       write_msg;
    hi_s32                   l_tmp;
    hi_u32                   off_set;
    hi_char                  ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                   ret;

    /* set FW no send any frame to driver, 0 will close this function: hipriv "wlan0 host_sleep 0|1" */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_host_sleep_switch::wal_get_cmd_one_arg return err_code [%u]!}\r\n",
            ret);
        return ret;
    }

    if ((0 != strcmp("0", ac_name)) && (0 != strcmp("1", ac_name))) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_host_sleep_switch::invalid switch value}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    l_tmp = oal_atoi(ac_name);

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_WOW_ACTIVATE_EN, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = l_tmp;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_wow_activate_switch::return err code[%u]!}\r\n", ret);
        return ret;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_HOST_SLEEP_EN, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = l_tmp;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_host_sleep_switch::return err code[%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : hipriv set wow function

 �޸���ʷ      :
  1.��    ��   : 2016��3��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_wow(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru       write_msg;
    hi_s32                   l_tmp;
    hi_u32                   off_set;
    hi_char                  ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                   ret;
    hi_char                 *pc_end = HI_NULL;

    /* Enable/disable WOW events: hipriv "wlan0 wow <value>" 0:clear all events, Bit 0:Magic Packet Bit 1:NetPattern
       Bit 2:loss-of-link Bit 3:retrograde tsf Bit 4:loss of beacon Bit 17:TCP keep alive timeout */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wow::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    if ((*ac_name != '0') || ((*(ac_name + 1) != 'x') && (*(ac_name + 1) != 'X'))) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow::invalid wow value}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    l_tmp = oal_strtol(ac_name, &pc_end, 16); /* 16: ת��Ϊ16���� */

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_WOW, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = l_tmp;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wow::return err code[%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡadd wow pattern�Ĳ���
*****************************************************************************/
static hi_u32 wal_hipriv_get_add_wow_pattern_param(hi_char *pc_param, hmac_cfg_wow_pattern_param_stru *wow_param)
{
    hi_char ac_value[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_char *pc_end = HI_NULL;
    hi_u32  data_offset, off_set, pattern_len;
    hi_u32  idx;
    hi_char high, low;

    /* pc_param ָ��'index', ����ȡ���ŵ� ac_index �� */
    if (wal_get_cmd_one_arg(pc_param, ac_value, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::get index failed!}");
        return HI_FAIL;
    }
    wow_param->us_pattern_index = (hi_u16)oal_strtol(ac_value, &pc_end, 10); /* 10: ת��Ϊ10���� */
    pc_param += off_set;

    /* pc_param ָ��'value', ����ȡ���ŵ�ac_value�� */
    if (wal_get_cmd_one_arg(pc_param, ac_value, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::get value failed!}");
        return HI_FAIL;
    }
    if ((*ac_value != '0') || ((*(ac_value + 1) != 'x') && (*(ac_value + 1) != 'X'))) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::invalid wow value}");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    wow_param->us_pattern_option = MAC_WOW_PATTERN_PARAM_OPTION_ADD;
    /* ���ȼ�ȥ [ �ո� + 0 + X ] */
    pattern_len = (off_set > 3) ? ((off_set - 3)>>1) : 0;    /* 3: ����ƫ���� */
    pattern_len = (pattern_len > WAL_HIPRIV_CMD_NAME_MAX_LEN) ? (WAL_HIPRIV_CMD_NAME_MAX_LEN) : pattern_len;
    wow_param->pattern_len = pattern_len;

    /* ת�� netpattern ��ʽ, ���ʽ���֧�� 40�ֽ� */
    for (idx = 0; idx < pattern_len; idx++) {
        /* ���ݱܿ� [ 0 + X ]  */
        data_offset = 2; /* 2: ����ƫ�� */
        if (isxdigit(ac_value[(idx<<1) + data_offset]) && isxdigit(ac_value[(idx<<1) + data_offset + 1])) {
            high = isdigit(ac_value[(idx<<1) + data_offset]) ? (ac_value[(idx<<1) + data_offset] - '0') :
                (hi_tolower((hi_u8)ac_value[(idx<<1) + data_offset]) - 'a' + 10); /* 10: ƫ���� */
            low  = isdigit(ac_value[(idx<<1) + data_offset + 1]) ? (ac_value[(idx<<1) + data_offset + 1] - '0') :
                (hi_tolower((hi_u8)ac_value[(idx<<1) + data_offset + 1]) - 'a' + 10); /* 10: ƫ���� */
            if ((hi_u8)high > 0xF || (hi_u8)low > 0xF) {
                oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::invalid wow value}\r\n");
                break;
            }
            wow_param->auc_pattern_value[idx] = (((hi_u8)high & 0xF)<<4) | ((hi_u8)low & 0xF); /* 4: ����4λ */
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::invalid wow value}\r\n");
            break;
        }
    }
    return HI_SUCCESS;
}

hi_u32 wal_get_add_wow_pattern_param(hi_u8 index, hi_char *pattern, hmac_cfg_wow_pattern_param_stru *cfg_wow_param)
{
    hi_u32 pattern_len, idx, data_offset;
    hi_char high, low;
    if ((index >= WOW_NETPATTERN_MAX_NUM) || (pattern == HI_NULL)) {
        oam_error_log2(0, 0, "wal_get_add_wow_pattern_param:: invalid_param, index[%d], pattern[%p]", index, pattern);
        return HI_FAIL;
    }

    cfg_wow_param->us_pattern_index = index;

    if ((*pattern != '0') || ((*(pattern + 1) != 'x') && (*(pattern + 1) != 'X'))) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_get_add_wow_pattern_param::invalid wow value}");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    cfg_wow_param->us_pattern_option = MAC_WOW_PATTERN_PARAM_OPTION_ADD;
    pattern_len = (strlen(pattern) > 2) ? ((strlen(pattern) - 2) >> 1) : 0; /* 2: ����ƫ���� */
    pattern_len = (pattern_len > WAL_HIPRIV_CMD_NAME_MAX_LEN) ? (WAL_HIPRIV_CMD_NAME_MAX_LEN) : pattern_len;
    cfg_wow_param->pattern_len = pattern_len;

    /* ת�� netpattern ��ʽ, ���ʽ���֧�� 40�ֽ� */
    for (idx = 0; idx < pattern_len; idx++) {
        /* ���ݱܿ� [ 0 + X ]  */
        data_offset = 2; /* 2: ����ƫ�� */
        if (isxdigit(pattern[(idx<<1) + data_offset]) && isxdigit(pattern[(idx<<1) + data_offset + 1])) {
            high = isdigit(pattern[(idx<<1) + data_offset]) ? (pattern[(idx<<1) + data_offset] - '0') :
                (hi_tolower((hi_u8)pattern[(idx<<1) + data_offset]) - 'a' + 10); /* 10: ƫ���� */
            low  = isdigit(pattern[(idx<<1) + data_offset + 1]) ? (pattern[(idx<<1) + data_offset + 1] - '0') :
                (hi_tolower((hi_u8)pattern[(idx<<1) + data_offset + 1]) - 'a' + 10); /* 10: ƫ���� */
            if ((hi_u8)high > 0xF || (hi_u8)low > 0xF) {
                oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::invalid wow value}\r\n");
                break;
            }
            cfg_wow_param->auc_pattern_value[idx] = (((hi_u8)high & 0xF)<<4) | ((hi_u8)low & 0xF); /* 4: ����4λ */
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::invalid wow value}\r\n");
            break;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : hipriv set wow pattern function
             hipriv.sh 'wlan0 wow_pattern add index 0x983B16F8F39C'
             hipriv.sh 'wlan0 wow_pattern del index'
             hipriv.sh 'wlan0 wow_pattern clr'

 �޸���ʷ      :
  1.��    ��   : 2016��3��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_wow_pattern(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hmac_cfg_wow_pattern_param_stru cfg_wow_param = {0};
    wal_msg_write_stru      write_msg;
    hi_char                 *pc_end = HI_NULL;
    hi_char                 ac_option[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_char                 ac_index[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                  retval, off_set;

    /* No options �C lists existing pattern list */
    if (pc_param == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }

    /* pc_param ָ��'clr|add|del', ����ȡ���ŵ�ac_option�� */
    if (wal_get_cmd_one_arg(pc_param, ac_option, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::get option failed");
        return HI_FAIL;
    }
    pc_param += off_set;
    /* add wow�¼� */
    if (strcmp("add", ac_option) == 0) {
        if (wal_hipriv_get_add_wow_pattern_param(pc_param, &cfg_wow_param) != HI_SUCCESS) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::get add param failed.}");
            return HI_FAIL;
        }
        /* ����pattern value���� */
        if (memcpy_s(&((hmac_cfg_wow_pattern_param_stru *)(write_msg.auc_value))->auc_pattern_value[0],
            WAL_HIPRIV_CMD_NAME_MAX_LEN, cfg_wow_param.auc_pattern_value, cfg_wow_param.pattern_len) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::copy pattern value failed.}");
            return HI_FAIL;
        }
    } else if (strcmp("del", ac_option) == 0) {
        /* pc_param ָ��'index', ����ȡ���ŵ� ac_index �� */
        if (wal_get_cmd_one_arg(pc_param, ac_index, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::get del index failed!}");
            return HI_FAIL;
        }
        cfg_wow_param.us_pattern_option = MAC_WOW_PATTERN_PARAM_OPTION_DEL;
        cfg_wow_param.us_pattern_index = (hi_u16)oal_strtol(ac_index, &pc_end, 10); /* 10: ת��Ϊ10���� */
    } else if (strcmp("clr", ac_option) == 0) {
        cfg_wow_param.us_pattern_option = MAC_WOW_PATTERN_PARAM_OPTION_CLR;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::invalid pattern OPTION}");
        return HI_FAIL;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_WOW_PATTERN, sizeof(hmac_cfg_wow_pattern_param_stru));
    /* ����pattern option���� */
    ((hmac_cfg_wow_pattern_param_stru *)(write_msg.auc_value))->us_pattern_option = cfg_wow_param.us_pattern_option;
    /* ����pattern index���� */
    ((hmac_cfg_wow_pattern_param_stru *)(write_msg.auc_value))->us_pattern_index  = cfg_wow_param.us_pattern_index;
    /* ����pattern pattern len���� */
    ((hmac_cfg_wow_pattern_param_stru *)(write_msg.auc_value))->pattern_len    = cfg_wow_param.pattern_len;
    retval = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hmac_cfg_wow_pattern_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(retval != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wow_pattern::return err code[%u]!}", retval);
    }

    return retval;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_PROMIS
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ������ر�monitorģʽ

 �޸���ʷ      :
  1.��    ��   : 2016��3��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_set_monitor_switch(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru write_msg;
    hi_u32             off_set;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u8              tmp;
    hi_u32             ret;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_monitor_switch::wal_get_cmd_one_arg return err_code %d!}\r\n",
            ret);
        return ret;
    }

    if ((strcmp("0", ac_name)) == 0) {
        tmp = 0;   /* 0: �رձ����ϱ� */
    } else if ((strcmp("1", ac_name)) == 0) {
        tmp = 0x1; /* 0x1: �ϱ��鲥(�㲥)���ݰ� */
    } else if ((strcmp("2", ac_name)) == 0) {
        tmp = 0x2; /* 0x2: �ϱ��������ݰ� */
    } else if ((strcmp("3", ac_name)) == 0) {
        tmp = 0x4; /* 0x4: �ϱ��鲥(�㲥)����� */
    } else if ((strcmp("4", ac_name)) == 0) {
        tmp = 0x8; /* 0x8: �ϱ���������� */
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_monitor_switch::command param is error!}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_MONITOR_EN, sizeof(hi_u8));
    *((hi_u8 *)(write_msg.auc_value)) = tmp;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_monitor_switch::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ������ر�ampdu���͹���

 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_ampdu_tx_on(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          off_set;
    hi_char                         ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                          ret;
    mac_cfg_ampdu_tx_on_param_stru  *aggr_tx_on_param = HI_NULL;
    hi_u8                           aggr_tx_on;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ampdu_tx_on::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    aggr_tx_on = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_AMPDU_TX_ON, sizeof(mac_cfg_ampdu_tx_on_param_stru));

    /* ��������������� */
    aggr_tx_on_param = (mac_cfg_ampdu_tx_on_param_stru *)(write_msg.auc_value);
    aggr_tx_on_param->aggr_tx_on = aggr_tx_on;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ampdu_tx_on_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ampdu_tx_on::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#if defined _PRE_WLAN_FEATURE_SIGMA
/*****************************************************************************
 ��������  : ����AP��STBC����

 �޸���ʷ      :
  1.��    ��   : 2014��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_hipriv_set_stbc_cap(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      ret;
    hi_u32                      value;

    if (oal_unlikely((netdev == HI_NULL) || (pc_param == HI_NULL))) {
        oam_error_log2(0, OAM_SF_ANY,
            "{wal_hipriv_set_stbc_cap::pst_cfg_net_dev or pc_param null ptr error %p, %p!}\r\n",
            (uintptr_t)netdev, (uintptr_t)pc_param);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* STBC���ÿ��ص�����: hipriv "vap0 set_stbc_cap 0 | 1"
            �˴���������"1"��"0"����ac_name
    */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_stbc_cap::wal_get_cmd_one_arg return err_code [%u]!}\r\n",
            ret);
        return ret;
    }

    /* ��Խ������Ĳ�ͬ�������TDLS���ÿ��� */
    if (0 == (strcmp("0", ac_name))) {
        value = 0;
    } else if (0 == (strcmp("1", ac_name))) {
        value = 1;
    } else {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_stbc_cap::the set stbc command is error %p!}\r\n",
            (uintptr_t)ac_name);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_STBC_CAP, sizeof(hi_u32));

    /* ��������������� */
    *((hi_u32 *)(write_msg.auc_value)) = value;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_stbc_cap::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ���÷�Ƭ������������
 �޸���ʷ      :
  1.��    ��   : 2014��1��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_frag_threshold(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          ret;
    hi_u16                          us_len;
    hi_char                         ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                          off_set = 0;
    mac_cfg_frag_threshold_stru     *threshold = HI_NULL;
    hi_u32                          thresholdval;

    /* ��ȡ��Ƭ���� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        hi_diag_log_msg_w0(0, "{wal_hipriv_frag_threshold::wal_get_cmd_one_arg failed.");
        return ret;
    }

    thresholdval = (hi_u32)oal_atoi(ac_name);
    if ((thresholdval < WLAN_FRAG_THRESHOLD_MIN) || (thresholdval > WLAN_FRAG_THRESHOLD_MAX)) {
        hi_diag_log_msg_w1(0, "{wal_hipriv_frag_threshold::ul_threshold value error [%d]!}", thresholdval);
        return HI_FAIL;
    }

    threshold = (mac_cfg_frag_threshold_stru *)(write_msg.auc_value);
    threshold->frag_threshold = thresholdval;
    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    us_len = sizeof(mac_cfg_frag_threshold_stru);
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_FRAG_THRESHOLD_REG, us_len);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_frag_threshold::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}
#endif

#if defined _PRE_WLAN_FEATURE_SIGMA
/*****************************************************************************
 ��������  : ����RTS������������
  �޸���ʷ      :
  1.��    ��   : 2014��1��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_rts_threshold(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_u16                      us_len;
    hi_char                       ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    mac_cfg_rts_threshold_stru  *threshold = HI_NULL;
    hi_u32                      thresholdval;

    /* ��ȡRTS���� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        hi_diag_log_msg_w0(0, "{wal_hipriv_rts_threshold::wal_get_cmd_one_arg failed!}");
        return ret;
    }

    thresholdval = (hi_u32)oal_atoi(ac_name);
    if ((thresholdval < WLAN_RTS_MIN) || (thresholdval > WLAN_RTS_MAX)) {
        hi_diag_log_msg_w1(0, "{wal_hipriv_rts_threshold::ul_threshold value error [%d]!}", thresholdval);
        return HI_FAIL;
    }
    threshold = (mac_cfg_rts_threshold_stru *)(write_msg.auc_value);
    threshold->rts_threshold = thresholdval;

    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    us_len = sizeof(mac_cfg_rts_threshold_stru);
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_RTS_THRESHHOLD, us_len);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_rts_threshold::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : д�Ĵ���

 �޸���ʷ      :
  1.��    ��   : 2013��9��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32  wal_hipriv_reg_write(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru           write_msg;
    hi_u32                       ret;
    hi_u16                       us_len;

    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    if (memcpy_s(write_msg.auc_value, WAL_MSG_WRITE_MAX_LEN, pc_param, strlen(pc_param)) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_set_ampdu_aggr_num::mem safe function err!}");
        return HI_FAIL;
    }

    write_msg.auc_value[strlen(pc_param)] = '\0';

    us_len = (hi_u16)(strlen(pc_param) + 1);

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_REG_WRITE, us_len);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_reg_write::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_DEBUG_MODE
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ��ȡĳһ��vap���շ���ͳ����Ϣ

 �޸���ʷ      :
  1.��    ��   : 2014��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_show_vap_pkt_stat(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru           write_msg;
    hi_u32                       ret;

    hi_unref_param(pc_param);
    /***************************************************************************
                                 ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_VAP_PKT_STAT, sizeof(hi_u32));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_show_vap_pkt_stat::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ����CCA ����
*****************************************************************************/
static hi_u32  wal_hipriv_set_cca_threshold(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru                      write_msg;
    hi_u32                                  off_set;
    hi_char                                 ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    /* ��ȡCCA���� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_cca_opt_log::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }

    hi_s32 cca_threshold = oal_atoi(ac_name);
    if (cca_threshold < HI_CCA_THRESHOLD_LO || cca_threshold > HI_CCA_THRESHOLD_HI) {
        oam_error_log1(0, 0, "wal_hipriv_set_cca_threshold:: invalid cca threshold[%d]", cca_threshold);
        return HI_FAIL;
    }
    hi_s32 *param = (hi_s32 *)write_msg.auc_value;
    *param = cca_threshold;

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_CCA_TH, sizeof(hi_s32));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hi_wifi_set_cca_threshold::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_ALG_CFG
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : cca_opt�㷨��־��������
        (1)ͳ�Ƶ���������: hipriv.sh "vap0 alg_tpc_log tpc_stat_log 11:22:33:44:55:66  2 500"
           ���������ĳһ��USER

 �޸���ʷ      :
  1.��    ��   : 2015��8��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_cca_opt_log(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru                      write_msg;
    hi_u32                                  off_set;
    hi_char                                 ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    mac_ioctl_alg_cca_opt_log_param_stru    *alg_cca_opt_log_param = HI_NULL;
    wal_ioctl_alg_cfg_stru                  alg_cfg;
    hi_u8                                   map_index = 0;

    alg_cca_opt_log_param = (mac_ioctl_alg_cca_opt_log_param_stru *)(write_msg.auc_value);

    /* ��ȡ���ò������� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_cca_opt_log::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }
    pc_param = pc_param + off_set;

    /* Ѱ��ƥ������� */
    alg_cfg = g_ast_alg_cfg_map[0];
    while (alg_cfg.pc_name != HI_NULL) {
        if (strcmp(alg_cfg.pc_name, ac_name) == 0) {
            break;
        }
        alg_cfg = g_ast_alg_cfg_map[++map_index];
    }

    /* û���ҵ���Ӧ������򱨴� */
    if (alg_cfg.pc_name == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_cca_opt_log::invalid alg_cfg command!}\r\n");
        return HI_FAIL;
    }

    /* ��¼�����Ӧ��ö��ֵ */
    alg_cca_opt_log_param->alg_cfg = g_ast_alg_cfg_map[map_index].alg_cfg;

    /* ���ֻ�ȡ�ض�֡���ʺ�ͳ����־�����:��ȡ����ֻ���ȡ֡���� */
    if (alg_cca_opt_log_param->alg_cfg == MAC_ALG_CFG_CCA_OPT_STAT_LOG_START) {
        /* ��ȡ���ò������� */
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_cca_opt_log::wal_get_cmd_one_arg return err_code [%u]!}", ret);
            return ret;
        }

        /* ��¼���� */
        alg_cca_opt_log_param->us_value = (hi_u16)oal_atoi(ac_name);
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_cca_opt_log_param_stru));

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_cca_opt_log_param_stru), (hi_u8 *)&write_msg,
        HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_cca_opt_log::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : �㷨ģ���������
        �����㷨����������: hipriv "vap0 alg_cfg vi_sch_limit 10"
        ���������ĳһ��VAP

 �޸���ʷ      :
  1.��    ��   : 2013��10��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_alg_cfg(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    hi_u8                       map_index = 0;
    mac_ioctl_alg_param_stru   *alg_param = (mac_ioctl_alg_param_stru *)(write_msg.auc_value);

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    /* ��ȡ���ò������� */
    if (wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_alg_cfg::wal_get_cmd_one_arg failed!}\r\n");
        return HI_FAIL;
    }

    /* Ѱ��ƥ������� */
    wal_ioctl_alg_cfg_stru alg_cfg = g_ast_alg_cfg_map[0];
    while (alg_cfg.pc_name != HI_NULL) {
        if (0 == strcmp(alg_cfg.pc_name, ac_name)) {
            break;
        }
        alg_cfg = g_ast_alg_cfg_map[++map_index];
    }

    /* û���ҵ���Ӧ������򱨴� */
    if (alg_cfg.pc_name == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_alg_cfg::invalid alg_cfg command!}\r\n");
        return HI_FAIL;
    }

    /* ��¼�����Ӧ��ö��ֵ */
    alg_param->alg_cfg = g_ast_alg_cfg_map[map_index].alg_cfg;

    /* ��ȡ��������ֵ */
    if (wal_get_cmd_one_arg(pc_param + off_set, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_alg_cfg::wal_get_cmd_one_arg failed!}\r\n");
        return HI_FAIL;
    }

    /* ��¼��������ֵ */
    alg_param->is_negtive = (ac_name[0] == '-');
    alg_param->value = (hi_u32)((ac_name[0] == '-') ? (-1 * oal_atoi(ac_name)) : oal_atoi(ac_name));
    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_param_stru));

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_alg_cfg::return err code [%u]!}\r\n", ret);
        return ret;
    }

    printk("OK\r\n");
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_ALG_CFG
static hi_u32  wal_hipriv_tpc_log_cfg(hi_char *pc_param, mac_ioctl_alg_tpc_log_param_stru *alg_tpc_log_param,
    hi_u32* off_set, hi_char *ac_name, hi_u8 *stop_flag)
{
    hi_u32 ret = wal_hipriv_get_mac_addr(pc_param, alg_tpc_log_param->auc_mac_addr, WLAN_MAC_ADDR_LEN, off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_tpc_log::wal_hipriv_get_mac_addr failed!}\r\n");
        return ret;
    }
    pc_param += *off_set;

    while ((*pc_param == '\0') || (*pc_param == ' ')) {
        if (*pc_param == '\0') {
            *stop_flag = HI_TRUE;
            break;
        }
        ++pc_param;
    }

    /* ��ȡҵ������ֵ */
    if (*stop_flag != HI_TRUE) {
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_tpc_log::wal_get_cmd_one_arg return err_code %u}\n", ret);
            return ret;
        }

        alg_tpc_log_param->ac_no = (hi_u8)oal_atoi(ac_name);
        pc_param = pc_param + *off_set;

        *stop_flag = HI_FALSE;
        while ((*pc_param == ' ') || (*pc_param == '\0')) {
            if (*pc_param == '\0') {
                *stop_flag = HI_TRUE;
                break;
            }
            ++pc_param;
        }

        if (*stop_flag != HI_TRUE) {
            /* ��ȡ��������ֵ */
            ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, off_set);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(0, OAM_SF_ANY,
                    "{wal_hipriv_tpc_log::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
                return ret;
            }

            /* ��¼��������ֵ */
            alg_tpc_log_param->us_value = (hi_u16)oal_atoi(ac_name);
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : tpc�㷨��־��������
        (1)ͳ�Ƶ���������: hipriv.sh "vap0 alg_tpc_log tpc_stat_log 11:22:33:44:55:66  2 500"
           ���������ĳһ��USER
        (2)��ȡ���ʵ���������: hipriv.sh "vap0 alg_tpc_log tpc_get_frame_pow <frm>_power"
            ����, <frm>�ַ�����ȡֵ����:
            - rts
            - ctsack
            - onepkt
            - selfcts
            - cfend
            - ndp
            - report

 �޸���ʷ      :
  1.��    ��   : 2015��1��12��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_tpc_log(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru                  write_msg;
    hi_u32                              off_set;
    hi_char                             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    hi_u8                               map_index = 0;
    hi_u8                               stop_flag = HI_FALSE;

    mac_ioctl_alg_tpc_log_param_stru *alg_tpc_log_param = (mac_ioctl_alg_tpc_log_param_stru *)(write_msg.auc_value);

    /* ��ȡ���ò������� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_tpc_log::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    pc_param = pc_param + off_set;

    /* Ѱ��ƥ������� */
    wal_ioctl_alg_cfg_stru alg_cfg = g_ast_alg_cfg_map[0];
    while (alg_cfg.pc_name != HI_NULL) {
        if (0 == strcmp(alg_cfg.pc_name, ac_name)) {
            break;
        }
        alg_cfg = g_ast_alg_cfg_map[++map_index];
    }

    /* û���ҵ���Ӧ������򱨴� */
    if (alg_cfg.pc_name == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_tpc_log::invalid alg_cfg command!}\r\n");
        return HI_FAIL;
    }

    /* ��¼�����Ӧ��ö��ֵ */
    alg_tpc_log_param->alg_cfg = g_ast_alg_cfg_map[map_index].alg_cfg;

    /* ���ֻ�ȡ�ض�֡���ʺ�ͳ����־�����:��ȡ����ֻ���ȡ֡���� */
    if (alg_tpc_log_param->alg_cfg == MAC_ALG_CFG_TPC_GET_FRAME_POW) {
        /* ��ȡ���ò������� */
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_tpc_log::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
            return ret;
        }
        /* ��¼�����Ӧ��֡���� */
        alg_tpc_log_param->pc_frame_name = ac_name;
    } else {
        ret = wal_hipriv_tpc_log_cfg(pc_param, alg_tpc_log_param, &off_set, ac_name, &stop_flag);
        if (ret != HI_SUCCESS) {
            return ret;
        }
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_tpc_log_param_stru));

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
        sizeof(mac_ioctl_alg_tpc_log_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_tpc_log::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}


static hi_u32  wal_hipriv_ar_log_cfg(mac_ioctl_alg_ar_log_param_stru *alg_ar_log_param, hi_char *pc_param,
    hi_u32 *off_set, hi_char *ac_name, hi_u8 *stop_flag)
{
    hi_u8                               map_index = 0;

    /* ��ȡ���ò������� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_log_cfg::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    pc_param = pc_param + *off_set;

    /* Ѱ��ƥ������� */
    wal_ioctl_alg_cfg_stru alg_cfg = g_ast_alg_cfg_map[0];
    while (alg_cfg.pc_name != HI_NULL) {
        if (0 == strcmp(alg_cfg.pc_name, ac_name)) {
            break;
        }
        alg_cfg = g_ast_alg_cfg_map[++map_index];
    }

    /* û���ҵ���Ӧ������򱨴� */
    if (alg_cfg.pc_name == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ar_log_cfg::invalid alg_cfg command!}\r\n");
        return HI_FAIL;
    }

    /* ��¼�����Ӧ��ö��ֵ */
    alg_ar_log_param->alg_cfg = g_ast_alg_cfg_map[map_index].alg_cfg;

    ret = wal_hipriv_get_mac_addr(pc_param, alg_ar_log_param->auc_mac_addr, WLAN_MAC_ADDR_LEN, off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ar_log_cfg::wal_hipriv_get_mac_addr failed!}\r\n");
        return ret;
    }
    pc_param += *off_set;

    while ((*pc_param == ' ') || (*pc_param == '\0')) {
        if (*pc_param == '\0') {
            *stop_flag = HI_TRUE;
            break;
        }
        ++pc_param;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : autorate�㷨��־��������
        �����㷨����������: hipriv "vap0 alg_ar_log ar_stat_log 11:22:33:44:55:66  2 500"
        ���������ĳһ��USER

 �޸���ʷ      :
  1.��    ��   : 2013��10��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_ar_log(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru                  write_msg;
    hi_u32                              off_set;
    hi_char                             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    hi_u8                               stop_flag = HI_FALSE;

    mac_ioctl_alg_ar_log_param_stru *alg_ar_log_param = (mac_ioctl_alg_ar_log_param_stru *)(write_msg.auc_value);

    hi_u32 ret = wal_hipriv_ar_log_cfg(alg_ar_log_param, pc_param, &off_set, ac_name, &stop_flag);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ar_log::wal_hipriv_ar_log_cfg failed!}\r\n");
        return ret;
    }

    /* ��ȡҵ������ֵ */
    if (stop_flag != HI_TRUE) {
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_log::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
            return ret;
        }

        alg_ar_log_param->ac_no = (hi_u8)oal_atoi(ac_name);
        pc_param = pc_param + off_set;

        stop_flag = HI_FALSE;
        while ((*pc_param == ' ') || (*pc_param == '\0')) {
            if (*pc_param == '\0') {
                stop_flag = HI_TRUE;
                break;
            }
            ++pc_param;
        }

        if (stop_flag != HI_TRUE) {
            /* ��ȡ��������ֵ */
            ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_log::wal_get_cmd_one_arg return err_code %u}\n", ret);
                return ret;
            }

            /* ��¼��������ֵ */
            alg_ar_log_param->us_value = (hi_u16)oal_atoi(ac_name);
        }
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_ar_log_param_stru));

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_ar_log_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_log::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_ALG_CFG_TEST
/*****************************************************************************
 ��������  : autorate�㷨������������:
            ���������ĳһ��USER
            �����㷨����������: hipriv "vap0 alg_ar_test cycle_rate 11:22:33:44:55:66 1"
            ���������ĳһ��USER

 �޸���ʷ      :
  1.��    ��   : 2013��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_ar_test(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru write_msg;
    hi_u32             offset = 0;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_u8              map_index = 0;

    mac_ioctl_alg_ar_test_param_stru *alg_ar_test_param = (mac_ioctl_alg_ar_test_param_stru *)(write_msg.auc_value);

    /* ��ȡ���ò������� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_test::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    pc_param = pc_param + offset;

    /* Ѱ��ƥ������� */
    wal_ioctl_alg_cfg_stru alg_cfg = g_ast_alg_cfg_map[0];
    while (alg_cfg.pc_name != HI_NULL) {
        if (0 == strcmp(alg_cfg.pc_name, ac_name)) {
            break;
        }
        alg_cfg = g_ast_alg_cfg_map[++map_index];
    }

    /* û���ҵ���Ӧ������򱨴� */
    if (alg_cfg.pc_name == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ar_test::invalid alg_cfg command!}\r\n");
        return HI_FAIL;
    }

    /* ��¼�����Ӧ��ö��ֵ */
    alg_ar_test_param->alg_cfg = g_ast_alg_cfg_map[map_index].alg_cfg;

    ret = wal_hipriv_get_mac_addr(pc_param, alg_ar_test_param->auc_mac_addr, WLAN_MAC_ADDR_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_ar_test::wal_hipriv_get_mac_addr failed!}\r\n");
        return ret;
    }
    pc_param += offset;

    /* ��ȡ��������ֵ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_test::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    /* ��¼��������ֵ */
    alg_ar_test_param->us_value = (hi_u16)oal_atoi(ac_name);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_ar_test_param_stru));
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_ar_test_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_ar_test::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

/*****************************************************************************
 ��������  : ͳ��ָ��tid��������

 �޸���ʷ      :
  1.��    ��   : 2014��1��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_hipriv_get_mac_addr(const hi_char *pc_param, hi_u8 mac_addr[], hi_u8 addr_len, hi_u32 *pul_total_offset)
{
    hi_u32                      off_set      = 0;
    hi_u32                      ret;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    /* ��ȡmac��ַ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_mac_addr::wal_get_cmd_one_arg return err_code [%u]!}\r\n",
            ret);
        return ret;
    }
    oal_strtoaddr(ac_name, mac_addr, addr_len);

    *pul_total_offset = off_set;

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP_DEBUG
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  : ָ���򿪻��߹ر�sta��edca�Ż�����

 �޸���ʷ      :
  1.��    ��   : 2014��1��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_set_edca_opt_switch_sta(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u8               flag;
    hi_u8               *puc_value       = 0;
    hi_u32              ret;
    hi_u32              off_set      = 0;
    mac_vap_stru        *mac_vap     = HI_NULL;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN];

    /* sh hipriv.sh "vap0 set_edca_switch_sta 1/0" */
    /* ��ȡmac_vap */
    mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap->vap_mode != WLAN_VAP_MODE_BSS_STA) {
        oam_warning_log0(0, OAM_SF_EDCA, "{wal_hipriv_set_edca_opt_switch_sta:: only STA_MODE support}");
        return HI_FAIL;
    }

    /* ��ȡ���ò��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_EDCA,
            "{wal_hipriv_set_edca_opt_switch_sta::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    flag = (hi_u8)oal_atoi(ac_name);
    /* �Ƿ����ò��� */
    if (flag > 1) {
        oam_warning_log0(0, OAM_SF_EDCA, "wal_hipriv_set_edca_opt_switch_sta, invalid config, should be 0 or 1");
        return HI_SUCCESS;
    }

    /* �����¼��ڴ� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_EDCA_OPT_SWITCH_STA, sizeof(hi_u8));
    puc_value = (hi_u8 *)(write_msg.auc_value);
    *puc_value = flag;

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_EDCA, "{wal_hipriv_set_edca_opt_switch_sta::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ָ���򿪻��߹ر�ap��edca�Ż�����

 �޸���ʷ      :
  1.��    ��   : 2014��1��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_set_edca_opt_switch_ap(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u8               flag;
    hi_u8               *puc_value       = 0;
    hi_u32              ret;
    hi_u32              off_set      = 0;
    mac_vap_stru        *mac_vap     = HI_NULL;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN];

    /* sh hipriv.sh "vap0 set_edca_switch_ap 1/0" */
    /* ��ȡmac_vap */
    mac_vap = oal_net_dev_priv(netdev);
    if ((mac_vap->vap_mode != WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        && (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)
#endif
    ) {
        oam_warning_log0(0, OAM_SF_EDCA, "{wal_hipriv_set_edca_opt_cycle_ap:: only AP_MODE support}");
        return HI_FAIL;
    }

    /* ��ȡ���ò��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_EDCA,
                         "{wal_hipriv_set_edca_opt_cycle_ap::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    flag = (hi_u8)oal_atoi(ac_name);
    /* �Ƿ����ò��� */
    if (flag > 1) {
        oam_warning_log0(0, OAM_SF_EDCA, "wal_hipriv_set_edca_opt_cycle_ap, invalid config, should be 0 or 1");
        return HI_SUCCESS;
    }

    /* �����¼��ڴ� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_EDCA_OPT_SWITCH_AP, sizeof(hi_u8));
    puc_value = (hi_u8 *)(write_msg.auc_value);
    *puc_value = flag;

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_EDCA, "{wal_hipriv_set_edca_opt_switch_ap::return err_code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����edca��������������

 �޸���ʷ      :
  1.��    ��   : 2014��1��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_u32  wal_hipriv_set_edca_opt_cycle_ap(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              cycle_ms;
    hi_u32             *pul_value       = 0;
    hi_u32              ret;
    hi_u32              off_set      = 0;
    mac_vap_stru       *mac_vap     = HI_NULL;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN];

    /* sh hipriv.sh "vap0 set_edca_cycle_ap 200" */
    /* ��ȡmac_vap */
    mac_vap = oal_net_dev_priv(netdev);
    if ((mac_vap->vap_mode != WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
    || (mac_vap->vap_mode != WLAN_VAP_MODE_MESH)
#endif
    ) {
        oam_warning_log0(0, OAM_SF_EDCA, "{wal_hipriv_set_edca_opt_cycle_ap:: only AP_MODE support}");
        return HI_FAIL;
    }

    /* ��ȡ����ֵ */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_EDCA,
            "{wal_hipriv_set_edca_opt_cycle_ap::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    cycle_ms = (hi_u32)oal_atoi(ac_name);

    /* �����¼��ڴ� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_EDCA_OPT_CYCLE_AP, sizeof(hi_u32));
    pul_value = (hi_u32 *)(write_msg.auc_value);
    *pul_value = cycle_ms;

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_EDCA, "{wal_hipriv_set_edca_opt_cycle_ap::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������  :  ����VAP mib

 �޸���ʷ      :
  1.��    ��   : 2014��2��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd��Ա������һ����Աwal_hipriv_getcountry��pc_param��ָ������ݽ������޸ģ�lint_t e818�澯���� */
static hi_u32  wal_hipriv_set_mib(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_u16                      us_len;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    hi_u32                      mib_idx;
    hi_u32                      mib_value;
    mac_cfg_set_mib_stru        *set_mib = HI_NULL;

    /* ��ȡ�趨mib���� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mib::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;

    mib_idx = (hi_u32)oal_atoi(ac_name);

    /* ��ȡ�趨�� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mib::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    mib_value = (hi_u32)oal_atoi(ac_name);

    set_mib = (mac_cfg_set_mib_stru *)(write_msg.auc_value);
    set_mib->mib_idx   = mib_idx;
    set_mib->mib_value = mib_value;
    us_len = sizeof(mac_cfg_set_mib_stru);

    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MIB, us_len);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mib::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡVAP mib

 �޸���ʷ      :
  1.��    ��   : 2014��2��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_get_mib(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_u16                      us_len;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    hi_u32                      mib_idx;

    /* ��ȡmib���� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_mib::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    mib_idx = (hi_u32)oal_atoi(ac_name);

    us_len = sizeof(hi_u32);
    *(hi_u32 *)(write_msg.auc_value) = mib_idx;
    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_GET_MIB, us_len);

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_mib::return err_code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_STA_PM
#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ˽�����PM���ܹرտ���

 �޸���ʷ      :
  1.��    ��   : 2014��12��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32  wal_hipriv_sta_ps_mode(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru           write_msg;
    hi_u32                       off_set;
    hi_char                      ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    mac_cfg_ps_mode_param_stru   *ps_mode_param = HI_NULL;
    oal_net_device_stru          *netdev_tmp = HI_NULL;
    mac_vap_stru                 *mac_vap = HI_NULL;
    mac_device_stru              *mac_dev = mac_res_get_dev();

    hi_unref_param(netdev);

    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_sta_ps_mode::wal_get_cmd_one_arg fail!}");
        return ret;
    }

    hi_u8 vap_ps_mode = (hi_u8)oal_atoi(ac_name);
    /* Ѱ��STA */
    for (hi_u8 vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            continue;
        }
        if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
            break;
        }
    }
    if (mac_vap == HI_NULL) {
        return HI_FAIL;
    }
    netdev_tmp = hmac_vap_get_net_device(mac_vap->vap_id);
    if (netdev_tmp == HI_NULL) {
        oam_error_log0(0, 0, "wal_hipriv_sta_ps_mode sta device not fonud.");
        return HI_FAIL;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_PS_MODE, sizeof(mac_cfg_ps_mode_param_stru));

    /* ��������������� */
    ps_mode_param = (mac_cfg_ps_mode_param_stru *)(write_msg.auc_value);
    ps_mode_param->vap_ps_mode = vap_ps_mode;

    ret = wal_send_cfg_event(netdev_tmp,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ps_mode_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_ps_mode::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ˽������,sta psm��listen interval / tbtt offset

 �޸���ʷ      :
  1.��    ��   : 2015��5��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_hipriv_sta_pm_on(oal_net_device_stru *netdev, const hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          off_set;
    hi_char                         ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                          ret;
    hi_u8                           sta_pm_open;
    mac_cfg_ps_open_stru            *sta_pm_open_info = HI_NULL;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_sta_pm_open::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    sta_pm_open = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_STA_PM_ON, sizeof(mac_cfg_ps_open_stru));

    /* ��������������� */
    sta_pm_open_info = (mac_cfg_ps_open_stru *)(write_msg.auc_value);
    /* MAC_STA_PM_SWITCH_ON / MAC_STA_PM_SWITCH_OFF */
    sta_pm_open_info->pm_enable      = sta_pm_open;
    sta_pm_open_info->pm_ctrl_type   = MAC_STA_PM_CTRL_TYPE_HOST;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ps_open_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_pm_open::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_HIPRIV
hi_u32 wal_hipriv_sta_set_psm_offset(oal_net_device_stru *netdev, hi_char *param)
{
    wal_msg_write_stru      write_msg;
    hi_u32                  off_set;
    hi_char                 name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    hi_u32                  ret;
    hi_u16                  beacon_timeout;
    hi_u16                  tbtt_offset;
    hi_u16                  ext_tbtt_offset;
    mac_cfg_ps_param_stru   *cfg_ps_para = HI_NULL;

    /* beacon timeout */
    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_sta_psm_param::btout arg error [%d]!}", ret);
        return ret;
    }

    beacon_timeout = (hi_u16)oal_atoi(name);
    param = param + off_set;

    /* tbtt offset */
    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_psm_param::tbtt arg error [%d]!}", ret);
        return ret;
    }

    tbtt_offset = (hi_u16)oal_atoi(name);
    param = param + off_set;

    /* ext tbtt offset */
    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_psm_param::ext tbtt arg error [%d]!}", ret);
        return ret;
    }

    ext_tbtt_offset = (hi_u16)oal_atoi(name);

    oam_info_log3(0, OAM_SF_PWR, "{wal_hipriv_sta_psm_param::[bcn tout] %d [tbtt] %d [ext] %d}!",
                  beacon_timeout, tbtt_offset, ext_tbtt_offset);

    /***************************************************************************
      ���¼���wal�㴦��
     ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_PSM_PARAM, sizeof(mac_cfg_ps_param_stru));

    /* ��������������� */
    cfg_ps_para = (mac_cfg_ps_param_stru *)(write_msg.auc_value);
    cfg_ps_para->beacon_timeout      = beacon_timeout;
    cfg_ps_para->tbtt_offset         = tbtt_offset;
    cfg_ps_para->ext_tbtt_offset     = ext_tbtt_offset;

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_ps_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_psm_param::send evt error [%d]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_u32 wal_hipriv_sta_set_offload_param(oal_net_device_stru *netdev, hi_char *param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              offset;
    hi_char             name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    mac_cfg_psm_offset  cfg;

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&cfg, sizeof(mac_cfg_psm_offset), 0, sizeof(mac_cfg_psm_offset));
    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR,
                         "{wal_hipriv_sta_set_psm_offset::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }

    if (strcmp("free_arp_interval", name) == 0) {
        cfg.type = MAC_PSM_FREE_ARP_INTERVAL;
    }
    param = param + offset;

    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR,
                         "{wal_hipriv_sta_set_psm_offset::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }

    cfg.value = (hi_u16)oal_atoi(name);
    cfg.resv = 0;
   /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_PSM_OFFSET, sizeof(mac_cfg_psm_offset));
    if (memcpy_s(write_msg.auc_value, sizeof(mac_cfg_psm_offset), &cfg, sizeof(mac_cfg_psm_offset)) != EOK) {
        oam_error_log0(0, OAM_SF_PWR, "{wal_hipriv_sta_set_psm_offset::mem safe function err!}");
        return HI_FAIL;
    }
    /* ��������������� */
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_psm_offset),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_set_psm_offset::return err code [%u]!}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32 wal_hipriv_sta_set_hw_ps_mode(oal_net_device_stru *netdev, hi_char *param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      off_set = 0;
    hi_u8                       hw_ps_mode;

    /* ��ȡ�趨��ֵ */
    ret = wal_get_cmd_one_arg(param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_set_hw_ps_mode::get_one_arg return err_code [%d]!}", ret);
        return ret;
    }

    hw_ps_mode = (hi_u8)oal_atoi(ac_name);
    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_STA_HW_PS_MODE, sizeof(hi_u8));
    *(hi_u8 *)(write_msg.auc_value) = hw_ps_mode;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_sta_set_hw_ps_mode::return err code [%u]!}", ret);
        return ret;
    }
    return HI_SUCCESS;
}
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ˽�����UAPSD��������

 �޸���ʷ      :
  1.��    ��   : 2014��12��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_hipriv_set_uapsd_para(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      ret;
    mac_cfg_uapsd_sta_stru     *uapsd_param = HI_NULL;
    hi_u8                       max_sp_len;
    hi_u8                       ac;
    hi_u8                       delivery_map = 0;
    hi_u8                       orig_dev_state = wal_dev_is_running();

    if (wal_netdev_stop(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_para::wal_netdev_stop failed\r\n");
        return HI_FAIL;
    }

    if ((OAL_IFF_RUNNING & oal_netdevice_flags(netdev)) != 0) {
        oam_error_log1(0, OAM_SF_ANY,
            "{wal_hipriv_set_uapsd_para::device is busy, please down it first %d!}\n",
            oal_netdevice_flags(netdev));
        return HI_FAIL;
    }

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY,
                         "{wal_hipriv_set_uapsd_para::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    max_sp_len = (hi_u8)oal_atoi(ac_name);

    for (ac = 0; ac < WLAN_WME_AC_BUTT; ac++) {
        pc_param = pc_param + off_set;
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_ANY,
                             "{wal_hipriv_set_uapsd_para::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
            return ret;
        }

        /* delivery_enabled�Ĳ������� */
        delivery_map |= (hi_u8)(((hi_u8)oal_atoi(ac_name) & BIT0) << ac);
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_UAPSD_PARA, sizeof(mac_cfg_uapsd_sta_stru));

    /* ��������������� */
    uapsd_param = (mac_cfg_uapsd_sta_stru *)(write_msg.auc_value);
    uapsd_param->max_sp_len   = max_sp_len;
    uapsd_param->delivery_map = delivery_map;
    /* trigger_enabled ���������� trigger��deliveryһ�� */
    uapsd_param->trigger_map  = delivery_map;
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_uapsd_sta_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_set_uapsd_para::return err code [%u]!}\r\n", ret);
        return ret;
    }

    if (orig_dev_state == HI_TRUE) {
        if (wal_netdev_open(netdev) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_uapsd_para::wal_netdev_open failed\r\n");
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}
#endif
#endif

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined (_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ����20M short gi����
 �޸���ʷ      :
  1.��    ��   : 2019��1��24��
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
hi_u32  wal_hipriv_set_shortgi20(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru       write_msg;
    hi_s32                   l_tmp;
    hi_u32                   off_set;
    hi_char                  ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                   ret;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_hipriv_set_shortgi20::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    if (strcmp("0", ac_name) == 0) {
        l_tmp = 0;
    } else if (strcmp("1", ac_name) == 0) {
        l_tmp = 1;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_shortgi20::command param is error!}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SHORTGI, sizeof(hi_s32));
    *((hi_s32 *)(write_msg.auc_value)) = l_tmp;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_shortgi20::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 �� �� ��  : wal_hipriv_set_retry_limit
 ��������  : ��������ش�����
 �������  : [1]net_dev
             [2]pc_param
 �� �� ֵ  : static hi_u32
*****************************************************************************/
/* ������g_ast_hipriv_cmd��Ա������һ����Աwal_hipriv_getcountry��pc_param��ָ������ݽ������޸ģ�lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_retry_limit(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                      ret;
    mac_cfg_retry_param_stru   *set_param = HI_NULL;
    hi_u8                       type;
    hi_u8                       limit;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_retry_limit::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;

    type = (hi_u8)oal_atoi(ac_name);

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{wal_hipriv_set_retry_limit1::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    limit = (hi_u8)oal_atoi(ac_name);

    set_param = (mac_cfg_retry_param_stru *)(write_msg.auc_value);
    set_param->type   = type;
    set_param->limit = limit;

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_RETRY_LIMIT, sizeof(mac_cfg_retry_param_stru));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_retry_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_retry_limit::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_MESH
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 �� �� ��  : wal_hipriv_set_report_param
 ��������  : ���������ϱ�lwip �ش�������������Ʋ���

 �޸���ʷ      :
  1.��    ��   : 2019��3��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_report_times_limit(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              off_set;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    hi_u8               times_limit;

    /*
        �����ʽ
        hipriv wlan0 set_times_limit X
    */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_report_times_limit::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    times_limit = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_REPORT_TIMES_LIMIT, sizeof(hi_u8));
    *(write_msg.auc_value) = times_limit;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_report_times_limit::return err code [%u]!}\r\n", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���������ϱ�lwip �ش�������������Ʋ���

 �޸���ʷ      :
  1.��    ��   : 2019��3��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_report_cnt_limit(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              off_set;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    hi_u8               cnt_limit;

    /*
        �����ʽ
        hipriv wlan0 set_cnt_limit X
    */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_report_cnt_limit::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    cnt_limit = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_REPORT_CNT_LIMIT, sizeof(hi_u8));
    *(write_msg.auc_value) = cnt_limit;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_report_cnt_limit::return err code [%u]!}\r\n", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����mesh vap�Ƿ�ΪMBR�ڵ�

 �޸���ʷ      :
  1.��    ��   : 2019��4��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_en_mbr(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              off_set;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    hi_u8               mbr;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "{wal_hipriv_set_en_mbr:wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    if (strcmp("0", ac_name) == 0) {
        mbr = HI_FALSE;
    } else if (strcmp("1", ac_name) == 0) {
        mbr = HI_TRUE;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_en_mbr::command param is error!}\r\n");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MBR_EN, sizeof(hi_u8));
    *(write_msg.auc_value) = mbr;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_en_mbr::return err code [%u]!}\r\n", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����mesh vap��mnid

 �޸���ʷ      :
  1.��    ��   : 2019��4��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_mnid(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              off_set;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    hi_u8               mnid;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG, "{wal_hipriv_set_mnid::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    mnid = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MNID, sizeof(hi_u8));
    *(write_msg.auc_value) = mnid ;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mnid::return err code [%u]!}\r\n", ret);
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����beacon priority(���Խӿ�)

 �޸���ʷ      :
  1.��    ��   : 2019��6��3��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_beacon_priority(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              off_set;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    hi_u32              beacon_prio;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_beacon_priority::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    beacon_prio = (hi_u32)oal_atoi(ac_name);
    if (beacon_prio > WLAN_MESH_BEACON_PRIO_MAX) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_beacon_priority::invalid beacon prio!!}\r\n");
        return HI_FAIL;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_BEACON_PRIORITY, sizeof(hi_u8));
    *(write_msg.auc_value) = (hi_u8)beacon_prio;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_beacon_priority::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����Mesh Accept STA��־λ(���Խӿ�)

 �޸���ʷ      :
  1.��    ��   : 2019��6��20��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_set_mesh_accept_sta(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              off_set;
    hi_char             ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32              ret;
    hi_u8               accept_sta;

    /* ��ȡRSSI���޿��� */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_hipriv_set_mesh_accept_sta::wal_get_cmd_one_arg return err_code [%u]!}\r\n", ret);
        return ret;
    }

    if ((strcmp("0", ac_name) == 0)) {
        accept_sta = 0;
    } else if ((strcmp("1", ac_name) == 0)) {
        accept_sta = 1;
    } else {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mesh_accept_sta::the mod switch command is error [%p]!}\r\n",
                         (uintptr_t)ac_name);
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MESH_ACCEPT_STA, sizeof(hi_u8));
    *(write_msg.auc_value) = accept_sta ;  /* ��������������� */

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_mesh_accept_sta::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#if defined(_PRE_WLAN_FEATURE_ARP_OFFLOAD) || defined(_PRE_WLAN_FEATURE_DHCP_OFFLOAD)
#ifdef _PRE_WLAN_FEATURE_HIPRIV
static hi_u32 wal_hipriv_offload_parse_ipv4(hi_char *ip_str, hi_u32 *result)
{
    const hi_char *delims = ".";
    hi_char *byte = HI_NULL;
    hi_u8 count = 0;
    hi_u32 byte_value;

    if (strlen(ip_str) > 15) { /* IPV4 �ַ���������� 15 �ֽ� */
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_offload_parse_ipv4::ip len wrong!}\n");
        return HI_FAIL;
    }

    byte = oal_strtok(ip_str, delims);
    while (byte != HI_NULL) {
        byte_value = (hi_u32)oal_atoi(byte);
        byte_value <<= count * 8; /* ��λ3�Σ�ÿ��8���ء� */
        count++;
        *result += byte_value;
        byte = oal_strtok(HI_NULL, delims);
    }

    if (count != 4) { /* IPV4�ĳ���Ϊ4���ֽ� */
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_offload_parse_ipv4::ip format wrong!}\n");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

static hi_u32 wal_hipriv_offload_build_ipv4(hi_char *param, mac_ip_addr_config_stru *ip)
{
    hi_u32 ret;
    hi_u32 offset;
    hi_char name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    /* Ĭ��IPV4���� */
    ip->type = MAC_CONFIG_IPV4;

    /* ��ȡIP���� */
    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR,
            "{wal_hipriv_offload_build_ipv4::wal_get_cmd_one_arg return err_code [%u]!}\n", ret);
        return ret;
    }
    param = param + offset;
    if ((strcmp("0", name) == 0)) {
        ip->oper = MAC_IP_ADDR_DEL;
        /* �������ip��ַ�����سɹ� */
        return HI_SUCCESS;
    } else if (strcmp("1", name) == 0) {
        ip->oper = MAC_IP_ADDR_ADD;
    } else {
        oam_error_log0(0, OAM_SF_PWR, "{wal_hipriv_offload_build_ipv4::IP operation wrong.}");
    }

    /* ��ȡIP��ַ */
    ret = wal_get_cmd_one_arg(param, name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &offset);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR,
            "{wal_hipriv_offload_build_ipv4::wal_get_cmd_one_arg return err_code [%u]!}\n", ret);
        return ret;
    }
    ret = wal_hipriv_offload_parse_ipv4(name, &ip->ip.ipv4);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR,
            "{wal_hipriv_offload_build_ipv4::wal_hipriv_offload_parse_ipv4 return err_code [%u]!}\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************m
 ��������      : ʹ�� ARP offload ����
 �����ʽ      : hipriv wlan0 arp_offload 0/1 ip
 �޸���ʷ      :
  1.��    ��   : 2019��4��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_arp_offload_setting(oal_net_device_stru *netdev, hi_char *param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              ret;
    hi_u16              len;
    mac_ip_addr_config_stru ip_addr_cfg = {0};

    ret = wal_hipriv_offload_build_ipv4(param, &ip_addr_cfg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_arp_offload_setting::build_ip error[%d]!}\n", ret);
        return HI_FAIL;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    if (memcpy_s(write_msg.auc_value, sizeof(mac_ip_addr_config_stru),
        (const hi_void *)&ip_addr_cfg, sizeof(mac_ip_addr_config_stru)) != EOK) {
        oam_error_log0(0, 0, "{wal_hipriv_arp_offload_setting::mem safe function err!}");
        return HI_FAIL;
    }
    len = sizeof(mac_ip_addr_config_stru);

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ARP_OFFLOAD_SETTING, len);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_arp_offload_setting::wal_send_cfg_event error[%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������      : ��ʾ ARP offload ��Ϣ
 �����ʽ      : hipriv wlan0 arp_offload_show_info 1/0 1/0

 �޸���ʷ      :
  1.��    ��   : 2019��4��19��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
static hi_u32 wal_hipriv_arp_offload_show_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru              write_msg;
    hi_u32                          off_set;
    hi_char                         ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                          ret;
    mac_cfg_arpoffload_info_stru    arp_offload_info;

    /* ��ȡ show ip addr */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0,
                         OAM_SF_PWR,
                         "{wal_hipriv_arp_offload_show_info::wal_get_cmd_one_arg return err_code [%u]!}\n",
                         ret);
        return ret;
    }

    arp_offload_info.show_ip_addr = (hi_u8)oal_atoi(ac_name);
    pc_param = pc_param + off_set;

    /* ��ȡ show arp offload info */
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR,
                         "{wal_hipriv_arp_offload_show_info::wal_get_cmd_one_arg return err_code [%u]!}\n",
                         ret);
        return ret;
    }

    arp_offload_info.show_arpoffload_info = (hi_u8)oal_atoi(ac_name);

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg,
                           WLAN_CFGID_ARP_OFFLOAD_SHOW_INFO,
                           sizeof(mac_cfg_arpoffload_info_stru));
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, WAL_MSG_WRITE_MAX_LEN,
        (const hi_void *)&arp_offload_info, sizeof(mac_cfg_arpoffload_info_stru)) != EOK) {
        oam_error_log0(0, 0, "{wal_hipriv_arp_offload_show_info::mem safe function err!}");
        return HI_FAIL;
    }

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_arpoffload_info_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_arp_offload_show_info::return err code [%u]!}\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_DHCP_OFFLOAD
#ifdef _PRE_WLAN_FEATURE_HIPRIV
static hi_u32 wal_hipriv_dhcp_offload_setting(oal_net_device_stru *netdev, hi_char *param)
{
    wal_msg_write_stru  write_msg;
    hi_u32              ret;
    hi_u16              len;
    mac_ip_addr_config_stru ip_addr_cfg = {0};

    ret = wal_hipriv_offload_build_ipv4(param, &ip_addr_cfg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_dhcp_offload_setting::build_ip error[%d]!}\n", ret);
        return HI_FAIL;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    if (memcpy_s(write_msg.auc_value, sizeof(mac_ip_addr_config_stru),
        (const hi_void *)&ip_addr_cfg, sizeof(mac_ip_addr_config_stru)) != EOK) {
        oam_error_log0(0, 0, "{wal_hipriv_dhcp_offload_setting::mem safe function err!}");
        return HI_FAIL;
    }
    len = sizeof(mac_ip_addr_config_stru);

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_DHCP_OFFLOAD_SETTING, len);
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + len,
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_PWR, "{wal_hipriv_dhcp_offload_setting::wal_send_cfg_event error[%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif
#endif

#ifdef _PRE_DEBUG_MODE
#ifdef _PRE_WLAN_FEATURE_HIPRIV

hi_u32 wal_hipriv_get_cfg_id(hi_char ac_arg, wlan_cfgid_enum_uint16 *cfg_id)
{
    if (strcmp(ac_arg, "aifsn") == 0) {
        *cfg_id = WLAN_CFGID_EDCA_TABLE_AIFSN;
    } else if (strcmp(ac_arg, "cwmin") == 0) {
        *cfg_id = WLAN_CFGID_EDCA_TABLE_CWMIN;
    } else if (strcmp(ac_arg, "cwmax") == 0) {
        *cfg_id = WLAN_CFGID_EDCA_TABLE_CWMAX;
    } else if (strcmp(ac_arg, "txoplimit") == 0) {
        *cfg_id = WLAN_CFGID_EDCA_TABLE_TXOP_LIMIT;
    } else if (strcmp(ac_arg, "qaifsn") == 0) {
        *cfg_id = WLAN_CFGID_QEDCA_TABLE_AIFSN;
    } else if (strcmp(ac_arg, "qcwmin") == 0) {
        *cfg_id = WLAN_CFGID_QEDCA_TABLE_CWMIN;
    } else if (strcmp(ac_arg, "qcwmax") == 0) {
        *cfg_id = WLAN_CFGID_QEDCA_TABLE_CWMAX;
    } else if (strcmp(ac_arg, "qtxoplimit") == 0) {
        *cfg_id = WLAN_CFGID_QEDCA_TABLE_TXOP_LIMIT;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_get_cfg_id::invalid wmm param!}");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

hi_u32 wal_hipriv_check_aifsn(wlan_cfgid_enum_uint16 cfg_id, hi_u32 value)
{
    if ((cfg_id == WLAN_CFGID_EDCA_TABLE_AIFSN) || (cfg_id == WLAN_CFGID_QEDCA_TABLE_AIFSN)) {
        if ((value < WLAN_QEDCA_TABLE_AIFSN_MIN) || (value > WLAN_QEDCA_TABLE_AIFSN_MAX)) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_check_aifsn::invalid AIFSN value!}");
            return HI_FAIL;
        }
    } else if ((cfg_id == WLAN_CFGID_EDCA_TABLE_CWMIN) || (cfg_id == WLAN_CFGID_QEDCA_TABLE_CWMIN)) {
        if ((value > WLAN_QEDCA_TABLE_CWMIN_MAX) || (value < WLAN_QEDCA_TABLE_CWMIN_MIN)) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_check_aifsn::invalid CWMIN value!}");
            return HI_FAIL;
        }
    } else if ((cfg_id == WLAN_CFGID_EDCA_TABLE_CWMAX) || (cfg_id == WLAN_CFGID_QEDCA_TABLE_CWMAX)) {
        if ((value > WLAN_QEDCA_TABLE_CWMAX_MAX) || (value < WLAN_QEDCA_TABLE_CWMAX_MIN)) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_check_aifsn::invalid CWMAX value!}");
            return HI_FAIL;
        }
    } else if ((cfg_id == WLAN_CFGID_EDCA_TABLE_TXOP_LIMIT) || (cfg_id == WLAN_CFGID_QEDCA_TABLE_TXOP_LIMIT)) {
        if ((value > WLAN_QEDCA_TABLE_TXOP_LIMIT_MAX) || (value < WLAN_QEDCA_TABLE_TXOP_LIMIT_MIN)) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_check_aifsn::invalid TXOP_LIMIT value!}");
            return HI_FAIL;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������      : ����WMM����

 �޸���ʷ      :
  1.��    ��   : 2019��4��23��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd��Ա������һ����Աwal_hipriv_getcountry��pc_param��ָ������ݽ������޸ģ�lint_t e818�澯���� */
/* ����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������: �����������ĺ�û�д򿪣��������� */
static hi_u32 wal_hipriv_set_wmm_param(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru     write_msg;
    hi_u32                 off_set;
    hi_char                ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_char                *ac_arg_ptr = ac_arg;
    wlan_cfgid_enum_uint16 cfg_id;
    hi_u8                  orig_dev_state = wal_dev_is_running();

    if (wal_netdev_stop(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wmm_param::wal_netdev_stop failed\r\n");
        return HI_FAIL;
    }

    /* wmm ���� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_arg_ptr, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wmm_param::wal_get_cmd_one_arg return err_code [%u]}", ret);
        return ret;
    }
    pc_param += off_set;
    ret = wal_hipriv_get_cfg_id(ac_arg_ptr, &cfg_id);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* ��ȡac num */
    ret = wal_get_cmd_one_arg(pc_param, ac_arg_ptr, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wmm_param::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }
    pc_param += off_set;

    hi_u32 ac = (hi_u32)oal_atoi(ac_arg_ptr);
    /* acȡֵ0~3 */
    if (ac >= WLAN_WME_AC_BUTT) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_set_wmm_param::invalid ac num!}\r\n");
        return HI_FAIL;
    }

    /* ��ȡac value */
    ret = wal_get_cmd_one_arg(pc_param, ac_arg_ptr, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wmm_param::wal_get_cmd_one_arg return err_code [%u]}", ret);
        return ret;
    }

    hi_u32 value = (hi_u32)oal_atoi(ac_arg_ptr);
    ret = wal_hipriv_check_aifsn(cfg_id, value);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    wal_write_msg_hdr_init(&write_msg, cfg_id, sizeof(wal_msg_wmm_stru));

    wal_msg_wmm_stru *wmm_params = (wal_msg_wmm_stru *)(write_msg.auc_value);
    wmm_params->cfg_id = cfg_id;
    wmm_params->ac     = ac;
    wmm_params->value  = value;

    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(wal_msg_wmm_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_wmm_param::return err code [%u]!}\r\n", ret);
    }

    if (orig_dev_state == HI_TRUE) {
        if (wal_netdev_open(netdev) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_wmm_switch::wal_netdev_open failed\r\n");
            return HI_FAIL;
        }
    }

    return ret;
}
#endif
#endif

/*****************************************************************************
 ��������  : ��ӡ��Ӧvap�Ľ���FCS����Ϣ

 �޸���ʷ      :
  1.��    ��   : 2019��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 wal_hipriv_rx_fcs_info(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru      write_msg;
    hi_u32                  ret;

    hi_unref_param(pc_param);
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_RX_FCS_INFO, sizeof(hi_u32));
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u32),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_rx_fcs_info::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_u32 wal_set_protocol(oal_net_device_stru *netdev, hi_char *protocol_param,
                        hi_s32 len, hi_s32 *protocol_value)
{
    hi_s32 protocol = oal_strtol(protocol_param, NULL, 10); /* 10���� */
    hi_u32 ret;

    if ((len != 1) || (protocol_param[0] < '0') || (protocol_param[0] > '2')) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_set_protocol:: protocol len [%d] error!}\r\n", len);
        return HI_FAIL;
    }

    switch (protocol) {
        case 0: /* 0:����ģʽ11bgn */
            /* ��ȫ��̹���6.6����(5) Դ�ڴ�ȫ���Ǿ�̬�ַ������� */
            strcpy_s(protocol_param, WAL_HIPRIV_CMD_NAME_MAX_LEN, "11bgn");
            break;
        case 1: /* 1:����ģʽ11bg */
            /* ��ȫ��̹���6.6����(5) Դ�ڴ�ȫ���Ǿ�̬�ַ������� */
            strcpy_s(protocol_param, WAL_HIPRIV_CMD_NAME_MAX_LEN, "11bg");
            break;
        case 2: /* 2:����ģʽ11b */
            /* ��ȫ��̹���6.6����(5) Դ�ڴ�ȫ���Ǿ�̬�ַ������� */
            strcpy_s(protocol_param, WAL_HIPRIV_CMD_NAME_MAX_LEN, "11b");
            break;
        default:
            oam_warning_log0(0, OAM_SF_ANY, "{wal_set_protocol:: protocol error!}\r\n");
            return HI_FAIL;
    }

    ret = wal_ioctl_set_mode(netdev, protocol_param);
    if (ret != HI_SUCCESS) {
        oam_error_log1(0, OAM_SF_ANY, "wal_set_protocol::set_mode return err_code [%d]!", ret);
        return ret;
    }

    *protocol_value = protocol;
    return HI_SUCCESS;
}

hi_u32 wal_set_rate(oal_net_device_stru *netdev, hi_char *rate_param, hi_s32 protocol)
{
    wlan_legacy_rate_value_enum_uint8 rate_index;
    hi_u32                            ret;

    /* ����������Ϊ��һ������ */
    for (rate_index = 0; rate_index < WLAN_LEGACY_RATE_VALUE_BUTT; rate_index++) {
        if (!strcmp(g_pauc_non_ht_rate_tbl[rate_index], rate_param)) {
            break;
        }
    }

    /* ������������TX�������е�Э��ģʽ */
    if (((rate_index <= WLAN_SHORT_11B_11_M_BPS) && (protocol == WAL_PHY_MODE_11B)) ||
        ((rate_index >= WLAN_LEGACY_OFDM_48M_BPS) && (rate_index <= WLAN_LEGACY_OFDM_9M_BPS) &&
        (protocol == WAL_PHY_MODE_11G))) {
        ret = wal_hipriv_set_rate(netdev, rate_param);
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, OAM_SF_ANY, "wal_set_rate::set_rate return err_code [%d]!}\r\n", ret);
        }
        return ret;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_set_rate::invalid rate!}\r\n");
        return HI_FAIL;
    }
}

hi_u32 wal_hipriv_get_value(const hi_char *pc_param, hi_char *ac_arg, hi_u32 *off_set, hi_u32 first_elem_flag)
{
    hi_u32 ret;
    hi_u32 check_offset = (first_elem_flag == 0) ? 0 : 1;

    if ((*(pc_param + check_offset)) == ' ') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_get_value::cmd error}");
        return HI_FAIL;
    }

    ret = wal_get_cmd_one_arg(pc_param, ac_arg, WAL_HIPRIV_CMD_NAME_MAX_LEN, off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_value::wal_get_cmd_one_arg return err_code[%u]}", ret);
        return ret;
    }

    return HI_SUCCESS;
}

hi_u32 wal_hipriv_check_switch(const hi_char *ac_arg, const hi_char *pc_param, hi_bool is_tx)
{
    /* ����ǹرճ��գ���ֱ�ӹرգ������������Ĳ��� */
    if (strcmp("0", ac_arg) == 0) {
        /* �ж�������Ƿ������� */
        if (*pc_param != '\0') {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_check_switch::cmd len error}");
            return HI_FAIL;
        }

#ifdef CUSTOM_AT_COMMAND
        hi_at_printf("OK\r\n");
#endif
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
        printk("OK\r\n");
#endif
        return HI_SUCCESS;
    }

    /* �жϿ����ַ��Ƿ�������,1:�򿪳���;2:tx_dc */
    if ((strcmp("1", ac_arg) != 0) && !(is_tx && (strcmp("2", ac_arg) == 0))) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_check_switch::strcmp err_code}");
        return HI_FAIL;
    }

    return HI_CONTINUE;
}

hi_u32 wal_hipriv_set_rate_or_mcs(oal_net_device_stru *netdev, hi_char *ac_arg, hi_s32 protocol_value)
{
    hi_u32 ret;

    if (protocol_value != WAL_PHY_MODE_11N) {
        ret = wal_set_rate(netdev, ac_arg, protocol_value);
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, OAM_SF_ANY, "wal_hipriv_al_tx::set_rate return err_code [%d]}", ret);
            return ret;
        }
    } else {
        ret = wal_hipriv_set_mcs(netdev, ac_arg);
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, OAM_SF_ANY, "wal_set_always_tx::set_mcs return err_code [%d]}", ret);
            return ret;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������      : ���ó��ղ���

 �޸���ʷ      :
  1.��    ��   : 2019��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd��Ա������һ����Աwal_hipriv_getcountry��pc_param��ָ������ݽ������޸ģ�lint_t e818�澯���� */
hi_u32 wal_hipriv_rx_proc(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32  off_set = 0;
    hi_s32  protocol_value = 0;
    hi_char ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_char *ac_arg_ptr = ac_arg;
    hi_u8   mac_filter_flag = 0;

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* ����ÿ�γ���ǰ����Ҫ�ر�����ģʽ */
    if (wal_stop_vap(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_rx_proc::stop vap fail.}");
        return HI_FAIL;
    }
#endif
    /*  ����ÿ�γ���ǰ���س��� */
    hi_u32 ret = wal_hipriv_always_rx(netdev, 0, mac_filter_flag);
    if (ret != HI_SUCCESS) {
        return ret;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    pc_param++;
#endif

    for (hi_u32 i = 0; i < 5; i++) { /* ����������5������ */
        ret = wal_hipriv_get_value(pc_param, ac_arg_ptr, &off_set, ((i == 0) ? 0 : 1));
        if (ret != HI_SUCCESS) {
            return ret;
        }

        pc_param += off_set;

        if (i == 0) {       /* 0: ����ʹ�ܿ��� */
            ret = wal_hipriv_check_switch(ac_arg_ptr, pc_param, HI_FALSE);
            if (ret != HI_CONTINUE) {
                return ret;
            }
        } else if (i == 1) { /* 1: ����Э������ */
            ret = wal_set_protocol(netdev, ac_arg_ptr, strlen(ac_arg_ptr), &protocol_value);
        } else if (i == 2) { /* 2: ���ô��� */
            if ((protocol_value == 2) && (oal_atoi(ac_arg_ptr) != 20)) { /* 2:protocol_value 20:bw */
                oam_error_log1(0, OAM_SF_ANY, "wal_hipriv_al_tx::set_bw return err_code [%d]}", ret);
                return HI_FAIL;
            }
            ret = wal_hipriv_set_bw(netdev, ac_arg_ptr);
        } else if (i == 3) { /* 3: �����ŵ�Ƶ�� */
            ret = wal_ioctl_set_freq(netdev, ac_arg_ptr);
            /* 14�ŵ���֧��11bģʽ */
            if ((ret != HI_SUCCESS) || ((protocol_value != 2) && (oal_atoi(ac_arg_ptr) == 14))) { /* 2: ģʽ,14: �ŵ� */
                return HI_FAIL;
            }
        } else if (i == 4) { /* 4: ��ȡMAC��ַ���˿��� */
            if ((strcmp("0", ac_arg_ptr) != 0) && (strcmp("1", ac_arg_ptr) != 0)) {
                oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_al_rx::get mac filter flag Error}");
                return HI_FAIL;
            }

            mac_filter_flag = (hi_u8)oal_atoi(ac_arg_ptr);
        }

        if (((i == 1) || (i == 2) || (i == 3)) && (ret != HI_SUCCESS)) { /* ����1/2/3���쳣��֧ */
            oam_error_log2(0, OAM_SF_ANY, "wal_hipriv_al_rx::fun[i=%d] return err_code [%d]}", i, ret);
            return ret;
        }
    }

    /* �ж�������Ƿ������� */
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_al_rx::cmd len error}");
        return HI_FAIL;
    }

    /* �򿪳��� */
    ret = wal_hipriv_always_rx(netdev, 1, mac_filter_flag);
    if (ret != HI_SUCCESS) {
        return ret;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (wal_start_vap(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_al_rx::start vap fail.}");
        return HI_FAIL;
    }
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������      : ���ó�������

 �޸���ʷ      :
  1.��    ��   : 2019��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd��Ա������һ����Աwal_hipriv_getcountry��pc_param��ָ������ݽ������޸ģ�lint_t e818�澯���� */
hi_u32 wal_hipriv_tx_proc(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32  off_set = 0;
    hi_s32  protocol_value = 0;
    hi_char ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_char *ac_arg_ptr = ac_arg;
    hi_u8   tx_flag = 0;

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* ����ÿ�γ���ǰ����Ҫ�ر�����ģʽ */
    if (wal_stop_vap(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_tx_proc::stop vap fail.}");
        return HI_FAIL;
    }
#endif
    /* ����ÿ�γ���ǰ���س��� */
    hi_u32 ret = wal_hipriv_always_tx(netdev, 0);
    if (ret != HI_SUCCESS) {
        return ret;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    pc_param++;
#endif

    for (hi_u32 i = 0; i < 5; i++) { /* ����������5������ */
        if (wal_hipriv_get_value(pc_param, ac_arg_ptr, &off_set, ((i == 0) ? 0 : 1)) != HI_SUCCESS) {
            return HI_FAIL;
        }

        pc_param += off_set;

        if (i == 0) {        /* 0: ����ʹ�ܿ��� */
            ret = wal_hipriv_check_switch(ac_arg_ptr, pc_param, HI_TRUE);
            if (ret != HI_CONTINUE) {
                return ret;
            }

            tx_flag = (hi_u8)oal_atoi(ac_arg_ptr);
            /* AT�������ӳ�� */
            tx_flag = (tx_flag == 2) ? WAL_ALWAYS_TX_DC : tx_flag; /* 2:AT�������,��ʾtx_dc */
        } else if (i == 1) { /* 1: ����Э������ */
            if (wal_set_protocol(netdev, ac_arg_ptr, strlen(ac_arg_ptr), &protocol_value) != HI_SUCCESS) {
                return HI_FAIL;
            }
        } else if (i == 2) { /* 2: ���ô��� */
            ret = wal_hipriv_set_bw(netdev, ac_arg_ptr);
            if ((ret != HI_SUCCESS) || ((protocol_value == 2) && (oal_atoi(ac_arg_ptr) != 20))) { /* 2:protocol 20:bw */
                oam_error_log1(0, OAM_SF_ANY, "wal_hipriv_al_tx::set_bw return err_code [%d]}", ret);
                return (ret != HI_SUCCESS) ? ret : HI_FAIL;
            }
        } else if (i == 3) { /* 3: �����ŵ�Ƶ�� */
            ret = wal_ioctl_set_freq(netdev, ac_arg_ptr);
            /* 14�ŵ���֧��11bģʽ */
            if ((ret != HI_SUCCESS) || ((protocol_value != 2) && (oal_atoi(ac_arg_ptr) == 14))) { /* 2:ģʽ,14: �ŵ� */
                return HI_FAIL;
            }
        } else if (i == 4) { /* 4: ��������MCS */
            if (wal_hipriv_set_rate_or_mcs(netdev, ac_arg_ptr, protocol_value) != HI_SUCCESS) {
                return HI_FAIL;
            }
        }
    }

    /* �ж�������Ƿ������� */
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_al_tx::cmd len error}");
        return HI_FAIL;
    }

    /* �򿪳��� */
    ret = wal_hipriv_always_tx(netdev, tx_flag);
    if (ret != HI_SUCCESS) {
        return ret;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (wal_start_vap(netdev) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_al_tx::start vap fail.}");
        return HI_FAIL;
    }
#endif
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_BTCOEX
#ifdef _PRE_WLAN_FEATURE_HIPRIV
/*****************************************************************************
 ��������      : ����BT����ʹ��
 �޸���ʷ      :
  1.��    ��   : 2019��5��5��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* ������g_ast_hipriv_cmd�ĳ�Ա������wal_hipriv_getcountry�޸��˶�Ӧ������lint_t e818�澯���� */
static hi_u32 wal_hipriv_btcoex_enable(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret, off_set;
    hi_u16                      us_len;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u8                       btcoex_enable, mode, share_ant;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_COEX, "{wal_hipriv_btcoex_enable::wal_get_cmd_one_arg return err_code[%u]}", ret);
        return ret;
    }
    pc_param += off_set;
    btcoex_enable = (hi_u8)oal_atoi(ac_name);
    if (btcoex_enable == 0) {
        *(hi_u8 *)(write_msg.auc_value) = btcoex_enable;
        us_len = sizeof(hi_u8);
    } else if (btcoex_enable == 1) {
        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_COEX, "{wal_hipriv_btcoex_enable::wal_get_cmd_one_arg return errCode[%u]}", ret);
            return ret;
        }
        pc_param += off_set;
        mode = (hi_u8)oal_atoi(ac_name);

        ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, OAM_SF_COEX, "{wal_hipriv_btcoex_enable::wal_get_cmd_one_arg return errCode[%u]}", ret);
            return ret;
        }
        share_ant = (hi_u8)oal_atoi(ac_name);

        write_msg.auc_value[0] = btcoex_enable;
        write_msg.auc_value[1] = mode;
        write_msg.auc_value[2] = share_ant; /* 2: ��3λ */
        us_len = sizeof(hi_u8) * 3; /* ����Ϊ3 */
    } else {
        oam_warning_log0(0, OAM_SF_COEX, "{wal_hipriv_btcoex_enable::input parameter error!}\r\n");
        return HI_SUCCESS;
    }

    /***************************************************************************
                              ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_BTCOEX_ENABLE, us_len);
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len,
                             (hi_u8*)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_COEX, "{wal_hipriv_btcoex_enable::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}
#endif /* _PRE_WLAN_FEATURE_BTCOEX */
#endif

#ifdef _PRE_DEBUG_MODE
#ifdef _PRE_WLAN_FEATURE_HIPRIV

hi_u32 wal_hipriv_add_vap_get_mode(wal_hipriv_two_param_stru *cmd_param, wlan_vap_mode_enum_uint8 *mode,
    wlan_p2p_mode_enum_uint8 *p2p_mode)
{
    if (strcmp("ap", cmd_param->cmd_param2) == 0) {
        *mode = WLAN_VAP_MODE_BSS_AP;
    } else if (strcmp("sta", cmd_param->cmd_param2) == 0) {
        *mode = WLAN_VAP_MODE_BSS_STA;
#ifdef _PRE_WLAN_FEATURE_MESH
    } else if ((strcmp("mesh", cmd_param->cmd_param2)) == 0) {
        *mode = WLAN_VAP_MODE_MESH;
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    /* ����P2P ���VAP */
    } else if (0 == (strcmp("p2p_device", cmd_param->cmd_param2))) {
        *mode = WLAN_VAP_MODE_BSS_STA;
        *p2p_mode = WLAN_P2P_DEV_MODE;
    } else if (0 == (strcmp("p2p_cl", cmd_param->cmd_param2))) {
        *mode = WLAN_VAP_MODE_BSS_STA;
        *p2p_mode = WLAN_P2P_CL_MODE;
    } else if (0 == (strcmp("p2p_go", cmd_param->cmd_param2))) {
        *mode = WLAN_VAP_MODE_BSS_AP;
        *p2p_mode = WLAN_P2P_GO_MODE;
#endif  /* _PRE_WLAN_FEATURE_P2P */
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_vap::the mode param is invalid!}");
        return HI_ERR_CODE_INVALID_CONFIG;
    }

    return HI_SUCCESS;
}

hi_u32 wal_hipriv_add_vap_wireless_dev_set(oal_net_device_stru *netdev_tmp, mac_device_stru *mac_dev,
    oal_wireless_dev *wdev, wlan_vap_mode_enum_uint8 mode, wlan_p2p_mode_enum_uint8 p2p_mode)
{
    /* ��netdevice���и�ֵ */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    netdev_tmp->wireless_handlers             = wal_get_g_iw_handler_def();
#endif
    netdev_tmp->netdev_ops                    = wal_get_net_dev_ops();

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 9))
    /* destructor change to priv_destructor */
    netdev->priv_destructor                   = oal_net_free_netdev;
    netdev->needs_free_netdev                 = false;
#else
    oal_netdevice_destructor(netdev_tmp)      = oal_net_free_netdev;
#endif
    oal_netdevice_ifalias(netdev_tmp)         = HI_NULL;
    oal_netdevice_watchdog_timeo(netdev_tmp)  = 5; /* �̶�����Ϊ 5 */
    oal_netdevice_wdev(netdev_tmp)            = wdev;
    oal_netdevice_qdisc(netdev_tmp, HI_NULL);

    wdev->netdev = netdev_tmp;

    if (mode == WLAN_VAP_MODE_BSS_AP) {
        wdev->iftype = NL80211_IFTYPE_AP;
    } else if (mode == WLAN_VAP_MODE_BSS_STA) {
        wdev->iftype = NL80211_IFTYPE_STATION;
    }
#ifdef _PRE_WLAN_FEATURE_MESH
    if (mode == WLAN_VAP_MODE_MESH) {
        wdev->iftype = NL80211_IFTYPE_MESH_POINT;
    }
#endif
#ifdef _PRE_WLAN_FEATURE_P2P
    if (p2p_mode == WLAN_P2P_DEV_MODE) {
        wdev->iftype = NL80211_IFTYPE_P2P_DEVICE;
    } else if (p2p_mode == WLAN_P2P_CL_MODE) {
        wdev->iftype = NL80211_IFTYPE_P2P_CLIENT;
    } else if (p2p_mode == WLAN_P2P_GO_MODE) {
        wdev->iftype = NL80211_IFTYPE_P2P_GO;
    }
#endif  /* _PRE_WLAN_FEATURE_P2P */

    wdev->wiphy = mac_dev->wiphy;

    oal_netdevice_flags(netdev_tmp) &= ~OAL_IFF_RUNNING;   /* ��net device��flag��Ϊdown */
    if (wal_get_dev_addr(netdev_tmp->dev_addr, ETH_ADDR_LEN, wdev->iftype) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_vap::wal_get_dev_addr failed!}");
        oal_net_free_netdev(netdev_tmp);
        oal_mem_free(wdev);
        return HI_FAIL;
    }

    /* ע��net_device */
    hi_u32 ret = (hi_u32)oal_net_register_netdev(netdev_tmp);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_add_vap::oal_net_register_netdev return error code %d!}\r\n", ret);
        oal_net_free_netdev(netdev_tmp);
        oal_mem_free(wdev);
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ˽���������VAP
*****************************************************************************/
static hi_u32 wal_hipriv_add_vap(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_hipriv_two_param_stru cmd_param;
    wlan_vap_mode_enum_uint8  mode;
    wlan_p2p_mode_enum_uint8  p2p_mode = WLAN_LEGACY_VAP_MODE;

    hi_unref_param(p2p_mode);

    hi_u32 ret = wal_hipriv_two_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_vap::parse cmd param failed!}");
        return ret;
    }

    hi_char *cmd_param1_ptr = cmd_param.cmd_param1;
    /* ��һ������Ϊvap_name length��Ӧ����OAL_IF_NAME_SIZE */
    if (strlen(cmd_param.cmd_param1) >= OAL_IF_NAME_SIZE) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_add_vap:vap name len[%d]over flow}", strlen(cmd_param.cmd_param1));
        return HI_FAIL;
    }

    ret = wal_hipriv_add_vap_get_mode(&cmd_param, &mode, &p2p_mode);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* ���������net device�Ѿ����ڣ�ֱ�ӷ��� */
    oal_net_device_stru *netdev_tmp = oal_get_netdev_by_name(cmd_param1_ptr);
    if (netdev_tmp != HI_NULL) {
        /* ����oal_dev_get_by_name�󣬱������oal_dev_putʹnet_dev�����ü�����һ */
        oal_dev_put(netdev_tmp);
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_vap::the net_device is already exist!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_device_stru *mac_dev = mac_res_get_dev();
#if defined(_PRE_WLAN_FEATURE_FLOWCTL)
    netdev_tmp = oal_net_alloc_netdev_mqs(cmd_param1_ptr);
#elif defined(_PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL)
    netdev_tmp = oal_net_alloc_netdev_mqs(cmd_param1_ptr);
#else
    netdev_tmp = oal_net_alloc_netdev(cmd_param1_ptr, OAL_IF_NAME_SIZE);
#endif
    if (oal_unlikely(netdev_tmp == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_vap::pst_net_dev null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    oal_wireless_dev *wdev = (oal_wireless_dev *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(oal_wireless_dev));
    if (oal_unlikely(wdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_add_vap::alloc mem, pst_wdev is null ptr!}");
        oal_net_free_netdev(netdev_tmp);
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(wdev, sizeof(oal_wireless_dev), 0, sizeof(oal_wireless_dev));

    ret = wal_hipriv_add_vap_wireless_dev_set(netdev_tmp, mac_dev, wdev, mode, p2p_mode);
    return ret;
}

/*****************************************************************************
 ��������  : ��������û�����������
*****************************************************************************/
static hi_u32 wal_hipriv_add_user(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      ret;
    mac_cfg_add_user_param_stru add_user_param_info;  /* ��ʱ�����ȡ��use����Ϣ */
    wal_hipriv_two_param_stru   cmd_param;
    hi_char*                    cmd_param1_ptr = HI_NULL;

    /* ��������û�����������: hipriv vap0 add_user xx xx xx xx xx xx(mac��ַ) 0 | 1(HT����λ) */
    /* ��ȡ����������� */
    ret = wal_hipriv_two_param_parse(pc_param, &cmd_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_user::parse cmd param failed!}");
        return ret;
    }
    cmd_param1_ptr = cmd_param.cmd_param1;
    /* ��ȡ�û�MAC��ַ */
    oal_strtoaddr(cmd_param1_ptr, add_user_param_info.auc_mac_addr, WLAN_MAC_ADDR_LEN);
    /* ��ȡ�û���HT��ʶ */
    /* ��Խ������Ĳ�ͬ�����user��HT�ֶν��в�ͬ������ ��0��Ϊ1 */
    if (0 == (strcmp("0", cmd_param.cmd_param2))) {
        add_user_param_info.ht_cap = 0;
    } else {
        add_user_param_info.ht_cap = 1;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ADD_USER, sizeof(mac_cfg_add_user_param_stru));
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, sizeof(mac_cfg_add_user_param_stru),
                 &add_user_param_info, sizeof(mac_cfg_add_user_param_stru)) != EOK) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_add_user::memcpy_s event param failed!}");
        return HI_FAIL;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_add_user_param_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_add_user::return err code[%u]!}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ��ӡ����ά����Ϣ
*****************************************************************************/
static hi_u32 wal_hipriv_btcoex_status_print(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32                       ret;
    wal_msg_write_stru           write_msg;

    hi_unref_param(pc_param);
    /* hipriv vap_name coex_print */
    if (memset_s((hi_u8*)&write_msg, sizeof(write_msg), 0, sizeof(write_msg)) != EOK) {
        return HI_FAIL;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_BTCOEX_INFO, sizeof(hi_s32));
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_TXOP, "{wal_hipriv_btcoex_status_print::return err code[%u]!}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : ��ȡdevice��ÿһ��tid�µ�ǰmpdu��Ŀ
*****************************************************************************/
static hi_u32  wal_hipriv_get_mpdu_num(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg;
    hi_u32                      off_set;
    hi_u32                      ret;

    /* sh hipriv.sh "vap_name mpdu_num user_macaddr" */
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_GET_MPDU_NUM, sizeof(param));
    /* ��ȡ�û�mac��ַ */
    ret = wal_hipriv_get_mac_addr(pc_param, write_msg.auc_value, WLAN_MAC_ADDR_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        return ret;
    }
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_get_mpdu_num_stru),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_get_mpdu_num::return err code[%u]!}", ret);
    }
    return ret;
}
#endif
#endif  /* #ifdef _PRE_DEBUG_MODE */

#if defined(_PRE_WLAN_FEATURE_HIPRIV) && defined(_PRE_WLAN_FEATURE_INTRF_MODE)
static hi_u32  wal_hipriv_set_intrf_mode(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru                      write_msg;
    hi_u32                                  off_set;
    hi_char                                 ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};

    /* �������� */
    hi_u32 ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_intrf_mode::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }

    hi_s32 mode = oal_atoi(ac_name);
    if ((mode != 0) && (mode != 1)) {
        oam_error_log1(0, 0, "wal_hipriv_set_intrf_mode:: invalid mode [%d]", mode);
        return HI_FAIL;
    }
    hi_bool *param = (hi_bool *)write_msg.auc_value;
    *param = (mode == 1);

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_INTRF_MODE_ON, sizeof(hi_bool));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_bool),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_set_intrf_mode::return err code [%u]!}\r\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}
#endif

static hi_u32 wal_hipriv_get_tx_params(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_unref_param(pc_param);

    hi_wifi_get_tx_params("wlan0", strlen("wlan0"));
    return HI_ERR_SUCCESS;
}

static hi_u32 wal_hipriv_set_dev_soft_reset(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_unref_param(pc_param);

    hi_s32 ret = hi_wifi_soft_reset_device();
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, 0, "wal_hipriv_set_dev_soft_reset fail ret[%d]", ret);
        return HI_FAIL;
    }
    return HI_ERR_SUCCESS;
}

#if defined(_PRE_WLAN_FEATURE_HIPRIV) || defined(_PRE_DEBUG_MODE) || defined(_PRE_WLAN_FEATURE_SIGMA)
/* hipriv����ͳһ��ʽ:  hipriv [vap_name] [cmd_name] [param1] [...] */
static const wal_hipriv_cmd_entry_stru  g_ast_hipriv_cmd[] = {
#if defined(_PRE_WLAN_FEATURE_HIPRIV) || defined(_PRE_WLAN_FEATURE_SIGMA)
    {"amsdu_tx_on",     wal_hipriv_amsdu_tx_on},    /* ����amsdu: amsdu_tx_on [0\1] */
    {"ampdu_tx_on",     wal_hipriv_ampdu_tx_on},    /* ����ampdu: ampdu_tx_on [0\1] */
    {"freq",            wal_ioctl_set_freq},        /* ����AP �ŵ� */
    {"uapsd_en_cap",    wal_hipriv_set_uapsd_cap},  /* ����uapsd: uapsd_en_cap [0\1] */
    {"frag_threshold",  wal_hipriv_frag_threshold}, /* ���÷�Ƭ����: frag_threshold [len] */
    {"setcountry",      wal_hipriv_setcountry},     /* ���ù�����: setcountry [cn_code] */
    {"set_netdev_state", wal_hipriv_set_vap_state}, /* ��������netdev״̬ [0\1] */
#endif
#ifdef _PRE_WLAN_FEATURE_HIPRIV
    {"info",            wal_hipriv_vap_info},       /* ��ӡvap�����в�����Ϣ: info */
    {"set_tx_dscr",     wal_hipriv_set_tx_dscr_param},  /* ������������Ϣ: set_tx_dscr [type] [param_name] [value] */
    {"ampdu_start",     wal_hipriv_ampdu_start},    /* ����AMPDU: ampdu_start [mac��ַ] [tidno] */
    {"ampdu_amsdu",     wal_hipriv_ampdu_amsdu_switch}, /* ����amsdu ampdu���Ͼۺ�: ampdu_amsdu [0|1] */
    {"delba_req",       wal_hipriv_delba_req},      /* ɾ��BA�Ự: delba_req [mac��ַ] [tidno] [direction] */
    {"userinfo",        wal_hipriv_user_info},      /* ��ӡuser��Ϣ: userinfo [user_mac_addr] */
    {"bw",              wal_hipriv_set_bw},         /* ���ô���: bw [value] */
    {"regwrite",        wal_hipriv_reg_write},      /* д�Ĵ���: regwrite [32/16] [addr] [val]" addr val����16���� */
    {"mode",            wal_ioctl_set_mode},        /* ����AP Э��ģʽ: mode [mode_type] */
    {"set_mib",         wal_hipriv_set_mib},        /* ����VAP mibֵ */
    {"get_mib",         wal_hipriv_get_mib},        /* ��ȡVAP mibֵ */
    {"rx_info",         wal_hipriv_rx_fcs_info},    /* ��ӡ����֡��FCS��ȷ�������Ϣ: rx_info */
    {"al_rx",           wal_hipriv_rx_proc},          /* ���ó���ģʽ: al_rx enable [mode] [bw] [freq] */
    {"al_tx",           wal_hipriv_tx_proc},          /* ���ó���ģʽ: al_tx enable [mode] [bw] [freq] [rate] */
    {"alg_cfg",         wal_hipriv_alg_cfg},           /* �㷨��������: hipriv "vap0 alg_cfg sch_vi_limit 10" */
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
    {"set_cal_bpwr",    wal_hipriv_set_cal_band_power},         /* �Ը�band��ƽ�����ʲ��� */
    {"set_cal_rpwr",    wal_hipriv_set_cal_rate_power},         /* �Ը����������ʲ��� */
    {"set_cal_freq",    wal_hipriv_set_cal_freq_power},         /* ����Ƶƫ���� */
    {"w_cal_data",      wal_hipriv_set_dataefuse},              /* ��У׼ֵд��efuse */
    {"get_caldata_info",   wal_hipriv_get_cal_data},            /* ��ȡУ׼���� */
    {"set_efuse_mac",   wal_hipriv_set_customer_mac},           /* ����mac��ַ */
    {"get_efuse_mac",   wal_hipriv_get_customer_mac},           /* ��ѯmac��ַ */
    {"set_rate_pwr",    wal_hipriv_set_rate_power},             /* �Ը����������ʵ��� */
#endif
    {"set_tx_pwr_offset",  hi_hipriv_set_tx_pwr_offset},        /* ���ù���ƫ�� */
    {"set_retry_limit", wal_hipriv_set_retry_limit},            /* �����ش����� */
    {"kick_user",       wal_hipriv_kick_user},      /* ɾ���û�: kick_user [user_mac_addr] */
    {"list_channel",    wal_hipriv_list_channel},   /* ��ѯ֧���ŵ��б� list_channel */
    {"wmm_switch",      wal_hipriv_wmm_switch},     /* ��̬�������߹ر�wmm: wmm_switch [0|1] */
    {"send_bar",        wal_hipriv_send_bar},       /* ����bar: send_bar [mac_addr)] [tid_num]" */
    {"getcountry",      wal_hipriv_getcountry},     /* ��ѯ������: getcountry */
#ifdef _PRE_DEBUG_MODE
    {"print_config",    wal_print_init_params},
#endif
    {"ampdu_aggr_num",  wal_hipriv_set_ampdu_aggr_num}, /* ����AMPDU�ۺϸ���: ampdu_aggr_num [0|1] [num] */
    {"random_mac_scan", wal_hipriv_set_random_mac_addr_scan},   /* ���macɨ�迪�� random_mac_addr_scan [0|1] */
#ifdef _PRE_WLAN_RF_110X_CALI_DPD
    {"start_dpd",       wal_hipriv_start_dpd},      /* Start DPD Calibration */
#endif
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    {"report_vap_info", wal_hipriv_report_vap_info}, /* �ϱ� vap����Ϣ: report_vap_info [flag] */
    {"reginfo",         wal_hipriv_reg_info},       /* ���Ĵ���: reginfo [16|32] [startaddr] [endaddr] */
#endif
#ifdef _PRE_WLAN_FEATURE_WOW
    {"wow_sleep",       wal_hipriv_host_sleep_switch},  /* ����host˯�߿���: host_sleep [0|1] */
    {"wow_event",       wal_hipriv_set_wow},            /* wow�¼�����: wow_event_set [value] */
    {"wow_pattern",     wal_hipriv_set_wow_pattern},    /* ����wowģʽ: wow_pattern [clr|add|del] [index] */
#endif
#ifdef _PRE_WLAN_FEATURE_PROMIS
    {"set_monitor",     wal_hipriv_set_monitor_switch}, /* ����monitorģʽ:  set_monitor [0|1|2|3|4] */
#endif
    {"set_device_rst",  wal_hipriv_set_dev_soft_reset}, /* ʹ��device����λ */
#endif
#if defined(_PRE_WLAN_FEATURE_STA_PM) || defined(_PRE_WLAN_FEATURE_SIGMA) || defined(_PRE_WLAN_FEATURE_HIPRIV)
    {"set_uapsd_para",  wal_hipriv_set_uapsd_para},     /* ����uapsd�Ĳ�����Ϣ: set_uapsd_para 3 1 1 1 1 */
    {"set_ps_mode",     wal_hipriv_sta_ps_mode},        /* ����PSPOLL����: set_ps_mode [3] [0] */
    {"set_sta_pm_on",   wal_hipriv_set_pm_switch},      /* �����͹���: set_sta_pm_on xx xx xx xx */
    {"set_wlan_pf_pm_enable",   wal_hipriv_set_wlan_pm_enable},  /* ����device platform ˯��ʹ�� [1] [0] */
    {"set_host_sleep_status",   wal_hipriv_set_host_sleep_status},  /* ����host˯��״̬ [1] [0] */
    {"set_sleep_open_tcxo",   wal_hipriv_set_deepsleep_open_tcxo},  /*  */
    {"set_wk_fail_process_pid",  wal_hipriv_setwk_fail_process},  /* ���ô�����deviceʧ��ʱ������ID */
    {"get_pm_info",  wal_hipriv_dump_pm_info},  /* ��ȡpm info, 1: host, 0: device */
#endif
#ifdef _PRE_WLAN_FEATURE_HIPRIV
    {"set_cca_threshold", wal_hipriv_set_cca_threshold},       /* ����CCA����: */
#ifdef _PRE_WLAN_FEATURE_STA_PM
    {"set_psm_offset",  wal_hipriv_sta_set_psm_offset}, /* ����tbtt��ext tbtt ��ǰ����beacon��ʱʱ�� */
    {"set_hw_ps_mode",  wal_hipriv_sta_set_hw_ps_mode}, /* ������Ӳ����˯��ǳ˯ģʽ */
    {"set_offload_param", wal_hipriv_sta_set_offload_param}, /* ����offload ���� */
#endif
#ifdef _PRE_WLAN_FEATURE_ALG_CFG
    {"alg_ar_log",      wal_hipriv_ar_log},            /* autorate�㷨��־��������: */
    {"alg_tpc_log",     wal_hipriv_tpc_log},           /* tpc�㷨��־��������: */
#ifdef _PRE_WLAN_FEATURE_ALG_CFG_TEST
    {"alg_ar_test",     wal_hipriv_ar_test},           /* autorate�㷨ϵͳ�������� */
#endif
#endif
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP_DEBUG
    {"edca_switch_sta", wal_hipriv_set_edca_opt_switch_sta},    /* STA�Ƿ���˽��edca�����Ż����� */
    {"edca_switch_ap",  wal_hipriv_set_edca_opt_switch_ap},     /* �Ƿ���edca�Ż����� */
    {"edca_cycle_ap",   wal_hipriv_set_edca_opt_cycle_ap},      /* ����edca�������������� */
#endif
#ifdef _PRE_WLAN_FEATURE_MESH
    {"set_times_limit", wal_hipriv_set_report_times_limit},     /* ���÷��ʹ����ϱ���ز���(��������ʹ��) */
    {"set_cnt_limit",   wal_hipriv_set_report_cnt_limit},       /* ���÷����ϱ���ز���(��������ʹ��) */
    {"set_en_mbr",      wal_hipriv_set_en_mbr},                 /* ����vap�Ƿ�ΪMBR�ڵ� */
    {"set_mnid",        wal_hipriv_set_mnid},                   /* ����mesh vap��mnid */
    {"set_bcn_prio",    wal_hipriv_set_beacon_priority},        /* ����beacon priority */
    {"set_accept_sta",  wal_hipriv_set_mesh_accept_sta},        /* ����֧��sta���� */
#endif
#ifdef _PRE_WLAN_FEATURE_BTCOEX
    {"btcoex_enable",   wal_hipriv_btcoex_enable},
#endif
#ifdef _PRE_WLAN_FEATURE_BW_HIEX
    {"selfcts",         wal_hipriv_hiex_config_selfcts}, /* ����selfcts���Ͳ���: selfcts [enable] [duration] [per] */
#endif
#ifdef _PRE_WLAN_FEATURE_ARP_OFFLOAD
    {"arp_offload", wal_hipriv_arp_offload_setting},          /* ���� ARP offload ���� */
    {"arp_offload_info",   wal_hipriv_arp_offload_show_info}, /* ��ʾ ARP offload ��Ϣ */
#endif
#ifdef _PRE_WLAN_FEATURE_DHCP_OFFLOAD
    {"dhcp_offload", wal_hipriv_dhcp_offload_setting},        /* ���� DHCP offload ���� */
#endif
#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
    {"set_flowctl_param",  wal_hipriv_set_flowctl_param},     /* ����������ز��� */
    {"get_flowctl_stat",   wal_hipriv_get_flowctl_stat},      /* ��ȡ�������״̬��Ϣ */
#endif
#endif
#ifdef _PRE_DEBUG_MODE
    {"wmm",             wal_hipriv_set_wmm_param},  /* ����wmm����: wmm [param_ac_nimber] */
    {"vap_pkt_stat",    wal_hipriv_show_vap_pkt_stat},          /* ��ȡvap���շ���ͳ����Ϣ: vap_pkt_stat */
    {"start_scan",      wal_hipriv_start_scan},     /* ����staɨ��: start_scan */
    {"start_join",      wal_hipriv_start_join},     /* ����sta���벢��֤����: start_join [num] num:ɨ�赽��AP��� */
    {"start_deauth",    wal_hipriv_start_deauth},   /* ����staȥ��֤: hipriv "vap0 start_deauth" */
    {"packet_xmit",     wal_hipriv_packet_xmit},    /* ��������֡: packet_xmit [tid_no] [num] [len] [ra_mac]" */
    {"hide_ssid",       wal_hipriv_hide_ssid},      /* ��������ssid: hide_ssid [0|1] */
    {"bgscan_enable",   wal_hipriv_bgscan_enable},  /* ����ɨ���������: bgscan_enable [0|1] */
    {"essid",           wal_ioctl_set_essid},       /* ����AP ssid */
    {"set_regd_pwr",    wal_hipriv_set_regdomain_pwr},  /* ���ù���������͹���: set_regdomain_pwr [value] ��λdBm */
    {"auto_protection", wal_hipriv_set_auto_protection},    /* �����Զ��������� */
    /* ���ù���������͹���(����ͻ������): set_regdomain_pwr_p [value] ��λdBm */
    {"set_regd_pwr_p",  wal_hipriv_set_regdomain_pwr_priv},
    {"create",          wal_hipriv_add_vap},        /* ����vap: Hisilicon0 create [vap0] [ap|sta] */
    {"destroy",         wal_hipriv_del_vap},        /* ɾ��vap: destroy */
    {"add_user",        wal_hipriv_add_user},       /* ����û�: add_user [mac��ַ] [0|1(HT����λ)] */
    {"btcoex_print",    wal_hipriv_btcoex_status_print},    /* ��ӡ����ά����Ϣ: coex_print */
    {"mpdu_num",        wal_hipriv_get_mpdu_num},   /* ��ȡtid��mpdu����: mpdu_num [user_macaddr] */
#endif
#if defined(_PRE_DEBUG_MODE) || defined(_PRE_WLAN_FEATURE_SIGMA)
    /* sigma��� */
    {"addba_req",       wal_hipriv_addba_req},      /* ����BA: addba_req [mac] [tidno] [buffsize] [timeout] */
    {"rate",            wal_hipriv_set_rate},       /* ����non-HTģʽ�µ�����: rate [value] */
    {"mcs",             wal_hipriv_set_mcs},        /* ����HTģʽ�µ�����: mcs [value] */
    {"rts_threshold",   wal_hipriv_rts_threshold},  /* ����RTS����:  rts_threshold [len] */
    {"set_stbc_cap",    wal_hipriv_set_stbc_cap},   /* ����STBC���� */
    {"txpower",         wal_ioctl_set_txpower},
    {"set_shortgi20",   wal_hipriv_set_shortgi20},  /* ����20M short GI: set_shortgi20 [1/0] */
#endif
#if defined(_PRE_WLAN_FEATURE_HIPRIV) && defined(_PRE_WLAN_FEATURE_INTRF_MODE)
    {"intrf_mode",      wal_hipriv_set_intrf_mode}, /* ���ø���ģʽ: intrf_mode [1/0],Ϊ1�����,����һϵ�п����Ŵ�ʩ */
#endif
    {"get_tx_params",   wal_hipriv_get_tx_params}
};
#endif

/*****************************************************************************
 ��������  : ��ȡ�����Ӧ��net_dev
 �������  : pc_cmd: �����ַ���
 �������  : ppst_net_dev: �õ�net_device
            pul_off_set: ȡnet_deviceƫ�Ƶ��ֽ�
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 wal_hipriv_get_netdev(const hi_char *pc_cmd, oal_net_device_stru **netdev, hi_u32 *pul_off_set)
{
    oal_net_device_stru *netdev_temp = HI_NULL;
    hi_char              ac_dev_name[WAL_HIPRIV_CMD_NAME_MAX_LEN];

    if (oal_unlikely((pc_cmd == HI_NULL) || (netdev == HI_NULL) || (pul_off_set == HI_NULL))) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_get_netdev::pc_cmd/ppst_net_dev/pul_off_set null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    if (wal_get_cmd_one_arg(pc_cmd, ac_dev_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, pul_off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_get_netdev::wal_get_cmd_one_arg return err_code!}");
        return HI_FAIL;
    }
    /* ����dev_name�ҵ�dev */
    netdev_temp = oal_get_netdev_by_name(ac_dev_name);
    if (netdev_temp == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_get_netdev::oal_get_netdev_by_name return null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ����oal_dev_get_by_name�󣬱������oal_dev_putʹnet_dev�����ü�����һ */
    oal_dev_put(netdev_temp);
    *netdev = netdev_temp;
    return HI_SUCCESS;
}

#if defined (_PRE_WLAN_FEATURE_HIPRIV) || defined(_PRE_WLAN_FEATURE_SIGMA)
/*****************************************************************************
 ��������  : ��ȡcmd id
 �������  : pc_cmd: �����ַ���
 �������  : ppst_net_dev: �õ�net_device
             pul_off_set: ȡnet_deviceƫ�Ƶ��ֽ�
 �� �� ֵ  : ������
*****************************************************************************/
/* 6721��puc_cmd_id�и�ֵ������pul_off_set��Ϊwal_get_cmd_one_arg�����Ĳ����������н������޸ģ�lint_t e818�澯���� */
static hi_u32 wal_hipriv_parse_cmd(const hi_char *pc_cmd, hi_u8 *puc_cmd_id, hi_u32 *pul_off_set)
{
    hi_u8                   cmd_id;
    hi_char                 ac_cmd_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};

    if (oal_unlikely((pc_cmd == HI_NULL) || (puc_cmd_id == HI_NULL) || (pul_off_set == HI_NULL))) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_parse_cmd::pc_cmd/puc_cmd_id/pul_off_set null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    if (wal_get_cmd_one_arg(pc_cmd, ac_cmd_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, pul_off_set) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_parse_cmd::wal_get_cmd_one_arg return err_code!}");
        return HI_FAIL;
    }
    /* �����������ҵ�����ö�� */
    for (cmd_id = 0; cmd_id < hi_array_size(g_ast_hipriv_cmd); cmd_id++) {
        if (strcmp(g_ast_hipriv_cmd[cmd_id].pc_cmd_name, ac_cmd_name) == 0) {
            *puc_cmd_id = cmd_id;
            return HI_SUCCESS;
        }
    }
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ����˽����������
 �������  : pc_cmd: ����
 �� �� ֵ  : ������
*****************************************************************************/
static hi_u32 wal_hipriv_process_cmd(oal_net_device_stru *netdev, hi_char *pc_cmd)
{
    hi_u8                   cmd;
    hi_u32                  off_set = 0;
    hi_u32                  ret;

    if (oal_unlikely(pc_cmd == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_process_cmd::pc_cmd null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /***************************************************************************
        cmd��ʽԼ��
        �����豸�� ����      ����   eg. Hisilicon0 create vap0
        1~15Byte   1~15Byte
    **************************** ***********************************************/
    ret = wal_hipriv_parse_cmd(pc_cmd, &cmd, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_process_cmd::parse_cmd failed!}");
        return ret;
    }
    pc_cmd += off_set;
    /* ���������Ӧ�ĺ��� */
    ret = g_ast_hipriv_cmd[cmd].func(netdev, pc_cmd);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_process_cmd::cmd func process failed!}");
#ifdef _PRE_WLAN_FEATURE_MFG_TEST
        printk("ERROR\r\n");
#endif
        return ret;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : hipriv�������
 �������  : *pc_buffer �������
            count �����
 �� �� ֵ  : �ֽ�����0��ʾhiprivʧ��
*****************************************************************************/
hi_u32 wal_hipriv_entry(const hi_char *pc_buffer, hi_u32 count)
{
    hi_char             *pc_cmd = HI_NULL;
    hi_char             *pc_cmd_tmp = HI_NULL;
    oal_net_device_stru *netdev = HI_NULL;
    hi_u32              ret;
    hi_u32              len = count;
    hi_u32              off_set = 0;

    if (len > WAL_HIPRIV_CMD_MAX_LEN) {
        oam_error_log1(0, OAM_SF_ANY, "{wal_hipriv_entry::param len overflow, ul_len[%u]!}", len);
        return 0;
    }

    pc_cmd = oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, WAL_HIPRIV_CMD_MAX_LEN);
    if (oal_unlikely(pc_cmd == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_entry::alloc mem return null ptr!}\r\n");
        return 0;
    }

    if (pc_buffer != HI_NULL) {
        if (memcpy_s(pc_cmd, len, pc_buffer, len) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_hipriv_entry::mem safe function err!}");
            oal_mem_free(pc_cmd);
            return 0;
        }
    }
    pc_cmd[len - 1] = '\0';
    pc_cmd_tmp = pc_cmd;
    ret = wal_hipriv_get_netdev(pc_cmd_tmp, &netdev, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_entry::wal_hipriv_get_netdev return error code [%d]!}\r\n", ret);
        oal_mem_free(pc_cmd);
        return 0;
    }

    pc_cmd_tmp += off_set;
    ret = wal_hipriv_process_cmd(netdev, pc_cmd_tmp);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_entry::parse cmd return err code[%d]!}\r\n", ret);
        oal_mem_free(pc_cmd);
        return 0;
    }
    oal_mem_free(pc_cmd);

    return len;
}
#endif

#ifdef _PRE_CONFIG_CONN_HISI_SYSFS_SUPPORT
/*****************************************************************************
 �� �� ��  : wal_hipriv_sys_write
 ��������  : sys write����

 �޸���ʷ      :
  1.��    ��   : 2014��10��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static hi_ssize_t  wal_hipriv_sys_write(oal_device_stru *dev, oal_device_attribute_stru *attr,
    const char *pc_buffer, hi_size_t count)
{
    hi_u32 len = (hi_u32)count;

    if (len > WAL_HIPRIV_CMD_MAX_LEN) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_hipriv_sys_write::len>WAL_HIPRIV_CMD_MAX_LEN, len [%d]!}\r\n", len);
        return -OAL_EINVAL;
    }

    if (wal_hipriv_entry(pc_buffer, len) != len) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_proc_write::parse cmd return err code!}\r\n");
    }

    return (hi_s32)len;
}

/*****************************************************************************
 �� �� ��  : wal_hipriv_sys_read
 ��������  : sys read���� �պ�������ֹ���뾯��

 �޸���ʷ      :
  1.��    ��   : 2014��10��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#define SYS_READ_MAX_STRING_LEN (4096 - 40)   /* ��ǰ�����ַ�����20�ֽ��ڣ�Ԥ��40��֤���ᳬ�� */
static hi_ssize_t  wal_hipriv_sys_read(oal_device_stru *dev, oal_device_attribute_stru *attr, char *pc_buffer)
{
    hi_u32              cmd_idx;
    hi_u32              buff_index = 0;

    for (cmd_idx = 0; cmd_idx < hi_array_count(g_ast_hipriv_cmd); cmd_idx++) {
        buff_index += snprintf_s(pc_buffer + buff_index, (SYS_READ_MAX_STRING_LEN - buff_index),
                                 strlen(g_ast_hipriv_cmd[cmd_idx].pc_cmd_name) + 3, /* ��3�ֽ� */
                                 "\t%s\n", g_ast_hipriv_cmd[cmd_idx].pc_cmd_name);
        if (buff_index > SYS_READ_MAX_STRING_LEN) {
            buff_index += snprintf_s(pc_buffer + buff_index,
                (SYS_READ_MAX_STRING_LEN - buff_index), 50, "\tmore...\n"); /* count is 50 */
            break;
        }
    }
    return buff_index;
}

#endif


#ifdef _PRE_WLAN_FEATURE_HIPRIV
#ifdef AT_DEBUG_CMD_SUPPORT
static hi_u32 wal_at_set_tpc(oal_net_device_stru *netdev, const hi_char *pc_param)
{
    wal_msg_write_stru        write_msg;
    hi_u32                    off_set = 0;
    hi_char                   tpc_value[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    mac_ioctl_alg_param_stru *alg_param = (mac_ioctl_alg_param_stru *)(write_msg.auc_value);

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    /* ��ȡTPC���ÿ��� */
    if (*pc_param == ' ') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_tpc::cmd error!}");
        return HI_FAIL;
    }

    hi_u32 ret = wal_get_cmd_one_arg(pc_param, tpc_value, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_at_set_tpc::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return ret;
    }

    if ((strcmp("0", tpc_value) != 0) && (strcmp("1", tpc_value) != 0)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_tpc::get tpc switch err}");
        return HI_FAIL;
    }

    /* �ж�������Ƿ������� */
    pc_param += off_set;
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_al_tx::cmd len error!}");
        return HI_FAIL;
    }

    alg_param->alg_cfg = MAC_ALG_CFG_TPC_MODE;
    alg_param->is_negtive = HI_FALSE;
    alg_param->value = (strcmp("0", tpc_value) == 0) ? ALG_TPC_MODE_DISABLE : ALG_TPC_MODE_ADAPT_POWER;

    /* ���¼���wal�㴦�� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_param_stru));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_at_set_tpc::wal_send_cfg_event return err code [%u]!}", ret);
        return ret;
    }

    hi_at_printf("OK\r\n");
    return HI_SUCCESS;
}

hi_u32 wal_at_setcountry(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_u32 ret = wal_hipriv_setcountry(netdev, pc_param);
    if (ret == HI_SUCCESS) {
        hi_at_printf("OK\r\n");
    }

    return ret;
}

static hi_u32 wal_at_set_trc(oal_net_device_stru *netdev, const hi_char *pc_param)
{
    wal_msg_write_stru        write_msg;
    hi_u32                    off_set = 0;
    hi_char                   trc_value[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {'\0'};
    mac_ioctl_alg_param_stru *alg_param = (mac_ioctl_alg_param_stru *)(write_msg.auc_value);

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    /* ��ȡTRC���ÿ��� */
    if (*pc_param == ' ') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_trc::cmd error!}");
        return HI_FAIL;
    }

    hi_u32 ret = wal_get_cmd_one_arg(pc_param, trc_value, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_at_set_trc::wal_get_cmd_one_arg return err_code [%u]!}", ret);
        return HI_FAIL;
    }

    if ((strcmp("0", trc_value) != 0) && (strcmp("1", trc_value) != 0)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_trc::param err}");
        return HI_FAIL;
    }

    /* �ж�������Ƿ������� */
    pc_param += off_set;
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_trc::cmd len error!}");
        return HI_FAIL;
    }

    alg_param->alg_cfg = MAC_ALG_CFG_AUTORATE_ENABLE;
    alg_param->is_negtive = HI_FALSE;
    alg_param->value = (strcmp("0", trc_value) == 0) ? 0 : 1; /* 0:��ֹ���ʵ��ڣ�1: ʹ�����ʵ��� */
    /* ���¼���wal�㴦�� */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_ALG_PARAM, sizeof(mac_ioctl_alg_param_stru));

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_ioctl_alg_param_stru),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_at_set_trc::wal_send_cfg_event return err code [%u]!}", ret);
        return ret;
    }
    g_auto_rate_flag = alg_param->value;

    hi_at_printf("OK\r\n");
    return HI_SUCCESS;
}

static hi_s32 wal_get_protocol_mode(const oal_net_device_stru *netdev, hi_s32 *protocol_mode)
{
    hi_s32                   phy_mode = -1;
    mac_vap_stru             *mac_vap = HI_NULL;

    if ((netdev == HI_NULL) || (netdev->ml_priv == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_get_protocol_mode::netdev or netdev->ml_priv null param!}");
        return HI_FAIL;
    }
    mac_vap = (mac_vap_stru *)netdev->ml_priv;
    /* rate����У�飬Ҫ���ֵ�ǰЭ��ģʽ */
    if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        phy_mode = hi_wifi_sta_get_protocol_mode();
        if (phy_mode == HISI_FAIL) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_get_protocol_mode::hi_wifi_sta_get_protocol_mode fail!}");
            return HI_FAIL;
        }
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_BSS_AP) {
        phy_mode = hi_wifi_softap_get_protocol_mode();
        if (phy_mode == HISI_FAIL) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_get_protocol_mode::hi_wifi_sta_get_protocol_mode fail!}");
            return HI_FAIL;
        }
    } else if (mac_vap->vap_mode == WLAN_VAP_MODE_MESH) {
        phy_mode = HI_WIFI_PHY_MODE_11BGN;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_get_protocol_mode::ifname err!}");
        return HI_FAIL;
    }

    *protocol_mode = phy_mode;
    return HI_SUCCESS;
}

static hi_u32 wal_is_set_rate_valid(hi_s32 protocol_mode, hi_s32 rate)
{
    if (protocol_mode == HI_WIFI_PHY_MODE_11B) {
        if (rate < 0 || rate > 3) { /* 0 3:11b ����ȡֵ��Χ */
            oam_warning_log0(0, OAM_SF_ANY, "{wal_is_set_rate_valid::protocol_mode 11b, rate or short gi err!}");
            return HI_FAIL;
        }
    } else if (protocol_mode == HI_WIFI_PHY_MODE_11BG) {
        if (!((rate >= 24 && rate <= 31) || (rate >= 0 && rate <= 3))) { /* 0 3 24 31:11bg ������Χ */
            oam_warning_log0(0, OAM_SF_ANY, "{wal_is_set_rate_valid::protocol_mode 11bg, rate or short gi err!}");
            return HI_FAIL;
        }
    } else if (protocol_mode == HI_WIFI_PHY_MODE_11BGN) {
        if (!((rate >= 32 && rate <= 39) || (rate >= 24 && rate <= 31) || /* 32 39 24 31 ������Χ */
            (rate >= 0 && rate <= 3))) { /* 0 3 ������Χ */
            oam_warning_log0(0, OAM_SF_ANY, "{wal_is_set_rate_valid::protocol_mode 11bgn, rate err!}");
            return HI_FAIL;
        }
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_is_set_rate_valid::protocol mode err!}");
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

static hi_u32 wal_set_rate_sgi(oal_net_device_stru *netdev, hi_u8 frame_type, hi_s32 protocol_mode,
    hi_s32 rate_value, hi_s8 sgi_val)
{
    wal_msg_write_stru write_msg;

    if (wal_is_set_rate_valid(protocol_mode, rate_value) != HI_SUCCESS) {
        return HI_FAIL;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_DSCR, sizeof(mac_cfg_set_dscr_param_stru));
    /* ��������������������� */
    mac_cfg_set_dscr_param_stru *set_dscr_param = (mac_cfg_set_dscr_param_stru *)(write_msg.auc_value);
    set_dscr_param->type = frame_type;
    set_dscr_param->function_index = MAC_SET_DSCR_PARAM_RATE;
    set_dscr_param->l_value = rate_value;
    if (wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
        sizeof(mac_cfg_set_dscr_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_set_rate_sgi:: set rate return err!}");
        return HI_FAIL;
    }

    /* ����short gi����ֵ */
    if (protocol_mode == HI_WIFI_PHY_MODE_11BGN) {
        /***************************************************************************
                                ���¼���wal�㴦��
        ***************************************************************************/
        set_dscr_param->type = frame_type;
        set_dscr_param->function_index = MAC_SET_DSCR_PARAM_SHORTGI;
        set_dscr_param->l_value = (hi_s32)sgi_val;
        if (wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
            sizeof(mac_cfg_set_dscr_param_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_set_rate_sgi::set sgi return err!}");
            return HI_FAIL;
        }
    }
    return HI_SUCCESS;
}

static hi_u32 wal_at_set_rate(oal_net_device_stru *netdev, const hi_char *pc_param)
{
    hi_char                             ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_char                             *ac_arg_ptr = ac_arg;
    hi_u32                              off_set = 0;
    mac_set_dscr_frame_type_enum_uint8  frame_type = MAC_SET_DSCR_TYPE_UCAST_DATA; /* ��֧�����õ�������֡ */
    hi_s32                              rate_value = -1;
    hi_s8                               sgi_val = 0; /* short gi ���� */
    hi_s32                              protocol_mode = -1;

    if (g_auto_rate_flag == 1) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_rate::auto rate is on!}");
        return HI_FAIL;
    }

    if (wal_get_protocol_mode(netdev, &protocol_mode) != HI_SUCCESS) {
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    pc_param++;
#endif
    for (hi_u32 i = 0; i < 3; i++) { /* 3: �ֱ�ȡ��3������ */
        if (wal_hipriv_get_value(pc_param, ac_arg_ptr, &off_set, 1) != HI_SUCCESS) {
            return HI_FAIL;
        }
        pc_param += off_set;
        if (i == 0) {
            if (strcmp("0", ac_arg_ptr) == 0) {
                frame_type = MAC_SET_DSCR_TYPE_UCAST_DATA; /* ��һ������ȡֵ0��֡����Ϊ��������֡ */
            } else {
                return HI_FAIL;
            }
        } else if (i == 1) {
            rate_value = oal_strtol(ac_arg_ptr, HI_NULL, 0);
            if ((protocol_mode == HI_WIFI_PHY_MODE_11B) || (protocol_mode == HI_WIFI_PHY_MODE_11BG)) {
                break;
            }
        } else if (i == 2) { /* 2: ���������� short gi */
            if ((strcmp("0", ac_arg_ptr) == 0) || (strcmp("1", ac_arg_ptr) == 0)) {
                sgi_val = (hi_s8)oal_atoi(ac_arg_ptr);
            } else {
                return HI_FAIL;
            }
        }
    }
    /* �ж�������Ƿ������� */
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_set_rate::cmd len error}");
        return HI_FAIL;
    }
    /* ����rate ��short gi����ֵ */
    if (wal_set_rate_sgi(netdev, frame_type, protocol_mode, rate_value, sgi_val) != HI_SUCCESS) {
        return HI_FAIL;
    }
#ifdef AT_DEBUG_CMD_SUPPORT
    hi_at_printf("OK\r\n");
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����˽����������
 �������  : pc_cmd: ����
 �� �� ֵ  : ������
*****************************************************************************/
static hi_u32 wal_at_cmd(oal_net_device_stru *netdev, hi_char *cmd, hi_u32 cmd_type)
{
    hi_u32 ret = HI_SUCCESS;

    if (cmd_type == HISI_AT_AL_TX) {
        ret = wal_hipriv_tx_proc(netdev, cmd);
    } else if (cmd_type == HISI_AT_AL_RX) {
        ret = wal_hipriv_rx_proc(netdev, cmd);
    } else if (cmd_type == HISI_AT_RX_INFO) {
        ret = wal_hipriv_rx_fcs_info(netdev, cmd);
    } else if (cmd_type == HISI_AT_SET_COUNTRY) {
        ret = wal_at_setcountry(netdev, cmd);
    } else if (cmd_type == HISI_AT_GET_COUNTRY) {
        ret = wal_hipriv_getcountry(netdev, cmd);
    } else if (cmd_type == HISI_AT_SET_WLAN0_BW) {
        ret = wal_hipriv_set_bw(netdev, cmd);
    } else if (cmd_type == HISI_AT_SET_AP0_BW) {
        ret = wal_hipriv_set_bw(netdev, cmd);
    } else if (cmd_type == HISI_AT_SET_MESH0_BW) {
        ret = wal_hipriv_set_bw(netdev, cmd);
#ifdef _PRE_WLAN_FEATURE_MESH
    } else if ((cmd_type == HISI_AT_GET_WLAN0_MESHINFO) || (cmd_type == HISI_AT_GET_MESH0_MESHINFO)) {
        ret = wal_hipriv_get_mesh_node_info(netdev, cmd);
#endif
    } else if (cmd_type == HISI_AT_SET_TPC) {
        ret = wal_at_set_tpc(netdev, cmd);
    } else if (cmd_type == HISI_AT_SET_TRC) {
        ret = wal_at_set_trc(netdev, cmd);
    } else if (cmd_type == HISI_AT_SET_RATE) {
        ret = wal_at_set_rate(netdev, cmd);
    } else {
        return HI_FAIL;
    }

    return ret;
}

/*****************************************************************************
 ��������  : ����ҵ��vap���Ͳ�ѯ����
 �������  : vap_mode VAP����
 �� �� ֵ  :��������,HI_NULL��ʾ����ʧ��
*****************************************************************************/
hi_char *wal_at_find_netif_by_mode(wlan_vap_mode_enum vap_mode)
{
    oal_net_device_stru            *netdev = HI_NULL;
    mac_vap_stru                   *mac_vap = HI_NULL;
    mac_device_stru *mac_dev = mac_res_get_dev();
    hi_u8 vap_idx;

    for (vap_idx = 0; vap_idx < mac_dev->vap_num; vap_idx++) {
        mac_vap = mac_vap_get_vap_stru(mac_dev->auc_vap_id[vap_idx]);
        if (mac_vap == HI_NULL) {
            continue;
        }
        if (mac_vap->vap_mode == vap_mode) {
            break;
        }
    }
    if (mac_vap == HI_NULL) {
        return HI_NULL;
    }
    netdev = hmac_vap_get_net_device(mac_vap->vap_id);
    if (netdev == HI_NULL) {
        oam_error_log1(0, 0, "wal_at_find_netif_by_mode cannot find netdevice,vap_mode[%d].", vap_mode);
        return HI_NULL;
    }

    return netdev->name;
}

/*****************************************************************************
 ��������  : hipriv�������
 �������  : *pc_buffer �������
            count �����
 �� �� ֵ  : �ֽ�����0��ʾhiprivʧ��
*****************************************************************************/
hi_u32 wal_at_entry(hi_char *buffer, hi_u32 cmd_type)
{
    hi_u32               ret;
    oal_net_device_stru *netdev = HI_NULL;
    hi_char             *dev_name        = HI_NULL;
    hi_char              net_hisilicon[] = "Hisilicon0";
    hi_char              ac_arg[WAL_HIPRIV_CMD_NAME_MAX_LEN];
    hi_char              *ac_arg_ptr = ac_arg;
    hi_u32               off_set = 0;
    hi_char              *cmd_buff = buffer;

    if ((cmd_type == HISI_AT_SET_COUNTRY) || (cmd_type == HISI_AT_GET_COUNTRY) || (cmd_type == HISI_AT_SET_TPC) ||
        (cmd_type == HISI_AT_SET_TRC)) {
        dev_name = net_hisilicon;
    } else if (cmd_type == HISI_AT_SET_AP0_BW) {
        dev_name = wal_at_find_netif_by_mode(WLAN_VAP_MODE_BSS_AP);
    } else if ((cmd_type == HISI_AT_SET_MESH0_BW) || (cmd_type == HISI_AT_GET_MESH0_MESHINFO)) {
        dev_name = wal_at_find_netif_by_mode(WLAN_VAP_MODE_MESH);
    } else if (cmd_type == HISI_AT_SET_RATE) {
        /* ��һ������Ϊ wlan0 ���� ap0 */
        if (wal_hipriv_get_value(cmd_buff, ac_arg_ptr, &off_set, 0) != HI_SUCCESS) {
            return HI_FAIL;
        }
        dev_name = ac_arg_ptr;
        cmd_buff += off_set;
    } else {
        dev_name = wal_at_find_netif_by_mode(WLAN_VAP_MODE_BSS_STA);
    }

    /* ����dev_name�ҵ�dev */
    netdev = oal_get_netdev_by_name(dev_name);
    if (netdev == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_at_entry::get netdev by name return null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    ret = wal_at_cmd(netdev, cmd_buff, cmd_type);
    return ret;
}

hi_u32 hi_wifi_at_start(hi_s32 argc, const hi_char *argv[], hi_u32 cmd_type)
{
    hi_u32      total_len = 0;
    hi_s32      index;
    hi_char     temp_buffer[3]; /* 3 �洢buffer */
    hi_char    *buffer = NULL;
    hi_char    *buffer_temp = NULL;
    hi_char    *buffer_index = NULL;

    if (argv == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "hi_wifi_at_start: argv null!");
        return HI_ERR_FAILURE;
    }
    /* HISI_AT_RX_INFO��HISI_AT_GET_COUNTRY���� */
    if (argc == 0) {
        temp_buffer[0] = '\0';
        buffer_temp = temp_buffer;
    } else {
        for (index = 0; index < argc; index++) {
            total_len += strlen((hi_char *)argv[index]) + 1;
        }

        buffer = oal_memalloc(total_len);
        if (buffer == NULL) {
            oam_error_log0(0, OAM_SF_ANY, "hi_wifi_at_start: malloc failed!");
            return HI_ERR_FAILURE;
        }

        buffer_index = buffer;
        for (index = 0; index < argc; index++) {
            hi_u32 len = strlen((hi_char *)argv[index]);
            if (memcpy_s(buffer_index, len, argv[index], len) != EOK) {
                oam_error_log0(0, 0, "{hi_wifi_at_start::mem safe function err!}");
                oal_free(buffer);
                return HI_ERR_FAILURE;
            }
            buffer_index[len] = ' ';
            buffer_index += (len + 1);
        }
        buffer[total_len - 1] = '\0';
        buffer_temp = buffer;
    }

    if (wal_at_entry(buffer_temp, cmd_type) != HI_SUCCESS) {
        if (buffer != NULL) {
            oal_free(buffer);
        }
        return HI_ERR_FAILURE;
    }

    if (buffer != NULL) {
        oal_free(buffer);
    }
    return HI_ERR_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_MFG_TEST
/*****************************************************************************
 ��������  : �Ը�band��ƽ�����ʲ��������ݲ����¼���hmac
 �������  : [1]band_num band���
             [2]offset ���ʲ���ֵ
 �������  : ��
 �� �� ֵ  : �Ը�band��ƽ�����ʲ��������ݲ����¼���hmac �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 wal_set_cal_band_power(hi_u8 band_num, hi_s32 offset)
{
    wal_msg_write_stru  write_msg;
    mac_cfg_cal_bpower *cal_bpower = HI_NULL;

    oal_net_device_stru *netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_set_cal_band_power:Hisilicon0 device not fonud.");
        return HI_FAIL;
    }
    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    if ((offset > CAL_BAND_POWER_OFFSET_MAX) || (offset < CAL_BAND_POWER_OFFSET_MIN)) {
        return HI_FAIL;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CAL_BAND_POWER, sizeof(mac_cfg_cal_bpower));

    /* ��������������������� */
    cal_bpower = (mac_cfg_cal_bpower *)(write_msg.auc_value);
    cal_bpower->band_num = band_num;
    cal_bpower->offset   = offset;

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_cal_bpower), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_set_cal_band_power:: wal_send_cfg_event return Err=%u}", ret);
    }
    return ret;
}

hi_u32 wal_hipriv_set_cal_band_power(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_u32             ret;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32             off_set;
    hi_u8              band_num;
    hi_s32             offset;

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_cal_band_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;

    band_num = (hi_u8)oal_atoi(ac_name);
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_cal_band_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    offset = (hi_s32)oal_atoi(ac_name);
    ret = wal_set_cal_band_power(band_num, offset);
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ��������ݲ����¼���hmac
 �������  : [1]protol Э�����
             [2]rate ����
             [3]val ����ֵ
 �������  : ��
 �� �� ֵ  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ��������ݲ����¼���hmac �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 wal_set_cal_rate_power(hi_u8 protol, hi_u8 rate, hi_s32 val)
{
    wal_msg_write_stru  write_msg;
    mac_cfg_cal_rpower *cal_rpower = HI_NULL;

    oal_net_device_stru *netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_set_cal_rate_power:Hisilicon0 device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CAL_RATE_POWER, sizeof(mac_cfg_cal_rpower));

    /* ��������������������� */
    cal_rpower = (mac_cfg_cal_rpower *)(write_msg.auc_value);
    cal_rpower->protol = protol;
    cal_rpower->rate   = rate;
    cal_rpower->val    = val;

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_cal_rpower), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_set_cal_rate_power:: wal_send_cfg_event return Err=%u}", ret);
    }
    return ret;
}

/*****************************************************************************
 ��������  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ�����at������в�������У��.��������
 �������  : [1]argc �����������
             [2]argv ����ָ��
 �������  : ��
 �� �� ֵ  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ�����at������в�������У�� �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 wal_hipriv_set_cal_rate_power(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_u32             ret;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32             off_set;
    hi_u8              protol;
    hi_u8              rate;
    hi_s32             val;
    hi_u8  ofs = 0;
    hi_u8  protol_ofs = 0;
    hi_s32 low_limit = -8;    /* -8:������������ */
    hi_s32 up_limit =  7;     /* 7:������������ */

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_cal_rate_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    protol = (hi_u8)oal_atoi(ac_name);
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{wal_hipriv_set_cal_rate_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    rate = (hi_u8)oal_atoi(ac_name);
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_cal_rate_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    val = (hi_s32)oal_atoi(ac_name);
    if (protol > 2) {   /* ��Χ0~2 */
        return HI_FAIL;
    }

    if (((protol == HI_WIFI_MODE_11BGN) && (rate > 7 + ofs)) || /* 11n��Χ0~7 */
        ((protol == HI_WIFI_MODE_11BG) && (rate > 7 + ofs)) ||  /* 11g��Χ0~7 */
        ((protol == HI_WIFI_MODE_11B) && (rate > 3 + ofs))) { /* 11b��Χ0~3 */
        return HI_ERR_FAILURE;
    }

    if ((val < low_limit) || (val > up_limit)) {
        return HI_FAIL;
    }

    protol += protol_ofs;   /* Э������ƫ���������з����Ի��ǲ������� */
    ret = wal_set_cal_rate_power(protol, rate, val);
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ��������ͻ��з�������,��дefuse
 �������  : [1]argc �����������
             [2]argv ����ָ��
 �������  : ��
 �� �� ֵ  : �Բ�ͬЭ�鳡�����������ʷֱ������ʲ�����at������в�������У�� �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 wal_hipriv_set_rate_power(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_u32             ret;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32             off_set;
    hi_u8              protol;
    hi_u8              rate;
    hi_s32             val;
    hi_u8  ofs = 1;
    hi_u8  protol_ofs = 10;   /* 10:�������ƫ��,�Ա�������at_hi_wifi_set_rate_power������ */
    hi_s32 low_limit = -100;  /* -100:������������ */
    hi_s32 up_limit = 40;     /* 40:������������ */

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_rate_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    protol = (hi_u8)oal_atoi(ac_name);
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{wal_hipriv_set_rate_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    rate = (hi_u8)oal_atoi(ac_name);
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
            "{wal_hipriv_set_rate_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    val = (hi_s32)oal_atoi(ac_name);
    if (protol > 2) { /* ��Χ0~2 */
        return HI_FAIL;
    }

    if (((protol == HI_WIFI_MODE_11BGN) && (rate > 7 + ofs)) || /* 11n��Χ0~7 */
        ((protol == HI_WIFI_MODE_11BG) && (rate > 7 + ofs)) ||  /* 11g��Χ0~7 */
        ((protol == HI_WIFI_MODE_11B) && (rate > 3 + ofs))) { /* 11b��Χ0~3 */
        return HI_ERR_FAILURE;
    }

    if ((val < low_limit) || (val > up_limit)) {
        return HI_FAIL;
    }

    protol += protol_ofs; /* Э������ƫ���������з����Ի��ǲ������� */
    ret = wal_set_cal_rate_power(protol, rate, val);
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ���г���Ƶƫ���ʲ��������ݲ����¼���hmac
 �������  : [1]freq_offset ����ֵ
 �������  : ��
 �� �� ֵ  : ���г���Ƶƫ���ʲ��������ݲ����¼���hmac �Ƿ�ɹ��Ľ��
*****************************************************************************/
hi_u32 wal_set_cal_freq(hi_s32 freq_offset)
{
    wal_msg_write_stru write_msg;
    hi_s32            *param = HI_NULL;

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    oal_net_device_stru *netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_set_cal_freq:Hisilicon0 device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    if ((freq_offset > CAL_FREP_OFFSET_MAX) || (freq_offset < CAL_FREP_OFFSET_MIN)) {
        return HI_FAIL;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_CAL_FREQ, sizeof(hi_s32));
    /* ��������������������� */
    param = (hi_s32 *)(write_msg.auc_value);
    *param = freq_offset;

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
        (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_set_cal_freq:: wal_send_cfg_event return Err=%u}", ret);
    }
    return ret;
}

hi_u32 wal_hipriv_set_cal_freq_power(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_u32             ret;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_s32             freq_offset;
    hi_u32             off_set;

    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{wal_hipriv_set_cal_freq_power::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

    freq_offset = (hi_s32)oal_atoi(ac_name);
    ret = wal_set_cal_freq(freq_offset);
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡefuse��MAC
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 wal_get_efuse_mac(hi_void)
{
    oal_net_device_stru *netdev;
    wal_msg_write_stru  write_msg = {0};

    netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_get_efuse_mac::sta device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_GET_EFUSE_MAC, sizeof(hi_s32));

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
        sizeof(hi_s32), (hi_u8 *)(&write_msg), HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_get_efuse_mac::return err code [%u]!}\r\n", ret);
    }

    return ret;
}

hi_u32 wal_hipriv_get_customer_mac(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(pc_param);
    hi_unref_param(netdev);
    hi_u32             ret;
    hi_uchar           mac_addr[WLAN_MAC_ADDR_LEN];

    /* ���ȼ�鷵��wifi_cfg�е�mac��ַ */
    if (cfg_get_mac(mac_addr, WLAN_MAC_ADDR_LEN) && (wal_macaddr_check(&mac_addr[0]) == HI_SUCCESS)) {
        printk("+EFUSEMAC:%02x:%02x:%02x:%02x:%02x:%02x\r\nOK\r\n",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]); /* 0:1:2:3:4:5 */
        return HI_SUCCESS;
    }
    /* ��efuse�� */
    ret = wal_get_efuse_mac();
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��MACд��efuse
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 wal_set_efuse_mac(const hi_char *mac_addr, hi_u32 type)
{
    hi_unref_param(type);
    wal_msg_write_stru  write_msg;
    oal_net_device_stru *netdev;

    netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_set_efuse_mac::sta device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    if (mac_addr == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "wal_set_efuse_mac:: macaddr is NULL!");
        return HI_FAIL;
    }
    /* ��������������� */
    if (memcpy_s(write_msg.auc_value, ETHER_ADDR_LEN, mac_addr, ETHER_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{wal_set_efuse_mac::mem safe function err!}");
        return HI_FAIL;
    }
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_EFUSE_MAC, ETHER_ADDR_LEN);

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
        ETHER_ADDR_LEN, (hi_u8 *)(&write_msg), HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_set_efuse_mac::return err code [%u]!}\r\n", ret);
    }
    return ret;
}

hi_u32 wal_hipriv_set_customer_mac(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_u32             ret;
    hi_uchar           mac_addr[WLAN_MAC_ADDR_LEN];
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_char            mac_str[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32             off_set;
    hi_u32             type = 0;

    /* ��ȡmac��ַ */
    ret = wal_get_cmd_one_arg(pc_param, mac_str, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_hipriv_set_customer_mac::wal_get_cmd_one_arg return err_code [%d]!}\r\n", ret);
        return ret;
    }
    pc_param += off_set;
    if (!parse_mac_addr((hi_u8 *)mac_str, strlen((const hi_char *)mac_str), mac_addr, WLAN_MAC_ADDR_LEN) ||
        (wal_macaddr_check(mac_addr) != HI_SUCCESS)) {
        printk("Mac addr is invalid.\r\n");
        return HI_FAIL;
    };
    hi_u8 mac_str_len = off_set;
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret == HI_SUCCESS) {
        type = (hi_u32)oal_atoi(ac_name);
    }
    pc_param += off_set;
    /* ����Ϊд�뵽wifi_cfg */
    if (type == 1) {
        if (firmware_write_cfg((hi_u8 *)WIFI_CFG_MAC, (hi_u8 *)mac_str, mac_str_len - 1) != HI_SUCCESS) { /* ��1 */
            oam_error_log0(0, OAM_SF_ANY, "wal_hipriv_set_customer_mac:: save to wifi_cfg failed!");
            return HI_FAIL;
        }
        printk("OK\r\n");
        return HI_SUCCESS;
    } else if (type == 0) { /* ����Ϊд�뵽efuse */
        ret = wal_set_efuse_mac((hi_char*)mac_addr, type);
        if (ret != HI_SUCCESS) {
            return HI_FAIL;
        }
    } else {
        oam_error_log0(0, OAM_SF_ANY, "wal_hipriv_set_customer_mac:: cmd para invalid!");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��У׼ֵд��efuse
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 wal_set_dataefuse(hi_u32 type)
{
    oal_net_device_stru *netdev;
    wal_msg_write_stru  write_msg = {0};
    hi_s32            *param = HI_NULL;

    netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_set_dataefuse::sta device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    /* ��������������������� */
    param = (hi_s32 *)(write_msg.auc_value);
    *param = type;

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_DATAEFUSE, sizeof(hi_s32));

    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH +
        sizeof(hi_s32), (hi_u8 *)(&write_msg), HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hi_wifi_set_dataefuse::return err code [%u]!}\r\n", ret);
    }
    return ret;
}

hi_u32 wal_hipriv_set_dataefuse(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_unref_param(pc_param);
    hi_u32              ret;
    hi_u32             off_set;
    hi_u32             type = 0;
    hi_char            ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};

    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret == HI_SUCCESS) {
        type = (hi_u32)oal_atoi(ac_name);
    }

    ret = wal_set_dataefuse(type);
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡУ׼����
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 wal_get_cal_data(hi_void)
{
    oal_net_device_stru *netdev;
    wal_msg_write_stru  write_msg = {0};
    hi_u32              ret;
    netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_get_cal_data::sta device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_GET_CAL_DATA, sizeof(hi_s32));
    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)(&write_msg),
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_get_cal_data::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_u32 wal_hipriv_get_cal_data(oal_net_device_stru *netdev, hi_char *pc_param)
{
    hi_unref_param(netdev);
    hi_u32              ret;

    /* �ж�������Ƿ������� */
    if (*pc_param != '\0') {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_hipriv_get_cal_data::cmd len error}");
        return HI_FAIL;
    }
    ret = wal_get_cal_data();
    if (ret != HI_SUCCESS) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}
#endif /* _PRE_WLAN_FEATURE_MFG_TEST */

hi_u32 hi_hipriv_set_tx_pwr_offset(oal_net_device_stru *netdev, hi_char *pc_param)
{
    wal_msg_write_stru          write_msg = {0};
    hi_s32                     *param = HI_NULL;
    hi_u32                      ret;
    hi_s16                      offset;
    hi_char                     ac_name[WAL_HIPRIV_CMD_NAME_MAX_LEN] = {0};
    hi_u32                  off_set;
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hi_wifi_set_tx_pwr_offset:: device not fonud.");
        return HI_FAIL;
    }
    /* �͹���״̬�²�����ִ�� */
    if (is_under_ps()) {
        oam_warning_log0(0, 0, "under ps mode,can not exec cmd");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif
    ret = wal_get_cmd_one_arg(pc_param, ac_name, WAL_HIPRIV_CMD_NAME_MAX_LEN, &off_set);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_CFG,
                         "{hi_hipriv_set_tx_pwr_offset::wal_get_cmd_one_arg return err_code %d!}\r\n", ret);
        return ret;
    }

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        offset = (hi_s16)atoi(ac_name);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        offset = (hi_s16)oal_atoi(ac_name);
#endif
    offset = (offset > 30) ? 30 : offset;     /* 30:���� */
    offset = (offset < -150) ? -150 : offset; /* -150:���� */
    /* ��������������������� */
    param = (hi_s32 *)(write_msg.auc_value);
    *param = offset;

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_TX_PWR_OFFSET, sizeof(hi_s32));
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
                             (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hi_wifi_set_tx_pwr_offset::return err code [%u]!}\r\n", ret);
        return ret;
    }
    return HI_SUCCESS;
}

#endif /* #ifdef _PRE_WLAN_FEATURE_HIPRIV */

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

