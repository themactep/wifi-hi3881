/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WOW hmac function.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_WOW_H__
#define __HMAC_WOW_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "frw_event.h"
#include "mac_device.h"
#include "hmac_device.h"
#include "mac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define WOW_H2D_SLP_MSG_CNT     (g_wow_info.debug_info.int_info.h2d_slp_msg_cnt)
#define WOW_H2D_WKUP_MSG_CNT    (g_wow_info.debug_info.int_info.h2d_wkup_msg_cnt)
#define WOW_D2H_MSG_CNT         (g_wow_info.debug_info.int_info.d2h_msg_cnt)

#define WOW_H2D_SLP_MSG             0
#define WOW_H2D_WKUP_MSG            1
#define WOW_D2H_MSG                 2

#define WOW_SLEEP_REQ_WAIT_TIMEOUT  (3000)
/* �Ĵ���ʱ��ת��ms */
#define calc_time_test_func(time) ((0xffffffff - (time)) * 256 / 50000)
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef enum {
    HMAC_HOST_STATE_INVALID,
    HMAC_HOST_STATE_WAKEUP,
    HMAC_HOST_STATE_SLEEP_REQ,
    HMAC_HOST_STATE_DEV_READY_FOR_HOST_SLEEP,
    HMAC_HOST_STATE_HOST_READY,
    HMAC_HOST_STATE_SLEPT,
    HMAC_HOST_STATE_BUTT
}hmac_host_sleep_state_enum;
typedef hi_u8 hmac_host_sleep_state_enum_uint8;

typedef enum {
    MAC_WOW_PATTERN_PARAM_OPTION_NONE,
    MAC_WOW_PATTERN_PARAM_OPTION_CLR,
    MAC_WOW_PATTERN_PARAM_OPTION_ADD,
    MAC_WOW_PATTERN_PARAM_OPTION_DEL,
    MAC_WOW_PATTERN_PARAM_OPTION_BUTT
}mac_wow_pattern_param_option_enum;

typedef enum {
    EVENT_TX_TYPE,
    EVENT_RX_TYPE,
    EVENT_DUAL_TYPE,
    EVENT_TYPE_BUTT
}mac_event_type_enum;
typedef hi_u8 mac_event_type_enum_uint8;

typedef enum {
    HMAC_WOW_MODULE_STATE_NOT_INIT  = 0,
    HMAC_WOW_MODULE_STATE_INIT      = 1,
    HMAC_WOW_MODULE_BUTT
}hmac_wow_init_state_enum;
typedef hi_u8 hmac_wow_init_state_enum_uint8;

/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
typedef struct {
    hi_u16      us_pattern_option;
    hi_u16      us_pattern_index;
    hi_u32      pattern_len;
    hi_u8       auc_pattern_value[WOW_NETPATTERN_MAX_LEN];
}hmac_cfg_wow_pattern_param_stru;

typedef struct {
    hi_u8                     ssid_set_flag;
    hi_s8                      ac_ssid[WLAN_SSID_MAX_LEN]; /* 32+1 */
    hi_u16                    us_pno_period;
    hi_u8                     channel_num;
    hi_u8                     auc_res[3]; /* 3 �����ֽ� */
}hmac_cfg_wow_ssid_param_stru;

typedef struct {
    hi_u8   tx_cnt;
    hi_u8   rx_cnt;
    hi_u8   dual_cnt;
    hi_u8   res;
}hmac_wow_event_stru;

typedef struct {
    hi_u32  h2d_slp_msg_cnt;
    hi_u32  h2d_wkup_msg_cnt;
    hi_u32  d2h_msg_cnt;
}hmac_wow_int_stru;

typedef struct {
    hmac_wow_event_stru event_info;
    hmac_wow_int_stru   int_info;
}hmac_wow_debug_info_stru;

typedef struct {
    hmac_host_sleep_state_enum_uint8    host_sleep_state;
    hi_u8                           is_wow_init;
    hi_u8                           wait_dev_data;
    hi_u8                           get_flag;
    hi_u32                          wakeup_reason;
    mac_wow_cfg_stu                 wow_cfg;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_completion                  sleep_req_done_event;
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_u32                          sleep_req_done_event;
#endif
    hmac_wow_debug_info_stru        debug_info;
}hmac_wow_info_stru;

/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_void hmac_wow_set_host_state(hi_u8 sleep_state);
hi_u8 hmac_wow_get_host_state(hi_void);
hi_void hmac_wow_init(hi_void);
hi_void hmac_wow_deinit(hi_void);
hi_void* hmac_wow_get_cfg_vap(hi_void);
hi_u32  hmac_wow_tx_check_filter_switch(hi_void);
hi_void hmac_wow_stop_scan_assoc(hi_void);
hi_void hmac_wow_stop_upper_layer_queue(hi_void);
hi_void hmac_wow_clear_data_channal(hi_void);
hi_void hmac_wow_clear_event_queue(hi_void);
hi_void hmac_wow_prepare_wakeup(hi_void);
hi_void hmac_wow_host_sleep_cmd(mac_vap_stru *mac_vap, hi_u32 is_host_sleep);
hi_void hmac_wow_set_wow_cmd(hi_u32 wow_event);
hi_void hmac_wow_set_wow_en_cmd(hi_u32 wow_en);
hi_u32 hmac_wow_add_pattern(hi_u16 us_pattern_index, hi_u32 pattern_len, const hi_u8 *puc_pattern);
hi_u32 hmac_wow_set_pattern_cmd(const hmac_cfg_wow_pattern_param_stru *pattern);
hi_void hmac_wow_host_sleep_request(hi_void);
hi_void hmac_wow_host_wakeup_notify(hi_void);
hi_void hmac_wow_create_lock(hi_void);
hi_void hmac_wow_obtain_lock(hi_void);
hi_void hmac_wow_release_lock(hi_void);
hi_s32 hmac_wow_completion(hi_void *data);
hi_void hmac_wow_trigger_host_state(hi_void);
hi_u32  hmac_wow_proc_dev_ready_slp_event(frw_event_mem_stru *event_mem);
hi_u32  hmac_wow_proc_dev_sync_host_event(frw_event_mem_stru *event_mem);
hi_u32  hmac_wow_set_dmac_cfg(hi_void);
hi_u32  hmac_wow_host_sleep_wakeup_notify(hi_u8 is_sleep_req);
hi_void wlan_suspend(hi_void);
hi_void wlan_resume(hi_void);
hi_void wlan_wifi_suspend(hi_void);
hi_void wlan_wifi_resume(hi_void);
hi_void hmac_wow_proc_dev_ready_slp(hi_void);
hi_s32 hmac_wow_msg_handle(hi_void);
hi_u32 hmac_wow_check_event(const frw_event_hdr_stru *event_hrd, hi_u8 event_dir);
hi_u32 hmac_wow_send_h2d_sync_data(hi_void);
hi_s32 hmac_save_wow(hi_void);
hi_s32 hmac_recover_wow(hi_void);
hi_void hmac_wow_msg_incr(hi_u32 msg_type);

/*****************************************************************************
 �� �� ��  : hisi_wlan_suspend
 ��������  : ǿ��˯�� API�ӿ�
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void hisi_wlan_suspend(hi_void);

/*****************************************************************************
 �� �� ��  : hisi_wlan_set_wow_event
 ��������  : ����ǿ��˯�߹��ܿ��ؽӿ�
 �������  : ul_event �¼�����ֵ
 �������  : ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void hisi_wlan_set_wow_event(hi_u32 event);

/*****************************************************************************
 �� �� ��  : hisi_wlan_add_netpattern
 ��������  : ǿ��˯��netpattern���ѱ��ĸ�ʽ�����API�ӿ�
 �������  : [1]netpattern_index: netpattern ������, 0~3
             [2]puc_netpattern_data: netpattern ������
             [3]netpattern_len: netpattern �����ݳ���, 0~64
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
*****************************************************************************/
hi_u32 hisi_wlan_add_netpattern(
                        hi_u32    netpattern_index,
                        hi_uchar  *puc_netpattern_data,
                        hi_u32    netpattern_len);

/*****************************************************************************
 �� �� ��  : hisi_wlan_del_netpattern
 ��������  : ǿ��˯��netpattern���ѱ��ĸ�ʽ��ɾ��API�ӿ�
 �������  :    ul_netpattern_index: netpattern ������, 0~3
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hisi_wlan_del_netpattern(hi_u32 netpattern_index);

/*****************************************************************************
 �� �� ��  : hisi_wlan_get_wakeup_reason
 ��������  : ǿ��˯�߻���ԭ��Ļ�ȡAPI�ӿ�
 �������  : * pul_wakeup_reason[OUT]: ����ԭ��
 �������  : ��
 �� �� ֵ  : 0  : �ɹ�
             ��0: ʧ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2017��01��05��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hisi_wlan_get_wakeup_reason(hi_u32 *pul_wakeup_reason);

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
#endif /* __HMAC_WOW_H__ */
