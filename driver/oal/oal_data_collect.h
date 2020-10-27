/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_data_collect.h.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_DATA_COLLECT_H__
#define __OAL_DATA_COLLECT_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* ��������� */
typedef enum {
    WLAN_DEBUG_DATA_ACQ    = 0,       /* DEBUG���ݲɼ� */
    WLAN_ABB_DATA_ACQ      = 1,       /* ABB���ݲɼ� */
    WLAN_ABB_DATA_GEN      = 2,       /* ABB���ݲ��� */
    WLAN_CBB_DATA_ACQ      = 3,       /* CBB���ݲɼ� */
    WLAN_MAC_DATA_ACQ      = 4,       /* MAC���ݲɼ� */
    WLAN_PHY_DATA_ACQ      = 5,       /* PHY���ݲɼ� */
    WLAN_CPU_TRACE_ACQ     = 6,       /* CPU_TRACE */
    WLAN_CPU_MONITOR_ACQ   = 7,       /* CPU_PC_MONITOR */
    WLAN_DATA_ACQ_STATUS   = 8,       /* ���ݲɼ����״̬��ѯ */
    WLAN_DATA_ACQ_RECODE   = 9,       /* ���ݲɼ���ɻ�ȡ���� */

    WLAN_DATA_ACQ_BUTT
} wlan_data_acq_enum;
typedef hi_u8 wlan_data_acq_enum_uint8;

/* ���ݲɼ�״̬ */
typedef enum {
    WLAN_DATA_ACQ_STATUS_INIT            = 0,  /*       ��ʼ��״̬      */
    WLAN_DATA_ACQ_STATUS_ENABLE          = 1,  /*    �������ݲɼ�״̬   */
    WLAN_DATA_ACQ_STATUS_COMPLETE        = 2,  /*  �������ݲɼ����״̬ */

    WLAN_DATA_ACQ_STATUS_BUTT
} wlan_data_acq_status_enum;
typedef hi_u8 wlan_data_acq_status_enum_uint8;

/* ���ݲɼ����ýṹ�� */
typedef struct {
    hi_u8                             vap_id;           /* �ɼ�vap id */
    hi_u8                             monitor_sel;      /* �ɼ�memoryѡ�� */
    hi_u8                             trace_recycle;    /* �ɼ��洢��ʽ */
    hi_u8                             monitor_mode;     /* �ɼ�Դͷѡ�� */
    wlan_data_acq_enum_uint8          monitor_type;     /* �ɼ�ģʽ */
    hi_u8                             mac_acq_type;     /* MAC��������ѡ�� */
    hi_u8                             mac_acq_subtype;  /* MAC����������ѡ�� */
    wlan_data_acq_status_enum_uint8   daq_status;       /* ��ǰ�Ƿ�����ʹ�����ݲɼ����� */
    hi_u16                            us_monitor_laddr;    /* ��ʼ��ַ���� */
    hi_u16                            us_monitor_haddr;    /* ������ַ���� */
    hi_u32                            phy_acq_type:4,      /* PHY��������ѡ�� */
                                      phy_test_node_sel:8, /* PHY������ѡ�� */
                                      phy_trig_cond:4,     /* PHY������������ */
                                      phy_smp_aft_trig:16; /* PHY����������������� */
} wlan_data_acq_stru;

typedef struct {
    hi_u32                            start_addr;     /* ��ʼ��ַ */
    hi_u32                            middle_addr1;   /* �м��ַ1 */
    hi_u32                            middle_addr2;   /* �м��ַ2 */
    hi_u32                            end_addr;       /* ������ַ */
} wlan_acq_result_addr_stru;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif
