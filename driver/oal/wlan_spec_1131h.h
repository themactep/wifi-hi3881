/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: 1102 wlan product specification macro definition.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WLAN_SPEC_1131_H__
#define __WLAN_SPEC_1131_H__

/*****************************************************************************
  ����ͷ�ļ�����
*****************************************************************************/
#include "hi_types.h"
#include "oal_err_wifi.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  1 �汾spec
*****************************************************************************/
/* ��efuseʵ�ֺ��л� TBD */
#define WLAN_CHIP_VERSION_HI1131HV100    0x11310101
#define WLAN_COMPILE_VERSION             PRODUCT_CFG_SOFT_VER_STR

/*****************************************************************************
  2 ��Core��Ӧspec
*****************************************************************************/
#define WLAN_FRW_MAX_NUM_CORES            1             /* WiFi��ӦLinuxϵͳCORE������ Ϊ1 */
#define WLAN_AMSDU_MAX_NUM                12            /* һ��amsdu������ӵ�е�msdu�������� */
/*****************************************************************************
  3 STA��������
*****************************************************************************/
#define WLAN_ASSOC_AP_MAX_NUM              2            /* STA��ͬʱ���������AP���� */
#define WLAN_JOIN_START_TIMEOUT            10000
#define WLAN_AUTH_TIMEOUT                  512
#ifdef _PRE_WLAN_FEATURE_PMF
#define WLAN_ASSOC_REJECT_TIMEOUT          2000
#endif
#define WLAN_ASSOC_TIMEOUT                 600
#define WLAN_SCAN_REQ_MAX_BSS              2        /* һ�ο���ɨ���BSS������PROBE REQ֡������Я����BSSID SSID���� */
#define WLAN_MAX_SCAN_BSS_PER_CH           8            /* һ���ŵ��¼�¼ɨ�赽�����BSS���� */
#define WLAN_SSID_MAX_LEN                  (32 + 1)     /* SSID��󳤶�, +1Ϊ\0Ԥ���ռ� */
#define WLAN_MESHID_MAX_LEN                (32 + 1)     /* Mesh ID��󳤶�, +1Ϊ\0Ԥ���ռ� */
#define WLAN_BG_SCAN_CNT_PER_CHANNEL       1            /* ����ɨ��ÿ�ŵ�ɨ����� */
#define WLAN_SCAN_REQ_CNT_PER_CHANNEL      1            /* ÿ���ŵ�ɨ�跢��probe req֡�Ĵ��� */
#define WLAN_MAX_TIME_PER_SCAN             4500         /* ɨ���Ĭ�ϵ����ִ��ʱ��ms����������ʱ���� */
#define WLAN_ACTIVE_SCAN_TIME              30           /* ����ɨ��ÿ���ŵ�ͣ��ʱ�� ʱ����������ŵ� */
#define WLAN_PASSIVE_SCAN_TIME             360          /* ����ɨ��ÿ���ŵ�ͣ��ʱ�� ʱ����������ŵ� */
#define WLAN_SCANRESULT_CLEAN_TIME         90000        /* ɨ�����ϻ�ʱ��90s */
#ifdef _PRE_WLAN_FEATURE_MESH
#define WLAN_MESH_CHL_SCAN_TIME            40           /* Meshָ���ŵ�ɨ�����ŵ���ͣ��ʱ�� */
#define WLAN_MESH_SCAN_TIME                60           /* Meshɨ��ÿ���ŵ�ͣ��ʱ��           ʱ����������ŵ� */
#endif
/*****************************************************************************
  4 �ȵ���������
*****************************************************************************/
#define WLAN_USER_ACTIVE_TRIGGER_TIME      1000         /* ��Ծ��ʱ���������� */
#define WLAN_USER_AGING_TRIGGER_TIME       5000         /* �ϻ���ʱ���������� */
#define WLAN_USER_ACTIVE_TO_INACTIVE_TIME  5000         /* �û��ɻ�Ծ���ǻ�Ծ��ת��ʱ�� ms */
#define WLAN_AP_USER_AGING_TIME            (300 * 1000) /* AP �û��ϻ�ʱ�� 300S */
#define WLAN_P2PGO_USER_AGING_TIME         (60 * 1000)  /* GO �û��ϻ�ʱ�� 60S */
#define WLAN_AP_KEEPALIVE_TRIGGER_TIME     (15 * 1000)  /* keepalive��ʱ���������� 15s */
#define WLAN_AP_KEEPALIVE_INTERVAL         (WLAN_AP_KEEPALIVE_TRIGGER_TIME * 4)   /* ap����keepalive null֡��� */
#define WLAN_GO_KEEPALIVE_INTERVAL         (25*1000)    /* P2P GO����keepalive null֡���  */
#define WLAN_STA_KEEPALIVE_TIME            (25*1000)    /* sta����keepalive null֡���, 25s */
#define WLAN_CL_KEEPALIVE_TIME             (20*1000)    /* CL����keepalive null֡���,����CL��GO pvb����,20s */
#ifdef _PRE_WLAN_FEATURE_MESH_ROM
#define WLAN_MESH_USER_AGING_TIME          (90 * 1000) /* Mesh �û��ϻ�ʱ�� 60S */
#define WLAN_MESH_KEEPALIVE_INTERVAL       (30 * 1000)    /* Mesh ����keepalive null֡���  */
#endif
/*****************************************************************************
  5 STA��������
*****************************************************************************/
#define WLAN_LINKLOSS_MIN_THRESHOLD        20           /* linkloss������С���ֵ */
#define WLAN_BEACON_INTVAL_MAX             3500         /* AP���beacon����, ms */
#define WLAN_BEACON_INTVAL_MIN             40           /* AP��Сbeacon����, ms */
#define WLAN_BEACON_INTVAL_DEFAULT         100          /* APĬ��beacon����, ms */
#define WLAN_BEACON_INTVAL_IDLE            1000         /* AP IDLE״̬��beacon intervalֵ */
/*****************************************************************************
  6 ����ģʽ����
*****************************************************************************/
#define WLAN_RTS_MIN                        1           /* RTS����������Сֵ */
#define WLAN_RTS_MAX                        2346        /* RTS�����������ֵ */
/*****************************************************************************
  7 ��Ƭ����
*****************************************************************************/
#define WLAN_FRAG_THRESHOLD_MIN             512       /* ��С��Ƭ���� */
#define WLAN_FRAG_THRESHOLD_MAX             2346      /* ����Ƭ���� */
/*****************************************************************************
  8 �������ʹ���
*****************************************************************************/
#define WLAN_MAX_SUPP_RATES                 12          /* ��¼ɨ�赽��ap֧�ֵ����������� */
#define WLAN_TX_RATE_MAX_NUM                4           /* ÿ���û�֧�ֵ�������ʼ����� */
/*****************************************************************************
  9 �����빦��
*****************************************************************************/
/* 2.4G��Ŀǰ���֧��2����������Ϣ ��wal_regdb.c */
#define WLAN_MAX_RC_NUM                      2          /* ������������ ��JPΪ2 */
#define WLAN_MAX_CHANNEL_NUM                 14         /* wifi 5G 2.4Gȫ���ŵ����� */

/*****************************************************************************
  10 WMM����
*****************************************************************************/
#define WLAN_QEDCA_TABLE_CWMIN_MIN           1
#define WLAN_QEDCA_TABLE_CWMIN_MAX           10
#define WLAN_QEDCA_TABLE_CWMAX_MIN           1
#define WLAN_QEDCA_TABLE_CWMAX_MAX           10
#define WLAN_QEDCA_TABLE_AIFSN_MIN           2
#define WLAN_QEDCA_TABLE_AIFSN_MAX           15
#define WLAN_QEDCA_TABLE_TXOP_LIMIT_MIN      1
#define WLAN_QEDCA_TABLE_TXOP_LIMIT_MAX      65535
#define WLAN_QEDCA_TABLE_MSDU_LIFETIME_MAX   500
/*****************************************************************************
  11 Э�����STA�๦��
*****************************************************************************/
#define WLAN_DTIM_DEFAULT                    3          /* default DTIM period */
#define WLAN_DTIM_PERIOD_MAX                 255        /* ����DTIM���� */
#define WLAN_DTIM_PERIOD_MIN                 1          /* ��С��DTIM���� */
/*****************************************************************************
  12 ��ȫЭ������spec
*****************************************************************************/
#define WLAN_NUM_TK                          4
#define WLAN_NUM_IGTK                        2
#define WLAN_MAX_IGTK_KEY_INDEX              5
#define WLAN_MAX_WEP_KEY_COUNT               4
/*****************************************************************************
  13 PMF STA����
*****************************************************************************/
#define WLAN_SA_QUERY_RETRY_TIME             (WLAN_AP_USER_AGING_TIME / 3)   /* SA Query���ʱ��,�ϻ�ʱ�������֮һ */
#define WLAN_SA_QUERY_MAXIMUM_TIME           (WLAN_SA_QUERY_RETRY_TIME * 3)  /* SA Query��ʱʱ��,С���ϻ�ʱ�� */
/*****************************************************************************
  14 WPA����
*****************************************************************************/
#define HAL_CE_LUT_UPDATE_TIMEOUT            4           /* Ӳ��MAC ���ȴ�32us�� ����ȴ�40us */
/*****************************************************************************
  15 ��ȷ�Ϲ���
*****************************************************************************/
#define WLAN_ADDBA_TIMEOUT                   500
#define WLAN_MAX_RX_BA                       16          /* ֧�ֵĽ���ba���������� mac lut = 16 */
#define WLAN_MAX_TX_BA                       8           /* ֧�ֵķ���ba���������� */
/*****************************************************************************
  16 AMPDU����
*****************************************************************************/
#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
#define WLAN_AMPDU_RX_BUFFER_SIZE            32         /* AMPDU���ն˽��ջ�������buffer size�Ĵ�С */
#define WLAN_AMPDU_RX_BA_LUT_WSIZE           32         /* AMPDU���ն�������дBA RX LUT���win size,
                                                           Ҫ����ڵ���WLAN_AMPDU_RX_BUFFER_SIZE */
#else       /* 31H IOT������PKT Bֻ��8����֡����, rx ampdu�ۺ�����Ϊ4�� �������������ϴ� */
#define WLAN_AMPDU_RX_BUFFER_SIZE            4          /* AMPDU���ն˽��ջ�������buffer size�Ĵ�С */
#define WLAN_AMPDU_RX_BA_LUT_WSIZE           4          /* AMPDU���ն�������дBA RX LUT���win size,
                                                           Ҫ����ڵ���WLAN_AMPDU_RX_BUFFER_SIZE */
#endif
#define WLAN_AMPDU_TX_MAX_NUM                32         /* AMPDU���Ͷ����ۺ���MPDU���� */
#define WLAN_AMPDU_TX_MAX_BUF_SIZE           64         /* ���Ͷ˵�buffer size */
#define WLAN_AMPDU_TX_SCHD_STRATEGY          2          /* ���ۺ�����Ϊ���ڴ�С��һ�� */
#define HAL_MAX_BA_LUT_SIZE                  16         /* 31H mac 16��lut�� */
/*****************************************************************************
  17 AMSDU����
*****************************************************************************/
#define AMSDU_ENABLE_ALL_TID                 0xFF
#define WLAN_MSDU_MAX_LEN                    128        /* amsdu����msdu����󳤶� */
#define WLAN_AMSDU_FRAME_MAX_LEN             7935       /* amsdu��󳤶ȣ�������һ��buffer���� */
#define WLAN_DSCR_SUBTABEL_MAX_NUM           1
/*****************************************************************************
  18 С���Ż�
*****************************************************************************/
#define WLAN_SMALL_RX_MAX_BUFFS              12        /* С�����ݽ��������������������������� */
#define WLAN_NORMAL_RX_MAX_BUFFS             8         /* ��ͨ���������������� */
#define WLAN_HIGH_RX_MAX_BUFFS               12        /* �����ȼ����������������� */
#define WLAN_SMALL_RX_MAX_BUFFS_PATCH        16        /* С�����ݽ��������������������������� */
#define WLAN_NORMAL_RX_MAX_BUFFS_PATCH       12        /* ��ͨ���������������� */
#define WLAN_HIGH_RX_MAX_BUFFS_PATCH         12        /* �����ȼ����������������� */
#define WLAN_NORMAL_RX_MAX_RX_OPT_BUFFS      8          /* ��ͨ���ȼ��������Ż���� */
/*****************************************************************************
  19 TPC����
*****************************************************************************/
#define WLAN_MAX_TXPOWER                     30         /* ����书�ʣ���λdBm */
/*****************************************************************************
  20 DBAC����
*****************************************************************************/
/* ��ٶ��и�������������һ���ŵ�ʱ����ԭ�ŵ��Ϸŵ�Ӳ���������֡�������� */
#define WLAN_TX_FAKE_QUEUE_NUM               3
#define WLAN_TX_FAKE_QUEUE_BGSCAN_ID         2
#define WLAN_FCS_PROT_MAX_FRAME_LEN          24
#define WLAN_FCS_NOA_MAX_FRAME_LEN           32         /* ����NOA����֡��,����FCS */
/*****************************************************************************
  21 оƬ������
*****************************************************************************/
#define WLAN_RF_CHANNEL_NUMS                 1          /* ˫ͨ�� */
#define WLAN_TX_CHAIN_DOUBLE                 3          /* ˫ͨ������ 11 */
#define WLAN_TX_CHAIN_ZERO                   1          /* ͨ��0 ���� 01 */
#define WLAN_TX_CHAIN_ONE                    2          /* ͨ��1 ���� 10 */
/*****************************************************************************
  22 STA AP���
*****************************************************************************/
#define WLAN_OHTER_BSS_BCAST_ID              14         /* ��������BSS�Ĺ㲥֡ID */
#define WLAN_OTHER_BSS_OTHER_ID              15         /* ��������BSS������֡(�鲥������) */
#define WLAN_USER_NUM_SPEC                   8          /* 31H����û��������8�� */
#define WLAN_MESHAP_ASSOC_USER_MAX_NUM       6          /* MESHAP����������û�����:6 */
#define WLAN_SOFTAP_ASSOC_USER_MAX_NUM       4          /* AP����������û�����:4 */
#define WLAN_ACTIVE_USER_MAX_NUM             7          /* ��Ծ�û�,DBAC����user֮��:MAX=7+1, IOT=6+1 */
#define WLAN_ASSOC_USER_IDX_BMAP_LEN         1          /* �����û�����λͼ���� 8 >> 3 */
#define WLAN_ACTIVE_USER_IDX_BMAP_LEN        1          /* ��Ծ�û�����λͼ���� 8 >> 3 */
#define WLAN_AP_NUM_PER_DEVICE               1          /* AP�Ĺ�� 1131H: 1��AP */
#define WLAN_STA_NUM_PER_DEVICE              2          /* STA�Ĺ�� 1131H: 2��STA */
#define WLAN_CFG_VAP_NUM_PER_DEVICE          1          /* ����VAP���� 1��оƬ1�� */
#define WLAN_SERVICE_VAP_NUM_PER_DEVICE  (WLAN_AP_NUM_PER_DEVICE + WLAN_STA_NUM_PER_DEVICE)  /* AP+STA */
#define WLAN_VAP_NUM_PER_DEVICE    (WLAN_AP_NUM_PER_DEVICE + WLAN_STA_NUM_PER_DEVICE + WLAN_CFG_VAP_NUM_PER_DEVICE)
#define WLAN_CHIP_NUM_PER_BOARD              1          /* ÿ��board֧��chip�����������������ᳬ��8�� */
#define WLAN_DEVICE_NUM_PER_CHIP             1          /* ÿ��chip֧��device�����������������ᳬ��8�� */
#define WLAN_DEVICE_NUM_PER_BOARD  (WLAN_CHIP_NUM_PER_BOARD * WLAN_DEVICE_NUM_PER_CHIP)  /* ������device���� */
#define WLAN_VAP_NUM_PER_BOARD     (WLAN_DEVICE_NUM_PER_BOARD * WLAN_VAP_NUM_PER_DEVICE) /* ������vap���� */
#define WLAN_SERVICE_VAP_START_ID            1          /* ��оƬ�£�ÿ��board��ҵ��vap id��1��ʼ */
#define WLAN_CFG_VAP_ID                      0          /* ��device�� ����vap��IDΪ0 */
#define WLAN_CFG_VAP_NAME                    "Hisilicon0"   /* ��device�� ����vap������ */
#define WLAN_ASSOC_MAX_ID   (WLAN_ACTIVE_USER_MAX_NUM + WLAN_SERVICE_VAP_NUM_PER_DEVICE)  /* ASSOC_ID���ֵ */


/*****************************************************************************
  23 �ͳɱ�Լ��
*****************************************************************************/
#define WLAN_TID_FOR_DATA                    0          /* Ĭ�ϵ���������ҵ���TID */
#define WLAN_RX_QUEUE_NUM                    3          /* ���ն��еĸ��� ��HAL_RX_DSCR_QUEUE_ID_BUTT��� */
#define WLAN_TX_QUEUE_NUM                    5          /* ���Ͷ��еĸ��� */
#define WLAN_RX_DSCR_LIST_NUM                2          /* �洢Ӳ�������ϱ���������������Ŀ(ping pongʹ��) */
#define WLAN_RX_ISR_MAX_COUNT                30         /* ��������ж������� */
#define WLAN_DOWM_PART_RX_TRACK_MEM          200
#define WLAN_DEBUG_RX_DSCR_LINE              (12 + 2)   /* ��������������ɼ�Ϊ��14�У����ڴ�ʱ����������� */
#define WLAN_RX_FRAME_MAX_LEN                8000       /* ���ջ��������˳���(������ֵ��Ӳ�����䶪��) */
/*****************************************************************************
  24 RX��������̬����
*****************************************************************************/
#define WLAN_PKT_MEM_PKT_OPT_LIMIT           2000
#define WLAN_PKT_MEM_PKT_RESET_LIMIT         500
#define WLAN_PKT_MEM_OPT_TIME_MS             1000
/*****************************************************************************
  25 P2P����
*****************************************************************************/
#ifdef _PRE_WLAN_FEATURE_P2P
#define WLAN_MAX_SERVICE_P2P_DEV_NUM         1          /* P2P DEV���� =1 */
#define WLAN_MAX_SERVICE_P2P_GOCLIENT_NUM    1          /* P2P GO/GC���� =1 */
#endif
/*****************************************************************************
  27 RSSI
*****************************************************************************/
#define WLAN_NEAR_DISTANCE_RSSI            (-35)        /* Ĭ�Ͻ������ź�����-35dBm */
#define WLAN_CLOSE_DISTANCE_RSSI           (-25)        /* ����ǰ�����ж�����-25dBm */
#define WLAN_FAR_DISTANCE_RSSI             (-73)        /* Ĭ��Զ�����ź�����-73dBm */
#define WLAN_NORMAL_DISTANCE_RSSI_UP       (-42)        /* �ź�ǿ��С��-42dBmʱ������Ϊ�ǳ������� */
#define WLAN_NORMAL_DISTANCE_RSSI_DOWN     (-66)        /* �ź�ǿ�ȴ���-66dBmʱ������Ϊ�Ƿǳ�Զ���� */
#define WLAN_NEAR_DISTANCE_IMPROVE_RSSI_UP (-40)        /* improve 1*1������,Ҫ��������ж�������Ϊ-44dBm */
#define WLAN_NEAR_DISTANCE_IMPROVE_RSSI_DOWN    (-48)   /* improve 1*1������,Ҫ��������ж�������Ϊ-50dBm */
/*****************************************************************************
  28 COEX FEATURE
*****************************************************************************/
#define BTCOEX_RSSI_THRESHOLD               (WLAN_FAR_DISTANCE_RSSI)
#define BTCOEX_RX_WINDOW_SIZE_INDEX_0       0
#define BTCOEX_RX_WINDOW_SIZE_INDEX_1       1
#define BTCOEX_RX_WINDOW_SIZE_INDEX_2       2
#define BTCOEX_RX_WINDOW_SIZE_INDEX_3       3
#define BTCOEX_RX_WINDOW_SIZE_INDEX_MAX     4
#define BTCOEX_MAC_HDR                      32
#define BT_POSTPREEMPT_MAX_TIMES            1
#define BT_PREEMPT_MAX_TIMES                1
#define BT_POSTPREEMPT_TIMEOUT_US           150
#define BT_ABORT_RETRY_TIMES_MAX            10
#define BT_PREEMPT_TIMEOUT_US               150
#define BLE_PREEMPT_TIMEOUT_US              10
#define BTCOEX_BT_DEFAULT_DURATION          0xFF

#define BT_WLAN_COEX_UNAVAIL_PAYLOAD_THRES  8
#define BT_WLAN_COEX_SMALL_PKT_THRES        200
#define BT_WLAN_COEX_SMALL_FIFO_THRES       1023
#define BTCOEX_OCCUPY_DATA_TIMEOUT_MS       60
#define BTCOEX_OCCUPY_MGMT_TIMEOUT_MS       10
#define COEX_LINKLOSS_OCCUP_PERIOD_MS       20
#define BTCOEX_ARP_PROTECT_TIMEOUT_MS       1000
#define BTCOEX_DHCP_STEP1_PROTECT_TIMEOUT_MS 6000
#define BTCOEX_DHCP_STEP3_PROTECT_TIMEOUT_MS 8000
#define BTCOEX_DHCP_EAPOL_PROTECT_TIMEOUT_MS 3000

/*****************************************************************************
  29 WiFi�ؼ���Ϣ���
*****************************************************************************/
#define WLAN_MAX_MAC_HDR_LEN                36            /* ����macͷ���� oal_mem.h�������øú� */
#define WLAN_MIN_MAC_HDR_LEN                10            /* ack��cts��֡ͷ����Ϊ10 */
#define WLAN_MGMT_MAC_HDR_LEN               24            /* ����֡��MAC֡ͷ���� */
#define WLAN_MEM_MAX_SUBPOOL_NUM            6             /* �ڴ����������ڴ�ظ��� */
#define WLAN_MEM_MAX_USERS_NUM              4             /* ����ͬһ���ڴ������û��� */
#define WLAN_MAC_ADDR_LEN                   6             /* MAC��ַ���Ⱥ� */
#define WLAN_MAC_ADDR_BYTE_LEN              17            /* MAC��ַռ���ַ����� */
#define WLAN_TID_MPDU_NUM_BIT               9
#define WLAN_TID_MPDU_NUM_LIMIT             (1 << WLAN_TID_MPDU_NUM_BIT)
/*****************************************************************************
  31 �������ڴ��������Ϣ
*****************************************************************************/
#define WLAN_MEM_SHARE_DSCR_SUBPOOL_CNT    2               /* �����������ڴ���ӳظ��� */
/* hal_rx_dscr_stru(����4) + hi1131_rx_buffer_addr_stru(����4) - 4 + hi1131_rx_status_dscr_stru +
   hi1131_rx_debug_dscr_stru */
#define WLAN_MEM_RX_DSCR_SIZE              48              /* �����������ṹ���С */
/* �������������� */
#define WLAN_MEM_RX_DSCR_CNT               (WLAN_SMALL_RX_MAX_BUFFS + WLAN_NORMAL_RX_MAX_BUFFS + WLAN_HIGH_RX_MAX_BUFFS)
#define WLAN_MEM_RX_DSCR_CNT_PATCH         (WLAN_SMALL_RX_MAX_BUFFS_PATCH + WLAN_NORMAL_RX_MAX_BUFFS_PATCH \
                                            + WLAN_HIGH_RX_MAX_BUFFS_PATCH)

/* hal_tx_dscr_stru(����4) + hi1131_tx_ctrl_dscr_one_stru(����4) - 4 + hi1131_tx_ctrl_dscr_two_stru +
   hi1131_tx_ctrl_dscr_three_stru */
#define WLAN_MEM_TX_DSCR_SIZE              76              /* �����������ṹ���С hal_tx_dscr_stru��4�ֽڹ��� */
#define WLAN_MEM_TX_DSCR_CNT               14              /* ���������� netbuff����48-����32-netbuffԣ��2 */
#define WLAN_MEM_TX_DSCR_CNT_PATCH         58              /* ���������� netbuff����48-����32-netbuffԣ��2 */
/*****************************************************************************
  34 �����ڴ��������Ϣ
*****************************************************************************/
#define WLAN_MEM_LOCAL_SUBPOOL_CNT          6               /* ���ر����ڴ���ӳظ��� */
#define WLAN_MEM_LOCAL_SIZE1                32
#define WLAN_MEM_LOCAL_SIZE2                64
#define WLAN_MEM_LOCAL_SIZE3                128
#define WLAN_MEM_LOCAL_SIZE4                256
#define WLAN_MEM_LOCAL_SIZE5                600
#define WLAN_MEM_LOCAL_SIZE6                1440            /* �Զ������㷨ʹ�� 956 * 8 users */

/*****************************************************************************
  35 netbuff�ڴ��������Ϣ
*****************************************************************************/
#define WLAN_SHORT_NETBUF_SIZE              256     /* ��֡netbufpayload���� */
#define WLAN_MGMT_NETBUF_SIZE               640     /* ����֡netbufpayload���� */
/* ��֡netbufpayload���� 1500+36(HDR)+4(FCS)+20(����ʧ��20��������Ϣ)+8(SNAP LLC) */
#define WLAN_LARGE_PAYLOAD_SIZE             1500    /* �����͵����֡���ݳ��� */
#define WLAN_LARGE_NETBUF_SIZE              1600    /* (WLAN_LARGE_PAYLOAD_SIZE + 100) */
/* netbuf���֡����֡ͷ + payload */
#define WLAN_MAX_NETBUF_SIZE                (WLAN_LARGE_NETBUF_SIZE + WLAN_MAX_MAC_HDR_LEN)
#define WLAN_MEM_NETBUF_ALIGN               4       /* netbuf���� */
/*****************************************************************************
  36 �¼��ṹ���ڴ��
*****************************************************************************/
#define WLAN_MEM_EVENT_SUBPOOL_CNT          2               /* �����¼��ڴ���ӳظ��� */
#define WLAN_MEM_EVENT_SIZE1                64              /* ע��: �¼��ڴ泤�� */
#define WLAN_MEM_EVENT_SIZE2                384             /* ע��: �¼��ڴ泤�� */
#define WLAN_MEM_EVENT_MULTI_USER_CNT1      96              /* ���û����¼����ӳ�1���� */
#define WLAN_MEM_EVENT_CNT2                 6               /* ���û����¼����ӳ�2���� */
#define WLAN_MEM_EVENT_MULTI_USER_CNT2      8               /* ���û����¼����ӳ�2���� */
#define WLAN_MEM_EVENT_CNT1                 40              /* ���û����¼����ӳ�1���� */
#define WLAN_WPS_IE_MAX_SIZE                (WLAN_MEM_EVENT_SIZE2 - 32)   /* 32��ʾ�¼�����ռ�õĿռ� */
/*****************************************************************************
  37 MIB�ڴ��
*****************************************************************************/
#define WLAN_MEM_MIB_SUBPOOL_CNT            1               /* ����MIB�ڴ���ӳظ��� */
#define WLAN_MEM_MIB_SIZE                   476             /* ��ǰ(wlan_mib_ieee802dot11_stru)=444+4 Ԥ��28bytes */
/*****************************************************************************
  38 TCP ACK�Ż�
*****************************************************************************/
#define DEFAULT_TX_TCP_ACK_THRESHOLD        1       /* ��������ack ������ */
#define DEFAULT_RX_TCP_ACK_THRESHOLD        1       /* ��������ack ������ */
/*****************************************************************************
  39 frw��ص�spec
*****************************************************************************/
/******************************************************************************
    �¼�����������Ϣ��
    ע��: ÿ�������������ɵ�����¼�����������2����������
*******************************************************************************/
#define FRW_EVENT_MAX_NUM_QUEUES    (FRW_EVENT_TYPE_BUTT * WLAN_VAP_NUM_PER_BOARD)
/* ����VAP�¼��������� */
#define WLAN_FRW_EVENT_CFG_TABLE_CFG_VAP \
         /* �¼�����                 ����Ȩ��   ��������¼�����   ���е��Ȳ��� */  \
/* FRW_EVENT_TYPE_HIGH_PRIO        */    { 1,          32,              0, 0}, \
/* FRW_EVENT_TYPE_HOST_CRX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_HOST_DRX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_HOST_CTX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_DMAC_TO_HMAC_CFG */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_CRX         */    { 1,          32,              0, 0}, \
/* FRW_EVENT_TYPE_WLAN_DRX         */    { 1,          64,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_CTX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_DTX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_TX_COMP     */    { 1,          32,              1, 0}, \
/* FRW_EVENT_TYPE_TBTT             */    { 1,           0,              1, 0}, \
/* FRW_EVENT_TYPE_TIMEOUT          */    { 1,          32,              1, 0}, \
/* FRW_EVENT_TYPE_DMAC_MISC        */    { 1,          32,              0, 0}, \
/* FRW_EVENT_TYPE_HCC              */    { 1,          32,              1, 0},

/* ҵ��VAP�¼��������� */
/* FRW_EVENT_TYPE_HIGH_PRIO             HAL��ֻͨ������VAP�ַ��¼�,ҵ��VAP������0
   FRW_EVENT_TYPE_WLAN_TX_COMP          HAL��ֻͨ������VAP�ַ��¼�,ҵ��VAP������0
   FRW_EVENT_TYPE_TIMEOUT               FRW��ֻͨ������VAP�ַ��¼�,ҵ��VAP������0
   FRW_EVENT_TYPE_TBTT                  ����VAPû��TBTT�ж�
*/
#define WLAN_FRW_EVENT_CFG_TABLE_SERVIC_VAP \
    /* �¼�����       ����Ȩ��   �����������ɵ�����¼�����   �����������Ȳ��� */  \
         /* �¼�����                 ����Ȩ��   ��������¼�����   ���е��Ȳ��� */  \
/* FRW_EVENT_TYPE_HIGH_PRIO        */    { 1,          0 ,              0, 0}, \
/* FRW_EVENT_TYPE_HOST_CRX         */    { 1,          32,              1, 0}, \
/* FRW_EVENT_TYPE_HOST_DRX         */    { 1,          32,              1, 0}, \
/* FRW_EVENT_TYPE_HOST_CTX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_DMAC_TO_HMAC_CFG */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_CRX         */    { 1,          64,              0, 0}, \
/* FRW_EVENT_TYPE_WLAN_DRX         */    { 1,          64,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_CTX         */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_DTX         */    { 1,          32,              1, 0}, \
/* FRW_EVENT_TYPE_WLAN_TX_COMP     */    { 1,          0 ,              1, 0}, \
/* FRW_EVENT_TYPE_TBTT             */    { 1,          16,              1, 0}, \
/* FRW_EVENT_TYPE_TIMEOUT          */    { 1,          0 ,              1, 0}, \
/* DMAC FRW_EVENT_TYPE_DMAC_MISC   */    { 1,          32,              0, 0}, \
/* FRW_EVENT_TYPE_HCC              */    { 1,          32,              1, 0},

#define WLAN_FRW_EVENT_CFG_TABLE \
{ \
    WLAN_FRW_EVENT_CFG_TABLE_CFG_VAP \
    WLAN_FRW_EVENT_CFG_TABLE_SERVIC_VAP \
    WLAN_FRW_EVENT_CFG_TABLE_SERVIC_VAP \
    WLAN_FRW_EVENT_CFG_TABLE_SERVIC_VAP \
}
/*****************************************************************************
  40 ����OS����
*****************************************************************************/
#define WLAN_WPA_KEY_LEN                    32          /* WPA ��Կ���� */
#define WLAN_WPA_SEQ_LEN                    16          /* WPA ��ų��� */

/* ����֡������ */
typedef enum {
    WLAN_ASSOC_REQ              = 0,    /* 0000 */
    WLAN_ASSOC_RSP              = 1,    /* 0001 */
    WLAN_REASSOC_REQ            = 2,    /* 0010 */
    WLAN_REASSOC_RSP            = 3,    /* 0011 */
    WLAN_PROBE_REQ              = 4,    /* 0100 */
    WLAN_PROBE_RSP              = 5,    /* 0101 */
    WLAN_TIMING_AD              = 6,    /* 0110 */
    WLAN_MGMT_SUBTYPE_RESV1     = 7,    /* 0111 */
    WLAN_BEACON                 = 8,    /* 1000 */
    WLAN_ATIM                   = 9,    /* 1001 */
    WLAN_DISASOC                = 10,   /* 1010 */
    WLAN_AUTH                   = 11,   /* 1011 */
    WLAN_DEAUTH                 = 12,   /* 1100 */
    WLAN_ACTION                 = 13,   /* 1101 */
    WLAN_ACTION_NO_ACK          = 14,   /* 1110 */
    WLAN_MGMT_SUBTYPE_RESV2     = 15,   /* 1111 */

    WLAN_MGMT_SUBTYPE_BUTT      = 16,   /* һ��16�ֹ���֡������ */
}wlan_frame_mgmt_subtype_enum;

typedef enum {
    WLAN_WME_AC_BE = 0,    /* best effort */
    WLAN_WME_AC_BK = 1,    /* background */
    WLAN_WME_AC_VI = 2,    /* video */
    WLAN_WME_AC_VO = 3,    /* voice */

    WLAN_WME_AC_BUTT = 4,
    WLAN_WME_AC_MGMT = WLAN_WME_AC_BUTT   /* ����AC��Э��û��,��ӦӲ�������ȼ����� */
}wlan_wme_ac_type_enum;
typedef hi_u8 wlan_wme_ac_type_enum_uint8;

/* TID������ */
typedef enum {
    WLAN_TIDNO_BEST_EFFORT              = 0, /* BEҵ�� */
    WLAN_TIDNO_BACKGROUND               = 1, /* BKҵ�� */
    WLAN_TIDNO_UAPSD                    = 2, /* U-APSD */
    WLAN_TIDNO_ANT_TRAINING_LOW_PRIO    = 3, /* �������ߵ����ȼ�ѵ��֡ */
    WLAN_TIDNO_ANT_TRAINING_HIGH_PRIO   = 4, /* �������߸����ȼ�ѵ��֡ */
    WLAN_TIDNO_VIDEO                    = 5, /* VIҵ�� */
    WLAN_TIDNO_VOICE                    = 6, /* VOҵ�� */
    WLAN_TIDNO_BCAST                    = 7, /* �㲥�û��Ĺ㲥�����鲥���� */

    WLAN_TIDNO_BUTT
}wlan_tidno_enum;
typedef hi_u8 wlan_tidno_enum_uint8;

enum wlan_serv_id {
    WLAN_STA0_ID = 0x00,
    WLAN_STA1_ID = 0x01,
    WLAN_STA2_ID = 0x02,
    WLAN_AP0_ID = 0x03,
    WLAN_ID_NUM = 0xff /* ���ڷǹ���״̬���ʼ״̬��ƽ̨ͶƱ������˳��͹��� */
};
#define WLAN_TID_MAX_NUM                WLAN_TIDNO_BUTT     /* TID����Ϊ8 */

/*****************************************************************************
  41 Mesh���
*****************************************************************************/
#define WLAN_MESH_PASSIVE_SCAN_PERIOD   500     /* mesh�ڵ������Խ��뱻��ɨ���ʱ�� */
#define WLAN_MESH_BEACON_PRIO_MAX       255     /* mesh�ڵ�beacon prio�����ֵ */
#define WLAN_MESH_BEACON_PRIO_MIN       0       /* mesh�ڵ�beacon prio����Сֵ */
#define WLAN_MESH_BEACON_TIMEOUT_VAL    20      /* Mesh�ڵ�Beacon���ͳ�ʱʱ��(ms) */
#define WLAN_MESH_6LO_PKT_LIMIT         500     /* Mesh�ڵ�6lo��ͷѹ��֡���ж� */

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* #ifndef __WLAN_SPEC_1131_H__ */
