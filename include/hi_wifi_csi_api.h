/*
 * @file hi_wifi_csi_api.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Hi wifi CSI API.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/**
 * @defgroup hi_wifi WiFi API
 */
/**
 * @defgroup hi_wifi_csi CSI
 * @ingroup hi_wifi
 */

#ifndef __HI_WIFI_CSI_API_H__
#define __HI_WIFI_CSI_API_H__

#include "hi_wifi_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @ingroup hi_wifi_csi
 *
 * Sample period of CSI.CNcomment:CSI �ϱ���������CNend
 */
typedef enum {
    CSI_REPORT_PERIOD_EVERY_FRAME = 0,
    CSI_REPORT_PERIOD_256US = 1,
    CSI_REPORT_PERIOD_512US = 2,
    CSI_REPORT_PERIOD_1024US = 3,
    CSI_REPORT_PERIOD_2048US = 4,
    CSI_REPORT_PERIOD_4096US = 5,
    CSI_REPORT_PERIOD_8192US = 6,
    CSI_REPORT_PERIOD_16384US = 7,
    CSI_REPORT_PERIOD_32768US = 8,
    CSI_REPORT_PERIOD_65536US = 9,
    CSI_REPORT_PERIOD_131072US = 10,
    CSI_REPORT_PERIOD_262144US = 11,
    CSI_REPORT_PERIOD_524288US = 12,
    CSI_REPORT_PERIOD_1048576US = 13,
    CSI_REPORT_PERIOD_2097152US = 14,
    CSI_REPORT_PERIOD_4194304US = 15,
    CSI_REPORT_PERIOD_BUTT
} hi_wifi_csi_period_enum;

/**
 * @ingroup hi_wifi_csi
 *
 * Frame type of CSI report.CNcomment:CSI �ϱ�����֡����CNend
 */
typedef enum {
    CSI_FRAME_TYPE_DATA = 1,        /**< data. CNcomment: ����֡.CNend */
    CSI_FRAME_TYPE_MGMT = 2,        /**< management. CNcomment: ����֡.CNend */
    CSI_FRAME_TYPE_MGMT_DATA = 3,   /**< management and data. CNcomment: ����֡������֡.CNend */
    CSI_FRAME_TYPE_CTRL = 4,        /**< control. CNcomment: ����֡.CNend */
    CSI_FRAME_TYPE_CTRL_DATA = 5,   /**< control and data. CNcomment: ����֡������֡.CNend */
    CSI_FRAME_TYPE_CTRL_MGMT = 6,   /**< control adn management. CNcomment: ����֡�͹���֡.CNend */
    CSI_FRAME_TYPE_ALL  = 7,        /**< control and data and management. CNcomment: ����֡������֡�͹���֡.CNend */
    CSI_FRAME_TYPE_BUTT
} hi_wifi_csi_frame_type_enum;

/**
 * @ingroup hi_wifi_csi
 *
 * Struct of CSI reporting config.CNcomment:CSI �ϱ���������CNend
 */
typedef struct {
    unsigned char mac[HI_WIFI_MAC_LEN];     /**< Mac address. CNcomment: MAC��ַ.CNend */
    hi_wifi_csi_frame_type_enum frame_type; /**< Report frame type. CNcomment: �ϱ�֡����.CNend */
    hi_wifi_csi_period_enum sample_period;  /**< Sample period. CNcomment: �ŵ���������.CNend */
} hi_wifi_csi_entry;

/**
* @ingroup  hi_wifi_csi
* @brief    CSI data report callback.
*
* @par Description:
*           user's callback to handle csi report data.
            CNcomment:�û�ע��Ļص����������ڴ���CSI�ϱ������ݡ�CNend
*
* @attention  NULL
* @param  csi_data        [IN]     Type  #unsigned char *, 4 bytes extend timestamp + 184 bytes 64bit big endian data.
                                         CNcomment:4�ֽ���չʱ���+184�ֽ�64λС�˴洢��ʽ��CSI���ݡ�CNend
* @param  len             [IN]     Type  #int, data length. CNcomment:���ݳ���,�̶�Ϊ188�ֽڡ�CNend
*
* @retval void
* @par Dependency:
*            @li hi_wifi_csi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
typedef void (*hi_wifi_csi_data_cb)(unsigned char *csi_data, int len);

/**
* @ingroup  hi_wifi_csi
* @brief    Config CSI.
*
* @par Description:
*           Config CSI basic parameters, config csi will colse low power, stop csi can open low power again.
            CNcomment:����CSI�����ϱ����ܵĻ������������ú��رյ͹��ģ���ʱ������CSI��ͨ��stop������͹��ġ�CNend
*
* @attention  NULL
* @param  ifname               [IN]     Type  #char *,interface which enable CSI, wlan0 or ap0.
* @param  report_min_interval  [IN]     Type  #unsigned int, report period: minimum 50 ms.
                                              CNcomment:CSI�����ϱ���С�������С����50ms��С��50msĬ��Ϊ50ms��CNend
* @param  entry_list           [IN]     Type  #hi_wifi_csi_entry *, configuration struct.
* @param  entry_num            [IN]     Type  #int, list number.CNcomment:entry_list�������������������������Ϊ6��CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_csi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_csi_set_config(const char *ifname, unsigned int report_min_interval,
                           const hi_wifi_csi_entry *entry_list, int entry_num);

/**
* @ingroup  hi_wifi_csi
* @brief    Register report callback of CSI.CNcomment:ע��CSI�����ϱ��ص�������CNend
*
* @par Description:
*           CSI data report interface.CNcomment:���û�ע��ص������������ϱ�CSI���ݡ�CNend
*
* @attention  NULL
* @param  data_cb         [IN]     Type  #hi_wifi_csi_data_cb, callback pointer.
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_csi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_csi_register_data_recv_func(hi_wifi_csi_data_cb data_cb);

/**
* @ingroup  hi_wifi_csi
* @brief    Start CSI.
*
* @par Description:
*           Start CSI.
*
* @attention  NULL
* @param  NULL
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_csi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_csi_start(void);

/**
* @ingroup  hi_wifi_csi
* @brief    Close CSI.
*
* @par Description:
*           Close CSI.
*
* @attention  NULL
* @param  NULL
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_csi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_csi_stop(void);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_wifi_csi_api.h */

