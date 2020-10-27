/**
* @file hi_wifi_mfg_test_if.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: header file for wifi manufacturing test interference.CNcomment:������WiFi ����ӿ�ͷ�ļ�CNend\n
* Author: Hisilicon \n
* Create: 2019-01-03
*/

/**
 * @defgroup hi_wifi_mfg_test_if
 */
/**
 * @defgroup hi_wifi_mfg_test_if Basic Settings
 * @ingroup hi_wifi
 */

#ifndef __HI_WIFI_MFG_TEST_IF_H__
#define __HI_WIFI_MFG_TEST_IF_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    HISI_AT_AL_TX,
    HISI_AT_AL_RX,
    HISI_AT_RX_INFO,
    HISI_AT_SET_COUNTRY,
    HISI_AT_GET_COUNTRY,
    HISI_AT_SET_WLAN0_BW,
    HISI_AT_SET_AP0_BW,
    HISI_AT_SET_MESH0_BW,
    HISI_AT_GET_WLAN0_MESHINFO,
    HISI_AT_GET_MESH0_MESHINFO,
    HISI_AT_SET_TPC,
    HISI_AT_SET_TRC,
    HISI_AT_SET_RATE,

    HISI_AT_TYPE_BUTT
}hisi_at_type_enum;

#if 1  //#ifdef _PRE_WLAN_FEATURE_MFG_TEST
/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  Set cal band power.CNcomment:���ø�bandƽ�����ʲ���CNend
*
* @par Description:
*           Set cal band power.CNcomment:���ø�bandƽ�����ʲ���CNend
*
* @attention  NULL
* @param  band_num         [IN]     Type  #unsigned char band num.CNcomment:band���CNend
* @param  offset           [IN]     Type  #int power offset.CNcomment:���ʲ���ֵCNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_set_cal_band_power(unsigned char band_num,  int offset);

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  Set cal rate power.CNcomment:�Բ�ͬЭ�鳡�����������ʷֱ������ʲ���CNend
*
* @par Description:
*           Set cal band power.CNcomment:�Բ�ͬЭ�鳡�����������ʷֱ������ʲ���CNend
*
* @attention  NULL
* @param  protol         [IN]     Type  #unsigned char protol.CNcomment:Э�����CNend
* @param  rate           [IN]     Type  #unsigned char rate.CNcomment:����CNend
* @param  val            [IN]     Type  #int power val.CNcomment:����ֵCNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_set_cal_rate_power(unsigned char protol, unsigned char rate, int val);

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  Set cal freq.CNcomment:���г���Ƶƫ���ʲ���CNend
*
* @par Description:
*           Set cal freq.CNcomment:���г���Ƶƫ���ʲ���CNend
*
* @attention  NULL
* @param  freq_offset    [IN]     Type  #int freq offset.CNcomment:����ֵCNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_set_cal_freq(int freq_offset);

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  set macefuse mac addr.CNcomment:��MAC��ַд��efuse��nvCNend
*
* @par Description:
*           set macefuse mac addr.CNcomment:��MAC��ַд��efuse��nvCNend
*
* @attention  NULL
* @param  mac_addr    [IN]     Type  #const char * mac addr.CNcomment:mac��ַCNend
* @param  type        [IN]     Type  #unsigned char type.CNcomment:д������,0:efuse,1:nvCNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_set_efuse_mac(const char *mac_addr, unsigned int type);

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  get macefuse mac addr.CNcomment:��ȡefuse�е�MAC��ַCNend
*
* @par Description:
*           get macefuse mac addr.CNcomment:��ȡefuse�е�MAC��ַCNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_get_efuse_mac(void);

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  write data into efuse.CNcomment:��У׼ֵд��efuseCNend
*
* @par Description:
*           write data into efuse.CNcomment:��У׼ֵд��efuseCNend
*
* @attention  NULL
* @param  type        [IN]     Type  #unsigned char type.CNcomment:д������,0:efuse,1:nvCNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_set_dataefuse(hi_u32 type);

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  get cur cal data.CNcomment:��ȡ��ǰ����У׼ֵCNend
*
* @par Description:
*           get cur cal data.CNcomment:��ȡ��ǰ����У׼ֵCNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int wal_get_cal_data(void);
#endif

/**
* @ingroup  hi_wifi_mfg_test_if
* @brief  always rx/tx interference function.CNcomment:�������յȽӿں���CNend
*
* @par Description:
*           always rx/tx interference function.CNcomment:�������յȽӿں���CNend
*
* @attention  NULL
* @param  argc         [IN]     Type  #int argc.CNcomment:�����������CNend
* @param  argv         [IN]     Type  #const char *argv.CNcomment:�����������Ӧ���ַ�������CNend
* @param  cmd_type     [IN]     Type  #unsigned int cmd_type.CNcomment:��������CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_mfg_test_if.h: WiFi mfg_test
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int hi_wifi_at_start(int argc, const char *argv[], unsigned int cmd_type);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif
