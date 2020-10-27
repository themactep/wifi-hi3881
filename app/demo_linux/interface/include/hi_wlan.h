/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: header file for Wi-Fi Station component
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/**
 * \file
 * \brief describle the information about WiFi STA component. CNcomment:�ṩWiFi STA�����ؽӿڡ����ݽṹ��Ϣ��CNend
 */

#ifndef __HI_WLAN_H__
#define __HI_WLAN_H__

#include "hi_type.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*************************** Structure Definition ****************************/
/**< \addtogroup     WLAN_STA */
/**< @{ */  /**< <!-- [WLAN_STA] */

#ifndef HI_WLAN_COMMON_DEF
#define HI_WLAN_COMMON_DEF

#define MAX_SSID_LEN        256    /**< max length of AP's ssid *//**< CNcomment:SSID��󳤶� */
#define BSSID_LEN           17     /**< length of MAC address *//**< CNcomment:MAC��ַ���� */
#define MAX_PSSWD_LEN       64     /**< max length of password *//**< CNcomment:������󳤶� */
#define WEP_PSSWD_LEN_5     5
#define WEP_PSSWD_LEN_13    13
#define MIN_CHAN            1
#define MAX_CHAN            14
#define BEACON_INT_MAX      1000
#define BEACON_INT_MIN      33
#define DEFAULT_BEACON_INT  100
#define DEFAULT_CHANNEL     6
#define SOCK_BUF_MAX        1024
#define SOCK_PORT           8001

/**< invalid parameter */
/**< CNcomment:��Ч�Ĳ��� -2 */
#define HI_WLAN_INVALID_PARAMETER           -2

/**< no supported WiFi device found */
/**< CNcomment:û���ҵ�WiFi�豸 -3 */
#define HI_WLAN_DEVICE_NOT_FOUND            -3

/**< load driver fail */
/**< CNcomment:��������ʧ�� -4 */
#define HI_WLAN_LOAD_DRIVER_FAIL            -4

/**< run wpa_supplicant process fail */
/**< CNcomment:����wpa_supplicantʧ�� -5 */
#define HI_WLAN_START_SUPPLICANT_FAIL       -5

/**< cann't connect to wpa_supplicant */
/**< CNcomment:����wpa_supplicantʧ�� -6 */
#define HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL  -6

/**< cann't send command to wpa_supplicant */
/**< CNcomment:���������wpa_supplicantʧ�� -7 */
#define HI_WLAN_SEND_COMMAND_FAIL           -7

/**< run hostapd process fail */
/**< CNcomment:����hostapdʧ�� -8 */
#define HI_WLAN_START_HOSTAPD_FAIL          -8

/**< network security mode type *//**< CNcomment:AP��ȫģʽ���� */
typedef enum hi_wlan_security_e {
    HI_WLAN_SECURITY_OPEN,          /**< OPEN mode, not encrypted *//**< CNcomment:OPENģʽ */
    HI_WLAN_SECURITY_WEP,           /**< WEP mode *//**< CNcomment:WEPģʽ */
    HI_WLAN_SECURITY_WPA_WPA2_PSK,  /**< WPA-PSK/WPA2-PSK mode *//**< CNcomment:WPA-PSK��WPA2-PSKģʽ */
    HI_WLAN_SECURITY_WPA_WPA2_EAP,  /**< WPA-EAP/WPA2-EAP mode *//**< CNcomment:WPA-EAP��WPA2-EAPģʽ */
    HI_WLAN_SECURITY_WAPI_PSK,      /**< WAPI-PSK mode *//**< CNcomment:WAPI-PSKģʽ */
    HI_WLAN_SECURITY_WAPI_CERT,     /**< WAPI-CERT mode *//**< CNcomment:WAPI-CERTģʽ */
    HI_WLAN_SECURITY_BUTT,
} hi_wlan_security_e;

#endif /* HI_WLAN_COMMON_DEF */
#define SCAN_CHAN_NUM_MIX 14

typedef struct hi_wlan_sta_scan_cfg_e {
    hi_u32 scan_chan[SCAN_CHAN_NUM_MIX];
    hi_u8   scan_chan_len;
} hi_wlan_sta_scan_cfg_e;

#ifndef HI_WLAN_STA_COMMON_DEF
#define HI_WLAN_STA_COMMON_DEF

#define PIN_CODE_LEN      8                 /**< length of wps pin code *//**< CNcomment:pin�볤�� */

/**< WiFi event type *//**< CNcomment:WiFi�¼����� */
typedef enum hi_wlan_sta_event_e {
    HI_WLAN_STA_EVENT_DISCONNECTED,         /**< network disconnected event *//**< CNcomment:����Ͽ��¼� */
    HI_WLAN_STA_EVENT_SCAN_RESULTS_AVAILABLE,    /**< scan done event *//**< CNcomment:ɨ������¼� */
    HI_WLAN_STA_EVENT_CONNECTING,           /**< try to connect to network event *//**< CNcomment:��������AP�¼� */
    HI_WLAN_STA_EVENT_CONNECTED,            /**< network connected event *//**< CNcomment:������AP�¼� */
    HI_WLAN_STA_EVENT_SUPP_STOPPED,         /**< supplicant abnormal event *//**< CNcomment:wpa_supplicantֹͣ�¼� */
    HI_WLAN_STA_EVENT_DRIVER_STOPPED,       /**< driver abnormal event *//**< CNcomment:�����˳��¼� */
    HI_WLAN_P2P_EVENT_PEERS_CHANGED,        /**< p2p status event *//**< CNcomment:״̬����¼� */
    HI_WLAN_P2P_EVENT_GROUP_STARTED,        /**< p2p group started event *//**< CNcomment:����Ⱥ���¼� */
    HI_WLAN_P2P_EVENT_GROUP_REMOVED,        /**< p2p group removed event *//**< CNcomment:ɾ��Ⱥ���¼� */
    HI_WLAN_P2P_EVENT_CONNECTED,            /**< p2p connected event *//**< CNcomment:�豸�������¼� */
    HI_WLAN_P2P_EVENT_DISCONNECTED,         /**< p2p disconnected event *//**< CNcomment:�豸δ�����¼� */
    HI_WLAN_P2P_EVENT_CONNECTION_REQUESTED,       /**< p2p connection requested event *//**< CNcomment:���������¼� */
    HI_WLAN_P2P_EVENT_PERSISTENT_GROUPS_CHANGED,  /**< p2p groups changed event *//**< CNcomment:Ⱥ�����¼� */
    HI_WLAN_P2P_EVENT_INVITATION,           /**< p2p invitation event *//**< CNcomment:�豸�����¼� */
    HI_WLAN_P2P_EVENT_DEVICE_FOUND,         /**< p2p device found event *//**< CNcomment:�豸�����¼� */
    HI_WLAN_P2P_EVENT_NEGOTIATION_FAILURE,  /**< p2p negotiation failure event *//**< CNcomment:p2p negʧ���¼� */
    HI_WLAN_P2P_EVENT_FORMATION_FAILURE,    /**< p2p formation failure event *//**< CNcomment:p2p formationʧ���¼� */
    HI_WLAN_WPS_EVENT_TIMEOUT,              /**< wps timeout event *//**< CNcomment:p2p wps��ʱ�¼� */
    HI_WLAN_WPS_EVENT_OVERLAP,              /**< wps overlap event *//**< CNcomment:p2p wps�豸�����¼� */
    HI_WLAN_STA_EVENT_BUTT,
} hi_wlan_sta_event_e;

/**< WPS method type *//**< CNcomment:WPS�������� */
typedef enum hi_wps_method_e {
    WPS_PBC,           /**< Push Button method *//**< CNcomment:Push Button��ʽ */
    WPS_PIN_DISPLAY,   /**< PIN Display method *//**< CNcomment:PIN Display��ʽ */
    WPS_PIN_KEYPAD,    /**< PIN Keypad method *//**< CNcomment:PIN Keypad��ʽ */
    WPS_PIN_LABEL,     /**< PIN Label method *//**< CNcomment:PIN Keypad��ʽ */
    WPS_BUTT,
} hi_wps_method_e;

/**< Callback function of receiving WiFi events *//**< CNcomment:����WiFi�¼��Ļص����� */
typedef hi_void(*hi_wlan_sta_event_callback)(hi_wlan_sta_event_e event, const hi_void *priv_data,
                                             hi_u32 priv_data_size);

#endif /* HI_WLAN_STA_COMMON_DEF */

/**< connection state type *//**< CNcomment:��������״̬���� */
typedef enum hi_wlan_sta_conn_state_e {
    HI_WLAN_STA_CONN_STATUS_DISCONNECTED,   /**< not connected to any network *//**< CNcomment:����Ͽ�״̬ */
    HI_WLAN_STA_CONN_STATUS_CONNECTING,     /**< connecting to a network *//**< CNcomment:��������AP״̬ */
    HI_WLAN_STA_CONN_STATUS_CONNECTED,      /**< connected to a network *//**< CNcomment:������AP״̬ */
    HI_WLAN_STA_CONN_STATUS_BUTT,
} hi_wlan_sta_conn_state_e;

/**< network information *//**< CNcomment:AP��Ϣ�ṹ�� */
typedef struct hi_wlan_sta_access_point_e {
    hi_char ssid[MAX_SSID_LEN + 1];         /**< AP's SSID */ /**< CNcomment:AP��SSID */
    hi_char bssid[BSSID_LEN + 1];           /**< AP's MAC address */ /**< CNcomment:AP��MAC��ַ */
    hi_s32  level;                          /* *< AP's signal level, 0 - 100 */ /* * CNcomment:AP���ź�ǿ�ȣ�0 - 100 */
    hi_u32  channel;                        /**< AP's channel number *//**< CNcomment:AP���ŵ� */
    hi_wlan_security_e security;            /**< AP's security mode *//**< CNcomment:AP�İ�ȫģʽ */
} hi_wlan_sta_access_point_e;

typedef enum hi_wlan_bandwith_e {
    HI_WLAN_BAND_WIDTH_20M,
    HI_WLAN_BAND_WIDTH_10M,
    HI_WLAN_BAND_WIDTH_5M,

    HI_WLAN_BAND_WIDTH_BUTT,
} hi_wlan_bandwith_e;

typedef struct hi_wlan_mode_conf {
    hi_u8   bw_enable;                      /* 1��ʹ�ܣ�0����ʹ�� */
    hi_wlan_bandwith_e   bw_bandwidth;      /* 0\1\2  20 10 5 */
} hi_wlan_mode_conf;

typedef enum hi_wlan_hwmode_e {
    HI_WLAN_HWMODE_11N,
    HI_WLAN_HWMODE_11G,
    HI_WLAN_HWMODE_11B,

    HI_WLAN_HW_MODE_BUTT,
} hi_wlan_hwmode_e;

typedef enum {
    HI_WLAN_NO_PROTECTION,
    HI_WLAN_PROTECTION_OPTIONAL,
    HI_WLAN_PROTECTION_REQUIRED,

    HI_WLAN_PROTECTION_BUTT,
} hi_wlan_pmf_mode;

typedef enum {
    HI_WLAN_WPS_PBC,
    HI_WLAN_WPS_PIN,

    HI_WLAN_WPS_BUTT,
} hi_wlan_wps_method;

/**< network configuration *//**< CNcomment:��Ҫ���ӵ�AP���� */
typedef struct hi_wlan_sta_config_s {
    hi_char   ssid[MAX_SSID_LEN + 1];       /**< network's SSID */ /**< CNcomment:AP��SSID */
    hi_char   bssid[BSSID_LEN + 1];         /**< network's MAC address */ /**< CNcomment:AP��MAC��ַ */
    hi_wlan_security_e security;            /**< network's security mode *//**< CNcomment:AP�İ�ȫģʽ */
    hi_char   psswd[MAX_PSSWD_LEN + 1];     /**< network's password, if not OPEN mode */ /**< CNcomment:���� */
    hi_bool   hidden_ssid;                  /**< whether network hiddens it's SSID *//**< CNcomment:AP�Ƿ�������SSID */
    hi_wlan_mode_conf  bw_sta_config;       /**< network's Narrow band suppout and  speed */
    hi_wlan_hwmode_e     hw_mode;           /* set Operation mode n\g\b */
    hi_wlan_pmf_mode  pmf_mode;
    hi_wlan_wps_method  wps_method;
    hi_char   wps_pin[PIN_CODE_LEN + 1];
} hi_wlan_sta_config_s;

/**< network status information *//**< CNcomment:��������״̬��Ϣ */
typedef struct hi_wlan_sta_conn_status_e {
    hi_wlan_sta_conn_state_e state;         /**< connection state *//**< CNcomment:���������״̬ */
    hi_wlan_sta_access_point_e ap;          /**< network information which connected or connecting */
    /**< CNcomment:�����ϻ����������ӵ�AP��Ϣ */
} hi_wlan_sta_conn_status_e;

/**< @}*/  /**< <!-- ==== Structure Definition End ====*/

/******************************* API Declaration *****************************/
/**< \addtogroup     WLAN_STA*/
/**< @{*/  /**< <!-- [WLAN_STA]*/

/**
\brief: Initialize STA.CNcomment:��ʼ��STA CNend
\attention \n
\param    N/A.CNcomment:�� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\see \n
::hi_wlan_sta_init
*/
HI_OPEN_API hi_s32 hi_wlan_sta_init(hi_void);

/**
\brief: Deintialize STA.CNcomment:ȥ��ʼ��STA CNend
\attention \n
\param  N/A.CNcomment:�� CNend
\retval N/A.CNcomment:�� CNend
\see \n
::hi_wlan_sta_deinit
*/
HI_OPEN_API hi_void hi_wlan_sta_deinit(hi_void);

/**
\brief: Open WiFi STA device.CNcomment:��WiFi STA�豸 CNend
\attention \n
\param[out] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] nameBufSize  parameter ifname length.CNcomment:ifanme�Ĵ�С, ��: strlen(ifname)
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_DEVICE_NOT_FOUND
\retval  ::HI_WLAN_LOAD_DRIVER_FAIL
\see \n
::HI_WLAN_STA_Open
*/
HI_OPEN_API hi_s32 hi_wlan_sta_open(hi_char *ifname, hi_u32 name_bug_size, hi_wlan_sta_config_s *sta_cfg);

/**
\brief: Close WiFi STA device.CNcomment:�ر�WiFi STA�豸 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_close
*/
HI_OPEN_API hi_s32 hi_wlan_sta_close(const hi_char *ifname);

/**
\brief: Start WiFi STA.CNcomment:����WiFi STA CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:�����¼��Ļص����� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_START_SUPPLICANT_FAIL
\retval  ::HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL
\see \n
::hi_wlan_sta_start
*/
HI_OPEN_API hi_s32 hi_wlan_sta_start(const hi_char *ifname, hi_wlan_sta_event_callback event_cb);

/**
\brief: Stop WiFi STA.CNcomment:ͣ��WiFi STA CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_stop
*/
HI_OPEN_API hi_s32 hi_wlan_sta_stop(const hi_char *ifname);

/**
\brief: Start to scan.CNcomment:��ʼɨ�� CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::hi_wlan_sta_start_scan
*/
HI_OPEN_API hi_s32 hi_wlan_sta_start_scan(const hi_char *ifname);

/**
\brief: Start to scan.CNcomment:ָ���ŵ�ɨ�� CNend
\attention \n
\param[in] scan_cfg  hi_wlan_sta_scan_cfg_e.CNcomment:hi_wlan_sta_scan_cfg_e�ṹ�� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::hi_wlan_sta_start_scan
*/
HI_OPEN_API hi_s32 hi_wlan_sta_start_chan_scan(hi_wlan_sta_scan_cfg_e *scan_cfg);

/**
\brief: Get scan results.CNcomment:��ȡɨ�赽��AP CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[out] pstApList AP list.CNcomment: ����ɨ�赽��AP�б� CNend
\param[inout] pstApNum  number of APs.CNcomment: AP�б���AP������ CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::hi_wlan_sta_get_scan_results
*/
HI_OPEN_API hi_s32 hi_wlan_sta_get_scan_results(const hi_char *ifname, hi_wlan_sta_access_point_e *ap_list, hi_u32 *ap_num);

/**
\brief: Connect to AP.CNcomment:��ʼ����AP CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstStaCfg  AP configuration try to connect.CNcomment:��Ҫ���ӵ�AP����Ϣ CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::hi_wlan_sta_connect
*/
HI_OPEN_API hi_s32 hi_wlan_sta_connect(const hi_char *ifname, hi_wlan_sta_config_s *sta_cfg);

/**
\brief: Disconnect to AP.CNcomment:�Ͽ����� CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::hi_wlan_sta_disconnect
*/
HI_OPEN_API hi_s32 hi_wlan_sta_disconnect(const hi_char *ifname);

/**
\brief: Get current network connection status.CNcomment:��õ�ǰ������״̬��Ϣ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[out] pstConnStatus network connection status.CNcomment:��������״̬��Ϣ CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::hi_wlan_sta_get_connection_status
*/
HI_OPEN_API hi_s32 hi_wlan_sta_get_connection_status(const hi_char *ifname, hi_wlan_sta_conn_status_e *conn_status);

/**
\brief: WPS connect to AP.CNcomment:��ʼ����WPS AP CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] wps_method  WPS method.CNcomment:WPS���� CNend
\param[in] pstPin  Pin code if WPS method is PIN.CNcomment:WPS pin�� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_SEND_COMMAND_FAIL
\see \n
::HI_WLAN_STA_StartWps
*/
HI_OPEN_API hi_s32 hi_wlan_sta_start_wps(const hi_char *ifname, hi_wlan_sta_config_s *sta_cfg);

/**
\brief: Get local WiFi MAC address.CNcomment:��ȡ����WiFi MAC��ַ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[out] pstMac  MAC address of local WiFi.CNcomment:���汾��WiFi MAC��ַ CNend
\param[in] macBufSize  parameter ifname length.CNcomment:ifname�Ĵ�С, ��Сһ��̶�Ϊ17 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_get_mac_address
*/
HI_OPEN_API hi_s32 hi_wlan_sta_get_mac_address(const hi_char *ifname, hi_char *mac, hi_u8 mac_buf_size);

/**< @}*/  /**< <!-- ==== API Declaration End ====*/
/*************************** Structure Definition ****************************/
/**< \addtogroup     WLAN_AP */
/**< @{ */  /**< <!-- [WLAN_AP] */

/**< network security mode type *//**< CNcomment:AP��ȫģʽ���� */ /**< AP's configuration */
typedef struct hi_wlan_ap_config_s {
    hi_char   ssid[MAX_SSID_LEN + 1];       /**< network's SSID */ /**< CNcomment:SSID */
    hi_s32    channel;                      /**< network's channel *//**< CNcomment:�ŵ��� */
    hi_wlan_security_e security;            /**< network's security mode *//**< CNcomment:��ȫģʽ */
    hi_char   psswd[MAX_PSSWD_LEN + 1];     /**< network's password, if not OPEN mode */ /**< CNcomment:���� */
    hi_bool   hidden_ssid;                  /**< whether network hiddens it's SSID *//**< CNcomment:�Ƿ�����SSID */
    hi_u32    beacon_int;                   /**< Beacon interval in kus (1.024 ms) (default: 100; range 15..65535) */
    hi_char   hw_mode;                      /**< set Operation mode */
    hi_wlan_bandwith_e   bw_bandwidth;      /**< set bandwidth */
} hi_wlan_ap_config_s;

/**< @}*/  /**< <!-- ==== Structure Definition End ====*/

/******************************* API Declaration *****************************/
/**< \addtogroup     WLAN_AP*/
/**< @{*/  /**< <!-- [WLAN_AP]*/

/**
\brief: Initialize SoftAP.CNcomment:��ʼ��SoftAP CNend
\attention \n
\param    N/A.CNcomment:�� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\see \n
::hi_wlan_ap_init
*/
HI_OPEN_API hi_s32 hi_wlan_ap_init(hi_void);

/**
\brief: Deintialize SoftAP.CNcomment:ȥ��ʼ��SoftAP CNend
\attention \n
\param  N/A.CNcomment:�� CNend
\retval N/A.CNcomment:�� CNend
\see \n
::hi_wlan_ap_deinit
*/
HI_OPEN_API hi_void hi_wlan_ap_deinit(hi_void);

/**
\brief: Open WiFi SoftAP device.CNcomment:��WiFi SoftAP�豸 CNend
\attention \n
\param[out] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] nameBufSize  parameter ifname length.CNcomment:ifanme�Ĵ�С, ��: strlen(ifname)
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_DEVICE_NOT_FOUND
\retval  ::HI_WLAN_LOAD_DRIVER_FAIL
\see \n
::hi_wlan_ap_open
*/
HI_OPEN_API hi_s32 hi_wlan_ap_open(hi_char *ifname, hi_u32 name_buf_size, hi_wlan_bandwith_e bw);

/**
\brief: Close WiFi SoftAP device.CNcomment:�ر�WiFi SoftAP�豸 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_ap_close
*/
HI_OPEN_API hi_s32 hi_wlan_ap_close(const hi_char *ifname);

/**
\brief: start SoftAP with configuration.CNcomment:����SoftAP CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstApCfg  AP's configuration.CNcomment:AP�����ò��� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_START_HOSTAPD_FAIL
\see \n
::hi_wlan_ap_start
*/
HI_OPEN_API hi_s32 hi_wlan_ap_start(const hi_char *ifname, hi_wlan_ap_config_s *ap_cfg);

/**
\brief: Stop SoftAP.CNcomment:�ر�SoftAP CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_ap_stop
*/
HI_OPEN_API hi_s32 hi_wlan_ap_stop(const hi_char *ifname);

/**
\brief: Set SoftAP.CNcomment:����SoftAP CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstApCfg  AP's configuration.CNcomment:AP�����ò��� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_START_HOSTAPD_FAIL
\see \n
::hi_wlan_ap_setsoftap
*/
HI_OPEN_API hi_s32 hi_wlan_ap_setsoftap(const hi_char *ifname, hi_wlan_ap_config_s *ap_cfg);

/**
\brief: Get local WiFi MAC address.CNcomment:��ȡ����WiFi MAC��ַ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[out] pstMac  MAC address of local WiFi.CNcomment:���汾��WiFi MAC��ַ CNend
\param[in] macBufSize  parameter ifname length.CNcomment:ifname�Ĵ�С, ��Сһ��̶�Ϊ17 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_ap_getmacaddress
*/
HI_OPEN_API hi_s32 hi_wlan_ap_getmacaddress(const hi_char *ifname, hi_char *pstMac, hi_u8 mac_buf_size);

/**< @}*/  /**< <!-- ==== API Declaration End ====*/

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* __HI_WLAN_STA_H__ */
