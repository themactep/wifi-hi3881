/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: header file for Wi-Fi P2P component.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/**
 * \file
 * \brief describle the information about WiFi-Direct component.
 *  CNcomment:�ṩWiFi-Direct�����ؽӿڡ����ݽṹ��Ϣ��CNend
 */

#ifndef __HI_WLAN_P2P_H__
#define __HI_WLAN_P2P_H__

#include "hi_type.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*************************** Structure Definition ****************************/
/**< \addtogroup     WLAN_P2P */
/**< @{ */  /**< <!-- [WLAN_P2P] */

#ifndef HI_WLAN_COMMON_DEF
#define HI_WLAN_COMMON_DEF

#define MAX_SSID_LEN    256    /**< max length of AP's ssid *//**< CNcomment:SSID��󳤶� */
#define BSSID_LEN       17     /**< length of MAC address *//**< CNcomment:MAC��ַ���� */
#define MAX_PSSWD_LEN   64     /**< max length of password *//**< CNcomment:������󳤶� */

/**< invalid parameter */
/**< CNcomment:��Ч�Ĳ��� -2 */
#define HI_WLAN_INVALID_PARAMETER           (-2)

/**< no supported WiFi device found */
/**< CNcomment:û���ҵ�WiFi�豸 -3 */
#define HI_WLAN_DEVICE_NOT_FOUND            (-3)

/**< load driver fail */
/**< CNcomment:��������ʧ�� -4 */
#define HI_WLAN_LOAD_DRIVER_FAIL            (-4)

/**< run wpa_supplicant process fail */
/**< CNcomment:����wpa_supplicantʧ�� -5 */
#define HI_WLAN_START_SUPPLICANT_FAIL       (-5)

/**< cann't connect to wpa_supplicant */
/**< CNcomment:����wpa_supplicantʧ�� -6 */
#define HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL  (-6)

/**< cann't send command to wpa_supplicant */
/**< CNcomment:���������wpa_supplicantʧ�� -7 */
#define HI_WLAN_SEND_COMMAND_FAIL           (-7)

/**< run hostapd process fail */
/**< CNcomment:����hostapdʧ�� -8 */
#define HI_WLAN_START_HOSTAPD_FAIL          (-8)

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

#ifndef HI_WLAN_STA_COMMON_DEF
#define HI_WLAN_STA_COMMON_DEF

#define PIN_CODE_LEN      8    /**< length of wps pin code *//**< CNcomment:pin�볤�� */

/**< WiFi event type *//**< CNcomment:WiFi�¼����� */
typedef enum hi_wlan_sta_event_e {
    HI_WLAN_STA_EVENT_DISCONNECTED,    /**< network disconnected event *//**< CNcomment:����Ͽ��¼� */
    HI_WLAN_STA_EVENT_SCAN_RESULTS_AVAILABLE,    /**< scan done event *//**< CNcomment:ɨ������¼� */
    HI_WLAN_STA_EVENT_CONNECTING,      /**< try to connect to network event *//**< CNcomment:��������AP�¼� */
    HI_WLAN_STA_EVENT_CONNECTED,       /**< network connected event *//**< CNcomment:������AP�¼� */
    HI_WLAN_STA_EVENT_SUPP_STOPPED,    /**< supplicant abnormal event *//**< CNcomment:wpa_supplicantֹͣ�¼� */
    HI_WLAN_STA_EVENT_DRIVER_STOPPED,  /**< driver abnormal event *//**< CNcomment:�����˳��¼� */
    HI_WLAN_P2P_EVENT_PEERS_CHANGED,   /**< p2p status event *//**< CNcomment:״̬����¼� */
    HI_WLAN_P2P_EVENT_GROUP_STARTED,   /**< p2p group started event *//**< CNcomment:����Ⱥ���¼� */
    HI_WLAN_P2P_EVENT_GROUP_REMOVED,   /**< p2p group removed event *//**< CNcomment:ɾ��Ⱥ���¼� */
    HI_WLAN_P2P_EVENT_CONNECTED,       /**< p2p connected event *//**< CNcomment:�豸�������¼� */
    HI_WLAN_P2P_EVENT_DISCONNECTED,    /**< p2p disconnected event *//**< CNcomment:�豸δ�����¼� */
    HI_WLAN_P2P_EVENT_CONNECTION_REQUESTED,       /**< p2p connection requested event *//**< CNcomment:���������¼� */
    HI_WLAN_P2P_EVENT_PERSISTENT_GROUPS_CHANGED,  /**< p2p groups changed event *//**< CNcomment:Ⱥ�����¼� */
    HI_WLAN_P2P_EVENT_INVITATION,      /**< p2p invitation event *//**< CNcomment:�豸�����¼� */
    HI_WLAN_P2P_EVENT_DEVICE_FOUND,    /**< p2p device found event *//**< CNcomment:�豸�����¼� */
    HI_WLAN_P2P_EVENT_NEGOTIATION_FAILURE,  /**< p2p negotiation failure event *//**< CNcomment:p2p negʧ���¼� */
    HI_WLAN_P2P_EVENT_FORMATION_FAILURE,    /**< p2p formation failure event *//**< CNcomment:p2p formationʧ���¼� */
    HI_WLAN_WPS_EVENT_TIMEOUT,         /**< wps timeout event *//**< CNcomment:p2p wps��ʱ�¼� */
    HI_WLAN_WPS_EVENT_OVERLAP,         /**< wps overlap event *//**< CNcomment:p2p wps�豸�����¼� */
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
typedef hi_void(*hi_wlan_sta_event_callback)(hi_wlan_sta_event_e event, hi_void *pstPrivData, hi_u32 privDataSize);

#endif /* HI_WLAN_STA_COMMON_DEF */

#define NETWORK_NAME_LEN  256  /**< length of P2P device or Group name *//**< CNcomment:P2P�豸���ƻ����������� */
#define DEVICE_TYPE_LEN   256  /**< length of device type string *//**< CNcomment:�豸���ͳ��� */

/**< WPS config methods bitmap *//**< CNcomment: */
#define WPS_CONFIG_DISPLAY         0x0008
#define WPS_CONFIG_PUSHBUTTON      0x0080
#define WPS_CONFIG_KEYPAD          0x0100

/**< Device Capability bitmap *//**< CNcomment: */
#define DEVICE_CAPAB_SERVICE_DISCOVERY         1
#define DEVICE_CAPAB_CLIENT_DISCOVERABILITY    1<<1
#define DEVICE_CAPAB_CONCURRENT_OPER           1<<2
#define DEVICE_CAPAB_INFRA_MANAGED             1<<3
#define DEVICE_CAPAB_DEVICE_LIMIT              1<<4
#define DEVICE_CAPAB_INVITATION_PROCEDURE      1<<5

/**< Group Capability bitmap *//**< CNcomment: */
#define GROUP_CAPAB_GROUP_OWNER                1
#define GROUP_CAPAB_PERSISTENT_GROUP           1<<1
#define GROUP_CAPAB_GROUP_LIMIT                1<<2
#define GROUP_CAPAB_INTRA_BSS_DIST             1<<3
#define GROUP_CAPAB_CROSS_CONN                 1<<4
#define GROUP_CAPAB_PERSISTENT_RECONN          1<<5
#define GROUP_CAPAB_GROUP_FORMATION            1<<6

/**< WiFi-Display Device Type value *//**< CNcomment: */
#define WFD_SOURCE                 0
#define PRIMARY_SINK               1
#define SECONDARY_SINK             2
#define SOURCE_OR_PRIMARY_SINK     3

/**< WiFi-Display information *//**< CNcomment:WiFi-Display��Ϣ�ṹ�� */
typedef struct hi_wlan_wfd_info_s {
    hi_bool wfdEnabled;   /**< is WFD enabled *//**< CNcomment:�Ƿ���WFD */
    hi_s32 deviceInfo;    /**< WFD device type *//**< CNcomment:WFD�豸���� */
    hi_s32 ctrlPort;      /**< control port *//**< CNcomment:���ƶ˿ں� */
    hi_s32 maxThroughput;    /**< the max throughput *//**< CNcomment:��������� */
} hi_wlan_wfd_info_s;

/**< WiFi-Direct device information *//**< CNcomment:WiFi-Direct�豸��Ϣ�ṹ�� */
typedef struct hi_wlan_p2p_device_s {
    hi_char name[NETWORK_NAME_LEN];           /**< device name *//**< CNcomment:�豸���� */
    hi_char bssid[BSSID_LEN + 1];  /**< MAC address */ /**< CNcomment:MAC��ַ */
    hi_char pri_dev_type[DEVICE_TYPE_LEN];   /**< device type *//**< CNcomment:�豸���� */
    hi_s32 config_method;        /**< WPS config method supported*//**< CNcomment:֧�ֵ�WPS���ӷ�ʽ */
    hi_s32 dev_capab;            /**< device capability *//**< CNcomment:�豸���� */
    hi_s32 group_capab;          /**< group capability *//**< CNcomment:group���� */
    hi_wlan_wfd_info_s wfd_info; /**< WiFi-Display information *//**< CNcomment:WiFi-Display��Ϣ */
} hi_wlan_p2p_device_s;

/**< configured network information *//**< CNcomment:��Ҫ���ӵ�������Ϣ�ṹ�� */
typedef struct hi_wlan_p2p_config_s {
    hi_char bssid[BSSID_LEN + 1];  /**< peer's MAC address */ /**< CNcomment:peer��MAC��ַ */
    hi_wps_method_e wps_method;  /**< WPS config method *//**< CNcomment:WPS���ӷ�ʽ */
    hi_char pin[PIN_CODE_LEN + 1]; /**< pin if config method is PIN method */ /**< CNcomment:PIN�� */
    hi_s32  intent;              /**< GO intent *//**< CNcomment:GO intent */
} hi_wlan_p2p_config_s;

/**< Group information *//**< CNcomment:Group��Ϣ�ṹ�� */
typedef struct hi_wlan_p2p_group_s {
    hi_char iface[IFNAMSIZ + 1];
    hi_bool is_group_owner;
    hi_char network_name[NETWORK_NAME_LEN];
    hi_wlan_p2p_device_s go;
} hi_wlan_p2p_group_s;

/**< @}*/  /**< <!-- ==== Structure Definition End ====*/

/******************************* API Declaration *****************************/
/**< \addtogroup     WLAN_P2P*/
/**< @{*/  /**< <!-- [WLAN_P2P]*/

/**
\brief: Initialize P2P.CNcomment:��ʼ��P2P CNend
\attention \n
\param    N/A.CNcomment:�� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\see \n
::hi_wlan_p2p_init
*/
hi_s32 hi_wlan_p2p_init(hi_void);

/**
\brief: Deintialize P2P.CNcomment:ȥ��ʼ��P2P CNend
\attention \n
\param  N/A.CNcomment:�� CNend
\retval N/A.CNcomment:�� CNend
\see \n
::hi_wlan_p2p_deinit
*/
hi_void hi_wlan_p2p_deinit(hi_void);

/**
\brief: Open WiFi P2P device.CNcomment:��WiFi P2P�豸 CNend
\attention \n
\param[out] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] nameBufSize  parameter ifname length.CNcomment:ifanme�Ĵ�С, ��: strlen(ifname)
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_DEVICE_NOT_FOUND
\retval  ::HI_WLAN_LOAD_DRIVER_FAIL
\see \n
::hi_wlan_p2p_open
*/
hi_s32 hi_wlan_p2p_open(hi_char *ifname, hi_u32 name_buf_size);

/**
\brief: Close WiFi P2P device.CNcomment:�ر�WiFi P2P�豸 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_close
*/
hi_s32 hi_wlan_p2p_close(const hi_char *ifname);

/**
\brief: Start WiFi P2P.CNcomment:����WiFi P2P CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:�����¼��Ļص����� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_START_SUPPLICANT_FAIL
\retval  ::HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL
\see \n
::hi_wlan_p2p_start
*/
hi_s32 hi_wlan_p2p_start(const hi_char *ifname, hi_wlan_sta_event_callback event_cb);

/**
\brief: Stop WiFi P2P.CNcomment:ͣ��WiFi P2P CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_stop
*/
hi_s32 hi_wlan_p2p_stop(const hi_char *ifname);

/**
\brief: search WiFi P2P devices.CNcomment:����WiFi P2P�豸 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] timeout timeout of find state.CNcomment:����P2P�豸�ĳ�ʱʱ�� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_find
*/
hi_s32 hi_wlan_p2p_find(const hi_char *ifname, hi_s32 timeout);

/**
\brief: Get WiFi P2P devices.CNcomment:��ȡ��������WiFi P2P�豸 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[out] pstDevList   buffer that save devices searched.CNcomment:�������������豸������ CNend
\param[inout] pstDevNum  number of devices searched.CNcomment:���������豸���� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_get_peers
*/
hi_s32 hi_wlan_p2p_get_peers(const hi_char *ifname, hi_wlan_p2p_device_s *devlist, hi_u32 *devnum);

/**
\brief: connect WiFi P2P peer.CNcomment:����WiFi P2P�豸 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstCfg  P2P network configuration.CNcomment:P2P�������� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_connect
*/
hi_s32 hi_wlan_p2p_connect(const hi_char *ifname, hi_wlan_p2p_config_s *p2p_cfg);

/**
\brief: disconnect WiFi P2P connection.CNcomment:�Ͽ�WiFi P2P���� CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_disconnect
*/
hi_s32 hi_wlan_p2p_disconnect(const hi_char *ifname);

/**
\brief: Set WiFi P2P device information.CNcomment:����WiFi P2P�豸��Ϣ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstDev  P2P device configuration.CNcomment:P2P�豸���� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_set_device_info
*/
hi_s32 hi_wlan_p2p_set_device_info(const hi_char *ifname, hi_wlan_p2p_device_s *p2p_dev);

/**
\brief: Set WiFi P2P device information.CNcomment:����WiFi P2P�豸��Ϣ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstDev  P2P device configuration.CNcomment:P2P�豸���� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_set_device_name
*/
hi_s32 hi_wlan_p2p_set_device_name(const hi_char *ifname, hi_char *name);

/**
\brief: Get persistent groups saved.CNcomment:��ñ����Persistent group CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[out] pstGroupList  save persistent groups.CNcomment:����Persistent Group������ CNend
\param[inout] pstGroupNum  number of persistent groups.CNcomment:persistent group������ CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_get_persistent_groups
*/
hi_s32 hi_wlan_p2p_get_persistent_groups(const hi_char *ifname, hi_wlan_p2p_group_s *group_list, hi_s32 *group_num);

/**
\brief: delete saved persistent group.CNcomment:ɾ�������Persistent Group CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] pstGroup  persistent group to be deleted.CNcomment:Ҫɾ����Persistent Group CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_delete_persistent_group
*/
hi_s32 hi_wlan_p2p_delete_persistent_group(const hi_char *ifname, hi_wlan_p2p_group_s *group);

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
::hi_wlan_p2p_get_mac_address
*/
hi_s32 hi_wlan_p2p_get_mac_address(const hi_char *ifname, hi_char *mac, hi_u8 mac_buf_size);

/**
\brief: Open WiFi STA + P2P device.CNcomment:��WiFi P2P�豸 CNend
\attention \n
\param[out] sta_ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in]  staIfnameSize  sta_ifname buffer size.CNcomment:sta_ifname�����С CNend
\param[out] p2p_ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\param[in]  p2pIfnameSize  p2p_ifname buffer size.CNcomment:p2p_ifname CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_DEVICE_NOT_FOUND
\retval  ::HI_WLAN_LOAD_DRIVER_FAIL
\see \n
::hi_wlan_sta_p2p_open
*/
hi_s32 hi_wlan_sta_p2p_open(hi_char *sta_ifname, hi_u8 sta_ifname_size, hi_char *p2p_ifname, hi_u8 p2p_ifname_size);

/**
\brief: Start WiFi STA + P2P.CNcomment:����WiFi P2P CNend
\attention \n
\param[in] sta_ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] p2p_ifname  WiFi network interface name.CNcomment:WiFi Direct����ӿ���, ��: p2p0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:�����¼��Ļص����� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\retval  ::HI_WLAN_START_SUPPLICANT_FAIL
\retval  ::HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL
\see \n
::hi_wlan_sta_p2p_start
*/
hi_s32 hi_wlan_sta_p2p_start(const hi_char *sta_ifname, const hi_char *p2p_ifname,
                             hi_wlan_sta_event_callback event_cb);

/**
\brief: Close WiFi STA + P2P device.CNcomment:�ر�WiFi P2P�豸 CNend
\attention \n
\param[in] sta_ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: wlan0 CNend
\param[in] p2p_ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_p2p_close
*/
hi_s32 hi_wlan_sta_p2p_close(const hi_char *sta_ifname, const hi_char *p2p_ifname);

/**
\brief: WiFi P2P listen.CNcomment:WiFi P2P�豸����listen״̬ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_p2p_close
*/
hi_s32 hi_wlan_p2p_listen(const hi_char *ifname);

/**
\brief: WiFi P2P flush.CNcomment:WiFi P2P�豸�˳�listen״̬ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_p2p_close
*/
hi_s32 hi_wlan_p2p_flush(const hi_char *ifname);

/**
\brief: WiFi P2P add group.CNcomment:WiFi P2P�豸����go״̬ CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_group_add
*/
hi_s32 hi_wlan_p2p_group_add(const hi_char *ifname);

/**
\brief: Register event callback function.CNcomment:ע���¼��ص����� CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:�����¼��Ļص����� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_event_register
*/
hi_s32 hi_wlan_event_register(const hi_char *ifname, hi_wlan_sta_event_callback event_cb);

/**
\brief: Unregister event callback function.CNcomment:ע��ע����¼��ص����� CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi����ӿ���, ��: p2p0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:�����¼��Ļص����� CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_event_unregister
*/
hi_s32 hi_wlan_event_unregister(const hi_char *ifname, hi_wlan_sta_event_callback event_cb);

/**< @}*/  /**< <!-- ==== API Declaration End ====*/

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* __HI_WLAN_P2P_H__ */
