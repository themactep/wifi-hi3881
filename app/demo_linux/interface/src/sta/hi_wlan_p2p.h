/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: header file for Wi-Fi P2P component.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/**
 * \file
 * \brief describle the information about WiFi-Direct component.
 *  CNcomment:提供WiFi-Direct组件相关接口、数据结构信息。CNend
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

#define MAX_SSID_LEN    256    /**< max length of AP's ssid *//**< CNcomment:SSID最大长度 */
#define BSSID_LEN       17     /**< length of MAC address *//**< CNcomment:MAC地址长度 */
#define MAX_PSSWD_LEN   64     /**< max length of password *//**< CNcomment:密码最大长度 */

/**< invalid parameter */
/**< CNcomment:无效的参数 -2 */
#define HI_WLAN_INVALID_PARAMETER           (-2)

/**< no supported WiFi device found */
/**< CNcomment:没有找到WiFi设备 -3 */
#define HI_WLAN_DEVICE_NOT_FOUND            (-3)

/**< load driver fail */
/**< CNcomment:加载驱动失败 -4 */
#define HI_WLAN_LOAD_DRIVER_FAIL            (-4)

/**< run wpa_supplicant process fail */
/**< CNcomment:启动wpa_supplicant失败 -5 */
#define HI_WLAN_START_SUPPLICANT_FAIL       (-5)

/**< cann't connect to wpa_supplicant */
/**< CNcomment:连接wpa_supplicant失败 -6 */
#define HI_WLAN_CONNECT_TO_SUPPLICANT_FAIL  (-6)

/**< cann't send command to wpa_supplicant */
/**< CNcomment:发送命令给wpa_supplicant失败 -7 */
#define HI_WLAN_SEND_COMMAND_FAIL           (-7)

/**< run hostapd process fail */
/**< CNcomment:启动hostapd失败 -8 */
#define HI_WLAN_START_HOSTAPD_FAIL          (-8)

/**< network security mode type *//**< CNcomment:AP安全模式类型 */
typedef enum hi_wlan_security_e {
    HI_WLAN_SECURITY_OPEN,          /**< OPEN mode, not encrypted *//**< CNcomment:OPEN模式 */
    HI_WLAN_SECURITY_WEP,           /**< WEP mode *//**< CNcomment:WEP模式 */
    HI_WLAN_SECURITY_WPA_WPA2_PSK,  /**< WPA-PSK/WPA2-PSK mode *//**< CNcomment:WPA-PSK或WPA2-PSK模式 */
    HI_WLAN_SECURITY_WPA_WPA2_EAP,  /**< WPA-EAP/WPA2-EAP mode *//**< CNcomment:WPA-EAP或WPA2-EAP模式 */
    HI_WLAN_SECURITY_WAPI_PSK,      /**< WAPI-PSK mode *//**< CNcomment:WAPI-PSK模式 */
    HI_WLAN_SECURITY_WAPI_CERT,     /**< WAPI-CERT mode *//**< CNcomment:WAPI-CERT模式 */
    HI_WLAN_SECURITY_BUTT,
} hi_wlan_security_e;

#endif /* HI_WLAN_COMMON_DEF */

#ifndef HI_WLAN_STA_COMMON_DEF
#define HI_WLAN_STA_COMMON_DEF

#define PIN_CODE_LEN      8    /**< length of wps pin code *//**< CNcomment:pin码长度 */

/**< WiFi event type *//**< CNcomment:WiFi事件类型 */
typedef enum hi_wlan_sta_event_e {
    HI_WLAN_STA_EVENT_DISCONNECTED,    /**< network disconnected event *//**< CNcomment:网络断开事件 */
    HI_WLAN_STA_EVENT_SCAN_RESULTS_AVAILABLE,    /**< scan done event *//**< CNcomment:扫描结束事件 */
    HI_WLAN_STA_EVENT_CONNECTING,      /**< try to connect to network event *//**< CNcomment:正在连接AP事件 */
    HI_WLAN_STA_EVENT_CONNECTED,       /**< network connected event *//**< CNcomment:连接上AP事件 */
    HI_WLAN_STA_EVENT_SUPP_STOPPED,    /**< supplicant abnormal event *//**< CNcomment:wpa_supplicant停止事件 */
    HI_WLAN_STA_EVENT_DRIVER_STOPPED,  /**< driver abnormal event *//**< CNcomment:驱动退出事件 */
    HI_WLAN_P2P_EVENT_PEERS_CHANGED,   /**< p2p status event *//**< CNcomment:状态变更事件 */
    HI_WLAN_P2P_EVENT_GROUP_STARTED,   /**< p2p group started event *//**< CNcomment:建立群组事件 */
    HI_WLAN_P2P_EVENT_GROUP_REMOVED,   /**< p2p group removed event *//**< CNcomment:删除群组事件 */
    HI_WLAN_P2P_EVENT_CONNECTED,       /**< p2p connected event *//**< CNcomment:设备连接上事件 */
    HI_WLAN_P2P_EVENT_DISCONNECTED,    /**< p2p disconnected event *//**< CNcomment:设备未连接事件 */
    HI_WLAN_P2P_EVENT_CONNECTION_REQUESTED,       /**< p2p connection requested event *//**< CNcomment:请求连接事件 */
    HI_WLAN_P2P_EVENT_PERSISTENT_GROUPS_CHANGED,  /**< p2p groups changed event *//**< CNcomment:群组变更事件 */
    HI_WLAN_P2P_EVENT_INVITATION,      /**< p2p invitation event *//**< CNcomment:设备邀请事件 */
    HI_WLAN_P2P_EVENT_DEVICE_FOUND,    /**< p2p device found event *//**< CNcomment:设备发现事件 */
    HI_WLAN_P2P_EVENT_NEGOTIATION_FAILURE,  /**< p2p negotiation failure event *//**< CNcomment:p2p neg失败事件 */
    HI_WLAN_P2P_EVENT_FORMATION_FAILURE,    /**< p2p formation failure event *//**< CNcomment:p2p formation失败事件 */
    HI_WLAN_WPS_EVENT_TIMEOUT,         /**< wps timeout event *//**< CNcomment:p2p wps超时事件 */
    HI_WLAN_WPS_EVENT_OVERLAP,         /**< wps overlap event *//**< CNcomment:p2p wps设备连接事件 */
    HI_WLAN_STA_EVENT_BUTT,
} hi_wlan_sta_event_e;

/**< WPS method type *//**< CNcomment:WPS连接类型 */
typedef enum hi_wps_method_e {
    WPS_PBC,           /**< Push Button method *//**< CNcomment:Push Button方式 */
    WPS_PIN_DISPLAY,   /**< PIN Display method *//**< CNcomment:PIN Display方式 */
    WPS_PIN_KEYPAD,    /**< PIN Keypad method *//**< CNcomment:PIN Keypad方式 */
    WPS_PIN_LABEL,     /**< PIN Label method *//**< CNcomment:PIN Keypad方式 */
    WPS_BUTT,
} hi_wps_method_e;

/**< Callback function of receiving WiFi events *//**< CNcomment:接收WiFi事件的回调函数 */
typedef hi_void(*hi_wlan_sta_event_callback)(hi_wlan_sta_event_e event, hi_void *pstPrivData, hi_u32 privDataSize);

#endif /* HI_WLAN_STA_COMMON_DEF */

#define NETWORK_NAME_LEN  256  /**< length of P2P device or Group name *//**< CNcomment:P2P设备名称或者组名长度 */
#define DEVICE_TYPE_LEN   256  /**< length of device type string *//**< CNcomment:设备类型长度 */

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

/**< WiFi-Display information *//**< CNcomment:WiFi-Display信息结构体 */
typedef struct hi_wlan_wfd_info_s {
    hi_bool wfdEnabled;   /**< is WFD enabled *//**< CNcomment:是否开启WFD */
    hi_s32 deviceInfo;    /**< WFD device type *//**< CNcomment:WFD设备类型 */
    hi_s32 ctrlPort;      /**< control port *//**< CNcomment:控制端口号 */
    hi_s32 maxThroughput;    /**< the max throughput *//**< CNcomment:最大吞吐量 */
} hi_wlan_wfd_info_s;

/**< WiFi-Direct device information *//**< CNcomment:WiFi-Direct设备信息结构体 */
typedef struct hi_wlan_p2p_device_s {
    hi_char name[NETWORK_NAME_LEN];           /**< device name *//**< CNcomment:设备名称 */
    hi_char bssid[BSSID_LEN + 1];  /**< MAC address */ /**< CNcomment:MAC地址 */
    hi_char pri_dev_type[DEVICE_TYPE_LEN];   /**< device type *//**< CNcomment:设备类型 */
    hi_s32 config_method;        /**< WPS config method supported*//**< CNcomment:支持的WPS连接方式 */
    hi_s32 dev_capab;            /**< device capability *//**< CNcomment:设备能力 */
    hi_s32 group_capab;          /**< group capability *//**< CNcomment:group能力 */
    hi_wlan_wfd_info_s wfd_info; /**< WiFi-Display information *//**< CNcomment:WiFi-Display信息 */
} hi_wlan_p2p_device_s;

/**< configured network information *//**< CNcomment:需要连接的网络信息结构体 */
typedef struct hi_wlan_p2p_config_s {
    hi_char bssid[BSSID_LEN + 1];  /**< peer's MAC address */ /**< CNcomment:peer的MAC地址 */
    hi_wps_method_e wps_method;  /**< WPS config method *//**< CNcomment:WPS连接方式 */
    hi_char pin[PIN_CODE_LEN + 1]; /**< pin if config method is PIN method */ /**< CNcomment:PIN码 */
    hi_s32  intent;              /**< GO intent *//**< CNcomment:GO intent */
} hi_wlan_p2p_config_s;

/**< Group information *//**< CNcomment:Group信息结构体 */
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
\brief: Initialize P2P.CNcomment:初始化P2P CNend
\attention \n
\param    N/A.CNcomment:无 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\see \n
::hi_wlan_p2p_init
*/
hi_s32 hi_wlan_p2p_init(hi_void);

/**
\brief: Deintialize P2P.CNcomment:去初始化P2P CNend
\attention \n
\param  N/A.CNcomment:无 CNend
\retval N/A.CNcomment:无 CNend
\see \n
::hi_wlan_p2p_deinit
*/
hi_void hi_wlan_p2p_deinit(hi_void);

/**
\brief: Open WiFi P2P device.CNcomment:打开WiFi P2P设备 CNend
\attention \n
\param[out] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] nameBufSize  parameter ifname length.CNcomment:ifanme的大小, 如: strlen(ifname)
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
\brief: Close WiFi P2P device.CNcomment:关闭WiFi P2P设备 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_close
*/
hi_s32 hi_wlan_p2p_close(const hi_char *ifname);

/**
\brief: Start WiFi P2P.CNcomment:启动WiFi P2P CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:接收事件的回调函数 CNend
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
\brief: Stop WiFi P2P.CNcomment:停用WiFi P2P CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_stop
*/
hi_s32 hi_wlan_p2p_stop(const hi_char *ifname);

/**
\brief: search WiFi P2P devices.CNcomment:搜索WiFi P2P设备 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] timeout timeout of find state.CNcomment:搜索P2P设备的超时时间 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_find
*/
hi_s32 hi_wlan_p2p_find(const hi_char *ifname, hi_s32 timeout);

/**
\brief: Get WiFi P2P devices.CNcomment:获取搜索到得WiFi P2P设备 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[out] pstDevList   buffer that save devices searched.CNcomment:保存搜索到的设备的数组 CNend
\param[inout] pstDevNum  number of devices searched.CNcomment:搜索到的设备数量 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_get_peers
*/
hi_s32 hi_wlan_p2p_get_peers(const hi_char *ifname, hi_wlan_p2p_device_s *devlist, hi_u32 *devnum);

/**
\brief: connect WiFi P2P peer.CNcomment:连接WiFi P2P设备 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] pstCfg  P2P network configuration.CNcomment:P2P网络配置 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_connect
*/
hi_s32 hi_wlan_p2p_connect(const hi_char *ifname, hi_wlan_p2p_config_s *p2p_cfg);

/**
\brief: disconnect WiFi P2P connection.CNcomment:断开WiFi P2P连接 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_disconnect
*/
hi_s32 hi_wlan_p2p_disconnect(const hi_char *ifname);

/**
\brief: Set WiFi P2P device information.CNcomment:设置WiFi P2P设备信息 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] pstDev  P2P device configuration.CNcomment:P2P设备配置 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_set_device_info
*/
hi_s32 hi_wlan_p2p_set_device_info(const hi_char *ifname, hi_wlan_p2p_device_s *p2p_dev);

/**
\brief: Set WiFi P2P device information.CNcomment:设置WiFi P2P设备信息 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] pstDev  P2P device configuration.CNcomment:P2P设备配置 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_set_device_name
*/
hi_s32 hi_wlan_p2p_set_device_name(const hi_char *ifname, hi_char *name);

/**
\brief: Get persistent groups saved.CNcomment:获得保存的Persistent group CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[out] pstGroupList  save persistent groups.CNcomment:保存Persistent Group的数组 CNend
\param[inout] pstGroupNum  number of persistent groups.CNcomment:persistent group的数量 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_get_persistent_groups
*/
hi_s32 hi_wlan_p2p_get_persistent_groups(const hi_char *ifname, hi_wlan_p2p_group_s *group_list, hi_s32 *group_num);

/**
\brief: delete saved persistent group.CNcomment:删除保存的Persistent Group CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] pstGroup  persistent group to be deleted.CNcomment:要删除的Persistent Group CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_delete_persistent_group
*/
hi_s32 hi_wlan_p2p_delete_persistent_group(const hi_char *ifname, hi_wlan_p2p_group_s *group);

/**
\brief: Get local WiFi MAC address.CNcomment:获取本地WiFi MAC地址 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[out] pstMac  MAC address of local WiFi.CNcomment:保存本地WiFi MAC地址 CNend
\param[in] macBufSize  parameter ifname length.CNcomment:ifname的大小, 大小一般固定为17 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_get_mac_address
*/
hi_s32 hi_wlan_p2p_get_mac_address(const hi_char *ifname, hi_char *mac, hi_u8 mac_buf_size);

/**
\brief: Open WiFi STA + P2P device.CNcomment:打开WiFi P2P设备 CNend
\attention \n
\param[out] sta_ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in]  staIfnameSize  sta_ifname buffer size.CNcomment:sta_ifname缓存大小 CNend
\param[out] p2p_ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
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
\brief: Start WiFi STA + P2P.CNcomment:启动WiFi P2P CNend
\attention \n
\param[in] sta_ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] p2p_ifname  WiFi network interface name.CNcomment:WiFi Direct网络接口名, 如: p2p0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:接收事件的回调函数 CNend
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
\brief: Close WiFi STA + P2P device.CNcomment:关闭WiFi P2P设备 CNend
\attention \n
\param[in] sta_ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: wlan0 CNend
\param[in] p2p_ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_p2p_close
*/
hi_s32 hi_wlan_sta_p2p_close(const hi_char *sta_ifname, const hi_char *p2p_ifname);

/**
\brief: WiFi P2P listen.CNcomment:WiFi P2P设备进入listen状态 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_p2p_close
*/
hi_s32 hi_wlan_p2p_listen(const hi_char *ifname);

/**
\brief: WiFi P2P flush.CNcomment:WiFi P2P设备退出listen状态 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_sta_p2p_close
*/
hi_s32 hi_wlan_p2p_flush(const hi_char *ifname);

/**
\brief: WiFi P2P add group.CNcomment:WiFi P2P设备进入go状态 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_p2p_group_add
*/
hi_s32 hi_wlan_p2p_group_add(const hi_char *ifname);

/**
\brief: Register event callback function.CNcomment:注册事件回调函数 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:接收事件的回调函数 CNend
\retval  ::HI_SUCCESS
\retval  ::HI_FAILURE
\retval  ::HI_WLAN_INVALID_PARAMETER
\see \n
::hi_wlan_event_register
*/
hi_s32 hi_wlan_event_register(const hi_char *ifname, hi_wlan_sta_event_callback event_cb);

/**
\brief: Unregister event callback function.CNcomment:注销注册的事件回调函数 CNend
\attention \n
\param[in] ifname  WiFi network interface name.CNcomment:WiFi网络接口名, 如: p2p0 CNend
\param[in] pfnEventCb  call back function that receives events.CNcomment:接收事件的回调函数 CNend
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
