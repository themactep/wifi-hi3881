/**
* @file hi_wifi_api.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: header file for wifi api.CNcomment:������WiFi api�ӿ�ͷ�ļ�.CNend\n
* Author: Hisilicon \n
* Create: 2019-01-03
*/

/**
 * @defgroup hi_wifi_basic WiFi Basic Settings
 * @ingroup hi_wifi
 */

#ifndef __HI_WIFI_API_H__
#define __HI_WIFI_API_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * mac transform string.CNcomment:��ַתΪ�ַ���.CNend
 */
#ifndef MACSTR
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

/**
 * @ingroup hi_wifi_basic
 *
 * TKIP of cipher mode.CNcomment:���ܷ�ʽΪTKIP.CNend
 */
#define WIFI_CIPHER_TKIP                 BIT(3)

/**
 * @ingroup hi_wifi_basic
 *
 * CCMP of cipher mode.CNcomment:���ܷ�ʽΪCCMP.CNend
 */
#define WIFI_CIPHER_CCMP                 BIT(4)

/**
 * @ingroup hi_wifi_basic
 *
 * Channel numbers of 2.4G frequency.CNcomment:2.4GƵ�ε��ŵ�����.CNend
 */
#define WIFI_24G_CHANNEL_NUMS 14

/**
 * @ingroup hi_wifi_basic
 *
 * max interiface name length.CNcomment:����ӿ�����󳤶�.CNend
 */
#define WIFI_IFNAME_MAX_SIZE             16

/**
 * @ingroup hi_wifi_basic
 *
 * The minimum timeout of a single reconnection.CNcomment:��С����������ʱʱ��.CNend
 */
#define WIFI_MIN_RECONNECT_TIMEOUT   2

/**
 * @ingroup hi_wifi_basic
 *
 * The maximum timeout of a single reconnection, representing an infinite number of loop reconnections.
 * CNcomment:��󵥴�������ʱʱ�䣬��ʾ���޴�ѭ������.CNend
 */
#define WIFI_MAX_RECONNECT_TIMEOUT   65535

/**
 * @ingroup hi_wifi_basic
 *
 * The minimum auto reconnect interval.CNcomment:��С�Զ��������ʱ��.CNend
 */
#define WIFI_MIN_RECONNECT_PERIOD    1

/**
 * @ingroup hi_wifi_basic
 *
 * The maximum auto reconnect interval.CNcomment:����Զ��������ʱ��.CNend
 */
#define WIFI_MAX_RECONNECT_PERIOD   65535

/**
 * @ingroup hi_wifi_basic
 *
 * The minmum times of auto reconnect.CNcomment:��С�Զ��������Ӵ���.CNend
 */
#define WIFI_MIN_RECONNECT_TIMES    1

/**
 * @ingroup hi_wifi_basic
 *
 * The maximum times of auto reconnect.CNcomment:����Զ��������Ӵ���.CNend
 */
#define WIFI_MAX_RECONNECT_TIMES   65535

/**
 * @ingroup hi_wifi_basic
 *
 * max scan number of ap.CNcomment:֧��ɨ��ap�������Ŀ.CNend
 */
#define WIFI_SCAN_AP_LIMIT               32

/**
 * @ingroup hi_wifi_basic
 *
 * length of status buff.CNcomment:��ȡ����״̬�ַ����ĳ���.CNend
 */
#define WIFI_STATUS_BUF_LEN_LIMIT        512

/**
 * @ingroup hi_wifi_basic
 *
 * Decimal only WPS pin code length.CNcomment:WPS��ʮ����pin�볤��.CNend
 */
#define WIFI_WPS_PIN_LEN              8

/**
 * @ingroup hi_wifi_basic
 *
 * default max num of vap.CNcomment:Ĭ��֧�ֵ��豸������.CNend
 */
#define WIFI_MAX_NUM_VAP              2

/**
 * @ingroup hi_wifi_basic
 *
 * default max num of user.CNcomment:Ĭ��֧�ֵ��û�������.CNend
 */
#define WIFI_MAX_NUM_USER             4

/**
 * @ingroup hi_wifi_basic
 *
 * default max num of station.CNcomment:Ĭ��֧�ֵ�station������.CNend
 */
#define WIFI_DEFAULT_MAX_NUM_STA        WIFI_MAX_NUM_USER

/**
 * @ingroup hi_wifi_basic
 *
 * return success value.CNcomment:���سɹ���ʶ.CNend
 */
#define HISI_OK                         0

/**
 * @ingroup hi_wifi_basic
 *
 * return failed value.CNcomment:����ֵ�����ʶ.CNend
 */
#define HISI_FAIL                       (-1)

/**
 * @ingroup hi_wifi_basic
 *
 * Max length of SSID.CNcomment:SSID��󳤶ȶ���.CNend
 */
#define HI_WIFI_MAX_SSID_LEN  32

/**
 * @ingroup hi_wifi_basic
 *
 * Length of MAC address.CNcomment:MAC��ַ���ȶ���.CNend
 */
#define HI_WIFI_MAC_LEN        6

/**
 * @ingroup hi_wifi_basic
 *
 * String length of bssid, eg. 00:00:00:00:00:00.CNcomment:bssid�ַ������ȶ���(00:00:00:00:00:00).CNend
 */
#define HI_WIFI_TXT_ADDR_LEN   17

/**
 * @ingroup hi_wifi_basic
 *
 * Length of Key.CNcomment:KEY ���볤�ȶ���.CNend
 */
#define HI_WIFI_AP_KEY_LEN     64

/**
 * @ingroup hi_wifi_basic
 *
 * Maximum  length of Key.CNcomment:KEY ������볤��.CNend
 */
#define HI_WIFI_MAX_KEY_LEN    64

/**
 * @ingroup hi_wifi_basic
 *
 * Return value of invalid channel.CNcomment:��Ч�ŵ�����ֵ.CNend
 */
#define HI_WIFI_INVALID_CHANNEL 0xFF

/**
 * @ingroup hi_wifi_basic
 *
 * Index of Vendor IE.CNcomment:Vendor IE �������.CNend
 */
#define HI_WIFI_VENDOR_IE_MAX_IDX 1

/**
 * @ingroup hi_wifi_basic
 *
 * Max length of Vendor IE.CNcomment:Vendor IE ��󳤶�.CNend
 */
#define HI_WIFI_VENDOR_IE_MAX_LEN 255

/**
 * @ingroup hi_wifi_basic
 *
 * Minimum length of custom's frame.CNcomment:�û����Ʊ�����С����ֵ.CNend
 */
#define HI_WIFI_CUSTOM_PKT_MIN_LEN 24

/**
 * @ingroup hi_wifi_basic
 *
 * Max length of custom's frame.CNcomment:�û����Ʊ�����󳤶�ֵ.CNend
 */
#define HI_WIFI_CUSTOM_PKT_MAX_LEN 1400

/**
 * @ingroup hi_wifi_basic
 *
 * Max num of retry.CNcomment:����ش���������.CNend
 */
#define HI_WIFI_RETRY_MAX_NUM               15

/**
 * @ingroup hi_wifi_basic
 *
 * Max time of retry.CNcomment:����ش������ʱ��.CNend
 */
#define HI_WIFI_RETRY_MAX_TIME              200

/**
 * @ingroup hi_wifi_basic
 *
 * Freq compensation param count.CNcomment:�����£�Ƶƫ������������.CNend
 */
#define HI_WIFI_FREQ_COMP_PARAM_CNT  3

/**
 * @ingroup hi_wifi_basic
 *
 * country code bits .CNcomment:�������ֽ���.CNend
 */
#define HI_WIFI_COUNTRY_CODE_BITS_CNT  3

/**
 * @ingroup hi_wifi_basic
 *
 * DBB scale param count.CNcomment:dbb scale��ز�������.CNend
 */
#define HI_WIFI_DBB_PARAM_CNT        7

/**
 * @ingroup hi_wifi_basic
 *
 * Ch depend tx power offset count.CNcomment:�ŵ���ط��͹��ʲ�������.CNend
 */
#define HI_WIFI_CH_TX_PWR_PARAM_CNT  13

/**
 * @ingroup hi_wifi_basic
 *
 * Reporting data type of monitor mode.CNcomment:����ģʽ�ϱ�����������.CNend
 */
typedef enum {
    HI_WIFI_MONITOR_OFF,                /**< close monitor mode. CNcomment: �رջ���ģʽ.CNend */
    HI_WIFI_MONITOR_MCAST_DATA,         /**< report multi-cast data frame. CNcomment: �ϱ��鲥(�㲥)���ݰ�.CNend */
    HI_WIFI_MONITOR_UCAST_DATA,         /**< report single-cast data frame. CNcomment: �ϱ��������ݰ�.CNend */
    HI_WIFI_MONITOR_MCAST_MANAGEMENT,   /**< report multi-cast mgmt frame. CNcomment: �ϱ��鲥(�㲥)�����.CNend */
    HI_WIFI_MONITOR_UCAST_MANAGEMENT,   /**< report sigle-cast mgmt frame. CNcomment: �ϱ����������.CNend */

    HI_WIFI_MONITOR_BUTT
} hi_wifi_monitor_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Definition of protocol frame type.CNcomment:Э�鱨�����Ͷ���.CNend
 */
typedef enum {
    HI_WIFI_PKT_TYPE_BEACON,        /**< Beacon packet. CNcomment: Beacon��.CNend */
    HI_WIFI_PKT_TYPE_PROBE_REQ,     /**< Probe Request packet. CNcomment: Probe Request��.CNend */
    HI_WIFI_PKT_TYPE_PROBE_RESP,    /**< Probe Response packet. CNcomment: Probe Response��.CNend */
    HI_WIFI_PKT_TYPE_ASSOC_REQ,     /**< Assoc Request packet. CNcomment: Assoc Request��.CNend */
    HI_WIFI_PKT_TYPE_ASSOC_RESP,    /**< Assoc Response packet. CNcomment: Assoc Response��.CNend */

    HI_WIFI_PKT_TYPE_BUTT
}hi_wifi_pkt_type;

/**
 * @ingroup hi_wifi_basic
 *
 * Interface type of wifi.CNcomment:wifi �ӿ�����.CNend
 */
typedef enum {
    HI_WIFI_IFTYPE_UNSPECIFIED,
    HI_WIFI_IFTYPE_ADHOC,
    HI_WIFI_IFTYPE_STATION = 2,         /**< Station. CNcomment: STA����.CNend */
    HI_WIFI_IFTYPE_AP = 3,              /**< SoftAp. CNcomment: SoftAp����.CNend */
    HI_WIFI_IFTYPE_AP_VLAN,
    HI_WIFI_IFTYPE_WDS,
    HI_WIFI_IFTYPE_MONITOR,
    HI_WIFI_IFTYPE_MESH_POINT = 7,      /**< Mesh. CNcomment: Mesh����.CNend */
    HI_WIFI_IFTYPE_P2P_CLIENT,
    HI_WIFI_IFTYPE_P2P_GO,
    HI_WIFI_IFTYPE_P2P_DEVICE,

    HI_WIFI_IFTYPES_BUTT
} hi_wifi_iftype;

/**
 * @ingroup hi_wifi_basic
 *
 * Definition of bandwith type.CNcomment:�ӿڴ�����.CNend
 */
typedef enum {
    HI_WIFI_BW_HIEX_5M,     /**< 5M bandwidth. CNcomment: խ��5M����.CNend */
    HI_WIFI_BW_HIEX_10M,    /**< 10M bandwidth. CNcomment: խ��10M����.CNend */
    HI_WIFI_BW_LEGACY_20M,  /**< 20M bandwidth. CNcomment: 20M����.CNend */
    HI_WIFI_BW_BUTT
} hi_wifi_bw;

/**
 * @ingroup hi_wifi_basic
 *
 * The protocol mode of softap and station interfaces.CNcomment:softap��station�ӿڵ�protocolģʽ.CNend
 */
typedef enum {
    HI_WIFI_PHY_MODE_11BGN, /**< 802.11BGN mode. CNcomment: 802.11BGN ģʽ.CNend */
    HI_WIFI_PHY_MODE_11BG,  /**< 802.11BG mode. CNcomment: 802.11BG ģʽ.CNend */
    HI_WIFI_PHY_MODE_11B,   /**< 802.11B mode. CNcomment: 802.11B ģʽ.CNend */
    HI_WIFI_PHY_MODE_BUTT
} hi_wifi_protocol_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Authentification type enum.CNcomment:��֤����(�������粻֧��HI_WIFI_SECURITY_WPAPSK).CNend
 */
typedef enum {
    HI_WIFI_SECURITY_OPEN,                  /**< OPEN. CNcomment: ��֤����:����.CNend */
    HI_WIFI_SECURITY_WEP,                   /**< WEP. CNcomment: ��֤����:WEP.CNend */
    HI_WIFI_SECURITY_WPA2PSK,               /**< WPA-PSK. CNcomment: ��֤����:WPA2-PSK.CNend */
    HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX,    /**< WPA/WPA2-PSK MIX. CNcomment: ��֤����:WPA-PSK/WPA2-PSK���.CNend */
    HI_WIFI_SECURITY_WPAPSK,                /**< WPA-PSK. CNcomment: ��֤����:WPA-PSK.CNend */
    HI_WIFI_SECURITY_WPA,                   /**< WPA. CNcomment: ��֤����:WPA.CNend */
    HI_WIFI_SECURITY_WPA2,                  /**< WPA2. CNcomment: ��֤����:WPA2.CNend */
    HI_WIFI_SECURITY_SAE,                   /**< SAE. CNcomment: ��֤����:SAE.CNend */
    HI_WIFI_SECURITY_UNKNOWN                /**< UNKNOWN. CNcomment: ������֤����:UNKNOWN.CNend */
} hi_wifi_auth_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Encryption type enum.CNcoment:��������.CNend
 *
 */
typedef enum {
    HI_WIFI_PARIWISE_UNKNOWN,               /**< UNKNOWN. CNcomment: ��������:UNKNOWN.CNend */
    HI_WIFI_PAIRWISE_AES,                   /**< AES. CNcomment: ��������:AES.CNend */
    HI_WIFI_PAIRWISE_TKIP,                  /**< TKIP. CNcomment: ��������:TKIP.CNend */
    HI_WIFI_PAIRWISE_TKIP_AES_MIX           /**< TKIP/AES MIX. CNcomment: ��������:TKIP AES���.CNend */
} hi_wifi_pairwise;

/**
 * @ingroup hi_wifi_basic
 *
 * PMF type enum.CNcomment:PMF����֡����ģʽ����.CNend
 */
typedef enum {
    HI_WIFI_MGMT_FRAME_PROTECTION_CLOSE,        /**< Disable. CNcomment: ����֡����ģʽ:�ر�.CNend */
    HI_WIFI_MGMT_FRAME_PROTECTION_OPTIONAL,     /**< Optional. CNcomment: ����֡����ģʽ:��ѡ.CNend */
    HI_WIFI_MGMT_FRAME_PROTECTION_REQUIRED      /**< Required. CNcomment: ����֡����ģʽ:����.CNend */
} hi_wifi_pmf_options;

/**
 * @ingroup hi_wifi_basic
 *
 * Type of connect's status.CNcomment:����״̬.CNend
 */
typedef enum {
    HI_WIFI_DISCONNECTED,   /**< Disconnected. CNcomment: ����״̬:δ����.CNend */
    HI_WIFI_CONNECTED,      /**< Connected. CNcomment: ����״̬:������.CNend */
} hi_wifi_conn_status;

/**
 * @ingroup hi_wifi_basic
 *
 * wifi's operation mode.CNcomment:wifi�Ĺ���ģʽ.CNend
 */
typedef enum {
    HI_WIFI_MODE_INFRA = 0,               /**< STAģʽ */
    HI_WIFI_MODE_AP    = 2,               /**< AP ģʽ */
    HI_WIFI_MODE_MESH  = 5                /**< MESH ģʽ */
} hi_wifi_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of WiFi event.CNcomment:WiFi���¼�����.CNend
 */
typedef enum {
    HI_WIFI_EVT_UNKNOWN,             /**< UNKNWON. CNcomment: UNKNOWN.CNend */
    HI_WIFI_EVT_SCAN_DONE,           /**< Scan finish. CNcomment: STAɨ�����.CNend */
    HI_WIFI_EVT_CONNECTED,           /**< Connected. CNcomment: ������.CNend */
    HI_WIFI_EVT_DISCONNECTED,        /**< Disconnected. CNcomment: �Ͽ�����.CNend */
    HI_WIFI_EVT_WPS_TIMEOUT,         /**< WPS timeout. CNcomment: WPS�¼���ʱ.CNend */
    HI_WIFI_EVT_MESH_CONNECTED,      /**< MESH connected. CNcomment: MESH������.CNend */
    HI_WIFI_EVT_MESH_DISCONNECTED,   /**< MESH disconnected. CNcomment: MESH�Ͽ�����.CNend */
    HI_WIFI_EVT_AP_START,            /**< AP start. CNcomment: AP����.CNend */
    HI_WIFI_EVT_STA_CONNECTED,       /**< STA connected with ap. CNcomment: AP��STA������.CNend */
    HI_WIFI_EVT_STA_DISCONNECTED,    /**< STA disconnected from ap. CNcomment: AP��STA�Ͽ�����.CNend */
    HI_WIFI_EVT_STA_FCON_NO_NETWORK, /**< STA connect, but can't find network. CNcomment: STA����ʱɨ�費������.CNend */
    HI_WIFI_EVT_MESH_CANNOT_FOUND,   /**< MESH can't find network. CNcomment: MESH����ɨ�����Զ�.CNend */
    HI_WIFI_EVT_MESH_SCAN_DONE,      /**< MESH AP scan finish. CNcomment: MESH APɨ�����.CNend */
    HI_WIFI_EVT_MESH_STA_SCAN_DONE,  /**< MESH STA scan finish. CNcomment: MESH STAɨ�����.CNend */
    HI_WIFI_EVT_AP_SCAN_DONE,        /**< AP scan finish. CNcomment: APɨ�����.CNend */
    HI_WIFI_EVT_BUTT
} hi_wifi_event_type;

/**
 * @ingroup hi_wifi_basic
 *
 * Scan type enum.CNcomment:ɨ������.CNend
 */
typedef enum {
    HI_WIFI_BASIC_SCAN,             /**< Common and all channel scan. CNcomment: ��ͨɨ��.CNend */
    HI_WIFI_CHANNEL_SCAN,           /**< Specified channel scan. CNcomment: ָ���ŵ�ɨ��.CNend */
    HI_WIFI_SSID_SCAN,              /**< Specified SSID scan. CNcomment: ָ��SSIDɨ��.CNend */
    HI_WIFI_SSID_PREFIX_SCAN,       /**< Prefix SSID scan. CNcomment: SSIDǰ׺ɨ��.CNend */
    HI_WIFI_BSSID_SCAN,             /**< Specified BSSID scan. CNcomment: ָ��BSSIDɨ��.CNend */
} hi_wifi_scan_type;

/**
 * @ingroup iot_lp
 * Sleep level enumeration.
 */
typedef enum {
    HI_NO_SLEEP,    /**< no sleep type.CNcomment:��˯ģʽ CNend */
    HI_LIGHT_SLEEP, /**< light sleep type.CNcomment:ǳ˯ģʽ CNend */
    HI_DEEP_SLEEP,  /**< deep sleep type.CNcomment:��˯ģʽ CNend */
} hi_plat_type;

/**
 * @ingroup hi_wifi_basic
 * wow pattern type
*/
typedef enum {
    HI_WOW_PATTERN_ADD,
    HI_WOW_PATTERN_DEL,
    HI_WOW_PATTERN_CLR,
} hi_wifi_wow_pattern_type;

/**
 * @ingroup hi_wifi_basic
 *
 * parameters of scan.CNcomment:station�ӿ�scan����.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID. CNcomment: SSID ֻ֧��ASCII�ַ�.CNend */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID. CNcomment: BSSID.CNend */
    unsigned char ssid_len;                 /**< SSID length. CNcomment: SSID����.CNend */
    unsigned char channel;                  /**< Channel number. CNcomment: �ŵ��ţ���Χ1-14����ͬ�����в���.CNend */
    hi_wifi_scan_type scan_type;            /**< Scan type. CNcomment: ɨ������.CNend */
} hi_wifi_scan_params;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of scan result.CNcomment:ɨ�����ṹ��.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID. CNcomment: SSID ֻ֧��ASCII�ַ�.CNend */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID. CNcomment: BSSID.CNend */
    unsigned int channel;                   /**< Channel number. CNcomment: �ŵ��ţ���Χ1-14����ͬ�����в���.CNend */
    hi_wifi_auth_mode auth;                 /**< Authentication type. CNcomment: ��֤����.CNend */
    int rssi;                               /**< Signal Strength. CNcomment: �ź�ǿ��.CNend */
    unsigned char wps_flag : 1;             /**< WPS flag. CNcomment: WPS��ʶ.CNend */
    unsigned char wps_session : 1;          /**< WPS session:PBC-0/PIN-1. CNcomment: WPS�Ự����,PBC-0/PIN-1.CNend */
    unsigned char wmm : 1;                  /**< WMM flag. CNcomment: WMM��ʶ.CNend */
    unsigned char resv : 1;                 /**< Reserved. CNcomment: Ԥ��.CNend */
    unsigned char hisi_mesh_flag : 1;       /**< MESH flag. CNcomment: MESH��ʶ.CNend */
} hi_wifi_ap_info;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of connect parameters.CNcomment:station���ӽṹ��.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID. CNcomment: SSID ֻ֧��ASCII�ַ�.CNend */
    hi_wifi_auth_mode auth;                 /**< Authentication mode. CNcomment: ��֤����.CNend */
    char key[HI_WIFI_MAX_KEY_LEN + 1];      /**< Secret key. CNcomment: ��Կ.CNend */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID. CNcomment: BSSID.CNend */
    hi_wifi_pairwise pairwise;              /**< Encryption type. CNcomment: ���ܷ�ʽ,����ָ��ʱ��0.CNend */
} hi_wifi_assoc_request;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of fast connect parameters.CNcomment:station�������ӽṹ��.CNend
 */
typedef struct {
    hi_wifi_assoc_request req;              /**< Association request. CNcomment: ��������.CNend */
    unsigned char channel;                  /**< Channel number. CNcomment: �ŵ��ţ���Χ1-14����ͬ�����в���.CNend */
} hi_wifi_fast_assoc_request;

/**
 * @ingroup hi_wifi_basic
 *
 * Status of sta's connection.CNcomment:��ȡstation����״̬.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID. CNcomment: SSID ֻ֧��ASCII�ַ�.CNend */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID. CNcomment: BSSID.CNend */
    unsigned int channel;                   /**< Channel number. CNcomment: �ŵ��ţ���Χ1-14����ͬ�����в���.CNend */
    hi_wifi_conn_status status;             /**< Connect status. CNcomment: ����״̬.CNend */
} hi_wifi_status;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of wifi scan done.CNcomment:ɨ������¼�.CNend
 */
typedef struct {
    unsigned short bss_num;                 /**< numbers of scan result. CNcomment: ɨ�赽��ap��Ŀ.CNend */
} event_wifi_scan_done;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of wifi connected CNcomment:wifi��connect�¼���Ϣ.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID. CNcomment: SSID ֻ֧��ASCII�ַ�.CNend */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID. CNcomment: BSSID.CNend */
    unsigned char ssid_len;                 /**< SSID length. CNcomment: SSID����.CNend */
    char ifname[WIFI_IFNAME_MAX_SIZE + 1];  /**< Iftype name. CNcomment: �ӿ�����.CNend */
} event_wifi_connected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of wifi disconnected.CNcomment:wifi�ĶϿ��¼���Ϣ.CNend
 */
typedef struct {
    unsigned char bssid[HI_WIFI_MAC_LEN];    /**< BSSID. CNcomment: BSSID.CNend */
    unsigned short reason_code;              /**< reason code. CNcomment: �Ͽ�ԭ��.CNend */
    char ifname[WIFI_IFNAME_MAX_SIZE + 1];   /**< Iftype name. CNcomment: �ӿ�����.CNend */
} event_wifi_disconnected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of ap connected sta.CNcomment:ap����sta�¼���Ϣ.CNend
 */
typedef struct {
    char addr[HI_WIFI_MAC_LEN];    /**< user's mac address of SoftAp. CNcomment: ����AP��sta��ַ.CNend */
} event_ap_sta_connected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of ap disconnected sta.CNcomment:ap�Ͽ�sta�¼���Ϣ.CNend
 */
typedef struct {
    unsigned char addr[HI_WIFI_MAC_LEN];    /**< User's mac address of SoftAp. CNcomment: AP�Ͽ�STA��MAC��ַ.CNend */
    unsigned short reason_code;             /**< Reason code. CNcomment: AP�Ͽ����ӵ�ԭ��ֵ.CNend */
} event_ap_sta_disconnected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of ap start.CNcomment:ap�����¼���Ϣ.CNend
 */
typedef struct {
    char ifname[WIFI_IFNAME_MAX_SIZE + 1];  /**< Iftype name. CNcomment: �ӿ�����.CNend */
} event_ap_start;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of mesh connected.CNcomment:mesh��connect�¼���Ϣ.CNend
 */
typedef struct {
    unsigned char addr[HI_WIFI_MAC_LEN];    /**< User's mac address of MESH. CNcomment: MESH���ӵ�peer MAC��ַ.CNend */
} event_mesh_connected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of mesh disconnected.CNcomment:mesh��disconnect�¼���Ϣ.CNend
 */
typedef struct {
    unsigned char addr[HI_WIFI_MAC_LEN];    /**< User's mac address of MESH. CNcomment: �Ͽ����ӵ�peer MAC��ַ.CNend */
    unsigned short reason_code;             /**< Reason code. CNcomment: MESH�Ͽ����ӵ�ԭ��.CNend */
} event_mesh_disconnected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type wifi information.CNcomment:wifi���¼���Ϣ��.CNend
 */
typedef union {
    event_wifi_scan_done wifi_scan_done;            /**< Scan finish event. CNcomment: WIFIɨ������¼���Ϣ.CNend */
    event_wifi_connected wifi_connected;            /**< STA's connected event. CNcomment: STA�������¼���Ϣ.CNend */
    event_wifi_disconnected wifi_disconnected;      /**< STA's dsiconnected event. CNcomment: STA�Ķ����¼���Ϣ.CNend */
    event_ap_sta_connected ap_sta_connected;        /**< AP's connected event . CNcomment: AP�������¼���Ϣ.CNend */
    event_ap_sta_disconnected ap_sta_disconnected;  /**< AP's disconnected event. CNcomment: AP�Ķ����¼���Ϣ.CNend */
    event_ap_start ap_start;                        /**< AP's start success event. CNcomment: AP�����ɹ���Ϣ.CNend */
    event_mesh_connected mesh_connected;            /**< MESH's connected event. CNcomment: MESH�����¼���Ϣ.CNend */
    event_mesh_disconnected mesh_disconnected;      /**< MESH's disconnected event. CNcomment: MESH�����¼���Ϣ.CNend */
} hi_wifi_event_info;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of WiFi event.CNcomment:WiFi�¼��ṹ��.CNend
 *
 */
typedef struct {
    hi_wifi_event_type event;   /**< Event type. CNcomment: �¼�����.CNend */
    hi_wifi_event_info info;    /**< Event information. CNcomment: �¼���Ϣ.CNend */
} hi_wifi_event;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of softap's basic config.CNcomment:softap��������.CNend
 *
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID. CNcomment: SSID ֻ֧��ASCII�ַ�.CNend */
    char key[HI_WIFI_AP_KEY_LEN + 1];       /**< Secret key. CNcomment: ��Կ.CNend */
    unsigned char channel_num;              /**< Channel number. CNcomment: �ŵ��ţ���Χ1-14����ͬ�����в���.CNend */
    int ssid_hidden;                        /**< Hidden ssid. CNcomment: �Ƿ�����SSID.CNend */
    hi_wifi_auth_mode authmode;             /**< Authentication mode. CNcomment: ��֤��ʽ.CNend */
    hi_wifi_pairwise pairwise;              /**< Encryption type. CNcomment: ���ܷ�ʽ,����ָ��ʱ��0.CNend */
} hi_wifi_softap_config;

/**
 * @ingroup hi_wifi_basic
 *
 * mac address of softap's user.CNcomment:��softap������station mac��ַ.CNend
 *
 */
typedef struct {
    unsigned char mac[HI_WIFI_MAC_LEN];     /**< MAC address.CNcomment:��softap������station mac��ַ.CNend */
} hi_wifi_ap_sta_info;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of frame filter config in monitor mode.CNcomment:����ģʽ���Ľ��չ�������.CNend
 */
typedef struct {
    char mdata_en : 1;  /**< get multi-cast data frame flag. CNcomment: ʹ�ܽ����鲥(�㲥)���ݰ�.CNend */
    char udata_en : 1;  /**< get single-cast data frame flag. CNcomment: ʹ�ܽ��յ������ݰ�.CNend */
    char mmngt_en : 1;  /**< get multi-cast mgmt frame flag. CNcomment: ʹ�ܽ����鲥(�㲥)�����.CNend */
    char umngt_en : 1;  /**< get single-cast mgmt frame flag. CNcomment: ʹ�ܽ��յ��������.CNend */
    char resvd    : 4;  /**< reserved bits. CNcomment: �����ֶ�.CNend */
} hi_wifi_ptype_filter;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of customize params.CNcomment:���ö��ƻ�����.CNend
 */
typedef struct {
    char country_code[HI_WIFI_COUNTRY_CODE_BITS_CNT];
    int rssi_offset;
    int freq_comp[HI_WIFI_FREQ_COMP_PARAM_CNT];
    unsigned int dbb_params[HI_WIFI_DBB_PARAM_CNT];
    unsigned int ch_txpwr_offset[HI_WIFI_CH_TX_PWR_PARAM_CNT];
} hi_wifi_customize_params;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of report datarate.CNcomment:����������.CNend
 */
typedef struct {
    unsigned int be_datarate;
    unsigned int be_avg_retry;
    unsigned int bk_datarate;
    unsigned int bk_avg_retry;
    unsigned int vi_datarate;
    unsigned int vi_avg_retry;
    unsigned int vo_datarate;
    unsigned int vo_avg_retry;
} hi_wifi_report_tx_params;

typedef enum {
    DEV_PANIC = 1,
    DRIVER_HUNG,
    UNKNOWN,
} hi_wifi_driver_event;

/**
 * @ingroup hi_wifi_basic
 *
 * report driving events to application layer.CNcommment:��Ӧ�ò��ϱ������¼�.CNend
 */
typedef  int (*hi_wifi_driver_event_cb)(hi_wifi_driver_event event);

/**
 * @ingroup hi_wifi_basic
 *
 * callback function definition of monitor mode.CNcommment:����ģʽ�հ��ص��ӿڶ���.CNend
 */
typedef int (*hi_wifi_promis_cb)(void* recv_buf, int frame_len, signed char rssi);

/**
 * @ingroup hi_wifi_basic
 *
 * callback function definition of wifi event.CNcommment:wifi�¼��ص��ӿڶ���.CNend
 */
typedef void (*hi_wifi_event_cb)(const hi_wifi_event *event);

/**
 * @ingroup hi_wifi_basic
 *
 * callback function definition of wifi event to get goodput and average send times.
 * CNcommment:wifi��ȡ��������ƽ�����ʹ����¼��ص��ӿڶ���.CNend
 */
typedef unsigned int (*hi_wifi_report_tx_params_callback)(hi_wifi_report_tx_params*);

/**
* @ingroup  hi_wifi_basic
* @brief  Wifi initialize.CNcomment:wifi��ʼ��.CNend
*
* @par Description:
        Wifi driver initialize.CNcomment:wifi������ʼ����������wifi�豸.CNend
*
* @attention  NULL
* @param  vap_res_num   [IN]  Type #const unsigned char, vap num[rang: 1-2].CNcomment:vap��Դ������ȡֵ[1-2].CNend
* @param  user_res_num  [IN]  Type #const unsigned char, user resource num[1-4].
*           CNcomment:�û���Դ��������vapʱ����ȡֵ[1-4].CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_init(const unsigned char vap_res_num, const unsigned char user_res_num);


/**
* @ingroup  hi_wifi_basic
* @brief  Wifi de-initialize.CNcomment:wifiȥ��ʼ��.CNend
*
* @par Description:
*           Wifi driver de-initialize.CNcomment:wifi����ȥ��ʼ��.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_deinit(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set protocol mode of sta.CNcomment:����station�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Set protocol mode of sta, set before calling hi_wifi_sta_start().\n
*           CNcomment:����station�ӿڵ�protocolģʽ, ��sta start֮ǰ����.CNend
*
* @attention  Default mode 802.11BGN CNcomment:Ĭ��ģʽ 802.11BGN.CNend
* @param  mode            [IN]     Type #hi_wifi_protocol_mode, protocol mode.
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_set_protocol_mode(hi_wifi_protocol_mode mode);

/**
* @ingroup  hi_wifi_basic
* @brief  Get protocol mode of.CNcomment:��ȡstation�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Get protocol mode of station.CNcomment:��ȡstation�ӿڵ�protocolģʽ.CNend
*
* @attention  NULL
* @param      NULL
*
* @retval #hi_wifi_protocol_mode protocol mode.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
hi_wifi_protocol_mode hi_wifi_sta_get_protocol_mode(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Config pmf settings of sta.CNcomment:����station��pmf.CNend
*
* @par Description:
*           Config pmf settings of sta, set before sta start.CNcomment:����station��pmf, ��sta start֮ǰ����.CNend
*
* @attention  Default pmf enum value 1. CNcomment:Ĭ��pmfö��ֵ1.CNend
* @param  pmf           [IN]     Type #hi_wifi_pmf_options, pmf enum value.CNcoment:pmfö��ֵ.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_pmf(hi_wifi_pmf_options pmf);

/**
* @ingroup  hi_wifi_basic
* @brief  Get pmf settings of sta.CNcomment:��ȡstation��pmf����.CNend
*
* @par Description:
*           Get pmf settings of sta.CNcomment:��ȡstation��pmf����.CNend
*
* @attention  NULL
* @param      NULL
*
* @retval #hi_wifi_pmf_options pmf enum value.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
hi_wifi_pmf_options hi_wifi_get_pmf(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Start wifi station.CNcomment:����STA.CNend
*
* @par Description:
*           Start wifi station.CNcomment:����STA.CNend
*
* @attention  1. Multiple interfaces of the same type are not supported.CNcomment:1. ��֧��ʹ�ö��ͬ���ͽӿ�.CNend\n
*             2. Dual interface coexistence support: STA + AP or STA + MESH.
*                CNcomment:2. ˫�ӿڹ���֧�֣�STA + AP or STA + MESH.CNend\n
*             3. Start timeout 5s.CNcomment:3. ������ʱʱ��5s.CNend\n
*             4. The memories of <ifname> and <len> should be requested by the caller��
*                the input value of len must be the same as the length of ifname��the recommended length is 17Bytes��.\n
*                CNcomment:4. <ifname>��<len>�ɵ����������ڴ棬�û�д��len��ֵ������ifname����һ�£����鳤��Ϊ17Bytes��.CNend
* @param  ifname          [IN/OUT]     Type #char *, device name.CNcomment:�ӿ���.CNend
* @param  len             [IN/OUT]     Type #int *, length of device name.CNcomment:�ӿ�������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_start(char *ifname, int *len);

/**
* @ingroup  hi_wifi_basic
* @brief  Close wifi station.CNcomment:�ر�STA.CNend
*
* @par Description:
*           Close wifi station.CNcomment:�ر�STA.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_stop(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Start sta basic scanning in all channels.CNcomment:station����ȫ�ŵ�����ɨ��.CNend
*
* @par Description:
*           Start sta basic scanning in all channels.CNcomment:����stationȫ�ŵ�����ɨ��.CNend
*
* @attention  NULL
* @param     NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_scan(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Start station scanning with specified parameter.CNcomment:stationִ�д��ض�������ɨ��.CNend
*
* @par Description:
*           Start station scanning with specified parameter.CNcomment:stationִ�д��ض�������ɨ��.CNend
*
* @attention  1. advance scan can scan with ssid only,channel only,bssid only,prefix_ssid only��
*                and the combination parameters scanning does not support.\n
*             CNcomment:1. �߼�ɨ��ֱ𵥶�֧�� ssidɨ�裬�ŵ�ɨ�裬bssidɨ�裬ssidǰ׺ɨ��, ��֧����ϲ���ɨ�跽ʽ.CNend\n
*             2. Scanning mode, subject to the type set by scan_type.
*              CNcomment:2 .ɨ�跽ʽ����scan_type���������Ϊ׼��CNend\n
*             3. SSID only supports ASCII characters.
*                CNcomment:3. SSID ֻ֧��ASCII�ַ�.CNend
* @param  sp            [IN]    Type #hi_wifi_scan_params * parameters of scan.CNcomment:ɨ�������������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_advance_scan(hi_wifi_scan_params *sp);

/**
* @ingroup  hi_wifi_basic
* @brief  sta start scan.CNcomment:station����ɨ��.CNend
*
* @par Description:
*           Get station scan result.CNcomment:��ȡstationɨ����.CNend
* @attention  1. The memories of <ap_list> and <ap_num> memories are requested by the caller. \n
*             The <ap_list> size up to : sizeof(hi_wifi_ap_info ap_list) * 32. \n
*             CNcomment:1. <ap_list>��<ap_num>�ɵ����������ڴ�,
*             <ap_list>size���Ϊ��sizeof(hi_wifi_ap_info ap_list) * 32.CNend \n
*             2. ap_num: parameters can be passed in to specify the number of scanned results.The maximum is 32. \n
*             CNcomment:2. ap_num: ���Դ��������ָ����ȡɨ�赽�Ľ�����������Ϊ32��CNend \n
*             3. If the user callback function is used, ap num refers to bss_num in event_wifi_scan_done. \n
*             CNcomment:3. ���ʹ���ϱ��û��Ļص�������ap_num�ο�event_wifi_scan_done�е�bss_num��CNend \n
*             4. ap_num should be same with number of hi_wifi_ap_info structures applied,
*                Otherwise, it will cause memory overflow. \n
*             CNcomment:4. ap_num�������hi_wifi_ap_info�ṹ������һ�£������������ڴ������CNend \n
*             5. SSID only supports ASCII characters. \n
*             CNcomment:5. SSID ֻ֧��ASCII�ַ�.CNend \n
*             6. The rssi in the scan results needs to be divided by 100 to get the actual rssi.\n
*             CNcomment:6. ɨ�����е�rssi��Ҫ����100���ܻ��ʵ�ʵ�rssi.CNend
* @param  ap_list         [IN/OUT]    Type #hi_wifi_ap_info * scan result.CNcomment:ɨ��Ľ��.CNend
* @param  ap_num          [IN/OUT]    Type #unsigned int *, number of scan result.CNcomment:ɨ�赽��������Ŀ.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_scan_results(hi_wifi_ap_info *ap_list, unsigned int *ap_num);

/**
* @ingroup  hi_wifi_basic
* @brief  sta start connect.CNcomment:station������������.CNend
*
* @par Description:
*           sta start connect.CNcomment:station������������.CNend
*
* @attention  1.<ssid> and <bssid> cannot be empty at the same time. CNcomment:1. <ssid>��<bssid>����ͬʱΪ��.CNend\n
*             2. When <auth_type> is set to OPEN, the <passwd> parameter is not required.
*                CNcomment:2. <auth_type>����ΪOPENʱ������<passwd>����.CNend\n
*             3. This function is non-blocking.CNcomment:3. �˺���Ϊ������ʽ.CNend\n
*             4. Pairwise can be set, default is 0.CNcomment:4. pairwise ������, Ĭ��Ϊ0.CNend\n
*             5. If the station is already connected to a network, disconnect the existing connection and
*                then connect to the new network.\n
*                CNcomment:5. ��station�ѽ���ĳ�����磬���ȶϿ��������ӣ�Ȼ������������.CNend\n
*             6. If the wrong SSID, BSSID or key is passed in, the HISI_OK will be returned,
*                but sta cannot connect the ap.
*                CNcomment:6. �����������ssid��bssid���߲���ȷ�����룬���سɹ���������apʧ�ܡ�CNend\n
*             7. SSID only supports ASCII characters.
*                CNcomment:7. SSID ֻ֧��ASCII�ַ�.CNend \n
*             8. Only support auth mode as bellow:
*                 HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX,
*                 HI_WIFI_SECURITY_WPA2PSK,
*                 HI_WIFI_SECURITY_WEP,
*                 HI_WIFI_SECURITY_OPEN
*                CNcomment:8. ֻ֧��������֤ģʽ��
*                 HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX,
*                 HI_WIFI_SECURITY_WPA2PSK,
*                 HI_WIFI_SECURITY_WEP,
*                 HI_WIFI_SECURITY_OPEN \n
*             9. WEP supports 64 bit and 128 bit encryption.
*                for 64 bit encryption, the encryption key is 10 hexadecimal characters or 5 ASCII characters;
*                for 128 bit encryption, the encryption key is 26 hexadecimal characters or 13 ASCII characters��\n
*                CNcomment:9. WEP֧��64λ��128λ���ܣ�����64λ���ܣ�������ԿΪ10��ʮ�������ַ���5��ASCII�ַ���
*                          ����128λ���ܣ�������ԿΪ26��ʮ�������ַ���13��ASCII�ַ���CNend\n
*            10. When the key of WEP is in the form of ASCII character,
*                the key in the input struct needs to be added with double quotation marks;
*                when the key of WEP is in the form of hexadecimal character,
*                the key in the input struct does not need to add double quotation marks.\n
*                CNcomment:10. WEP����ԿΪASCIl�ַ���ʽʱ����νṹ���е�key��Ҫ���˫���ţ�
*                          WEP����ԿΪΪʮ�������ַ�ʱ����νṹ���е�key����Ҫ���˫���š�CNend\n
*
* @param  req    [IN]    Type #hi_wifi_assoc_request * connect parameters of network.CNcomment:���������������.CNend
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_connect(hi_wifi_assoc_request *req);

/**
* @ingroup  hi_wifi_basic
* @brief  Start fast connect.CNcomment:station���п�����������.CNend
*
* @par Description:
*           Start fast connect.CNcomment:station���п�����������.CNend
*
* @attention  1. <ssid> and <bssid> cannot be empty at the same time. CNcomment:1��<ssid>��<bssid>����ͬʱΪ��.CNend\n
*             2. When <auth_type> is set to OPEN, the <passwd> parameter is not required.
*                CNcomment:2��<auth_type>����ΪOPENʱ������<passwd>����.CNend\n
*             3. <chn> There are differences in the range of values, and China is 1-13.
*                CNcomment:3��<chn>ȡֵ��Χ��ͬ�����в��죬�й�Ϊ1-13.CNend\n
*             4. This function is non-blocking.CNcomment:4���˺���Ϊ������ʽ.CNend\n
*             5. Pairwise can be set, set to zero by default.CNcomment:5. pairwise ������,Ĭ������.CNend\n
*             6. If the wrong SSID, BSSID or key is passed in, the HISI_FAIL will be returned,
*                and sta cannot connect the ap.
*                CNcomment:7. �����������ssid��bssid���߲���ȷ�����룬����ʧ�ܲ�������apʧ�ܡ�CNend\n
*             7. SSID only supports ASCII characters.
*                CNcomment:8. SSID ֻ֧��ASCII�ַ�.CNend \n
* @param fast_request [IN] Type #hi_wifi_fast_assoc_request *,fast connect parameters. CNcomment:���������������.CNend

* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_fast_connect(hi_wifi_fast_assoc_request *fast_request);

/**
* @ingroup  hi_wifi_basic
* @brief  Disconnect from network.CNcomment:station�Ͽ�����������.CNend
*
* @par Description:
*           Disconnect from network.CNcomment:station�Ͽ�����������.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_disconnect(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set reconnect policy.CNcomment:station�������������������.CNend
*
* @par Description:
*           Set reconnect policy.CNcomment:station�������������������.CNend
*
* @attention  1. It is recommended called after STA start or connected successfully.
*             CNcomment:1. ��STA��������߹����ɹ�����øýӿ�.CNend\n
*             2. The reconnection policy will be triggered when the station is disconnected from ap.\n
*             CNcomment:2. �������ƽ���station��һ��ȥ����ʱ��Ч,��ǰ�Ѿ�ȥ����������Ч.CNend\n
*             3. The Settings will take effect on the next reconnect timer.\n
*             CNcomment:3. �ع��������и����ع������ý�����һ��������ʱ��Ч.CNend\n
*             4. After calling station connect/disconnect or station stop, stop reconnecting.
*             CNcomment:4. ����station connect/disconnect��station stop��ֹͣ����.CNend\n
*             5. If the target network cannot be found by scanning,
                 the reconnection policy cannot trigger to take effect.\n
*             CNcomment:5. ��ɨ�費��Ŀ�����磬���������޷�������Ч.CNend\n
*             6. When the <seconds> value is 65535, it means infinite loop reconnection.
*             CNcomment:6. <seconds>ȡֵΪ65535ʱ����ʾ���޴�ѭ������.CNend\n
*             7.Enable reconnect, user and lwip will not receive disconnect event when disconnected from ap until 15
*               seconds later and still don't reconnect to ap successfully.
*             CNcomment:7. ʹ���Զ�����,wifi����15s�ڳ����Զ��������ڴ��ڼ䲻�ϱ�ȥ�����¼����û���lwipЭ��ջ,
*                          ����15���������ɹ��û����ϲ����粻��֪.CNend\n
*             8.Must call again if add/down/delete SoftAp or MESH's interface status after last call.
*             CNcomment:8. ���ú�������/����/ɾ����SoftAp,MESH�ӿڵ�״̬,��Ҫ�ٴε��øýӿ�.CNend\n

* @param  enable        [IN]    Type #int enable reconnect.0-disable/1-enable.CNcomment:ʹ�������������.CNend
* @param  seconds       [IN]    Type #unsigned int reconnect timeout in seconds for once, range:[2-65535].
*                                                  CNcomment:����������ʱʱ�䣬ȡֵ[2-65535].CNend
* @param  period        [IN]    Type #unsigned int reconnect period in seconds, range:[1-65535].
                                                   CNcomment:����������ڣ�ȡֵ[1-65535].CNend
* @param  max_try_count [IN]    Type #unsigned int max reconnect try count number��range:[1-65535].
                                                   CNcomment:�������������ȡֵ[1-65535].CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_set_reconnect_policy(int enable, unsigned int seconds,
    unsigned int period, unsigned int max_try_count);

/**
* @ingroup  hi_wifi_basic
* @brief  Get status of sta.CNcomment:��ȡstation���ӵ�����״̬.CNend
*
* @par Description:
*           Get status of sta.CNcomment:��ȡstation���ӵ�����״̬.CNend
*
* @attention  NULL
* @param  connect_status  [IN/OUT]    Type #hi_wifi_status *, connect status�� memory is requested by the caller.
*                                                             CNcomment:����״̬, �ɵ����������ڴ�.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_get_connect_info(hi_wifi_status *connect_status);

/**
* @ingroup  hi_wifi_basic
* @brief  Start pbc connect in WPS.CNcomment:����WPS����pbc����.CNend
*
* @par Description:
*           Start pbc connect in WPS.CNcomment:����WPS����pbc����.CNend
*
* @attention  1. bssid can be NULL or MAC. CNcomment:1. bssid ����ָ��mac������NULL.CNend
* @param  bssid   [IN]  Type #unsigned char * mac address
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_wps_pbc(unsigned char *bssid);

/**
* @ingroup  hi_wifi_basic
* @brief  Start pin connect in WPS.CNcomment:WPSͨ��pin����������.CNend
*
* @par Description:
*           Start pin connect in WPS.CNcomment:WPSͨ��pin����������.CNend
*
* @attention  1. Bssid can be NULL or MAC. CNcomment:1. bssid ����ָ��mac������NULL.CNend \n
*             2. Decimal only WPS pin code length is 8 Bytes.CNcomment:2. WPS��pin�����ʮ���ƣ�����Ϊ8 Bytes.CNend
* @param  pin      [IN]   Type #char * pin code
* @param  bssid    [IN]   Type #unsigned char * mac address
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_wps_pin(char *pin, unsigned char *bssid);

/**
* @ingroup  hi_wifi_basic
* @brief  Get pin code.CNcomment:WPS��ȡpin��.CNend
*
* @par Description:
*           Get pin code.CNcomment:WPS��ȡpin��.CNend
*
* @attention  Decimal only WPS pin code length is 8 Bytes.CNcomment:WPS��pin�����ʮ���ƣ�����Ϊ8 Bytes.CNend
* @param  pin    [IN/OUT]   Type #char *, pin code buffer, should be obtained, length is 9 Bytes.
*                                                               The memory is requested by the caller.\n
*                                       CNcomment:����ȡpin��,����Ϊ9 Bytes���ɵ����������ڴ�.CNend
* @param  len    [IN]   Type #unsigned int, length of pin code.CNcomment:pin��ĳ���.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_wps_pin_get(char* pin, unsigned int len);

/**
* @ingroup  hi_wifi_basic
* @brief  register user callback interface.CNcomment:ע��ص������ӿ�.CNend
*
* @par Description:
*           register user callback interface.CNcomment:ע��ص������ӿ�.CNend
*
* @attention  NULL
* @param  event_cb  [OUT]    Type #hi_wifi_event_cb, event callback .CNcomment:�ص�����.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_register_event_callback(hi_wifi_event_cb event_cb);

/**
* @ingroup  hi_wifi_basic
* @brief  Set protocol mode of softap.CNcomment:����softap�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Set protocol mode of softap.CNcomment:����softap�ӿڵ�protocolģʽ.CNend\n
*           Initiallize config, set before softap start.CNcomment:��ʼ����,��softap start֮ǰ����.CNend
*
* @attention  Default mode(802.11BGN) CNcomment:Ĭ��ģʽ��802.11BGN��.CNend
* @param  mode            [IN]     Type  #hi_wifi_protocol_mode protocol mode.
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_set_protocol_mode(hi_wifi_protocol_mode mode);

/**
* @ingroup  hi_wifi_basic
* @brief  Get protocol mode of softap.CNcomment:��ȡsoftap�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Get protocol mode of softap.CNcomment:��ȡsoftap�ӿڵ�protocolģʽ.CNend
*
* @attention  NULL
* @param      NULL
*
* @retval #hi_wifi_protocol_mode protocol mode.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
hi_wifi_protocol_mode hi_wifi_softap_get_protocol_mode(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set softap's beacon interval.CNcomment:����softap��beacon����.CNend
*
* @par Description:
*           Set softap's beacon interval.CNcomment:����softap��beacon����.CNend. \n
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend
*
* @attention  NULL
* @param  beacon_period      [IN]     Type  #int beacon period in milliseconds, range(33ms~1000ms), default(100ms)
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_set_beacon_period(int beacon_period);

/**
* @ingroup  hi_wifi_basic
* @brief  Set softap's dtim count.CNcomment:����softap��dtim����.CNend
*
* @par Description:
*           Set softap's dtim count.CNcomment:����softap��dtim����.CNend \n
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend
*
* @attention  NULL
* @param  dtim_period     [IN]     Type  #int, dtim period , range(1~30), default(2)
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_set_dtim_period(int dtim_period);

/**
* @ingroup  hi_wifi_basic
* @brief  Set update time of softap's group key.CNcomment:����softap�鲥��Կ����ʱ��.CNend
*
* @par Description:
*           Set update time of softap's group key.CNcomment:����softap�鲥��Կ����ʱ��.CNend\n
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend\n
*           If you need to use the rekey function, it is recommended to use WPA+WPA2-PSK + CCMP encryption.
*           CNcomment:����Ҫʹ��rekey���ܣ��Ƽ�ʹ��WPA+WPA2-PSK + CCMP���ܷ�ʽ.CNend
*
* @attention  When using wpa2psk-only + CCMP encryption, rekey is forced to 86400s by default.
*    CNcomment:��ʹ��wpa2psk-only + CCMP���ܷ�ʽʱ  ��rekeyĬ��ǿ�Ƹ�Ϊ 86400.CNend
* @param  wpa_group_rekey [IN]     Type  #int, update time in seconds, range(30s-86400s), default(86400s)
*                                   CNcomment:����ʱ������Ϊ��λ����Χ��30s-86400s��,Ĭ�ϣ�86400s��.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_set_group_rekey(int wifi_group_rekey);

/**
* @ingroup  hi_wifi_basic
* @brief  Set short-gi of softap.CNcomment:����softap��SHORT-GI����.CNend
*
* @par Description:
*           Enable or disable short-gi of softap.CNcomment:��������ر�softap��SHORT-GI����.CNend\n
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend
* @attention  NULL
* @param  flag            [IN]    Type  #int, enable(1) or disable(0). default enable(1).
                                        CNcomment:ʹ�ܱ�־��Ĭ��ʹ�ܣ�1��.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_set_shortgi(int flag);

/**
* @ingroup  hi_wifi_basic
* @brief  Start softap interface.CNcomment:����SoftAP.CNend
*
* @par Description:
*           Start softap interface.CNcomment:����SoftAP.CNend
*
* @attention  1. Multiple interfaces of the same type are not supported.CNcomment:��֧��ʹ�ö��ͬ���ͽӿ�.CNend\n
*             2. Dual interface coexistence support: STA + AP. CNcomment:˫�ӿڹ���֧�֣�STA + AP.CNend \n
*             3. Start timeout 5s.CNcomment:������ʱʱ��5s��CNend \n
*             4. Softap key length range(8 Bytes - 64 Bytes).CNcomment:softap key���ȷ�Χ��8 Bytes - 64 Bytes��.CNend \n
*             5. Only support auth mode as bellow: \n
*                 HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX, \n
*                 HI_WIFI_SECURITY_WPA2PSK, \n
*                 HI_WIFI_SECURITY_OPEN \n
*                CNcomment:5. ֻ֧��������֤ģʽ��\n
*                 HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX, \n
*                 HI_WIFI_SECURITY_WPA2PSK, \n
*                 HI_WIFI_SECURITY_OPEN.CNend \n
*             6. The memories of <ifname> and <len> should be requested by the caller��
*                the input value of len must be the same as the length of ifname��the recommended length is 17Bytes��.\n
*                CNcomment:6. <ifname>��<len>�ɵ����������ڴ棬�û�д��len��ֵ������ifname����һ�£����鳤��Ϊ17Bytes��.CNend \n
*             7. SSID only supports ASCII characters. \n
*                CNcomment:7. SSID ֻ֧��ASCII�ַ�.CNend
* @param  conf            [IN]      Type  #hi_wifi_softap_config *, softap's configuration.CNcomment:SoftAP����.CNend
* @param  ifname          [IN/OUT]  Type  #char *, interface name.CNcomment:�ӿ�����.CNend
* @param  len             [IN/OUT]  Type  #int *, interface name length.CNcomment:�ӿ����ֳ���.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_start(hi_wifi_softap_config *conf, char *ifname, int *len);

/**
* @ingroup  hi_wifi_basic
* @brief  Close softap interface.CNcomment:�ر�SoftAP.CNend
*
* @par Description:
*           Close softap interface.CNcomment:�ر�SoftAP.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_stop(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Get all user's information of softap.CNcomment:softap��ȡ�����ӵ�station����Ϣ.CNend
*
* @par Description:
*           Get all user's information of softap.CNcomment:softap��ȡ�����ӵ�station����Ϣ.CNend
*
* @attention  1.sta_list: malloc by user.CNcomment:1.ɨ�������������û���̬���롣CNend \n
*             2.sta_list: max size is hi_wifi_ap_sta_info * 6.
*               CNcomment:2.sta_list �㹻�Ľṹ���С�����Ϊhi_wifi_ap_sta_info * 6��CNend \n
*             3.sta_num:parameters can be passed in to specify the number of connected sta.The maximum is 6.
*               CNcomment:3.���Դ��������ָ����ȡ�ѽ����sta���������Ϊ6��CNend \n
*             4.sta_num should be the same with number of hi_wifi_ap_sta_info structures applied, Otherwise,
*               it will cause memory overflow.\n
*               CNcomment:4.sta_num�������hi_wifi_ap_sta_info�ṹ������һ�£������������ڴ������CNend
* @param  sta_list        [IN/OUT]  Type  #hi_wifi_ap_sta_info *, station information.CNcomment:STA��Ϣ.CNend
* @param  sta_num         [IN/OUT]  Type  #unsigned int *, station number.CNcomment:STA����.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_get_connected_sta(hi_wifi_ap_sta_info *sta_list, unsigned int *sta_num);

/**
* @ingroup  hi_wifi_basic
* @brief  Softap deauth user by mac address.CNcomment:softapָ���Ͽ����ӵ�station����.CNend
*
* @par Description:
*          Softap deauth user by mac address.CNcomment:softapָ���Ͽ����ӵ�station����.CNend
*
* @attention  NULL
* @param  addr             [IN]     Type  #const unsigned char *, station mac address.CNcomment:MAC��ַ.CNend
* @param  addr_len         [IN]     Type  #unsigned char, station mac address length, must be 6.
*                                         CNcomment:MAC��ַ����,����Ϊ6.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_softap_deauth_sta(const unsigned char *addr, unsigned char addr_len);

/**
* @ingroup  hi_wifi_basic
* @brief  set mac address.CNcomment:����MAC��ַ.CNend
*
* @par Description:
*           Set original mac address.CNcomment:������ʼmac��ַ.CNend\n
*           mac address will increase or recycle when adding or deleting device.
*           CNcomment:����豸mac��ַ������ɾ���豸���ն�Ӧ��mac��ַ.CNend
*
* @attention  NULL
* @param  mac_addr          [IN]     Type #char *, mac address.CNcomment:MAC��ַ.CNend
* @param  mac_len           [IN]     Type #unsigned char, mac address length.CNcomment:MAC��ַ����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_macaddr(const char *mac_addr, unsigned char mac_len);

/**
* @ingroup  hi_wifi_basic
* @brief  get mac address.CNcomment:��ȡMAC��ַ.CNend
*
* @par Description:
*           Get original mac address.CNcomment:��ȡmac��ַ.CNend\n
*           mac address will increase or recycle when adding device or deleting device.
*           CNcomment:����豸mac��ַ������ɾ���豸���ն�Ӧ��mac��ַ.CNend
*
* @attention  NULL
* @param  mac_addr          [OUT]    Type #char *, mac address.
* @param  mac_len           [IN]     Type #unsigned char, mac address length.
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_get_macaddr(char *mac_addr, unsigned char mac_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set country code.CNcomment:���ù�����.CNend
*
* @par Description:
*           Set country code(two uppercases).CNcomment:���ù����룬��������д�ַ����.CNend
*
* @attention  1.Before setting the country code, you must call hi_wifi_init to complete the initialization.
*             CNcomment:���ù�����֮ǰ���������hi_wifi_init��ʼ�����.CNend\n
*             2.cc_len should be greater than or equal to 3.CNcomment:cc_lenӦ���ڵ���3.CNend
* @param  cc               [IN]     Type  #char *, country code.CNcomment:������.CNend
* @param  cc_len           [IN]     Type  #unsigned char, country code length.CNcomment:�����볤��.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_country(const char *cc, unsigned char cc_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Get country code.CNcomment:��ȡ������.CNend
*
* @par Description:
*           Get country code.CNcomment:��ȡ�����룬��������д�ַ����.CNend
*
* @attention  1.Before getting the country code, you must call hi_wifi_init to complete the initialization.
*             CNcomment:��ȡ������֮ǰ���������hi_wifi_init��ʼ�����.CNend
* @param  cc               [OUT]     Type  #char *, country code.CNcomment:������.CNend
* @param  len              [IN/OUT]  Type  #int *, country code length.CNcomment:�����볤��.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_get_country(char *cc, int *len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set bandwidth.CNcomment:���ô���.CNend
*
* @par Description:
*           Set bandwidth, support 5M/10M/20M.CNcomment:���ýӿڵĹ�������֧��5M 10M 20M���������.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
* @param  bw               [IN]     Type  #hi_wifi_bw, bandwidth enum.CNcomment:����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_bandwidth(const char *ifname, unsigned char ifname_len, hi_wifi_bw bw);

/**
* @ingroup  hi_wifi_basic
* @brief  Get bandwidth.CNcomment:��ȡ����.CNend
*
* @par Description:
*           Get bandwidth.CNcomment:��ȡ����.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
*
* @retval #bandwidth enum.CNcomment:�����ö��ֵ.CNend
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
hi_wifi_bw hi_wifi_get_bandwidth(const char *ifname, unsigned char ifname_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set channel.CNcomment:�����ŵ�.CNend
*
* @par Description:
*           Set channel.CNcomment:�����ŵ�.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
* @param  channel          [IN]     Type  #int , listen channel.CNcomment:�ŵ���.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_channel(const char *ifname, unsigned char ifname_len, int channel);

/**
* @ingroup  hi_wifi_basic
* @brief  Get channel.CNcomment:��ȡ�ŵ�.CNend
*
* @par Description:
*           Get channel.CNcomment:��ȡ�ŵ�.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
*
* @retval #HI_WIFI_INVALID_CHANNEL
* @retval #Other                   chanel value.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_get_channel(const char *ifname, unsigned char ifname_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set monitor mode.CNcomment:���û���ģʽ.CNend
*
* @par Description:
*           Enable/disable monitor mode of interface.CNcomment:����ָ���ӿڵĻ���ģʽʹ��.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char * interface name.CNcomment:�ӿ���.CNend
* @param  enable           [IN]     Type  #int enable(1) or disable(0).CNcomment:����/�ر�.CNend
* @param  filter           [IN]     Type  #hi_wifi_ptype_filter * filtered frame type enum.CNcomment:�����б�.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_promis_enable(const char *ifname, int enable, const hi_wifi_ptype_filter *filter);

/**
* @ingroup  hi_wifi_basic
* @brief  Register receive callback in monitor mode.CNcomment:ע�����ģʽ���հ��ص�����.CNend
*
* @par Description:
*           1.Register receive callback in monitor mode.CNcomment:1.ע�����ģʽ���հ��ص�����.CNend\n
*           2.Wifi driver will put the receive frames to this callback.
*           CNcomment:2.����������ģʽ���յ��ı��ĵݽ���ע��Ļص���������.CNend
*
* @attention  NULL
* @param  data_cb          [IN]     Type  #hi_wifi_promis_cb callback function pointer.CNcomment:����ģʽ�ص�����.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_promis_set_rx_callback(hi_wifi_promis_cb data_cb);

/**
* @ingroup  hi_wifi_basic
* @brief    Open/close system power save.CNcomment:����/�ر�WiFi�͹���ģʽ.CNend
*
* @par Description:
*           Open/close system power save.CNcomment:����/�ر�WiFi�͹���ģʽ.CNend
*
* @attention  NULL
* @param  enable     [IN] Type  #unsigned char, enable(1) or disable(0).CNcomment:����/�ر�WiFi�͹���.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_pm_switch(unsigned char enable);

/**
* @ingroup  hi_wifi_basic
* @brief    Set wow wakeup pattern .CNcomment:����wow wakeup ģʽ.CNend
*
* @attention: set specific pattern of TCP/UPD for wow wakeup host
  CNcomment: ����wow ���� host�� ��TCP/UDP������, ���֧������4�ֻ��Ѱ�. CNend
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  type            [IN]     Type  #hi_wifi_wow_pattern_type, operation_type.
* @param  index           [IN]     Type  #unsigned char, patter_index. invalid value: 0, 1, 2, 3
* @param  pattern         [IN]     Type  #char *, hex payload of TCP/UDP.

* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned char hi_wifi_wow_set_pattern(const char *ifname, hi_wifi_wow_pattern_type type,
                                      unsigned char index, char *pattern);

/**
* @ingroup  hi_wifi_basic
* @brief    Set wow_sleep .CNcomment:����wow_sleep ˯��.CNend
*
* @attention: the only valid parameter is 1 now, it means that host request for sleep. other value of parameter
'en' is not support
  ��API��ǰΨһ��Ч����Ϊ1�� ��������host������˯�ߣ���������ֵ�ݲ�֧��
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  en              [IN]     Type  #unsigned char, wow_sleep switch, 1-sleep, 0-wakeup.

* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned char hi_wifi_wow_host_sleep_switch(const char *ifname, unsigned char en);

/**
* @ingroup  hi_wifi_basic
* @brief    Set dhcp offload on/off.CNcomment:����dhcp offload ��/�ر�.CNend
*
* @par Description:
*           Set dhcp offload on with ip address, or set dhcp offload off.
*           CNcomment:����dhcp offload�򿪡�����������Ӧip��ַ����������dhcp offload�ر�.CNend
*
* @attention  NULL
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  en              [IN]     Type  #unsigned char, dhcp offload type, 1-on, 0-off.
* @param  ip              [IN]     Type  #unsigned int, ip address in network byte order, eg:192.168.50.4 -> 0x0432A8C0.
*
* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned char hi_wifi_dhcp_offload_setting(const char *ifname, unsigned char en, unsigned int ip);

/**
* @ingroup  hi_wifi_basic
* @brief    Set arp offload on/off.CNcomment:����arp offload ��/�ر�.CNend
*
* @par Description:
*           Set arp offload on with ip address, or set arp offload off.
*           CNcomment:����arp offload�򿪡�����������Ӧip��ַ����������arp offload�ر�.CNend
*
* @attention  NULL
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  en              [IN]     Type  #unsigned char, arp offload type, 1-on, 0-off.
* @param  ip              [IN]     Type  #unsigned int, ip address in network byte order, eg:192.168.50.4 -> 0x0432A8C0.
*
* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned char hi_wifi_arp_offload_setting(const char *ifname, unsigned char en, unsigned int ip);

/**
* @ingroup  hi_wifi_basic
* @brief  Get rssi value.CNcomment:��ȡrssiֵ.CNend
*
* @par Description:
*           Get current rssi of ap which sta connected to.CNcomment:��ȡsta��ǰ������ap��rssiֵ.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #0x7F          Invalid value.
* @retval #Other         rssi
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_sta_get_ap_rssi(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set retry params.CNcomment:��������ش�����.CNend
*
* @par Description:
*           Set retry params.CNcomment:����ָ���ӿڵ�����ش�����.CNend
*
* @attention  1.Need call befora start sta or softap.CNcomment:1.��API��Ҫ��STA��AP start֮�����.CNend
* @param  ifname    [IN]     Type  #const char * interface name.CNcomment:�ӿ���.CNend
* @param  type      [IN]     Type  #unsigned char retry type.
*                            CNcomment:0:�����ش�������֡��; 1:�����ش�������֡��; 2:ʱ���ش�.CNend
* @param  limit     [IN]     Type  #unsigned char limit value.
*                            CNcomment:�ش�����(0~15��)/�ش�ʱ��(0~200��ʱ������,ʱ������10ms).CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_set_retry_params(const char *ifname, unsigned char type, unsigned char limit);

/**
* @ingroup  hi_wifi_basic
* @brief  Set sta plat pm mode.CNcomment:����STA��ƽ̨�͹���ģʽ.CNend
*
* @par Description:
*           Set sta pm mode.CNcomment:����STA��FAST_PS��PSPOLL_PS��uapsd�͹���ģʽ.CNend
*
* @attention  NULL
* @param  sleep_mode      [IN]     Type  #unsigned char, 0-no_sleep, 1-light_sleep, 2-deep_sleep.
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_set_plat_ps_mode(unsigned char sleep_mode);

/**
* @ingroup  hi_wifi_basic
* @brief  Set sta plat pm disable.CNcomment:ȥʹ��device��ƽ̨�͹���.CNend
*
* @par Description:
*           Set sta plat pm disable.CNcomment:ȥʹ��device��ƽ̨�͹���.CNend
*
* @attention  NULL
* @param NULL
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_plat_pm_disable(void);


/**
* @ingroup  hi_wifi_basic
* @brief  Set sta plat pm enable.CNcomment:ʹ��device��ƽ̨�͹���.CNend
*
* @par Description:
*           Set sta plat pm enable.CNcomment:ʹ��device��ƽ̨�͹���.CNend
*
* @attention  NULL
* @param NULL
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_plat_pm_enable(void);

/**
* @ingroup  hi_wifi_basic
* @brief  host notifies device of host's sleep state.CNcomment:host��˯��״̬��֪device.CNend
*
* @par Description:
*           host notifies device of host's sleep state.CNcomment:host��˯��״̬��֪device.CNend
*
* @attention  Once the device receives the host's sleep message, it will no longer send data to
* the host unless the host wakes up the device or the device wakes up the Host.CNcomment:һ��device
* �յ�host��˯����Ϣ����������host�������ݣ�����host����device����device����Host.CNend
* @param  slp          [IN]     Type  #bool, host sleep status, 0-wake, 1-sleep.
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_host_request_sleep(bool slp);

/**
* @ingroup  hi_wifi_basic
* @brief  The host sets device to deep sleep without turning off crystal.CNcomment:����device��˯ʱ���رվ���.CNend
*
* @par Description:
*           The host sets device to deep sleep without turning off crystal.CNcomment:����device��˯ʱ���رվ���.CNend
*
* @attention  set before setting up sleep, by default, the crystal is disabled when the device is in deep sleep.
* CNcomment:������device˯��ǰ�������ã�Ĭ������£�device��˯ʱ�رվ���.CNend
* @param  NULL.
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_set_deepsleep_open_tcxo(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set cca threshold.CNcomment:����CCA����.CNend
*
* @par Description:
*           Set cca threshold.CNcomment:����CCA����.CNend
*
* @attention  CNcomment:1.threshold���÷�Χ��-128~126ʱ����ֵ�̶�Ϊ����ֵ.CNend\n
*             CNcomment:2.threshold����ֵΪ127ʱ���ָ�Ĭ����ֵ-62dBm����ʹ�ܶ�̬����.CNend
* @param  ifname          [IN]     Type #char *, device name. CNcomment:�ӿ���.CNend
* @param  threshold       [IN]     Type #char, threshold. CNcomment:����ֵ.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
*
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_set_cca_threshold(const char* ifname, signed char threshold);

/**
* @ingroup  hi_wifi_basic
* @brief  Set tcp mode.CNcomment:����tpc����.CNend
*
* @par Description:
*           Set tpc mode.CNcomment:����tpc����.CNend
*
* @attention  1.Mode set to 1, enable auto power control. set to 0, disbale it.
*             CNcomment:1.mode��Χ��0~1,1:�򿪷��͹����Զ�����,0:�رշ��͹����Զ�����.CNend
* @param  ifname          [IN]     Type #char *, device name. CNcomment:�ӿ���.CNend
* @param  ifname_len      [IN]     Type #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
* @param  tpc_value       [IN]     Type #unsigned int, tpc_value. CNcomment:tpc����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
*
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_set_tpc(const char* ifname, unsigned char ifname_len, unsigned int tpc_value);

/**
* @ingroup  hi_wifi_basic
* @brief  Set customize parameters.CNcomment:���ö��ƻ�����.CNend
*
* @par Description:
*           Set customize parameters:���ö��ƻ�����.CNend
*
* @attention  1.rssi_offset:rx rssi compnesation val. CNcomment:1.rssi_offset:rx rssi�Ĳ���ƫ��ֵ.CNend
* @attention  2.freq_comp:3 elements refer to enter and quit temp freq compensation threshold, and compensation val.
              CNcomment:2.freq_comp:3��Ԫ�طֱ��Ӧ����Ƶƫ�������¶���ֵ���˳��������¶���ֵ�͸���Ƶƫ����ֵ.CNend
* @attention  3.dbb_params:first 5 elements are dbb scales, 6th is freq and band power offset, 7th is evm related val.
              CNcomment:3.dbb_params:ǰ5����dbb scale����ֵ����6����Ƶƫ��band���ʲ���ֵ����7����evm������ֵ.CNend
* @attention  4.ch_txpwr_offset:tx power offset of 13 channels, for FCC.ch 14 or upper use the cfg val of ch 13.
              CNcomment:4.ch_txpwr_offset:��Ӧ13���ŵ��Ĺ���ƫ�ƣ����÷���FCCҪ��Ĺ���,����13�ŵ�ʹ��13�ŵ���ֵ.CNend
* @param  params          [IN]     Type #hi_wifi_customize_params *, parameters. CNcomment:���ƻ�����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
*
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_set_customize_params(hi_wifi_customize_params *params);

/**
 * @ingroup  hi_wifi_basic
 * @brief  Register function callback of report datarate and average send times.
 *         CNcomment:ע���ϱ�ʵ����������ƽ�����ʹ��������ص�.CNend
 *
 * @par Description:
 *         Register function callback of report datarate and average send times
 *         CNcomment:ע���ϱ�ʵ����������ƽ�����ʹ��������ص�.CNend
 *
 * @attention  1.function callback type must been suited to hi_wifi_report_tx_params_callback.
               CNcomment:1.�ص����������� hi_wifi_report_tx_params_callback ����.CNend
 *
 * @param  func      [IN] type #hi_wifi_report_tx_params_callback, report tx params callback. CNcomment:�ϱ�ʵ����������
 ƽ�����ʹ��������ص���Nend
 * @retval None
 * @par Dependency:
 *            @li hi_wifi_api.h: WiFi API
 * @see  NULL
 * @since Hi3881_V100R001C00
 */
void hi_wifi_register_tx_params_callback(hi_wifi_report_tx_params_callback func);

/**
 * @ingroup  hi_wifi_basic
 * @brief  Get datarate.CNcomment:��ȡʵ�����ʼ�ƽ�����ʹ���.CNend
 *
 * @par Description:
 *           Get goodput and average send times.CNcomment:��ȡʵ�����ʼ�ƽ�����ʹ���.CNend
 *
 * @attention  1. Call hi_wifi_register_datarate_callback before call this function.
 *             CNcomment:1. ���ñ�����ǰ������ hi_wifi_register_datarate_callback ע��ص�.CNend
 *             2. after call this function, result will be reported by register function.
 *             CNcomment:2. ����ִ�н����ͨ��ע��Ļص�����֪ͨ.CNend
 * @param  ifname          [IN]     Type #char *, device name. CNcomment:�ӿ���.CNend
 * @param  ifname_len      [IN]     Type #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
 *
 * @retval #HISI_OK  Excute successfully
 * @retval #Other           Error code
 *
 * @par Dependency:
 *            @li hi_wifi_api.h: WiFi API
 * @see  NULL
 * @since Hi3881_V100R001C00
 */
unsigned int hi_wifi_get_tx_params(const char* ifname, unsigned char ifname_len);

/**
* @ingroup  hi_wifi_basic
* @brief  register driver callback interface.CNcomment:ע�������¼��ص������ӿ�.CNend
*
* @par Description:
*           register driver callback interface.CNcomment:ע�������¼��ص������ӿ�.CNend
*
* @attention  NULL
* @param  event_cb  [IN]    Type #hi_wifi_driver_event_cb, event callback .CNcomment:�ص�����.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_register_driver_event_callback(hi_wifi_driver_event_cb event_cb);

/**
* @ingroup  hi_wifi_basic
* @brief  sdio send message to reset device. CNcomment:SDIO���͸�λ�豸��Ϣ.CNend
*
* @par Description:
*            sdio send message to reset device.CNcomment:SDIO���͸�λ�豸��Ϣ.CNend
*
* @attention  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
int hi_wifi_soft_reset_device(void);

/**
* @ingroup  hi_wifi_basic
* @brief  enable device's gpio soft reset function. CNcomment:ʹ���豸GPIO��λ����.CNend
*
* @par Description:
*            when function enabled, device will reset after receive GPIO5's  Falling edge interrupt. default not enabled.
CNcomment:ʹ�ܸù��ܺ�device��ӦGPIO5���½����жϽ�����λ��Ĭ�ϸù���δʹ��.CNend
*
* @attention  shoule call after wifi init.CNcomment:����WIFI��ʼ���ɹ������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_open_gpio_soft_reset_device(void);

/**
* @ingroup  hi_wifi_basic
* @brief  disable device's gpio soft reset function. CNcomment:�����豸GPIO��λ����.CNend
*
* @par Description:
*            disable device's gpio soft reset function. CNcomment:�����豸GPIO��λ����.CNend
*
* @attention  shoule call after wifi init.CNcomment:����WIFI��ʼ���ɹ������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3881_V100R001C00
*/
unsigned int hi_wifi_close_gpio_soft_reset_device(void);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_wifi_api.h */
