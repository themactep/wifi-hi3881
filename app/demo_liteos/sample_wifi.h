/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sample wifi.
 * Author: Hisilicon
 * Create: 2019-03-04
 */

#ifndef __SAMPLE_WIFI_H__
#define __SAMPLE_WIFI_H__


/*****************************************************************************
  2 枚举、结构体定义
*****************************************************************************/
typedef enum {
    HSL_STATUS_UNCREATE,
    HSL_STATUS_CREATE,
    HSL_STATUS_RECEIVE,
    HSL_STATUS_CONNECT,
    HSL_STATUS_BUTT
} hsl_status_enum;

typedef enum {
    HILINK_STATUS_UNCREATE,
    HILINK_STATUS_RECEIVE,  /* hilink处于接收组播阶段 */
    HILINK_STATUS_CONNECT,  /* hilink处于关联阶段 */
    HILINK_STATUS_BUTT
} hilink_status_enum;

/*****************************************************************************
  3 宏定义
*****************************************************************************/
/* 从启动dhcp，间隔1秒查询IP是否获取，30秒未获取IP执行去关联动作 */
#define DHCP_CHECK_CNT                      30
#define DHCP_CHECK_TIME                     1000

#define WLAN_FILE_STORE_MIN_SIZE            0
#define WLAN_FILE_STORE_MID_SIZE            0x30000
#define WLAN_FILE_STORE_MAX_SIZE            0x70000
#define WLAN_FILE_STORE_BASEADDR            0x750000

#define WIFI_IRQ                            54   /* GPIO6 */
#define WIFI_SDIO_INDEX                     1

#define WIFI_INIT_VAP_NUM    2
#define WIFI_INIT_USR_NUM    4

#ifdef HISI_WIFI_PLATFORM_HI3516EV100
#define WIFI_DATA_INTR_GPIO_GROUP           3
#define WIFI_DATA_INTR_GPIO_OFFSET          2

#define HOST_WAK_DEV_GPIO_GROUP             3
#define HOST_WAK_DEV_GPIO_OFFSET            0

#define WIFI_WAK_FLAG_GPIO_GROUP            3
#define WIFI_WAK_FLAG_GPIO_OFFSET           1

#define DEV_WAK_HOST_GPIO_GROUP             3
#define DEV_WAK_HOST_GPIO_OFFSET            3

#define REG_MUXCTRL_WIFI_DATA_INTR_GPIO_MAP (IO_MUX_REG_BASE + 0x08C)
#define REG_MUXCTRL_HOST_WAK_DEV_GPIO_MAP   (IO_MUX_REG_BASE + 0x094)
#define REG_MUXCTRL_WIFI_WAK_FLAG_GPIO_MAP  (IO_MUX_REG_BASE + 0x090)
#define REG_MUXCTRL_DEV_WAK_HOST_GPIO_MAP   (IO_MUX_REG_BASE + 0x088)
#else
#define WIFI_DATA_INTR_GPIO_GROUP           6
#define WIFI_DATA_INTR_GPIO_OFFSET          7

#define HOST_WAK_DEV_GPIO_GROUP             5
#define HOST_WAK_DEV_GPIO_OFFSET            1

#define DEV_WAK_HOST_GPIO_GROUP             8
#define DEV_WAK_HOST_GPIO_OFFSET            6

#endif

#define REG_MUXCTRL_SDIO1_CLK_MAP           0x112c0048
#define REG_MUXCTRL_SDIO1_CDATA1_MAP        0x112c0060
#define REG_MUXCTRL_SDIO1_CDATA0_MAP        0x112c0064
#define REG_MUXCTRL_SDIO1_CDATA3_MAP        0x112c0058
#define REG_MUXCTRL_SDIO1_CCMD_MAP          0x112c004C
#define REG_MUXCTRL_SDIO1_CDATA2_MAP        0x112c005C

#define LOG_TAG "sample"

#define LOGE(fmt, arg...) dprintf("[E/" LOG_TAG "]" fmt "\r\n", ##arg)
#define LOGW(fmt, arg...) dprintf("[W/" LOG_TAG "]" fmt "\r\n", ##arg)
#define LOGI(fmt, arg...) dprintf("[I/" LOG_TAG "]" fmt "\r\n", ##arg)
#define LOGD(fmt, arg...) dprintf("[D/" LOG_TAG "]" fmt "\r\n", ##arg)
#define LOGV(fmt, arg...) dprintf("[V/" LOG_TAG "]" fmt "\r\n", ##arg)

extern int gpio_dev_init(void);
#ifdef SUPPORT_FMASS_PARITION
extern int fmass_register_notify(void (*notify)(void *context, int status), void *context);
extern int fmass_partition_startup(char *path);
#endif

extern struct los_eth_driver higmac_drv_sc;
extern struct los_eth_driver hisi_eth_drv_sc;

#endif // __APP_MAIN_H__
