/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Source file implemented by the operation interface function associated with the configuration.
 * Author: Hsilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "sys/types.h"
#include "sys/time.h"
#include "unistd.h"
#include "fcntl.h"
#include "sys/statfs.h"
#include "limits.h"

#include "los_event.h"
#include "los_printf.h"

#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/dhcp.h"

#include "arch/perf.h"
#include "fcntl.h"
#include "fs/fs.h"
#include "stdio.h"
#include "shell.h"
#include "hisoc/uart.h"
#include "vfs_config.h"
#include "disk.h"
#include "los_cppsupport.h"
#include "linux/fb.h"

#include "los_event.h"
#include <mmc/host.h>
#include <linux/completion.h>
#include <linux/mtd/mtd.h>
#include <pm/hi_type.h>
#include "hirandom.h"
#include "spinor.h"
#include "proc_fs.h"
#include "console.h"
#include "hisoc/uart.h"
#include "uart.h"
#include "hi_wifi_api.h"
#include <hi_at.h>
#include "reset_shell.h"
#include "sample_wifi.h"
#include "gpio.h"
#include "implementation/usb_init.h"

#define hi_unused(x) ((x) = (x))

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define DELAY_TIME_MS           150
#define GPIO_GROUP_6            6
#define GPIO_PIN                4
#define GPIO_DIR_OUT            1

#define GPIO_CONFIG             0x120F0000
#define GPIO_CONFIG_VALUE       100160

#define GPIO_CONFIG_PIN         0x120F0024
#define GPIO_PIN_VALUE          7

#define _GPIO_RESET_DEVICE

#define MONITOR_TASK_SIZE       0x1000
#define MONITOR_TASK_PRIO       4
#define MONITOR_TASK_NAME       "wifi_drv_monitor"

#define HI_SUCCESS              0
#define HI_FAIL                 (-1)

#define MAX_EVENT_CNT           4

/*****************************************************************************
  4 全局变量
*****************************************************************************/
struct netif       *g_pnetif;
struct timer_list   g_hisi_dhcp_timer;
struct completion   g_wpa_ready_complet;
char g_sta_ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
unsigned int        g_check_ip_loop = 0;

/*****************************************************************************
  5 函数实现
*****************************************************************************/
/*****************************************************************************
 功能描述  : 网络相关初始化
*****************************************************************************/
void net_init(void)
{
    tcpip_init(NULL, NULL);
#ifdef LOSCFG_DRIVERS_HIGMAC
    g_pnetif = &(higmac_drv_sc.ac_if);
    higmac_init();
#endif

#ifdef LOSCFG_DRIVERS_HIETH_SF
    g_pnetif = &(hisi_eth_drv_sc.ac_if);
    hisi_eth_init();
#endif

    LOGI("cmd_startnetwork : DHCP_BOUND finished\n");

    netifapi_netif_set_up(g_pnetif);
    init_timer(&g_hisi_dhcp_timer);
}

#ifdef SUPPORT_FMASS_PARITION
void fmass_app_notify(void *conext, int status)
{
    if (status == 1) { /* usb device connect */
        char *path = "/dev/mmcblk0p0";
        /* startup fmass access patition */
        fmass_partition_startup(path);
    }
}
#endif



void hi_wifi_power_set(unsigned char val)
{
    hi_unused(val);
    LOGE("[ERR]hi_wifi_power_set\n");
}
void hi_wifi_rst_set(unsigned char val)
{
    hi_unused(val);
    LOGE("[ERR]hi_wifi_rst_set\n");
}

void hi_wifi_pre_proc(void)
{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifdef CFG_FCC_MODE
    hi_wifi_customize_params wifi_customize_params = {"CN", 0, {105, 100, -30},
        {0x61636263, 0x6A6A6A6A, 0x4F536061, 0x60686768, 0x51516161, 0x00000000, 0x01000000},
        {0x8aa8aaa1, 0x24424441, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
         0x00000001, 0x00000001, 0x02202221, 0x68868881, 0xffffffff, 0xffffffff}};
#else /* CFG_CE_MODE */
    hi_wifi_customize_params wifi_customize_params = {"CN", 0, {105, 100, -30},
        {0x6B6B6D6E, 0x67676767, 0x50545F60, 0x565E5E5E, 0x4F4F5656, 0x00000000, 0x01000000},
        {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
         0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}};
#endif

    unsigned int ret;
    ret = hi_wifi_set_customize_params(&wifi_customize_params);
    if (ret != 0) {
        LOGE("hi_wifi_set_customize_params fail!");
        return;
    }
#endif
}

/*****************************************************************************
 功能描述  : 检查dhcp是否成功
*****************************************************************************/
void hi_check_dhcp_success(ULONG para)
{
    int ret;
    struct netif *pwifi = NULL;

    pwifi = netif_find((char *)(uintptr_t)para);
    if (pwifi == NULL) {
        LOGE("can't find netif[%s]", (char *)(uintptr_t)para);
        return;
    }

    ret = dhcp_is_bound(pwifi);
    if (ret == 0) {
        /* IP获取成功后通知wifi驱动 */
        LOGI("\n\n DHCP SUCC\n\n");
        del_timer(&g_hisi_dhcp_timer);
        return;
    }

    if (g_check_ip_loop++ > DHCP_CHECK_CNT) {
        /* IP获取失败执行去关联 */
        LOGE("\n\n DHCP FAILED\n\n");
        del_timer(&g_hisi_dhcp_timer);
        return;
    }

    /* 重启查询定时器 */
    add_timer(&g_hisi_dhcp_timer);
    return;
}

/*****************************************************************************
 功能描述  : wifi事件回调函数
*****************************************************************************/
void hisi_wifi_event_cb(const hi_wifi_event *event)
{
    struct netif *pwifi = NULL;
    LOGI("wifi_event_cb,event:%d", event->event);

    switch (event->event) {
        case HI_WIFI_EVT_SCAN_DONE:
            LOGI("Scan results available\n");
            break;
        case HI_WIFI_EVT_CONNECTED:
            LOGI("WiFi: Connected[%s]\n", event->info.wifi_connected.ifname);
            pwifi = netif_find(event->info.wifi_connected.ifname);
            if (pwifi == NULL) {
                LOGE("can't find netif[%s]\n", event->info.wifi_connected.ifname);
                return;
            }
            /* 启动dhcp获取IP */
            netifapi_dhcp_stop(pwifi);
            netifapi_dhcp_start(pwifi);
            if (memset_s(g_sta_ifname, WIFI_IFNAME_MAX_SIZE + 1, 0, WIFI_IFNAME_MAX_SIZE + 1) != EOK) {
                LOGE("memset netif's name fail!\n");
            }
            if (memcpy_s(g_sta_ifname, WIFI_IFNAME_MAX_SIZE + 1,
                event->info.wifi_connected.ifname, WIFI_IFNAME_MAX_SIZE + 1) != EOK) {
                LOGE("memcpy netif's name fail!\n");
            }

            /* 查询IP是否获取 */
            g_check_ip_loop = 0;
            del_timer(&g_hisi_dhcp_timer);
            g_hisi_dhcp_timer.expires = LOS_MS2Tick(DHCP_CHECK_TIME);
            g_hisi_dhcp_timer.function = hi_check_dhcp_success;
            g_hisi_dhcp_timer.data = (uintptr_t)g_sta_ifname;
            add_timer(&g_hisi_dhcp_timer);
            msleep(500);    /* sleep 500ms */
            break;
        case HI_WIFI_EVT_DISCONNECTED:
            LOGI("WiFi: disconnect[%s]\n", event->info.wifi_disconnected.ifname);
            pwifi = netif_find(event->info.wifi_disconnected.ifname);
            if (pwifi == NULL) {
                LOGE("can't find netif[%s]\n", event->info.wifi_disconnected.ifname);
                return;
            }
            netifapi_dhcp_stop(pwifi);
            netifapi_netif_set_addr(pwifi, NULL, NULL, NULL);
            break;

        case HI_WIFI_EVT_AP_START:
            LOGI("WiFi: AP Start[%s].\n", event->info.ap_start.ifname);
            pwifi = netif_find(event->info.ap_start.ifname);
            if (pwifi == NULL) {
                LOGE("can't find netif[%s]", event->info.ap_start.ifname);
                return;
            }

            if (0 == netifapi_dhcps_stop(pwifi)) {
                LOGI("dhcp servier stop.\n");
            }

            ip4_addr_t ip = {0x0101a8c0UL};
            ip4_addr_t netmask = {0x00ffffffUL};
            ip4_addr_t gw = {0x0101a8c0UL};

            IP4_ADDR(&ip, 192, 168, 43, 1);         /* ip       192.168.43.1 */
            IP4_ADDR(&gw, 192, 168, 43, 1);         /* gw       192.168.43.1 */
            IP4_ADDR(&netmask, 255, 255, 255, 0);   /* netmask  255.255.255.0 */

            netifapi_netif_set_addr(pwifi, &ip, &netmask, &gw);

            /* hostapd创建成功 */
            netifapi_netif_set_up(pwifi);
            if (0 == netifapi_dhcps_start(pwifi, NULL, 0)) {
                LOGI("dhcp servier start.");
            }

            break;
        case HI_WIFI_EVT_STA_CONNECTED:
            LOGI("WiFi: STA connected.\n");
            break;
        case HI_WIFI_EVT_STA_DISCONNECTED:
            LOGI("WiFi: STA disconnected.\n");
            break;
        default:
            break;
    }
}

/*****************************************************************************
 功能描述  : sdio管脚复用配置
*****************************************************************************/
void sdio_pin_mux_init(void)
{
#if defined(HISI_WIFI_PLATFORM_HI3516EV300)
    writel(0x00100164, 0x120F0000);
    writel(0x7, 0x120F0024);
    writel(0x1D54, 0x100C0060);
    writel(0x1174, 0x100C0064);
    writel(0x1174, 0x100C0068);
    writel(0x1174, 0x100C006C);
    writel(0x1174, 0x100C0070);
    writel(0x1174, 0x100C0074);
    writel(0x28000000, 0x10020028);
    writel(0x20000000, 0x10020028);
#elif defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    /* Hi3559V200 */
    writel(0x681, 0x112F0008);
    writel(0x581, 0x112F0014);
    writel(0x581, 0x112F0010);
    writel(0x581, 0x112F001C);
    writel(0x581, 0x112F000C);
    writel(0x581, 0x112F0018);
#else
    /* Hi3518ev300 */
    writel(0x1D54, 0x112C0048);
    writel(0x1134, 0x112C0060);
    writel(0x1134, 0x112C0064);
    writel(0x1134, 0x112C0058);
    writel(0x1134, 0x112C004C);
    writel(0x1134, 0x112C005C);
#endif
}

void board_gpio_pin_power_off_init(void)
{
#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    writel(0x0601, 0x112F00B8);
    writel(0x08, 0x120DB400);
#else
    gpio_dir_config(GPIO_GROUP_6, GPIO_PIN, GPIO_DIR_OUT);
#endif
}


void  board_gpio_set_power_off_value(unsigned char level)
{
#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    if (level)
        writel(0x08, 0x120DB400);
    else
        writel(0x00, 0x120DB400);
#else
    gpio_write(GPIO_GROUP_6, GPIO_PIN, level); /* gpio group:6; offset:4 */
#endif
}

/*****************************************************************************
控制WIFI芯片上电
*****************************************************************************/
void board_power_on(void)
{
#ifdef HISI_WIFI_PLATFORM_HI3516EV300
    writel(0x00100164, 0x120F0000);
    writel(0x7, 0x120F0024);
#else
    board_gpio_pin_power_off_init();
    board_gpio_set_power_off_value(1);
#endif
}

/*****************************************************************************
控制WIFI芯片下电
*****************************************************************************/
void board_power_off(void)
{
#ifdef HISI_WIFI_PLATFORM_HI3516EV300
    writel(GPIO_CONFIG_VALUE, GPIO_CONFIG);
    writel(GPIO_PIN_VALUE, GPIO_CONFIG_PIN);
#else
    board_gpio_pin_power_off_init();
    board_gpio_set_power_off_value(0);
#endif
}

/*****************************************************************************
控制WIFI芯片重新上电
*****************************************************************************/
void hi_wlan_power_reset(void)
{
    board_power_off();
    LOS_Msleep(DELAY_TIME_MS); /* sleep before power_on */
    board_power_on();
    LOS_Msleep(DELAY_TIME_MS);
    printk("\r\nhi_wlan_power_reset SUCCESSFULLY\r\n");
}

/*****************************************************************************
 功能描述  : 复位device,有两种方式，一种是GPIO复位，一种是通过SDIO发送消息复位
*****************************************************************************/
void hi_reset_device(void)
{
#ifdef _GPIO_RESET_DEVICE
    hi_wlan_power_reset();
#else
    /* SDIO复位设备 */
    hi_wifi_soft_reset_device();
    LOS_Msleep(DELAY_TIME_MS);
#endif
}

/*****************************************************************************
 功能描述  : 处理WIFI异常业务
*****************************************************************************/
void* hi_wifi_monitor_task_thread(void* args)
{
    hi_wifi_driver_event event = (hi_wifi_driver_event)args;
    switch (event) {
        case DEV_PANIC:
            LOGE("wifi driver device panic.\n");
            break;
        case DRIVER_HUNG:
            LOGE("wifi driver frw enqueue fail.\n");
            break;
        default:
            LOGE("read unkown event error\n");
            break;
    }
    return NULL;
}

/*****************************************************************************
 功能描述  : 创建监控wifi驱动异常处理
*****************************************************************************/
int hi_wifi_create_monitor_driver_task(hi_wifi_driver_event event)
{
    unsigned int ret, taskid;
    TSK_INIT_PARAM_S my_task = { 0, };
    my_task.pcName      = MONITOR_TASK_NAME;
    my_task.uwStackSize = MONITOR_TASK_SIZE;
    my_task.usTaskPrio  = MONITOR_TASK_PRIO;
    my_task.uwResved = LOS_TASK_STATUS_DETACHED;
    my_task.pfnTaskEntry = (TSK_ENTRY_FUNC) hi_wifi_monitor_task_thread;
    my_task.auwArgs[0] = (unsigned int)(uintptr_t)event;

    ret = LOS_TaskCreate(&taskid, &my_task);
    if (ret != LOS_OK) {
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 功能描述  : 处理驱动返回的事件类型
*****************************************************************************/
int hisi_wifi_driver_event_cb(hi_wifi_driver_event event)
{
    return hi_wifi_create_monitor_driver_task(event);
}

/*****************************************************************************
 功能描述  : app初始化
*****************************************************************************/
void app_init(void)
{
    UINT32 ret;

    LOGI("random init ...");
    ran_dev_register();

    LOGI("uart init ...");
    if (uart_dev_init() != 0) {
        LOGE("uart_dev_init failed");
    }
    if (virtual_serial_init(TTY_DEVICE) != 0) {
        LOGE("virtual_serial_init failed");
    }
    if (system_console_init(SERIAL) != 0) {
        LOGE("system_console_init failed");
    }

    hi_at_factory_shell_cmd_register();
    hi_at_wifi_shell_cmd_register();
    hi_at_general_cmd_register();
    LOGI("spi nor falsh init ...");
    spinor_init();

    LOGI("gpio init ...");
    gpio_dev_init();

    LOGI("sdio io mux init ...");
    sdio_pin_mux_init();

    (void)osReHookFuncAdd((STORAGE_HOOK_FUNC)hi_reset_device, NULL);

    LOGI("net init ...");
    net_init();

#if defined(_PRE_FEATURE_USB) || defined(_CONFIG_SIGMA_TEST)
    LOGI("usb init ...");
    usb_init(HOST, 0);
#endif

#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
#else
    LOGI("sd/mmc host init ...");
    SD_MMC_Host_init();
#endif

    /* check system bootup or wakeup */
    hi_wifi_pre_proc();

    LOGI("porc fs init ...");
    proc_fs_init();

#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    LOGI("sd/mmc host init ...");
    SD_MMC_Host_init();
#endif

    hi_wifi_register_event_callback(hisi_wifi_event_cb); /*  WFA认证自动化测试需要注释掉，因为回调函数关联后会自动获取ip */
    LOGI("hi_wifi_init");
    ret = (UINT32)hi_wifi_init(WIFI_INIT_VAP_NUM, WIFI_INIT_USR_NUM);
    /* ret = 0 :非待机唤醒时，驱动初始化成功，客户进行wpa_supplicant_start wpa_cli_scan wpa_cli_connect DHCP动作
                 待机唤醒时,驱动初始化及恢复成功，自动恢复到关联成功以及IP地址恢复的状态
       ret = 1 :待机唤醒时，恢复失败(FLASH数据异常，相关接口已经暴露)，Hi1131发现异常退出待机恢复，并进行驱动初始化
                 以及wpa_supplicant_start动作，客户进行wpa_cli_scan wpa_cli_connect DHCP动作
       ret = -1或其它值，表示驱动异常或硬件异常，请执行reset，确认是否能解决。
    */
    if (ret != 0) {
        LOGE("fail to start hisi wifi");
        hi_wifi_deinit();
        return;
    }
    hi_wifi_register_driver_event_callback(hisi_wifi_driver_event_cb);

    LOGI("hi_wifi_init end");
    init_completion(&g_wpa_ready_complet);
    return;
}

