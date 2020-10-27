/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sample ap.
 * Author: Hisilicon
 * Create: 2018-08-04
 * Description:
       +------------+             +-----------+
  App  |  main loop | <--command--| UI thread |
       +------------+             +-----------+
          |     /|\
        call   event
  - - - - + - -  + - - - - - - - - - - - - - -
         \|/     |
       +------------+
       |  interface |
       +------------+
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "hi_wlan.h"

#include "securec.h"
#include "sample_common.h"
#include <semaphore.h>
#include <signal.h>

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
#define VERSION         "1.0.4"
#define IFNAMSIZ        16
#define MAX_AP_NUM      32

#define SOCK_STRUCT_LEN 8
#define SYSTEM_CMD_SIZE 1024
#define WK_FAIL_SIG 44
#define DELAY_TIME_US      150000
#define MONITOR_SLEEP_TIMEOUT       10000
#define MONITOR_FAIL_SLEEP_TIME     10000

#define _GPIO_RESET_DEVICE

const hi_pchar g_sample_version = "sample_sta v" VERSION "\n";

static const hi_char    g_dev_wifi_dir[] = "/dev/wifi";
static const hi_char    g_pid_file[] = "/dev/wifi/sample.pid";

static hi_bool          g_terminate = HI_FALSE;
static hi_bool          g_persist_on_signal = HI_FALSE;
static pthread_t        g_wlan_timer_thread_power = 0;

static sem_t g_wakeup_device_sem;
volatile sig_atomic_t g_wkup_fail_event = 0;
volatile sig_atomic_t g_wait_enable_event = 0;

/*****************************************************************************
  3 枚举、结构体定义
*****************************************************************************/
typedef enum hi_wlan_sta_state_e {
    STA_STATE_DISABLED,
    STA_STATE_ENABLED,
    STA_STATE_SCANNING,
    STA_STATE_CONNECTING,
    STA_STATE_CONNECTED,
    STA_STATE_BUTT,
} hi_wlan_sta_state_e;

typedef enum hi_wlan_msg_s {
    /* commands */
    STA_CMD_ENABLE,             /* start WiFi STA */
    STA_CMD_DISABLE,            /* stop WiFi */
    STA_CMD_GET_STATUS,         /* get current connection status */
    STA_CMD_SCAN,               /* start to scan */
    STA_CMD_SCANCHAN,           /* Specified channel scan */
    STA_CMD_GET_SCANRESULTS,    /* get scan results */
    STA_CMD_CONNECT,            /* connect to AP */
    STA_CMD_DISCONNECT,         /* disconnect to AP */
    STA_CMD_WPS,                /* start WPS process */
    STA_CMD_MACADDRESS,         /* get local WiFi MAC address */
    STA_CMD_HELP,               /* help sample_sta */
    STA_CMD_QUIT,               /* quit sample_sta */
    /* events */
    STA_EVT_SCANRESULTS_AVAILABLE,  /* scan is done, results is ready */
    STA_EVT_DISCONNECTED,       /* connection has been disconnected */
    STA_EVT_CONNECTING,         /* try to connect to AP */
    STA_EVT_CONNECTED,          /* connect successfully */
    STA_EVT_SUPP_STOPPED,       /* wpa_supplicant exited */
    STA_EVT_DRIVER_STOPPED,     /* driver stopped */
    WLAN_MSG_BUTT,
} hi_wlan_msg_s;

typedef union hi_wlan_msg_data_s {
    hi_wlan_sta_config_s config;
    hi_char bssid[BSSID_LEN + 1];
    /* scan channel config */
    hi_wlan_sta_scan_cfg_e chan_scan_cfg;
} hi_wlan_msg_data_s;

/* command/event information */
typedef struct hi_wlan_message_s {
    hi_wlan_msg_s what;
    hi_wlan_msg_data_s obj;
} hi_wlan_message_s;

struct snode {
    hi_wlan_message_s message;
    struct snode *next;
};

struct squeue {
    struct snode *front;
    struct snode *rear;
};

typedef struct hi_wlan_data_s {
    hi_char ifname[IFNAMSIZ + 1];
    hi_char mac[BSSID_LEN + 1];
    hi_wlan_sta_access_point_e aplist[MAX_AP_NUM];  /* save AP list of scan */
    hi_u32  ap_num;
    hi_wlan_sta_config_s config;                    /* configuration of network connected or connecting */
    hi_wlan_sta_conn_status_e connection;           /* connection status */
    hi_wlan_sta_state_e state;                      /* current state of WiFi */
    hi_wlan_sta_scan_cfg_e chan_scan_cfg;           /* scan channel config */

    pthread_mutex_t mut;                            /* mutex */
    pthread_cond_t cond;
    struct squeue cmd_queue;
    hi_bool persist_on;                             /* used for power save, if true, need turn on after wakeup */
    pthread_t sock_thread;
    hi_s32 sockfd;
} hi_wlan_data_s;

#ifdef DRIVER_EXCEPTION_REPORT
typedef struct {
    pthread_t monitor_thread;
    hi_s32 dev_fd;
    hi_u8 monitor_exit;
} hi_wlan_monitor;

typedef enum {
    DEV_PANIC = 1,
    DRIVER_HUNG,
    UNKNOWN,
} hi_wifi_driver_event;
#endif

static hi_wlan_data_s  *g_data = NULL;

#ifdef DRIVER_EXCEPTION_REPORT
hi_wlan_monitor g_monitor = {0};
#endif

hi_void wlan_stop_udhcpc(hi_void);
#ifdef DRIVER_EXCEPTION_REPORT
hi_void hi_wlan_stop_monitor();
#endif

/*****************************************************************************
  4 函数实现
*****************************************************************************/
static hi_void usage(hi_void)
{
    printf("\nUsage:\n");
    printf("\tsample_cli  enable,<bw_enable>,[bw_bandwidth],<b/g/n>,<pmf>           start wifi station, \
            load driver and start supplicant\n");
    printf("\t\tbw_enable:        0:narrow band OFF   1:barrow band ON\n");
    printf("\t\tbw_bandwidth:   5/10, bandwidth for narrow band\n");
    printf("\t\tb/g/n:               b mode not support when barrow band ON\n");
    printf("\t\tpmf:                  PMF Mode(0/1/2) 0:NO_PROTECTION 1:PROTECTION_OPTIONAL 2:PROTECTION_REQUIRED\n");
    printf("\t\tfor example:   sample_cli  enable,1,5,n\n");
    printf("\tsample_cli  disable           stop wifi station, stop supplicant and unload driver\n");
    printf("\tsample_cli  scan               scan for APs\n");
    printf("\tsample_cli  scanchan         scan Aps of the specified channel\n");
    printf("\t\tfor example:   sample_cli  scanchan,1,2,3\n");
    printf("\tsample_cli   connect,<ssid>,<security>,[password],<hidden>              connect to AP\n");
    printf("\t\tssid:                 if contains spaces need add a '\' before, and contains ',' \
            need add a '\\' before it\n");
    printf("\t\tsecurity:            OPEN/WEP/WPA_WPA2_PSK\n");
    printf("\t\tpassword:          if PWD contains spaces need add a '\' before, and contains ',' \
            need add a '\\' before it\n");
    printf("\t\thidden:              0:not hidden SSID    1:hidden SSID\n");
    printf("\t\tfor example:   sample_cli  connect,HISILICON,WPA_WPA2_PSK,12345678,0\n");
    printf("\tsample_cli  disconnect        disconnect to network\n");
    printf("\tsample_cli  wps,<method>,[bssid],[pin]        start wps connect\n");
    printf("\t\tmethod:        PBC/PIN\n");
    printf("\t\tbssid:           network bssid\n");
    printf("\t\tpin:              pin code\n");
    printf("\tsample_cli  status              request current connection status\n");
    printf("\tsample_cli  mac                 request local wifi mac address\n");
    printf("\tsample_cli  quit                 quit sample_sta\n");
    printf("\tsample_cli  help                show this message\n");
}

void sdio_pin_mux_init(void)
{
#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    system("himm 0x112F0008 0x681");
    system("himm 0x112F0010 0x581");
    system("himm 0x112F0014 0x581");
    system("himm 0x112F0018 0x581");
    system("himm 0x112F000C 0x581");
    system("himm 0x112F001C 0x581");
#else
    system("himm 0x112C0048 0x1D54");
    system("himm 0x112C004c 0x1134");
    system("himm 0x112C0060 0x1134");
    system("himm 0x112C0064 0x1134");
    system("himm 0x112C0058 0x1134");
    system("himm 0x112C005c 0x1134");
#endif
}

hi_void board_gpio_pin_power_off_init(void)
{
#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    system("himm 0x112F00B8 0x0601");
    system("himm 0x120DB400 0x08");
#else
    system("himm 0x112C0074 0x1000");
    system("himm 0x120B6400 0x10");
#endif
}

hi_void  board_gpio_set_power_off_value(hi_u8 level)
{
#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
    if (level) {
        system("himm 0x120DB3FC 0x08");
    } else {
        system("himm 0x120DB3FC 0x00");
    }
#else
    if (level) {
        system("himm 0x120B6040 0x10");
    } else {
        system("himm 0x120B6040 0x00");
    }
#endif
}

hi_void board_power_on(hi_void)
{
    board_gpio_pin_power_off_init();
    board_gpio_set_power_off_value(1);
}

hi_void board_power_off(hi_void)
{
    board_gpio_pin_power_off_init();
    board_gpio_set_power_off_value(0);
}

hi_void hi_wlan_power_reset()
{
    board_power_off();
    usleep(DELAY_TIME_US);
    board_power_on();
    usleep(DELAY_TIME_US);
}

static hi_s32 scan_chan_str_tok(hi_char *strin, hi_wlan_sta_scan_cfg_e *scan_cfg)
{
    hi_char *pstr = NULL;
    hi_u32  i = 0;
    hi_u32  current_chan_num = 0;
    hi_u32  chan_num = 0;

    pstr = strtok(strin, ",");
    while (pstr) {
        chan_num = (hi_u32)atoi(pstr);
        for (i = 0; i < current_chan_num + 1; i++) {
            if (scan_cfg->scan_chan[i] == chan_num) {
                break;
            } else if (chan_num > 0 && chan_num <= SCAN_CHAN_NUM_MIX) {
                scan_cfg->scan_chan[current_chan_num] = chan_num;
                current_chan_num++;
                break;
            } else {
                return HI_WLAN_INVALID_PARAMETER;
            }
        }
        pstr = strtok(NULL, ",");
    }
    scan_cfg->scan_chan_len = current_chan_num;
    return HI_SUCCESS;
}

static hi_void wlan_cleanup(hi_void)
{
    if (g_data->sock_thread) {
        pthread_cancel(g_data->sock_thread);
        pthread_join(g_data->sock_thread, NULL);
    }

#ifdef DRIVER_EXCEPTION_REPORT
    if (g_monitor.dev_fd > 0) {
        g_monitor.monitor_exit = HI_TRUE;
        int ret = ioctl(g_monitor.dev_fd, 0, NULL);
        if (ret < 0) {
            printf("fd:%d,ret=%d\n", g_monitor.dev_fd, ret);
        }
        close(g_monitor.dev_fd);
        g_monitor.dev_fd = -1;
    }

    if (g_monitor.monitor_thread) {
        pthread_cancel(g_monitor.monitor_thread);
        pthread_join(g_monitor.monitor_thread, NULL);
    }
#endif

    pthread_mutex_destroy(&g_data->mut);
    pthread_cond_destroy(&g_data->cond);
    if (g_data->state != STA_STATE_DISABLED) {
        wlan_stop_udhcpc();
        hi_wlan_sta_stop(g_data->ifname);
        hi_wlan_sta_close(g_data->ifname);
#ifdef _GPIO_RESET_DEVICE
        hi_wlan_power_reset();
#endif
    }

    if (g_data->sockfd != -1) {
        close(g_data->sockfd);
    }
    if (g_data) {
        free(g_data);
        g_data = NULL;
    }
    hi_wlan_sta_deinit();

    unlink(g_pid_file);
}

static hi_void wlan_terminate(hi_s32 sig)
{
    hi_unused(sig);
    wlan_cleanup();
    g_terminate = HI_TRUE;
    _exit(0);
}

static hi_void wlan_print_status(hi_wlan_data_s *pAd)
{
    hi_u32 i;
    hi_s32 results = 0;
    hi_char state[13] = {0};    /* max state length 13 */

    printf("\n==============================================================\n");
    printf("Scan List:\n");
    printf("  ID / SSID / MAC Address / Channel / Security / Signal Level\n");
    for (i = 0; i < pAd->ap_num; i++) {
        hi_char sec[13];        /* max sec length 13 */
        results = memset_s(sec, sizeof(sec), 0, sizeof(sec));
        if (results < EOK) {
            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
        }
        switch (pAd->aplist[i].security) {
            case HI_WLAN_SECURITY_OPEN:
                results = strcpy_s(sec, sizeof(sec), "OPEN");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
            case HI_WLAN_SECURITY_WEP:
                results = strcpy_s(sec, sizeof(sec), "WEP");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
            case HI_WLAN_SECURITY_WPA_WPA2_PSK:
                results = strcpy_s(sec, sizeof(sec), "WPA_WPA2_PSK");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
            case HI_WLAN_SECURITY_WPA_WPA2_EAP:
                results = strcpy_s(sec, sizeof(sec), "WPA_WPA2_EAP");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
            case HI_WLAN_SECURITY_WAPI_PSK:
                results = strcpy_s(sec, sizeof(sec), "WAPI_PSK");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
            case HI_WLAN_SECURITY_WAPI_CERT:
                results = strcpy_s(sec, sizeof(sec), "WAPI_CERT");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
            default:
                results = strcpy_s(sec, sizeof(sec), "UNKOWN");
                if (results < EOK) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                break;
        }
        printf("  %02d  %s  %s  %d  %s  %d\n", i, pAd->aplist[i].ssid,
               pAd->aplist[i].bssid,
               pAd->aplist[i].channel,
               sec,
               pAd->aplist[i].level);
    }
    printf("\n");
    printf("Connection:\n");
    printf("  Status / AP\n");
    if (pAd->connection.state == HI_WLAN_STA_CONN_STATUS_DISCONNECTED) {
        results = strcpy_s(state, sizeof(state), "DISCONNECTED");
        if (results < EOK) {
            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
        }
    } else if (pAd->connection.state == HI_WLAN_STA_CONN_STATUS_CONNECTING) {
        results = strcpy_s(state, sizeof(state), "CONNECTING");
        if (results < EOK) {
            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
        }
    } else if (pAd->connection.state == HI_WLAN_STA_CONN_STATUS_CONNECTED) {
        results = strcpy_s(state, sizeof(state), "CONNECTED");
        if (results < EOK) {
            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
        }
    } else {
        results = strcpy_s(state, sizeof(state), "UNKOWN");
        if (results < EOK) {
            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
        }
    }
    printf("  %s   %s\n", state,
           pAd->connection.state == HI_WLAN_STA_CONN_STATUS_DISCONNECTED ?
           "NONE" : pAd->connection.ap.ssid);
    printf("==============================================================\n");
    fflush(stdout);
}

/* insert a element to queue's end */
hi_s32 wlan_enqueue(struct squeue *pqueue, const hi_wlan_message_s *element)
{
    struct snode *pnew = NULL;

    if (pqueue == NULL || element == NULL) {
        return -1;
    }

    /* Create a new node */
    pnew = malloc(sizeof(struct snode));
    if (pnew == NULL) {
        return -1;
    }

    pnew->message = *element;
    pnew->next = NULL;

    if (pqueue->rear == NULL) {
        /* queue is empty, set front and rear points to new node */
        pqueue->front = pqueue->rear = pnew;
    } else {
        /* queue is not empty, set rear points to the new node */
        pqueue->rear = pqueue->rear->next = pnew;
    }

    return HI_SUCCESS;
}

/* read a element from queue's front, then free the buffer */
hi_s32 wlan_dequeue(struct squeue *pqueue, hi_wlan_message_s *element)
{
    struct snode *p = NULL;

    if (pqueue == NULL || element == NULL) {
        return HI_FAILURE;
    }

    if (pqueue->front == NULL) {
        return HI_FAILURE;
    }

    *element = pqueue->front->message;
    p = pqueue->front;
    pqueue->front = p->next;
    /* if the queue is empty, set rear = NULL */
    if (pqueue->front == NULL) {
        pqueue->rear = NULL;
    }
    free(p);

    return HI_SUCCESS;
}

/* receive events from interface layer, then send to main loop */
static hi_void wlan_event_receiver(hi_wlan_sta_event_e event, const hi_void *pPrivateData, hi_u32 PrivDataSize)
{
    hi_unused(PrivDataSize);
    hi_wlan_message_s message;
    hi_s32 results = 0;

    memset_s(&message, sizeof(message), 0, sizeof(hi_wlan_message_s));
    message.what = WLAN_MSG_BUTT;

    switch (event) {
        case HI_WLAN_STA_EVENT_DISCONNECTED:
            message.what = STA_EVT_DISCONNECTED;
            break;

        case HI_WLAN_STA_EVENT_SCAN_RESULTS_AVAILABLE:
            message.what = STA_EVT_SCANRESULTS_AVAILABLE;
            break;

        case HI_WLAN_STA_EVENT_CONNECTING:
            message.what = STA_EVT_CONNECTING;
            results = strcpy_s(message.obj.bssid, sizeof(message.obj.bssid), pPrivateData);
            if (results < EOK) {
                printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
            }
            break;

        case HI_WLAN_STA_EVENT_CONNECTED:
            message.what = STA_EVT_CONNECTED;
            results = strcpy_s(message.obj.bssid, sizeof(message.obj.bssid), pPrivateData);
            if (results < EOK) {
                printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
            }
            break;

        case HI_WLAN_STA_EVENT_SUPP_STOPPED:
            message.what = STA_EVT_SUPP_STOPPED;
            break;

        case HI_WLAN_STA_EVENT_DRIVER_STOPPED:
            message.what = STA_EVT_DRIVER_STOPPED;
            break;

        default:
            break;
    }
    if (message.what != WLAN_MSG_BUTT) {
        pthread_mutex_lock(&g_data->mut);
        if (wlan_enqueue(&g_data->cmd_queue, &message) == HI_SUCCESS) {
            pthread_cond_signal(&g_data->cond);
        }
        pthread_mutex_unlock(&g_data->mut);
    }
}

static hi_s32 wlan_enable_parse_bw_enable(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "1") == 0) {
        msg->obj.config.bw_sta_config.bw_enable = HI_TRUE;
    } else if (strcmp(tmp_arg, "0") == 0) {
        msg->obj.config.bw_sta_config.bw_enable = HI_FALSE;
    } else {
        printf("SAMPLE_STA: Other modes (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_enable_parse_bandwidth(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "5") == 0) {
        msg->obj.config.bw_sta_config.bw_bandwidth = HI_WLAN_BAND_WIDTH_5M;
    } else if (strcmp(tmp_arg, "10") == 0) {
        msg->obj.config.bw_sta_config.bw_bandwidth = HI_WLAN_BAND_WIDTH_10M;
    } else {
        printf("SAMPLE_STA: Other bandwidth (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_enable_parse_hw_module(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "g") == 0) {
        msg->obj.config.hw_mode = HI_WLAN_HWMODE_11G;
    } else if (strcmp(tmp_arg, "n") == 0) {
        msg->obj.config.hw_mode = HI_WLAN_HWMODE_11N;
    } else if (strcmp(tmp_arg, "b") == 0 && msg->obj.config.bw_sta_config.bw_enable == HI_FALSE) {
        msg->obj.config.hw_mode = HI_WLAN_HWMODE_11B;
    } else {
        printf("SAMPLE_STA: Other rate (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_enable_parse_pmf(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if ((atoi(tmp_arg) < HI_WLAN_NO_PROTECTION) || (atoi(tmp_arg) > HI_WLAN_PROTECTION_REQUIRED)) {
        printf("SAMPLE_STA: pmf modes (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    msg->obj.config.pmf_mode = (hi_wlan_pmf_mode)atoi(tmp_arg);
    return HI_SUCCESS;
}

static hi_s32 wlan_connect_parse_ssid(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strlen(tmp_arg) == 0 || strlen(tmp_arg) > MAX_SSID_LEN) {
        printf("SAMPLE_STA: SSID length is wrong!\n");
        return HI_FAILURE;
    }
    hi_s32 results = strcpy_s(msg->obj.config.ssid, sizeof(msg->obj.config.ssid), tmp_arg);
    if (results < 0) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_connect_parse_security(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};

    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "OPEN") == 0) {
        msg->obj.config.security = HI_WLAN_SECURITY_OPEN;
    } else if (strcmp(tmp_arg, "WEP") == 0) {
        msg->obj.config.security = HI_WLAN_SECURITY_WEP;
    } else if (strcmp(tmp_arg, "WPA_WPA2_PSK") == 0) {
        msg->obj.config.security = HI_WLAN_SECURITY_WPA_WPA2_PSK;
    } else {
        printf("SAMPLE_STA: security (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_connect_parse_password(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};

    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    hi_s32 results = strcpy_s(msg->obj.config.psswd, sizeof(msg->obj.config.psswd), tmp_arg);
    if (results < 0) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_connect_parse_hidden(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};

    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "1") == 0) {
        msg->obj.config.hidden_ssid = HI_TRUE;
    } else if (strcmp(tmp_arg, "0") == 0) {
        msg->obj.config.hidden_ssid = HI_FALSE;
    } else {
        printf("SAMPLE_STA: Other modes (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_wps_parse_method(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};

    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "PBC") == 0) {
        msg->obj.config.wps_method = HI_WLAN_WPS_PBC;
    } else if (strcmp(tmp_arg, "PIN") == 0) {
        msg->obj.config.wps_method = HI_WLAN_WPS_PIN;
    } else {
        printf("SAMPLE_STA: wps method (%s) is not supported!\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_wps_parse_bssid(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};

    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strlen(tmp_arg) != BSSID_LEN) {
        printf("SAMPLE_STA: BSSID length is wrong!\n");
        return HI_FAILURE;
    }
    hi_s32 results = strcpy_s(msg->obj.config.bssid, sizeof(msg->obj.config.bssid), tmp_arg);
    if (results < 0) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_wps_parse_pin(const hi_char *param, hi_wlan_message_s *msg, hi_u32 *off_set)
{
    *off_set = 0;
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};

    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strlen(tmp_arg) != PIN_CODE_LEN) {
        printf("SAMPLE_STA: PIN length is wrong!\n");
        return HI_FAILURE;
    }
    hi_s32 results = strcpy_s(msg->obj.config.wps_pin, sizeof(msg->obj.config.wps_pin), tmp_arg);
    if (results < 0) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    return HI_SUCCESS;
}

hi_s32 wlan_enable_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_u32                  off_set = 0;
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;

    printf(">SAMPLE_STA enable command\n");
    if (pdata->state != STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    if (wlan_enable_parse_bw_enable(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (msg->obj.config.bw_sta_config.bw_enable == HI_TRUE) {
        if (wlan_enable_parse_bandwidth(param, msg, &off_set) != HI_SUCCESS) {
            printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
            return HI_FAILURE;
        }
        param += off_set + 1;
    }
    if (wlan_enable_parse_hw_module(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (wlan_enable_parse_pmf(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    msg->what = STA_CMD_ENABLE;
    return HI_SUCCESS;
}

hi_s32 wlan_scan_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(param);
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA scan command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    msg->what = STA_CMD_SCAN;
    return HI_SUCCESS;
}

hi_s32 wlan_scanchan_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA scanchan command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    hi_s32 ret = scan_chan_str_tok(param, &msg->obj.chan_scan_cfg);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_STA: scanchn cmd Parameter error!\n");
        return HI_FAILURE;
    }

    msg->what = STA_CMD_SCANCHAN;
    return HI_SUCCESS;
}

hi_s32 wlan_status_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(param);
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA status command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    msg->what = STA_CMD_GET_STATUS;
    return HI_SUCCESS;
}

hi_s32 wlan_connect_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_u32                  off_set = 0;
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;

    printf(">SAMPLE_STA connect command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (wlan_connect_parse_ssid(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (wlan_connect_parse_security(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (msg->obj.config.security != HI_WLAN_SECURITY_OPEN) {
        if (wlan_connect_parse_password(param, msg, &off_set) != HI_SUCCESS) {
            printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
            return HI_FAILURE;
        }
        param += off_set + 1;
    }
    if (wlan_connect_parse_hidden(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    msg->what = STA_CMD_CONNECT;
    return HI_SUCCESS;
}

hi_s32 wlan_disconnect_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(param);
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA disconnect command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    msg->what = STA_CMD_DISCONNECT;
    return HI_SUCCESS;
}

hi_s32 wlan_disable_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(param);
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA disable command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    msg->what = STA_CMD_DISABLE;
    return HI_SUCCESS;
}

hi_s32 wlan_mac_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(param);
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA mac command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    msg->what = STA_CMD_MACADDRESS;
    return HI_SUCCESS;
}

hi_s32 wlan_quit_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA quit command\n");
    msg->what = STA_CMD_QUIT;
    return HI_SUCCESS;
}

hi_s32 wlan_help_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA help command\n");
    msg->what = STA_CMD_HELP;
    return HI_SUCCESS;
}

hi_s32 wlan_wps_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_u32                  off_set = 0;
    hi_wlan_data_s *pdata = (hi_wlan_data_s *)wdata;
    hi_wlan_message_s *msg = (hi_wlan_message_s *)pmsg;
    printf(">SAMPLE_STA wps command\n");
    if (pdata->state == STA_STATE_DISABLED) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    if (wlan_wps_parse_method(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (wlan_wps_parse_bssid(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    param += off_set + 1;
    if (wlan_wps_parse_pin(param, msg, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    param += off_set + 1;
    msg->what = STA_CMD_WPS;
    return HI_SUCCESS;
}

static const wlan_cmd_entry_stru  g_sta_cmd[] = {
    {"enable",              wlan_enable_cmd_process},
    {"scan",                wlan_scan_cmd_process},
    {"scanchan",            wlan_scanchan_cmd_process},
    {"status",              wlan_status_cmd_process},
    {"connect",             wlan_connect_cmd_process},
    {"disconnect",          wlan_disconnect_cmd_process},
    {"disable",             wlan_disable_cmd_process},
    {"mac",                 wlan_mac_cmd_process},
    {"quit",                wlan_quit_cmd_process},
    {"help",                wlan_help_cmd_process},
    {"wps",                 wlan_wps_cmd_process},
};
#define    STA_CMD_NUM    (sizeof(g_sta_cmd) / sizeof(g_sta_cmd[0]))

static hi_void *wlan_sock_thread(hi_void *args)
{
    hi_wlan_data_s *wdata = (hi_wlan_data_s *)args;
    hi_char buf[SOCK_BUF_MAX];
    ssize_t recvbytes = 0;
    hi_wlan_message_s message;
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    while (1) {
        /* 安全编程规则6.6例外(1) 对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
        memset_s(buf, sizeof(buf), 0, sizeof(buf));
        addrlen = sizeof(clientaddr);
        /* 安全编程规则6.6例外(1) 对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
        memset_s(&clientaddr, sizeof(struct sockaddr_in), 0, addrlen);

        if (memset_s(&message, sizeof(hi_wlan_message_s), 0, sizeof(hi_wlan_message_s)) < 0) {
            printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        }
        recvbytes = recvfrom(wdata->sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&clientaddr, &addrlen);
        if (recvbytes < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                printf("SAMPLE_STA: recvfrom error!file=%s,line=%d,func=%s, error:%s, fd:%d\n", \
                       __FILE__, __LINE__, __FUNCTION__, strerror(errno), wdata->sockfd);
                return NULL;
            }
        }
        if (sendto(wdata->sockfd, "OK", strlen("OK"), MSG_DONTWAIT, (const struct sockaddr *)&clientaddr,
                   addrlen) == -1) {
            printf("SAMPLE_STA: sendto error!file=%s,line=%d,func=%s, error:%s, fd:%d\n", \
                   __FILE__, __LINE__, __FUNCTION__, strerror(errno), wdata->sockfd);
        }
        if (wlan_sock_cmd_entry((hi_void *)wdata, buf, recvbytes, (hi_void *)&message) != HI_SUCCESS) {
            printf("SAMPLE_STA: wlan_sock_cmd_entry failed! file=%s,line=%d,func=%s\n", \
                   __FILE__, __LINE__, __FUNCTION__);
            continue;
        }
        pthread_mutex_lock(&wdata->mut);
        if (wlan_enqueue(&wdata->cmd_queue, &message) == HI_SUCCESS) {
            pthread_cond_signal(&wdata->cond);
        }
        pthread_mutex_unlock(&wdata->mut);
    }
}

static hi_s32 wlan_sock_create(hi_wlan_data_s *pdata)
{
    pdata->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (pdata->sockfd == -1) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s error:%s\n", __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return HI_FAILURE;
    }
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SOCK_PORT);
    if (bind(pdata->sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s,%s\n", __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 wlan_start_udhcpc(const hi_char *ifname)
{
    hi_s32 ret;
    hi_char param[128];     /* max param length 128 */
    hi_char cmd[SYSTEM_CMD_SIZE];
    hi_char *spawn_args[] = {"udhcpc", NULL, NULL, NULL};

    if (ifname == NULL) {
        return HI_FAILURE;
    }

    ret = sprintf_s(param, sizeof(param), "%s&", ifname);
    if (ret == -1) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    spawn_args[1] = "-i";   /* 1: 2th param */
    spawn_args[2] = param;  /* 2: 3th param */

    ret = sprintf_s(cmd, sizeof(cmd), "%s %s %s", spawn_args[0], spawn_args[1], spawn_args[2]); /* 0/1/2th param */
    if (ret == -1) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    ret = system(cmd);
    if (ret == -1) {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_void wlan_stop_udhcpc(hi_void)
{
    hi_s32 ret;
    hi_char cmd[SYSTEM_CMD_SIZE];
    hi_char *spawn_args[] = {"killall", NULL, NULL};

    spawn_args[1] = "udhcpc";

    ret = sprintf_s(cmd, sizeof(cmd), "%s -9 %s", spawn_args[0], spawn_args[1]);
    if (ret == -1) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    ret = system(cmd);
}

hi_void wlan_kill_process(hi_char *process)
{
    hi_s32 ret;
    hi_char cmd[SYSTEM_CMD_SIZE];
    hi_char *spawn_args[] = {"killall", NULL, NULL};

    spawn_args[1] = process;

    ret = sprintf_s(cmd, sizeof(cmd), "%s -9 %s", spawn_args[0], spawn_args[1]);
    if (ret == -1) {
        printf("SAMPLE_STA: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    ret = system(cmd);
}

static hi_void wlan_power(hi_s32 sig)
{
    hi_unused(sig);
    g_persist_on_signal = HI_TRUE;
}

/* handle SIGPWR from sample_pmoc. Before sleep, sample_pmoc sends a SIGPWR,
 * when received the SIGPWR, turn off WiFi. After wakeup, sample_pmoc sends
 * a SIGPWR again, when received the SIGPWR, turn on WiFi.
 * Notes: only used for sample, please use socktes for real life.
 */
static hi_void *wlan_power_timer(hi_void *args)
{
    hi_unused(args);
    hi_s32 results = 0;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    if (!g_persist_on_signal) {
        sleep(20);     /* sleep 20s */
        return NULL;
    }
    g_persist_on_signal = HI_FALSE;
    printf("SAMPLE_STA: Received SIGPWR\n");
    if (g_data->persist_on) {
        if (hi_wlan_sta_open(g_data->ifname, sizeof(g_data->ifname), &g_data->config) == HI_SUCCESS) {
            if (hi_wlan_sta_start(g_data->ifname, wlan_event_receiver) == HI_SUCCESS) {
                g_data->state = STA_STATE_ENABLED;
            } else {
                printf("SAMPLE_STA: hi_wlan_sta_start fail\n");
#ifdef DRIVER_EXCEPTION_REPORT
                hi_wlan_stop_monitor();
#endif
                hi_wlan_sta_close(g_data->ifname);
#ifdef _GPIO_RESET_DEVICE
                hi_wlan_power_reset();
#endif
            }
        }

        wlan_print_status(g_data);

        g_data->persist_on = HI_FALSE;
    } else {
        if (g_data->state != STA_STATE_DISABLED) {
            wlan_stop_udhcpc();
            hi_wlan_sta_stop(g_data->ifname);
#ifdef DRIVER_EXCEPTION_REPORT
            hi_wlan_stop_monitor();
#endif
            hi_wlan_sta_close(g_data->ifname);
#ifdef _GPIO_RESET_DEVICE
            hi_wlan_power_reset();
#endif
            results = memset_s(&g_data->connection, sizeof(hi_wlan_sta_conn_status_e), 0, \
                               sizeof(hi_wlan_sta_conn_status_e));
            if (results < 0) {
                printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
            }
            g_data->state = STA_STATE_DISABLED;
            g_data->persist_on = HI_TRUE;
        }
    }

    return NULL;
}

static hi_s32 wlan_timer_thread_cancel_power(hi_void)
{
    hi_s32 ret = 0;

    if (g_wlan_timer_thread_power) {
        pthread_cancel(g_wlan_timer_thread_power);
        pthread_join(g_wlan_timer_thread_power, (void *)&ret);
        g_wlan_timer_thread_power = 0;
    }

    return HI_SUCCESS;
}

static hi_s32 wlan_start_power_timer(hi_void)
{
    hi_s32 ret;

    ret = wlan_timer_thread_cancel_power();
    if (ret != HI_SUCCESS) {
        printf(("WiFi: call wlan_timer_thread_cancel_power fail!\n"));
    }

    ret = pthread_create(&g_wlan_timer_thread_power, NULL, wlan_power_timer, NULL);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_STA: Cann't create timer thread\n");
        g_wlan_timer_thread_power = 0;
    }

    return ret;
}

hi_void wlan_create_pid_file(const hi_char *pid_file)
{
    hi_char fbuf[100];      /* max fbuf length 100 */
    hi_s32 results;

    /* ensure /dev/wifi exist */
    if (access(g_dev_wifi_dir, F_OK) < 0) {
        if (mkdir(g_dev_wifi_dir, 0666) != 0) {                 /* wifi dir mod 0666 */
            printf("SAMPLE_STA: Create '%s' fail\n", g_dev_wifi_dir);
            return;
        }
        chmod(g_dev_wifi_dir, 0666);                            /* wifi dir mod 0666 */
    }

    /* create pid file, if exist, delete it firstly */
    if (access(pid_file, F_OK) == 0) {
        unlink(pid_file);
    }

    hi_s32 fd = open(pid_file, O_CREAT | O_TRUNC | O_WRONLY, 0666);    /* pid_file mod 0666 */
    if (fd < 0) {
        printf("SAMPLE_STA: Cann't create file '%s'\n", g_pid_file);
        return;
    }

    /* write pid into pid file */
    results = memset_s(fbuf, sizeof(fbuf), 0, sizeof(fbuf));
    if (results < EOK) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    results = sprintf_s(fbuf, sizeof(fbuf), "%d", getpid());
    if (results < EOK) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }

    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        printf("SAMPLE_STA: Cann't write pid to '%s'\n", g_pid_file);
    }
    close(fd);

    if (chmod(pid_file, 0666) < 0) {                            /* pid_file mod 0666 */
        printf("SAMPLE_STA: Failed to change '%s' to 0666\n", g_pid_file);
        unlink(pid_file);
    }
}
static hi_void set_lo_ipaddr(hi_void)
{
    hi_s32 results;
    hi_char cmd[SYSTEM_CMD_SIZE] = {0}; /* system Temporary variables */
    hi_char *spawn_args[] = {"ifconfig", "lo", "127.0.0.1", NULL};

    results = sprintf_s(cmd, sizeof(cmd), "%s %s %s", spawn_args[0], /* spawn_args[0]:ifconfig */
                        spawn_args[1], spawn_args[2]); /* spawn_args[1]:lo,spawn_args[2]:ipaddr */
    if (results < EOK) {
        printf("SAMPLE_STA: set lo ipaddr sprintf_s err!\n");
        return;
    }
    system(cmd);
}

void wlan_wakeup_device_fail_sig_handler(int sig)
{
    hi_unused(sig);
    g_wkup_fail_event = 1;
    sem_post(&g_wakeup_device_sem);
    hi_unused(sig);
}

static void* wlan_wkup_fail_thread_handler()
{
    int my_pid = getpid();
    char cmd_buf[128];  /* 128: buf len */
    if (sprintf_s(cmd_buf, sizeof(cmd_buf), "echo wlan0 set_wk_fail_process_pid %d > /sys/hisys/hipriv ",
        my_pid) == -1) {
        return NULL;
    }
    while (!g_terminate) {
        /* first wait insmod ko, so we can write /sys */
        sem_wait(&g_wakeup_device_sem);
        /* second, wirte pid to sys */
        if (g_wait_enable_event) {
            g_wait_enable_event = 0;
            system(cmd_buf);
        }
        /* wakeup device fail process.... */
        if (g_wkup_fail_event) {
            g_wkup_fail_event = 0;
            /* do something, such as: backup business, rm ko, and insmod ko again */
            printf("wakeup device fail, do something \n");
        }
    }
    return NULL;
}

static void wlan_wait_enable_ok(void)
{
    g_wait_enable_event = 1;
    sem_post(&g_wakeup_device_sem);
}

static void wlan_wkup_thread_exit(void)
{
    sem_post(&g_wakeup_device_sem);
}

static void wlan_wakeup_device_fail_init(void)
{
    pthread_t event_thread;
    if (pthread_create(&event_thread, NULL, wlan_wkup_fail_thread_handler, NULL) != 0) {
        printf("Thread create failed%s.\n", strerror(errno));
    }
    sem_init(&g_wakeup_device_sem, 0, 0);
    signal(WK_FAIL_SIG, wlan_wakeup_device_fail_sig_handler);
}

#ifdef DRIVER_EXCEPTION_REPORT
int do_read(hi_wlan_monitor* sta_data)
{
    hi_wifi_driver_event event;
    ssize_t bytes = read(sta_data->dev_fd, &event, sizeof(hi_wifi_driver_event));
    if (bytes <= 0) {
        return HI_FAILURE;
    }
    switch (event) {
        case DEV_PANIC:
            printf("wifi driver device panic.\n");
            break;
        case DRIVER_HUNG:
            printf("wifi driver hung.\n");
            break;
        default:
            printf("unkown event error:%d\n", event);
            break;
    }
    return HI_SUCCESS;
}

static void handle_wlan_driver_event(hi_wlan_monitor* sta_data)
{
    int ret = HI_FAILURE;
    if (sta_data->dev_fd < 0) {
        sta_data->dev_fd = open("/dev/hisi_wifi", O_RDWR);
        if (sta_data->dev_fd < 0) {
            usleep(MONITOR_FAIL_SLEEP_TIME);
            return ;
        }
    }

    while (!g_terminate && sta_data->monitor_exit == HI_FALSE) {
        ret = do_read(sta_data);
        if (ret != HI_SUCCESS) {
            break;
        }
    }
}

static hi_void *sta_monitor_thread(hi_void *args)
{
    hi_wlan_monitor* sta_data = (hi_wlan_monitor*)args;
    if (sta_data == NULL) {
        return NULL;
    }
    sta_data->monitor_exit = HI_FALSE;
    while (!g_terminate) {
        if (g_data->state != STA_STATE_ENABLED || sta_data->monitor_exit == HI_TRUE) {
            usleep(MONITOR_SLEEP_TIMEOUT);
            continue;
        }

        handle_wlan_driver_event(sta_data);
    }
    return NULL;
}

hi_void hi_wlan_stop_monitor()
{
    if (g_monitor.dev_fd > 0) {
        g_monitor.monitor_exit = HI_TRUE;
        int ret = ioctl(g_monitor.dev_fd, 0, NULL);
        if (ret < 0) {
            printf("fd:%d,ret=%d\n", g_monitor.dev_fd, ret);
        }
        close(g_monitor.dev_fd);
        g_monitor.dev_fd = -1;
    }
}

hi_void hi_wlan_start_monitor()
{
    g_monitor.monitor_exit = HI_FALSE;
}
#endif

hi_s32 main(hi_s32 argc, hi_char *argv[])
{
    hi_unused(argc);
    hi_unused(argv);
    hi_s32 ret;
    hi_s32 results;
    printf("%s\n", g_sample_version);
    set_lo_ipaddr();
    usage();

    wlan_create_pid_file(g_pid_file);

    signal(SIGINT, wlan_terminate);
    signal(SIGTERM, wlan_terminate);
    signal(SIGPWR, wlan_power);

    sdio_pin_mux_init();
    wlan_start_power_timer();
    g_data = (hi_wlan_data_s *)malloc(sizeof(hi_wlan_data_s));
    if (g_data == NULL) {
        return -1;
    }
    results = memset_s(g_data, sizeof(hi_wlan_data_s), 0, sizeof(hi_wlan_data_s));
    if (results < 0) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }

#ifdef DRIVER_EXCEPTION_REPORT
    results = memset_s(&g_monitor, sizeof(hi_wlan_monitor), 0, sizeof(hi_wlan_monitor));
    if (results < 0) {
        printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
#endif

    pthread_mutex_init(&g_data->mut, NULL);
    pthread_cond_init(&g_data->cond, NULL);
    g_data->cmd_queue.front = g_data->cmd_queue.rear = NULL;

    g_data->state = STA_STATE_DISABLED;
    ret = wlan_register_cmd((wlan_cmd_entry_stru *)&g_sta_cmd, STA_CMD_NUM);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_STA: register wlan cmd failed\n");
        goto out;
    }
    ret = wlan_sock_create(g_data);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_STA: create sock failed, please check if sample_ap or sample_sta is running\n");
        goto out;
    }
    ret = pthread_create(&g_data->sock_thread, NULL, wlan_sock_thread, g_data);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_STA: create sock thread failed\n");
        goto out;
    }

#ifdef DRIVER_EXCEPTION_REPORT
    g_monitor.dev_fd = -1;
    ret = pthread_create(&g_monitor.monitor_thread, NULL, sta_monitor_thread, &g_monitor);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_AP: create sta_monitor_thread failed\n");
        goto out;
    }
#endif

    ret = hi_wlan_sta_init();
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_STA: Init failed\n");
        return -1;
    }

    wlan_print_status(g_data);
    wlan_wakeup_device_fail_init();

    /* main loop */
    while (!g_terminate) {
        hi_wlan_message_s message;
        hi_u32 i;

        /* dequeue cmd_queue, if no command/event, wait */
        pthread_mutex_lock(&g_data->mut);
        while (wlan_dequeue(&g_data->cmd_queue, &message) != HI_SUCCESS) {
            pthread_cond_wait(&g_data->cond, &g_data->mut);
        }
        pthread_mutex_unlock(&g_data->mut);
        printf("=======MAIN LOOP MSG:%d========\n", message.what);
        /* a command or event arrives, process it */
        switch (message.what) {
            case STA_CMD_ENABLE:
                if (g_data->state == STA_STATE_ENABLED) {
                    break;
                }
                g_data->config = message.obj.config;
#ifdef _GPIO_RESET_DEVICE
                hi_wlan_power_reset();
#endif
                ret = hi_wlan_sta_open(g_data->ifname, sizeof(g_data->ifname), &g_data->config);
                if (ret == HI_SUCCESS) {
#ifdef DRIVER_EXCEPTION_REPORT
                    hi_wlan_start_monitor();
#endif
                    ret = hi_wlan_sta_start(g_data->ifname, wlan_event_receiver);
                    if (ret == HI_SUCCESS) {
                        g_data->state = STA_STATE_ENABLED;
                        wlan_print_status(g_data);
                        wlan_wait_enable_ok();
                    } else {
                        printf("SAMPLE_STA: hi_wlan_sta_start fail (%d)\n", ret);
#ifdef DRIVER_EXCEPTION_REPORT
                        hi_wlan_stop_monitor();
#endif
                        hi_wlan_sta_close(g_data->ifname);
#ifdef _GPIO_RESET_DEVICE
                        hi_wlan_power_reset();
#endif
                    }
                } else if (ret == (hi_s32)HI_INVALID_HANDLE) {
                    printf("SAMPLE_STA: hi_wlan_sta_open fail, other interface exist!\n");
                    g_terminate = HI_TRUE;
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_open fail (%d)\n", ret);
                }
                break;

            case STA_CMD_DISABLE:
                ret = hi_wlan_sta_stop(g_data->ifname);
                if (ret == HI_SUCCESS) {
#ifdef DRIVER_EXCEPTION_REPORT
                    hi_wlan_stop_monitor();
#endif
                    ret = hi_wlan_sta_close(g_data->ifname);
                    if (ret == HI_SUCCESS) {
                        results = memset_s(g_data, sizeof(hi_wlan_data_s), 0, sizeof(hi_wlan_data_s) - SOCK_STRUCT_LEN);
                        if (results < 0) {
                            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                                   results, __FILE__, __LINE__, __FUNCTION__);
                        }
                        g_data->state = STA_STATE_DISABLED;
                        wlan_stop_udhcpc();
                    }
#ifdef _GPIO_RESET_DEVICE
                    hi_wlan_power_reset();
#endif
                }
                wlan_print_status(g_data);
                break;

            case STA_CMD_SCAN:
                ret = hi_wlan_sta_start_scan(g_data->ifname);
                if (ret == HI_SUCCESS) {
                    g_data->state = STA_STATE_SCANNING;
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_start_scan fail (%d)\n", ret);
                }
                break;
            case STA_CMD_SCANCHAN:
                g_data->chan_scan_cfg = message.obj.chan_scan_cfg;
                ret = hi_wlan_sta_start_chan_scan(&g_data->chan_scan_cfg);
                if (ret == HI_SUCCESS) {
                    g_data->state = STA_STATE_SCANNING;
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_start_chan_scan fail (%d)\n", ret);
                }
                break;

            case STA_CMD_CONNECT:
                g_data->config = message.obj.config;

                ret = hi_wlan_sta_connect(g_data->ifname, &g_data->config);
                if (ret == HI_SUCCESS) {
                    g_data->state = STA_STATE_CONNECTING;
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_connect fail (%d)\n", ret);
                }
                break;

            case STA_CMD_DISCONNECT:
                ret = hi_wlan_sta_disconnect(g_data->ifname);
                if (ret == HI_SUCCESS) {
                    g_data->connection.state = HI_WLAN_STA_CONN_STATUS_DISCONNECTED;
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_disconnect fail (%d)\n", ret);
                }
                break;

            case STA_CMD_GET_STATUS:
                ret = hi_wlan_sta_get_connection_status(g_data->ifname, &g_data->connection);
                if (ret == HI_SUCCESS) {
                    wlan_print_status(g_data);
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_get_connection_status fail (%d)\n", ret);
                }
                break;

            case STA_CMD_WPS:
                g_data->config = message.obj.config;
                ret = hi_wlan_sta_start_wps(g_data->ifname, &g_data->config);
                if (ret != HI_SUCCESS) {
                    printf("SAMPLE_STA: hi_wlan_sta_get_connection_status fail (%d)\n", ret);
                }
                break;

            case STA_CMD_MACADDRESS:
                ret = hi_wlan_sta_get_mac_address(g_data->ifname, g_data->mac, sizeof(g_data->mac));
                if (ret == HI_SUCCESS) {
                    printf("MAC: %s\n", g_data->mac);
                    printf("> ");
                    fflush(stdout);
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_get_mac_address fail (%d)\n", ret);
                }
                break;

            case STA_CMD_QUIT:
                g_terminate = HI_TRUE;
                break;

            case STA_EVT_DISCONNECTED:
                g_data->connection.state = HI_WLAN_STA_CONN_STATUS_DISCONNECTED;
                wlan_stop_udhcpc();
                wlan_print_status(g_data);
                break;

            case STA_EVT_SCANRESULTS_AVAILABLE: {
                hi_u32 num = sizeof(g_data->aplist) / sizeof(hi_wlan_sta_access_point_e);

                results = memset_s(g_data->aplist, sizeof(g_data->aplist), 0, sizeof(g_data->aplist));
                if (results < 0) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                ret = hi_wlan_sta_get_connection_status(g_data->ifname, &g_data->connection);
                if (ret != HI_SUCCESS) {
                    printf("SAMPLE_STA: hi_wlan_sta_get_scan_results get status fail (%d)\n", ret);
                    break;
                }
                ret = hi_wlan_sta_get_scan_results(g_data->ifname, g_data->aplist, &num);
                if (ret == HI_SUCCESS) {
                    g_data->ap_num = num;
                    wlan_print_status(g_data);
                } else {
                    printf("SAMPLE_STA: hi_wlan_sta_get_scan_results fail (%d)\n", ret);
                }
            }
            break;

            case STA_EVT_CONNECTING:
                results = memset_s(&g_data->connection, sizeof(g_data->connection), 0, sizeof(g_data->connection));
                if (results < 0) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                g_data->connection.state = HI_WLAN_STA_CONN_STATUS_CONNECTING;
                results = strcpy_s(g_data->connection.ap.bssid, sizeof(g_data->connection.ap.bssid), message.obj.bssid);
                if (results < 0) {
                    printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                           results, __FILE__, __LINE__, __FUNCTION__);
                }
                for (i = 0; i < g_data->ap_num; i++) {
                    if (strcmp(g_data->connection.ap.bssid, g_data->aplist[i].bssid) == 0) {
                        ret = strcpy_s(g_data->connection.ap.ssid, sizeof(g_data->connection.ap.ssid),
                            g_data->aplist[i].ssid);
                        if (results < 0) {
                            printf("SAMPLE_STA: results=%d file=%s,line=%d,func=%s\n", \
                                   results, __FILE__, __LINE__, __FUNCTION__);
                        }
                    }
                }
                wlan_print_status(g_data);
                break;

            case STA_EVT_CONNECTED:
                ret = memset_s(&g_data->connection, sizeof(g_data->connection), 0, sizeof(g_data->connection));
                if (ret < 0) {
                    printf("SAMPLE_STA: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__);
                }
                g_data->connection.state = HI_WLAN_STA_CONN_STATUS_CONNECTED;
                ret = strcpy_s(g_data->connection.ap.bssid, sizeof(g_data->connection.ap.bssid), message.obj.bssid);
                if (ret < 0) {
                    printf("SAMPLE_STA: ret=%d file=%s, line=%d, func=%s\n", ret, __FILE__, __LINE__, __FUNCTION__);
                }
                for (i = 0; i < g_data->ap_num; i++) {
                    if (strcmp(g_data->connection.ap.bssid, g_data->aplist[i].bssid) == 0) {
                        ret = strcpy_s(g_data->connection.ap.ssid, sizeof(g_data->connection.ap.ssid),
                            g_data->aplist[i].ssid);
                        if (ret < 0) {
                            printf("SAMPLE_STA: ret=%d file=%s, line=%d, func=%s\n", \
                                   ret, __FILE__, __LINE__, __FUNCTION__);
                        }
                    }
                }
                ret = hi_wlan_sta_get_connection_status(g_data->ifname, &g_data->connection);
                if (ret != HI_SUCCESS) {
                    printf("SAMPLE_STA: STA_EVT_CONNECTED get status fail (%d)\n", ret);
                }
                wlan_print_status(g_data);
                wlan_start_udhcpc(g_data->ifname);
                break;

            case STA_EVT_SUPP_STOPPED:
            case STA_EVT_DRIVER_STOPPED:
                printf("SAMPLE_STA: Something wrong, disabling WiFi...\n");
                ret = hi_wlan_sta_stop(g_data->ifname);
                if (ret == HI_SUCCESS) {
#ifdef DRIVER_EXCEPTION_REPORT
                    hi_wlan_stop_monitor();
#endif
                    ret = hi_wlan_sta_close(g_data->ifname);
                    if (ret == HI_SUCCESS) {
                        if (memset_s(g_data, sizeof(hi_wlan_data_s), 0, sizeof(hi_wlan_data_s)) != 0) {
                            printf("SAMPLE_STA: file=%s, line=%d, func=%s\n", __FILE__, __LINE__, __FUNCTION__);
                        }
                        g_data->state = STA_STATE_DISABLED;
                    }
#ifdef _GPIO_RESET_DEVICE
                    hi_wlan_power_reset();
#endif
                }
                wlan_print_status(g_data);
                break;
            case STA_CMD_HELP:
                usage();
                break;
            default:
                break;
        }
    }
    wlan_wkup_thread_exit();
out:
    ret = wlan_timer_thread_cancel_power();
    if (ret != HI_SUCCESS) {
        printf(("WiFi: call wlan_timer_thread_cancel_power fail!\n"));
    }
    wlan_cleanup();
    return ret;
}
