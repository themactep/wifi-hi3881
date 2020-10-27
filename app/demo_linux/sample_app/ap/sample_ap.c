/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Demo of wifi SoftAP interfaces usage.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/poll.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "sample_common.h"
#include "hi_wlan.h"
#include "securec.h"

#define DELAY_TIME_US               150000
#define MONITOR_SLEEP_TIMEOUT       10000
#define MONITOR_FAIL_SLEEP_TIME     10000

#define _GPIO_RESET_DEVICE

#define VERSION         "1.0.1"
#define SIN_ADDR(x)     (((struct sockaddr_in *) (&(x)))->sin_addr.s_addr)
/* SET_SA_FAMILY - set the sa_family field of a struct sockaddr */
#define SET_SA_FAMILY(addr, family)                 \
    do {                                            \
        memset_s ((char *) &(addr), sizeof(addr), '\0', sizeof(addr));  \
        (addr).sa_family = (family);                \
    } while (0)

const hi_pchar sample_version = "sample_ap v" VERSION "\n";

typedef enum hi_ap_msg_e {
    /* commands */
    AP_CMD_ENABLE,        /* start WiFi AP */
    AP_CMD_DISABLE,       /* stop WiFi AP */
    AP_CMD_BW,            /* set AP narrow band mode */
    AP_CMD_SET,           /* set AP config */
    AP_CMD_MACADDRESS,    /* get local WiFi MAC address */
    AP_CMD_HELP,          /* help sample_ap */
    AP_CMD_QUIT,          /* quit sample_ap */
    WLAN_MSG_BUTT,
} ap_msg_e;

typedef union hi_ap_msg_data_u {
    hi_wlan_ap_config_s config;
}ap_msg_data_u;

/* command/event information */
typedef struct hi_ap_message_s {
    ap_msg_e what;
    ap_msg_data_u obj;
} ap_message_s;

struct snode {
    ap_message_s message;
    struct snode *next;
};

struct squeue {
    struct snode *front;
    struct snode *rear;
};

typedef struct hi_ap_data_s {
    hi_char ifname[IFNAMSIZ + 1];
    hi_char mac[BSSID_LEN + 1];
    /* configuration of network connected or connecting */
    hi_wlan_ap_config_s config;

    /* current state of AP */
    hi_bool ap_enabled;

    /* mutex */
    pthread_mutex_t mut;
    pthread_cond_t cond;
    struct squeue cmd_queue;
    /* used for power save, if true, need turn on after wakeup */
    hi_bool persist_on;
    pthread_t sock_thread;
    hi_s32 sockfd;
} ap_data_s;

#ifdef DRIVER_EXCEPTION_REPORT
typedef enum {
    DEV_PANIC = 1,
    DRIVER_HUNG,
    UNKNOWN,
} hi_wifi_driver_event;

typedef struct {
    pthread_t monitor_thread;
    hi_s32 dev_fd;
    hi_u8 monitor_exit;
} hi_wlan_monitor;
#endif

hi_void wlan_ap_stop_udhcpd(hi_void);

#ifdef DRIVER_EXCEPTION_REPORT
hi_void hi_wlan_stop_monitor();
#endif

static ap_data_s *g_ap_data = NULL;

#ifdef DRIVER_EXCEPTION_REPORT
hi_wlan_monitor g_monitor = {0};
#endif

static hi_bool persist_on_signal = HI_FALSE;
static pthread_t wlan_timerThread_power = 0;

static const hi_char DEV_WIFI_DIR[] = "/dev/wifi";
static const hi_char PID_FILE[] = "/dev/wifi/sample.pid";
static const hi_char IPADDR[] = "192.168.49.1";
static const hi_char UDHCPD_CONFIG_FILE[] = "/etc/Wireless/udhcpd.conf";
#define SYSTEM_CMD_SIZE 1024

static hi_bool terminate = HI_FALSE;
static hi_void usage(hi_void)
{
    printf("\nUsage:\n");
    printf("\tsample_cli  enable       start wifi softap\n");
    printf("\tsample_cli  disable      stop wifi softap\n");
    printf("\tsample_cli  set,<ssid>,<channel>,<beacon int>,<b/g/n>,<bandwidth>,<security>,[password],<hidden> \
             set softap\n");
    printf("\t\tssid:                 if contains spaces need add a '\' before, \
             and contains ',' need add a '\\' before it\n");
    printf("\t\tchannel:            channel number(1 ~ 13)\n");
    printf("\t\tbeacon int:        (33 ~ 1000)\n");
    printf("\t\tb/g/n:              b/g/n mode\n");
    printf("\t\tbandwidth:        5/10/20, 5/10 not support in b mode\n");
    printf("\t\tsecurity:            OPEN/WEP/WPA_WPA2_PSK\n");
    printf("\t\tpassword:          length <= 63(HEX 64),if contains spaces need add a '\' before, \
              and contains ',' need add a '\\' before it\n");
    printf("\t\thidden:              0:not hidden SSID    1:hidden SSID\n");
    printf("\t\tfor example:   sample_cli  set,HISILICON,6,100,n,WPA_WPA2_PSK,12345678,0\n");
    printf("\tsample_cli  mac         get local wifi MAC address\n");
    printf("\t\tfor example:   sample_cli  bw,5\n");
    printf("\tsample_cli  quit          quit sample_ap\n");
    printf("\tsample_cli  help          show this message\n");
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

/* insert a element to queue's end */
hi_s32 wlan_enqueue(struct squeue *pqueue, const ap_message_s *element)
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
hi_s32 wlan_dequeue(struct squeue *pqueue, ap_message_s *element)
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
static hi_void wlan_cleanup(hi_void)
{
    if (g_ap_data->sock_thread) {
        pthread_cancel(g_ap_data->sock_thread);
        pthread_join(g_ap_data->sock_thread, NULL);
    }

#ifdef DRIVER_EXCEPTION_REPORT
    if (g_monitor.dev_fd > 0) {
        g_monitor.monitor_exit = HI_TRUE;
        close(g_monitor.dev_fd);
        g_monitor.dev_fd = -1;
    }

    if (g_monitor.monitor_thread) {
        pthread_cancel(g_monitor.monitor_thread);
        pthread_join(g_monitor.monitor_thread, NULL);
    }
#endif

    pthread_mutex_destroy(&g_ap_data->mut);
    pthread_cond_destroy(&g_ap_data->cond);
    if (g_ap_data->ap_enabled) {
        wlan_ap_stop_udhcpd();
        hi_wlan_ap_stop(g_ap_data->ifname);
        hi_wlan_ap_close(g_ap_data->ifname);
#ifdef _GPIO_RESET_DEVICE
        hi_wlan_power_reset();
#endif
    }

    if (g_ap_data->sockfd != -1) {
        close(g_ap_data->sockfd);
    }

    if (g_ap_data) {
        free(g_ap_data);
        g_ap_data = NULL;
    }

    hi_wlan_ap_deinit();

    unlink(PID_FILE);
}

static hi_void wlan_terminate(hi_s32 sig)
{
    hi_unused(sig);
    wlan_cleanup();
    terminate = HI_TRUE;
    _exit(0);
}

hi_s32 wlan_ap_set_ip(const hi_char *ifname, const hi_char *ip)
{
    hi_s32 ret = HI_FAILURE;
    hi_s32 results;
    struct ifreq ifr;

    if (ifname == NULL || *ifname == '\0' || ip == NULL)
        return HI_FAILURE;

    hi_s32 s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s <= 0)
        return HI_FAILURE;

    results = memset_s(&ifr, sizeof(struct ifreq), 0, sizeof(struct ifreq));
    if (results < EOK) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    SET_SA_FAMILY(ifr.ifr_addr,    AF_INET);
    SET_SA_FAMILY(ifr.ifr_dstaddr, AF_INET);
    SET_SA_FAMILY(ifr.ifr_netmask, AF_INET);
    results = strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
    if (results < EOK) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    SIN_ADDR(ifr.ifr_addr) = inet_addr(ip);
    if (ioctl(s, SIOCSIFADDR, &ifr) >= 0) {
        ret = HI_SUCCESS;
    }

    close(s);
    return ret;
}

static
hi_s32 creat_udhcpd_config_file(hi_char *ifname, const hi_char *config_file)
{
    hi_s32 ret = 0;
    hi_s32 fd;
    char *wbuf = NULL;

    /* open configure file, if not exist, create it */
    fd = open(config_file, O_CREAT | O_TRUNC | O_WRONLY, 0666); /* config_file mode 0666 */
    if (fd < 0) {
        printf("SAMPLE_AP: Cann't open configure file '%s'\n", config_file);
        return -1;
    }

    asprintf(&wbuf, "start           192.168.49.20\n"
                    "end             192.168.49.254\n"
                    "interface       %s\n"
                    "opt     dns     192.168.49.1\n"
                    "option  subnet  255.255.255.0\n"
                    "opt     router  192.168.49.1\n"
                    "option  domain  local\n"
                    "option  lease   864000\n",
                    ifname);

    if (write(fd, wbuf, strlen(wbuf)) < 0) {
        printf("SAMPLE_AP: Cann't write configuration to '%s'\n", config_file);
        ret = -1;
    }
    close(fd);
    free(wbuf);

    if (chmod(config_file, 0666) < 0) {                         /* config_file mode 0666 */
        printf("SAMPLE_AP: Failed to change '%s' to 0666\n", config_file);
        unlink(config_file);
        ret = -1;
    }

    return ret;
}

static hi_s32 wlan_ap_start_udhcpd(const hi_char *config_file)
{
    hi_s32 ret;
    hi_char param[128] = {0};   /* param max len 128 */
    hi_char cmd[SYSTEM_CMD_SIZE] = {0};
    char *spawn_args[] = {"udhcpd", NULL, NULL, NULL};

    if (config_file == NULL)
        return HI_FAILURE;

    ret = sprintf_s(param, sizeof(param), "%s", config_file);
    if (ret == -1) {
        return HI_FAILURE;
    }
    spawn_args[1] = "-S";   /* spawn_args[1]:-S,spawn_args[2]:wlan0\ap0 */
    spawn_args[2] = param;  /* spawn_args[1]:-S,spawn_args[2]:wlan0\ap0 */

    if (sprintf_s(cmd, sizeof(cmd), "%s %s %s", spawn_args[0],  /* spawn_args[0]:udhcpd */
        spawn_args[1], spawn_args[2]) == -1) {                      /* spawn_args[1]:-S,spawn_args[2]:wlan0\ap0 */
        return HI_FAILURE;
    }
    ret = system(cmd);
    if (ret == -1) {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_void wlan_ap_stop_udhcpd(hi_void)
{
    hi_s32 results;
    hi_char cmd[SYSTEM_CMD_SIZE] = {0}; /* system Temporary variables */
    hi_char *spawn_args[] = {"killall", "udhcpd", NULL};

    spawn_args[1] = "udhcpd";

    results = sprintf_s(cmd, sizeof(cmd), "%s -9 %s", spawn_args[0], spawn_args[1]);
    if (results < EOK) {
        printf("SAMPLE_AP: wlan_ap_stop_udhcpd sprintf_s err!\n");
        return;
    }
    system(cmd);
}
static hi_void set_lo_ipaddr(hi_void)
{
    hi_s32 results;
    hi_char cmd[SYSTEM_CMD_SIZE] = {0};
    hi_char *spawn_args[] = {"ifconfig", "lo", "127.0.0.1", NULL};

    results = sprintf_s(cmd, sizeof(cmd), "%s %s %s", spawn_args[0], /* spawn_args[0]:ifconfig */
        spawn_args[1], spawn_args[2]); /* spawn_args[1]:lo, spawn_args[2]:127.0.0.1 */
    if (results < EOK) {
        printf("SAMPLE_AP: set lo ipaddr sprintf_s err!\n");
        return;
    }
    system(cmd);
}
static hi_void wlan_power(hi_s32 sig)
{
    hi_unused(sig);
    persist_on_signal = HI_TRUE;
}

/* handle SIGPWR from sample_pmoc. Before sleep, sample_pmoc sends a SIGPWR,
 * when received the SIGPWR, turn off WiFi. After wakeup, sample_pmoc sends
 * a SIGPWR again, when received the SIGPWR, turn on WiFi.
 * Notes: only used for sample, please use socktes for real life.
 */
static hi_void *wlan_power_timer(hi_void *args)
{
    hi_unused(args);
    hi_s32 ret;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    if (!persist_on_signal) {
        sleep(20);          /* sleep 20s */
        return NULL;
    }
    persist_on_signal = HI_FALSE;
    printf("SAMPLE_AP: Received SIGPWR\n");
    if (g_ap_data->persist_on) {
        if (hi_wlan_ap_open(g_ap_data->ifname, sizeof(g_ap_data->ifname),
            g_ap_data->config.bw_bandwidth) == HI_SUCCESS) {
            if (hi_wlan_ap_start(g_ap_data->ifname, &g_ap_data->config) == HI_SUCCESS) {
                g_ap_data->ap_enabled = HI_TRUE;
                ret = wlan_ap_set_ip(g_ap_data->ifname, IPADDR);
                if (ret) {
                    printf("SAMPLE_AP: set local IP failed\n");
                }
                ret = creat_udhcpd_config_file(g_ap_data->ifname, UDHCPD_CONFIG_FILE);
                if (ret != 0) {
                    printf("\nSAMPLE_AP: creat udhcpd.conf failure\n");
                }
                ret = wlan_ap_start_udhcpd(UDHCPD_CONFIG_FILE);
                if (ret) {
                    printf("SAMPLE_AP: start udhcpd failed\n");
                }
            } else {
                printf("SAMPLE_AP: hi_wlan_ap_start fail\n");
#ifdef DRIVER_EXCEPTION_REPORT
                hi_wlan_stop_monitor();
#endif
                hi_wlan_ap_close(g_ap_data->ifname);
#ifdef _GPIO_RESET_DEVICE
                hi_wlan_power_reset();
#endif
            }
        }

        g_ap_data->persist_on = HI_FALSE;
    } else {
        if (g_ap_data->ap_enabled) {
            wlan_ap_stop_udhcpd();
            hi_wlan_ap_stop(g_ap_data->ifname);
#ifdef DRIVER_EXCEPTION_REPORT
            hi_wlan_stop_monitor();
#endif
            hi_wlan_ap_close(g_ap_data->ifname);
#ifdef _GPIO_RESET_DEVICE
            hi_wlan_power_reset();
#endif
            g_ap_data->ap_enabled = HI_FALSE;
            g_ap_data->persist_on = HI_TRUE;
        }
    }
    return NULL;
}

hi_s32 wlan_timer_thread_cancel_power(hi_void)
{
    hi_s32 ret = 0;

    if (wlan_timerThread_power) {
        pthread_cancel(wlan_timerThread_power);
        pthread_join(wlan_timerThread_power, (void*)&ret);
        wlan_timerThread_power = 0;
    }

    return HI_SUCCESS;
}

static hi_s32 wlan_start_power_timer(hi_void)
{
    hi_s32 ret;

    ret = wlan_timer_thread_cancel_power();
    if (ret != HI_SUCCESS) {
        printf("WiFi: call wlan_timer_thread_cancel_power fail!\n");
    }

    ret = pthread_create(&wlan_timerThread_power, NULL, wlan_power_timer, NULL);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_AP: Cann't create timer thread\n");
        wlan_timerThread_power = 0;
    }

    return ret;
}
hi_s32 ap_enable_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    ap_message_s *msg = (ap_message_s *)pmsg;
    printf(">SAMPLE_AP enable command\n");
    msg->what = AP_CMD_ENABLE;
    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_ssid(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    hi_s32 results = strcpy_s(msg->obj.config.ssid, sizeof(msg->obj.config.ssid), tmp_arg);
    if (results < 0) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }

    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_channel(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    msg->obj.config.channel = atoi(tmp_arg);
    if (msg->obj.config.channel < MIN_CHAN || msg->obj.config.channel > MAX_CHAN) {
        printf("SAMPLE_AP: channel (%d) not supported\n", msg->obj.config.channel);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_beacon_int(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    msg->obj.config.beacon_int = (hi_u32)atoi(tmp_arg);
    if ((msg->obj.config.beacon_int < BEACON_INT_MIN) || (msg->obj.config.beacon_int > BEACON_INT_MAX)) {
        printf("SAMPLE_AP: Beacon interval (%d) not supported\n", msg->obj.config.beacon_int);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_bandwidth(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    if (strcmp(tmp_arg, "5") == 0) {
        msg->obj.config.bw_bandwidth = HI_WLAN_BAND_WIDTH_5M;
    } else if (strcmp(tmp_arg, "10") == 0) {
        msg->obj.config.bw_bandwidth = HI_WLAN_BAND_WIDTH_10M;
    } else if (strcmp(tmp_arg, "20") == 0) {
        msg->obj.config.bw_bandwidth = HI_WLAN_BAND_WIDTH_20M;
    } else {
        printf("SAMPLE_AP: not support band (%s) in narrow band mode!\n", tmp_arg);
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}


static hi_s32 ap_set_parse_hw_module(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (!strcmp(tmp_arg, "b")) {
        msg->obj.config.hw_mode = 'b';
    } else if (!strcmp(tmp_arg, "g")) {
        msg->obj.config.hw_mode = 'g';
    } else if (!strcmp(tmp_arg, "n")) {
        msg->obj.config.hw_mode = 'n';
    } else {
        printf("SAMPLE_AP: hw_mode (%s) not supported\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_security(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "OPEN") == 0) {
        msg->obj.config.security = HI_WLAN_SECURITY_OPEN;
    } else if (strcmp(tmp_arg, "WPA_WPA2_PSK") == 0) {
        msg->obj.config.security = HI_WLAN_SECURITY_WPA_WPA2_PSK;
    } else {
        printf("SAMPLE_AP: security (%s) not supported\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_password(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strlen(tmp_arg) > MAX_PSSWD_LEN) {
        printf("SAMPLE_AP: error(password length > 64)\n");
        return HI_FAILURE;
    }

    hi_s32 results = strcpy_s(msg->obj.config.psswd, sizeof(msg->obj.config.psswd), tmp_arg);
    if (results < 0) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    return HI_SUCCESS;
}

static hi_s32 ap_set_parse_hidden(const hi_char *param, ap_message_s *msg, hi_u32 *off_set)
{
    hi_char tmp_arg[WLAN_CMD_MAX_LEN] = {0};
    *off_set = 0;
    memset_s(&tmp_arg, WLAN_CMD_MAX_LEN, 0, WLAN_CMD_MAX_LEN);
    if (wlan_get_cmd_one_arg(param, tmp_arg, WLAN_CMD_MAX_LEN, off_set) != HI_SUCCESS) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (strcmp(tmp_arg, "1") == 0) {
        msg->obj.config.hidden_ssid = HI_TRUE;
    } else if (strcmp(tmp_arg, "0") == 0) {
        msg->obj.config.hidden_ssid = HI_FALSE;
    } else {
        printf("SAMPLE_AP: hidden (%s) not supported\n", tmp_arg);
        return HI_FAILURE;
    }
    return HI_SUCCESS;
}
hi_s32 ap_set_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_u32                  off_set = 0;
    ap_message_s *msg = (ap_message_s *)pmsg;

    printf(">SAMPLE_AP set command\n");
    if (ap_set_parse_ssid(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (ap_set_parse_channel(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (ap_set_parse_beacon_int(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (ap_set_parse_hw_module(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (ap_set_parse_bandwidth(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (ap_set_parse_security(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    if (msg->obj.config.security != HI_WLAN_SECURITY_OPEN) {
        if (ap_set_parse_password(param, msg, &off_set) != HI_SUCCESS) {
            return HI_FAILURE;
        }
        param += off_set + 1;
    }
    if (ap_set_parse_hidden(param, msg, &off_set) != HI_SUCCESS) {
        return HI_FAILURE;
    }
    param += off_set + 1;
    msg->what = AP_CMD_SET;
    return HI_SUCCESS;
}
hi_s32 ap_disable_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    ap_message_s *msg = (ap_message_s *)pmsg;
    printf(">SAMPLE_AP disable command\n");
    msg->what = AP_CMD_DISABLE;
    return HI_SUCCESS;
}

hi_s32 ap_mac_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    ap_message_s *msg = (ap_message_s *)pmsg;
    printf(">SAMPLE_AP mac command\n");
    msg->what = AP_CMD_MACADDRESS;
    return HI_SUCCESS;
}
hi_s32 ap_help_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    ap_message_s *msg = (ap_message_s *)pmsg;
    printf(">SAMPLE_AP help command\n");
    msg->what = AP_CMD_HELP;
    return HI_SUCCESS;
}
hi_s32 ap_quit_cmd_process(hi_void *wdata, hi_char *param, hi_void *pmsg)
{
    hi_unused(wdata);
    hi_unused(param);
    ap_message_s *msg = (ap_message_s *)pmsg;
    printf(">SAMPLE_AP quit command\n");
    msg->what = AP_CMD_QUIT;
    return HI_SUCCESS;
}

static const wlan_cmd_entry_stru  g_ap_cmd[] = {
    {"enable",              ap_enable_cmd_process},
    {"set",                 ap_set_cmd_process},
    {"disable",               ap_disable_cmd_process},
    {"mac",               ap_mac_cmd_process},
    {"quit",               ap_quit_cmd_process},
    {"help",               ap_help_cmd_process},
};
#define    AP_CMD_NUM    (sizeof(g_ap_cmd) / sizeof(g_ap_cmd[0]))

static hi_void *ap_sock_thread(hi_void *args)
{
    ap_data_s *wdata = (ap_data_s *)args;
    hi_char buf[SOCK_BUF_MAX];
    ssize_t recvbytes = 0;
    ap_message_s message;
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    while (1) {
        /* 安全编程规则6.6例外(1) 对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
        memset_s(buf, sizeof(buf), 0, sizeof(buf));
        addrlen = sizeof(clientaddr);
        /* 安全编程规则6.6例外(1) 对固定长度的数组进行初始化，或对固定长度的结构体进行内存初始化 */
        memset_s(&clientaddr, sizeof(struct sockaddr_in), 0, addrlen);

        if (memset_s(&message, sizeof(ap_message_s), 0, sizeof(ap_message_s)) < 0) {
            printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        }
        recvbytes = recvfrom(wdata->sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&clientaddr, &addrlen);
        if (recvbytes < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                printf("SAMPLE_AP: recvfrom error!file=%s,line=%d,func=%s, error:%s, fd:%d\n", \
                    __FILE__, __LINE__, __FUNCTION__, strerror(errno), wdata->sockfd);
                return NULL;
            }
        }

        if (sendto(wdata->sockfd, "OK", strlen("OK"), MSG_DONTWAIT, (const struct sockaddr *)&clientaddr,
            addrlen) == -1) {
            printf("SAMPLE_AP: sendto error!file=%s,line=%d,func=%s, error:%s, fd:%d\n", \
                __FILE__, __LINE__, __FUNCTION__, strerror(errno), wdata->sockfd);
        }
        if (wlan_sock_cmd_entry((hi_void *)wdata, buf, recvbytes, (hi_void *)&message) != HI_SUCCESS) {
            printf("SAMPLE_AP: wlan_sock_cmd_entry failed! file=%s,line=%d,func=%s\n", \
                __FILE__, __LINE__, __FUNCTION__);
            continue;
        }

        pthread_mutex_lock(&wdata->mut);
        if (wlan_enqueue(&wdata->cmd_queue, &message) == HI_SUCCESS)
            pthread_cond_signal(&wdata->cond);
        pthread_mutex_unlock(&wdata->mut);
    }
}

static hi_s32 ap_sock_create(ap_data_s *pdata)
{
    pdata->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (pdata->sockfd == -1) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s error:%s\n", __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return HI_FAILURE;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SOCK_PORT);
    if (bind(pdata->sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s,%s\n", __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_void wlan_create_pid_file(const hi_char *pid_file)
{
    hi_char fbuf[100] = {0};  /* pbuf max len 100 */
    hi_s32 results;

    /* ensure /dev/wifi exist */
    if (access(DEV_WIFI_DIR, F_OK) < 0) {
        if (mkdir(DEV_WIFI_DIR, 0666) != 0) {                        /* DEV_WIFI_DIR mode 0666 */
            printf("SAMPLE_AP: Create '%s' fail\n", DEV_WIFI_DIR);
            return;
        }
        chmod(DEV_WIFI_DIR, 0666);                                  /* DEV_WIFI_DIR mode 0666 */
    }

    /* create pid file, if exist, delete it firstly */
    if (access(pid_file, F_OK) == 0)
        unlink(pid_file);

    hi_s32 fd = open(pid_file, O_CREAT | O_TRUNC | O_WRONLY, 0666);        /* pid_file mode 0666 */
    if (fd < 0) {
        printf("SAMPLE_AP: Cann't create file '%s'\n", PID_FILE);
        return;
    }

    /* write pid into pid file */
    results = memset_s(fbuf, sizeof(fbuf), 0, sizeof(fbuf));
    if (results < EOK) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    results = sprintf_s(fbuf, sizeof(fbuf), "%d", getpid());
    if (results < EOK) {
        printf("SAMPLE_AP: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }

    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        printf("SAMPLE_AP: Cann't write pid to '%s'\n", PID_FILE);
    }
    close(fd);

    if (chmod(pid_file, 0666) < 0) {                                /* pid_file mode 0666 */
        printf("SAMPLE_AP: Failed to change '%s' to 0666\n", PID_FILE);
        unlink(pid_file);
    }
}

#ifdef DRIVER_EXCEPTION_REPORT
int do_read(hi_wlan_monitor* ap_data)
{
    hi_wifi_driver_event event;
    ssize_t bytes = read(ap_data->dev_fd, &event, sizeof(hi_wifi_driver_event));
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

static void handle_wlan_driver_event(hi_wlan_monitor* ap_data)
{
    int ret = HI_FAILURE;
    if (ap_data->dev_fd < 0) {
        ap_data->dev_fd = open("/dev/hisi_wifi", O_RDWR);
        if (ap_data->dev_fd < 0) {
            usleep(MONITOR_FAIL_SLEEP_TIME);
            return ;
        }
    }

    while (!terminate && ap_data->monitor_exit == HI_FALSE) {
        ret = do_read(ap_data);
        if (ret != HI_SUCCESS) {
            break;
        }
    }
}

static hi_void *ap_monitor_thread(hi_void *args)
{
    hi_wlan_monitor* ap_data = (hi_wlan_monitor*)args;
    if (ap_data == NULL) {
        return NULL;
    }
    ap_data->monitor_exit = HI_FALSE;
    while (!terminate) {
        if (g_ap_data->ap_enabled != HI_TRUE || ap_data->monitor_exit == HI_TRUE) {
            usleep(MONITOR_SLEEP_TIMEOUT);
            continue;
        }

        handle_wlan_driver_event(ap_data);
    }
    return NULL;
}

hi_void hi_wlan_stop_monitor()
{
    if (g_monitor.dev_fd > 0) {
        g_monitor.monitor_exit = HI_TRUE;
        int ret = ioctl(g_monitor.dev_fd, 0, NULL);
        if (ret < 0) {
            printf("=fd:%d,ret=%d\n", g_monitor.dev_fd, ret);
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

    printf("%s\n", sample_version);
    set_lo_ipaddr();
    usage();

    wlan_create_pid_file(PID_FILE);

    signal(SIGINT, wlan_terminate);
    signal(SIGTERM, wlan_terminate);
    signal(SIGPWR, wlan_power);

    sdio_pin_mux_init();
    wlan_start_power_timer();
    g_ap_data = (ap_data_s *)malloc(sizeof(ap_data_s));
    if (g_ap_data == NULL) {
        return -1;
    }
    results = memset_s(g_ap_data, sizeof(ap_data_s), 0, sizeof(ap_data_s));
    if (results < 0) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }

#ifdef DRIVER_EXCEPTION_REPORT
    results = memset_s(&g_monitor, sizeof(hi_wlan_monitor), 0, sizeof(hi_wlan_monitor));
    if (results < 0) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
#endif

    pthread_mutex_init(&g_ap_data->mut, NULL);
    pthread_cond_init(&g_ap_data->cond, NULL);
    g_ap_data->cmd_queue.front = g_ap_data->cmd_queue.rear = NULL;

    results = strcpy_s(g_ap_data->config.ssid, sizeof(g_ap_data->config.ssid), "HisiAP");
    if (results < 0) {
        printf("SAMPLE_AP: results=%d file=%s,line=%d,func=%s\n", results, __FILE__, __LINE__, __FUNCTION__);
    }
    g_ap_data->config.channel = DEFAULT_CHANNEL;
    g_ap_data->config.security = HI_WLAN_SECURITY_OPEN;
    g_ap_data->config.beacon_int = DEFAULT_BEACON_INT;
    g_ap_data->config.hidden_ssid = HI_FALSE;
    g_ap_data->config.bw_bandwidth = HI_WLAN_BAND_WIDTH_20M;
    g_ap_data->ap_enabled = HI_FALSE;
    g_ap_data->persist_on = HI_FALSE;
    ret = wlan_register_cmd((wlan_cmd_entry_stru *)&g_ap_cmd, AP_CMD_NUM);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_AP: register AP cmd failed\n");
        goto out;
    }
    ret = ap_sock_create(g_ap_data);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_AP: create sock failed, please check if sample_ap or sample_sta is running\n");
        goto out;
    }

    ret = pthread_create(&g_ap_data->sock_thread, NULL, ap_sock_thread, g_ap_data);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_AP: create sock thread failed\n");
        goto out;
    }

#ifdef DRIVER_EXCEPTION_REPORT
    g_monitor.dev_fd = -1;
    ret = pthread_create(&g_monitor.monitor_thread, NULL, ap_monitor_thread, &g_monitor);
    if (ret != HI_SUCCESS) {
        printf("SAMPLE_AP: create sock thread failed\n");
        goto out;
    }
#endif

    ret = hi_wlan_ap_init();
    if (ret) {
        printf("SAMPLE_AP: initialize AP failed (%d)\n", ret);
        goto out;
    }

    while (!terminate) {
        ap_message_s message;
        pthread_mutex_lock(&g_ap_data->mut);
        while (wlan_dequeue(&g_ap_data->cmd_queue, &message) != HI_SUCCESS) {
            pthread_cond_wait(&g_ap_data->cond, &g_ap_data->mut);
        }
        pthread_mutex_unlock(&g_ap_data->mut);
        printf("=======SAMPLE_AP MAIN LOOP RECIEVE MSG:%d=======\n", message.what);

        fflush(stdout);

        switch (message.what) {
            case AP_CMD_ENABLE:
                if (g_ap_data->ap_enabled) {
                    printf("SAMPLE_AP: AP is already on!\n");
                    continue;
                }
#ifdef _GPIO_RESET_DEVICE
                hi_wlan_power_reset();
#endif
                ret = hi_wlan_ap_open(g_ap_data->ifname, sizeof(g_ap_data->ifname), g_ap_data->config.bw_bandwidth);
                if (ret == (hi_s32)HI_INVALID_HANDLE) {
                    printf("SAMPLE_AP: open AP failed , other interface exist!\n");
                    terminate = HI_TRUE;
                    continue;
                }
                if (ret != HI_SUCCESS) {
                    printf("SAMPLE_AP: open AP failed (%d)\n", ret);
#ifdef _GPIO_RESET_DEVICE
                    hi_wlan_power_reset();
#endif
                    continue;
                }
#ifdef DRIVER_EXCEPTION_REPORT
                hi_wlan_start_monitor();
#endif
                ret = hi_wlan_ap_start(g_ap_data->ifname, &g_ap_data->config);
                if (ret) {
                    printf("SAMPLE_AP: start AP failed (%d)\n", ret);
#ifdef DRIVER_EXCEPTION_REPORT
                    hi_wlan_stop_monitor();
#endif
                    hi_wlan_ap_close(g_ap_data->ifname);
#ifdef _GPIO_RESET_DEVICE
                    hi_wlan_power_reset();
#endif
                    continue;
                }

                g_ap_data->ap_enabled = HI_TRUE;
                ret = wlan_ap_set_ip(g_ap_data->ifname, IPADDR);
                if (ret)
                    printf("SAMPLE_AP: set local IP failed\n");

                ret = creat_udhcpd_config_file(g_ap_data->ifname, UDHCPD_CONFIG_FILE);
                if (ret != 0)
                    printf("\nSAMPLE_AP: creat udhcpd.conf failure\n");

                ret = wlan_ap_start_udhcpd(UDHCPD_CONFIG_FILE);
                if (ret)
                    printf("SAMPLE_AP: start udhcpd failed\n");
                printf("SAMPLE_AP: start udhcpd success\n");
                break;
            case AP_CMD_DISABLE:
                if (!g_ap_data->ap_enabled)
                    continue;
                ret = hi_wlan_ap_stop(g_ap_data->ifname);
                if (ret) {
                    printf("SAMPLE_AP: stop AP failed (%d)\n", ret);
                }
#ifdef DRIVER_EXCEPTION_REPORT
                hi_wlan_stop_monitor();
#endif
                ret = hi_wlan_ap_close(g_ap_data->ifname);
                if (ret != HI_SUCCESS) {
                    printf("SAMPLE_AP: close AP failed (%d)\n", ret);
                }
#ifdef _GPIO_RESET_DEVICE
                hi_wlan_power_reset();
#endif
                g_ap_data->ap_enabled = HI_FALSE;
                wlan_ap_stop_udhcpd();
                break;
            case AP_CMD_SET:
                /* restart AP */
                if (message.obj.config.bw_bandwidth != HI_WLAN_BAND_WIDTH_20M &&
                    (message.obj.config.hw_mode == 'b' || message.obj.config.channel == 14)) { /* 不支持14信道窄带AP */
                    printf("SAMPLE_AP: bw(%s) not support b mode or channel 14!\n",
                        message.obj.config.bw_bandwidth == HI_WLAN_BAND_WIDTH_5M ? "5" : "10");
                    continue;
                }
                g_ap_data->config = message.obj.config;
                wlan_ap_stop_udhcpd();
                if (*(g_ap_data->ifname) == '\0') {
                    printf("SAMPLE_AP: set AP without ifname!\n");
                    continue;
                }
#ifdef DRIVER_EXCEPTION_REPORT
                hi_wlan_stop_monitor();
#endif
                ret = hi_wlan_ap_setsoftap(g_ap_data->ifname, &g_ap_data->config);
                if (ret) {
                    printf("SAMPLE_AP: set AP failed (%d)\n", ret);
                    continue;
                }
#ifdef DRIVER_EXCEPTION_REPORT
                hi_wlan_start_monitor();
#endif
                ret = wlan_ap_set_ip(g_ap_data->ifname, IPADDR);
                if (ret)
                    printf("SAMPLE_AP: set local IP failed\n");

                ret = creat_udhcpd_config_file(g_ap_data->ifname, UDHCPD_CONFIG_FILE);
                if (ret != 0)
                    printf("\nSAMPLE_AP: creat udhcpd.conf failure\n");

                ret = wlan_ap_start_udhcpd(UDHCPD_CONFIG_FILE);
                if (ret)
                    printf("SAMPLE_AP: start udhcpd failed\n");
                break;
            case AP_CMD_MACADDRESS:
                ret = hi_wlan_ap_getmacaddress(g_ap_data->ifname, g_ap_data->mac, sizeof(g_ap_data->mac));
                if (ret) {
                    printf("SAMPLE_AP: get MAC failed (%d)\n", ret);
                    continue;
                }
                printf("MAC: %s\n", g_ap_data->mac);
                break;
            case AP_CMD_HELP:
                usage();
                break;
            case AP_CMD_QUIT:
                terminate = HI_TRUE;
                break;
            default:
                break;
        }
    }

out:
    ret = wlan_timer_thread_cancel_power();
    if (ret != HI_SUCCESS) {
        printf(("WiFi: call wlan_timer_thread_cancel_power fail!\n"));
    }
    wlan_cleanup();
    return 0;
}
