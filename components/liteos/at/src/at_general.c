/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL layer external API interface implementation.
 * Author: Hisilicon
 * Create: 2019-11-11
 */

#include <hi_stdlib.h>
#include <hi_at.h>
#include "at.h"
#include "at_general.h"

#ifndef CONFIG_FACTORY_TEST_MODE
#include "lwip/netifapi.h"
#include "lwip/api_shell.h"
#include "lwip/sockets.h"
#ifdef CONFIG_IPERF_SUPPORT
#include "iperf.h"
#endif
#endif
#include "hi_config.h"
#include <at_cmd.h>
#include <hi_wifi_api.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <oam_log.h>
#ifdef CONFIG_SIGMA_TEST
#include "hi_wifitest.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HI_AT_VER_FULL_PRODUCT_NAME_MAX_SIZE 100
#define IP_LINK_ID_MAX            8           /* 最多支持8个link,linkid 0-7 */
#define IP_TCP_SERVER_LISTEN_NUM  4           /* TCP 服务器能接收的最大客户端个数 */
#define IP_RESV_BUF_LEN           1024        /* IP收包buff */
#define IP_SEND_BUF_LEN           1024        /* IP发包buff，与AT_DATA_MAX_LEN 值要保持一致 */
#define IP_MUX_WAIT_TIME          HI_SYS_WAIT_FOREVER  /* 互斥锁时间 */
#define PRINT_SIZE_MAX            128
#define IP_UDP_LINK_MAX           4           /* 手动创建UDP link 最大个数 */

typedef struct {
    hi_s32 sfd;
    hi_u8 link_stats;
    hi_u8 link_res;       /* 标识当前连接是用户手动创建还是对端连接时自动创建 */
    hi_u8 ip_protocol;
    hi_u8 res;
} ip_conn_ctl_stru;

typedef struct {
    hi_s32 sfd;
    hi_u8 link_stats;
    hi_u8 res[3]; /* 3 4字节对齐补位 */
} ip_listen_socket_stru;

typedef enum {
    IP_NULL = 0,
    IP_TCP  = 1,
    IP_UDP  = 2,

    IP_PROTOCAL_BUTT
} ip_protocol ;
typedef hi_u8 ip_protocol_uint8;

typedef enum {
    IP_LINK_RES_INIT = 0, /* 初始值 */
    IP_LINK_MANUAL  = 1,  /* 手动创建link */
    IP_LINK_AUTO  = 2,   /* 自动创建link */

    IP_LINK_RES_BUTT
} ip_link_res ;
typedef hi_u8 ip_link_res_uint8;

typedef enum {
    IP_LINK_ID_IDLE = 0,      /* 空闲态 */
    IP_LINK_WAIT_RESV,        /* 等待接收数据 */
    IP_LINK_WAIT_CLOSE,       /* 执行异常触发关闭 */
    IP_LINK_USER_CLOSE,       /* 用户手动关闭 */
    IP_LINK_SERVER_LISTEN,    /* SERVER 监听态 */

    IP_LINK_STAUS_BUTT
} ip_link_stats ;
typedef hi_u8 ip_link_stats_uint8;

#ifndef CONFIG_FACTORY_TEST_MODE
static ip_conn_ctl_stru g_ip_link_ctl[IP_LINK_ID_MAX];
#endif

hi_u32 at_exe_at_cmd(void)
{
    AT_RESPONSE_OK;
    return HI_ERR_SUCCESS;
}

hi_u32 at_task_show(void)
{
#ifndef CONFIG_FACTORY_TEST_MODE
    TSK_INFO_S* ptask_info = HI_NULL;

    hi_u32 i = 0;

    ptask_info = (TSK_INFO_S*)malloc(sizeof(TSK_INFO_S));
    if (ptask_info == HI_NULL) {
        free(ptask_info);
        return HI_ERR_MALLOC_FAILUE;
    }

    hi_at_printf("task_info:\r\n");
    for (i = 0; i < g_taskMaxNum; i++) {
        memset_s(ptask_info, sizeof(TSK_INFO_S), 0, sizeof(TSK_INFO_S));
        hi_u32 ret = LOS_TaskInfoGet(i, ptask_info);
        if (ret == HI_ERR_SUCCESS) {
            hi_at_printf("%s,id=%d,status=%hd,pri=%hd,size=0x%x,cur_size=0x%x,peak_size=0x%x\r\n",
                         ptask_info->acName, ptask_info->uwTaskID, ptask_info->usTaskStatus, ptask_info->usTaskPrio,
                         ptask_info->uwStackSize, ptask_info->uwCurrUsed, ptask_info->uwPeakUsed);
        }
    }

    free(ptask_info);
#endif
    return HI_ERR_SUCCESS;
}

#ifndef CONFIG_FACTORY_TEST_MODE
hi_u32 at_exe_help_cmd(void)
{
    at_cmd_func_list *cmd_list = at_get_list();
    hi_u32 i = 0;
    hi_u32 cnt = 0;

    hi_at_printf("+HELP:\r\n");
    for (i = 0; i < AT_CMD_LIST_NUM; i++) {
        hi_u16 j = 0;

        for (j = 0; j < cmd_list->at_cmd_num[i]; j++) {
            at_cmd_func *cmd_func = (at_cmd_func *) ((cmd_list->at_cmd_list[i] + j));

            hi_at_printf("AT%-16s ", cmd_func->at_cmd_name);
            cnt++;
            if (cnt % 4 == 0) {  /* 每4个换行 */
                hi_at_printf("\r\n");
            }
        }
    }

    AT_ENTER;
    AT_RESPONSE_OK;
    return HI_ERR_SUCCESS;
}
#endif

/*****************************************************************************
 功能描述  :设置mac地址
*****************************************************************************/
hi_u32 cmd_set_macaddr(hi_s32 argc, const hi_char* argv[])
{
    hi_uchar mac_addr[HI_WIFI_MAC_LEN];

    if (argc != 1) { /* 1 param num */
        return HI_ERR_FAILURE;
    }
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    if (strlen(argv[0]) != 17) { /* 17 mac string len */
        return HI_ERR_FAILURE;
    }

    hi_u32 ret = cmd_strtoaddr(argv[0], mac_addr, HI_WIFI_MAC_LEN);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_set_macaddr((hi_char*)mac_addr, HI_WIFI_MAC_LEN) != 0) {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
 功能描述  :设置mac地址
*****************************************************************************/
hi_u32 cmd_get_macaddr(hi_s32 argc, const hi_char* argv[])
{
    hi_uchar mac_addr[HI_WIFI_MAC_LEN] = {0};
    hi_unref_param(argc);
    hi_unref_param(argv);

    if (hi_wifi_get_macaddr((hi_char*)mac_addr, HI_WIFI_MAC_LEN) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("+MAC:" AT_MACSTR "\r\n", at_mac2str(mac_addr));
    hi_at_printf("OK\r\n");

    return HI_ERR_SUCCESS;
}

#ifndef CONFIG_FACTORY_TEST_MODE
#ifdef CONFIG_IPERF_SUPPORT
hi_u32 at_iperf(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    if (cmd_iperf(argc, argv) == 0) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}
#endif

#endif

hi_u32 lwip_ifconfig_check(hi_s32 argc, const hi_char **argv)
{
    if ((argc == 0) || (argc == 1)) {
        return HI_ERR_SUCCESS;
    } else if (argc == 2) { /* 2个命令参数场景 */
        if ((strcmp("up", argv[1]) == 0) || (strcmp("down", argv[1]) == 0)) {
            return HI_ERR_SUCCESS;
        } else {
            return HI_ERR_FAILURE;
        }
    } else if (argc == 6) { /* 6个命令参数场景 */
        if ((strcmp("netmask", argv[2]) == 0) && (strcmp("gateway", argv[4]) == 0) && /* 2/4:配置netmask和gateway */
            (strcmp("inet", argv[1]) != 0) && (strcmp("inet6", argv[1]) != 0)) {
            return HI_ERR_SUCCESS;
        } else {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }
}

hi_u32 at_lwip_ifconfig_param_check(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    hi_u32 ret = lwip_ifconfig_check(argc, argv);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 at_lwip_ifconfig(hi_s32 argc, const hi_char **argv)
{
    hi_u32 ret = at_lwip_ifconfig_param_check(argc, argv);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
#ifndef CONFIG_FACTORY_TEST_MODE
    if (argc == 2) { /* 2:参数个数 */
        struct netif *netif = netif_find(argv[0]);
        if (netif == HI_NULL) {
            return HI_ERR_FAILURE;
        }
        ip4_addr_t loop_ipaddr, loop_netmask, loop_gw;
        if (strcmp(argv[1], "down") == 0) {
            (void)netifapi_netif_set_link_down(netif);
            (void)netifapi_netif_set_down(netif);
            (void)netifapi_netif_set_addr(netif, HI_NULL, HI_NULL, HI_NULL);
            for (hi_u8 index = 0; index < LWIP_IPV6_NUM_ADDRESSES; index++) {
                (void)netifapi_netif_rmv_ip6_address(netif, &netif->ip6_addr[index]);
            }
        } else if (strcmp(argv[1], "up") == 0) {
            (void)netifapi_netif_set_up(netif);
            if (strcmp(argv[0], netif->name) == 0) {
                (void)netifapi_netif_set_link_up(netif);
                (hi_void)netifapi_netif_add_ip6_linklocal_address(netif, HI_TRUE);
            } else if (strcmp(argv[0], DEFAULT_IFNAME_LOCALHOST) == 0) {
                (void)netifapi_netif_set_link_up(netif);
                IP4_ADDR(&loop_gw, 127, 0, 0, 1);       /* gateway 127.0.0.1 */
                IP4_ADDR(&loop_ipaddr, 127, 0, 0, 1);   /* ipaddr 127.0.0.1 */
                IP4_ADDR(&loop_netmask, 255, 0, 0, 0);  /* netmask 255.0.0.0 */
                (void)netifapi_netif_set_addr(netif, &loop_ipaddr, &loop_netmask, &loop_gw);
                (void)netifapi_netif_set_up(netif);
            }
        }
    } else {
#ifdef _PRE_LOSCFG_KERNEL_SMP
        ret = lwip_ifconfig(argc, (const char **)argv);
#else
        ret = lwip_ifconfig(argc, (char **)argv);
#endif
        if (ret == 0) {
            return HI_ERR_SUCCESS;
        } else if (ret == 3) { /* 3:up down 执行成功 */
            hi_at_printf("OK\r\n");
            return HI_ERR_SUCCESS;
        }
        return HI_ERR_FAILURE;
    }
#endif
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 at_set_log_level(hi_s32 argc, const hi_char **argv)
{
    hi_u8 level;

    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    if (argc != 1) {
        return HI_ERR_FAILURE;
    }

    level = (hi_u8)atoi(argv[0]);
    if (level > 3) { /* 1:param count, err:1, wrn:2, info:3 */
        return HI_ERR_FAILURE;
    }

    if (oam_log_level_set(level) != HI_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

#ifndef CONFIG_FACTORY_TEST_MODE
hi_void ip_link_release(hi_u8 link_id)
{
    closesocket(g_ip_link_ctl[link_id].sfd);
    g_ip_link_ctl[link_id].sfd = -1;
    g_ip_link_ctl[link_id].link_stats = IP_LINK_ID_IDLE;
    g_ip_link_ctl[link_id].link_res = IP_LINK_RES_INIT;
    g_ip_link_ctl[link_id].ip_protocol = IP_NULL;
}
#endif

hi_void at_exe_reset_cmd(hi_void)
{
    dprintf("OK\r\n");
    dprintf("start reset");

    cmd_reset();
}

#ifdef CONFIG_SIGMA_TEST
hi_u32 at_sigma_start(hi_s32 argc, const hi_char **argv)
{
    hi_unref_param(argc);
    hi_unref_param(argv);

    if (hi_sigma_init() != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}
#endif

const at_cmd_func g_at_general_func_tbl[] = {
    {"", 0, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_exe_at_cmd},
    {"+RST", 4, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_exe_reset_cmd},
    {"+MAC", 4, HI_NULL, (at_call_back_func)cmd_get_macaddr, (at_call_back_func)cmd_set_macaddr, HI_NULL},
#ifdef CONFIG_SIGMA_TEST
    {"+SIGMA", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_sigma_start},
#endif
#ifndef CONFIG_FACTORY_TEST_MODE
    {"+HELP", 5, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_exe_help_cmd},
#ifdef CONFIG_IPERF_SUPPORT
    {"+IPERF", 6, HI_NULL, HI_NULL, (at_call_back_func)at_iperf, HI_NULL},
#endif
#endif
    {"+LOGL", 5, HI_NULL, HI_NULL, (at_call_back_func)at_set_log_level, HI_NULL},
};

#define AT_GENERAL_FUNC_NUM (sizeof(g_at_general_func_tbl) / sizeof(g_at_general_func_tbl[0]))

void hi_at_general_cmd_register(void)
{
    hi_at_register_cmd(g_at_general_func_tbl, AT_GENERAL_FUNC_NUM);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
