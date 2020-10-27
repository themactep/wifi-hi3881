/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sample common file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "hi_wlan.h"
#include "securec.h"
#include "sample_common.h"

/*****************************************************************************
  2 宏定义、全局变量
*****************************************************************************/
static wlan_cmd_common g_cmd_com = {0};

/*****************************************************************************
  4 函数实现
*****************************************************************************/
hi_s32 wlan_get_cmd_one_arg(const hi_char *pc_cmd, hi_char *pc_arg, hi_u32 pc_arg_len, hi_u32 *pul_cmd_offset)
{
    const hi_char *pc_cmd_copy = HI_NULL;
    hi_u32   pos = 0;

    if ((pc_cmd == HI_NULL) || (pc_arg == HI_NULL) || (pul_cmd_offset == HI_NULL)) {
        printf("SAMPLE_COMMON: pc_cmd/pc_arg/pul_cmd_offset null ptr error %pK, %pK, %pK!\n", \
               pc_cmd, pc_arg, pul_cmd_offset);
        return HI_FAILURE;
    }

    pc_cmd_copy = pc_cmd;

    while (*pc_cmd_copy != '\0' && !((*(pc_cmd_copy) == ',') && (*(pc_cmd_copy - 1) != '\\'))) {
        if ((*(pc_cmd_copy + 1) == ',') && (*(pc_cmd_copy) == '\\')) {
            ++pc_cmd_copy;
            continue;
        }
        pc_arg[pos] = *pc_cmd_copy;
        ++pos;
        ++pc_cmd_copy;

        if (pos >= pc_arg_len) {
            printf("SAMPLE_COMMON: ul_pos >= WLAN_CMD_NAME_MAX_LEN, ul_pos %d!\n", pos);
            return HI_FAILURE;
        }
    }

    pc_arg[pos]  = '\0';

    /* 字符串到结尾，返回错误码 */
    if (0 == pos) {
        printf("SAMPLE_COMMON:return param pc_arg is null!}\r\n");
        return HI_FAILURE;
    }
    printf("SAMPLE_COMMON:wlan_get_cmd_one_arg return [%s]\n", pc_arg);
    *pul_cmd_offset = (hi_u32)(pc_cmd_copy - pc_cmd);

    return HI_SUCCESS;
}

hi_s32 wlan_parse_cmd(hi_void *wdata, hi_char *cmd, hi_void *msg)
{
    hi_u8                    cmd_id;
    hi_u32                  off_set = 0;
    hi_char                wlan_name[WLAN_CMD_MAX_LEN] = {0};

    if (cmd == HI_NULL) {
        printf("SAMPLE_COMMON: cmd NULL! file=%s,line=%d,func=%s\n",  __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }

    if (wlan_get_cmd_one_arg(cmd, wlan_name, WLAN_CMD_MAX_LEN, &off_set) != HI_SUCCESS) {
        printf("SAMPLE_COMMON: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    cmd += (off_set + 1);

    for (cmd_id = 0; cmd_id < g_cmd_com.count; cmd_id++) {
        if (strcmp(g_cmd_com.cmd_tbl[cmd_id].cmd_name, wlan_name) == 0) {
            if (g_cmd_com.cmd_tbl[cmd_id].func(wdata, cmd, msg) != HI_SUCCESS) {
                printf("SAMPLE_COMMON:cmd[%s] exec fail! file=%s,line=%d,func=%s\n", \
                       wlan_name, __FILE__, __LINE__, __FUNCTION__);
                return HI_FAILURE;
            }
            return HI_SUCCESS;
        }
    }
    printf("SAMPLE_COMMON:cmd[%s] mismatch! file=%s,line=%d,func=%s\n", wlan_name, __FILE__, __LINE__, __FUNCTION__);
    return HI_FAILURE;
}

hi_s32 wlan_sock_cmd_entry(hi_void *wdata, const char *cmd, ssize_t len, hi_void *msg)
{
    hi_char *pcmd = HI_NULL;
    hi_char *pcmd_tmp = HI_NULL;

    if (len > WLAN_CMD_MAX_LEN) {
        printf("SAMPLE_COMMON: command len > %d! file=%s,line=%d,func=%s\n", \
               WLAN_CMD_MAX_LEN, __FILE__, __LINE__, __FUNCTION__);
        return HI_FAILURE;
    }
    pcmd = malloc(WLAN_CMD_MAX_LEN);
    if (pcmd == HI_NULL) {
        return HI_FAILURE;
    }
    if (cmd != HI_NULL) {
        if (memcpy_s(pcmd, len, cmd, len) != EOK) {
            printf("SAMPLE_COMMON: command memcpy_s failed! file=%s,line=%d,func=%s\n", \
                   __FILE__, __LINE__, __FUNCTION__);
            free(pcmd);
            return HI_FAILURE;
        }
    }
    pcmd[len] = '\0';
    pcmd_tmp = pcmd;
    if (wlan_parse_cmd(wdata, pcmd_tmp, msg) != HI_SUCCESS) {
        printf("SAMPLE_COMMON: wlan_parse_cmd return failed! file=%s,line=%d,func=%s\n", \
               __FILE__, __LINE__, __FUNCTION__);
        free(pcmd);
        return HI_FAILURE;
    }
    free(pcmd);
    return HI_SUCCESS;
}

hi_s32 wlan_register_cmd(wlan_cmd_entry_stru *cmd_tbl, hi_u32 num)
{
    wlan_cmd_common *tmp_list = HI_NULL;
    tmp_list = (wlan_cmd_common *)&g_cmd_com;
    for (hi_u32 i = 0; i < num; i++) {
        if (cmd_tbl[i].cmd_name == HI_NULL || cmd_tbl[i].func == HI_NULL) {
            printf("SAMPLE_COMMON: register cmd table failed! file=%s,line=%d,func=%s\n", \
                   __FILE__, __LINE__, __FUNCTION__);
            return HI_FAILURE;
        }
    }
    tmp_list->cmd_tbl = cmd_tbl;
    tmp_list->count = num;
    return HI_SUCCESS;
}

