/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: AT cmd implementation.
 * Author: liangguangrui
 * Create: 2019-10-15
 */
#include <stdlib.h>
#include <at.h>
#include <at_cmd.h>
#include <hi_at.h>
#include "at_wifi.h"
#include "securec.h"
#include "unistd.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

static hi_u32 check_name_and_callback(const at_cmd_func_list *ctx, hi_u8 tbl_index, HI_CONST at_cmd_func *cmd_tbl,
                                      hi_u16 cmd_num)
{
    hi_u32 ret = HI_ERR_SUCCESS;
    hi_u16 i;
    hi_u16 j;

    for (i = 0; i < ctx->at_cmd_num[tbl_index]; i++) {
        HI_CONST at_cmd_func *cmd_func = (at_cmd_func *)((ctx->at_cmd_list[tbl_index] + i));

        for (j = 0; j < cmd_num; j++) {
            if (((cmd_func->at_cmd_len == cmd_tbl[j].at_cmd_len) &&
                (strcmp(cmd_func->at_cmd_name, cmd_tbl[j].at_cmd_name) == 0)) ||
                ((cmd_tbl[j].at_test_cmd != HI_NULL) && (cmd_func->at_test_cmd == cmd_tbl[j].at_test_cmd)) ||
                ((cmd_tbl[j].at_query_cmd != HI_NULL) && (cmd_func->at_query_cmd == cmd_tbl[j].at_query_cmd)) ||
                ((cmd_tbl[j].at_setup_cmd != HI_NULL) && (cmd_func->at_setup_cmd == cmd_tbl[j].at_setup_cmd)) ||
                ((cmd_tbl[j].at_exe_cmd != HI_NULL) && (cmd_func->at_exe_cmd == cmd_tbl[j].at_exe_cmd))) {
                return HI_ERR_AT_NAME_OR_FUNC_REPEAT_REGISTERED;
            }
        }
    }

    return ret;
}

static hi_u32 check_cmd_tbl(HI_CONST at_cmd_func *cmd_tbl, hi_u16 cmd_num)
{
    hi_u16 i;
    hi_u16 j;

    for (i = 0; i < cmd_num; i++) {
        if (cmd_tbl[i].at_cmd_len != (hi_s8)strlen(cmd_tbl[i].at_cmd_name)) {
            return HI_ERR_AT_INVALID_PARAMETER;
        }

        for (j = 0; j < cmd_num; j++) {
            if (i == j) {
                continue;
            }

            if (((cmd_tbl[j].at_cmd_len == cmd_tbl[i].at_cmd_len) &&
                (strcmp(cmd_tbl[j].at_cmd_name, cmd_tbl[i].at_cmd_name) == 0)) ||
                ((cmd_tbl[j].at_test_cmd != HI_NULL) && (cmd_tbl[j].at_test_cmd == cmd_tbl[i].at_test_cmd)) ||
                ((cmd_tbl[j].at_query_cmd != HI_NULL) && (cmd_tbl[j].at_query_cmd == cmd_tbl[i].at_query_cmd)) ||
                ((cmd_tbl[j].at_setup_cmd != HI_NULL) && (cmd_tbl[j].at_setup_cmd == cmd_tbl[i].at_setup_cmd)) ||
                ((cmd_tbl[j].at_exe_cmd != HI_NULL) && (cmd_tbl[j].at_exe_cmd == cmd_tbl[i].at_exe_cmd))) {
                return HI_ERR_AT_NAME_OR_FUNC_REPEAT_REGISTERED;
            }

        }
    }

    return HI_ERR_SUCCESS;
}

hi_u32 hi_at_register_cmd(HI_CONST at_cmd_func *cmd_tbl, hi_u16 cmd_num)
{
    hi_u32 ret = HI_ERR_FAILURE;
    hi_u8 i;

    if (cmd_tbl == HI_NULL || cmd_num == 0) {
        return HI_ERR_FAILURE;
    }

    ret = check_cmd_tbl(cmd_tbl, cmd_num);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    at_cmd_func_list *cmd_list = at_get_list();
    for (i = 0; i < AT_CMD_LIST_NUM; i++) {
        if ((cmd_list->at_cmd_list[i] == HI_NULL) || (cmd_list->at_cmd_num[i] == 0)) {
            cmd_list->at_cmd_list[i] = cmd_tbl;
            cmd_list->at_cmd_num[i] = cmd_num;
            ret = HI_ERR_SUCCESS;
            break;
        }

        ret = check_name_and_callback(cmd_list, i, cmd_tbl, cmd_num);
        if (ret != HI_ERR_SUCCESS) {
            break;
        }
    }


    return ret;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
