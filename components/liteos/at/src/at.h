/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Process AT cmd
 * Author: liangguangrui
 * Create: 2019-10-15
 */
#ifndef __AT_H__
#define __AT_H__

//#include <hi_early_debug.h>
#include <hi_types_base.h>
//#include "oal_mem.h"
#include "hi_at.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AT_CMD_MAX_PARAS 64
#define AT_CMD_MAX_LEN   128
#define AT_CMD_LIST_NUM  20

#define AT_RESPONSE_OK              do {                      \
                                        hi_at_printf("OK\r\n");     \
                                    } while (0)

#define AT_RESPONSE_ERROR           do {                      \
                                        hi_at_printf("ERROR\r\n");  \
                                    } while (0)

#define AT_ENTER                    do {                      \
                                        hi_at_printf("\r\n");       \
                                    } while (0)

#ifdef AT_CMD_DEBUG
#define at_printf(fmt...)  dprintf(fmt)
#else
#define at_printf(fmt...)
#endif

#define AT_MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define at_mac2str(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]

typedef enum {
    AT_IDLE,
    AT_CMD_PROCESS,
    AT_DATA_RECVING,
    AT_DATA_SENDING,
    AT_TRANSPARENT,
} at_state_machine;

typedef struct {
    at_state_machine at_state;
    unsigned short send_len;
    unsigned short trans_len;
    unsigned char is_first_recv_data;
    unsigned char is_first_over_data;
    unsigned short is_recv_end_char_flag;
} at_cmd_ctrl;

typedef enum {
    AT_CMD_TYPE_TEST   = 1,
    AT_CMD_TYPE_QUERY  = 2,
    AT_CMD_TYPE_SETUP  = 3,
    AT_CMD_TYPE_EXE = 4,
} at_cmd_type;

typedef struct {
    hi_s8 at_cmd_len;
    hi_char cmd_name[AT_CMD_MAX_LEN];
    at_cmd_type at_cmd_type;
    hi_s32 at_param_cnt;                  /* command actual para num  */
    hi_u32 param_array[AT_CMD_MAX_PARAS];
} at_cmd_attr;

typedef struct {
    HI_CONST at_cmd_func *at_cmd_list[AT_CMD_LIST_NUM];     /* user input at cmd list */
    hi_u16 at_cmd_num[AT_CMD_LIST_NUM];                     /* command number */
} at_cmd_func_list;

extern at_cmd_ctrl g_at_ctrl;

hi_u32 at_cmd_process(const hi_char *at_cmd_line);
hi_u32 at_param_null_check(hi_s32 argc, const hi_char **argv);
hi_u32 integer_check(const hi_char *val);
hi_u32 cmd_strtoaddr(const hi_char *param, hi_uchar *mac_addr, hi_u32 addr_len);
char* at_parse_string(const char *value, size_t *len);
const char* at_ssid_txt(const hi_u8 *ssid, size_t ssid_len);
void* at_malloc(size_t size);
void at_free(char *ptr);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif
