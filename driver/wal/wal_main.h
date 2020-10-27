/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for wal_main.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __WAL_MAIN_H__
#define __WAL_MAIN_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"
#include "oam_ext_if.h"
#include "wal_event_msg.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define WAL_SDT_MEM_MAX_LEN             32      /* SDT读写内存的最大长度 */
/* 读取和设置全局变量的结构体 */
#define WAL_GLB_VAR_NAME_LEN            31
#define WAL_GLB_VAR_VAL_LEN             128
/* 提升到与接收任务优先级一致，避免因优先级低于接收任务，DHCP结果迟迟无法发送而连接失败 */
#define wal_wake_lock()
#define wal_wake_unlock()

/*****************************************************************************
  3 枚举定义
*****************************************************************************/
/* offload时，表示哪一个核的枚举 */
typedef enum {
    WAL_OFFLOAD_CORE_MODE_HMAC,
    WAL_OFFLOAD_CORE_MODE_DMAC,

    WAL_OFFLOAD_CORE_MODE_BUTT
} wal_offload_core_mode_enum;
typedef hi_u8 wal_offload_core_mode_enum_uint8;

/*****************************************************************************
  4 结构体定义
*****************************************************************************/
/* 维测，设置某一种具体event上报开关的参数结构体 */
typedef struct {
    hi_s32 l_event_type;
    hi_s32 l_param;
} wal_specific_event_type_param_stru;

/*****************************************************************************
  4 函数声明
*****************************************************************************/
hi_u32 wal_main_init(hi_void);
hi_void wal_main_exit(hi_void);
hi_u32 hi_wifi_device_init(hi_void);
hi_u32 hi_wifi_host_init(hi_void);
hi_u32 hi_wifi_host_download_fw(hi_void);
hi_void hi_wifi_host_exit(hi_void);
hi_u32 hi_wifi_plat_init(const hi_u8 vap_num, const hi_u8 user_num);
hi_void hi_wifi_plat_exit(hi_void);
hi_void hisi_wifi_resume_process(hi_void);
hi_u8 hi_wifi_get_host_exit_flag(hi_void);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wal_main */
