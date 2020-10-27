/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: plat_firmware.cͷ�ļ�
 * Author: Hisilicon
 * Create: 2018-08-04
 */
#ifndef __PLAT_FIRMWARE_H__
#define __PLAT_FIRMWARE_H__

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "stdlib.h"
#include "hi_types.h"
#include "oal_net.h"
#include "exception_rst.h"
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include "oal_net.h"
#include "exception_rst.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define READ_MEG_TIMEOUT            200      /* 200ms */
#define READ_MEG_JUMP_TIMEOUT       100000   /* 100s */

#define FILE_CMD_WAIT_TIME_MIN      5000     /* 5000us */
#define FILE_CMD_WAIT_TIME_MAX      5100     /* 5100us */

#define VERSION_LEN                 64
#define READ_CFG_BUF_LEN            2048

#define DOWNLOAD_CMD_LEN            32
#define DOWNLOAD_CMD_PARA_LEN       150

#define CMD_SUB_PARA_CNT_MAX        15       /* ����������Ӳ��������Ŀ */

#define HOST_DEV_TIMEOUT            3
#define INT32_STR_LEN               32

#define SHUTDOWN_TX_CMD_LEN         64

#define CMD_JUMP_EXEC_RESULT_SUCC   0
#define CMD_JUMP_EXEC_RESULT_FAIL   1

#define MFG_FIRMWARE_BIN            1
#define FIRMWARE_BIN                0

/* �����Ƿ���device����Ĺؼ��� */
#define VER_CMD_KEYWORD             "VERSION"
#define JUMP_CMD_KEYWORD            "JUMP"
#define CONFIG_CMD_KEYWORD          "CONFIG"
#define FILES_CMD_KEYWORD           "FILES"
#define RMEM_CMD_KEYWORD            "READM"
#define WMEM_CMD_KEYWORD            "WRITEM"
#define QUIT_CMD_KEYWORD            "QUIT"

/* ������device������ִ�гɹ����صĹؼ��֣�host�յ�һ�¹ؼ���������ִ�гɹ� */
#define MSG_FROM_DEV_WRITEM_OK      "WRITEM OK"
#define MSG_FROM_DEV_READM_OK       ""
#define MSG_FROM_DEV_FILES_OK       "FILES OK"
#define MSG_FROM_DEV_READY_OK       "READY"
#define MSG_FROM_DEV_JUMP_OK        "JUMP OK"
#define MSG_FROM_DEV_CONFIG_OK      "CONFIG OK"
#define MSG_FROM_DEV_SET_OK         "SET OK"
#define MSG_FROM_DEV_QUIT_OK        ""

/* ������cfg�ļ���������Ĳ���ͷ��һ���Ϸ���cfg�����ʽΪ:����ͷ+����ؼ���(QUIT�������) */
#define FILE_TYPE_CMD_KEY           "ADDR_FILE_"
#define NUM_TYPE_CMD_KEY            "PARA_"
#define CFG_TYPE_CMD_KEY            "CFG_"

#define WIFI_CFG_MAC                "MAC"
#define WIFI_CFG_COUNTRY_CODE       "COUNTRY_CODE"
#define WIFI_CFG_DBB_PARAMS         "DBB_PARAMS"
#define WIFI_CFG_CH_TXPWR           "CH_TXPWR_OFFSET"
#define WIFI_CFG_FREQ_COMP          "FREQ_COMP"
#define WIFI_CFG_RSSI_OFFSET        "RSSI_OFFSET"

#define COMPART_KEYWORD             ' '
#define CMD_LINE_SIGN               ';'
#define CFG_INFO_RESERVE_LEN        2

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define OS_MEM_KFREE(p)             free(p)
#define OS_KMALLOC_GFP(size)        memalign(32, SKB_DATA_ALIGN(size))
#define OS_VMALLOC_GFP(size)        malloc(size)
#define OS_MEM_VFREE(p)             free(p)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define OS_KMALLOC_GFP(size)        oal_memalloc(size)
#endif
#define hiusb_align_32(len)         (ALIGN((len), 32))

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
enum FIRMWARE_CFG_CMD_ENUM {
    ERROR_TYPE_CMD = 0,            /* ��������� */
    FILE_TYPE_CMD,                 /* �����ļ������� */
    NUM_TYPE_CMD,                  /* �������ò��������� */
    CFG_TYPE_CMD,                  /* ������������ */
    QUIT_TYPE_CMD,                 /* �˳����� */
    SHUTDOWN_WIFI_TYPE_CMD,        /* SHUTDOWN WCPU���� */
};

enum FIRMWARE_CFG_FILE_ENUM {
    WIFI_CFG = 0,
    RAM_REG_TEST_CFG,
    CFG_FILE_TOTAL
};

enum DEV_SOFT_VER_TYPE {
    SOFT_VER_CO1 = 0,
    SOFT_VER_CO2,
    SOFT_VER_BUTT
};

/*****************************************************************************
  3 STRUCT DEFINE
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
typedef struct cmd_type_st {
    hi_s32       cmd_type;
    hi_u8        cmd_name[DOWNLOAD_CMD_LEN];
    hi_u8        cmd_para[DOWNLOAD_CMD_PARA_LEN];
} cmd_type_struct;

typedef struct cfg_cmd_st {
    hi_u8      cmd_name[DOWNLOAD_CMD_LEN];
    hi_u8      cmd_para[DOWNLOAD_CMD_PARA_LEN];
    hi_u16       val_len;
    hi_u32       val_offset;
} cfg_cmd_struct;

typedef struct firmware_globals_st {
    hi_s32            al_count[CFG_FILE_TOTAL];      /* �洢ÿ��cfg�ļ���������Ч��������� */
    cmd_type_struct  *apst_cmd[CFG_FILE_TOTAL];      /* �洢ÿ��cfg�ļ�����Ч���� */
    hi_u8             auc_CfgVersion[VERSION_LEN];   /* �洢cfg�ļ������õİ汾����Ϣ */
    hi_u8             auc_DevVersion[VERSION_LEN];   /* �洢����ʱdevice���ϱ��İ汾����Ϣ */
} firmware_globals_struct;

typedef struct _firmware_mem {
    /* ����firmware file���ݵ�buffer���Ƚ��ļ��������buffer�У�Ȼ��������device buffer���� */
    hi_u8  *puc_data_buf;
    /* pucDataBuf�ĳ��� */
    hi_u32 ul_data_buf_len;

#define CMD_BUFF_LEN       256
    hi_u8  *puc_recv_cmd_buff;
    hi_u8  *puc_send_cmd_buff;
} firmware_mem_stru;

typedef struct _efuse_info_st_ {
    hi_u32   chip_id: 8;
    hi_u32   chip_ver: 2;
    hi_u32   soft_ver: 2;
    hi_u32   host_ver: 2;
    hi_u32   resv_b2: 2;
    hi_u32   chip_ver_butt: 16;

    hi_u32   mac_h: 16;
    hi_u32   mac_h_butt: 16;

    hi_u32   mac_m: 16;
    hi_u32   mac_m_butt: 16;

    hi_u32   mac_l: 16;
    hi_u32   mac_l_butt: 16;
} efuse_info_stru;

typedef struct _firmware_file_st_ {
    hi_u8 *addr;
    hi_u32 len;
} firmware_file_stru;

#define DECLARE_FIRMWARE_FILE(filename)                     \
    static firmware_file_stru  firmware_file_##filename = { \
        .addr = (hi_u8 *)firmware_array_##filename,         \
        .len  = sizeof(firmware_array_##filename),          \
    }

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_s32 firmware_download(hi_u32 ul_index);
hi_s32 device_mem_dump(wifi_dump_mem_info_stru *mem_dump_info);
hi_u32 plat_firmware_init(void);
hi_s32 plat_firmware_clear(void);
hi_s32 firmware_read_efuse_info(hi_void);
efuse_info_stru *get_efuse_info_handler(hi_void);
hi_u32 get_device_soft_version(hi_void);
hi_s32 firmware_write_cfg(hi_u8 *key, hi_u8 *new_val, hi_u8 len);
hi_bool cfg_get_mac(hi_u8 *mac_addr, hi_u8 size);
hi_u32 firmware_sync_cfg_paras_to_wal_customize(hi_void);
hi_bool parse_mac_addr(const hi_u8 *str, hi_u8 str_len, hi_u8 *mac, hi_u8 size);
#ifdef _PRE_LINUX_BUILTIN
void firmware_set_fw_mode(int mode);
int firmware_get_fw_mode(hi_void);
#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of plat_firmware.h */
