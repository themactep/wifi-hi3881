/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for oal_mem.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_MEM_H__
#define __OAL_MEM_H__

#include "oal_net.h"
#include "oal_util.h"
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/kallsyms.h>
#endif
#include "oal_spinlock.h"
#include "oal_mm.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  �궨��
*****************************************************************************/
#define OAL_MEM_MAX_WORD_ALIGNMENT_BUFFER         3
#define hi_malloc(_id, _size) oal_memalloc((_size) + OAL_MEM_MAX_WORD_ALIGNMENT_BUFFER)
#define hi_free(_id, _ptr) oal_free(_ptr)

#define PACKET_H_MEM __attribute__((section("pkt_head_mem_section"))) __attribute__((zero_init))
#define PACKETMEM __attribute__((section("pkt_mem_section"))) __attribute__((zero_init))
#define PACKET_DC_MEM __attribute__((section("pkt_dc_mem_section"))) __attribute__((zero_init))

/* host����device�෢�����ݣ�sdio����Ϊ��ʹpayload�������ֽڶ��룬��������payloadǰ�����pad�������䣬
   ��ˣ�device����Ҫ�������payload���֣���Ҫƫ��pay�ĳ��ȣ��˽ӿ�ֻ��device��rx adaptʱʹ�ã���pad
   ���ְ����������ͨ��OAL_NETBUF_DATA(_pst_buf)��ȡ�ļ�Ϊ������payload���� */
#define oal_dev_netbuf_hcc_payload(_pst_buf) \
        (oal_dev_netbuf_get_payload(_pst_buf) + ((struct hcc_header *)oal_dev_netbuf_hcchdr(_pst_buf))->pad_payload)
#define oal_dev_netbuf_hcchdr(_pst_buf)  oal_netbuf_get_hcc_hdr_addr(_pst_buf)

#ifdef _PRE_DEBUG_MODE
#define oal_mem_tracing(_p_data, _uc_lock) oal_mem_trace(0, __LINE__, _p_data, _uc_lock)
#define OAL_DOG_TAG_SIZE             4   /* ���ƴ�С(4�ֽ�) */
#else
#define oal_mem_tracing(_p_data, _uc_lock)
#define OAL_DOG_TAG_SIZE             0
#endif

/* ����enhanced���͵�����ӿ����ͷŽӿڣ�ÿһ���ڴ�鶼����һ��4�ֽڵ�ͷ���� */
/* ����ָ���ڴ�����ṹ��oal_mem_struc�������ڴ��Ľṹ������ʾ��           */
/*                                                                           */
/* +-------------------+------------------------------------------+---------+ */
/* | oal_mem_stru addr |                    payload               | dog tag | */
/* +-------------------+------------------------------------------+---------+ */
/* |      4/8 byte       |                                          | 4 byte  | */
/* +-------------------+------------------------------------------+---------+ */
#define OAL_MEM_INFO_SIZE            4
#define OAL_DOG_TAG    0x5b3a293e    /* ���ƣ����ڼ���ڴ�Խ�� */

#define OAL_NETBUF_MACHDR_BYTE_LEN         64      /* netbuf mac head */
#define MAC_HEAD_OFFSET             (OAL_NETBUF_MACHDR_BYTE_LEN - WLAN_MAX_MAC_HDR_LEN)
#define CB_OFFSET                   (OAL_NETBUF_MACHDR_BYTE_LEN - WLAN_MAX_MAC_HDR_LEN - HI_MAX_DEV_CB_LEN)
/* HCC PAD LEN (64 - hcc - cb - mac) */
#define OAL_PAD_HDR_LEN             (OAL_NETBUF_MACHDR_BYTE_LEN - WLAN_MAX_MAC_HDR_LEN - HI_MAX_DEV_CB_LEN - \
                                     OAL_HCC_HDR_LEN)
#define OAL_NETBUF_CONTROL_COUNT  10

#define OAL_HCC_HDR_LEN         8
#define OAL_TX_CB_LEN           48
#define HI_MAX_DEV_CB_LEN      20      /* device��cb�ֶνṹ�峤�ȡ�ԭֵ19�� ���ֽڲ����롣 */

/* ����enhanced���͵�����ӿ����ͷŽӿڣ�ÿһ���ڴ�鶼����һ��4�ֽڵ�ͷ���� */
/* ����ָ���ڴ�����ṹ��oal_mem_struc�������ڴ��Ľṹ������ʾ��           */
/*                                                                           */
/* +-------------------+------------------------------------------+---------+ */
/* | oal_mem_stru addr |                    payload               | dog tag | */
/* +-------------------+------------------------------------------+---------+ */
/* |      4 byte       |                                          | 4 byte  | */
/* +-------------------+------------------------------------------+---------+ */
/*****************************************************************************
  ö�ٶ���
*****************************************************************************/
typedef enum {
    OAL_MEM_STATE_FREE  = 0,            /* ���ڴ���� */
    OAL_MEM_STATE_ALLOC,                /* ���ڴ��ѷ��� */
    OAL_MEM_STATE_BUTT
} oal_mem_state_enum;
typedef hi_u8 oal_mem_state_enum_uint8;

/*****************************************************************************
  ö����  : oal_mem_pool_id_enum_uint8
  Э����:
  ö��˵��: HOST���ڴ��ID
*****************************************************************************/
typedef enum {
    OAL_MEM_POOL_ID_EVENT = 0,              /* �¼��ڴ�� */
    OAL_MEM_POOL_ID_LOCAL,                  /* ���ر����ڴ��  */
    OAL_MEM_POOL_ID_MIB,                    /* MIB�ڴ�� */
    OAL_MEM_POOL_ID_BUTT,
}oal_mem_pool_id_enum;
typedef hi_u8 oal_mem_pool_id_enum_uint8;

/*****************************************************************************
  ö����  : oal_netbuf_priority_enum_uint8
  Э����:
  ö��˵��: netbuf���ȼ�
*****************************************************************************/
typedef enum {
    OAL_NETBUF_PRIORITY_LOW     = 0,  /* ������ȼ�,���ܿ������ */
    OAL_NETBUF_PRIORITY_MID     = 1,  /* �м����ȼ������Կ�����룬�����������������NƬ */
    OAL_NETBUF_PRIORITY_HIGH    = 2,  /* ������ȼ������Կ�����룬�ҿ��������������NƬ */

    OAL_NETBUF_PRIORITY_BUTT
}oal_netbuf_priority_enum;
typedef hi_u8 oal_netbuf_priority_enum_uint8;

/*****************************************************************************
  ö����  : oal_netbuf_id_enum_uint8
  Э����:
  ö��˵��: �����ṩnetbuf�ڴ��ID
*****************************************************************************/
typedef enum {
    OAL_NORMAL_NETBUF = 0,                /* ������֡����֡�ڴ�� */
    OAL_MGMT_NETBUF   = 1,                /* ����֡�ڴ�� */

    OAL_NETBUF_POOL_ID_BUTT
}oal_netbuf_id_enum;
typedef hi_u8 oal_netbuf_id_enum_uint8;

/*****************************************************************************
  ö����  : oal_mem_netbuf_pool_id_enum_uint8
  Э����:
  ö��˵��: netbuf�ڴ��ID
*****************************************************************************/
typedef enum {
    OAL_MEM_NETBUF_POOL_ID_SHORT_PKT = 0,                /* ��֡�ڴ�� */
    OAL_MEM_NETBUF_POOL_ID_MGMT_PKT,                     /* ����֡ */
    OAL_MEM_NETBUF_POOL_ID_LARGE_PKT,                    /* ��֡�ڴ�� */

    OAL_MEM_NETBUF_POOL_ID_BUTT
}oal_mem_netbuf_pool_id_enum;
typedef hi_u8 oal_mem_netbuf_pool_id_enum_uint8;

/*****************************************************************************
  �ṹ˵��: PKT�ڴ����ýṹ��
*****************************************************************************/
typedef struct {
    uintptr_t start_addr;  /* PKT�ڴ����׵�ַ */
    hi_u32    length;      /* �ڴ�鳤�� */
}oal_mem_pkt_cfg_stru;

/*****************************************************************************
  �ṹ��  : oal_netbuf_machdr_stru
  �ṹ˵��: ��ϵͳ��mac�ṹ���С
*****************************************************************************/
typedef struct {
    hi_u8        auc_mac_hdr[OAL_NETBUF_MACHDR_BYTE_LEN + OAL_DOG_TAG_SIZE];
}oal_netbuf_machdr_stru;

/*****************************************************************************
  �ṹ��  : oal_mem_pool_info_stru
  �ṹ˵��: �ڴ����Ϣ�ṹ��
*****************************************************************************/
typedef struct {
    uintptr_t   buff_base;    /* ���ڴ���ڴ�����ַ */
    hi_u32      buff_len;     /* ���ڴ���ڴ���ܳ��� */
}oal_mem_pool_info_stru;

/*****************************************************************************
  STRUCT����
*****************************************************************************/
/*****************************************************************************
  �ṹ��  : oal_mem_ctrl_blk_stru
  �ṹ˵��: ���ڴ�����ÿռ��װ��һ���ṹ��
*****************************************************************************/
typedef struct {
    hi_u8  *puc_base_addr;
    hi_u32 idx;
    hi_u32 max_size;
}oal_mem_ctrl_blk_stru;

/*****************************************************************************
  �ṹ��  : oal_mem_netbuf_info_stru
  �ṹ˵��: netbuf�ڴ��ά��ṹ��
*****************************************************************************/
typedef struct {
    hi_u32   dog_tag;            /* ���ƣ������ڴ�дԽ���� */
    hi_u32   alloc_file_id;      /* ����netbuf�ڴ�ʱ���ļ�ID */
    hi_u32   alloc_line_num;     /* ����netbuf�ڴ�ʱ���к� */
    hi_u32   alloc_time_stamp;   /* ����netbuf�ڴ�ʱ��ʱ��� */
    hi_u32   trace_file_id;      /* netbuf�ڴ��ڹؼ�·���ϵ��ļ�ID */
    hi_u32   trace_line_num;     /* netbuf�ڴ��ڹؼ�·���ϵ��к� */
    hi_u32   trace_time_stamp;   /* netbuf�ڴ��ڹؼ�·���ϵ�ʱ��� */
}oal_mem_netbuf_info_stru;

/*****************************************************************************
  �ṹ��  : oal_mem_stru
  �ṹ˵��: �ڴ��ṹ��
*****************************************************************************/
#pragma pack(push, 1)  /* �漰λ���������1�ֽڶ��� */
struct oal_mem_stru_tag {
    hi_u8                  *puc_data;                                   /* ������ݵ�ָ�� */
    hi_u8                  *puc_origin_data;                            /* ��¼���ݵ�ԭʼָ�� */
    hi_u16                  us_len;                                     /* �ڴ��ĳ��� */
    hi_u8                   user_cnt       :4;                          /* ���뱾�ڴ����û����� */
    oal_mem_state_enum_uint8    mem_state_flag :4;                      /* �ڴ��״̬ */
    oal_mem_pool_id_enum_uint8  pool_id        :4;                      /* ���ڴ�������һ���ڴ�� */
    hi_u8                   subpool_id     :4;                          /* ���ڴ���������һ�����ڴ�� */
};
typedef struct oal_mem_stru_tag  oal_mem_stru;
/* ȡ��ʵ�ʽṹ���룬�ָ�ԭ�ж��뷽ʽ */
#pragma pack(pop)
/*****************************************************************************
  �ṹ��  : oal_mem_subpool_stru
  �ṹ˵��: ���ڴ�ؽṹ��
*****************************************************************************/
typedef struct {
    oal_spin_lock_stru    st_spinlock;
    hi_u16            us_len;             /* �����ڴ�ص��ڴ�鳤�� */
    hi_u16            us_free_cnt;        /* �����ڴ�ؿ����ڴ���� */

    /* ��¼oal_mem_stru�����ڴ��������ջ��Ԫ�أ�������Ϊoal_mem_struָ�� */
    hi_void                **free_stack;

    hi_u16            us_total_cnt;       /* �����ڴ���ڴ������ */
    hi_u8             auc_resv[2];        /* 2: bytes�����ֶ� */
} oal_mem_subpool_stru;

/*****************************************************************************
  �ṹ��  : oal_mem_pool_stru
  �ṹ˵��: �ڴ�ؽṹ��
*****************************************************************************/
typedef struct {
    hi_u16              us_max_byte_len;        /* ���ڴ�ؿɷ����ڴ����󳤶� */
    hi_u8               subpool_cnt;         /* ���ڴ��һ���ж������ڴ�� */
    hi_u8               uc_resv;
    /* ���ڴ������������ */
    oal_mem_subpool_stru    ast_subpool_table[WLAN_MEM_MAX_SUBPOOL_NUM];

    hi_u16              us_mem_used_cnt;        /* ���ڴ�������ڴ�� */
    hi_u16              us_mem_total_cnt;       /* ���ڴ��һ���ж����ڴ�� */
    oal_mem_stru           *mem_start_addr;
}oal_mem_pool_stru;

/*****************************************************************************
  �ṹ��  : oal_mem_subpool_cfg_stru
  �ṹ˵��: ���ڴ�����ýṹ��
*****************************************************************************/
typedef struct {
    hi_u16  us_size;    /* �����ڴ���ڴ���С */
    hi_u16  us_cnt;     /* �����ڴ���ڴ����� */
}oal_mem_subpool_cfg_stru;

/*****************************************************************************
  �ṹ��  : oal_mem_pool_cfg_stru
  �ṹ˵��: �ڴ�����ýṹ��
*****************************************************************************/
typedef struct {
    oal_mem_pool_id_enum_uint8          pool_id;      /* �ڴ��ID */
    hi_u8                           subpool_cnt;  /* ���ڴ�����ڴ�ظ��� */

    hi_u8                           auc_resv[2];  /* 2: bytes�����ֶ� */

    /* ָ��ÿһ���ڴ�ؾ���������Ϣ */
    oal_mem_subpool_cfg_stru  *subpool_cfg_info;
}oal_mem_pool_cfg_stru;

/*****************************************************************************
  ��������
*****************************************************************************/
hi_void oal_mem_exit(hi_void);
hi_void *oal_mem_alloc(oal_mem_pool_id_enum_uint8 pool_id, hi_u16 us_len);
hi_u32 oal_mem_free(const hi_void *data);
hi_u32 oal_mem_free_enhanced(oal_mem_stru *mem);
hi_u32 oal_mem_init_pool(hi_void);
oal_mem_stru* oal_mem_alloc_enhanced(oal_mem_pool_id_enum_uint8 pool_id, hi_u16 us_len);
hi_u8 *oal_dev_netbuf_get_payload(const oal_dev_netbuf_stru *dev_netbuf);
hi_u8 *oal_dev_netbuf_cb(hi_u16 us_netbuf_index);
hi_u8 *oal_dev_netbuf_get_mac_hdr(const oal_dev_netbuf_stru *dev_netbuf);
hi_u32 oal_mem_dev_netbuf_free(oal_dev_netbuf_stru *dev_netbuf);
hi_u16 oal_dev_netbuf_get_len(const oal_dev_netbuf_stru *dev_netbuf);
hi_u32 oal_mem_trace(hi_u32 file_id, hi_u32 line_num, hi_void *data, hi_u8 lock);
hi_u8  oal_mem_get_vap_res_num(hi_void);
hi_u8  oal_mem_get_user_res_num(hi_void);
hi_u32 oal_mem_set_vap_res_num(const hi_u8 vap_res_num, const hi_u8 vap_spec);
hi_u32 oal_mem_set_user_res_num(const hi_u8 user_res_num, const hi_u8 user_spec);
hi_u32 oal_mem_set_subpool_config(const oal_mem_subpool_cfg_stru *subpool_cfg, oal_mem_pool_id_enum_uint8 pool_id,
                                  hi_u8 subpool_num);
hi_u16 oal_mem_get_dev_netbuff_cnt(hi_void);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif /* end of oal_mm.h */
