/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hcc driver implementatioin.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HCC_HOST_H
#define __HCC_HOST_H

#include "hi_types.h"
#include "hcc_comm.h"
#include "oal_ext_if.h"
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "oal_sdio_host_if.h"
#include "oal_sdio_comm.h"
#include "oal_thread.h"
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
 �궨��
*****************************************************************************/
#define HCC_OFF         0
#define HCC_ON          1
#define HCC_EXCEPTION   2

#define HCC_TX_FLOW_HI_LEVEL        512
#define HCC_TX_FLOW_LO_LEVEL        128

#define HCC_FLOW_HIGH_PRI_BUFF_CNT  5 /* device��Ԥ���ĸ����ȼ�ר��buffer������Ҫ��OAL_NETBUF_HIGH_PRIORITY_COUNT��ͬ */
#define HCC_FLOW_LOW_PRI_BUFF_CNT   5

#define LOG_P0                   0
#define LOG_P1                   1
#define LOG_P2                   2
#define LOG_P3                   3
#define LOG_ID                   4
#define SHIF_8_BIT               8
#define WORD_WIDTH               4

#define HCC_HEARTBEAT_TIMEOUT           (60 * 1000)
#define VERIFY_CODE                     0x55aa55aa
#define HCC_NETBUF_RESERVED_ROOM_SIZE   (HCC_HDR_TOTAL_LEN + HISDIO_H2D_SCATT_BUFFLEN_ALIGN)

/*****************************************************************************
 ö�ٶ���
*****************************************************************************/
typedef enum {
    HCC_FLOWCTRL_SDIO,
    HCC_FLOWCTRL_CREDIT,
    HCC_FLOWCTRL_BUTT
}hcc_flowctrl_type;

typedef enum {
    HCC_SINGLE_SEND  = 0,
    HCC_ASSEM_SEND,
    HCC_MODE_COUNT
} hcc_send_mode;

typedef enum {
    HCC_TX,
    HCC_RX,
    HCC_DIR_COUNT
} hcc_chan_type;

typedef hi_s32 (* hcc_rx_pre_do)(hi_u8 stype, hcc_netbuf_stru *pst_netbuf, hi_u8 **pre_do_context);
typedef hi_s32 (* hcc_rx_post_do)(hi_u8 stype, const hcc_netbuf_stru *pst_netbuf, hi_u8 *pre_do_context);


typedef struct {
    hi_u32              pkts_count;
    hcc_rx_pre_do       pre_do;
    hcc_rx_post_do      post_do;
    hi_void            *context;    /* the callback argument */
}hcc_rx_action_stru;

typedef struct {
    hcc_rx_action_stru          action[HCC_ACTION_TYPE_BUTT];
} hcc_rx_action_info_stru;

/*****************************************************************************
 �ṹ�嶨��
*****************************************************************************/
typedef sdio_msg_rx hcc_msg_rx;

typedef struct {
    hi_u8                       flowctrl_flag;
    hi_u8                       enable;
    hi_u16                      flow_type;
    hi_u16                      is_stopped;
    hi_u16                      low_waterline;
    hi_u16                      high_waterline;
} hcc_flow_ctrl_stru;

typedef struct {
    /* transfer pkts limit every loop */
    hi_u32                  netbuf_pool_type;
    hi_u32                  burst_limit;
    hcc_flow_ctrl_stru               flow_ctrl;
    hcc_send_mode               send_mode;
    hi_u32                  total_pkts;
    hi_u32                  loss_pkts;
    oal_netbuf_head_stru        data_queue;
    oal_spin_lock_stru          data_queue_lock;
    wlan_net_queue_type         wlan_queue_id;
} hcc_trans_queue_stru;

#define HCC_TX_ASSEM_INFO_MAX_NUM  (HISDIO_HOST2DEV_SCATT_MAX + 1)
#define HCC_RX_ASSEM_INFO_MAX_NUM    (HISDIO_DEV2HOST_SCATT_MAX + 1)

typedef struct {
    hcc_trans_queue_stru              queues[HCC_QUEUE_COUNT];
} hcc_trans_queues_stru;

typedef struct {
    /* The +1 for the single pkt */
    hi_u32                       info[HCC_TX_ASSEM_INFO_MAX_NUM];

    /* The max support assemble pkts */
    hi_u32                      assemble_max_count;
    /* netx assem pkts list */
    oal_netbuf_head_stru            assembled_head;
    /* the queue is assembling */
    hcc_queue_type_enum                  assembled_queue_type;
} hcc_tx_assem_info_stru;

typedef struct {
    hi_u32                       info[HCC_RX_ASSEM_INFO_MAX_NUM];
} hcc_rx_assem_info;

typedef hi_void (*flowctrl_cb)(hi_void);

typedef struct {
    hi_u32 flowctrl_flag;
    hi_u32 flowctrl_on_count;
    hi_u32 flowctrl_off_count;
    hi_u32 flowctrl_reset_count;
    hi_u32 flowctrl_hipri_update_count;
    hi_u8  uc_hipriority_cnt;
    hi_u8  uc_lopriority_cnt;
    hi_u8  des_cnt;
    hi_u8  auc_resv[2];                 /* resv 2 ���� */
    oal_spin_lock_stru  st_hipri_lock;  /* ��дuc_hipriority_cntʱҪ���� */
    oal_wait_queue_head_stru   wait_queue;
    flowctrl_cb net_stopall;
    flowctrl_cb net_startall;
#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
    hcc_flowctl_get_mode    get_mode;
    hcc_flowctl_stop_subq   stop_subq;
    hcc_flowctl_start_subq  start_subq;
#endif
    oal_timer_list_stru      flow_timer;
    unsigned long             timeout;
    oal_delayed_work  worker;
    oal_spin_lock_stru lock;
}hcc_tx_flow_ctrl_info_stru;

typedef struct {
    hi_u8                   descr_num;
    oal_netbuf_head_stru        tx_assem_descr_hdr;
} hcc_tx_assem_descr;

typedef enum {
    TIMER_ADD,
    TIMER_RUNING,
    TIMER_STOP,
    TIMER_DEL
}hcc_timer_status;

typedef struct {
    hi_u32  verify_code;
    hi_u32  timeout; /* device�೤ʱ��(��λ:S) û���յ���������λ */
}hcc_heartbeat_stru;

typedef struct {
    hi_u32  is_open;
    hi_u32  reserve;
}hcc_open_gpio_soft_rest;

typedef struct {
    oal_kthread_stru            *hcc_transfer_thread;
    oal_kthread_stru            *hcc_rx_thread;
    oal_wait_queue_head_stru    hcc_transfer_wq;
    oal_wait_queue_head_stru    hcc_rx_wq;
    oal_timer_list_stru hcc_timer;
    hcc_timer_status hcc_timer_status;
#ifdef _PRE_CONFIG_WLAN_THRANS_THREAD_DEBUG
    hcc_thread_stat             thread_stat;
#endif
    hcc_trans_queues_stru       hcc_queues[HCC_DIR_COUNT];
    hcc_tx_assem_info_stru           tx_assem_info;
    hcc_rx_assem_info           rx_assem_info;
    hcc_tx_flow_ctrl_info_stru       tx_flow_ctrl;
    hcc_rx_action_info_stru     rx_action_info;
#if(_PRE_OS_VERSION==_PRE_OS_VERSION_LITEOS)
    hi_u32                    taskid;
#endif
} hcc_transfer_handler_stru;

typedef hi_u8 oal_bool_enum_uint8;
typedef hi_s32 (*hmac_tcp_ack_process_func)(hi_void);
typedef oal_bool_enum_uint8 (*hmac_tcp_ack_need_schedule_func)(hi_void);

typedef struct {
    oal_atomic                  state;  /* hcc's state */
    oal_atomic                  tx_seq;
    oal_channel_stru           *hi_channel;
    unsigned long               hdr_rever_max_len;

    oal_mutex_stru              tx_transfer_lock;
    oal_wakelock_stru           tx_wake_lock;

    hcc_transfer_handler_stru hcc_transer_info;

    /* the tx descr info, first descr */
    hcc_tx_assem_descr   tx_descr_info;
    hmac_tcp_ack_process_func   p_hmac_tcp_ack_process_func;
    hmac_tcp_ack_need_schedule_func p_hmac_tcp_ack_need_schedule_func;
} hcc_handler_stru;

typedef hi_void (*hcc_tx_cb_callback)(hcc_handler_stru* hcc);

#define HCC_TX_WAKELOCK_MAGIC   0xdead5ead
typedef struct {
    hcc_tx_cb_callback destory;
    hi_u32  magic;
} hcc_tx_cb_stru;

/* device��ṹ�� */
#define HI_SYSERR_EXC_TASK_NAME_SIZE 8

typedef struct {
    hi_u8 timer_usage;  /**< Number of used system timers.CNcomment:��ǰʹ��ϵͳ��ʱ������ CNend */
    hi_u8 task_usage;   /**< Number of used tasks.CNcomment:��ǰʹ��������� CNend */
    hi_u8 sem_usage;    /**< Number of used semaphores.CNcomment:��ǰʹ���ź������� CNend */
    hi_u8 queue_usage;  /**< Number of used message queues.CNcomment:��ǰʹ����Ϣ���и��� CNend */
    hi_u8 mux_usage;    /**< Number of used mutexes.CNcomment:��ǰʹ�û��������� CNend */
    hi_u8 event_usage;  /**< Number of used events.CNcomment:��ǰʹ���¼����� CNend */
    hi_u16 err_info;    /**< Error statistic HI_OS_STAT_XXX, used to log occurred errors.
                           CNcomment:����ͳ����HI_OS_STAT_XXX�����ڼ�¼�������ֹ��Ĵ��� CNend */
}hi_os_resource_use_stat;

typedef struct {
    hi_char name[HI_SYSERR_EXC_TASK_NAME_SIZE];
    hi_u32 id;  /**< task id.CNcomment:����ID.CNend */
    hi_u32 status;  /**< task status.CNcomment:��������״̬.CNend */
    hi_u16 stack_peak;      /**< stack peak.CNcomment:ջʹ�÷�ֵ.CNend */
    hi_u16 stack_size;      /**< stack size.CNcomment:����ջ��С.CNend */
    hi_u32 sp;              /**< stack point.CNcomment:ջָ��.CNend */
    hi_u32 stack[2];        /**< stack[2] is stack top and end address.CNcomment:ջ����ջ�׵�ַ.CNend */
    hi_u32 real_sp;         /**< real stack point.CNcomment:��ʵջָ��.CNend */
    hi_u32 overflow_flag;                   /**< stack overflow flag.CNcomment:ջ�����ʶ.CNend */
} syserr_task_info;

typedef struct {
    hi_u32 pool_addr;       /* �ڴ�ص�ַ */
    hi_u32 pool_size;       /* �ڴ�ش�С */
    hi_u32 fail_count;      /* �ڴ�����ʧ�ܼ��� */
    hi_u32 peek_size;       /* �ڴ��ʹ�÷�ֵ */
    hi_u32 cur_use_size;    /* �ڴ���Ѿ�ʹ�ô�С����λ��byte�� */
} hi_mem_pool_crash_info;


typedef struct {
    hi_os_resource_use_stat usage; /**< os resource used count.CNcomment:ϵͳ��Դʹ�ø���.CNend */
    syserr_task_info task;         /**< task information.CNcomment:������Ϣ.CNend */
    hi_mem_pool_crash_info mem;    /**< memory pool information.CNcomment:��̬�ڴ����Ϣ.CNend */
} syserr_os_info;

typedef struct {
    hi_u32 mepc;
    hi_u32 ra;
    hi_u32 sp;
    hi_u32 gp;
    hi_u32 tp;
    hi_u32 t0;
    hi_u32 t1;
    hi_u32 t2;
    hi_u32 s0;
    hi_u32 s1;
    hi_u32 a0;
    hi_u32 a1;
    hi_u32 a2;
    hi_u32 a3;
    hi_u32 a4;
    hi_u32 a5;
} syserr_reg_info;

typedef struct {
    hi_u32 mstatus;     /**< CPU mstatus register value.CNcomment:CPU mstatus�Ĵ���ֵ.CNend */
    hi_u32 mtval;       /**< CPU mtval register value.CNcomment:CPU mtval�Ĵ���ֵ.CNend */
    hi_u32 mcause;      /**< CPU mcause register value.CNcomment:CPU mcause�Ĵ���ֵ.CNend */
    hi_u32 ccause;      /**< CPU ccause register value.CNcomment:CPU ccause�Ĵ���ֵ.CNend */
    hi_u16 cur_task_id; /**< current task id.CNcomment:��ǰ����ID.CNend */
} syserr_core_info;

typedef struct {
    syserr_os_info os_info;       /**< OS data of crash information.CNcomment:����OS��Ϣ.CNend */
    syserr_reg_info reg_info;     /**< CPU registers of crash information.CNcomment:����CPU�Ĵ�����Ϣ.CNend */
    syserr_core_info core_info;   /**< CPU CSR registers of crash information.CNcomment:����CPU״̬�Ĵ�����Ϣ.CNend */
} hi_syserr_info;

/*****************************************************************************
 ȫ�ֱ�������
*****************************************************************************/
extern oal_netbuf_head_stru g_hcc_hmac_rx_netbuf;
extern hcc_handler_stru *g_hcc_host_handler;
extern hi_u8  g_hcc_sched_stat[FRW_EVENT_TYPE_BUTT];
extern hi_u8  g_hcc_flowctrl_stat[FRW_EVENT_TYPE_BUTT];

/*****************************************************************************
 inline ��������
*****************************************************************************/
static inline void hcc_tx_transfer_lock(hcc_handler_stru *hcc)
{
    oal_mutex_lock(&hcc->tx_transfer_lock);
}

static inline void hcc_tx_transfer_unlock(hcc_handler_stru *hcc)
{
    if (OAL_WARN_ON(hcc == HI_NULL)) {
        oal_io_print1("%s,hcc is null\n", __FUNCTION__);
        return;
    }

    oal_mutex_unlock(&hcc->tx_transfer_lock);
}

static inline void hcc_rx_transfer_lock(const hcc_handler_stru *hcc)
{
    if (OAL_WARN_ON(hcc == HI_NULL)) {
        oal_io_print1("%s,hcc is null\n", __FUNCTION__);
        return;
    }
    oal_channel_rx_transfer_lock(hcc->hi_channel);
}

static inline void hcc_rx_transfer_unlock(const hcc_handler_stru *hcc)
{
    if (OAL_WARN_ON(hcc == HI_NULL)) {
        oal_io_print1("%s,hcc is null\n", __FUNCTION__);
        return;
    }
    oal_channel_rx_transfer_unlock(hcc->hi_channel);
}

static inline void hcc_transfer_lock(hcc_handler_stru *hcc)
{
    if (OAL_WARN_ON(hcc == HI_NULL)) {
        oal_io_print1("%s,hcc is null\n", __FUNCTION__);
        return;
    }

    hcc_rx_transfer_lock(hcc);

    hcc_tx_transfer_lock(hcc);
}

static inline void hcc_transfer_unlock(hcc_handler_stru *hcc)
{
    if (OAL_WARN_ON(hcc == HI_NULL)) {
        oal_io_print1("%s,hcc is null\n", __FUNCTION__);
        return;
    }
    hcc_tx_transfer_unlock(hcc);
    hcc_rx_transfer_unlock(hcc);
}

/*****************************************************************************
 ��������
*****************************************************************************/
hi_s32 hcc_hmac_adapt_init(hi_void);
hi_u32 hcc_host_init(hi_void);
hi_void hcc_host_exit(hcc_handler_stru *hcc);
hcc_handler_stru *hcc_host_get_handler(hi_void);
hi_void hcc_host_rx_queue_sched(hi_void);
hi_void hcc_host_tx_queue_sched(hi_void);
hi_s32 queues_flow_ctrl_check(hcc_handler_stru *hcc_handler, hcc_chan_type dir);
hi_s32 queues_len_check(hcc_handler_stru *hcc_handler, hcc_chan_type dir);
hi_void hcc_sched_transfer(hcc_handler_stru *hcc_handler);
hi_void hcc_print_device_mem_info(hi_void);
hi_void hi_wifi_device_deinit(const hcc_handler_stru *hcc_handler);
hi_void hcc_exit_task_thread(hcc_handler_stru* hcc);
hi_u8 hcc_get_thread_exit_flag(hi_void);
hi_s32 hcc_host_proc_tx_queue(hcc_handler_stru *hcc_handler, hcc_queue_type_enum type);
hi_s32 hcc_host_proc_rx_queue(hcc_handler_stru *hcc_handler, hcc_queue_type_enum  type);
hi_void hcc_clear_all_queues(hcc_handler_stru *hcc_handler, hi_s32 is_need_lock);
hi_u8 hcc_list_overflow(hi_void);
hi_u32 hcc_host_tx(hcc_handler_stru *hcc_handler, oal_netbuf_stru *netbuf, const hcc_transfer_param *param);
hi_u32 hcc_send_control_msg(hcc_handler_stru *hcc_handler, hi_u8 sub_type, hi_u8* buf, int len);
hi_s32 hi_wifi_enable_heart_beat(hi_bool enable);
hi_bool hi_wifi_get_heart_beat_enable(hi_void);
hi_u8 hcc_discard_key_frame(hi_void);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
