/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sdio驱动 的头文件
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_SDIO_HOST_IF_H__
#define __OAL_SDIO_HOST_IF_H__

/*****************************************************************************
  1 外部头文件
*****************************************************************************/
#include "oal_util.h"
#include "oal_net.h"
#include "oal_sdio_comm.h"
#include "oal_wakelock.h"
#include "oal_workqueue.h"
#include "oal_semaphore.h"
#include "oal_schedule.h"
#include "oal_thread.h"
#include "oal_sdio_if.h"
#include "oal_spinlock.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define MODULE_DEVICE_TABLE(a, b)
#endif

/* 0x30~0x38, 0x3c~7B */
#define HISDIO_EXTEND_BASE_ADDR     0x30
#define HISDIO_EXTEND_CREDIT_ADDR   0x3c
#define HISDIO_EXTEND_REG_COUNT     64

#define HISDIO_ALIGN_4_OR_BLK(len)  ((len) < HISDIO_BLOCK_SIZE ? ALIGN((len), 4) : ALIGN((len), HISDIO_BLOCK_SIZE))

#define HISDIO_WAKEUP_DEV_REG       0xf0
#define ALLOW_TO_SLEEP_VALUE        1
#define DISALLOW_TO_SLEEP_VALUE     0

#define OAL_SDIO_TX                 (1<<0)
#define OAL_SDIO_RX                 (1<<1)
#define OAL_SDIO_ALL                (OAL_SDIO_TX | OAL_SDIO_RX)

/*****************************************************************************
  3 枚举 结构体定义
*****************************************************************************/
enum {
    SDIO_READ = 0,
    SDIO_WRITE,
    SDIO_OPT_BUTT
};

typedef hi_s32(*sdio_msg_rx)(hi_void *data);
typedef hi_s32(*hisdio_rx)(hi_void *data);
typedef struct _sdio_bus_ops_ {
    hisdio_rx rx;
} sdio_bus_ops;

typedef struct {
    hi_u32 max_scatt_num;
    struct scatterlist  *sglist;
} sdio_scatt_stru;

typedef struct {
    sdio_msg_rx msg_rx;
    void *data;
    hi_u32 count;
    hi_u64 cpu_time; /* the time of the last come! */
} sdio_msg_stru;

typedef struct {
    hi_u32 int_stat;
    hi_u32 msg_stat;
    hi_u32 xfer_count;
    hi_u32 credit_info;
    hi_u8  comm_reg[HISDIO_EXTEND_REG_COUNT];
} hisdio_extend_func;

typedef struct {
    hi_u8   short_free_cnt;
    hi_u8   large_free_cnt;
    oal_spin_lock_stru credit_lock;
} hsdio_credit_info;

typedef struct {
    hi_u32 func1_err_reg_info;
    hi_u32 func1_err_int_count;
    hi_u32 func1_ack_int_acount;
    hi_u32 func1_msg_int_count;
    hi_u32 func1_data_int_count;
    hi_u32 func1_unknow_int_count;
    hi_u32 func1_no_int_count;
} hsdio_func1_info;

typedef struct {
    hi_u32 rx_scatt_info_not_match;
} hsdio_error_info;

typedef struct _wlan_pm_callback {
    unsigned long (*wlan_pm_wakeup_dev)(hi_void);    /* SDIO发包过程中中PM状态检查，如果是睡眠状态，同时唤醒 */
    unsigned long (*wlan_pm_state_get)(hi_void);     /* 获取当前PM状态 */
    unsigned long (*wlan_pm_wakeup_host)(hi_void);   /* device唤醒host中断处理 */
    hi_void (*wlan_pm_feed_wdg)(hi_void);            /* PM Sleep watch dog喂狗接口 */
    hi_void (*wlan_pm_wakeup_dev_ack)(hi_void);      /* 唤醒device的ACK 中断处理 */
} wlan_pm_callback_stru;

typedef struct {
    /* record the tx scatt list assembled buffer */
    hi_void *buff;
    hi_u32   len;
} hsdio_tx_scatt_buff;

typedef struct {
    /* sdio work state, sleep , work or shutdown */
    hi_u32                  state;

    oal_spin_lock_stru      st_pm_state_lock;       /* pm state互斥锁，pm和gpio中断都用到 */
    wlan_pm_callback_stru  *pst_pm_callback;

    oal_spin_lock_stru      st_irq_lock;            /* wlan gpio中断操作锁 */
    unsigned long           ul_wlan_irq ;           /* wlan gpio中断 */
    oal_wakelock_stru       st_sdio_wakelock;

#ifdef CONFIG_MMC
    struct sdio_func       *func;
#endif
    oal_mutex_stru          rx_transfer_lock;
    /* used to sg list sdio block align */
    hi_u8                  *sdio_align_buff;

    hi_u64                  sdio_int_count;
    hi_u64                  gpio_int_count;
    hi_u64                  data_int_count;
    hi_u64                  data_int_finish_count;
    hi_u64                  wakeup_int_count;
    hi_u32                  ul_sdio_suspend;
    hi_u32                  ul_sdio_resume;
    oal_kthread_stru       *gpio_rx_tsk;

    /* used to process the sdio int */
    oal_semaphore_stru      gpio_rx_sema;

    hi_void                *bus_data;
    sdio_bus_ops            bus_ops;
    hisdio_rx               credit_update_cb;

    sdio_scatt_stru         scatt_info[SDIO_OPT_BUTT];

    sdio_msg_stru           msg[D2H_MSG_COUNT];
    hi_u32                  last_msg;

    /* This is get from sdio , must alloc for dma,
       the extend area only can access by CMD53 */
    hisdio_extend_func     *sdio_extend;
    hsdio_credit_info       sdio_credit_info;
    hi_u32                  func1_int_mask;
    hsdio_func1_info        func1_stat;
    hsdio_error_info        error_stat;

    hsdio_tx_scatt_buff     scatt_buff;
    hi_void                *rx_reserved_buff;   /* use the mem when rx alloc mem failed! */
    hi_u32                  rx_reserved_buff_len;

    hi_u32                  ul_last_step_time[10];  /* array len 10 */
} oal_channel_stru;

struct sdio_scatt {
    hi_u32 max_scatt_num;
    struct scatterlist  *sglist;
};

extern oal_semaphore_stru g_chan_wake_sema;

/*****************************************************************************
  4 外部函数声明
*****************************************************************************/
hi_s32 oal_sdio_get_credit(const oal_channel_stru *hi_sdio, hi_u32 *uc_priority_cnt);
hi_u32 oal_sdio_get_large_pkt_free_cnt(oal_channel_stru *hi_sdio);
hi_void oal_netbuf_list_hex_dump(const oal_netbuf_head_stru *head);
hi_void oal_netbuf_hex_dump(const oal_netbuf_stru *netbuf);
#ifdef CONFIG_MMC
hi_s32 oal_sdio_get_state(const oal_channel_stru *hi_sdio, hi_u32 mask);
hi_void oal_enable_sdio_state(oal_channel_stru *hi_sdio, hi_u32 mask);
hi_void oal_disable_sdio_state(oal_channel_stru *hi_sdio, hi_u32 mask);
hi_void oal_sdio_info_show(oal_channel_stru *hi_sdio);
hi_void oal_netbuf_list_hex_dump(const oal_netbuf_head_stru *head);
hi_void oal_netbuf_hex_dump(const oal_netbuf_stru *netbuf);
hi_s32 oal_sdio_build_rx_netbuf_list(oal_channel_stru *hi_sdio, oal_netbuf_head_stru    *head);
hi_void oal_gpio_intr_enable(oal_channel_stru *hi_sdio, hi_char enable);
hi_s32 oal_sdio_func_probe(oal_channel_stru *hi_sdio);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_s32 oal_sdio_func_probe_resume(void);
#endif
hi_s32 oal_sdio_reinit(void);
hi_s32 oal_sdio_func_reset(void);
hi_void oal_sdio_func_remove(oal_channel_stru *hi_sdio);
hi_s32 oal_sdio_message_register(oal_channel_stru *hi_sdio, hi_u8 msg, sdio_msg_rx cb, hi_void *data);
hi_void oal_sdio_message_unregister(oal_channel_stru *hi_sdio, hi_u8 msg);
hi_s32 oal_sdio_transfer_rx_register(oal_channel_stru *hi_sdio, hisdio_rx rx);
hi_void  oal_sdio_credit_update_cb_register(oal_channel_stru *hi_sdio, hisdio_rx cb);
hi_void oal_sdio_transfer_rx_unregister(oal_channel_stru *hi_sdio);
extern hi_s32 oal_sdio_transfer_tx(const oal_channel_stru *hi_sdio, oal_netbuf_stru *netbuf);
hi_s32 oal_sdio_transfer_netbuf_list(const oal_channel_stru *hi_sdio, const oal_netbuf_head_stru *head, hi_s32 rw);
extern oal_channel_stru  *oal_sdio_init_module(hi_void *data);
extern hi_void  oal_sdio_exit_module(oal_channel_stru *hi_sdio);
hi_s32 oal_sdio_send_msg(oal_channel_stru *hi_sdio, unsigned long val);
extern oal_channel_stru *oal_get_sdio_default_handler(hi_void);
extern unsigned long oal_sdio_get_sleep_state(oal_channel_stru *hi_sdio);
extern hi_void oal_sdio_get_dev_pm_state(oal_channel_stru *hi_sdio, unsigned long *pst_ul_f1,
    unsigned long *pst_ul_f2, unsigned long *pst_ul_f3, unsigned long *pst_ul_f4);
extern hi_s32 oal_sdio_wakeup_dev(oal_channel_stru *hi_sdio);
extern hi_s32 oal_sdio_sleep_dev(oal_channel_stru *hi_sdio);
extern void oal_sdio_wake_lock(oal_channel_stru *pst_hi_sdio);
extern void oal_sdio_wake_unlock(oal_channel_stru *pst_hi_sdio);
extern unsigned long oal_sdio_wakelock_active(oal_channel_stru *pst_hi_sdio);
extern hi_void oal_sdio_wakelocks_release_detect(oal_channel_stru *pst_hi_sdio);
extern hi_u32 oal_sdio_func_max_req_size(const oal_channel_stru *pst_hi_sdio);
extern hi_void oal_wlan_gpio_intr_enable(oal_channel_stru *hi_sdio, hi_u32  ul_en);
extern hi_s32 oal_sdio_transfer_prepare(oal_channel_stru *hi_sdio);
hi_void oal_unregister_sdio_intr(const oal_channel_stru *hi_sdio);
hi_void oal_sdio_isr(struct sdio_func *func);
#endif /* #ifdef CONFIG_MMC */

static inline hi_void oal_sdio_claim_host(const oal_channel_stru *hi_sdio)
{
#ifdef CONFIG_MMC
    if (OAL_WARN_ON(hi_sdio == NULL)) {
        return;
    }

    if (OAL_WARN_ON(hi_sdio->func == NULL)) {
        return;
    }
    sdio_claim_host(hi_sdio->func);
#endif
}

static inline hi_void oal_sdio_release_host(const oal_channel_stru *hi_sdio)
{
#ifdef CONFIG_MMC
    if (OAL_WARN_ON(hi_sdio == NULL)) {
        return;
    }

    if (OAL_WARN_ON(hi_sdio->func == NULL)) {
        return;
    }
    sdio_release_host(hi_sdio->func);
#endif
}

static inline hi_void oal_sdio_rx_transfer_lock(oal_channel_stru *hi_sdio)
{
    /* wakelock modified */
    hi_unref_param(hi_sdio);
}

static inline hi_void oal_sdio_rx_transfer_unlock(oal_channel_stru *hi_sdio)
{
    /* wakelock modified */
    hi_unref_param(hi_sdio);
}

static inline hi_void oal_sdio_func1_int_mask(oal_channel_stru *hi_sdio, hi_u32 func1_int_mask)
{
    if (OAL_WARN_ON(hi_sdio == NULL)) {
        return;
    }
    oal_sdio_claim_host(hi_sdio);
    hi_sdio->func1_int_mask &= ~func1_int_mask;
    oal_sdio_release_host(hi_sdio);
}

static inline hi_void oal_sdio_func1_int_unmask(oal_channel_stru *hi_sdio, hi_u32 func1_int_mask)
{
    if (OAL_WARN_ON(hi_sdio == NULL)) {
        return;
    }
    oal_sdio_claim_host(hi_sdio);
    hi_sdio->func1_int_mask |= func1_int_mask;
    oal_sdio_release_host(hi_sdio);
}

/*****************************************************************************
 功能描述  : 获取wifi wakelock锁
 返 回 值  : 成功或失败原因

 修改历史      :
  1.日    期   : 2015年5月20日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
#define oal_sdio_wake_lock(pst_hi_sdio) oal_wake_lock(&(pst_hi_sdio)->st_sdio_wakelock)

/*****************************************************************************
 功能描述  : 释放wifi wakelock锁
 返 回 值  : 成功或失败原因

 修改历史      :
  1.日    期   : 2015年5月20日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
#define oal_sdio_wake_unlock(pst_hi_sdio) oal_wake_unlock(&(pst_hi_sdio)->st_sdio_wakelock)

/*****************************************************************************
 功能描述  : 判断 wifi wakelock锁是否active
 返 回 值  : 成功或失败原因

 修改历史      :
  1.日    期   : 2015年5月20日
    作    者   : Hisilicon
    修改内容   : 新生成函数

*****************************************************************************/
#define oal_sdio_wakelock_active(pst_hi_sdio)   oal_wakelock_active(&(pst_hi_sdio)->st_sdio_wakelock)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif

