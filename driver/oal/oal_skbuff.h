/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_skbuff.h
 * Author: Hisilicon
 * Create: 2018-08-04
 */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#ifndef _LITEOS_SKBUFF_H
#define _LITEOS_SKBUFF_H

/*****************************************************************************
    1 其他头文件包含
*****************************************************************************/
#include <linux/spinlock.h>
#include "los_memory.h"
#include <linux/kernel.h>
#include <asm/page.h>
#include "oal_err_wifi.h"
#include "oal_util.h"
#include "oal_spinlock.h"
#include "hi_atomic.h"
#include "hi_stdlib.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
    2 宏定义
*****************************************************************************/
/* Don't change this without changing skb_csum_unnecessary! */
#define CHECKSUM_NONE           0
#define CHECKSUM_UNNECESSARY    1
#define CHECKSUM_COMPLETE       2
#define CHECKSUM_PARTIAL        3

#define L1_CACHE_BYTES          (1 << 5)
#define SMP_CACHE_BYTES         L1_CACHE_BYTES


#define skb_data_align(x)       (((x) + (SMP_CACHE_BYTES - 1)) & ~(SMP_CACHE_BYTES - 1))
#define skb_max_order(x, order) SKB_WITH_OVERHEAD((PAGE_SIZE << (order)) - (x))
#define skb_max_head(x)         (skb_max_order((x), 0))
#define SKB_MAX_ALLOC           (skb_max_order(0, 2))

/* return minimum truesize of one skb containing X bytes of data */
#define skb_truesize(x)         ((x) + skb_data_align(sizeof(struct sk_buff)))


#define SKB_DATA_ALIGN(x)       skb_data_align(x)

#ifndef NET_SKB_PAD
#define NET_SKB_PAD     64
#endif

#define NUMA_NO_NODE    (-1)

#if defined(HISI_WIFI_PLATFORM_HI3559) || defined(HISI_WIFI_PLATFORM_HI3556)
#define USB_CACHE_ALIGN_SIZE 64
#else
#define USB_CACHE_ALIGN_SIZE 32
#endif

#define SKB_ALLOC_FCLONE    0x01
#define SKB_ALLOC_RX        0x02
#define skb_queue_walk(queue, skb)                                    \
    for ((skb) = (queue)->next;                                       \
         (skb) != (struct sk_buff *)(queue);                          \
         (skb) = (skb)->next)

#define skb_queue_walk_safe(queue, skb, tmp)                          \
    for ((skb) = (queue)->next, (tmp) = (skb)->next;                  \
         (skb) != (struct sk_buff *)(queue);                          \
         (skb) = (tmp), (tmp) = (skb)->next)

typedef hi_u32 gfp_t;
typedef hi_u32 sk_buff_data_t;

/*****************************************************************************
    3 结构体定义
*****************************************************************************/
struct sk_buff_head {
    /* These two members must be first. */
    struct sk_buff  *next;
    struct sk_buff  *prev;

    hi_u32        qlen;
    oal_spin_lock_stru    lock;
};

struct sk_buff {
    /* These two members must be first. */
    struct sk_buff *next;
    struct sk_buff *prev;

    hi_void        *dev;               /* for hwal_netif_rx */
    hi_u32          len;
    hi_u32          data_len;
    hi_u16          queue_mapping;

    /* These elements must be at the end, see alloc_skb() for details. */
    sk_buff_data_t  tail;
    sk_buff_data_t  end;

    hi_s8           cb[48];  /* 48: SIZE(0..48) */
    hi_u8          *head;
    hi_u8          *data;

    hi_u32          truesize;
    hi_u32          priority;
    hi_atomic       users;

    /* use for lwip_pbuf zero_copy:actual start addr of memory space */
    hi_u8           *mem_head;
    hi_u32          protocol;

    hi_u16          mac_header;
    hi_u8           resv[2];   /* 2: bytes保留字段 */
};

/*****************************************************************************
    4 函数声明
*****************************************************************************/
hi_void skb_trim(struct sk_buff *skb, hi_u32 len);
struct sk_buff *skb_unshare(struct sk_buff *skb);
hi_s32 pskb_expand_head(struct sk_buff *skb, hi_u32 nhead, hi_u32 ntail, gfp_t gfp_mask);
struct sk_buff *alloc_skb(hi_u32 size);
struct sk_buff *skb_dequeue(struct sk_buff_head *list);
struct sk_buff *skb_dequeue_tail(struct sk_buff_head *list);
hi_void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk);
hi_void dev_kfree_skb(struct sk_buff *skb);
struct sk_buff *dev_alloc_skb(hi_u32 length);
hi_u8 *skb_put(struct sk_buff *skb, hi_u32 len);
void skb_queue_purge(struct sk_buff_head *list);
void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk);

#define dev_kfree_skb_any(a) dev_kfree_skb(a)

/*****************************************************************************
    5 内联函数
*****************************************************************************/
static inline bool skb_pfmemalloc(const struct sk_buff *skb)
{
    if (skb == HI_NULL) {
        return true;
    }

    return false;
}

static inline hi_void _skb_queue_head_init(struct sk_buff_head *list)
{
    list->prev = list->next = (struct sk_buff *)list;
    list->qlen = 0;
}

static inline hi_void skb_queue_head_init(struct sk_buff_head *list)
{
    oal_spin_lock_init(&list->lock);
    _skb_queue_head_init(list);
}

static inline hi_void skb_reset_tail_pointer(struct sk_buff *skb)
{
    skb->tail = (sk_buff_data_t)(skb->data - skb->head);
}

static inline hi_u8 *skb_tail_pointer(const struct sk_buff *skb)
{
    hi_u8 *phead = skb->head;
    return (phead + skb->tail);
}

static inline hi_s32 skb_queue_empty(const struct sk_buff_head *list)
{
    return list->next == (struct sk_buff *)list;
}

static inline hi_void skb_reserve(struct sk_buff *skb, hi_u32 len)
{
    skb->data += len;
    skb->tail += len;
}

static inline hi_u8 *skb_mac_header(const struct sk_buff  *skb)
{
    return skb->data;
}

static inline struct sk_buff *_dev_alloc_skb(hi_u32 length)
{
    struct sk_buff *skb = alloc_skb(length + NET_SKB_PAD);
    if (skb != NULL) {
        skb_reserve(skb, NET_SKB_PAD);
    }
    return skb;
}

static inline hi_void _skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
    struct sk_buff *next = NULL;
    struct sk_buff *prev = NULL;

    list->qlen--;
    next       = skb->next;
    prev       = skb->prev;
    skb->next  = skb->prev = NULL;
    next->prev = prev;
    prev->next = next;
}

static inline struct sk_buff *skb_get(struct sk_buff *skb)
{
    hi_atomic_inc(&skb->users);
    return skb;
}

static inline struct sk_buff *skb_peek(const struct sk_buff_head *list_)
{
    struct sk_buff *list = ((const struct sk_buff *)list_)->next;
    if (list == (struct sk_buff *)list_) {
        list = NULL;
    }
    return list;
}

static inline struct sk_buff *skb_peek_next(const struct sk_buff *skb, const struct sk_buff_head *list_)
{
    struct sk_buff *next = skb->next;

    if (next == (struct sk_buff *)list_) {
        next = NULL;
    }
    return next;
}

static inline struct sk_buff *skb_peek_tail(const struct sk_buff_head *list_)
{
    struct sk_buff *skb = list_->prev;

    if (skb == (struct sk_buff *)list_) {
        skb = NULL;
    }
    return skb;
}

static inline struct sk_buff *_skb_dequeue(struct sk_buff_head *list)
{
    struct sk_buff *skb = skb_peek(list);
    if (skb) {
        _skb_unlink(skb, list);
    }
    return skb;
}

static inline struct sk_buff *_skb_dequeue_tail(struct sk_buff_head *list)
{
    struct sk_buff *skb = skb_peek_tail(list);
    if (skb) {
        _skb_unlink(skb, list);
    }
    return skb;
}

static inline hi_s32 skb_headlen(const struct sk_buff *skb)
{
    return (hi_s32)(skb->len - skb->data_len);
}

static inline hi_void _skb_insert(struct sk_buff *newsk,
                                  struct sk_buff *prev, struct sk_buff *next,
                                  struct sk_buff_head *list)
{
    newsk->next = next;
    newsk->prev = prev;
    next->prev  = prev->next = newsk;
    list->qlen++;
}

static inline hi_void _skb_queue_before(struct sk_buff_head *list, struct sk_buff *next, struct sk_buff *newsk)
{
    _skb_insert(newsk, next->prev, next, list);
}

static inline hi_void _skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
    _skb_queue_before(list, (struct sk_buff *)list, newsk);
}

static inline hi_void _skb_queue_splice(const struct sk_buff_head *list, struct sk_buff *prev, struct sk_buff *next)
{
    struct sk_buff *first = list->next;
    struct sk_buff *last = list->prev;

    first->prev = prev;
    prev->next = first;

    last->next = next;
    next->prev = last;
}

static inline hi_void skb_queue_splice(const struct sk_buff_head *list, struct sk_buff_head *head)
{
    if (!skb_queue_empty(list)) {
        _skb_queue_splice(list, (struct sk_buff *) head, head->next);
        head->qlen += list->qlen;
    }
}

static inline hi_void skb_queue_splice_tail_init(struct sk_buff_head *list, struct sk_buff_head *head)
{
    if (!skb_queue_empty(list)) {
        _skb_queue_splice(list, head->prev, (struct sk_buff *) head);
        head->qlen += list->qlen;
        _skb_queue_head_init(list);
    }
}

static inline hi_void skb_queue_splice_init(struct sk_buff_head *list, struct sk_buff_head *head)
{
    if (!skb_queue_empty(list)) {
        _skb_queue_splice(list, (struct sk_buff *) head, head->next);
        head->qlen += list->qlen;
        _skb_queue_head_init(list);
    }
}

static inline hi_u8 *_skb_pull(struct sk_buff *skb, hi_u32 len)
{
    skb->len -= len;
    return skb->data += len;
}

static inline hi_s32 skb_headroom(const struct sk_buff *skb)
{
    return (hi_s32)(skb->data - skb->head);
}

static inline bool skb_is_nonlinear(const struct sk_buff *skb)
{
    return skb->data_len;
}

static inline hi_void skb_copy_from_linear_data_offset(const struct sk_buff *skb,
                                                       const hi_s32 offset, const hi_u32 len, hi_void *to,
                                                       const hi_u32 copy)
{
    if (memcpy_s(to, len, skb->data + offset, copy) != EOK) {
        return;
    }
}

static inline hi_void skb_set_tail_pointer(struct sk_buff *skb, const hi_u32 offset)
{
    skb_reset_tail_pointer(skb);
    skb->tail += offset;
}

static inline hi_void _skb_trim(struct sk_buff *skb, hi_u32 len)
{
    if (oal_unlikely(skb_is_nonlinear(skb))) {
        return;
    }
    skb->len = len;
    skb_set_tail_pointer(skb, len);
}

static inline hi_u8 *skb_push(struct sk_buff *skb, hi_u32 len)
{
    if (skb->data - len < skb->head) {
        return NULL;
    }

    skb->data -= len;
    skb->len  += len;
    return skb->data;
}

static inline hi_u32 skb_tailroom(const struct sk_buff *skb)
{
    return skb_is_nonlinear(skb) ? 0 : skb->end - skb->tail;
}

static inline bool skb_queue_is_last(const struct sk_buff_head *list, const struct sk_buff *skb)
{
    return skb->next == (struct sk_buff *)list;
}

static inline hi_u8 *skb_end_pointer(const struct sk_buff *skb)
{
    return skb->head + skb->end;
}

static inline hi_u32 skb_end_offset(const struct sk_buff *skb)
{
    return skb->end;
}

static inline hi_void _skb_queue_after(struct sk_buff_head *list, struct sk_buff *prev, struct sk_buff *newsk)
{
    _skb_insert(newsk, prev, prev->next, list);
}

static inline hi_void _skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
    _skb_queue_after(list, (struct sk_buff *)list, newsk);
}

static inline hi_void skb_set_queue_mapping(struct sk_buff *skb, hi_u16 queue_mapping)
{
    skb->queue_mapping = queue_mapping;
}

static inline hi_u16 skb_get_queue_mapping(const struct sk_buff *skb)
{
    return skb->queue_mapping;
}

static inline hi_void skb_copy_queue_mapping(struct sk_buff *to, const struct sk_buff *from)
{
    to->queue_mapping = from->queue_mapping;
}
static inline hi_u32 skb_queue_len(const struct sk_buff_head *list_)
{
    return list_->qlen;
}
#endif  /* _LITEOS_SKBUFF_H */
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */
