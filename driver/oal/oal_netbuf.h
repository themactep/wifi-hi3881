/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for oal_netbuff.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __OAL_LITEOS_NETBUFF_H__
#define __OAL_LITEOS_NETBUFF_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "oal_skbuff.h"
#include "lwip/netif.h"
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#endif

#include "hi_types_base.h"
#include "hi_stdlib.h"
#include "oal_err_wifi.h"

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define PBUF_ZERO_COPY_RESERVE 36
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define ETH_P_CONTROL                       0x0016      /* Card specific control frames */

#define oal_netbuf_list_num(_pst_head)              ((_pst_head)->qlen)
#define oal_net_dev_priv(_pst_dev)                  ((_pst_dev)->ml_priv)
#define oal_net_dev_wireless_dev(_pst_dev)          ((_pst_dev)->ieee80211_ptr)
#define oal_netbuf_next(_pst_buf)                   ((_pst_buf)->next)
#define oal_netbuf_prev(_pst_buf)                   ((_pst_buf)->prev)
#define oal_netbuf_head_next(_pst_buf_head)         ((_pst_buf_head)->next)
#define oal_netbuf_head_prev(_pst_buf_head)         ((_pst_buf_head)->prev)

#define oal_netbuf_protocol(_pst_buf)               ((_pst_buf)->protocol)
#define oal_netbuf_last_rx(_pst_buf)                ((_pst_buf)->last_rx)
#define oal_netbuf_data(_pst_buf)                   ((_pst_buf)->data)
#define oal_netbuf_header(_pst_buf)                 ((_pst_buf)->data)
#define oal_netbuf_payload(_pst_buf)                 ((_pst_buf)->data)

#define oal_netbuf_cb(_pst_buf)                     ((_pst_buf)->cb)
#define oal_netbuf_cb_size()                        (sizeof(((oal_netbuf_stru*)0)->cb))
#define oal_netbuf_len(_pst_buf)                    ((_pst_buf)->len)
#define oal_netbuf_priority(_pst_buf)               ((_pst_buf)->priority)
#define OAL_NETBUF_TAIL                              skb_tail_pointer
#define OAL_NETBUF_QUEUE_TAIL                        skb_queue_tail
#define OAL_NETBUF_QUEUE_HEAD_INIT                   skb_queue_head_init
#define OAL_NETBUF_DEQUEUE                           skb_dequeue

/* �����������ֽ���ת�� */
#ifdef HAVE_PCLINT_CHECK
#define oal_host2net_short(_x)      _x
#define oal_net2host_short(_x)      _x
#define oal_host2net_long(_x)       _x
#define oal_net2host_long(_x)       _x
#define oal_high_half_byte(a)       a
#define oal_low_half_byte(a)        a
#else
#define oal_host2net_short(_x)      hi_swap_byteorder_16(_x)
#define oal_net2host_short(_x)      hi_swap_byteorder_16(_x)
#define oal_host2net_long(_x)       hi_swap_byteorder_32(_x)
#define oal_net2host_long(_x)       hi_swap_byteorder_32(_x)
#define oal_high_half_byte(a)       (((a) & 0xF0) >> 4)
#define oal_low_half_byte(a)        ((a) & 0x0F)
#endif

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
typedef hi_u8 oal_mem_state_enum_uint8;

/*****************************************************************************
  4 �ṹ�嶨��
*****************************************************************************/
typedef gfp_t                               oal_gfp_enum_uint8;
typedef struct sk_buff                      oal_netbuf_stru;
typedef struct sk_buff_head                 oal_netbuf_head_stru;
typedef struct pbuf                         oal_lwip_buf;

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
typedef struct {
    oal_netbuf_stru netbuf;
    hi_u32 flag;
} netbuf_stru;
#endif

typedef struct oal_netbuf_stru_tag {
    struct oal_netbuf_stru_tag*  next;
    oal_mem_state_enum_uint8    mem_state_flag;             /* �ڴ��״̬ */
    hi_u8                       subpool_id        :  4;     /* ��¼�����ӳ�id */
    hi_u8                       is_high_priority  :  1;
    hi_u8                       bit_resv          :  3;
    hi_u16                  us_index;
} oal_dev_netbuf_stru;

typedef struct {
    oal_dev_netbuf_stru*   next;
    oal_dev_netbuf_stru*   prev;
    hi_u32                 num;
} oal_dev_netbuf_head_stru;

typedef struct oal_ip_header {
#if (_PRE_LITTLE_CPU_ENDIAN == _PRE_CPU_ENDIAN)            /* LITTLE_ENDIAN */
    hi_u8    us_ihl: 4,
             version_ihl: 4;
#else
    hi_u8    version_ihl: 4,
             us_ihl: 4;
#endif
    /* liuming modifed proxyst end */
    hi_u8    tos;
    hi_u16   us_tot_len;
    hi_u16   us_id;
    hi_u16   us_frag_off;
    hi_u8    ttl;
    hi_u8    protocol;
    hi_u16   us_check;
    hi_u32   saddr;
    hi_u32   daddr;
    /* The options start here */
} oal_ip_header_stru;

typedef struct oal_tcp_header {
    hi_u16  us_sport;
    hi_u16  us_dport;
    hi_u32  seqnum;
    hi_u32  acknum;
    hi_u8   offset;
    hi_u8   flags;
    hi_u16  us_window;
    hi_u16  us_check;
    hi_u16  us_urgent;
} oal_tcp_header_stru;

/*****************************************************************************
  3 ��������
*****************************************************************************/
hi_void oal_dev_netbuf_add_to_list(oal_dev_netbuf_stru* dev_netbuf, oal_dev_netbuf_stru* prev,
                                   oal_dev_netbuf_head_stru* next);
hi_void oal_dev_netbuf_add_to_list_tail(oal_dev_netbuf_stru* dev_netbuf, oal_dev_netbuf_head_stru* head);
hi_void oal_dev_netbuf_list_head_init(oal_dev_netbuf_head_stru* list_head);
hi_void oal_dev_netbuf_delete(oal_dev_netbuf_stru* dev_netbuf, oal_dev_netbuf_head_stru* list_head);
oal_dev_netbuf_stru* oal_dev_netbuf_delist(oal_dev_netbuf_head_stru* list_head);
oal_dev_netbuf_stru* oal_dev_netbuf_peek(const oal_dev_netbuf_head_stru* head);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_void oal_init_netbuf_stru(hi_void);
#endif
oal_netbuf_stru* oal_malloc_netbuf_stru(hi_void);
hi_void oal_free_netbuf_stru(oal_netbuf_stru* netbuf);
hi_void oal_free_netbuf_list(oal_netbuf_head_stru* list_head);
#ifdef _PRE_LWIP_ZERO_COPY
oal_netbuf_stru* oal_pbuf_netbuf_alloc(hi_u32 len);
#endif
oal_netbuf_stru* oal_netbuf_alloc(hi_u32 ul_size, hi_u32 l_reserve, hi_u32 l_align);
hi_u32  oal_netbuf_get_appointed_netbuf(const oal_netbuf_stru *netbuf, hi_u8 num, oal_netbuf_stru** expect_netbuf);
hi_u32 oal_netbuf_concat(oal_netbuf_stru* netbuf_head, oal_netbuf_stru* netbuf);
#ifdef _PRE_WLAN_FEATURE_FLOWCTL
hi_void oal_netbuf_get_txtid(oal_netbuf_stru* netbuf, hi_u8* puc_tos);
#endif
hi_u8 oal_netbuf_is_tcp_ack(oal_ip_header_stru  *ip_hdr);
hi_u8 oal_netbuf_is_icmp(const oal_ip_header_stru  *ip_hdr);

/*****************************************************************************
  4 ��������
*****************************************************************************/
static inline hi_void oal_netbuf_copy_queue_mapping(oal_netbuf_stru*  netbuf_to,
    const oal_netbuf_stru* netbuf_from)
{
    skb_copy_queue_mapping(netbuf_to, netbuf_from);
}

/*****************************************************************************
 ��������  : �ڻ�����β����������
 �������  : pst_netbuf: �������ṹ��ָ��
             ul_len: ��Ҫ�������ݵĳ���
*****************************************************************************/
static inline hi_u8* oal_netbuf_put(oal_netbuf_stru* netbuf, hi_u32 len)
{
    return skb_put(netbuf, len);
}

/*****************************************************************************
 ��������  : �ڻ�������ͷ��������
*****************************************************************************/
static inline hi_u8*  oal_netbuf_push(oal_netbuf_stru* netbuf, hi_u32 len)
{
    return skb_push(netbuf, len);
}

/*****************************************************************************
 ��������  : ��skbͷ��ȡ������
 �������  : pst_netbuf: skb�ṹ��ָ��
*****************************************************************************/
static inline hi_u8* oal_netbuf_pull(oal_netbuf_stru* netbuf, hi_u32 len)
{
    if (len > netbuf->len) {
        return HI_NULL;
    }

    netbuf->len -= len;

    return (netbuf->data += len);
}

static inline hi_void oal_set_netbuf_prev(oal_netbuf_stru* netbuf, oal_netbuf_stru* prev)
{
    netbuf->prev = prev;
}

/*****************************************************************************
 ��������  : �ж�skb list�Ƿ�Ϊ��
*****************************************************************************/
static inline hi_s32  oal_netbuf_list_empty(const oal_netbuf_head_stru* list_head)
{
    return skb_queue_empty(list_head);
}

/*****************************************************************************
 �� �� ��  : oal_netbuf_reserve
 ��������  : �����Ľṹ���dataָ���tailָ��ͬʱ����
 �������  : pst_netbuf���Ľṹ��ָ��
             len: Ԥ������
*****************************************************************************/
static inline hi_void  oal_netbuf_reserve(oal_netbuf_stru* netbuf, hi_u32 l_len)
{
    skb_reserve(netbuf, l_len);
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : �ͷű��Ľṹ���ڴ�ռ�, ��Ӳ�жϻ�����ʹ��
 �������  : pst_netbuf: ���Ľṹ��ָ��
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ���HI_ERR_CODE_PTR_NULL
*****************************************************************************/
static inline hi_u32  oal_netbuf_free(oal_netbuf_stru* netbuf)
{
    /* �ͷŵ���alloc_skb�ӿ�������ڴ� */
    if ((netbuf->mem_head == HI_NULL) && (netbuf->head != HI_NULL)) {
        dev_kfree_skb(netbuf);
    } else {
        /* �ͷŵ���pbuf_alloc�ӿ�������ڴ� */
        pbuf_free((struct pbuf*)(netbuf->mem_head));
        oal_free_netbuf_stru(netbuf);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ͷű��Ľṹ���ڴ�ռ䣬�������жϻ���
*****************************************************************************/
static inline hi_void  oal_netbuf_free_any(oal_netbuf_stru* netbuf)
{
    /* �ͷŵ���alloc_skb�ӿ�������ڴ� */
    if ((netbuf->mem_head == HI_NULL) && (netbuf->head != HI_NULL)) {
        dev_kfree_skb_any(netbuf);
    } else {
        /* �ͷŵ���pbuf_alloc�ӿ�������ڴ� */
        pbuf_free((struct pbuf*)(netbuf->mem_head));
        free(netbuf);
    }
}

/*****************************************************************************
 ��������  : �ж�һ��skb�Ƿ�Ϊ��¡�ģ�����copyһ���µ�skb������ֱ�ӷ��ش����skb
 �������  : pst_netbuf: skb�ṹ��ָ��
             en_pri: �ڴ��������ȼ�
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_unshare(oal_netbuf_stru* netbuf)
{
    return skb_unshare(netbuf);
}
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : �ͷű��Ľṹ���ڴ�ռ�, ��Ӳ�жϻ�����ʹ��
 �������  : pst_netbuf: ���Ľṹ��ָ��
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ���HI_ERR_CODE_PTR_NULL
*****************************************************************************/
static inline hi_u32  oal_netbuf_free(oal_netbuf_stru* netbuf)
{
    /* �ͷŵ���alloc_skb�ӿ�������ڴ� */
    dev_kfree_skb(netbuf);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ͷű��Ľṹ���ڴ�ռ䣬�������жϻ���
*****************************************************************************/
static inline hi_void  oal_netbuf_free_any(oal_netbuf_stru* netbuf)
{
    dev_kfree_skb_any(netbuf);
}


/*****************************************************************************
 ��������  : �ж�һ��skb�Ƿ�Ϊ��¡�ģ�����copyһ���µ�skb������ֱ�ӷ��ش����skb
 �������  : pst_netbuf: skb�ṹ��ָ��
             en_pri: �ڴ��������ȼ�
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_unshare(oal_netbuf_stru* netbuf, oal_gfp_enum_uint8 pri)
{
    return skb_unshare(netbuf, pri);
}
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

/*****************************************************************************
 ��������  : ��ȡͷ���ռ��С
*****************************************************************************/
static inline hi_u32  oal_netbuf_headroom(const oal_netbuf_stru* netbuf)
{
    return (hi_u32)skb_headroom(netbuf);
}

/*****************************************************************************
 ��������  : ��ȡβ���ռ��С
*****************************************************************************/
static inline hi_u32  oal_netbuf_tailroom(const oal_netbuf_stru* netbuf)
{
    return (hi_u32)skb_tailroom(netbuf);
}

/*****************************************************************************
 ��������  : skbβ���ռ�����
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_realloc_tailroom(oal_netbuf_stru* netbuf, hi_u32 tailroom)
{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (pskb_expand_head(netbuf, 0, tailroom, GFP_ATOMIC)) {
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (pskb_expand_head(netbuf, 0, tailroom, GFP_ATOMIC)) {
#endif
        netbuf = HI_NULL;
    }

    return netbuf;
}

/*****************************************************************************
 ��������  : ��skb����skb������
 �������  : pst_new: Ҫ�������skbָ��
             pst_prev: β�ڵ�
             pst_head: skb����ͷָ��
*****************************************************************************/
static inline hi_void  oal_netbuf_add_to_list(oal_netbuf_stru* netbuf, oal_netbuf_stru* prev, oal_netbuf_stru* next)
{
    netbuf->next   = next;
    netbuf->prev   = prev;
    next->prev  = netbuf;
    prev->next  = netbuf;
}

/*****************************************************************************
 ��������  : ��skb����skb�����е�β��
 �������  : pst_new: Ҫ�������skbָ��
             pst_head: skb����ͷָ��
*****************************************************************************/
static inline hi_void  oal_netbuf_add_to_list_tail(oal_netbuf_stru* netbuf, oal_netbuf_head_stru* head)
{
    skb_queue_tail(head, netbuf);
}

/*****************************************************************************
 ��������  : skb�������
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_delist(oal_netbuf_head_stru* list_head)
{
    return skb_dequeue(list_head);
}

/*****************************************************************************
 ��������  : skb�����ͷ�����
*****************************************************************************/
static inline hi_void oal_netbuf_addlist(oal_netbuf_head_stru* list_head, oal_netbuf_stru* netbuf)
{
    skb_queue_head(list_head, netbuf);
}

/*****************************************************************************
 ��������  : ��ʼ��skb����ͷ
*****************************************************************************/
static inline hi_void  oal_netbuf_list_head_init(oal_netbuf_head_stru* list_head)
{
    skb_queue_head_init(list_head);
}

/*****************************************************************************
 ��������  : ����������ָ���ڵ����һ���ڵ�
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_list_next(const oal_netbuf_stru* netbuf)
{
    return netbuf->next;
}
/*****************************************************************************
 ��������  : add a netbuf to skb list
*****************************************************************************/
static inline hi_void oal_netbuf_list_tail(oal_netbuf_head_stru* list, oal_netbuf_stru* netbuf)
{
    skb_queue_tail(list, netbuf);
}

/*****************************************************************************
 ��������  : join two skb lists and reinitialise the emptied list
 �������  : @list: the new list to add
             @head: the place to add it in the first list
 �������  : The list at @list is reinitialised
*****************************************************************************/
static inline hi_void oal_netbuf_splice_init(oal_netbuf_head_stru* list, oal_netbuf_head_stru* head)
{
    skb_queue_splice_init(list, head);
}

/*****************************************************************************
 ��������  :  join two skb lists and reinitialise the emptied list
 �������  : @list: the new list to add
             @head: the place to add it in the first list
 �������  : The list at @list is reinitialised
*****************************************************************************/
static inline hi_void oal_netbuf_queue_splice_tail_init(oal_netbuf_head_stru* list, oal_netbuf_head_stru* head)
{
    skb_queue_splice_tail_init(list, head);
}

/*****************************************************************************
 ��������  : remove skb from list tail
 �������  : @head: the place to add it in the first list
 �������  : The list at @list is reinitialised
 �� �� ֵ  : the netbuf removed from the list
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_delist_tail(oal_netbuf_head_stru *head)
{
    return skb_dequeue_tail(head);
}

/*****************************************************************************
 ��������  : move head buffs to list
 �������  : @list: the new list to add
             @head: the place to add it in the first list
 �������  : The list at @list is reinitialised
*****************************************************************************/
static inline hi_void oal_netbuf_splice_sync(oal_netbuf_head_stru* list, oal_netbuf_head_stru* head)
{
    oal_netbuf_stru* netbuf = HI_NULL;
    for (;;) {
        netbuf = oal_netbuf_delist_tail(head);
        if (netbuf == NULL) {
            break;
        }
        oal_netbuf_addlist(list, netbuf);
    }
}

/*****************************************************************************
 ��������  : init netbuf list
*****************************************************************************/
static inline hi_void oal_netbuf_head_init(oal_netbuf_head_stru* list)
{
    skb_queue_head_init(list);
}

/*****************************************************************************
 ��������  : ����skb�����еĵ�һ��Ԫ��
 �������  : pst_head: skb����ͷָ��
 �� �� ֵ  : �����е�һ��Ԫ��
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_peek(const oal_netbuf_head_stru *head)
{
    return skb_peek(head);
}

/*****************************************************************************
 ��������  : ����skb�����е����һ��Ԫ��
 �������  : pst_head: skb����ͷָ��
 �� �� ֵ  : ���������һ��Ԫ��
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_tail(const oal_netbuf_head_stru *head)
{
    return skb_peek_tail(head);
}

/*****************************************************************************
 ��������  : ��ȡnetbuf˫��������buf�ĸ���
*****************************************************************************/
static inline hi_u32  oal_netbuf_get_buf_num(const oal_netbuf_head_stru *netbuf_head)
{
    return netbuf_head->qlen;
}

/*****************************************************************************
 ��������  : ��ȡnetbuf
*****************************************************************************/
static inline oal_netbuf_stru* oal_netbuf_get(oal_netbuf_stru* netbuf)
{
    return skb_get(netbuf);
}

/*****************************************************************************
 ��������  : ��skb�е�������ƫ��ul_offset�� ��ָ�����ȿ�����ָ���ڴ���
*****************************************************************************/
static inline hi_u32 oal_netbuf_copydata(const oal_netbuf_stru *netbuf, hi_u32 offset, hi_void* dst,
                                         hi_u32 dst_len, hi_u32 len)
{
    hi_void* scr = HI_NULL;
    scr = oal_netbuf_data(netbuf) + offset;

    if (memcpy_s(dst, dst_len, scr, len) != EOK) {
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȥskb��β������Ϣ
*****************************************************************************/
static inline hi_void  oal_netbuf_trim(oal_netbuf_stru* netbuf, hi_u32 len)
{
    skb_trim(netbuf, netbuf->len - len);
}

/*****************************************************************************
 ��������  : ��skb���������ݳ�������Ϊָ������
*****************************************************************************/
static inline hi_void  oal_netbuf_set_len(oal_netbuf_stru* netbuf, hi_u32 len)
{
    if (netbuf->len > len) {
        skb_trim(netbuf, len);
    } else {
        skb_put(netbuf, (len - netbuf->len));
    }
}

/*****************************************************************************
 ��������  : ��ʼ��netbuf
*****************************************************************************/
static inline hi_void  oal_netbuf_init(oal_netbuf_stru* netbuf, hi_u32 len)
{
    oal_netbuf_set_len(netbuf, len);
    netbuf->protocol = ETH_P_CONTROL;
}

static inline oal_dev_netbuf_stru* oal_get_dev_netbuf_next(const oal_dev_netbuf_stru *dev_netbuf)
{
    return dev_netbuf->next;
}

#endif
