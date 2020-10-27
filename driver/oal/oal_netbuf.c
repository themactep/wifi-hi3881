/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_netbuff.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */
/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "hi_task.h"
#include "oal_netbuf.h"
#include "mac_frame.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ���
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
static netbuf_stru g_netbuf_list[16]; /* 16: SIZE(0..16) */
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ��ʼ��g_netbuf_list�ṹ
*****************************************************************************/
hi_void oal_init_netbuf_stru(hi_void)
{
    hi_u32 count;
    for (count = 0; count < 16; count++) { /* 16: g_netbuf_list size */
        g_netbuf_list[count].flag = 0;
    }
}

/*****************************************************************************
 ��������  : ����g_netbuf_list�ṹ
*****************************************************************************/
oal_netbuf_stru* oal_malloc_netbuf_stru(hi_void)
{
    hi_u32 count;

    hi_task_lock();
    for (count = 0; count < 16; count++) { /* 16: g_netbuf_list size */
        if (g_netbuf_list[count].flag == 0) {
            g_netbuf_list[count].flag = 1;
            hi_task_unlock();
            return &g_netbuf_list[count].netbuf;
        }
    }
    hi_task_unlock();

    return NULL;
}

/*****************************************************************************
 ��������  : �ͷ�netbuf_list�ṹ
*****************************************************************************/
hi_void oal_free_netbuf_stru(oal_netbuf_stru* netbuf)
{
    hi_task_lock();
    netbuf_stru* netbuf_str = (netbuf_stru*)netbuf;
    netbuf_str->flag = 0;
    hi_task_unlock();
}

/*****************************************************************************
 ��������  : �ͷ�eapol�������нڵ�
*****************************************************************************/
hi_void oal_free_netbuf_list(oal_netbuf_head_stru* list_head)
{
    oal_netbuf_stru *skb_buf = HI_NULL;

    while (oal_netbuf_list_empty(list_head) == HI_FALSE) {
        skb_buf = oal_netbuf_delist(list_head);
        /* ��Ϊ���ҳ��ֿ�ָ�� �����쳣 */
        if (skb_buf == HI_NULL) {
            oam_error_log0(0, 0, "oal_free_netbuff_list:: get netbuf is null.");
            return;
        }
        oal_netbuf_free(skb_buf);
    }
}

#ifdef _PRE_LWIP_ZERO_COPY
/*****************************************************************************
 ��������  : ����lwip pbuf�ṹ��
*****************************************************************************/
oal_netbuf_stru* oal_pbuf_netbuf_alloc(hi_u32 len)
{
    oal_netbuf_stru* netbuf = HI_NULL;
    oal_lwip_buf*    lwip_buf = HI_NULL;

    /*
    |---PBUF_STRU---|-------HEADROOM-------|------ul_len-------|----TAILROOM-----|
    |    16BYTE     |         64BYTE       |      ul_len       |      32BYTE     |
    p_mem_head      head                   data                tail              end
    */
    lwip_buf = pbuf_alloc(PBUF_RAW, (hi_u16)len, PBUF_RAM);
    if (oal_unlikely(lwip_buf == HI_NULL)) {
        return HI_NULL;
    }

    netbuf = oal_malloc_netbuf_stru();
    if (oal_unlikely(netbuf == HI_NULL)) {
        pbuf_free(lwip_buf);
        return HI_NULL;
    }

    /* malloc֮���ʼ�������Բ�ʹ�ð�ȫ���� */
    memset_s(netbuf, sizeof(oal_netbuf_stru), 0, sizeof(oal_netbuf_stru));
    hi_atomic_set(&netbuf->users, 1);

    netbuf->mem_head = (hi_u8*)lwip_buf;
    netbuf->head       = (hi_u8*)lwip_buf->payload - PBUF_ZERO_COPY_RESERVE;
    netbuf->data       = netbuf->head;
    skb_reset_tail_pointer(netbuf);
    netbuf->end        = netbuf->tail + len + PBUF_ZERO_COPY_RESERVE;

    return netbuf;
}
#endif

/*****************************************************************************
 ��������  : Ϊnetbuf�����ڴ�
 �������  : ul_size: �����ڴ�Ĵ�С
             l_reserve: data��ָ��ͷ֮��ҪԤ���ĳ���
             ul_align: ��Ҫ���ֽڶ���
 �� �� ֵ  : �ɹ����ؽṹ��ָ�룻ʧ�ܷ���HI_NULL
*****************************************************************************/
oal_netbuf_stru* oal_netbuf_alloc(hi_u32 size, hi_u32 l_reserve, hi_u32 align)
{
    oal_netbuf_stru *netbuf = HI_NULL;
    hi_u32          offset;

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    align = (hi_u32)CACHE_ALIGNED_SIZE;
#endif

    /* ��֤data���ֵ�size�������ֽڶ����С��Ԥ�������Ĵ�С */
    size += (align - 1);

    netbuf = dev_alloc_skb(size);
    if (oal_unlikely(netbuf == HI_NULL)) {
        return HI_NULL;
    }
    skb_reserve(netbuf, l_reserve);
    netbuf->mem_head = HI_NULL;
    /* ����Ϊ����ʹ�ֽڶ����ƫ���� */
    offset = ((uintptr_t)netbuf->data) % (uintptr_t)align;
    if (offset) {
        skb_reserve(netbuf, align - offset);
    }
    return netbuf;
}

#ifdef _PRE_WLAN_FEATURE_FLOWCTL
/*****************************************************************************
 ��������  : ��lan�������ĵ�ҵ��ʶ��
*****************************************************************************/
hi_void oal_netbuf_get_txtid(oal_netbuf_stru* netbuf, hi_u8* puc_tos)
{
    oal_ether_header_stru  *ether_header = HI_NULL;
    oal_ip_header_stru     *ip = HI_NULL;
    oal_vlan_ethhdr_stru   *vlan_ethhdr = HI_NULL;
    hi_u32                  ipv6_hdr;
    hi_u32                  pri;
    hi_u16                  us_vlan_tci;
    hi_u8                   tid = 0;
    hi_u16                  ether_type;

    /* ��ȡ��̫��ͷ */
    ether_header = (oal_ether_header_stru *)oal_netbuf_data(netbuf);
    ether_type = (hi_u16)oal_net2host_short(ether_header->us_ether_type);

    switch (ether_type) {
        /* ����Info -- Constant expression evaluates to 0 in operation '&' */
        case ETHER_TYPE_IP:
            /* ��IP TOS�ֶ�Ѱ�����ȼ� */
            /* --------------------------------------------------------------------
                tosλ����
             ----------------------------------------------------------------------
            | bit7~bit5 | bit4 |  bit3  |  bit2  |   bit1   | bit0 |
            | �����ȼ�  | ʱ�� | ������ | �ɿ��� | ����ɱ� | ���� |
             ---------------------------------------------------------------------- */
            ip = (oal_ip_header_stru *)(ether_header + 1);      /* ƫ��һ����̫��ͷ��ȡipͷ */
            tid = ip->tos >> WLAN_IP_PRI_SHIFT;
#ifdef _PRE_WLAN_FEATURE_SCHEDULE
            /* ����chariot����Ľ������⴦����ֹ���� */
            if (ip->protocol == MAC_TCP_PROTOCAL) {
                oal_tcp_header_stru *tcp = (oal_tcp_header_stru*)(ip + 1);
                if ((oal_host2net_short(MAC_CHARIOT_NETIF_PORT) == tcp->us_dport)
                    || (oal_host2net_short(MAC_CHARIOT_NETIF_PORT) == tcp->us_sport)) {
                    tid = WLAN_TIDNO_VOICE;
                }
            }
#endif
            break;
        case ETHER_TYPE_IPV6:
            /* ��IPv6 traffic class�ֶλ�ȡ���ȼ� */
            /*----------------------------------------------------------------------
                IPv6��ͷ ǰ32Ϊ����
             -----------------------------------------------------------------------
            | �汾�� | traffic class   | ������ʶ |
            | 4bit   | 8bit(ͬipv4 tos)|  20bit   |
            -----------------------------------------------------------------------*/
            ipv6_hdr = *((hi_u32 *)(ether_header + 1));  /* ƫ��һ����̫��ͷ��ȡipͷ */
            pri = (oal_net2host_long(ipv6_hdr) & WLAN_IPV6_PRIORITY_MASK) >> WLAN_IPV6_PRIORITY_SHIFT;
            tid = (hi_u8)(pri >> WLAN_IP_PRI_SHIFT);
            break;
        case ETHER_TYPE_PAE:
            tid = WLAN_DATA_VIP_TID;
            break;
#ifdef _PRE_WLAN_FEATURE_WAPI
        case ETHER_TYPE_WAI:
            tid = WLAN_DATA_VIP_TID;
            break;
#endif
        case ETHER_TYPE_VLAN:
            /* ��ȡvlan tag�����ȼ� */
            vlan_ethhdr = (oal_vlan_ethhdr_stru *)oal_netbuf_data(netbuf);
            /*------------------------------------------------------------------
                802.1Q(VLAN) TCI(tag control information)λ����
             -------------------------------------------------------------------
            |Priority | DEI  | Vlan Identifier |
            | 3bit    | 1bit |      12bit      |
             ------------------------------------------------------------------*/
            us_vlan_tci = oal_net2host_short(vlan_ethhdr->h_vlan_tci);
            tid = us_vlan_tci >> OAL_VLAN_PRIO_SHIFT;    /* ����13λ����ȡ��3λ���ȼ� */
            break;

        default:
            break;
    }
    /* ���θ�ֵ */
    *puc_tos = tid;

    return;
}
#endif
#endif

/*****************************************************************************
 ��������  : ��netbu_head��β������netbuf
*****************************************************************************/
hi_u32 oal_netbuf_concat(oal_netbuf_stru* netbuf_head, oal_netbuf_stru* netbuf)
{
     /* �жϿռ��Ƿ��㹻 */
    if (((hi_u32)netbuf_head->end - (hi_u32)netbuf_head->tail) < netbuf->len) {
        oal_netbuf_free(netbuf);
        oam_error_log3(0, 0, "oal_netbuf_concat::no enough space: end:%d, tail:%d, len:%d.",
            netbuf_head->end, netbuf_head->tail, netbuf->len);
        return HI_FAIL;
    }
    if (memcpy_s(skb_tail_pointer(netbuf_head), netbuf->len, netbuf->data, netbuf->len) != EOK) {
        oam_error_log0(0, 0, "oal_netbuf_concat:: memcpy_s failed");
        oal_netbuf_free(netbuf);
        return HI_FAIL;
    }

    skb_put(netbuf_head, netbuf->len);
    oal_netbuf_free(netbuf);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ��ǰnetbufԪ�غ�ĵ�n��Ԫ��
 �������  : (1)��ʼ���ҽڵ�
             (2)�����ҵĸ���
 �������  : ָ��������netbuf��ָ��
 �� �� ֵ  : ������betbufԪ�ص�ָ����ָ��
*****************************************************************************/
hi_u32  oal_netbuf_get_appointed_netbuf(const oal_netbuf_stru *netbuf, hi_u8 num, oal_netbuf_stru** expect_netbuf)
{
    hi_u8   buf_num;

    if (oal_unlikely((netbuf == HI_NULL) || (expect_netbuf == HI_NULL))) {
        return HI_ERR_CODE_PTR_NULL;
    }

    *expect_netbuf = HI_NULL;

    for (buf_num = 0; buf_num < num; buf_num++) {
        *expect_netbuf = oal_netbuf_next(netbuf);

        if (*expect_netbuf == HI_NULL) {
            break;
        }

        netbuf = *expect_netbuf;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ж�ipv4 �Ƿ�Ϊicmp����
 �������  : pst_ip_hdr: IP����ͷ��
*****************************************************************************/
hi_u8 oal_netbuf_is_icmp(const oal_ip_header_stru *ip_hdr)
{
    hi_u8  protocol;
    protocol = ip_hdr->protocol;

    /* ICMP���ļ�� */
    if (protocol == MAC_ICMP_PROTOCAL) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

/*****************************************************************************
 ��������  : �ж�ipv4 tcp�����Ƿ�Ϊtcp ack
*****************************************************************************/
hi_u8 oal_netbuf_is_tcp_ack(oal_ip_header_stru  *ip_hdr)
{
    oal_tcp_header_stru    *tcp_hdr = HI_NULL;
    hi_u32                 ip_pkt_len;
    hi_u32                 ip_hdr_len;
    hi_u32                 tcp_hdr_len;

    tcp_hdr     = (oal_tcp_header_stru *)(ip_hdr + 1);
    ip_pkt_len   = oal_net2host_short(ip_hdr->us_tot_len);
    ip_hdr_len   = (oal_low_half_byte(ip_hdr->us_ihl)) << 2;   /* 2: ����2λ */
    tcp_hdr_len  = (oal_high_half_byte(tcp_hdr->offset)) << 2; /* 2: ����2λ */
    if (tcp_hdr_len + ip_hdr_len == ip_pkt_len) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : Ϊnetbuf�����ڴ�
 �������  : ul_size: �����ڴ�Ĵ�С
             l_reserve: data��ָ��ͷ֮��ҪԤ���ĳ���
             ul_align: ��Ҫ���ֽڶ���
 �� �� ֵ  : �ɹ����ؽṹ��ָ�룻ʧ�ܷ���OAL_PTR_NULL
*****************************************************************************/
oal_netbuf_stru* oal_netbuf_alloc(hi_u32 ul_size, hi_u32 l_reserve, hi_u32 l_align)
{
    oal_netbuf_stru *pst_netbuf = HI_NULL;
    hi_u32       ul_offset;

    /* ��֤data���ֵ�size�������ֽڶ����С��Ԥ�������Ĵ�С */
    if (l_align) {
        ul_size += (l_align - 1);
    }

    if (NET_SKB_PAD < 64) {                         /* net skb pad less than 64 */
        pst_netbuf = dev_alloc_skb(ul_size + 32);   /* Ԥ��32�ֽڸ�ͷ��ʹ���������� */
    } else {
        pst_netbuf = dev_alloc_skb(ul_size);
    }

    if (oal_unlikely(pst_netbuf == HI_NULL)) {
        return HI_NULL;
    }

    if (NET_SKB_PAD < 64) {                         /* net skb pad less than 64 */
        skb_reserve(pst_netbuf, l_reserve + 32);    /* Ԥ��32�ֽڸ�ͷ��ʹ���������� */
    } else {
        skb_reserve(pst_netbuf, l_reserve);
    }

    if (l_align) {
        /* ����Ϊ����ʹ4�ֽڶ����ƫ���� */
        ul_offset = (hi_u32)(((unsigned long)pst_netbuf->data) % (unsigned long)l_align);
        if (ul_offset) {
            skb_reserve(pst_netbuf, l_align - ul_offset);
        }
    }

    return pst_netbuf;
}
#endif /* #if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION) */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

