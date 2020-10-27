/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: wal net file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "wal_net.h"
#include "wal_main.h"
#include "hmac_config.h"
#include "wal_ioctl.h"
#include "wal_event_msg.h"
#include "wal_customize.h"
#include "wal_scan.h"
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include "lwip/tcpip.h"
#include "lwip/netifapi.h"
#endif

#ifdef _PRE_WLAN_FEATURE_MESH
#include "dmac_ext_if.h"
#include "hmac_vap.h"
#include "hmac_user.h"
#endif
#include "wal_cfg80211.h"
#include "wal_cfg80211_apt.h"
#include "plat_firmware.h"
#include "hcc_hmac_if.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define WAL_PROTOCOL_MAX_LEN    40
/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
netif_flow_ctrl_enum            g_netif_flow_ctrl = NETIF_FLOW_CTRL_OFF;
wal_dev_addr_stru g_dev_addr = {0};
hi_u8 g_wait_mac_set = 1;
#ifdef _PRE_LINUX_BUILTIN
hi_u8 g_fw_install = 0;
#endif
#define netif_is_not_ready() (NETIF_FLOW_CTRL_ON == g_netif_flow_ctrl)
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
wal_delay_report_stru g_delay_report;
#endif
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �������ʼmac��ַ �õ�������ʱЯ��Ĭ��mac
 �޸���ʷ      :
 1.��    ��   : 2019��5��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
 2.��    ��   : 2019��5��29��
    ��    ��   : Hisilicon
    �޸�����   :���Ӵ�efuse��ȡmac addr
*****************************************************************************/
hi_void wal_init_dev_addr(hi_void)
{
    hi_u32 wait_count = 10;

    if ((cfg_get_mac(&g_dev_addr.ac_addr[0], ETHER_ADDR_LEN)) &&
        (wal_macaddr_check(&g_dev_addr.ac_addr[0]) == HI_SUCCESS)) { /* ���ȴ�nv��ȡMAC��ַ */
        return;
    }
    /* δ�����������õ�MAC��ַ,���Դ�efuse���������������ַ */
    /* ���������ַ */
    oal_random_ether_addr(g_dev_addr.ac_addr, WLAN_MAC_ADDR_LEN);
    g_dev_addr.ac_addr[1] = 0x11;
    g_dev_addr.ac_addr[2] = 0x31; /* 2 ��ַ��3λ */
    g_dev_addr.us_status = 0;

    /* �����·��¼���efuse��ȡMAC��ַ */
    g_wait_mac_set = 1;
    hi_u32 ret = wal_get_efuse_mac_addr();
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_get_efuse_mac::return err code [%u]!}", ret);
    }
    while (g_wait_mac_set == 1 && (wait_count--) > 0) {
        msleep(1);
    }
    if (g_wait_mac_set == 1) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_init_dev_addr::read addr from efuse timeout!}");
    }
}

hi_u32 wal_get_efuse_mac_addr(hi_void)
{
    oal_net_device_stru *netdev;
    wal_msg_write_stru  write_msg = {0};

    netdev = oal_get_netdev_by_name(WLAN_CFG_VAP_NAME);
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "wal_get_efuse_mac_addr::sta device not fonud.");
        return HI_FAIL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_dev_put(netdev);
#endif

    /***************************************************************************
                                ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_GET_EFUSE_MAC_ADDR, sizeof(hi_s32));
    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE, WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_s32),
        (hi_u8 *)(&write_msg), HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_get_efuse_mac_addr::return err code [%u]!}\r\n", ret);
    }

    return ret;
}

hi_u32 wal_set_dev_addr_from_efuse(const hi_char *pc_addr, hi_u8 mac_len)
{
    if (pc_addr == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "wal_set_dev_addr:: pc_addr is NULL!");
        return HI_FAIL;
    }
    if (wal_macaddr_check((const hi_u8 *)pc_addr) != HI_SUCCESS) {
        g_wait_mac_set = 0;
        oam_warning_log0(0, OAM_SF_ANY, "wal_set_dev_addr:: mac from efuse is zero!");
        return HI_FAIL;
    }

    if (memcpy_s(g_dev_addr.ac_addr, ETHER_ADDR_LEN, pc_addr, mac_len) != EOK) {
        oam_error_log0(0, 0, "wal_set_dev_addr:: memcpy_s FAILED");
        return HI_FAIL;
    }

    g_wait_mac_set = 0;
    return HI_SUCCESS;
}

hi_u32 wal_set_dev_addr(const hi_char *pc_addr, hi_u8 mac_len)
{
    hi_u32 index;
    hi_u32 count = 0;

    for (index = 0; index < WLAN_VAP_NUM_PER_BOARD; index++) {
        if (oal_get_past_net_device_by_index(index) != HI_NULL) {
            count++;
        }
    }

    /* ����ҵ��vap�����޸�mac��ַ */
    if (count > 1) {
        oam_error_log0(0, OAM_SF_ANY, "wal_set_dev_addr::vap exist, could not set mac address!");
        return HI_FAIL;
    }

    if (memcpy_s(g_dev_addr.ac_addr, ETHER_ADDR_LEN, pc_addr, mac_len) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "wal_set_dev_addr:: memcpy_s FAILED");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

/* �����豸���ͷ���mac��ַ���� */
wal_addr_idx wal_get_dev_addr_idx(nl80211_iftype_uint8 type)
{
    wal_addr_idx addr_idx = WAL_ADDR_IDX_BUTT;

    switch (type) {
        case NL80211_IFTYPE_STATION:
            addr_idx = WAL_ADDR_IDX_STA0;
            break;
        case NL80211_IFTYPE_AP:
        case NL80211_IFTYPE_P2P_CLIENT:
        case NL80211_IFTYPE_P2P_GO:
        case NL80211_IFTYPE_MESH_POINT:
            addr_idx = WAL_ADDR_IDX_AP0;
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            addr_idx = WAL_ADDR_IDX_STA2;
            break;
        default:
            oam_error_log1(0, OAM_SF_ANY, "wal_get_dev_addr_idx:: dev type [%d] is not supported !", type);
            break;
    }

    return addr_idx;
}
/* ����5.5�󱨣���166�ж���ָ�����ݽ������޸� */
hi_u32 wal_get_dev_addr(hi_u8 *pc_addr, hi_u8 addr_len, nl80211_iftype_uint8 type) /* ����5.5�󱨣�166����Ԫ�ظ�ֵ */
{
    hi_u16 us_addr[ETHER_ADDR_LEN];
    hi_u32 tmp;
    wal_addr_idx addr_idx;

    if (pc_addr == NULL) {
        oam_error_log0(0, OAM_SF_ANY, "wal_get_dev_addr:: pc_addr is NULL!");
        return HI_FAIL;
    }
    addr_idx = wal_get_dev_addr_idx(type);
    if (addr_idx >= WAL_ADDR_IDX_BUTT) {
        return HI_FAIL;
    }

    for (tmp = 0; tmp < ETHER_ADDR_LEN; tmp++) {
        us_addr[tmp] = (hi_u16)g_dev_addr.ac_addr[tmp];
    }

    /* 1.��λ���� 2.��λȡ���λ 3.��λ����λλ��0 */
    us_addr[5] += addr_idx;                         /* 5 ��ַ��6λ */
    us_addr[4] += ((us_addr[5] & (0x100))  >> 8);   /* 4 ��ַ��5λ 5 ��ַ��6λ 8 ����8λ */
    us_addr[5] = us_addr[5] & (0xff);               /* 5 ��ַ��6λ */
    /* ���λ�������,�������� */
    us_addr[3] += ((us_addr[4] & (0x100))  >> 8);   /* 3 ��ַ��4λ 4 ��ַ��5λ 8 ����8λ */
    us_addr[4] = us_addr[4] & (0xff);               /* 4 ��ַ��5λ */
    us_addr[2] += ((us_addr[3] & (0x100))  >> 8);   /* 2 ��ַ��3λ 3 ��ַ��4λ 8 ����8λ */
    us_addr[3] = us_addr[3] & (0xff);               /* 3 ��ַ��4λ */
    us_addr[1] += ((us_addr[2] & (0x100))  >> 8);   /* 1 ��ַ��2λ 2 ��ַ��3λ 8 ����8λ */
    us_addr[2] = us_addr[2] & (0xff);               /* 2 ��ַ��3λ */
    us_addr[0] += ((us_addr[1] & (0x100))  >> 8);   /* 8 ����8λ */
    us_addr[1] = us_addr[1] & (0xff);
    if (us_addr[0] > 0xff) {
        us_addr[0] = 0;
    }
    us_addr[0] &= 0xFE;

    for (tmp = 0; tmp < addr_len; tmp++) {
        pc_addr[tmp] = (hi_u8)us_addr[tmp];
    }

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u8 wal_lwip_set_hwaddr(struct netif *netif, hi_u8 *addr, hi_u8 len);
hi_void wal_lwip_status_callback(struct netif *netif);
/*****************************************************************************
 �� �� ��  : netif_set_flow_ctrl_status
 ��������  : LiteOSЭ��ջ���ط�ѹ�ӿ�
 �������  : oal_netif *netif, netif_flow_ctrl_enum_uint8 status
 �������  : ��
 �� �� ֵ  : hi_void
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��3��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void  netif_set_flow_ctrl_status(const oal_lwip_netif *netif, netif_flow_ctrl_enum_uint8 status)
{
    if (netif == HI_NULL) {
        oam_error_log0(0, 0, "netif parameter NULL.");
        return;
    }

    if (status == NETIF_FLOW_CTRL_ON) {
        g_netif_flow_ctrl = NETIF_FLOW_CTRL_ON;
    } else if (status == NETIF_FLOW_CTRL_OFF) {
        g_netif_flow_ctrl = NETIF_FLOW_CTRL_OFF;
    } else {
        oam_error_log0(0, 0, "netif_set_flow_ctrl_status::status invalid!\r\n");
    }
}

/*****************************************************************************
 ��������  : ��ʱ�Լ�����ap������������eapol�ͷŵ� ��ֹWPA�쳣ʱ����ռ��pbuff��Դ
             ��ʱʱ��Ϊ����ͳ�� �������WPA�쳣��ά��
 �������  : netdev skb����
*****************************************************************************/
hi_void hwal_handle_eapol_list(oal_net_device_stru *netdev)
{
    oal_netbuf_stru     *skb_buf = HI_NULL;
    oal_hisi_eapol_stru *hisi_eapol = &netdev->hisi_eapol;
    hi_u16              cur_time = (hi_u16)hi_get_seconds();    /* ��ȡʧ�ܲ���Ҫ��ע */
    hi_u16              time_interval;
    const hi_u16        time_5_minutes = 300;
    /* eapol�������ȡmesh��softap���������û� ȷ�������û�ͬʱ����eapol OK */
    hi_u8               max_eapol_cnt = (WLAN_SOFTAP_ASSOC_USER_MAX_NUM > WLAN_MESHAP_ASSOC_USER_MAX_NUM) ?
                        WLAN_SOFTAP_ASSOC_USER_MAX_NUM : WLAN_MESHAP_ASSOC_USER_MAX_NUM;
    /* ����Ϊ�ձ�ʾ�׸�EAPOL��� �������ʱ������� */
    if (oal_netbuf_list_empty(&hisi_eapol->eapol_skb_head) == HI_TRUE) {
        hisi_eapol->enqueue_time = cur_time;
        hisi_eapol->eapol_cnt = 0;
        return;
    }
    /* �ǿ����ж��׸����ʱ�䳬��5min������������ ���ͷŵ�һ��������ʱ�� */
    if (cur_time < hisi_eapol->enqueue_time) {
        time_interval = 0xffff - hisi_eapol->enqueue_time + cur_time;   /* ������ת */
    } else {
        time_interval = cur_time - hisi_eapol->enqueue_time;
    }
    if ((time_interval > time_5_minutes) || (hisi_eapol->eapol_cnt == max_eapol_cnt)) {
        /* �����ͬά�����ڶ�λ */
        if (time_interval > time_5_minutes) {
            oam_warning_log1(0, 0, "hwal_handle_eapol_list:wpa over time:%d to handle eapol.", time_interval);
        } else {
            oam_warning_log1(0, 0, "hwal_handle_eapol_list:eapol number reach to max:%d.", max_eapol_cnt);
        }
        hisi_eapol->eapol_cnt--;   /* �߼���֤���ᷭת */
        hisi_eapol->enqueue_time = cur_time;
        skb_buf = oal_netbuf_delist(&netdev->hisi_eapol.eapol_skb_head);
        if (skb_buf == HI_NULL) {
            oam_error_log0(0, 0, "hwal_handle_eapol_list:: get netbuf is null.");
            return;
        }
        oal_netbuf_free(skb_buf);
    }
}

/*****************************************************************************
 ��������  : liteos���ݽ��սӿڣ�ʵ�������ϱ�lwipЭ��ջ
 �������  : oal_netbuf_stru *pst_netbuf
*****************************************************************************/
hi_u32 hwal_netif_rx(oal_net_device_stru *netdev, oal_netbuf_stru *netbuf)
{
    hi_u16                  us_ether_type;
    oal_ether_header_stru      *eth_hdr = HI_NULL;
    oal_hisi_eapol_stru        *hisi_eapol = HI_NULL;

    if ((netbuf == HI_NULL) || (netdev == HI_NULL)) {
        oam_error_log0(0, 0, "netif_rx_ni parameter NULL.");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡ֡���� */
    eth_hdr     = (oal_ether_header_stru *)(netbuf->data);
    us_ether_type   = eth_hdr->us_ether_type;

    /* ���ݲ�ͬ֡���ͣ�������Ӧ���� */
    if ((us_ether_type == oal_host2net_short(ETHER_TYPE_IP)) ||
        (us_ether_type == oal_host2net_short(ETHER_TYPE_ARP)) ||
        (us_ether_type == oal_host2net_short(ETHER_TYPE_RARP)) ||
        (us_ether_type == oal_host2net_short(ETHER_TYPE_IPV6)) ||
        (us_ether_type == oal_host2net_short(ETHER_TYPE_6LO))) {
        hwal_lwip_receive(netdev->lwip_netif, netbuf);

#ifdef _PRE_LWIP_ZERO_COPY
        if (HI_SUCCESS != hwal_skb_struct_free(netbuf)) {
            oam_error_log0(0, 0, "[hwal_lwip_receive] skb_struct free fail");
        }
#else
        oal_netbuf_free(netbuf);
#endif
        /* DTS2016081109861  Hi1131C bug fix  masiyuan/m00354437 end */
    } else if (oal_host2net_short(ETHER_TYPE_PAE) == us_ether_type) {
        hisi_eapol = &netdev->hisi_eapol;
        /* ��Ӻ����¼���WPA��ȡ */
        if ((hisi_eapol->register_code == HI_TRUE) && (hisi_eapol->notify_callback != HI_NULL)) {
            /* ���ǰ�жϵ�ǰ������ʱ2min�Լ�����ap������������eapol�ͷŵ� ��ֹWPA�쳣ʱ����ռ��pbuff��Դ */
            /* mesh��6����softap 2�� */
            hwal_handle_eapol_list(netdev);
            /* ��ǰeapol������Ӳ�֪ͨwpa���� */
            hisi_eapol->eapol_cnt++;   /* ���+1 */
            oal_netbuf_list_tail(&hisi_eapol->eapol_skb_head, netbuf);
            hisi_eapol->notify_callback(netdev->name, hisi_eapol->context);
        } else {
            /* δע����ֱ���ͷ�netbuff */
            oal_netbuf_free(netbuf);
            oam_error_log0(0, 0, "eapol process is not register.\r\n");
        }
    } else {
        oal_netbuf_free(netbuf);
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hwal_lwip_skb_alloc
 ��������  : ����netbuf�ռ䣬ȡ����������ͷ�ռ估β�ռ�Ԥ��
 �������  : hi_s32 l_size
 �������  : ��
 �� �� ֵ  : static oal_netbuf_stru *
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��3��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
oal_netbuf_stru *hwal_lwip_skb_alloc(const oal_net_device_stru *netdev, hi_u16 us_lwip_buflen)
{
    oal_netbuf_stru *netbuf = HI_NULL;
    hi_u32           total_size;

    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_lwip_skb_alloc pst_net_dev NULL.");
        return HI_NULL;
    }

    /* �����СΪHCC������󳤶ȼ���ͷ�ռ估β�ռ� */
    total_size = us_lwip_buflen + (hi_u16)netdev->needed_headroom + (hi_u16)netdev->needed_tailroom;

    netbuf = oal_netbuf_alloc(total_size, (hi_u32)netdev->needed_headroom, 4);  /* align 4 */

    return netbuf;
}

/*****************************************************************************
 �� �� ��  : hwal_skb_struct_alloc
 ��������  : ��������struct sk_buff
 �������  : hi_void
 �������  : ��
 �� �� ֵ  : oal_netbuf_stru *
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��7��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
oal_netbuf_stru *hwal_skb_struct_alloc(hi_void)
{
    oal_netbuf_stru *skb = oal_malloc_netbuf_stru();
    if (oal_unlikely(skb == HI_NULL)) {
        oam_error_log0(0, 0, "{hwal_skb_struct_alloc::oal_malloc_netbuf_stru err}");
        return HI_NULL;
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(skb, sizeof(oal_netbuf_stru), 0, sizeof(oal_netbuf_stru));

    hi_atomic_set(&skb->users, 1);

    return skb;
}
/*****************************************************************************
 �� �� ��  : hwal_skb_struct_free
 ��������  : �����ͷ�struct sk_buff
 �������  : oal_netbuf_stru *pst_sk_buf
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��7��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hwal_skb_struct_free(oal_netbuf_stru *sk_buf)
{
    if (sk_buf == HI_NULL) {
        return HI_FAIL;
    }

    oal_free_netbuf_stru(sk_buf);

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hwal_pbuf_convert_2_skb
 ��������  : ��Lwip��pbuf��skbת��
 �������  : oal_lwip_buf *pst_lwip_buf
             oal_netbuf_stru *pst_sk_buf
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  : hwal_lwip_send

 �޸���ʷ      :
  1.��    ��   : 2016��7��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hwal_pbuf_convert_2_skb(const oal_net_device_stru *netdev, oal_lwip_buf *lwip_buf, oal_netbuf_stru *sk_buf)
{
    hi_u32          reserve_tail_room ;

    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "[hwal_pbuf_convert_2_skb] pst_netdev is NULL!");
        return HI_FAIL;
    }

    reserve_tail_room = (hi_u32)oal_netdevice_tailroom(netdev);
    /*
    1.skb/pbufָ��ת��
    2.sk/pbuf����ת��
    3.pbuf->ref������ȷ��������HCC�ɹ����ͺ����ͷſռ�
    */
    if ((lwip_buf == HI_NULL) || (sk_buf == HI_NULL)) {
        oam_error_log2(0, 0, "[hwal_pbuf_convert_2_skb] pst_lwip_buf[%p],pst_sk_buf[%p]!",
                       (uintptr_t)lwip_buf, (uintptr_t)sk_buf);
        return HI_FAIL;
    }

    /*
                                 pbuf's memory distribution
    |-----PBUF-----|--------RESERVE--------|----------PAYLOAD---------|---TAILROOM---|

                          converted sk_buff's ptr according to pbuf
    p_mem_head     head                    data                       tail           end
    */
    sk_buf->mem_head = (hi_u8 *)lwip_buf;
    sk_buf->head       = (hi_u8 *)lwip_buf->payload - PBUF_ZERO_COPY_RESERVE;
    sk_buf->data       = (hi_u8 *)lwip_buf->payload;
    skb_reset_tail_pointer(sk_buf);
    sk_buf->tail      += lwip_buf->len;
    /* �ڴ�����ʱ����������ֽڶ��룬�˴����õ����ڴ�Խ�� */
    sk_buf->end        = oal_nlmsg_align((hi_u32)sk_buf->tail) + oal_nlmsg_align(reserve_tail_room);

    sk_buf->len        = lwip_buf->len;

    pbuf_ref(lwip_buf);

    return HI_SUCCESS;
}
/*****************************************************************************
 �� �� ��  : hwal_skb_convert_2_pbuf
 ��������  : ��skb��Lwip��pbufת��
 �������  : oal_netbuf_stru *pst_sk_buf
 �������  : ��
 �� �� ֵ  : oal_lwip_buf *
 ���ú���  :
 ��������  : hwal_lwip_receive

 �޸���ʷ      :
  1.��    ��   : 2016��7��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
oal_lwip_buf *hwal_skb_convert_2_pbuf(const oal_netbuf_stru *sk_buf)
{
    /*
    1.skb/pbufָ��ת��
    2.sk/pbuf����ת�� len, tot_len
    */
    oal_lwip_buf       *lwip_buf  = HI_NULL;

    if ((sk_buf == HI_NULL) || (sk_buf->mem_head == HI_NULL)) {
        oam_error_log0(0, 0, "[hwal_skb_convert_2_pbuf] pst_sk_buf or p_mem_head = NULL!");
        return HI_NULL;
    }

    lwip_buf          = (oal_lwip_buf *)sk_buf->mem_head;
    lwip_buf->payload = sk_buf->data;
    lwip_buf->tot_len = (hi_u16)sk_buf->len ; /* 32bit --->16bit */
    lwip_buf->len     = (hi_u16)sk_buf->len;  /* 32bit --->16bit */

    return lwip_buf;
}

/*****************************************************************************
 �� �� ��  : hwal_lwip_receive
 ��������  : �����������ݲ��ϱ�lwip�ӿڣ��������ͷ�netbuf�ڴ�
 �������  :
 �������  : ��
 �� �� ֵ  : hi_void
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��3��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2016��7��30��
    ��    ��   : Hisilicon
    �޸�����   : �����޸�

*****************************************************************************/
hi_void hwal_lwip_receive(oal_lwip_netif *netif, oal_netbuf_stru *drv_buf)
{
    oal_lwip_buf       *lwip_buf = HI_NULL;
#ifdef _PRE_WLAN_FEATURE_LWIP_NETIF_USE_L2_METRICS
    hmac_rx_ctl_stru   *rx_cb = HI_NULL;
#endif

    if ((netif == HI_NULL) || (drv_buf == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_lwip_receive pst_netif is null!");
        return;
    }

#ifdef _PRE_LWIP_ZERO_COPY
    lwip_buf = hwal_skb_convert_2_pbuf(drv_buf);
    if (lwip_buf != (oal_lwip_buf *)drv_buf->mem_head) {
        oam_error_log0(0, 0, "[hwal_lwip_receive] skb_convert_2_pbuf, addr not match!");
        return;
    }
    if (lwip_buf == HI_NULL) {
        oam_error_log0(0, 0, "[hwal_lwip_receive] skb_convert_2_pbuf, pst_lwip_buf is null!");
        return;
    }
#else
    /* ����LWIPЭ��ջ�����ڴ� 32bit->16bit */
    lwip_buf = pbuf_alloc(PBUF_RAW, (hi_u16)(oal_netbuf_len(drv_buf) + ETH_PAD_SIZE), PBUF_RAM);
    if (lwip_buf == HI_NULL) {
        oam_error_log1(0, 0, "hwal_lwip_receive pbuf_alloc failed! len = %d", oal_netbuf_len(drv_buf));
        return;
    }

    /* ��payload��ַ����ƫ��2�ֽ� */
#if ETH_PAD_SIZE
    pbuf_header(lwip_buf, -ETH_PAD_SIZE);
#endif

    /* ���ڴ渴�Ƶ�LWIPЭ��ջ�����ڴ� */
    if (memcpy_s(lwip_buf->payload, oal_netbuf_len(drv_buf),
        oal_netbuf_data(drv_buf), oal_netbuf_len(drv_buf)) != EOK) {
        oam_error_log0(0, 0, "{hwal_lwip_receive::mem safe function err!}");
        return;
    }
#endif

#ifdef _PRE_WLAN_FEATURE_LWIP_NETIF_USE_L2_METRICS
    rx_cb = (hmac_rx_ctl_stru *)oal_netbuf_cb(drv_buf);
    pbuf_set_RSSI(lwip_buf, rx_cb->rssi_dbm);
    pbuf_set_LQI(lwip_buf, 0);
#endif

    /* ��payload��ַǰ��2�ֽ� */
#if ETH_PAD_SIZE
    pbuf_header(lwip_buf, ETH_PAD_SIZE);
#endif

    /* �ϱ�Э��ջ */
    driverif_input(netif, lwip_buf);
}

hi_u32 hwal_lwip_send_check(const oal_lwip_netif *netif, const oal_lwip_buf *lwip_buf)
{
    if ((lwip_buf == HI_NULL) || (netif == HI_NULL)) {
        oam_error_log0(0, 0, "hwal_lwip_send parameter NULL.");
        return HI_FAIL;
    }

    oal_net_device_stru *netdev = (oal_net_device_stru *)netif->state;
    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "pst_netif->state parameter NULL.");
        return HI_FAIL;
    }

    return HI_SUCCESS;
}

oal_netbuf_stru *hwal_get_converted_skb(oal_lwip_buf *lwip_buf, const oal_net_device_stru *netdev)
{
    oal_netbuf_stru *converted_skb = HI_NULL;
    oal_lwip_buf    *buf_tmp       = HI_NULL;
    hi_u32 lwip_buf_index = 0;
    hi_u32 drv_buf_offset = 0;

#if ETH_PAD_SIZE
    /* magic num to be modified */
    converted_skb = hwal_lwip_skb_alloc(netdev, lwip_buf->tot_len + 32 - (ETHER_HDR_LEN - SNAP_LLC_FRAME_LEN)); /* 32 */
    if (converted_skb == HI_NULL) {
        return HI_NULL;
    }
    skb_reserve(converted_skb, 32 - (ETHER_HDR_LEN - SNAP_LLC_FRAME_LEN)); /* 32 ƫ���� */
#else
    converted_skb = hwal_lwip_skb_alloc(netdev, lwip_buf->tot_len);
    if (converted_skb == HI_NULL) {
        return HI_NULL;
    }
#endif

    for (buf_tmp = lwip_buf; buf_tmp != HI_NULL; buf_tmp = buf_tmp->next) {
        lwip_buf_index++;
        if (oal_netbuf_tailroom(converted_skb) < buf_tmp->len) {
            oam_error_log3(0, 0, "oal_netbuf_tailroom.tail = %d, len = %d, idx = %d",
                oal_netbuf_tailroom(converted_skb), buf_tmp->len, lwip_buf_index);
            oal_netbuf_free(converted_skb);
            return HI_NULL;
        }

        oal_netbuf_put(converted_skb, buf_tmp->len);
        if ((buf_tmp->payload != HI_NULL) && (memcpy_s(oal_netbuf_data(converted_skb) + drv_buf_offset, buf_tmp->len,
            buf_tmp->payload, buf_tmp->len) != EOK)) {
            oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_send::mem safe function err!}");
            continue;
        }

        /* ��ƫ�������£�����pbuf������һ��buf */
        drv_buf_offset += buf_tmp->len;
    }

    return converted_skb;
}

/*****************************************************************************
 �� �� ��  : hwal_lwip_send
 ��������  : ��LWIPЭ��ջע��ķ��ͻص�����
 �������  :
 �������  : ��
 �� �� ֵ  : static hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��3��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2016��7��30��
    ��    ��   : Hisilicon
    �޸�����   : �����޸�
*****************************************************************************/
/* 1337�н��ú���ָ�븳����netif->drv_set_hwaddr������ı�ú���������Ҫ�ı�netif�ṹ�壬lint_t e818�澯���� */
hi_void hwal_lwip_send(oal_lwip_netif *netif, oal_lwip_buf *lwip_buf)
{
    oal_netbuf_stru *converted_skb = HI_NULL;

    if (hwal_lwip_send_check(netif, lwip_buf) != HI_SUCCESS) {
        return;
    }

    oal_net_device_stru *netdev = (oal_net_device_stru *)netif->state;

    /* Flow_ctl */
    if ((hi_bool)netif_is_not_ready() == HI_TRUE) {
        /* release thread, reduce packet loss rate */
        hi_sleep(1);

        /* ��������֡���� DHCP ARP RARP EAPOL */
        if (mac_get_data_type_from_8023(lwip_buf->payload, MAC_NETBUFF_PAYLOAD_ETH) <= MAC_DATA_DHCP_ACK) {
            oam_warning_log0(0, OAM_SF_TX, "[hwal_lwip_wifi_drv_send] dhcp drop to driver!\r\n");
        }
        return ;
    }

#ifdef _PRE_LWIP_ZERO_COPY
    /* HCC���ͳɹ�֮ǰ,Lwip�ش��������ٴ��·�,ֱ�ӷ���,������ڴ��ظ����� */
    if (lwip_buf->ref >= 2) { /* 2 �����·���ֱ�ӷ��� */
        return ;
    }

    converted_skb = hwal_skb_struct_alloc();
    if (converted_skb == HI_NULL) {
        return ;
    }

    if (hwal_pbuf_convert_2_skb(netdev, lwip_buf, converted_skb) != HI_SUCCESS) {
        oal_netbuf_free(converted_skb);
        return ;
    }
#else
    converted_skb = hwal_get_converted_skb(lwip_buf, netdev);
    if (converted_skb == HI_NULL) {
        return;
    }
#endif

#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    /* Mesh�豣��lwipЭ��ջextflag����ʱʹ��cb�ֶν�flag���浽hmac�㴦��hmac��ʹ��cb�ֶ�ǰ������ */
    hi_u16 *pus_cb = (hi_u16 *)oal_netbuf_cb(converted_skb);
    if (memcpy_s(pus_cb, sizeof(hi_u16), &lwip_buf->flags, sizeof(hi_u16)) != EOK) {
        oal_netbuf_free(converted_skb);
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_send::mem safe function err!}");
        return;
    }

    /* ����Pbuf�����ȼ��ֶ� */
    oal_netbuf_priority(converted_skb) = lwip_buf->priority;
#endif

    if ((netdev->netdev_ops == HI_NULL) || (netdev->netdev_ops->ndo_start_xmit == HI_NULL)) {
        oam_error_log0(0, 0, "pst_net_dev->netdev_ops NULL.");
        oal_netbuf_free(converted_skb);
        return ;
    }

    converted_skb->queue_mapping = 0;
    netdev->netdev_ops->ndo_start_xmit(converted_skb, netdev);
}

hi_void hwal_netif_drv_config(struct netif *netif, hi_u32 config_flags, hi_u8 set_bit)
{
    hi_unref_param(netif);
    hi_unref_param(config_flags);
    hi_unref_param(set_bit);
    return;
}


#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
/*****************************************************************************
 ��������  : MeshЭ��ջ֪ͨ������ĳ���û�ȥ����
 �������  : oal_lwip_netif *pst_netif, oal_linklayer_addr *pst_mac_addr
 �� �� ֵ  :hi_s32
 �޸���ʷ      :
  1.��    ��   : 2019��1��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_s32  hwal_lwip_remove_user(oal_lwip_netif *netif, oal_linklayer_addr *mac_addr)
{
    oal_net_device_stru *netdev = HI_NULL;
    mac_vap_stru        *mac_vap = HI_NULL;
    wal_msg_write_stru   write_msg;
    mac_cfg_kick_user_param_stru *kick_user_param = HI_NULL;

    if (netif == HI_NULL) {
        oam_error_log0(0, 0, "hwal_lwip_remove_user parameter NULL.");
        return HI_ERR_CODE_PTR_NULL;
    }

    netdev = (oal_net_device_stru *)netif->state;
    if (oal_unlikely((netdev == HI_NULL) || (mac_addr == HI_NULL))) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_remove_user::pst_net_dev or pst_mac_addr null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡVAP�ṹ�� */
    mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);
    /* ���VAP�ṹ�岻���ڣ���ֱ�ӷ��� */
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_lwip_remove_user::pst_vap = OAL_PTR_NULL!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_addr->addrlen != WLAN_MAC_ADDR_LEN) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_lwip_remove_user::the mac address len is invalid!}");
        return HI_FAIL;
    }

    if (ether_is_multicast(mac_addr->addr)) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_lwip_remove_user::is not unicast mac address!}");
        return HI_FAIL;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_KICK_USER, sizeof(mac_cfg_kick_user_param_stru));

    /* ��������������� */
    kick_user_param = (mac_cfg_kick_user_param_stru *)(write_msg.auc_value);
    if (memcpy_s(kick_user_param->auc_mac_addr, WLAN_MAC_ADDR_LEN,
        (hi_u8*)(mac_addr->addr), WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_remove_user::mem safe function err!}");
        return HI_FAIL;
    }
    /* ��дȥ����reason code */
    kick_user_param->us_reason_code = MAC_UNSPEC_REASON;

    hi_u32 ret = wal_send_cfg_event(netdev,
                                    WAL_MSG_TYPE_WRITE,
                                    WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_kick_user_param_stru),
                                    (hi_u8 *)&write_msg,
                                    HI_FALSE,
                                    HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hwal_lwip_remove_user::return err code [%u]!}", ret);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : MeshЭ��ջ����beacon/probe rsp�е�Hisi-optimization�ֶ�
 �������  : oal_lwip_netif *pst_netif, hi_u8 uc_prio
 �� �� ֵ  :hi_s32
 �޸���ʷ      :
  1.��    ��   : 2019��4��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_s32 hwal_lwip_set_beacon_priority(oal_lwip_netif *netif, hi_u8 prio)
{
    hi_u32               ret;
    oal_net_device_stru *netdev = HI_NULL;
    mac_vap_stru        *mac_vap = HI_NULL;
    wal_msg_write_stru   write_msg;

    if (netif == HI_NULL) {
        oam_error_log0(0, 0, "hwal_lwip_set_beacon_priority pst_netif parameter NULL.");
        return HI_ERR_CODE_PTR_NULL;
    }

    netdev = (oal_net_device_stru *)netif->state;
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_set_beacon_priority::pst_net_dev null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȡVAP�ṹ�� */
    mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);
    /* ���VAP�ṹ�岻���ڣ���ֱ�ӷ��� */
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_lwip_set_beacon_priority::pst_vap = OAL_PTR_NULL!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_BEACON_PRIORITY, sizeof(hi_u8));

    /* ��������������� */
    *((hi_u8 *)(write_msg.auc_value)) = prio;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u8),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hwal_lwip_set_beacon_priority::return err code [%u]!}", ret);
        return (hi_s32)ret;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_netdev_set_mnid
 ��������  : MeshЭ��ջ����vap��mnid
 �������  : oal_lwip_netif *pst_netif, oal_uniqid_t us_mnid
 �� �� ֵ  :hi_s32
 �޸���ʷ      :
  1.��    ��   : 2019��4��28��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_s32 hwal_lwip_set_mnid(oal_lwip_netif *netif, oal_uniqid_t us_mnid)
{
    hi_u32               ret;
    oal_net_device_stru *netdev = HI_NULL;
    mac_vap_stru        *mac_vap = HI_NULL;
    wal_msg_write_stru   write_msg;

    if (oal_unlikely(netif == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_set_mnid::pst_netif null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    netdev = (oal_net_device_stru *)netif->state;
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_set_mnid::pst_net_dev null ptr error!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ��ȡVAP�ṹ�� */
    mac_vap = (mac_vap_stru *)oal_net_dev_priv(netdev);
    /* ���VAP�ṹ�岻���ڣ���ֱ�ӷ��� */
    if (oal_unlikely(mac_vap == HI_NULL)) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_lwip_set_mnid::pst_vap = OAL_PTR_NULL!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (mac_vap->vap_mode != WLAN_VAP_MODE_MESH) {
        oam_warning_log0(0, OAM_SF_ANY, "{hwal_lwip_set_mnid::pst_vap is not mesh vap!}");
        return HI_FAIL;
    }

    /***************************************************************************
                             ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_SET_MNID, sizeof(hi_u16));

    /* ��������������� */
    *((hi_u16 *)(write_msg.auc_value)) = us_mnid;

    ret = wal_send_cfg_event(netdev,
                             WAL_MSG_TYPE_WRITE,
                             WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(hi_u16),
                             (hi_u8 *)&write_msg,
                             HI_FALSE,
                             HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{hwal_lwip_set_mnid::return err code [%u]!}", ret);
        return (hi_s32)ret;
    }
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 �� �� ��  : hwal_lwip_register_netdev
 ��������  : LWIPЭ��ջ��ʼ��
 �������  :
 �������  : ��
 �� �� ֵ  : hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��3��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hwal_lwip_register(oal_net_device_stru *netdev, oal_ip_addr_t *ip, oal_ip_addr_t *netmask, oal_ip_addr_t *gw)
{
    oal_lwip_netif *netif = malloc(sizeof(oal_lwip_netif));
    if (netif == HI_NULL) {
        oam_error_log0(0, 0, "hwal_lwip_register_netdev failed mem alloc NULL.");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(netif, sizeof(oal_lwip_netif), 0, sizeof(oal_lwip_netif));

    OAL_IP4_ADDR(gw, 0, 0, 0, 0);
    OAL_IP4_ADDR(ip, 0, 0, 0, 0);
    OAL_IP4_ADDR(netmask, 0, 0, 0, 0);

    /* �����豸ע�� */
    netif->state            = (hi_void *)netdev;
    netif->drv_send         = hwal_lwip_send;
    netif->drv_set_hwaddr   = wal_lwip_set_hwaddr;
    netif->link_layer_type  = WIFI_DRIVER_IF;
    netif->hwaddr_len       = ETHARP_HWADDR_LEN;
    netif->drv_config       = hwal_netif_drv_config;

    /* ��dev���Ƴ�ʼ��netif���� */
    if (strncpy_s(netif->name, IFNAMSIZ, netdev->name, IFNAMSIZ - 2) != EOK) { /* 2 size��2 */
        oam_error_log0(0, OAM_SF_ANY, "{hwal_lwip_register_netdev::strncpy_s err!}");
        free(netif);
        return HI_FAIL;
    }
    netif->name[IFNAMSIZ - 2] = '\0'; /* 2 string���һλ */

    if (netifapi_netif_add(netif, ip, netmask, gw) != HI_SUCCESS) {
        free(netif);
        oam_error_log0(0, 0, "hwal_lwip_register_netdev failed netif_add NULL.");
        return HI_FAIL;
    }

    /* ������Ӻ�ӿ���(�����)����dev���� */
    hi_s32 size = snprintf_s(netdev->name, IFNAMSIZ, (IFNAMSIZ-1), "%s%"U16_F, netif->name, netif->num);
    if ((size != -1) && (size < OAL_IF_NAME_SIZE)) {
        netdev->name[size] = '\0';
    } else {
        free(netif);
        return HI_FAIL;
    }
#if 0
    netif->status_callback = wal_lwip_status_callback;
#endif
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    netif->remove_peer     = hwal_lwip_remove_user;
    netif->set_beacon_prio = hwal_lwip_set_beacon_priority;
    netif->set_unique_id   = hwal_lwip_set_mnid;
#endif

    if (memcpy_s(netif->hwaddr, NETIF_MAX_HWADDR_LEN, netdev->dev_addr, ETHER_ADDR_LEN) != EOK) {
        free(netif);
        return HI_FAIL;
    }
    netdev->lwip_netif = netif;

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hwal_lwip_deinit
 ��������  : LWIPЭ��ջȥ��ʼ��
 �������  :
 �������  : ��
 �� �� ֵ  : hi_s32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2016��3��22��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void hwal_lwip_unregister_netdev(oal_net_device_stru *netdev)
{
    if (netdev == HI_NULL) {
        return;
    }

    if (netdev->lwip_netif != HI_NULL) {
        netifapi_netif_remove(netdev->lwip_netif);
        free(netdev->lwip_netif);
    }

    netdev->lwip_netif = HI_NULL;

    return;
}

#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
/*****************************************************************************
 ��������  : �����ϱ�ȥ����״̬�ı䵽LWIP��
*****************************************************************************/
hi_void wal_report_sta_disassoc_to_lwip(oal_net_device_stru *netdev)
{
    hi_u8 index;
    /* �ڲ����ú����������Ϸ����ɵ����߱�֤ */
    if (netdev->lwip_netif->linklayer_event != HI_NULL) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::LL_EVENT_AP_DISCONN}");
            netdev->lwip_netif->linklayer_event(netdev->lwip_netif, LL_EVENT_AP_DISCONN, HI_NULL);
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::linklayer_event callback isn't registed}");
    }

    (hi_void)netifapi_netif_set_link_down(netdev->lwip_netif);
    (hi_void)netifapi_netif_set_addr(netdev->lwip_netif, HI_NULL, HI_NULL, HI_NULL);
    for (index = 0; index < LWIP_IPV6_NUM_ADDRESSES; index++) {
        (hi_void)netifapi_netif_rmv_ip6_address(netdev->lwip_netif, &netdev->lwip_netif->ip6_addr[index]);
    }
    oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::report sta disconn succ to lwip!}");
}
#endif

/*****************************************************************************
 �� �� ��  : wal_lwip_set_hwaddr
 ��������  : ��LWIPЭ��ջע����޸�mac��ַ�ص�����
 �������  : [1]netif
             [2]addr
             [3]len
 �������  : ��
 �� �� ֵ  : hi_u32
*****************************************************************************/
/* 1337�н��ú���ָ�븳����netif->drv_set_hwaddr������ı�ú���������Ҫ�ı�netif�ṹ�壬lint_t e818�澯���� */
hi_u8 wal_lwip_set_hwaddr(struct netif *netif, hi_u8 *addr, hi_u8 len)
{
    oal_net_device_stru *netdev = HI_NULL;

    if (netif == NULL) {
        oam_error_log0(0, 0, "netif is NULL!");
        return (hi_u8)HI_FAIL;
    }
    if (addr == NULL) {
        oam_error_log0(0, 0, "addr is NULL!");
        return (hi_u8)HI_FAIL;
    }

    if ((addr[0] & 0x01) != 0) {
        oam_error_log0(0, 0, "config a muticast mac address, please check!");
        return (hi_u8)HI_FAIL;
    }
    if (len != ETHER_ADDR_LEN) {
        oam_error_log1(0, 0, "config wrong mac address len=%u.", len);
        return (hi_u8)HI_FAIL;
    }

    netdev = (oal_net_device_stru *)netif->state;
    if (netdev == NULL) {
        oam_error_log0(0, 0, "netdev is NULL!");
        return (hi_u8)HI_FAIL;
    }

    /* ���netdev��running״̬����ֱ�ӷ���ʧ�� */
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) != 0) {
        oam_error_log0(0, 0, "netdev is running!");
        return (hi_u8)HI_FAIL;
    }

    /* ����netdev�е�mac��ַ */
    if (memcpy_s(netdev->dev_addr, ETHER_ADDR_LEN, addr, ETHER_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_lwip_set_hwaddr::mem safe function err!}");
        return (hi_u8)HI_FAIL;
    }
    /* ����netdevice��MAC��ַ��MAC��ַ��HMAC�㱻��ʼ����MIB�� */
    if (wal_set_mac_to_mib(netdev) != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_lwip_set_hwaddr::wal_set_mac_to_mib fail!}");
        return (hi_u8)HI_FAIL;
    }

    return (hi_u8)HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��LWIPЭ��ջע������ӱ仯�ص�����
 �������  : struct netif *netif
*****************************************************************************/
/* 1366�н��ú���ָ�븳����netif->drv_set_hwaddr������ı�ú���������Ҫ�ı�netif�ṹ�壬lint_t e818�澯���� */
hi_void wal_lwip_status_callback(struct netif *netif)
{
    oal_net_device_stru *netdev = HI_NULL;

    if ((netif == HI_NULL) || (netif->state == HI_NULL)) {
        return;
    }

    netdev = (oal_net_device_stru *)netif->state;
    if (netif->flags & NETIF_FLAG_UP) {
        wal_netdev_open(netdev);
    } else {
        wal_netdev_stop(netdev);
    }
}
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

#ifdef _PRE_WLAN_FEATURE_MESH
/*****************************************************************************
 �� �� ��  : wal_mesh_inform_tx_data_info
 ��������  : MESH �����ϱ�Lwip ��������֡��һЩ��Ϣ��
 �������  : frw_event_mem_stru *event_mem
 �� �� ֵ  :hi_u32
 �޸���ʷ      :
  1.��    ��   : 2019��1��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_mesh_inform_tx_data_info(frw_event_mem_stru *event_mem)
{
    frw_event_stru              *event = HI_NULL;
    dmac_tx_info_report_stru *tx_info_param = HI_NULL;
    oal_net_device_stru *netdev = HI_NULL;
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    oal_event_tx_info_stru tx_info;
#endif

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_mesh_inform_tx_data_info::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    event  = (frw_event_stru *)event_mem->puc_data;

    tx_info_param = (dmac_tx_info_report_stru *)event->auc_event_data;
    netdev = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ANY,
            "{wal_mesh_inform_tx_data_info::get net device ptr is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    if (memcpy_s(tx_info.addr.addr, NETIF_MAX_HWADDR_LEN, tx_info_param->auc_da, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_mesh_inform_tx_data_info::mem safe function err!}");
        return HI_FAIL;
    }
    tx_info.addr.addrlen = WLAN_MAC_ADDR_LEN;
    tx_info.retry_count = tx_info_param->tx_count;
    tx_info.status = tx_info_param->mesh_tx_status;
    tx_info.pkt_sz = tx_info_param->us_length;
    tx_info.data_rate = tx_info_param->rate_kbps;
    tx_info.bandwidth = tx_info_param->bw;
    oam_info_log4(0, OAM_SF_ANY,
        "{wal_mesh_inform_tx_data_info::report to mesh stack,retry_count = %d,status = %d,pkt_sz = %d,data_rate = %d}",
        tx_info_param->tx_count, tx_info_param->mesh_tx_status, tx_info_param->us_length, tx_info_param->rate_kbps);
    oam_info_log1(0, OAM_SF_ANY, "{wal_mesh_inform_tx_data_info::report to mesh stack,bandwidth = %d!}",
        tx_info_param->bw);

    if (netdev->lwip_netif->linklayer_event != HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_inform_tx_data_info::LL_EVENT_TX_INFO}");
        netdev->lwip_netif->linklayer_event(netdev->lwip_netif, LL_EVENT_TX_INFO, (hi_u8 *)&tx_info);
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_inform_tx_data_info::linklayer_event callback isn't registed!}");
    }

    oam_info_log0(0, OAM_SF_ANY, "{wal_mesh_inform_tx_data_info::report tx data info!}");
#else
    hi_unref_param(tx_info_param);
#endif
    return HI_SUCCESS;
}

/* wal_mesh_report_assoc_infoû����������lin_t515�澯���澯���� */
hi_u32 wal_mesh_report_assoc_info(const mac_user_assoc_info_stru *assoc_info, oal_net_device_stru *netdev)
{
    hi_unref_param(netdev);

#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    oal_event_new_peer_stru new_peer;
    if (memcpy_s(new_peer.addr.addr, NETIF_MAX_HWADDR_LEN, assoc_info->auc_user_addr, WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::mem safe function err!}");
        return HI_FAIL;
    }
    new_peer.addr.addrlen = WLAN_MAC_ADDR_LEN;
    new_peer.is_mesh_user = ((assoc_info->is_initiative_role << 4) | (assoc_info->is_mesh_user & 0x0F)); /* 4 */
    new_peer.beacon_prio  = assoc_info->bcn_prio;
    new_peer.rssi         = (hi_s8)(-(assoc_info->conn_rx_rssi));
    new_peer.lqi          = 0;

    if (netdev->lwip_netif->linklayer_event != HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::LL_EVENT_NEW_PEER}");
        netdev->lwip_netif->linklayer_event(netdev->lwip_netif, LL_EVENT_NEW_PEER, (hi_s8 *)&new_peer);
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info:linklayer_event callback isn't registed}");
    }
#endif

    if (assoc_info->is_mesh_user == HI_TRUE) {
        oam_warning_log3(0, OAM_SF_ANY,
            "{wal_mesh_report_mesh_user_info:report add mesh peer to lwip,bcn_prio=%d,role=%d,rssi=%d}",
            assoc_info->bcn_prio, assoc_info->is_initiative_role, (hi_s32)(-(assoc_info->conn_rx_rssi)));
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::report add sta to lwip}");
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : MESH �����ϱ�ĳ�û�����״̬�ı䡣
 �������  : frw_event_mem_stru *event_mem
 �� �� ֵ  :hi_u32
 �޸���ʷ      :
  1.��    ��   : 2019��4��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_mesh_report_mesh_user_info(frw_event_mem_stru *event_mem)
{
    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_stru            *event      = (frw_event_stru *)event_mem->puc_data;
    mac_user_assoc_info_stru *assoc_info = (mac_user_assoc_info_stru *)event->auc_event_data;
    oal_net_device_stru       *netdev     = hmac_vap_get_net_device(event->event_hdr.vap_id);
    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::netdev null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    if (assoc_info->assoc_state == MAC_USER_STATE_DEL) {
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
        oal_event_del_peer_stru del_peer;
        if (memcpy_s(del_peer.addr.addr, NETIF_MAX_HWADDR_LEN,
            assoc_info->auc_user_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::mem safe function err!}");
            return HI_FAIL;
        }
        del_peer.addr.addrlen = WLAN_MAC_ADDR_LEN;
        del_peer.is_mesh_user = assoc_info->is_mesh_user;

        if (netdev->lwip_netif->linklayer_event != HI_NULL) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::LL_EVENT_DEL_PEER}");
            netdev->lwip_netif->linklayer_event(netdev->lwip_netif, LL_EVENT_DEL_PEER, (hi_u8 *)&del_peer);
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info:linklayer_event callback isn't registed}");
        }
#endif

        if (assoc_info->is_mesh_user == HI_TRUE) {
            oam_warning_log2(0, OAM_SF_ANY,
                "{wal_mesh_report_mesh_user_info:report del mesh peer to lwip,mac addr[%x:%x]}",
                assoc_info->auc_user_addr[4], assoc_info->auc_user_addr[5]); /* 4 5 ��ַλ�� */
        } else {
            oam_warning_log2(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::report del sta to lwip,mac addr[%x:%x]}",
                assoc_info->auc_user_addr[4], assoc_info->auc_user_addr[5]); /* 4 5 ��ַλ�� */
        }

        return HI_SUCCESS;
    } else if (assoc_info->assoc_state == MAC_USER_STATE_ASSOC) {
        hi_u32 ret = wal_mesh_report_assoc_info(assoc_info, netdev);
        return ret;
    } else {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_mesh_report_mesh_user_info::rx unsupport state}");

        return HI_FAIL;
    }
}
#endif /* #ifdef _PRE_WLAN_FEATURE_MESH */

/*****************************************************************************
 ��������  : �����鲥ip��ַ��ȡ�鲥mac��ַ
 �������  : puc_group_ipָ��ip��ַ��ָ��; uc_ip_len ip��ַ����
 �������  : puc_group_mac �洢�鲥mac��ַ��ָ��
 �޸���ʷ      :
  1.��    ��   : 2019��5��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_ip_conver_multi_mac(hi_u8 *puc_group_mac, const hi_u8 *puc_group_ip, hi_u8 ip_len)
{
    if (puc_group_ip == HI_NULL) {
        oam_error_log0(0, 0, "wal_ip_conver_multi_mac::puc_group_ip null!");
        return;
    }

    if (ip_len == OAL_IPV6_ADDR_SIZE) {
        /* ipv6�£��鲥mac���4�ֽ���IP��ַӳ����� */
        puc_group_mac[0] = 0x33;
        puc_group_mac[1] = 0x33;
        puc_group_ip    += 12; /* 12 ȡ���4���ֽ� */
        if (memcpy_s(puc_group_mac + 2, WLAN_MAC_ADDR_LEN - 2, puc_group_ip, 4) != EOK) { /* 2 ƫ���� 4 ���Ƴ��� */
            oam_error_log0(0, OAM_SF_ANY, "{wal_ip_conver_multi_mac::mem safe function err!}");
            return;
        }
    } else {
        /* ipv4�£��鲥mac���23bit��IP��ַӳ����� */
        puc_group_mac[0] = 0x01;
        puc_group_mac[1] = 0x0;
        puc_group_mac[2] = 0x5e; /* 2 mac��3λ */
        puc_group_ip    += 1;
        if (memcpy_s(puc_group_mac + 3, WLAN_MAC_ADDR_LEN - 3, puc_group_ip, 3) != EOK) { /* 3 ƫ���� ���Ƴ��� */
            oam_error_log0(0, OAM_SF_ANY, "{wal_ip_conver_multi_mac::mem safe function err!}");
            return;
        }
        puc_group_mac[3] &= 0x7f; /* 3 mac��4λ */
    }

    return;
}

hi_u32 wal_netdev_open_send_event(oal_net_device_stru *netdev)
{
    wal_msg_write_stru  write_msg;
    wal_msg_stru       *rsp_msg = HI_NULL;
    hi_u32              ret;

    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_START_VAP, sizeof(mac_cfg_start_vap_param_stru));
    ((mac_cfg_start_vap_param_stru *)write_msg.auc_value)->net_dev = netdev;

#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8 p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(netdev->ieee80211_ptr->iftype);
    if (p2p_mode == WLAN_P2P_BUTT) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_netdev_open::wal_wireless_iftype_to_mac_p2p_mode return BUFF}");
        wal_wake_unlock();
        return HI_FAIL;
    }
    ((mac_cfg_start_vap_param_stru *)write_msg.auc_value)->p2p_mode = p2p_mode;
#endif

    ((mac_cfg_start_vap_param_stru *)write_msg.auc_value)->mgmt_rate_init_flag = HI_TRUE;

    /* ������Ϣ */
    ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_start_vap_param_stru), (hi_u8 *)&write_msg, HI_TRUE, &rsp_msg);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_netdev_open::wal_alloc_cfg_event return err code %u!}", ret);
        wal_wake_unlock();
        return ret;
    }

    /* ��������Ϣ */
    ret = wal_check_and_release_msg_resp(rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_netdev_open::hmac start vap fail,err code[%u]!}", ret);
        wal_wake_unlock();
        return ret;
    }

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ������ʱ�ϱ�ȥ����״̬��LWIP�ĳ�ʱ������
*****************************************************************************/
hi_u32 wal_delay_report_timeout_fn(hi_void *arg)
{
    oal_net_device_stru *netdev = (oal_net_device_stru *)arg;
    /* �ϱ�LWIPʱ��ɾ����ʱ�� �ڲ��ж϶�ʱ���Ƿ���ע�� */
    g_delay_report.enable = HI_FALSE;   /* �ϱ�һ�κ���δ���¹����ɹ�ǰ�˺��ÿ��ȥ��������Ҫ�ϱ� */
    frw_timer_immediate_destroy_timer(&(g_delay_report.delay_timer));
    if (netdev == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_delay_report_timeout_fn::null param.");
        return HI_FAIL;
    }
    if (netdev->lwip_netif == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_delay_report_timeout_fn::lwip netif null param.");
        return HI_FAIL;
    }
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    /* �ϱ�LWIP */
    wal_report_sta_disassoc_to_lwip(netdev);
#endif
    /* �ϱ�wpa,�Ա�WPA�ϱ��û� */
    return cfg80211_timeout_disconnected(netdev);
}

/*****************************************************************************
 ��������  : ������ʱ�ϱ�����״̬����ز���
*****************************************************************************/
hi_void wal_set_delay_report_config(hi_u8 enable, hi_u16 timeout)
{
    g_delay_report.enable = enable & BIT0;
    g_delay_report.delay_timer.timeout = (hi_u32)timeout * 1000;    /* 1000:�ϲ㴫��s,ת��Ϊms */
    if (g_delay_report.enable == HI_FALSE) {
        /* �����ʱ��ִ�����������ϱ� */
        if (g_delay_report.delay_timer.is_enabled == HI_TRUE) {
            frw_timer_stop_timer(&(g_delay_report.delay_timer));
            wal_delay_report_timeout_fn(g_delay_report.delay_timer.timeout_arg);
        }
    }
    /* WPAˢ��״̬ʱɾ����ʱ�� */
    frw_timer_immediate_destroy_timer(&(g_delay_report.delay_timer));
}

/*****************************************************************************
 ��������  : �����Ƿ�ΪWPA�Զ�������־
*****************************************************************************/
hi_void wal_set_auto_conn_status(hi_u8 auto_reconn)
{
    g_delay_report.reconn = auto_reconn;
}
#endif

/*****************************************************************************
 ��������  : �����ϱ�sta����/ȥ����AP
 �������  : frw_event_mem_stru *event_mem
 �� �� ֵ  :hi_u32
 �޸���ʷ      :
  1.��    ��   : 2019��7��9��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
/* g_ast_wal_host_ctx_table�����Ա����Ҫ�޸Ľṹ��frw_event_sub_table_item_stru������Ҫ�޸�
   g_ast_dmac_host_crx_table����ĳ�Ա������dmac_cfg_vap_init_event�Ա����������޸ģ�lint_t e818�澯���� */
hi_u32 wal_report_sta_assoc_info(frw_event_mem_stru *event_mem)
{
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    oal_event_ap_conn_stru ap_conn_info;
#endif

    if (oal_unlikely(event_mem == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::event_mem is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    frw_event_stru                  *event          = (frw_event_stru *)event_mem->puc_data;
    hmac_sta_report_assoc_info_stru *sta_asoc_param = (hmac_sta_report_assoc_info_stru *)event->auc_event_data;
    oal_net_device_stru             *netdev         = hmac_vap_get_net_device(event->event_hdr.vap_id);

    if (netdev == HI_NULL) {
        oam_error_log0(event->event_hdr.vap_id, OAM_SF_ANY, "{wal_report_sta_assoc_info::net device null}");
        return HI_ERR_CODE_PTR_NULL;
    }
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
    /* WPA�Զ�������־���޵��ι���,����״̬��������,�ȱ������� */
    hi_u8 reconn_status = g_delay_report.reconn;
    g_delay_report.reconn = HI_FALSE;
#endif
    if (sta_asoc_param->is_assoc == HI_TRUE) {
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
        /* WPA�Զ�����,���ϱ������¼���LWIP */
        if ((reconn_status != HI_FALSE) && (g_delay_report.enable != HI_FALSE)) {
            return HI_SUCCESS;
        }
        if (memcpy_s(ap_conn_info.addr.addr, WLAN_MAC_ADDR_LEN,
            sta_asoc_param->auc_mac_addr, WLAN_MAC_ADDR_LEN) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::mem safe function err!}");
            return HI_FAIL;
        }
        ap_conn_info.addr.addrlen = WLAN_MAC_ADDR_LEN;
        ap_conn_info.rssi = -(sta_asoc_param->rssi);
        ap_conn_info.is_mesh_ap = sta_asoc_param->conn_to_mesh;

        if (netdev->lwip_netif->linklayer_event != HI_NULL) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::LL_EVENT_AP_CONN}");
            netdev->lwip_netif->linklayer_event(netdev->lwip_netif, LL_EVENT_AP_CONN, (hi_u8 *)&ap_conn_info);
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::linklayer_event callback isn't registed}");
        }

        (hi_void)netifapi_netif_set_link_up(netdev->lwip_netif);
#ifdef _PRE_WLAN_FEATURE_LWIP_IPV6_AUTOCONFIG
        (hi_void)netifapi_set_ipv6_forwarding(netdev->lwip_netif, HI_FALSE);
        (hi_void)netifapi_set_ra_enable(netdev->lwip_netif, HI_FALSE);
        (hi_void)netifapi_set_ip6_autoconfig_enabled(netdev->lwip_netif);
        (hi_void)netifapi_set_accept_ra(netdev->lwip_netif, HI_TRUE);
#endif
        (hi_void)netifapi_netif_add_ip6_linklocal_address(netdev->lwip_netif, HI_TRUE);
#endif
        oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::report sta conn succ to lwip!}");
        oam_warning_log4(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::rssi=%x,is_mesh_ap=%d,mac addr=X:X:X:X:%x:%x}",
            (hi_s32)(-(sta_asoc_param->rssi)), sta_asoc_param->conn_to_mesh,
            sta_asoc_param->auc_mac_addr[4], sta_asoc_param->auc_mac_addr[5]); /* 4 5 ��ַλ�� */
    } else {
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        /* �Ƿ�����WPA����,���ú�������ʱ������ʱ�ϱ�LWIP */
        if (g_delay_report.enable == HI_FALSE) {
#ifdef _PRE_WLAN_FEATURE_MESH_LWIP_RIPPLE
            wal_report_sta_disassoc_to_lwip(netdev);
#endif
            return HI_SUCCESS;
        }

        /* ��ʱ�ϱ��Ҷ�ʱ��δ��Ч��������ʱ�� */
        if (g_delay_report.delay_timer.is_enabled == HI_FALSE) {
            if (g_delay_report.delay_timer.timeout != 0) {
                frw_timer_create_timer(&(g_delay_report.delay_timer), wal_delay_report_timeout_fn,
                    g_delay_report.delay_timer.timeout, (hi_void *)netdev, HI_FALSE);
            } else {
                oam_warning_log0(0, OAM_SF_ANY, "{wal_report_sta_assoc_info::relay report disconnect timeout is 0!}");
            }
        }
#endif
    }
    return HI_SUCCESS;
}

hi_u32 wal_init_netdev_setmode(oal_net_device_stru *netdev, nl80211_iftype_uint8 type, wal_phy_mode mode, hi_u16 bw)
{
    hi_char              ac_mode_str[WAL_PROTOCOL_MAX_LEN] = {0};

    /* ��ȫ��̹���6.6���⣨5��Դ�ڴ�ȫ���Ǿ�̬�ַ���������Ŀ���ڴ������㹻�Ĵ洢�ռ䣩 */
    strcpy_s(ac_mode_str, WAL_PROTOCOL_MAX_LEN, "11bgn"); /* 40 Ԥ��Э��ģʽ�ַ����ռ� */
    if (mode == WAL_PHY_MODE_11G) {
        /* ��ȫ��̹���6.6���⣨5��Դ�ڴ�ȫ���Ǿ�̬�ַ���������Ŀ���ڴ������㹻�Ĵ洢�ռ䣩 */
        strcpy_s(ac_mode_str, WAL_PROTOCOL_MAX_LEN, "11bg"); /* 40 Ԥ��Э��ģʽ�ַ����ռ� */
    } else if (mode == WAL_PHY_MODE_11B) {
        /* ��ȫ��̹���6.6���⣨5��Դ�ڴ�ȫ���Ǿ�̬�ַ���������Ŀ���ڴ������㹻�Ĵ洢�ռ䣩 */
        strcpy_s(ac_mode_str, WAL_PROTOCOL_MAX_LEN, "11b"); /* 40 Ԥ��Э��ģʽ�ַ����ռ� */
    }

    if (wal_ioctl_set_mode(netdev, (hi_char *)ac_mode_str) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_init_netdev_setmode::failed to set mode}");
        return HI_FAIL;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (type == NL80211_IFTYPE_STATION) {
        if (wal_wifi_set_bw(netdev, bw) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_init_netdev_setmode::failed to set bw}");
            return HI_FAIL;
        }
    }
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_netdev_open
 ��������  : ����VAP
 �������  : pst_net_dev: net_device
 �������  : ��
 �� �� ֵ  : ������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��12��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_netdev_open_wrap(oal_net_device_stru *netdev)
{
    wal_msg_query_stru  query_msg;
    wal_msg_stru       *rsp_msg = HI_NULL;
    hi_u32              ret;

    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_netdev_open::pst_net_dev is null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }
    oam_warning_log1(0, OAM_SF_ANY, "{wal_netdev_open::iftype:%d.!}", netdev->ieee80211_ptr->iftype);
    wal_wake_lock();

    if ((netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        || (netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_MESH_POINT)
#endif
    ) {
#if (_PRE_OS_VERSION == _PRE_OS_VERSION_LINUX)
        if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
            oal_netdevice_flags(netdev) |= OAL_IFF_RUNNING;
        }
        oal_net_tx_wake_all_queues(); /* �������Ͷ��� */
        wal_wake_unlock();
        return HI_SUCCESS;
#endif
        query_msg.wid = WLAN_CFGID_SSID;

        /* ������Ϣ */
        ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_QUERY, WAL_MSG_WID_LENGTH, (hi_u8*)&query_msg, HI_TRUE, &rsp_msg);
        if ((ret != HI_SUCCESS) || (rsp_msg == HI_NULL)) {
            oam_warning_log1(0, OAM_SF_ANY, "{_wal_netdev_open::wal_alloc_cfg_event return err code %d!}", ret);
            wal_wake_unlock();
            return ret;
        }

        /* ��������Ϣ */
        wal_msg_rsp_stru        *query_rsp_msg = (wal_msg_rsp_stru *)(rsp_msg->auc_msg_data);
        mac_cfg_ssid_param_stru *ssid          = (mac_cfg_ssid_param_stru *)(query_rsp_msg->auc_value);
        hi_u8                    ssid_len      = ssid->ssid_len;

        oal_free(rsp_msg);

        if (ssid_len == 0) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_netdev_open::ssid not set,no need to start vap.!}");
            oal_net_tx_wake_all_queues(); /* �������Ͷ��� */
            wal_wake_unlock();
            return HI_SUCCESS;
        }
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    ret = wal_netdev_open_send_event(netdev);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
        oal_netdevice_flags(netdev) |= OAL_IFF_RUNNING;
    }

    oal_net_tx_wake_all_queues(); /* �������Ͷ��� */
    wal_wake_unlock();

    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32  wal_netdev_open(oal_net_device_stru *netdev)
{
    return wal_netdev_open_wrap(netdev);
}
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_u32 wal_netdev_setaddr(oal_net_device_stru *netdev)
{
    hi_u8 ac_addr[ETHER_ADDR_LEN] = {0};

    if (wal_get_dev_addr(ac_addr, ETHER_ADDR_LEN, netdev->ieee80211_ptr->iftype) != HI_SUCCESS) {
        oam_warning_log0(0, 0, "{wal_netdev_setaddr::wal_get_dev_addr failed!}");
        return HI_FAIL;
    }
    if (memcpy_s(netdev->dev_addr, ETHER_ADDR_LEN, ac_addr, ETHER_ADDR_LEN) != EOK) {
        oam_error_log0(0, 0, "{wal_netdev_setaddr::mem safe function err!}");
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

hi_u32 wal_netdev_vap_destroy(oal_net_device_stru *netdev)
{
    mac_vap_stru *mac_vap = oal_net_dev_priv(netdev);
    if (mac_vap == HI_NULL) {
        oam_error_log0(0, 0, "{wal_netdev_vap_destroy::can't get mac vap from netdevice priv data!}\r\n");
        return HI_FAIL;
    }
    hmac_vap_stru *hmac_vap = hmac_vap_get_vap_stru(mac_vap->vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(0, 0, "{wal_netdev_vap_destroy::hmac_vap null.}");
        return HI_FAIL;
    }
    hi_u32 return_code  = hmac_vap_destroy(hmac_vap);
    if (return_code != HI_SUCCESS) {
        oam_warning_log1(0, 0, "{wal_netdev_vap_destroy::hmac_vap_destroy failed[%d].}", return_code);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}

#ifdef _PRE_LINUX_BUILTIN
hi_u8 wal_get_fw_install(hi_void)
{
    return g_fw_install;
}

hi_s32 wal_proc_installfw(hi_void)
{
    hi_u32 ret;
    mac_device_stru     *mac_dev = mac_res_get_dev();
    hi_u16 protocol = wal_get_protocol_type();
    hi_u16 bw = wal_get_bw_type();
    hi_u32   netdev_index;
    oal_net_device_stru *netdev = HI_NULL;

    if (g_fw_install != 0) {
        oam_error_log0(0, 0, "{wal_proc_installfw::fw is already install.}");
        return HI_FAIL;
    }
    if (mac_dev->vap_num == 0) {
        ret = wal_customize_init();
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, 0, "wal_proc_installfw: wal_customize_init return error code: %d", ret);
            goto wal_customize_init_fail;
        }
        ret = hi_wifi_host_download_fw();
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, 0, "wal_proc_installfw: hi_wifi_host_download_fw return error code: %d", ret);
            goto wal_customize_init_fail;
        }
#if (_PRE_MULTI_CORE_MODE == _PRE_MULTI_CORE_MODE_OFFLOAD_DMAC)
        hmac_vap_stru   *hmac_vap = hmac_vap_get_vap_stru(WLAN_CFG_VAP_ID);
        if (hmac_vap == HI_NULL) {
            oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{wal_proc_installfw::pst_vap null.}");
            goto hmac_cfg_vap_fail;
        }
        ret = hmac_set_rx_filter_value(hmac_vap->base_vap);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(0, 0, "{wal_proc_installfw::hmac_set_rx_filter_value fail[%d].", ret);
            goto hmac_cfg_vap_fail;
        }
        ret = hmac_cfg_vap_send_event(mac_dev);
        if (oal_unlikely(ret != HI_SUCCESS)) {
            oam_warning_log1(0, 0, "{wal_proc_installfw::hmac_cfg_vap_send_event fail[%d].", ret);
            goto hmac_cfg_vap_fail;
        }
#endif

#ifdef _PRE_WLAN_FEATURE_WOW
        hmac_wow_init();
#endif
    }
    wal_init_dev_addr();
    if (mac_dev->vap_num == 0) {
        /* ����wifi_cfg������������ͬ����wal_customize */
        ret = firmware_sync_cfg_paras_to_wal_customize();
        if (ret != HI_SUCCESS) {
            oam_error_log1(0, 0, "wal_proc_installfw: sync cfg paras to customize return error code: %d", ret);
            goto hmac_cfg_vap_fail;
        }
        ret = wal_customize_set_config();
        if (ret != HI_SUCCESS) {
            oam_warning_log1(0, 0, "{wal_proc_installfw::customize init failed [%d]!}", ret);
            goto hmac_cfg_vap_fail;
        }
    }

    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev = oal_get_past_net_device_by_index(netdev_index);
        if (netdev != HI_NULL) {
            if (strncmp(netdev->name, WLAN_CFG_VAP_NAME, strlen(WLAN_CFG_VAP_NAME)) == 0) {
                continue;
            }
            if (wal_netdev_setaddr(netdev) != HI_SUCCESS) {
                goto hmac_cfg_vap_fail;
            }
            if (wal_init_wlan_vap(netdev) != HI_SUCCESS) {
                goto hmac_cfg_vap_fail;
            }
            if (netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_AP) {
                protocol = WAL_PHY_MODE_11N;
            }
            ret = wal_init_netdev_setmode(netdev, netdev->ieee80211_ptr->iftype, protocol, bw);
            if (ret != HI_SUCCESS) {
                oam_warning_log1(0, 0, "{wal_proc_installfw::wal_init_netdev_setmode return err code %d!}", ret);
                goto wal_netdev_open_fail;
            }
        }
    }

    printk("install firmware finish\r\n");
    g_fw_install = 1;
    return HI_SUCCESS;
wal_netdev_open_fail:
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev = oal_get_past_net_device_by_index(netdev_index);
        if (netdev != HI_NULL) {
            if (strncmp(netdev->name, WLAN_CFG_VAP_NAME, strlen(WLAN_CFG_VAP_NAME)) == 0) {
                continue;
            }
            if (wal_deinit_wlan_vap(netdev) != HI_SUCCESS) {
                oam_error_log0(0, 0, "{wal_netdev_open::wal_deinit_wlan_vap fail.}");
            }
        }
    }
hmac_cfg_vap_fail:
    if (mac_dev->vap_num == 0) {
        plat_firmware_clear();
        hcc_hmac_exit();
    }
wal_customize_init_fail:
    if (mac_dev->vap_num == 0) {
        wal_customize_exit();
    }
    printk("install firmware fail\r\n");
    return HI_FAIL;
}
#endif

hi_s32  wal_netdev_open(oal_net_device_stru *netdev)
{
    if (wal_netdev_open_wrap(netdev) == HI_SUCCESS) {
        printk("OK\r\n");
        return HI_SUCCESS;
    } else {
        printk("ERROR\r\n");
        return HI_FAIL;
    }
}
#endif

hi_u32 wal_netdev_stop_del_vap(const oal_net_device_stru *netdev)
{
    /* wlan0/p2p0 downʱ ɾ��VAP */
    if (netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_AP || netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_STATION ||
        netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_P2P_DEVICE
#ifdef _PRE_WLAN_FEATURE_MESH
        || netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_MESH_POINT
#endif
        ) {
#ifdef _PRE_WLAN_FEATURE_P2P
        /* ����ɾ��p2pС�� */
        if (oal_net_dev_priv(netdev) == HI_NULL) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_netdev_stop::pst_mac_vap is null, netdev released.}");
            wal_wake_unlock();
            return HI_SUCCESS;
        }
        mac_device_stru *mac_dev = mac_res_get_dev(); /* ����ɾ��p2pС�� */
        if (mac_dev != HI_NULL) {
            wal_del_p2p_group(mac_dev);
        }
#endif
        wal_wake_unlock();
        return HI_SUCCESS;
    }

    return HI_CONTINUE;
}

/*****************************************************************************
 �� �� ��  : wal_netdev_stop
 ��������  : ͣ��vap
 �������  : pst_net_dev: net_device
 �������  : ��
 �� �� ֵ  : ������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��5��13��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_netdev_stop_wrap(oal_net_device_stru *netdev)
{
    wal_msg_write_stru          write_msg;
    wal_msg_stru               *rsp_msg = HI_NULL;

    if (oal_unlikely((netdev == HI_NULL) || (netdev->ieee80211_ptr == NULL))) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_netdev_stop::pst_net_dev/ieee80211_ptr is null ptr!}");
        return HI_ERR_CODE_PTR_NULL;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* stop vapʱ��ɾ����ʱ�ϱ���ʱ�� */
    if (netdev->ieee80211_ptr->iftype == NL80211_IFTYPE_STATION) {
        frw_timer_immediate_destroy_timer(&(g_delay_report.delay_timer));
        g_delay_report.enable = HI_FALSE;
    }
#endif
    /* stop the netdev's queues */
    oal_net_tx_stop_all_queues(); /* ֹͣ���Ͷ��� */

    oam_warning_log1(0, OAM_SF_ANY, "{wal_netdev_stop::iftype:%d.}", netdev->ieee80211_ptr->iftype);

    wal_wake_lock();
    wal_force_scan_complete(netdev);

    /* ���netdev����running״̬����ֱ�ӷ��سɹ� */
    if ((oal_netdevice_flags(netdev) & OAL_IFF_RUNNING) == 0) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_netdev_stop::vap is already down!}");
        wal_wake_unlock();
        return HI_SUCCESS;
    }

    /***************************************************************************
                           ���¼���wal�㴦��
    ***************************************************************************/
    /* ��дWID��Ϣ */
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_DOWN_VAP, sizeof(mac_cfg_down_vap_param_stru));
    ((mac_cfg_down_vap_param_stru *)write_msg.auc_value)->net_dev = netdev;
#ifdef _PRE_WLAN_FEATURE_P2P
    wlan_p2p_mode_enum_uint8 p2p_mode = wal_wireless_iftype_to_mac_p2p_mode(netdev->ieee80211_ptr.iftype);
    if (p2p_mode == WLAN_P2P_BUTT) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_netdev_stop::wal_wireless_iftype_to_mac_p2p_mode return BUFF}");
        wal_wake_unlock();
        return HI_FAIL;
    }
    ((mac_cfg_start_vap_param_stru *)write_msg.auc_value)->p2p_mode = p2p_mode;
#endif

    /* ������Ϣ */
    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_down_vap_param_stru), (hi_u8 *)&write_msg, HI_TRUE, &rsp_msg);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_netdev_stop::wal_alloc_cfg_event return err code %u!}", ret);
        wal_wake_unlock();
        return ret;
    }

    /* BEGIN: DTS2015052503410 1102 P2P������ΪGOʱ����ӡ����.�޸�wal_net_dev_stop Ϊ��Ҫ�ȴ�hmac ��Ӧ */
    /* ��������Ϣ */
    ret = wal_check_and_release_msg_resp(rsp_msg);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_netdev_stop::hmac stop vap fail!err code [%d]}", ret);
        wal_wake_unlock();
        return ret;
    }

    if (wal_netdev_stop_del_vap(netdev) == HI_SUCCESS) {
        wal_wake_unlock();
        return HI_SUCCESS;
    }

    wal_wake_unlock();
    return HI_SUCCESS;
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32  wal_netdev_stop(oal_net_device_stru *netdev)
{
    return wal_netdev_stop_wrap(netdev);
}
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32  wal_netdev_stop(oal_net_device_stru *netdev)
{
    if (wal_netdev_stop_wrap(netdev) == HI_SUCCESS) {
        printk("OK\r\n");
        return HI_SUCCESS;
    } else {
        printk("ERROR\r\n");
        return HI_FAIL;
    }
}
#endif

/*****************************************************************************
 �� �� ��  : wal_netdev_get_stats
 ��������  : ��ȡͳ����Ϣ
*****************************************************************************/
static oal_net_device_stats_stru* wal_netdev_get_stats(oal_net_device_stru *netdev)
{
    oal_net_device_stats_stru  *stats = HI_NULL;

    if (netdev == HI_NULL) {
        return HI_NULL;
    }

    stats = (oal_net_device_stats_stru *)&(netdev->stats);
    stats->rx_packets = 10; /* rx_packets 10 */
    stats->rx_bytes   = 10; /* rx_bytes 10 */
    stats->tx_packets = 10; /* tx_packets 10 */
    stats->tx_bytes   = 10; /* tx_bytes 10 */

    return stats;
}

/*****************************************************************************
 ��������  : net device��ioctl����
 �������  : net deviceָ��
 �� �� ֵ  : ͳ�ƽ��ָ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_u32 wal_net_device_ioctl(oal_net_device_stru *netdev, oal_ifreq_stru *ifr, hi_s32 cmd)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32 wal_net_device_ioctl(oal_net_device_stru *netdev, oal_ifreq_stru *ifr, hi_s32 cmd)
#endif
{
    hi_u32 ret = HI_SUCCESS;

    if ((netdev == HI_NULL) || (ifr == HI_NULL) || (ifr->ifr_data == HI_NULL)) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_net_device_ioctl::pst_dev %p, pst_ifr %p!}",
                       (uintptr_t)netdev, (uintptr_t)ifr);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* 1102 wpa_supplicant ͨ��ioctl �·����� */
    if (cmd == WAL_SIOCDEVPRIVATE + 1) {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        ret = wal_android_priv_cmd(netdev, ifr, cmd);
#endif
        return ret;
    } else {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_net_device_ioctl::unrecognised cmd, %d!}", cmd);
        return HI_SUCCESS;
    }
}

/*****************************************************************************
 �� �� ��  : oal_net_device_change_mtu
 ��������  : net device��change_mtu����
 �������  : net deviceָ��
 �������  : ��
 �� �� ֵ  : ͳ�ƽ��ָ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��12��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
static inline hi_u32 oal_net_device_change_mtu(oal_net_device_stru *netdev, hi_s32 mtu)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static inline hi_s32 oal_net_device_change_mtu(oal_net_device_stru *netdev, hi_s32 mtu)
#endif
{
    /* ��Ҫ�Ż� */
    if (netdev == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }
    netdev->mtu = (hi_u32)mtu;
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_netdev_set_mac_addr
 ��������  : ����mac��ַ
 �������  : pst_dev: �����豸
             p_addr : ��ַ
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��12��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
static hi_u32  wal_netdev_set_mac_addr(oal_net_device_stru *netdev, oal_sockaddr_stru *addr)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static hi_s32  wal_netdev_set_mac_addr(oal_net_device_stru *netdev, void *addr)
#endif
{
    oal_sockaddr_stru            *mac_addr = HI_NULL;

    if (oal_unlikely((netdev == HI_NULL) || (addr == HI_NULL))) {
        oam_error_log2(0, OAM_SF_ANY, "{wal_netdev_set_mac_addr::pst_net_dev or p_addr null ptr error %p, %p!}",
                       (uintptr_t)netdev, (uintptr_t)addr);

        return HI_ERR_CODE_PTR_NULL;
    }

    if (oal_netif_running(netdev)) {  /* ҵ����Ҫ,lin_t e506/e774�澯���� */
        oam_warning_log0(0, OAM_SF_ANY, "{wal_netdev_set_mac_addr::cannot set address; device running!}");

        return HI_FAIL;
    }

    mac_addr = (oal_sockaddr_stru *)addr;

    if (ether_is_multicast(mac_addr->sa_data)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_netdev_set_mac_addr::can not set group/broadcast addr!}");
        return HI_FAIL;
    }
    wal_wake_lock();
    if (memcpy_s((netdev->dev_addr), WLAN_MAC_ADDR_LEN, (mac_addr->sa_data), WLAN_MAC_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_netdev_set_mac_addr::mem safe function err!}");
        return HI_FAIL;
    }

    /* 1131���return���޷�ͨ����������mac��ַ���Ĵ��� */
    /* when sta and ap are coexist,close the line "return HI_SUCCESS" DTS2016050607426 */
    /* set mac address,need open the following line,DTS2016102403276 */
    wal_wake_unlock();
    return HI_SUCCESS;
}

/*****************************************************************************
  net_device�Ϲҽӵ�net_device_ops����
*****************************************************************************/
oal_net_device_ops_stru g_wal_net_dev_ops =
{
    .ndo_get_stats          = wal_netdev_get_stats,
    .ndo_open               = wal_netdev_open,
    .ndo_stop               = wal_netdev_stop,
    .ndo_start_xmit         = hmac_bridge_vap_xmit,
    .ndo_do_ioctl           = wal_net_device_ioctl,
    .ndo_change_mtu         = oal_net_device_change_mtu,
    .ndo_init               = oal_net_device_init,

#if (defined(_PRE_WLAN_FEATURE_FLOWCTL) || defined(_PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL))
    .ndo_select_queue       = wal_netdev_select_queue,
#endif

    .ndo_set_mac_address    = wal_netdev_set_mac_addr,
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    .ndo_netif_notify       = HI_NULL,
#endif
};

/*****************************************************************************
 ��������  : ��ȡg_wal_net_dev_ops�ṹ
*****************************************************************************/
oal_net_device_ops_stru* wal_get_net_dev_ops(hi_void)
{
    return &g_wal_net_dev_ops;
}

hi_s32 wal_init_netdev(nl80211_iftype_uint8 type, oal_net_device_stru *netdev, oal_wireless_dev *wdev)
{
    hi_u8 ac_addr[ETHER_ADDR_LEN] = {0};

    /* ��netdevice���и�ֵ */
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    netdev->wireless_handlers = wal_get_g_iw_handler_def();
#endif
    netdev->netdev_ops        = wal_get_net_dev_ops();

    if (wal_get_dev_addr(ac_addr, ETHER_ADDR_LEN, type) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_init_wlan_netdev::wal_get_dev_addr failed!}");
        oal_net_free_netdev(netdev);
        return HI_FAIL;
    }

    if (memcpy_s(netdev->dev_addr, ETHER_ADDR_LEN, ac_addr, ETHER_ADDR_LEN) != EOK) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_init_wlan_netdev::mem safe function err!}");
        oal_net_free_netdev(netdev);
        return HI_FAIL;
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE) && (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    netdev->ethtool_ops                   = &g_wal_ethtool_ops;
#endif

#if (LINUX_VERSION_CODE >= kernel_version(4, 11, 9))
    /* destructor change to priv_destructor */
    netdev->priv_destructor               = oal_net_free_netdev;
    netdev->needs_free_netdev             = false;
#else
    oal_netdevice_destructor(netdev)      = oal_net_free_netdev;
#endif
    oal_netdevice_ifalias(netdev)         = HI_NULL;
    oal_netdevice_watchdog_timeo(netdev)  = 5; /* �̶�����Ϊ 5 */
    oal_netdevice_wdev(netdev)            = wdev;
    oal_netdevice_qdisc(netdev, HI_NULL);

    wdev->netdev = netdev;
    wdev->iftype = type;
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    wdev->wiphy = mac_res_get_dev()->wiphy;
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    wdev->wiphy = oal_wiphy_get();
#endif

    oal_netdevice_flags(netdev) &= ~OAL_IFF_RUNNING;   /* ��net device��flag��Ϊdown */

    return HI_SUCCESS;
}

hi_s32 wal_init_netif(nl80211_iftype_uint8 type, oal_net_device_stru *netdev)
{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* ע��net_device */
    hi_u32 ret = oal_net_register_netdev(netdev);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_init_netif::oal_net_register_netdev return error code %d}", ret);
        oal_net_free_netdev(netdev);
        return HI_FAIL;
    }

    struct netif *netif = netif_find((const hi_char *)netdev->name);
    if (netif == HI_NULL) {
        oal_net_unregister_netdev(netdev);
        oal_net_free_netdev(netdev);
        oam_error_log0(0, OAM_SF_ANY, "wal_init_netif:pst_netif is null");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����IPv6 linklocal address(SLAAC) */
    if ((type == NL80211_IFTYPE_AP) || (type == NL80211_IFTYPE_MESH_POINT)) {
#ifdef _PRE_WLAN_FEATURE_LWIP_IPV6_AUTOCONFIG
        (hi_void)netifapi_set_ip6_autoconfig_disabled(netdev->lwip_netif);
        (hi_void)netifapi_set_accept_ra(netif, HI_FALSE);
        (hi_void)netifapi_set_ipv6_forwarding(netif, HI_TRUE);
        (hi_void)netifapi_set_ra_enable(netif, HI_TRUE);
#endif
        (hi_void)netifapi_netif_add_ip6_linklocal_address(netif, HI_TRUE);
    }
    netifapi_netif_set_default(netif);
#endif
#ifndef _PRE_LINUX_BUILTIN
    if (wal_init_wlan_vap(netdev) != HI_SUCCESS) {
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        oal_net_unregister_netdev(netdev);
#endif
        oal_net_free_netdev(netdev);
        return HI_FAIL;
    }
#endif
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ʼ��wlan�豸
 �������  : [1]type �豸����
             [2]mode ģʽ
 �������  : [1]ifname �豸��
             [2]len �豸������
 �� �� ֵ  : ������
*****************************************************************************/
/* ����5.5��죬��2024����Ϊstrncpy_s�����ĵ�һ���������� */
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_s32 wal_init_drv_wlan_netdev(nl80211_iftype_uint8 type, wal_phy_mode mode, hi_char *ifname, hi_u32 *len)
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_u32 wal_init_drv_wlan_netdev(nl80211_iftype_uint8 type, wal_phy_mode mode, hi_u16 bw)
#endif
{
    oal_net_device_stru *netdev          = HI_NULL;
    hi_u32               dev_name_len    = OAL_IF_NAME_SIZE;
#ifndef _PRE_LINUX_BUILTIN
    hi_char              ac_mode_str[WAL_PROTOCOL_MAX_LEN] = {0};
#endif
    hi_char              dev_name[OAL_IF_NAME_SIZE];

    /* У���Ƿ������netdev,���ԵĻ�����netdev���� */
    if (oal_net_check_and_get_devname(type, dev_name, &dev_name_len) != HI_SUCCESS) {
        oam_error_log1(0, 0, "wal_init_drv_netdev:: invalid type[%d]", type);
        return HI_FAIL;
    }

#if (defined(_PRE_WLAN_FEATURE_FLOWCTL) || defined(_PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL))
    netdev = oal_net_alloc_netdev_mqs(dev_name);
#else
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    netdev = oal_net_alloc_netdev(dev_name, OAL_IF_NAME_SIZE);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    netdev = oal_net_alloc_netdev(0, dev_name, oal_ether_setup);
#endif
#endif
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{oal_net_alloc_netdev return null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_wireless_dev *wdev = (oal_wireless_dev *)oal_memalloc(sizeof(oal_wireless_dev));
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_wireless_dev *wdev = (oal_wireless_dev *)oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, sizeof(oal_wireless_dev));
#endif
    if (oal_unlikely(wdev == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{alloc mem, pst_wdev is null ptr!}");
        oal_net_free_netdev(netdev);
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(wdev, sizeof(oal_wireless_dev), 0, sizeof(oal_wireless_dev));

    hi_s32 ret = wal_init_netdev(type, netdev, wdev);
    if (ret != HI_SUCCESS) {
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
        oal_free(wdev);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_mem_free(wdev);
#endif
        return ret;
    }

    ret = wal_init_netif(type, netdev);
    if (ret != HI_SUCCESS) {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
        oal_mem_free(wdev);
#endif
        return ret;
    }
#ifndef _PRE_LINUX_BUILTIN
    /* ��ȫ��̹���6.6���⣨5��Դ�ڴ�ȫ���Ǿ�̬�ַ���������Ŀ���ڴ������㹻�Ĵ洢�ռ䣩 */
    strcpy_s(ac_mode_str, WAL_PROTOCOL_MAX_LEN, "11bgn"); /* 40 Ԥ��Э��ģʽ�ַ����ռ� */
    if (mode == WAL_PHY_MODE_11G) {
        /* ��ȫ��̹���6.6���⣨5��Դ�ڴ�ȫ���Ǿ�̬�ַ���������Ŀ���ڴ������㹻�Ĵ洢�ռ䣩 */
        strcpy_s(ac_mode_str, WAL_PROTOCOL_MAX_LEN, "11bg"); /* 40 Ԥ��Э��ģʽ�ַ����ռ� */
    } else if (mode == WAL_PHY_MODE_11B) {
        /* ��ȫ��̹���6.6���⣨5��Դ�ڴ�ȫ���Ǿ�̬�ַ���������Ŀ���ڴ������㹻�Ĵ洢�ռ䣩 */
        strcpy_s(ac_mode_str, WAL_PROTOCOL_MAX_LEN, "11b"); /* 40 Ԥ��Э��ģʽ�ַ����ռ� */
    }

    if (wal_ioctl_set_mode(netdev, (hi_char *)ac_mode_str) != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_init_drv_wlan_netdev::failed to set mode}");
        goto fail;
    }

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    if (type == NL80211_IFTYPE_STATION) {
        if (wal_wifi_set_bw(netdev, bw) != HI_SUCCESS) {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_init_drv_wlan_netdev::failed to set bw}");
            goto fail;
        }
    }
#endif
#endif
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    strncpy_s(ifname, *len, netdev->name, strlen(netdev->name) + 1); /* ���������� */
    *len = strlen(netdev->name);
#endif

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    /* ע��net_device */
    if (oal_unlikely(oal_net_register_netdev(netdev) != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_init_wlan_netdev::oal_net_register_netdev return error code %d}", ret);
        goto fail;
    }
#endif

    return HI_SUCCESS;
fail:
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_mem_free(wdev);
#endif
    wal_deinit_wlan_vap(netdev);
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    oal_net_unregister_netdev(netdev);
#endif
    oal_net_free_netdev(netdev);
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : ȥ��ʼ��wlan�豸
 �������  : *ifname �豸��
 �� �� ֵ��������
*****************************************************************************/
hi_s32 wal_deinit_drv_wlan_netdev(const hi_char *ifname)
{
    oal_net_device_stru        *netdev = HI_NULL;
    hi_u32                      ret;

    if (ifname == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_deinit_wlan_netdev::ifname is null!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ����dev_name�ҵ�dev */
    netdev = oal_get_netdev_by_name(ifname);
    if (netdev == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_deinit_wlan_netdev::the net_device is not exist!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��֪ͨlwip��ע�� */
    oal_net_unregister_netdev(netdev);

    ret = wal_deinit_wlan_vap(netdev);
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_deinit_wlan_netdev::deinit vap failed!}");
        return HI_FAIL;
    }

    oal_net_free_netdev(netdev);

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ж�netdev�Ƿ���busy
*****************************************************************************/
hi_u8 wal_dev_is_running(hi_void)
{
    hi_u8 loop;
    oal_net_device_stru *netdev = HI_NULL;

    for (loop = 0; loop < WLAN_VAP_NUM_PER_BOARD; loop++) {
        netdev = oal_get_past_net_device_by_index(loop);
        if (netdev == HI_NULL) {
            continue;
        }

        if (oal_unlikely((OAL_IFF_RUNNING & oal_netdevice_flags(netdev)) != 0)) {
            return HI_TRUE;
        }
    }
    return HI_FALSE;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
