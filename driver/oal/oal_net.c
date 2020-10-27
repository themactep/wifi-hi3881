/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_net.h"
#include "mac_data.h"

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef _PRE_WLAN_FEATURE_OFFLOAD_FLOWCTL
#define WLAN_DATA_VIP_QUEUE (WLAN_HI_QUEUE)
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
oal_net_stru  g_init_net;
oal_sock_stru g_sock;
#endif
oal_wiphy_stru* g_wiphy = HI_NULL;

oal_net_device_stru *g_past_net_device[WLAN_VAP_NUM_PER_BOARD] = {HI_NULL};

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
struct dev_excp_globals g_dev_excp_handler_data;
#endif

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
oal_sock_stru* oal_netlink_kernel_create(hi_void)
{
    return &g_sock;
}

hi_void oal_netlink_kernel_release(hi_void)
{
    return;
}

/*
 * ��������  : ע��wiphy
 */
hi_void oal_wiphy_register(oal_wiphy_stru* wiphy)
{
    g_wiphy = wiphy;
}

#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */
hi_void oal_set_past_net_device_by_index(hi_u32 netdev_index, oal_net_device_stru *netdev)
{
    if (netdev_index >= WLAN_VAP_NUM_PER_BOARD) {
        return;
    }
    g_past_net_device[netdev_index] = netdev;
}

oal_wiphy_stru* oal_wiphy_get(hi_void)
{
    return g_wiphy;
}

oal_net_device_stru* oal_get_past_net_device_by_index(hi_u32 netdev_index)
{
    return g_past_net_device[netdev_index];
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : receive netlink date from app
*****************************************************************************/
hi_void oal_dev_netlink_rev(oal_netbuf_stru *netbuf)
{
    oal_netbuf_stru                *skb_info = HI_NULL;
    oal_nlmsghdr_stru              *nlh = HI_NULL;
    struct dev_netlink_msg_hdr_stru msg_hdr = {0};
    hi_u32                       len;

    if (netbuf == NULL) {
        oal_io_print0("WIFI DFR:para fail\n");
        return;
    }

    oal_io_print0("WIFI DFR:dev_kernel_netlink_recv.\n");

    if (memset_s(g_dev_excp_handler_data.data, OAL_EXCP_DATA_BUF_LEN, 0, OAL_EXCP_DATA_BUF_LEN) != EOK) {
        oal_io_print0("dev_netlink_rev::mem safe function err!}");
        return;
    }

    skb_info = oal_netbuf_get(netbuf);
    if (skb_info->len >= oal_nlmsg_space(0)) {
        nlh = oal_nlmsg_hdr(skb_info);
        /* ��ⱨ�ĳ�����ȷ�� */
        if (!oal_nlmsg_ok(nlh, skb_info->len)) {
            oal_io_print2("[ERROR]invaild netlink buff data packge data len = :%u,skb_buff data len = %u\n",
                          nlh->nlmsg_len, skb_info->len);
            kfree_skb(skb_info);
            return;
        }
        len = oal_nlmsg_payload(nlh, 0);
        if (len < OAL_EXCP_DATA_BUF_LEN && len >= sizeof(msg_hdr)) {
            if (memcpy_s(g_dev_excp_handler_data.data, len, oal_nlmsg_data(nlh), len) != EOK) {
                oal_io_print0("dev_netlink_rev::mem safe function err!}");
                kfree_skb(skb_info);
                return;
            }
        } else {
            oal_io_print2("[ERROR]invaild netlink buff len:%u,max len:%u\n", len, OAL_EXCP_DATA_BUF_LEN);
            kfree_skb(skb_info);
            return;
        }
        if (memcpy_s((hi_void *)&msg_hdr, sizeof(msg_hdr),
            g_dev_excp_handler_data.data, sizeof(msg_hdr)) != EOK) {
            oal_io_print0("dev_netlink_rev::mem safe function err!}");
            kfree_skb(skb_info);
            return;
        }
        if (0 == msg_hdr.cmd) {
            g_dev_excp_handler_data.usepid = nlh->nlmsg_pid;   /* pid of sending process */
            oal_io_print1("WIFI DFR:pid is [%d]\n", g_dev_excp_handler_data.usepid);
        }
    }
    kfree_skb(skb_info);
    return;
}

/*****************************************************************************
 ��������  : create netlink for device exception
*****************************************************************************/
hi_s32 oal_dev_netlink_create(hi_void)
{
    g_dev_excp_handler_data.nlsk = oal_netlink_kernel_create(oal_dev_netlink_rev);
    if (g_dev_excp_handler_data.nlsk == HI_NULL) {
        oal_io_print0("WIFI DFR:fail to create netlink socket \n");
        return HI_FAIL;
    }

    oal_io_print1("WIFI DFR:suceed to create netlink socket��%p \n", g_dev_excp_handler_data.nlsk);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : send netlink data
*****************************************************************************/
hi_s32 oal_dev_netlink_send (hi_u8 *data, hi_s32 data_len)
{
    oal_netbuf_stru        *netbuf = HI_NULL;
    oal_nlmsghdr_stru      *nlh = HI_NULL;
    hi_u32                  ret;
    hi_u32                  len;

    len = oal_nlmsg_space(data_len);
    netbuf = alloc_skb(len, GFP_KERNEL);
    if (netbuf == HI_NULL) {
        oal_io_print1("WIFI DFR:dev error: allocate failed, len[%d].\n", len);
        return HI_FAIL;
    }
    nlh = oal_nlmsg_put(netbuf, 0, 0, 0, data_len, 0);
    oal_io_print1("WIFI DFR: data[%p].\n", (uintptr_t)data);

    if (data != HI_NULL) {
        if (memcpy_s(oal_nlmsg_data(nlh), data_len, data, data_len) != EOK) {
            oal_io_print0("dev_netlink_send::mem safe function err!");
            kfree_skb(netbuf);
            return HI_FAIL;
        }
    }
    oal_netlink_cb(netbuf).portid = 0;                 /* from kernel */

    if (g_dev_excp_handler_data.nlsk == HI_NULL) {
        oal_io_print0("WIFI DFR: NULL Pointer_sock.\n");
        kfree_skb(netbuf);
        return HI_FAIL;
    }

    ret = oal_netlink_unicast(g_dev_excp_handler_data.nlsk, netbuf, g_dev_excp_handler_data.usepid, MSG_DONTWAIT);
    if (ret <= 0) {
        oal_io_print1("WIFI DFR:send dev error netlink msg, ret = %d \n", ret);
    }

    return ret;
}

/*****************************************************************************
 ��������  : init dev exception handler
*****************************************************************************/
hi_s32 oal_init_dev_excp_handler(hi_void)
{
    hi_s32   ret;

    oal_io_print0("DFR: into init_exception_enable_handler\n");

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s((hi_u8*)&g_dev_excp_handler_data, sizeof(g_dev_excp_handler_data), 0,
        sizeof(g_dev_excp_handler_data));

    g_dev_excp_handler_data.data = (hi_u8*)kzalloc(OAL_EXCP_DATA_BUF_LEN, GFP_KERNEL);
    if (g_dev_excp_handler_data.data == HI_NULL) {
        oal_io_print1("DFR: alloc dev_excp_handler_data.puc_data fail, len = %d.\n", OAL_EXCP_DATA_BUF_LEN);
        g_dev_excp_handler_data.data = HI_NULL;
        return HI_FAIL;
    }
    if (memset_s(g_dev_excp_handler_data.data, OAL_EXCP_DATA_BUF_LEN, 0, OAL_EXCP_DATA_BUF_LEN) != EOK) {
        oal_io_print0("oal_init_dev_excp_handler: memset_s fail.");
    }

    ret = oal_dev_netlink_create();
    if (ret < 0) {
        kfree(g_dev_excp_handler_data.data);
        oal_io_print0("init_dev_err_kernel init is ERR!\n");
        return HI_FAIL;
    }

    oal_io_print0("DFR: init_exception_enable_handler init ok.\n");

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : deinit dev exception handler
*****************************************************************************/
hi_void oal_deinit_dev_excp_handler(hi_void)
{
    if (g_dev_excp_handler_data.nlsk != HI_NULL) {
        oal_netlink_kernel_release();
        g_dev_excp_handler_data.usepid = 0;
    }

    if (g_dev_excp_handler_data.data != HI_NULL) {
        kfree(g_dev_excp_handler_data.data);
    }

    oal_io_print0("DFR: deinit ok.\n");

    return;
}
#endif

/*****************************************************************************
 ��������  : ���ŵ�ת����Ƶ��
 �������  : hi_s32 l_channel      :�ŵ���
             enum ieee80211_band band :Ƶ��
*****************************************************************************/
hi_s32 oal_ieee80211_channel_to_frequency(hi_s32 l_channel, wlan_channel_band_enum_uint8 band)
{
    /* see 802.11 17.3.8.3.2 and Annex J
        * there are overlapping channel numbers in 5GHz and 2GHz bands */
    if (l_channel <= 0) {
        return 0; /* not supported */
    }

    switch (band) {
        case IEEE80211_BAND_2GHZ: {
            if (l_channel == 14) { /* 14���ŵ��� */
                return 2484; /* 2484: ����ֵ */
            } else if (l_channel < 14) { /* 14���ŵ��� */
                return 2407 + l_channel * 5; /* 2407: ����ֵ 5: ����5 */
            }
            break;
        }

        case IEEE80211_BAND_5GHZ: {
            if (l_channel >= 182 && l_channel <= 196) {  /* 182,196���ŵ��� */
                return 4000 + l_channel * 5; /* 4000: ����ֵ 5: ����5 */
            } else {
                return 5000 + l_channel * 5; /* 5000: ����ֵ 5: ����5 */
            }
        }
        default:
            /* not supported other BAND */
            return 0;
    }

    /* not supported */
    return 0;
}

/*****************************************************************************
 ��������  : Ƶ��ת�ŵ�
*****************************************************************************/
hi_s32  oal_ieee80211_frequency_to_channel(hi_s32 l_center_freq)
{
    hi_s32 l_channel;

    /* see 802.11 17.3.8.3.2 and Annex J */
    if (l_center_freq == 2484) { /* 2484������Ƶ�� */
        l_channel = 14;                  /* 14: channel number */
    } else if (l_center_freq < 2484) {   /* 2484������Ƶ�� */
        l_channel = (l_center_freq - 2407) / 5;                  /* 2407������Ƶ��  5: ����5 */
    } else if (l_center_freq >= 4910 && l_center_freq <= 4980) { /* 4910,4980������Ƶ�� */
        l_channel = (l_center_freq - 4000) / 5;                  /* 4000������Ƶ��  5: ����5 */
    } else if (l_center_freq <= 45000) { /* DMG band lower limit */  /* 45000������Ƶ�� */
        l_channel = (l_center_freq - 5000) / 5;                  /* 5000������Ƶ��  5: ����5 */
    } else if (l_center_freq >= 58320 && l_center_freq <= 64800) { /* 58320,64800������Ƶ�� */
        l_channel = (l_center_freq - 56160) / 2160; /* 56160������Ƶ�� 2160: ����2160 */
    } else {
        l_channel = 0;
    }
    return l_channel;
}

/*****************************************************************************
 ��������  : ��ȡ�ŵ�
*****************************************************************************/
oal_ieee80211_channel_stru* oal_ieee80211_get_channel(const oal_wiphy_stru *wiphy, hi_s32 freq)
{
    int i;
    ieee80211_band_uint8 band;
    struct ieee80211_supported_band* sband = HI_NULL;

    for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
        sband = wiphy->bands[band];

        if (!sband) {
            continue;
        }

        for (i = 0; i < sband->n_channels; i++) {
            if (sband->channels[i].center_freq == freq)
            { return &sband->channels[i]; }
        }
    }

    return HI_NULL;
}

/*****************************************************************************
 ��������  : ��������Ѱ��netdevice
*****************************************************************************/
oal_net_device_stru* oal_get_netdev_by_name(const hi_char* pc_name)
{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_u32 netdev_index;
    oal_net_device_stru *netdev = HI_NULL;

    if (pc_name == HI_NULL) {
        return HI_NULL;
    }
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev = oal_get_past_net_device_by_index(netdev_index);
        if ((netdev != HI_NULL) &&
            (strcmp((const hi_char*)netdev->name, (const hi_char*)pc_name) == 0)) {
            return netdev;
        }
    }

    return HI_NULL;
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return dev_get_by_name(&init_net, pc_name);
#endif
}

/*****************************************************************************
 ��������  : ���������豸
 �������  : ul_sizeof_priv: ˽�нṹ�ռ䳤��
           : puc_name �豸����
           : p_set_up:��������ָ��
*****************************************************************************/
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
oal_net_device_stru* oal_net_alloc_netdev(const hi_char *puc_name, hi_u8 max_name_len)
{
    hi_u32               size;
    oal_net_device_stru *netdev = HI_NULL;

    hi_unref_param(max_name_len);
    if (puc_name == HI_NULL) {
        hi_diag_log_msg_i0(0, "oal_net_alloc_netdev::puc_name null.");
        return HI_NULL;
    }
    size = strlen((const hi_char*)puc_name) + 1;  /* ����'\0' */

    netdev = (oal_net_device_stru*)malloc(sizeof(oal_net_device_stru));
    if (netdev == HI_NULL) {
        return HI_NULL;
    }

    /* ��ȫ��̹���6.6����(3)�Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(netdev, sizeof(oal_net_device_stru), 0, sizeof(oal_net_device_stru));
    /* ��name���浽netdeivce */
    if (memcpy_s(netdev->name, OAL_IF_NAME_SIZE, puc_name, size) != EOK) {
        free(netdev);
        return HI_NULL;
    }

    return netdev;
}
#endif

/*****************************************************************************
 ��������  : ���������豸,�����������
 �������  : ul_sizeof_priv: ˽�нṹ�ռ䳤��
           : puc_name �豸����
           : p_set_up:��������ָ��
*****************************************************************************/
oal_net_device_stru* oal_net_alloc_netdev_mqs(const hi_char *puc_name)
{
    hi_u32           size;
    oal_net_device_stru* netdev;

    size = strlen((const hi_char*)puc_name) + 1;  /* ����'\0' */
    netdev = (oal_net_device_stru*)oal_memalloc(sizeof(oal_net_device_stru));
    if (netdev == HI_NULL) {
        return HI_NULL;
    }

    /* ��ȫ��̹���6.6����(3) �Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(netdev, sizeof(oal_net_device_stru), 0, sizeof(oal_net_device_stru));

    /* ��name���浽netdeivce */
    if (memcpy_s(netdev->name, OAL_IF_NAME_SIZE, puc_name, size) != EOK) {
        oal_free(netdev);
        return HI_NULL;
    }

    return netdev;
}

/*****************************************************************************
 ��������  : �ͷ������豸
 �������  : ul_sizeof_priv: ˽�нṹ�ռ䳤��
           : puc_name �豸����
           : p_set_up:��������ָ��
*****************************************************************************/
hi_void oal_net_free_netdev(oal_net_device_stru *netdev)
{
    if (netdev == HI_NULL) {
        return;
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    if (netdev->priv != HI_NULL) {
        free((hi_void *)netdev->priv);
        netdev->priv = HI_NULL;
    }
    if (netdev->ieee80211_ptr != HI_NULL) {
        if (netdev->ieee80211_ptr->preset_chandef.chan != HI_NULL) {
            free(netdev->ieee80211_ptr->preset_chandef.chan);
            netdev->ieee80211_ptr->preset_chandef.chan = HI_NULL;
        }
        free(netdev->ieee80211_ptr);
        netdev->ieee80211_ptr = HI_NULL;
    }
    /* ɾ��netdevʱ �ͷ�wpaδ���������eapol��Դ */
    oal_free_netbuf_list(&(netdev->hisi_eapol.eapol_skb_head));
    free((hi_void *)netdev);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    free_netdev(netdev);
#endif
}

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ע�������豸
 �������  : p_net_device: net device �ṹ��ָ��
 �� �� ֵ  : ������
*****************************************************************************/
hi_u32 oal_net_register_netdev(oal_net_device_stru* netdev)
{
    hi_u32   netdev_index;
    hi_u8    dev_register = HI_FALSE;
    oal_net_device_stru *netdev_temp = HI_NULL;

    if (netdev == HI_NULL) {
        oam_error_log0(0, 0, "hwal_lwip_register_netdev parameter NULL.");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ע���������ݽṹ */
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev_temp = oal_get_past_net_device_by_index(netdev_index);
        if (netdev_temp == HI_NULL) {
            oal_set_past_net_device_by_index(netdev_index, netdev);

            dev_register = HI_TRUE;
            break;
        }
    }

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
    /* HCC���� */
    oal_netdevice_headroom(netdev) = 64; /* �̶�����Ϊ 64 */
    oal_netdevice_tailroom(netdev) = 32; /* �̶�����Ϊ 32 */
#endif

    if (dev_register != HI_TRUE) {
        return HI_FAIL;
    }

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    /* ��ʼ��skb list */
    oal_netbuf_head_init(&netdev->hisi_eapol.eapol_skb_head);

    /* ����vap(Hisilicon0)����Ҫע�� */
    if (strncmp(netdev->name, "Hisilicon", strlen("Hisilicon")) == 0) {
        return HI_SUCCESS;
    }

    oal_ip_addr_t gw, ipaddr, netmask;

    /* ע��LWIPЭ��ջ */
    if (hwal_lwip_register(netdev, &ipaddr, &netmask, &gw) != HI_SUCCESS) {
        oal_set_past_net_device_by_index(netdev_index, HI_NULL);

        return HI_FAIL;
    }
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : oal_net_unregister_netdev
 ��������  : ȥע�������豸
 �������  : p_net_device: net device �ṹ��ָ��
*****************************************************************************/
hi_void oal_net_unregister_netdev(oal_net_device_stru* netdev)
{
    hi_u32    netdev_index;
    oal_net_device_stru *netdev_temp = HI_NULL;

    if (netdev == HI_NULL) {
        return;
    }

    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev_temp = oal_get_past_net_device_by_index(netdev_index);
        if (netdev_temp == netdev) {
            oal_set_past_net_device_by_index(netdev_index, HI_NULL);
            /* �Ƚ�ע��LWIPЭ��ջ */
            hwal_lwip_unregister_netdev(netdev);
            return;
        }
    }
}

#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
/*****************************************************************************
 ��������  : ȥע�������豸
 �������  : p_net_device: net device �ṹ��ָ��
*****************************************************************************/
hi_void oal_net_unregister_netdev(oal_net_device_stru* netdev)
{
    hi_u32    netdev_index;
    oal_net_device_stru *netdev_temp = HI_NULL;

    if (netdev == HI_NULL) {
        return;
    }
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev_temp = oal_get_past_net_device_by_index(netdev_index);
        if (netdev_temp == netdev) {
            oal_set_past_net_device_by_index(netdev_index, HI_NULL);
            unregister_netdev(netdev);
            return;
        }
    }
}

hi_u32 oal_net_register_netdev(oal_net_device_stru* netdev)
{
    hi_u32   netdev_index;
    oal_net_device_stru *netdev_temp = HI_NULL;

    if (netdev == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }
    /* ע���������ݽṹ */
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev_temp = oal_get_past_net_device_by_index(netdev_index);
        if (netdev_temp == HI_NULL) {
            oal_set_past_net_device_by_index(netdev_index, netdev);
            break;
        }
    }

    /* HCC���� */
    oal_netdevice_headroom(netdev) = 64; /* �̶�����Ϊ 64 */
    oal_netdevice_tailroom(netdev) = 32; /* �̶�����Ϊ 32 */
    if (register_netdev(netdev) != HI_SUCCESS) {
        oal_set_past_net_device_by_index(netdev_index, HI_NULL);
        return HI_FAIL;
    }
    return HI_SUCCESS;
}
#endif

/*****************************************************************************
 ��������  : ����ipv6��magic
*****************************************************************************/
hi_u16 oal_csum_ipv6_magic(hi_u32 len, hi_u8* buffer)
{
    hi_u32    cksum  = 0;
    hi_u16*   p      = (hi_u16*)buffer;
    hi_u32    size   = (len >> 1) + (len & 0x1);

    while (size > 0) {
        cksum += *p;
        p++;
        size--;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);  /* 16:����16λ */
    cksum = (cksum >> 16) + (cksum & 0xffff);  /* 16:����16λ */

    return (hi_u16)(~cksum);
}

/*****************************************************************************
 ��������  : ��֤skb->data����ul_lenָָʾ�Ŀռ䣬���û�У���� skb_shinfo(skb)->frags[]��
             ����һ�����ݡ�
*****************************************************************************/
hi_s32 oal_eth_header(oal_netbuf_stru* netbuf, oal_net_device_stru* netdev, oal_eth_header_info_stru *eth_header_info)
{
    oal_ether_header_stru* eth = (oal_ether_header_stru*)oal_netbuf_push(netbuf, 14);  /* 14: �ռ䳤�� */
    if (eth == HI_NULL) {
        oal_io_print0("oal_eth_header into eth is null !\n");
        return HI_FAIL;
    }

    if (eth_header_info->type != 0x0001 && eth_header_info->type != 0x0004) {
        eth->us_ether_type = (hi_u16)oal_host2net_short(eth_header_info->type);
    } else {
        eth->us_ether_type = (hi_u16)oal_host2net_short(eth_header_info->len);
    }

    if (!(eth_header_info->saddr)) {
        eth_header_info->saddr = netdev->dev_addr;
    }

    if (memcpy_s(eth->auc_ether_shost, ETHER_ADDR_LEN, eth_header_info->saddr, ETHER_ADDR_LEN) != EOK) {
        return HI_FAIL;
    }

    if (eth_header_info->daddr != HI_NULL) {
        if (memcpy_s(eth->auc_ether_dhost, ETHER_ADDR_LEN, eth_header_info->daddr, ETHER_ADDR_LEN) != EOK) {
            return HI_FAIL;
        }
        return 14;  /* 14: ����ֵ */
    }

    return HI_FAIL;
}

#ifdef _PRE_DEBUG_MODE
/*****************************************************************************
 ��������  : ����һ��arp��
*****************************************************************************/
/* ����5.1 ���⺯������������������50�У��ǿշ�ע�ͣ�����������: ��֡�������Һ����޵��ȣ��������� */
oal_netbuf_stru *oal_arp_create(const oal_arp_create_info_stru *p_arp_create_info, oal_net_device_stru* netdev)
{
    hi_s8                    ac_bcast[6] = {0x33, 0x33, 0x33, 0x33, 0x33, 0x33}; /* 6: Ԫ�ظ��� */
    oal_eth_header_info_stru eth_header_info;

    /* Allocate a buffer */
    oal_netbuf_stru *netbuf = oal_netbuf_alloc(oal_arp_hdr_len(netdev) + oal_ll_allocated_space(netdev), 0);
    if (netbuf == HI_NULL) {
        return HI_NULL;
    }

    skb_reserve(netbuf, oal_ll_allocated_space(netdev)); /* reserve 16 */

    oal_eth_arphdr_stru *arp = (oal_eth_arphdr_stru *)oal_netbuf_put(netbuf, (hi_u32)oal_arp_hdr_len(netdev));

    netbuf->dev = netdev;
    netbuf->protocol = oal_host2net_short(ETHER_TYPE_ARP);

    if (((p_arp_create_info->puc_src_hw != HI_NULL) &&
        (memcpy_s(p_arp_create_info->puc_src_hw, ETHER_ADDR_LEN, netdev->dev_addr, ETHER_ADDR_LEN) != EOK)) ||
        ((p_arp_create_info->puc_dest_hw != HI_NULL) &&
        (memcpy_s(p_arp_create_info->puc_dest_hw, ETHER_ADDR_LEN, ac_bcast, ETHER_ADDR_LEN) != EOK))) {
        goto NETBUF_FREE;
    }

    /* Fill the device header for the ARP frame */
    eth_header_info.type  = p_arp_create_info->l_ptype;
    eth_header_info.daddr = p_arp_create_info->puc_dest_hw;
    eth_header_info.saddr = p_arp_create_info->puc_src_hw;
    eth_header_info.len   = netbuf->len;
    if (oal_eth_header(netbuf, netdev, &eth_header_info) < 0) {
        goto NETBUF_FREE;
    }

    arp->us_ar_hrd = (hi_u16)oal_host2net_short(netdev->type);
    arp->us_ar_pro = (hi_u16)oal_host2net_short(ETHER_TYPE_IP);

    arp->ar_hln    = 6;  /* 6: length of hardware address */
    arp->ar_pln    = 4;  /* 4: length of protocol address */
    arp->us_ar_op  = (hi_u16)oal_host2net_short(p_arp_create_info->l_type);

    hi_u8 *arp_ptr = (hi_u8 *)arp + 8; /* 8: ƫ��8 */
    if ((p_arp_create_info->puc_src_hw != HI_NULL) &&
        (memcpy_s(arp_ptr, ETHER_ADDR_LEN, p_arp_create_info->puc_src_hw, ETHER_ADDR_LEN) != EOK)) {
        goto NETBUF_FREE;
    }

    arp_ptr += 6; /* 6: ƫ��6 */
    if (memcpy_s(arp_ptr, ETH_IP_ADDR_LEN, &(p_arp_create_info->src_ip), ETH_IP_ADDR_LEN) != EOK) {
        goto NETBUF_FREE;
    }

    arp_ptr += 4; /* 4: ƫ��4 */
    if (p_arp_create_info->puc_target_hw != HI_NULL) {
        if (memcpy_s(arp_ptr, ETHER_ADDR_LEN, p_arp_create_info->puc_target_hw, ETHER_ADDR_LEN) != EOK) {
            oal_netbuf_free(netbuf);
            return HI_NULL;
        }
    } else {
        if (memset_s(arp_ptr, ETHER_ADDR_LEN, 0, ETHER_ADDR_LEN) != EOK) {
            oal_netbuf_free(netbuf);
            return HI_NULL;
        }
    }

    arp_ptr += 6; /* 6: ƫ��6 */
    if (memcpy_s(arp_ptr, ETH_IP_ADDR_LEN, &(p_arp_create_info->dest_ip), ETH_IP_ADDR_LEN) != EOK) {
        goto NETBUF_FREE;
    }

    return netbuf;

NETBUF_FREE:
    oal_netbuf_free(netbuf);
    return HI_NULL;
}
#endif

/*****************************************************************************
 ��������  :У���豸���Ͳ����Ի�ȡ�豸��
*****************************************************************************/
hi_u32 oal_net_check_and_get_devname(nl80211_iftype_uint8 type, char* dev_name, hi_u32* len)
{
    hi_u32   netdev_index;
    hi_s32   netdev_count = 0;
    oal_net_device_stru *netdev = HI_NULL;

    /* ��ȡ��ע��netdev��Ϣ */
    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev = oal_get_past_net_device_by_index(netdev_index);
        if (netdev != HI_NULL) {
            ++netdev_count;
        }
    }
    /* ���ֻ֧��3��netdev���� */
    if (netdev_count > 3) {  /* 3: ���ֻ֧��4��netdev���� */
        oal_io_print0("{oal_net_check_and_get_devname::already have 4 vaps. Could not start a new one!}\r\n");
        return HI_FAIL;
    }

    /* strncpyԴ�ڴ�ȫ���Ǿ�̬�ַ������������Բ��ð�ȫ���� */
    switch (type) {
        case NL80211_IFTYPE_STATION:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
            strncpy_s(dev_name, *len, "wlan", strlen("wlan") + 1);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
            strncpy_s(dev_name, *len, "wlan%d", strlen("wlan%d") + 1);
#endif
            break;
        case NL80211_IFTYPE_AP:
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
            strncpy_s(dev_name, *len, "ap", strlen("ap") + 1);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
            strncpy_s(dev_name, *len, "ap%d", strlen("ap%d") + 1);
#endif
            break;
        case NL80211_IFTYPE_P2P_DEVICE:
            strncpy_s(dev_name, *len, "p2p", strlen("p2p") + 1);
            break;
        case NL80211_IFTYPE_P2P_CLIENT:
            /* fall-through */
        case NL80211_IFTYPE_P2P_GO:
            strncpy_s(dev_name, *len, "p2p-p2p0-", strlen("p2p-p2p0-") + 1);
            break;
        case NL80211_IFTYPE_MESH_POINT:
            strncpy_s(dev_name, *len, "mesh", strlen("mesh") + 1);
            break;
        default:
            oal_io_print0("{oal_net_check_and_get_devname::not supported dev type!}\r\n");
            return HI_FAIL;
    }
    *len = strlen(dev_name);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ͷ�����dev
*****************************************************************************/
hi_void oal_dev_destroy_all(hi_void)
{
    hi_u32   netdev_index;
    oal_net_device_stru *netdev = HI_NULL;
    oal_net_device_stru *netdev_temp = HI_NULL;

    for (netdev_index = 0; netdev_index < WLAN_VAP_NUM_PER_BOARD; netdev_index++) {
        netdev_temp = oal_get_past_net_device_by_index(netdev_index);
        if (netdev_temp != HI_NULL) {
            netdev = netdev_temp;
            oal_net_unregister_netdev(netdev_temp);
            oal_net_free_netdev(netdev);
        }
    }

    return;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

