/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_util.c.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/******************************************************************************
  1 ͷ�ļ�����
******************************************************************************/
#include "oal_util.h"
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/etherdevice.h>
#endif

#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif

/*****************************************************************************
1 ȫ�ֱ�������
*****************************************************************************/
hi_u32 g_level_log = 1;

/*****************************************************************************
2 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �ַ���תMAC��ַ
 �������  : param: MAC��ַ�ַ���, ��ʽ xx:xx:xx:xx:xx:xx  �ָ���֧��':'��'-'
 �������  : mac_addr: ת����16���ƺ��MAC��ַ
 �� �� ֵ  :
*****************************************************************************/
WIFI_ROM_TEXT hi_void oal_strtoaddr(const hi_char* param, hi_u8* mac_addr, hi_u8 mac_addr_len)
{
    hi_u8 index;

    /* ��ȡmac��ַ,16����ת�� */
    for (index = 0; index < 12; index++) { /* ѭ��12�� */
        if ((*param == ':') || (*param == '-')) {
            param++;
            if (index != 0) {
                index--;
            }
            continue;
        }
        if ((index / 2) >= mac_addr_len) { /* ��2 ���ҵ���ȷ��MAC��ַ */
            break; /* ��ֹmac_addr ����Խ�� */
        }
        mac_addr[index / 2] = /* ��2 ���ҵ���ȷ��MAC��ַ */
            (hi_u8)(mac_addr[index / 2] * 16 * (index % 2) + oal_strtohex(param)); /* ��2 ��16���ҵ���ȷ��MAC��ַ */
        param++;
    }
}

/*****************************************************************************
 ��������  : �ҵ�1�ֽ�������һ����1��λ��
 �������  : pbyte: Ҫ���ҵ��ֽ�
 �������  : ��
 �� �� ֵ  : ������һ����1��λ��
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 oal_bit_find_first_bit_four_byte(hi_u32 word)
{
    hi_u8 ret = 0;

    if (word == 0) {
        return ret;
    }

    if (!(word & 0xffff)) {
        word >>= 16; /* ����16bit */
        ret += 16;   /* bit����16 */
    }

    if (!(word & 0xff)) {
        word >>= 8; /* ����8bit */
        ret += 8;   /* bit����8 */
    }

    if (!(word & 0xf)) {
        word >>= 4; /* ����4bit */
        ret += 4;   /* bit����4 */
    }

    if (!(word & 0x3)) {
        word >>= 2; /* ����2bit */
        ret += 2;   /* bit����2 */
    }

    if (!(word & 1)) {
        ret += 1;
    }

    return ret;
}

/*****************************************************************************
 ��������  : ��LUT index bitmap���У���ȡһ��û�б�ʹ�õ�������û���ҵ��Ļ���
             ���ز����õ�������ʶ(�ǹؼ�·����δ�����Ż�����ʱ������Ż�)
*****************************************************************************/
WIFI_ROM_TEXT hi_u8 oal_get_lut_index(hi_u8* lut_index_table, hi_u8 bitmap_len, hi_u16 max_lut_size)
{
    hi_u8       byte;
    hi_u8       bit_idx;
    hi_u8       temp;
    hi_u16      index;

    for (byte = 0; byte < bitmap_len; byte++) {
        temp = lut_index_table[byte];

        if (temp == 0xFF) {
            continue;
        }

        for (bit_idx = 0; bit_idx < 8; bit_idx++) { /* 8 bitѭ������ */
            if ((temp & (1 << bit_idx)) != 0) {
                continue;
            }

            index = (byte * 8 + bit_idx); /* ��8ת��bit index */

            if (index < max_lut_size) {
                lut_index_table[byte] |= (hi_u8)(1 << bit_idx);

                return (hi_u8)index;
            } else {
                return (hi_u8)max_lut_size;
            }
        }
    }

    return (hi_u8)max_lut_size;
}

/*****************************************************************************
 ��������  : RSSI��ͨ�˲���עRSSIһ����С��0����
 �������  : c_old, �ϵ�RSSI��c_new���µ�RSSI
 �������  : �˲����RSSI
*****************************************************************************/
WIFI_ROM_TEXT hi_s8 wlan_rssi_lpf(hi_s8 old, hi_s8 new)
{
    hi_u8   oldval;
    hi_u8   newval;
    hi_u16  us_sum;

    /* ���c_new��������0����˵����RSSI�����⣬����Ҫ���¼��� */
    if (new >= 0) {
        return old;
    }

    /* ����ǵ�һ�Σ���ֱ�ӷ����µ�RSSI */
    if (old == WLAN_RSSI_DUMMY_MARKER) {
        return new;
    }

    /* �Ȼ�ȡ����ֵ��������� */
    oldval = (hi_u8)oal_abs(old);
    newval = (hi_u8)oal_abs(new);

    /* ��ʽ: (uc_old x 7/8 + uc_new x 1/8) */
    us_sum = (((oldval) << 3) + (newval) - (oldval));
    newval = (us_sum >> 3) & 0xFF;

    /* �����෴�� */
    return -(newval & WLAN_RSSI_DUMMY_MARKER);
}

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_s32  oal_atoi(const hi_char *c_string)
{
    hi_s32 l_ret = 0;
    hi_s32 flag = 0;

    for (; ; c_string++) {
        switch (*c_string) {
            case '0' ... '9':
                l_ret = 10 * l_ret + (*c_string - '0'); /* 10:ʮ������ */
                break;
            case '-':
                flag = 1;
                break;
            case ' ':
                continue;
            default:
                return ((flag == 0) ? l_ret : (-l_ret));
        }
    }
}
#endif

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_void oal_random_ether_addr(hi_u8* mac_addr, hi_u8 mac_addr_len)
{
    struct timeval tv1;
    struct timeval tv2;

    hi_unref_param(mac_addr_len);
    /* ��ȡ������� */
    gettimeofday(&tv1, NULL);

    /* ��ֹ�뼶����Ϊ0 */
    tv1.tv_sec += 2; /* ��2 */

    tv2.tv_sec = (hi_u32)((hi_u32)((hi_u64)tv1.tv_sec * tv1.tv_sec) * (hi_u64)tv1.tv_usec);
    tv2.tv_usec = (hi_u32)((hi_u32)((hi_u64)tv1.tv_sec * tv1.tv_usec) * (hi_u64)tv1.tv_usec);

    /* ���������mac��ַ */
    mac_addr[0] = ((hi_u32)tv2.tv_sec & 0xff) & 0xfe;
    mac_addr[1] = (hi_u32)tv2.tv_usec & 0xff;
    mac_addr[2] = ((hi_u32)tv2.tv_sec & 0xff0) >> 4;   /* mac_addr[2]����4 bit */
    mac_addr[3] = ((hi_u32)tv2.tv_usec & 0xff0) >> 4;  /* mac_addr[3]����4 bit */
    mac_addr[4] = ((hi_u32)tv2.tv_sec & 0xff00) >> 8;  /* mac_addr[4]����8 bit */
    mac_addr[5] = ((hi_u32)tv2.tv_usec & 0xff00) >> 8; /* mac_addr[5]����8 bit */
}
#else
hi_void oal_random_ether_addr(hi_u8* mac_addr, hi_u8 mac_addr_len)
{
    hi_unref_param(mac_addr_len);
    random_ether_addr(mac_addr);
}
#endif /* #if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION) */

/*****************************************************************************
 ��������  : ��ӡ��Ӧ���ڴ�ֵ
*****************************************************************************/
hi_void oal_print_hex_dump(const hi_u8 *addr, hi_s32 len, hi_s32 group_size, hi_char* pre_str)
{
#ifdef CONFIG_PRINTK
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_unref_param(group_size);
    printk(KERN_DEBUG"buf %p,len:%d\n",
           addr,
           len);
    print_hex_dump(KERN_DEBUG, pre_str, DUMP_PREFIX_ADDRESS, 16, 1, /* 16 */
                   addr, len, true);
    printk(KERN_DEBUG"\n");
#else
    hi_unref_param(addr);
    hi_unref_param(group_size);
    hi_unref_param(pre_str);
#endif
#endif
    hi_diag_log_msg_i0(0, "---start--\n");
    hi_s32 i = 0;
    for (i = 0; i < len; i++) {
        hi_diag_log_msg_i2(0, "netbuf[%d]=%02x\n", (hi_u32)i, addr[i]);
    }
    hi_diag_log_msg_i0(0, "---end---\n");
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

