/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_uapsd.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_UAPSD_H__
#define __HMAC_UAPSD_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#include "mac_user.h"
#include "hmac_ext_if.h"
#include "dmac_ext_if.h"
#include "hmac_user.h"
#include "hmac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
#define HMAC_UAPSD_SEND_ALL  0xff        /* ���Ͷ��������б���,����ΪUINT8�������ֵ */
#define HMAC_UAPSD_WME_LEN   8

/*****************************************************************************
  3 ��������
*****************************************************************************/
hi_u32 hmac_config_set_uapsden(mac_vap_stru *mac_vap, hi_u16 us_len, const hi_u8 *puc_param);
hi_void hmac_uapsd_update_user_para(const hi_u8 *puc_mac_hdr, hi_u8 sub_type,
                                    hi_u32 msg_len, const hmac_user_stru *hmac_user);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* __HMAC_UAPSD_H__ */
