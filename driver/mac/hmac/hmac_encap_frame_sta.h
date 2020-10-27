/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_encap_frame_sta.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __PREPARE_FRAME_STA_H__
#define __PREPARE_FRAME_STA_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"
#include "hi_types.h"
#include "oal_err_wifi.h"
#include "hmac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 函数声明
*****************************************************************************/
hi_u32 hmac_mgmt_encap_asoc_req_sta(const hmac_vap_stru *hmac_vap, hi_u8 *puc_req_frame);
hi_u16 hmac_mgmt_encap_auth_req(const hmac_vap_stru *hmac_vap, hi_u8 *puc_mgmt_frame);
hi_u16 hmac_mgmt_encap_auth_req_seq3(const hmac_vap_stru *hmac_vap, hi_u8 *puc_mgmt_frame, hi_u8 *puc_mac_hrd);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __PREPARE_FRAME_STA_H__ */
