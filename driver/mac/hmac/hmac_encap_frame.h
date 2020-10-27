/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_encap_frame.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_ENCAP_FRAME_H__
#define __HMAC_ENCAP_FRAME_H__

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_user.h"
#include "mac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 函数声明
*****************************************************************************/
hi_u16 hmac_mgmt_encap_deauth(const mac_vap_stru *mac_vap, hi_u8 *puc_data, const hi_u8 *da_mac_addr,
                              hi_u16 us_err_code);
hi_u16 hmac_mgmt_encap_disassoc(const mac_vap_stru *mac_vap, hi_u8 *puc_data, const hi_u8 *da_mac_addr,
                                hi_u16 us_err_code);
hi_u16 hmac_encap_sa_query_req(const mac_vap_stru *mac_vap, hi_u8 *puc_data, const hi_u8 *da_mac_addr,
                               hi_u16 us_trans_id);
hi_u16 hmac_encap_sa_query_rsp(const mac_vap_stru *mac_vap, const hi_u8 *hdr, hi_u8 *puc_data);
hi_void hmac_check_sta_base_rate(hi_u8 *user, mac_status_code_enum_uint16 *pen_status_code);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_ENCAP_FRAME_H__ */
