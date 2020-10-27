/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Hmac_sms4.c header file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_WAPI_SMS4_H__
#define __HMAC_WAPI_SMS4_H__

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define byte_sub(_s, _a) ((_s)[((hi_u32)(_a)) >> 24 & 0xFF] << 24 ^ \
                        (_s)[((hi_u32)(_a)) >> 16 & 0xFF] << 16 ^ \
                        (_s)[((hi_u32)(_a)) >>  8 & 0xFF] <<  8 ^ \
                        (_s)[((hi_u32)(_a)) & 0xFF])

#define l1(_b) ((_b) ^ rotl32(_b, 2) ^ rotl32(_b, 10) ^ rotl32(_b, 18) ^ rotl32(_b, 24))
#define l2(_b) ((_b) ^ rotl32(_b, 13) ^ rotl32(_b, 23))

/*****************************************************************************
  2 函数声明
*****************************************************************************/
hi_void hmac_sms4_crypt(const hi_u8 *puc_input, hi_u8 input_len, hi_u8 *puc_output,
    const hi_u32 *puc_rk, hi_u8 rk_len);
hi_void hmac_sms4_keyext(const hi_u8 *puc_key, hi_u8 key_len, hi_u32 *puc_rk, hi_u8 rk_len);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_WAPI_SMS4_H__ */
