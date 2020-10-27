/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for hmac_wapi.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HMAC_WAPI_WPI_H__
#define __HMAC_WAPI_WPI_H__

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define WPI_PR_KEYIN_LEN  32

typedef struct {
    hi_u8 *puc_key;
    hi_u8 *puc_iv;
    hi_u8  key_len;
    hi_u8  iv_len;
    hi_u8  resv[2]; /* resv 2byte */
} hmac_wapi_crypt_stru;

/*****************************************************************************
  2 函数声明
*****************************************************************************/
hi_u32 hmac_wpi_encrypt(hmac_wapi_crypt_stru wpi_key, hi_u8 *puc_bufin, hi_u32 buflen, hi_u8 *puc_bufout);
hi_u32 hmac_wpi_decrypt(hmac_wapi_crypt_stru wpi_key, hi_u8 *puc_bufin, hi_u32 buflen, hi_u8 *puc_bufout);
hi_u32 hmac_wpi_pmac(hmac_wapi_crypt_stru wpi_key, hi_u8 *puc_buf, hi_u32 pamclen, hi_u8 *puc_mic, hi_u8 mic_len);

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif

#endif /* __HMAC_WAPI_WPI_H__ */
