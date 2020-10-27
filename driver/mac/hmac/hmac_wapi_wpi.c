/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Wpi data encryption and decryption.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "oal_err_wifi.h"
#include "hmac_wapi_sms4.h"
#include "hmac_wapi_wpi.h"
#include "hmac_wapi.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ofb encrypt
 �������  : hi_u8 *puc_iv    ΪIV�洢����ʼ��ַ
             hi_u8 *puc_bufin    Ϊ���Ĵ洢����ʼ��ַ
             hi_u32 ul_buflen    Ϊ���ģ���ByteΪ��λ������
             hi_u8 *puc_key      Ϊ�Ự��Կ�洢����ʼ��ַ
             hi_u8* puc_bufout   Ϊ���Ĵ洢����ʼ��ַ��
                                ���Ĵ洢���ռ������Ĵ洢���ռ��С��ͬ
 �޸���ʷ      :
  1.��    ��   : 2012��5��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

  2.��    ��   : 2015��5��28��
    ��    ��   : Hisilicon
    �޸�����   : ��ֲ
*****************************************************************************/
hi_u32 hmac_wpi_encrypt(hmac_wapi_crypt_stru wpi_key, hi_u8 *puc_bufin, hi_u32 buflen, hi_u8 *puc_bufout)
{
    hi_u32 aul_iv_out[4] = { 0 }; /* Ԫ�ظ���Ϊ4 */
    hi_u32 *pul_in = HI_NULL;
    hi_u32 *pul_out = HI_NULL;
    hi_u8 *puc_out = HI_NULL;
    hi_u8 *puc_in = HI_NULL;
    hi_u32 counter;
    hi_u32 comp;
    hi_u32 loop;
    hi_u32 aul_pr_keyin[WPI_PR_KEYIN_LEN] = { 0 };
    hi_u8 *puc_iv = wpi_key.puc_iv;
    hi_u8  iv_len = wpi_key.iv_len;
    hi_u8 *puc_key = wpi_key.puc_key;
    hi_u8 key_len = wpi_key.key_len;

    if (buflen < 1) {
#ifdef WAPI_DEBUG_MODE
        g_stMacDriverStats.ulsms4ofbinparminvalid++;
#endif
        return HI_FAIL;
    }

    hmac_sms4_keyext(puc_key, key_len, aul_pr_keyin, WPI_PR_KEYIN_LEN);

    counter = buflen / 16; /* 16 ���ڼ��� */
    comp = buflen % 16; /* 16 ���ڼ��� */

    /* get the iv */
    hmac_sms4_crypt(puc_iv, iv_len, (hi_u8 *)aul_iv_out, aul_pr_keyin, WPI_PR_KEYIN_LEN);
    pul_in = (hi_u32 *)puc_bufin;
    pul_out = (hi_u32 *)puc_bufout;

    for (loop = 0; loop < counter; loop++) {
        pul_out[0] = pul_in[0] ^ aul_iv_out[0];
        pul_out[1] = pul_in[1] ^ aul_iv_out[1];
        pul_out[2] = pul_in[2] ^ aul_iv_out[2]; /* 2 Ԫ������ */
        pul_out[3] = pul_in[3] ^ aul_iv_out[3]; /* 3 Ԫ������ */

        hmac_sms4_crypt((hi_u8 *)aul_iv_out, 4, (hi_u8 *)aul_iv_out, aul_pr_keyin, WPI_PR_KEYIN_LEN); /* iv_out len 4 */
        pul_in += 4;  /* ����4 */
        pul_out += 4; /* ����4 */
    }

    puc_in = (hi_u8 *)pul_in;
    puc_out = (hi_u8 *)pul_out;
    puc_iv = (hi_u8 *)aul_iv_out;

    for (loop = 0; loop < comp; loop++) {
        puc_out[loop] = puc_in[loop] ^ puc_iv[loop];
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ofb decrypt
 �������  : hi_u8* puc_iv    ΪIV�洢����ʼ��ַ
             hi_u8* puc_bufin    Ϊ���Ĵ洢����ʼ��ַ
             hi_u32 ul_buflen    Ϊ���ģ���ByteΪ��λ������
             hi_u8* puc_key      Ϊ�Ự��Կ�洢����ʼ��ַ
             hi_u8* puc_bufout   Ϊ���Ĵ洢����ʼ��ַ
 �޸���ʷ      :
  1.��    ��   : 2012��5��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

  2.��    ��   : 2015��5��28��
    ��    ��   : Hisilicon
    �޸�����   : ��ֲ
*****************************************************************************/
hi_u32 hmac_wpi_decrypt(hmac_wapi_crypt_stru wpi_key, hi_u8 *puc_bufin, hi_u32 buflen, hi_u8 *puc_bufout)
{
    return hmac_wpi_encrypt(wpi_key, puc_bufin, buflen, puc_bufout);
}

/*****************************************************************************
 ��������  : ����mic
 �������  : hi_u8* puc_iv    ΪIV�洢����ʼ��ַ
             hi_u8* pucBuf      Ϊtext�洢����ʼ��ַ
             hi_u32 ulPamclen   Ϊtext���ȣ���ByteΪ��λ����ӦΪ16Byte��������������16�ı���
             hi_u8* pucKey      Ϊ���ڼ���MIC����ԿKEY�洢����ʼ��ַ
             hi_u8* pucMic      ΪMIC�洢����ʼ��ַ
 �޸���ʷ      :
  1.��    ��   : 2012��5��2��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_wpi_pmac(hmac_wapi_crypt_stru wpi_key, hi_u8 *puc_buf, hi_u32 pamclen, hi_u8 *puc_mic, hi_u8 mic_len)
{
    hi_u32 aul_mic_tmp[4] = { 0 };  /* Ԫ�ظ���Ϊ4 */
    hi_u32 loop;
    hi_u32 *pul_in = HI_NULL;
    hi_u32 aul_pr_mac_keyin[WPI_PR_KEYIN_LEN] = { 0 };
    hi_u8 *puc_iv = wpi_key.puc_iv;
    hi_u8  iv_len = wpi_key.iv_len;
    hi_u8 *puc_key = wpi_key.puc_key;
    hi_u8  key_len = wpi_key.key_len;

    if (mic_len < SMS4_MIC_LEN) {
        return HI_FAIL;
    }
    if ((pamclen < 1) || (pamclen > 4096)) { /* 4096 �߽� */
        return HI_FAIL;
    }

    hmac_sms4_keyext(puc_key, key_len, aul_pr_mac_keyin, WPI_PR_KEYIN_LEN);
    pul_in = (hi_u32 *)puc_buf;
    hmac_sms4_crypt(puc_iv, iv_len, (hi_u8 *)aul_mic_tmp, aul_pr_mac_keyin, WPI_PR_KEYIN_LEN);

    for (loop = 0; loop < pamclen; loop++) {
        aul_mic_tmp[0] ^= pul_in[0];
        aul_mic_tmp[1] ^= pul_in[1];
        aul_mic_tmp[2] ^= pul_in[2]; /* 2 Ԫ������ */
        aul_mic_tmp[3] ^= pul_in[3]; /* 3 Ԫ������ */
        pul_in += 4; /* ����4 */
        hmac_sms4_crypt((hi_u8 *)aul_mic_tmp, 4, (hi_u8 *)aul_mic_tmp, aul_pr_mac_keyin, WPI_PR_KEYIN_LEN); /* len 4 */
    }

    pul_in = (hi_u32 *)puc_mic;
    pul_in[0] = aul_mic_tmp[0];
    pul_in[1] = aul_mic_tmp[1];
    pul_in[2] = aul_mic_tmp[2]; /* 2 Ԫ������ */
    pul_in[3] = aul_mic_tmp[3]; /* 3 Ԫ������ */

    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
        }
#endif
#endif
