/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file for oal_err_wifi.h, basic data type definition.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __HI_ERR_WIFI_H__
#define __HI_ERR_WIFI_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* �����������붨�� */
typedef enum {
    HI_SUCCESS                              = 0,
    HI_FAIL                                 = 1,                            /* ͨ���쳣�����������쳣�޷�ƥ����д��ֵ */
    HI_CONTINUE                             = 2,
    /**************************************************************************
        plat pm exception
    **************************************************************************/
    HI_ERR_CODE_PM_BASE                     = 10,
    HI_ERR_CODE_ALREADY_OPEN                = (HI_ERR_CODE_PM_BASE + 0),    /* �Ѿ��� */
    HI_ERR_CODE_ALREADY_CLOSE               = (HI_ERR_CODE_PM_BASE + 1),    /* �Ѿ��ر� */

    /**************************************************************************
        system exception
    **************************************************************************/
    HI_ERR_CODE_SYS_BASE                     = 100,
    HI_ERR_CODE_PTR_NULL                     = (HI_ERR_CODE_SYS_BASE + 0),  /* ָ����Ϊ�� */
    HI_ERR_CODE_ARRAY_OVERFLOW               = (HI_ERR_CODE_SYS_BASE + 1),  /* �����±�Խ�� */
    HI_ERR_CODE_DIV_ZERO                     = (HI_ERR_CODE_SYS_BASE + 2),  /* ��0���� */          /* 2: SYS_BASE + 2 */
    HI_ERR_CODE_ALLOC_MEM_FAIL               = (HI_ERR_CODE_SYS_BASE + 3),  /* �����ڴ�ʧ�� */     /* 3: SYS_BASE + 3 */
    HI_ERR_CODE_FREE_MEM_FAIL                = (HI_ERR_CODE_SYS_BASE + 4),  /* 4: SYS_BASE offset 4 */
    HI_ERR_CODE_START_TIMRE_FAIL             = (HI_ERR_CODE_SYS_BASE + 5),  /* ������ʱ��ʧ�� */   /* 5: SYS_BASE + 5 */
    HI_ERR_CODE_RESET_INPROGRESS             = (HI_ERR_CODE_SYS_BASE + 6),  /* ��λ������ */       /* 6: SYS_BASE + 6 */
    /* mac_device_struz�Ҳ��� */
    HI_ERR_CODE_MAC_DEVICE_NULL              = (HI_ERR_CODE_SYS_BASE + 7),  /* 7: SYS_BASE + 7 */
    HI_ERR_CODE_MAGIC_NUM_FAIL               = (HI_ERR_CODE_SYS_BASE + 8),  /* ħ�����ּ��ʧ�� */ /* 8: SYS_BASE + 8 */
    HI_ERR_CODE_NETBUF_INDEX_CHANGE          = (HI_ERR_CODE_SYS_BASE + 9),  /* netbuf ���۸� */    /* 9: SYS_BASE + 9 */
    HI_ERR_CODE_CFG_REG_TIMEOUT              = (HI_ERR_CODE_SYS_BASE + 10), /* ���üĴ�����ʱ */ /* 10: SYS_BASE + 10 */
    HI_ERR_CODE_CFG_REG_ERROR                = (HI_ERR_CODE_SYS_BASE + 11), /* ���üĴ������� */ /* 11: SYS_BASE + 11 */
    /* ����Ϊ�գ�һ�������������������� */
    HI_ERR_CODE_LIST_NOT_EMPTY_ERROR         = (HI_ERR_CODE_SYS_BASE + 12), /* 12: SYS_BASE + 12 */

    /* system error���ֵ */
	HI_ERR_SYS_BUTT                          = (HI_ERR_CODE_SYS_BASE + 199), /* 199: SYS_BASE + 199 */

    /**************************************************************************
        resv func result
    ***************************************************************************/
    HI_ERR_CODE_RESV_FUNC_BASE               = 300,
    HI_ERR_CODE_RESV_FUNC_REPLACE            = (HI_ERR_CODE_RESV_FUNC_BASE + 0), /* ���ִ��,ԭ����������� */
    HI_ERR_CODE_RESV_FUNC_ADD                = (HI_ERR_CODE_RESV_FUNC_BASE + 1), /* ����ִ��,ԭ�������뱣�� */

    HI_ERR_CODE_RESV_FUNC_BUTT               = (HI_ERR_CODE_RESV_FUNC_BASE + 99), /* 99: FUNC_BASE + 99 */

    /**************************************************************************
        config exception
    ***************************************************************************/
    HI_ERR_CODE_CONFIG_BASE                 = 1000,
    HI_ERR_CODE_INVALID_CONFIG              = (HI_ERR_CODE_CONFIG_BASE + 0), /* ��Ч���� */
    HI_ERR_CODE_CONFIG_UNSUPPORT            = (HI_ERR_CODE_CONFIG_BASE + 1), /* ���ò�֧�� */
    HI_ERR_CODE_CONFIG_EXCEED_SPEC          = (HI_ERR_CODE_CONFIG_BASE + 2), /* ���ó������ */ /* 2: CONFIG_BASE + 2 */
    HI_ERR_CODE_CONFIG_TIMEOUT              = (HI_ERR_CODE_CONFIG_BASE + 3), /* ���ó�ʱ */     /* 3: CONFIG_BASE + 3 */
    HI_ERR_CODE_CONFIG_BUSY                 = (HI_ERR_CODE_CONFIG_BASE + 4), /* 4: CONFIG_BASE + 4 */
    /* HMAC��DMAC����vapʱ��index��һ�� */
    HI_ERR_CODE_ADD_VAP_INDX_UNSYNC         = (HI_ERR_CODE_CONFIG_BASE + 5), /* 5: CONFIG_BASE + 5 */
    /* HMAC��DMAC����multi userʱ��index��һ�� */
    HI_ERR_CODE_ADD_MULTI_USER_INDX_UNSYNC  = (HI_ERR_CODE_CONFIG_BASE + 6), /* 6: CONFIG_BASE + 6 */
    /* �û���Դ�Ѿ��ͷţ��ظ��ͷ� */
    HI_ERR_CODE_USER_RES_CNT_ZERO           = (HI_ERR_CODE_CONFIG_BASE + 7), /* 7: CONFIG_BASE + 7 */

    /* ���ô������ֵ */
	HI_ERR_CODE_CONFIG_BUTT                 = (HI_ERR_CODE_CONFIG_BASE + 99), /* 99: CONFIG_BASE + 99 */

    /**************************************************************************
        MSG exception
    **************************************************************************/
    HI_ERR_CODE_MSG_BASE                  = 1100,
    HI_ERR_CODE_MSG_TYPE_ERR              = (HI_ERR_CODE_MSG_BASE + 0),   /* ��Ϣ���ͽ������� */
    HI_ERR_CODE_MSG_NOT_CMPTBL_WITH_STATE = (HI_ERR_CODE_MSG_BASE + 1),   /* ��Ϣ��������״̬��һ�� */
    HI_ERR_CODE_MSG_IE_MISS               = (HI_ERR_CODE_MSG_BASE + 2),   /* ��ϢIEȱʧ */ /* 2: MSG_BASE + 2 */
    HI_ERR_CODE_MSG_IE_VALUE_ERR          = (HI_ERR_CODE_MSG_BASE + 3),   /* ��ϢIE��ֵ���� */ /* 3: MSG_BASE + 3 */
    /* ipc�ڲ���Ϣ���Ͷ��������� */
    HI_ERR_CODE_IPC_QUEUE_FULL            = (HI_ERR_CODE_MSG_BASE + 4),   /* 4: MSG_BASE + 4 */
    HI_ERR_CODE_MSG_NOT_FIND_STA_TAB      = (HI_ERR_CODE_MSG_BASE + 5),   /* ��Ϣ�Ҳ���״̬�� */ /* 5: MSG_BASE + 5 */
    HI_ERR_CODE_MSG_NOT_FIND_ACT_TAB      = (HI_ERR_CODE_MSG_BASE + 6),   /* ��Ϣ�Ҳ��������� */ /* 6: MSG_BASE +6 */
    /* ��Ϣ��Ӧ�Ĵ�����ΪNULL */
    HI_ERR_CODE_MSG_ACT_FUN_NULL          = (HI_ERR_CODE_MSG_BASE + 7),   /* 7: MSG_BASE + 7 */
    HI_ERR_CODE_MSG_LENGTH_ERR            = (HI_ERR_CODE_MSG_BASE + 8),   /* ��Ϣ���ȴ��� */ /* 8: MSG_BASE + 8 */

    HI_ERR_CODE_MSG_BUTT                  = (HI_ERR_CODE_MSG_BASE + 99),  /* ��Ϣ�������ֵ */ /* 99: MSG_BASE + 99 */

    /**************************************************************************
        �ļ�����������
    **************************************************************************/
    HI_ERR_CODE_FILE_BASE           = 1200,
    HI_ERR_CODE_OPEN_FILE_FAIL      = (HI_ERR_CODE_FILE_BASE + 0),
    HI_ERR_CODE_WRITE_FILE_FAIL     = (HI_ERR_CODE_FILE_BASE + 1),
    HI_ERR_CODE_READ_FILE_FAIL      = (HI_ERR_CODE_FILE_BASE + 2), /* 2: FILE_BASE + 2 */
    HI_ERR_CODE_CLOSE_FILE_FAIL     = (HI_ERR_CODE_FILE_BASE + 3), /* 3: FILE_BASE + 3 */

    HI_ERR_CODE_FILE_BUTT           = (HI_ERR_CODE_FILE_BASE + 99), /* �ļ������������ֵ */ /* 99: FILE_BASE + 99 */

    /**************************************************************************
        ��ģ���Զ������
    **************************************************************************/
    /**************************** �������������� *****************************/
    HI_ERR_CODE_DSCR_BASE                     = 10000,
    HI_ERR_CODE_RX_DSCR_AMSDU_DISORDER        = (HI_ERR_CODE_DSCR_BASE + 0),  /* AMSDU��Ӧ������������ */
    HI_ERR_CODE_RX_DSCR_LOSE                  = (HI_ERR_CODE_DSCR_BASE + 1),  /* ��������buf��Ŀ����Ӧ */

    HI_ERR_CODE_DSCR_BUTT                     = (HI_ERR_CODE_DSCR_BASE + 999), /* 999: DSCR_BASE + 999 */

    /**************************************************************************
        �������Զ������,��20000��ʼ��ÿ�����Է���100��
    **************************************************************************/
    /**************************** AMSDU���� ***********************************/
    HI_ERR_CODE_HMAC_AMSDU_BASE               = 20000,
    HI_ERR_CODE_HMAC_AMSDU_DISABLE            = (HI_ERR_CODE_HMAC_AMSDU_BASE + 0),  /* amsdu���ܹر� */
    HI_ERR_CODE_HMAC_MSDU_LEN_OVER            = (HI_ERR_CODE_HMAC_AMSDU_BASE + 1),

    HI_ERR_CODE_HMAC_AMSDU_BUTT               = (HI_ERR_CODE_HMAC_AMSDU_BASE + 999), /* 999: AMSDU_BASE + 999 */

    /********************************* ���� **********************************/
    /**************************** 11i ���� ***********************************/
    HI_ERR_CODE_SECURITY_BASE               = 21000,
    HI_ERR_CODE_SECURITY_KEY_TYPE           = (HI_ERR_CODE_SECURITY_BASE + 0),
    HI_ERR_CODE_SECURITY_KEY_LEN            = (HI_ERR_CODE_SECURITY_BASE + 1),
    HI_ERR_CODE_SECURITY_KEY_ID             = (HI_ERR_CODE_SECURITY_BASE + 2),  /* 2: SECURITY_BASE + 2 */
    HI_ERR_CODE_SECURITY_CHIPER_TYPE        = (HI_ERR_CODE_SECURITY_BASE + 3),  /* 3: SECURITY_BASE + 3 */
    HI_ERR_CODE_SECURITY_BUFF_NUM           = (HI_ERR_CODE_SECURITY_BASE + 4),  /* 4: SECURITY_BASE + 4 */
    HI_ERR_CODE_SECURITY_BUFF_LEN           = (HI_ERR_CODE_SECURITY_BASE + 5),  /* 5: SECURITY_BASE + 5 */
    HI_ERR_CODE_SECURITY_WRONG_KEY          = (HI_ERR_CODE_SECURITY_BASE + 6),  /* 6: SECURITY_BASE + 6 */
    HI_ERR_CODE_SECURITY_USER_INVAILD       = (HI_ERR_CODE_SECURITY_BASE + 7),  /* 7: SECURITY_BASE + 7 */
    HI_ERR_CODE_SECURITY_PARAMETERS         = (HI_ERR_CODE_SECURITY_BASE + 8),  /* 8: SECURITY_BASE + 8 */
    HI_ERR_CODE_SECURITY_AUTH_TYPE          = (HI_ERR_CODE_SECURITY_BASE + 9),  /* 9: SECURITY_BASE + 9 */
    HI_ERR_CODE_SECURITY_CAP                = (HI_ERR_CODE_SECURITY_BASE + 10), /* 10: SECURITY_BASE + 10 */
    HI_ERR_CODE_SECURITY_CAP_MFP            = (HI_ERR_CODE_SECURITY_BASE + 11), /* 11: SECURITY_BASE + 11 */
    HI_ERR_CODE_SECURITY_CAP_BSS            = (HI_ERR_CODE_SECURITY_BASE + 12), /* 12: SECURITY_BASE + 12 */
    HI_ERR_CODE_SECURITY_CAP_PHY            = (HI_ERR_CODE_SECURITY_BASE + 13), /* 13: SECURITY_BASE + 13 */
    HI_ERR_CODE_SECURITY_PORT_INVALID       = (HI_ERR_CODE_SECURITY_BASE + 14), /* 14: SECURITY_BASE + 14 */
    HI_ERR_CODE_SECURITY_MAC_INVALID        = (HI_ERR_CODE_SECURITY_BASE + 15), /* 15: SECURITY_BASE + 15 */
    HI_ERR_CODE_SECURITY_MODE_INVALID       = (HI_ERR_CODE_SECURITY_BASE + 16), /* 16: SECURITY_BASE + 16 */
    HI_ERR_CODE_SECURITY_LIST_FULL          = (HI_ERR_CODE_SECURITY_BASE + 17), /* 17: SECURITY_BASE + 17 */
    HI_ERR_CODE_SECURITY_AGING_INVALID      = (HI_ERR_CODE_SECURITY_BASE + 18), /* 18: SECURITY_BASE + 18 */
    HI_ERR_CODE_SECURITY_THRESHOLD_INVALID  = (HI_ERR_CODE_SECURITY_BASE + 19), /* 19: SECURITY_BASE + 19 */
    HI_ERR_CODE_SECURITY_RESETIME_INVALID   = (HI_ERR_CODE_SECURITY_BASE + 20), /* 20: SECURITY_BASE + 20 */
    HI_ERR_CODE_SECURITY_BUTT               = (HI_ERR_CODE_SECURITY_BASE + 99), /* 99: SECURITY_BASE + 99 */
    /* �����������Ȳ�ɾ��ԭ�ȵĴ����룬��ȫ��������Ժ���ɾ�� */
    HI_ERR_CODE_HMAC_SECURITY_BASE              = 21100,
    HI_ERR_CODE_HMAC_SECURITY_KEY_TYPE          = (HI_ERR_CODE_HMAC_SECURITY_BASE + 0),
    HI_ERR_CODE_HMAC_SECURITY_KEY_LEN           = (HI_ERR_CODE_HMAC_SECURITY_BASE + 1),
    HI_ERR_CODE_HMAC_SECURITY_KEY_ID            = (HI_ERR_CODE_HMAC_SECURITY_BASE + 2),   /* 2: SECURITY_BASE + 2 */
    HI_ERR_CODE_HMAC_SECURITY_CHIPER_TYPE       = (HI_ERR_CODE_HMAC_SECURITY_BASE + 3),   /* 3: SECURITY_BASE + 3 */
    HI_ERR_CODE_HMAC_SECURITY_BUFF_NUM          = (HI_ERR_CODE_HMAC_SECURITY_BASE + 4),   /* 4: SECURITY_BASE + 4 */
    HI_ERR_CODE_HMAC_SECURITY_BUFF_LEN          = (HI_ERR_CODE_HMAC_SECURITY_BASE + 5),   /* 5: SECURITY_BASE + 5 */
    HI_ERR_CODE_HMAC_SECURITY_WRONG_KEY         = (HI_ERR_CODE_HMAC_SECURITY_BASE + 6),   /* 6: SECURITY_BASE + 6 */
    HI_ERR_CODE_HMAC_SECURITY_USER_INVAILD      = (HI_ERR_CODE_HMAC_SECURITY_BASE + 7),   /* 7: SECURITY_BASE + 7 */
    HI_ERR_CODE_HMAC_SECURITY_PARAMETERS        = (HI_ERR_CODE_HMAC_SECURITY_BASE + 8),   /* 8: SECURITY_BASE + 8 */
    HI_ERR_CODE_HMAC_SECURITY_AUTH_TYPE         = (HI_ERR_CODE_HMAC_SECURITY_BASE + 9),   /* 9: SECURITY_BASE + 9 */
    HI_ERR_CODE_HMAC_SECURITY_CAP               = (HI_ERR_CODE_HMAC_SECURITY_BASE + 10),  /* 10: SECURITY_BASE + 10 */
    HI_ERR_CODE_HMAC_SECURITY_CAP_MFP           = (HI_ERR_CODE_HMAC_SECURITY_BASE + 11),  /* 11: SECURITY_BASE + 11 */
    HI_ERR_CODE_HMAC_SECURITY_CAP_BSS           = (HI_ERR_CODE_HMAC_SECURITY_BASE + 12),  /* 12: SECURITY_BASE + 12 */
    HI_ERR_CODE_HMAC_SECURITY_CAP_PHY           = (HI_ERR_CODE_HMAC_SECURITY_BASE + 13),  /* 13: SECURITY_BASE + 13 */
    HI_ERR_CODE_HMAC_SECURITY_PORT_INVALID      = (HI_ERR_CODE_HMAC_SECURITY_BASE + 14),  /* 14: SECURITY_BASE + 14 */
    HI_ERR_CODE_HMAC_SECURITY_MAC_INVALID       = (HI_ERR_CODE_HMAC_SECURITY_BASE + 15),  /* 15: SECURITY_BASE + 15 */
    HI_ERR_CODE_HMAC_SECURITY_MODE_INVALID      = (HI_ERR_CODE_HMAC_SECURITY_BASE + 16),  /* 16: SECURITY_BASE + 16 */
    HI_ERR_CODE_HMAC_SECURITY_LIST_FULL         = (HI_ERR_CODE_HMAC_SECURITY_BASE + 17),  /* 17: SECURITY_BASE + 17 */
    HI_ERR_CODE_HMAC_SECURITY_AGING_INVALID     = (HI_ERR_CODE_HMAC_SECURITY_BASE + 18),  /* 18: SECURITY_BASE + 18 */
    HI_ERR_CODE_HMAC_SECURITY_THRESHOLD_INVALID = (HI_ERR_CODE_HMAC_SECURITY_BASE + 19),  /* 19: SECURITY_BASE + 19 */
    HI_ERR_CODE_HMAC_SECURITY_RESETIME_INVALID  = (HI_ERR_CODE_HMAC_SECURITY_BASE + 20),  /* 20: SECURITY_BASE + 20 */
    HI_ERR_CODE_HMAC_SECURITY_BUTT              = (HI_ERR_CODE_HMAC_SECURITY_BASE + 499), /* 499: SECURITY_BASE + 499 */

    /**************************** wapi ���� ***********************************/
    HI_ERR_CODE_WAPI_BASE                          = 21600,
    HI_ERR_CODE_WAPI_NETBUFF_LEN_ERR               = (HI_ERR_CODE_WAPI_BASE + 0),
    HI_ERR_CODE_WAPI_DECRYPT_FAIL                  = (HI_ERR_CODE_WAPI_BASE + 1),
    HI_ERR_CODE_WAPI_MIC_CALC_FAIL                 = (HI_ERR_CODE_WAPI_BASE + 2),  /* 2: WAPI_BASE + 2 */
    HI_ERR_CODE_WAPI_ENRYPT_FAIL                   = (HI_ERR_CODE_WAPI_BASE + 3),  /* 3: WAPI_BASE + 3 */
    HI_ERR_CODE_WAPI_MIC_CMP_FAIL                  = (HI_ERR_CODE_WAPI_BASE + 4),  /* 4: WAPI_BASE + 4 */

    HI_ERR_CODE_WAPI_BUTT                          = (HI_ERR_CODE_WAPI_BASE + 99), /* 99: WAPI_BASE + 99 */
    /********************************* ���� **********************************/
    /**************************** 11w ���� ***********************************/
    HI_ERR_CODE_PMF_BASE                      = 22000,
    /* user��bit_pmf_active����û��ʹ�ܿ��� */
    HI_ERR_CODE_PMF_ACTIVE_DOWN               = (HI_ERR_CODE_PMF_BASE + 0),
    /* hmac_send_sa_query_req��������sa query req����ʧ�� */
    HI_ERR_CODE_PMF_SA_QUERY_REQ_SEND_FAIL    = (HI_ERR_CODE_PMF_BASE + 1),
    /* dot11RSNAProtectedManagementFramesActivated ֵΪ0 */
    HI_ERR_CODE_PMF_DISABLED                  = (HI_ERR_CODE_PMF_BASE + 2),   /* 2: PMF_BASE + 2 */
    /* hmac_start_sa_query�������ؽ��ʧ�� */
    HI_ERR_CODE_PMF_SA_QUERY_START_FAIL       = (HI_ERR_CODE_PMF_BASE + 3),   /* 3: PMF_BASE + 3 */
    /* hmac_sa_query_del_user����,SA query����ɾ���û�ʧ�� */
    HI_ERR_CODE_PMF_SA_QUERY_DEL_USER_FAIL    = (HI_ERR_CODE_PMF_BASE + 4),   /* 4: PMF_BASE + 4 */
    /* oal_crypto_aes_cmac_encrypt������AES_CMAC����ʧ�� */
    HI_ERR_CODE_PMF_BIP_AES_CMAC_ENCRYPT_FAIL = (HI_ERR_CODE_PMF_BASE + 5),   /* 5: PMF_BASE + 5 */
    /* dmac_bip_crypto������bip����ʧ�� */
    HI_ERR_CODE_PMF_BIP_CRIPTO_FAIL           = (HI_ERR_CODE_PMF_BASE + 6),   /* 6: PMF_BASE + 6 */
    /* oal_crypto_bip_demic������bip����ʧ�� */
    HI_ERR_CODE_PMF_BIP_DECRIPTO_FAIL         = (HI_ERR_CODE_PMF_BASE + 7),   /* 7: PMF_BASE + 7 */
    /* ����igtk_index ���� */
    HI_ERR_CODE_PMF_IGTK_INDX_FAIL            = (HI_ERR_CODE_PMF_BASE + 8),   /* 8: PMF_BASE + 8 */
    /* VAP��mfpc&mfpr���ô��� */
    HI_ERR_CODE_PMF_VAP_CAP_FAIL              = (HI_ERR_CODE_PMF_BASE + 9),   /* 9: PMF_BASE + 9 */
    /* VAP��mib dot11RSNAActived����ΪOAL_FALES */
    HI_ERR_CODE_PMF_VAP_ACTIVE_DOWN           = (HI_ERR_CODE_PMF_BASE + 10),  /* 10: PMF_BASE + 10 */
    /* igtk�����ڻ���igtk_idֵ���� */
    HI_ERR_CODE_PMF_IGTK_NOT_EXIST            = (HI_ERR_CODE_PMF_BASE + 11),  /* 11: PMF_BASE + 11 */
    /* bip�ӽ��ܹ��̴��� */
    HI_ERR_CODE_PMF_ALIGN_ERR                 = (HI_ERR_CODE_PMF_BASE + 12),  /* 12: PMF_BASE + 12 */
    HI_ERR_CODE_PMF_REPLAY_ATTAC              = (HI_ERR_CODE_PMF_BASE + 13),  /* bip�طŹ��� */ /* 13: PMF_BASE + 13 */
    /* bip������У����ʧ�� */
    HI_ERR_CODE_PMF_MMIE_ERR                  = (HI_ERR_CODE_PMF_BASE + 14),  /* 14: PMF_BASE + 14 */
    /* PMFʹ���յ�δ���ܵĵ���ǿ������֡ */
    HI_ERR_CODE_PMF_NO_PROTECTED_ERROR        = (HI_ERR_CODE_PMF_BASE + 15),  /* 15: PMF_BASE + 15 */

    HI_ERR_CODE_PMF_BUTT                      = (HI_ERR_CODE_PMF_BASE + 999), /* 999: PMF_BASE + 999 */
    /********************************* ���� **********************************/
    /***************hostapd/wpa_supplicant�¼��ϱ����·����� *****************/
    HI_ERR_CODE_CFG80211_BASE               = 23000,
    HI_ERR_CODE_CFG80211_SKB_MEM_FAIL       = (HI_ERR_CODE_CFG80211_BASE + 0),  /* skb�����޷�����Ϣͷ������ */
    HI_ERR_CODE_CFG80211_EMSGSIZE           = (HI_ERR_CODE_CFG80211_BASE + 1),  /* ��Ϣ̫��,�����޷���� */
    HI_ERR_CODE_CFG80211_MCS_EXCEED         = (HI_ERR_CODE_CFG80211_BASE + 2),  /* MCS����32 */
    HI_ERR_CODE_CFG80211_ENOBUFS            = (HI_ERR_CODE_CFG80211_BASE + 3),  /* 3: CFG80211_BASE + 3 */

    HI_ERR_CODE_CFG80211_BUTT               = (HI_ERR_CODE_CFG80211_BASE + 999), /* 999: CFG80211_BASE + 999 */

    /********************************* OAL **********************************/
    HI_ERR_CODE_BASE                    = 24000,

    /**************************** OAL --- �ڴ�� ****************************/
    HI_ERR_CODE_MEM_BASE                = (HI_ERR_CODE_BASE + 0),
    HI_ERR_CODE_MEM_GET_POOL_FAIL       = (HI_ERR_CODE_MEM_BASE + 0), /* ��ȡ�ڴ��ȫ��ָ��ʧ�� */
    HI_ERR_CODE_MEM_ALLOC_CTRL_BLK_FAIL = (HI_ERR_CODE_MEM_BASE + 1), /* ������ڴ�ʧ�� */
    /* ��ȡnetbuf subpool idʧ�� */
    HI_ERR_CODE_MEM_SKB_SUBPOOL_ID_ERR  = (HI_ERR_CODE_MEM_BASE + 2), /* 2: MEM_BASE + 2 */
    HI_ERR_CODE_MEM_GET_CFG_TBL_FAIL    = (HI_ERR_CODE_MEM_BASE + 3), /* ��ȡ�ڴ��������Ϣʧ�� */ /* 3: MEM_BASE + 3 */
    HI_ERR_CODE_MEM_EXCEED_MAX_LEN      = (HI_ERR_CODE_MEM_BASE + 4), /* �ڴ����󳤶ȳ������� */ /* 4: MEM_BASE + 4 */
    HI_ERR_CODE_MEM_EXCEED_SUBPOOL_CNT  = (HI_ERR_CODE_MEM_BASE + 5), /* ���ڴ�ظ����������� */ /* 5: MEM_BASE + 5 */
    HI_ERR_CODE_MEM_DOG_TAG             = (HI_ERR_CODE_MEM_BASE + 6), /* �ڴ汻�� */ /* 6: MEM_BASE + 6 */
    /* �ͷ���һ���Ѿ����ͷŵ��ڴ� */
    HI_ERR_CODE_MEM_ALREADY_FREE        = (HI_ERR_CODE_MEM_BASE + 7), /* 7: MEM_BASE + 7 */
    /* �ͷ�һ�����ü���Ϊ0���ڴ� */
    HI_ERR_CODE_MEM_USER_CNT_ERR        = (HI_ERR_CODE_MEM_BASE + 8), /* 8: MEM_BASE + 8 */
    /* �����ڴ����Ŀ�����������ڴ�����ڴ���� */
    HI_ERR_CODE_MEM_EXCEED_TOTAL_CNT    = (HI_ERR_CODE_MEM_BASE + 9), /* 9: MEM_BASE + 9 */
    /**************************** OAL --- �¼� ****************************/
    HI_ERR_CODE_EVENT_BASE              = (HI_ERR_CODE_BASE + 100), /* 100: CODE_BASE + 100 */
    HI_ERR_CODE_EVENT_Q_EMPTY           = (HI_ERR_CODE_EVENT_BASE + 0),
    HI_ERR_CODE_EVENT_BUTT                    = (HI_ERR_CODE_BASE + 999), /* 999: CODE_BASE + 999 */

    /********************************* OAM **********************************/
    HI_ERR_CODE_OAM_BASE                    = 25000,

    /**************************** OAM --- event *****************************/
    HI_ERR_CODE_OAM_EVT_BASE               = (HI_ERR_CODE_OAM_BASE + 0),
    HI_ERR_CODE_OAM_EVT_USER_IDX_EXCEED    = (HI_ERR_CODE_OAM_EVT_BASE + 0),    /* �û������������ֵ */
    HI_ERR_CODE_OAM_EVT_FRAME_DIR_INVALID  = (HI_ERR_CODE_OAM_EVT_BASE + 1),    /* �Ȳ��Ƿ������̣�Ҳ���ǽ������� */
    /* ֡ͷ�����쳣 */
    HI_ERR_CODE_OAM_EVT_FR_HDR_LEN_INVALID = (HI_ERR_CODE_OAM_EVT_BASE + 2),    /* 2: EVT_BASE + 2 */
    /* ֡��(����֡ͷ)�����쳣 */
    HI_ERR_CODE_OAM_EVT_FR_LEN_INVALID     = (HI_ERR_CODE_OAM_EVT_BASE + 3),    /* 3: EVT_BASE + 3 */
    /* �����������쳣 */
    HI_ERR_CODE_OAM_EVT_DSCR_LEN_INVALID   = (HI_ERR_CODE_OAM_EVT_BASE + 4),    /* 4: EVT_BASE + 4 */

    HI_ERR_CODE_OAM_BUTT                    = (HI_ERR_CODE_OAM_BASE + 999),     /* 999: EVT_BASE + 999 */

    /********************************* KeepAlive **********************************/
    HI_ERR_CODE_KEEPALIVE_BASE             = 26000,
    /**************************** KeepAlive --- event *****************************/
    HI_ERR_CODE_KEEPALIVE_CONFIG_VAP       = (HI_ERR_CODE_KEEPALIVE_BASE + 1),
    HI_ERR_CODE_KEEPALIVE_BIG_INTERVAL     = (HI_ERR_CODE_KEEPALIVE_BASE + 2), /* 2: KEEPALIVE_BASE + 2 */
    HI_ERR_CODE_KEEPALIVE_SMALL_LIMIT      = (HI_ERR_CODE_KEEPALIVE_BASE + 3), /* 3: KEEPALIVE_BASE + 3 */
    HI_ERR_CODE_KEEPALIVE_INVALID_VAP      = (HI_ERR_CODE_KEEPALIVE_BASE + 4), /* 4: KEEPALIVE_BASE + 4 */
    HI_ERR_CODE_KEEPALIVE_PTR_NULL         = (HI_ERR_CODE_KEEPALIVE_BASE + 5), /* 5: KEEPALIVE_BASE + 5 */

    HI_ERR_CODE_KEEPALIVE_BUTT             = (HI_ERR_CODE_KEEPALIVE_BASE + 999), /* 999: KEEPALIVE_BASE + 999 */

    /* PROXY ARP���� COMP--skb�������; INCOMP--skbû�д�����ɣ������������� */
    HI_ERR_CODE_PROXY_ARP_BASE                     = 27000,
    HI_ERR_CODE_PROXY_ARP_INVLD_SKB_INCOMP         = (HI_ERR_CODE_PROXY_ARP_BASE + 0), /* ���յ���SKB�쳣 */
    HI_ERR_CODE_PROXY_ARP_LEARN_USR_NOTEXIST_COMP  = (HI_ERR_CODE_PROXY_ARP_BASE + 1), /* GARPԴ��ַ�Ǳ�BSS */
    /* GARPԴ��ַѧϰ�ɹ� */
    HI_ERR_CODE_PROXY_ARP_LEARN_USR_COMP           = (HI_ERR_CODE_PROXY_ARP_BASE + 2),  /* 2: ARP_BASE + 2 */
    /* �� arp reply����BSS */
    HI_ERR_CODE_PROXY_ARP_REPLY2BSS_COMP           = (HI_ERR_CODE_PROXY_ARP_BASE + 3),  /* 3: ARP_BASE + 3 */
    /* �� arp reply��ETH */
    HI_ERR_CODE_PROXY_ARP_REPLY2ETH_COMP           = (HI_ERR_CODE_PROXY_ARP_BASE + 4),  /* 4: ARP_BASE + 4 */
    /* ����SKBʧ�� */
    HI_ERR_CODE_PROXY_ARP_CREATE_FAIL_COMP         = (HI_ERR_CODE_PROXY_ARP_BASE + 5),  /* 5: ARP_BASE + 5 */
    /* ���յ���SKB�쳣 */
    HI_ERR_CODE_PROXY_ND_INVLD_SKB1_INCOMP         = (HI_ERR_CODE_PROXY_ARP_BASE + 6),  /* 6: ARP_BASE + 6 */
    /* ���յ���SKB�쳣 */
    HI_ERR_CODE_PROXY_ND_INVLD_SKB2_INCOMP         = (HI_ERR_CODE_PROXY_ARP_BASE + 7),  /* 7: ARP_BASE + 7 */
    /* ���յ��鲥��arp reply */
    HI_ERR_CODE_PROXY_ARP_REPLY_MCAST_COMP         = (HI_ERR_CODE_PROXY_ARP_BASE + 8),  /* 8: ARP_BASE + 8 */
    /* ���յ�arp reply��ת�� */
    HI_ERR_CODE_PROXY_ARP_REPLY_INCOMP             = (HI_ERR_CODE_PROXY_ARP_BASE + 9),  /* 9: ARP_BASE + 9 */
    /* ����arp req����reply */
    HI_ERR_CODE_PROXY_ARP_NOT_REQ_REPLY_INCOMP     = (HI_ERR_CODE_PROXY_ARP_BASE + 10), /* 10: ARP_BASE + 10 */
    /* ͨ��NSѧϰ��ַ��ap���ָ�ns��Դmac������ */
    HI_ERR_CODE_PROXY_ND_LEARN_USR_NOTEXIST_COMP   = (HI_ERR_CODE_PROXY_ARP_BASE + 11), /* 11: ARP_BASE + 11 */
    /* ͨ��NSѧϰ��ַ��ap���ָ�ipv6��ַ�Ѿ���¼��hash�� */
    HI_ERR_CODE_PROXY_ND_LEARN_USR_ALREADY_EXIST_INCOMP   = (HI_ERR_CODE_PROXY_ARP_BASE + 12), /* 12: ARP_BASE + 12 */
    /* ͨ��NSѧϰ��ַ���� */
    HI_ERR_CODE_PROXY_ND_LEARN_USR_SUCC_COMP      = (HI_ERR_CODE_PROXY_ARP_BASE + 13),  /* 13: ARP_BASE + 13 */
    /* ͨ��NSѧϰ��ַʧ�� */
    HI_ERR_CODE_PROXY_ND_LEARN_USR_FAIL_INCOMP    = (HI_ERR_CODE_PROXY_ARP_BASE + 14),  /* 14: ARP_BASE + 14 */
    /* ��NS��icmpv6 opt�л�ȡllʧ�� */
    HI_ERR_CODE_PROXY_ND_NS_OPT_INVLD_COMP        = (HI_ERR_CODE_PROXY_ARP_BASE + 15),  /* 15: ARP_BASE + 15 */
    /* NS icmpv6�е�target ipv6��ַ����hash���� */
    HI_ERR_CODE_PROXY_ND_NS_FINDUSR_ERR_COMP      = (HI_ERR_CODE_PROXY_ARP_BASE + 16),  /* 16: ARP_BASE + 16 */
    /* ����NAʧ�� */
    HI_ERR_CODE_PROXY_ND_NS_CREATE_NA_FAIL_COMP   = (HI_ERR_CODE_PROXY_ARP_BASE + 17),  /* 17: ARP_BASE + 17 */
    /* �յ�NS��AP�����ظ�NA��BSS */
    HI_ERR_CODE_PROXY_ND_NS_REPLY_NA2BSS_COMP     = (HI_ERR_CODE_PROXY_ARP_BASE + 18),  /* 18: ARP_BASE + 18 */
    /* �Ƿ���NA */
    HI_ERR_CODE_PROXY_ND_NA_INVLD_COMP            = (HI_ERR_CODE_PROXY_ARP_BASE + 19),  /* 19: ARP_BASE + 19 */
    /* ���鲥��Ӧ��NA�� icmpv6 opt��ȡllʧ�� */
    HI_ERR_CODE_PROXY_ND_NA_MCAST_NOT_LLA_COMP    = (HI_ERR_CODE_PROXY_ARP_BASE + 20),  /* 20: ARP_BASE + 20 */
    /* �ӵ�����Ӧ��NA�� icmpv6 opt��ȡllʧ�� */
    HI_ERR_CODE_PROXY_ND_NA_UCAST_NOT_LLA_INCOMP  = (HI_ERR_CODE_PROXY_ARP_BASE + 21),  /* 21: ARP_BASE + 21 */
    /* NA��Я����ipv6��ַ��ͻ */
    HI_ERR_CODE_PROXY_ND_NA_DUP_ADDR_INCOMP       = (HI_ERR_CODE_PROXY_ARP_BASE + 22),  /* 22: ARP_BASE + 22 */
    /* NA��S��־Ϊ0 */
    HI_ERR_CODE_PROXY_ND_NA_UNSOLICITED_COMP      = (HI_ERR_CODE_PROXY_ARP_BASE + 23),  /* 23: ARP_BASE + 23 */
    /* NA��S��־Ϊ1 */
    HI_ERR_CODE_PROXY_ND_NA_SOLICITED_INCOMP      = (HI_ERR_CODE_PROXY_ARP_BASE + 24),  /* 24: ARP_BASE + 24 */
    /* û��Я��icmpv6 */
    HI_ERR_CODE_PROXY_ND_NOT_ICMPV6_INCOMP        = (HI_ERR_CODE_PROXY_ARP_BASE + 25),  /* 25: ARP_BASE + 25 */
    /* ����NS����NA */
    HI_ERR_CODE_PROXY_ND_ICMPV6_NOT_NSNA_INCOMP   = (HI_ERR_CODE_PROXY_ARP_BASE + 26),  /* 26: ARP_BASE + 26 */
    /* arp�е�target ipv4��ַ����hash���� */
    HI_ERR_CODE_PROXY_ARP_FINDUSR_ERR_COMP        = (HI_ERR_CODE_PROXY_ARP_BASE + 27),  /* 27: ARP_BASE + 27 */
    /* ������proxy �����֡ */
    HI_ERR_CODE_PROXY_OTHER_INCOMP                = (HI_ERR_CODE_PROXY_ARP_BASE + 28),  /* 28: ARP_BASE + 28 */
    /* �յ�NS��AP�����ظ�NA��ETH */
    HI_ERR_CODE_PROXY_ND_NS_REPLY_NA2ETH_COMP     = (HI_ERR_CODE_PROXY_ARP_BASE + 29),  /* 29: ARP_BASE + 29 */
    HI_ERR_CODE_PROXY_ARP_BUTT                    = (HI_ERR_CODE_PROXY_ARP_BASE + 499), /* 499: ARP_BASE + 499 */

    /* PSM���� */
    HI_ERR_CODE_PSM_BASE                          = 27500,
    HI_ERR_CODE_PS_QUEUE_OVERRUN                  = (HI_ERR_CODE_PSM_BASE + 0), /* ps������ */

    /********************************* ����ģ�� **********************************/
    HI_ERR_CODE_QUEUE_BASE                             = 28000,
    HI_ERR_CODE_QUEUE_CNT_ZERO                         = (HI_ERR_CODE_QUEUE_BASE + 0),    /* ����Ϊ�� */

    /********************************* SWP CBBģ�� *******************************/
    HI_ERR_CODE_SWP_CBB_BASE                           = 28100,
    HI_ERR_CODE_SWP_CBB_ALREADY_ACTIVE                 = (HI_ERR_CODE_SWP_CBB_BASE + 0),  /* ��ǰCBB�ӿ��Ѿ����� */
    HI_ERR_CODE_SWP_CBB_INT_REGISTER_FAIL              = (HI_ERR_CODE_SWP_CBB_BASE + 1),  /* �жϴ�����ע��ʧ�� */
    /* ���ݳ�����Ч */
    HI_ERR_CODE_SWP_CBB_LENGTH_INVALID                 = (HI_ERR_CODE_SWP_CBB_BASE + 2),  /* 2: CBB_BASE + 2 */
    /* SWP CBB RX��TX�������� */
    HI_ERR_CODE_SWP_CBB_BUFFUR_FULL                    = (HI_ERR_CODE_SWP_CBB_BASE + 3),  /* 3: CBB_BASE + 3 */

    /********************************* Type Aģ�� ********************************/
    HI_ERR_CODE_TYPE_A_BASE       = 28200,
    HI_ERR_CODE_UID_ERR           = (HI_ERR_CODE_TYPE_A_BASE  + 0),  /* UID ����  */
    HI_ERR_TIME_OUT_TIMES_BEYOND  = (HI_ERR_CODE_TYPE_A_BASE  + 1),  /* ��ʱ�������� */
    HI_ERR_LEVEL_BEYOND           = (HI_ERR_CODE_TYPE_A_BASE  + 2),  /* ������������ */ /* 2: TYPE_A_BASE + 2 */

    /********************************* Type A LISTEN NFC-DEPģ�� ********************************/
    HI_ERR_CODE_NFC_DEP_LISTEN_BASE                    = 28300,

    /********************************* Type A POLL NFC-DEPģ�� ********************************/
    HI_ERR_CODE_NFC_DEP_POLL_BASE                      = 28400,

    /********************************* NFC-DEPЭ��ģ�� ********************************/
    HI_ERR_CODE_NFC_DEP_BASE                           = 28500,
    HI_ERR_CODE_NFC_DEP_FRAME_TYPE_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 0),  /* ֡���ʹ��� */
    HI_ERR_CODE_NFC_DEP_FRAME_OPCODE_ERR               = (HI_ERR_CODE_NFC_DEP_BASE + 1),  /* ֡��������� */
    /* DID ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_DID_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 2),  /* 2: NFC_DEP_BASE + 2 */
    /* GEN INFO flag ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_GEN_INFO_FLAG_ERR       = (HI_ERR_CODE_NFC_DEP_BASE + 3),  /* 3: NFC_DEP_BASE + 3 */
    /* DSI ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_DSI_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 4),  /* 4: NFC_DEP_BASE + 4 */
    /* DRI ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_DRI_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 5),  /* 5: NFC_DEP_BASE + 5 */
    /* FSL ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_FSL_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 6),  /* 6: NFC_DEP_BASE + 6 */
    /* MI ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_MI_ERR                  = (HI_ERR_CODE_NFC_DEP_BASE + 7),  /* 7: NFC_DEP_BASE + 7 */
    /* NAD ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_NAD_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 8),  /* 8: NFC_DEP_BASE + 8 */
    /* PNI ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_PNI_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 9),  /* 9: NFC_DEP_BASE + 9 */
    /* PAYLOAD ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_PAYLOAD_ERR             = (HI_ERR_CODE_NFC_DEP_BASE + 10), /* 10: NFC_DEP_BASE + 10 */
    /* sens_res  ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_SENS_RES_ERR            = (HI_ERR_CODE_NFC_DEP_BASE + 11), /* 11: NFC_DEP_BASE + 11 */
    /* sens_res ��������tag1����ͻ�������� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_TAG1_PLT_SUCC           = (HI_ERR_CODE_NFC_DEP_BASE + 12), /* 12: NFC_DEP_BASE + 12 */
    /* SDD_REQ ����ֵ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_CL_ERR                  = (HI_ERR_CODE_NFC_DEP_BASE + 13), /* 13: NFC_DEP_BASE + 13 */
    /* NFCID���� */
    HI_ERR_CODE_NFC_DEP_NFCID_ERR                      = (HI_ERR_CODE_NFC_DEP_BASE + 14), /* 14: NFC_DEP_BASE + 14 */
    /* Cascade��ʶ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_CASCADE_ERR             = (HI_ERR_CODE_NFC_DEP_BASE + 15), /* 15: NFC_DEP_BASE + 15 */
    /* BCCУ����� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_BCC_ERR                 = (HI_ERR_CODE_NFC_DEP_BASE + 16), /* 16: NFC_DEP_BASE + 16 */
    /* CTλ���� */
    HI_ERR_CODE_NFC_DEP_TYPE_A_CT_ERR                  = (HI_ERR_CODE_NFC_DEP_BASE + 17), /* 17: NFC_DEP_BASE + 17 */

    /********************************* NFC CBB ģ��**********************************/
    HI_ERR_CODE_NFC_CBB_BASE                           = 28600,
    HI_ERR_CODE_NFC_RX_CRC_ERR                         = (HI_ERR_CODE_NFC_CBB_BASE + 0),  /* CRC ���� */
    HI_ERR_CODE_NFC_RX_PTY_ERR                         = (HI_ERR_CODE_NFC_CBB_BASE + 1),  /* PTY ���� */
    /* BCC ���� */
    HI_ERR_CODE_NFC_RX_BCC_ERR                         = (HI_ERR_CODE_NFC_CBB_BASE + 2),  /* 2: NFC_CBB_BASE + 2 */
    /* CRPLL ʧ�� ���� */
    HI_ERR_CODE_NFC_CRPLL_UNLOCK_FLAG_ERR              = (HI_ERR_CODE_NFC_CBB_BASE + 3),  /* 3: NFC_CBB_BASE + 3 */
    /* FAILING EDGE ���� */
    HI_ERR_CODE_NFC_LSTNA_FALLING_FALL_ERR             = (HI_ERR_CODE_NFC_CBB_BASE + 4),  /* 4: NFC_CBB_BASE + 4 */
    /* BUFF ���� */
    HI_ERR_CODE_NFC_RX_BUFF_ERR                        = (HI_ERR_CODE_NFC_CBB_BASE + 5),  /* 5: NFC_CBB_BASE + 5 */
    /* FRAME TYPE ���� */
    HI_ERR_CODE_NFC_RX_BUFF_FRAME_TYPE_ERR             = (HI_ERR_CODE_NFC_CBB_BASE + 6),  /* 6: NFC_CBB_BASE + 6 */
    /* INT_REGISTER_FAIL ���� */
    HI_ERR_CODE_CBB_INT_REGISTER_FAIL                  = (HI_ERR_CODE_NFC_CBB_BASE + 7),  /* 7: NFC_CBB_BASE + 7 */
    /* Listenģʽ�����ݷ��ͳ�ʱ */
    HI_ERR_CODE_CBB_LSTN_RX2TX_TO                      = (HI_ERR_CODE_NFC_CBB_BASE + 8),  /* 8: NFC_CBB_BASE + 8 */
    /* type f Listenģʽ���������ݶ�Ӧ���������ʴ��� */
    HI_ERR_CODE_NFC_RX_LSTN_RATE_ERR                   = (HI_ERR_CODE_NFC_CBB_BASE + 9),  /* 9: NFC_CBB_BASE + 9 */

    /********************************* ����ģ�� **********************************/
    HI_ERR_CODE_SCHED_BASE                             = 28700,
    HI_ERR_CODE_SCHED_FSM_EXCEPT_FUN_NULL              = (HI_ERR_CODE_SCHED_BASE + 0),  /* ״̬���쳣������ΪNULL */
    HI_ERR_CODE_SCHED_FSM_STA_TAB_NULL                 = (HI_ERR_CODE_SCHED_BASE + 1),  /* ״̬��״̬��ΪNULL�������� */
    /* �������ID��Ч */
    HI_ERR_CODE_SCHED_PUSH_QUEUE_ID_INVALID            = (HI_ERR_CODE_SCHED_BASE + 2),  /* 2: SCHED_BASE + 2 */

    /********************************* Tag4Bģ�� **********************************/
    HI_ERR_CODE_TAG4B_BASE                = 28800,
    HI_ERR_CODE_TAG4B_NOT_COMPLIANT_14443 = (HI_ERR_CODE_TAG4B_BASE + 0), /* ������14443Э����� */
    HI_ERR_CODE_TAG4B_OPCODE_ERR          = (HI_ERR_CODE_TAG4B_BASE + 1), /* ATTRIB��������� */
    HI_ERR_CODE_TAG4B_TYPE_B_DID_ERR      = (HI_ERR_CODE_TAG4B_BASE + 2), /* DID���� */   /* 2: TAG4B_BASE + 2 */
    HI_ERR_CODE_TAG4B_NFCID_ERR           = (HI_ERR_CODE_TAG4B_BASE + 3), /* NFCID���� */ /* 3: TAG4B_BASE + 3 */
    HI_ERR_CODE_TAG4B_BR_ERR              = (HI_ERR_CODE_TAG4B_BASE + 4), /* ���ʴ��� */  /* 4: TAG4B_BASE + 4 */
    /* PARAM3 b8-b4��Ϊ0 */
    HI_ERR_CODE_TAG4B_PARAM3_MSB_ERR      = (HI_ERR_CODE_TAG4B_BASE + 5), /* 5: TAG4B_BASE + 5 */

    /********************************* ISO-DEPЭ��ģ�� **********************************/
    HI_ERR_CODE_ISO_DEP_BASE                           = 28900,
    HI_ERR_CODE_ISO_DEP_IBLOCK_RETRY_ERR               = (HI_ERR_CODE_ISO_DEP_BASE + 0),  /* IBLOCK�ش��������ֵ���� */
    /* ���ͽ���block���ȴ���FSC���� */
    HI_ERR_CODE_ISO_DEP_OVER_FSC_ERR                   = (HI_ERR_CODE_ISO_DEP_BASE + 1),
    /* ���ͽ���block���ȴ���FSD���� */
    HI_ERR_CODE_ISO_DEP_OVER_FSD_ERR                   = (HI_ERR_CODE_ISO_DEP_BASE + 2),  /* 2: ISO_DEP_BASE + 2 */
    /* BLOCK���ʹ��� */
    HI_ERR_CODE_ISO_DEP_BLOCK_TYPE_ERR                 = (HI_ERR_CODE_ISO_DEP_BASE + 3),  /* 3: ISO_DEP_BASE + 3 */
    /* DID���� */
    HI_ERR_CODE_ISO_DEP_DID_ERR                        = (HI_ERR_CODE_ISO_DEP_BASE + 4),  /* 4: ISO_DEP_BASE + 4 */
    /* NAD���� */
    HI_ERR_CODE_ISO_DEP_NAD_ERR                        = (HI_ERR_CODE_ISO_DEP_BASE + 5),  /* 5: ISO_DEP_BASE + 5 */
    /* BLOCK NUM���� */
    HI_ERR_CODE_ISO_DEP_BN_ERR                         = (HI_ERR_CODE_ISO_DEP_BASE + 6),  /* 6: ISO_DEP_BASE + 6 */
    /* R_ACK�ش��������ֵ���� */
    HI_ERR_CODE_ISO_DEP_ACK_RETRY_ERR                  = (HI_ERR_CODE_ISO_DEP_BASE + 7),  /* 7: ISO_DEP_BASE + 7 */
    /* R_NAK�ش��������ֵ���� */
    HI_ERR_CODE_ISO_DEP_NAK_RETRY_ERR                  = (HI_ERR_CODE_ISO_DEP_BASE + 8),  /* 8: ISO_DEP_BASE + 8 */
    /* S_WTX�ش��������ֵ���� */
    HI_ERR_CODE_ISO_DEP_WTX_RETRY_ERR                  = (HI_ERR_CODE_ISO_DEP_BASE + 9),  /* 9: ISO_DEP_BASE + 9 */
    /* S_DSL�ش��������ֵ���� */
    HI_ERR_CODE_ISO_DEP_DSL_RETRY_ERR                  = (HI_ERR_CODE_ISO_DEP_BASE + 10), /* 10: ISO_DEP_BASE + 10 */
    /* PBC��fix num���� */
    HI_ERR_CODE_ISO_DEP_PCB_FIX_NUM_ERR                = (HI_ERR_CODE_ISO_DEP_BASE + 11), /* 11: ISO_DEP_BASE + 11 */
    /* WTXM���� */
    HI_ERR_CODE_ISO_DEP_WTXM_ERR                       = (HI_ERR_CODE_ISO_DEP_BASE + 12), /* 12: ISO_DEP_BASE + 12 */
    /* Э����� */
    HI_ERR_CODE_ISO_DEP_PROTOCOL_ERR                   = (HI_ERR_CODE_ISO_DEP_BASE + 13), /* 13: ISO_DEP_BASE + 13 */
    /* ���ɻָ��쳣 */
    HI_ERR_CODE_ISO_DEP_UNRECOVERABLE_EXCEPTIOM        = (HI_ERR_CODE_ISO_DEP_BASE + 14), /* 14: ISO_DEP_BASE + 14 */

    /********************************* TYPE BЭ��ģ�� **********************************/
    HI_ERR_CODE_TYPE_B_BASE                            = 29000,
    HI_ERR_CODE_CUR_SLOT_NUM_ERR                       = (HI_ERR_CODE_TYPE_B_BASE + 1),   /* ʱ��������� */
    /* ʱ����������� */
    HI_ERR_CODE_SLOT_NUM_ERR                           = (HI_ERR_CODE_TYPE_B_BASE + 2),   /* 2: YPE_B_BASE + 2 */
    /* SENSB_RES��������� */
    HI_ERR_CODE_TYPE_B_SENSB_RES_OPCODE_ERR            = (HI_ERR_CODE_TYPE_B_BASE + 3),   /* 3: YPE_B_BASE + 3 */
    /* AFI��һ�µĴ��� */
    HI_ERR_CODE_TYPE_B_CR_AFI_ERR                      = (HI_ERR_CODE_TYPE_B_BASE + 4),   /* 4: YPE_B_BASE + 4 */
    /* didֵ������Χ */
    HI_ERR_CODE_DID_OVER_ERR                           = (HI_ERR_CODE_TYPE_B_BASE + 5),   /* 5: YPE_B_BASE + 5 */
    /* FSD����FSCȡֵ���� */
    HI_ERR_CODE_FSD_FSC_TR0_TR1_TR2_VALUE_ERR          = (HI_ERR_CODE_TYPE_B_BASE + 6),   /* 6: YPE_B_BASE + 6 */
    /* MBLȡֵ����ȷ */
    HI_ERR_CODE_MBL_ERR                                = (HI_ERR_CODE_TYPE_B_BASE + 7),   /* 7: YPE_B_BASE + 7 */
    /********************************* TAG4Aģ�� **********************************/
    HI_ERR_CODE_TAG4A_BASE                             = 29100,
    HI_ERR_CODE_TAG4A_ATS_TL_ERR                       = (HI_ERR_CODE_SCHED_BASE + 0),    /* ATS TL���� */
    HI_ERR_CODE_TAG4A_PPS_RES_ERR                      = (HI_ERR_CODE_SCHED_BASE + 1),    /* PPS_RES���� */
    /* PPS_RES DID���� */
    HI_ERR_CODE_TAG4A_PPS_DID_ERR                      = (HI_ERR_CODE_SCHED_BASE + 2),    /* 2: SCHED_BASE + 2 */
    /* RATS ֡ͷ���� */
    HI_ERR_CODE_TAG4A_RATS_OPCODE_ERR                  = (HI_ERR_CODE_SCHED_BASE + 3),    /* 3: SCHED_BASE + 3 */
    /* RATS DID���� */
    HI_ERR_CODE_TAG4A_RATS_DID_ERR                     = (HI_ERR_CODE_SCHED_BASE + 4),    /* 4: SCHED_BASE + 4 */
    /********************************* TYPE FЭ��ģ�� **********************************/
    HI_ERR_CODE_TYPE_F_BASE                            = 29200,
    HI_ERR_CODE_TYPE_F_SENSF_RES_OPCODE_ERR            = (HI_ERR_CODE_TYPE_F_BASE + 1),   /* SENSF_RES��������� */
    /* SENSF_REQ��������� */
    HI_ERR_CODE_TYPE_F_SENSF_REQ_OPCODE_ERR            = (HI_ERR_CODE_TYPE_F_BASE + 2),   /* 2: TYPE_F_BASE + 2 */
    /* SENSF_RES����RD���� */
    HI_ERR_CODE_TYPE_F_SENSF_RES_WITH_RD_ERR           = (HI_ERR_CODE_TYPE_F_BASE + 3),   /* 3: TYPE_F_BASE + 3 */
    /********************************* TAG3Э��ģ�� **********************************/
    HI_ERR_CODE_TAG3_BASE               = 29300,
    HI_ERR_CODE_TAG3_CUP_CMD_OPCODE_ERR = (HI_ERR_CODE_TAG3_BASE + 1),  /* CUP_CMD֡ͷ���� */
    HI_ERR_CODE_TAG3_CUP_RES_OPCODE_ERR = (HI_ERR_CODE_TAG3_BASE + 2),  /* CUP_RES֡ͷ���� */ /* 2: TAG3_BASE + 2 */
    HI_ERR_CODE_TAG3_PAYLOAD_ERR        = (HI_ERR_CODE_TAG3_BASE + 3),  /* PAYLOAD���� */     /* 3: TAG3_BASE + 3 */

    /********************************* NCIЭ��RF DISCOVERYģ�� **********************************/
    HI_ERR_CODE_RF_DISCOVERY_BASE              = 29400,
    HI_ERR_CODE_RF_DISCOVERY_TECH_TYPE_ERR     = (HI_ERR_CODE_RF_DISCOVERY_BASE + 1), /* �������ʹ��� */
    /* ���õ�ģʽ���� */
    HI_ERR_CODE_RF_DISCOVERY_MODE_ERR          = (HI_ERR_CODE_RF_DISCOVERY_BASE + 2), /* 2: RF_DISCOVERY_BASE + 2 */

    /********************************* TECH DETECT ACTģ�� **********************************/
    HI_ERR_CODE_TECH_DETECT_ACT_BASE                   = 29500,
    /* �������Ͷ����������Ĵ��� */
    HI_ERR_CODE_TECH_DETECT_ACT_TECH_TYPE_ERR          = (HI_ERR_CODE_TECH_DETECT_ACT_BASE + 1),

    /********************************* NCIЭ��ģ��**********************************/
    HI_ERR_CODE_NCI_BASE                 = 29600,
    HI_ERR_CODE_NCI_CONFIG_PARAM_INVALID = (HI_ERR_CODE_NCI_BASE + 1), /* ��Ч�Ĳ��� */
    HI_ERR_CODE_NCI_UNKNOWN_MSG          = (HI_ERR_CODE_NCI_BASE + 2), /* ����ʶ������� */     /* 2: NCI_BASE + 2 */
    HI_ERR_CODE_NCI_PAYLOAD_ERR          = (HI_ERR_CODE_NCI_BASE + 3), /* PAYLOAD���� */        /* 3: NCI_BASE + 3 */
    /* Dispatch�еĺ���ΪNULL */
    HI_ERR_CODE_NCI_DISPATCH_FUN_NULL    = (HI_ERR_CODE_NCI_BASE + 4), /* 4: NCI_BASE + 4 */
    HI_ERR_CODE_NCI_VAL_LEN_TOO_SHORT    = (HI_ERR_CODE_NCI_BASE + 5), /* �洢�����Ŀռ䲻�� */ /* 5: NCI_BASE + 5 */
    /* ���յ���Ϣ��װ��治�� */
    HI_ERR_CODE_NCI_RECV_MSG_TOO_BIG     = (HI_ERR_CODE_NCI_BASE + 6), /* 6: NCI_BASE + 6 */
    HI_ERR_CODE_NCI_PARAM_ID_TOO_BIG     = (HI_ERR_CODE_NCI_BASE + 7), /* ������ID������Χ */   /* 7: NCI_BASE + 7 */
    HI_ERR_CODE_NCI_GID_OID_INVALID      = (HI_ERR_CODE_NCI_BASE + 8), /* NCI��Ϣ��GID��OID��Ч */ /* 8: NCI_BASE + 8 */
    /* ���յ���NCI Packet����Ч�� */
    HI_ERR_CODE_NCI_PACKET_INVALID       = (HI_ERR_CODE_NCI_BASE + 9), /* 9: NCI_BASE + 9 */

    /********************************* SHDLCЭ��ģ��**********************************/
    HI_ERR_CODE_SHDLC_BASE                             = 29700,
    /* ���յ���֡�����뵱ǰ״̬���� */
    HI_ERR_RECV_FRAME_TYPE_DIF_FSM                     = (HI_ERR_CODE_SHDLC_BASE + 1),
    /* ���յ���RSET֡��payload���ȳ����޶���Χ */
    HI_ERR_RECV_RSET_LENGTH                            = (HI_ERR_CODE_SHDLC_BASE + 2), /* 2: SHDLC_BASE + 2 */
    /* ���յ�֡������δ֪ */
    HI_ERR_RECV_FRAME_TYPE_UNKNOWN                     = (HI_ERR_CODE_SHDLC_BASE + 3), /* 3: SHDLC_BASE + 3 */
    /* ���յ�֡��I֡��payload���ȳ����޶���Χ */
    HI_ERR_RECV_I_FRAME_LENGTH                         = (HI_ERR_CODE_SHDLC_BASE + 4), /* 4: SHDLC_BASE + 4 */

    /********************************* HW RESET ģ�� *************************************/
    HI_ERR_CODE_HW_RESET_BASE                          = 30600,
    HI_ERR_CODE_HW_RESET_PHY_SAVE_MEMALLOC             = (HI_ERR_CODE_HW_RESET_BASE + 0),
    HI_ERR_CODE_HW_RESET_MAC_SAVE_MEMALLOC             = (HI_ERR_CODE_HW_RESET_BASE + 1),
    HI_ERR_CODE_HW_RESET_MAC_SAVE_SIZELIMIT            = (HI_ERR_CODE_HW_RESET_BASE + 2), /* 2: HW_RESET_BASE + 2 */
    HI_ERR_CODE_HW_RESET_PHY_SAVE_SIZELIMIT            = (HI_ERR_CODE_HW_RESET_BASE + 3), /* 3: HW_RESET_BASE + 3 */
    /* reset����������tx fake queueʧ�� */
    HI_ERR_CODE_HW_RESET_TX_QUEUE_MEMALLOC             = (HI_ERR_CODE_HW_RESET_BASE + 4), /* 4: HW_RESET_BASE + 4 */
    /********************************* MESH ģ�� *************************************/
    HI_ERR_CODE_MESH_BASE = 31000,
    HI_ERR_CODE_MESH_NOT_ACCEPT_PEER = (HI_ERR_CODE_MESH_BASE + 0),  /* ��ǰMESH VAP���޷������������ */
    HI_ERR_CODE_MESH_NOT_MESH_USER = (HI_ERR_CODE_MESH_BASE + 1),    /* �յ�Mesh Action֡ʱ����û����ֲ���Mesh�û� */

    HI_ERR_CODE_BUTT
}hi_err_code_enum;


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#include "hi_types.h"
#endif /* end of oal_err_wifi.h */

