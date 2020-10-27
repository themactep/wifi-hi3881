/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: MAC resource pool master file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include "mac_resource.h"
#include "oal_util.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  ȫ�ֱ�������
*****************************************************************************/
mac_res_hash_stru g_mac_hash_res;

/*****************************************************************************
  ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ��Դ���˳����ͷŶ�̬������ڴ�
 �޸���ʷ      :
  1.��    ��   : 2013��8��27��
    ��    ��   : Hisilicon
*****************************************************************************/
hi_void mac_res_exit(hi_void)
{
    hi_free(HI_MOD_ID_WIFI_DRV, g_mac_hash_res.user_hash_info);
    hi_free(HI_MOD_ID_WIFI_DRV, g_mac_hash_res.pul_idx);
    hi_free(HI_MOD_ID_WIFI_DRV, g_mac_hash_res.puc_user_cnt);

    g_mac_hash_res.user_hash_info = HI_NULL;
    g_mac_hash_res.pul_idx            = HI_NULL;
    g_mac_hash_res.puc_user_cnt       = HI_NULL;
}

/*****************************************************************************
 ��������  : ��ʼ��MAC��Դ������
 �޸���ʷ      :
  1.��    ��   : 2013��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_res_init(hi_void)
{
    hi_u32  loop;
    hi_u8   user_num = oal_mem_get_user_res_num();
    hi_void *hash_info = HI_NULL;
    hi_void *hash_idx  = HI_NULL;
    hi_void *hash_cnt  = HI_NULL;

    /* ��ȫ��̹���6.6����(1) �Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s(&g_mac_hash_res, sizeof(mac_res_hash_stru), 0, sizeof(mac_res_hash_stru));

    /***************************************************************************
            ��ʼ��HASHͰ����Դ��������
    ***************************************************************************/
    hash_info = hi_malloc(HI_MOD_ID_WIFI_DRV, sizeof(mac_res_user_hash_stru) * user_num);
    hash_idx  = hi_malloc(HI_MOD_ID_WIFI_DRV, sizeof(hi_u32) * user_num);
    hash_cnt  = hi_malloc(HI_MOD_ID_WIFI_DRV, sizeof(hi_u8) * user_num);
    if ((hash_info == HI_NULL) || (hash_idx == HI_NULL) || (hash_cnt == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{mac_res_init::malloc fail.}");
        goto exit;
    }
    /* �ڴ��ʼ��0 */
    /* ��ȫ��̹���6.6����(3) �Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(hash_info, (sizeof(mac_res_user_hash_stru) * user_num), 0, (sizeof(mac_res_user_hash_stru) * user_num));
    memset_s(hash_idx, (sizeof(hi_u32) * user_num), 0, (sizeof(hi_u32) * user_num));
    memset_s(hash_cnt, (sizeof(hi_u8) * user_num), 0, (sizeof(hi_u8) * user_num));

    g_mac_hash_res.user_hash_info = hash_info;
    g_mac_hash_res.pul_idx            = hash_idx;
    g_mac_hash_res.puc_user_cnt       = hash_cnt;
    oal_queue_set(&(g_mac_hash_res.queue), g_mac_hash_res.pul_idx, user_num);
    for (loop = 0; loop < user_num; loop++) {
        /* ��ʼֵ������Ƕ�Ӧ�����±�ֵ��1 */
        oal_queue_enqueue(&(g_mac_hash_res.queue), (hi_void *)(uintptr_t)(loop + 1));
        /* ��ʼ����Ӧ�����ü���ֵΪ0 */
        g_mac_hash_res.puc_user_cnt[loop] = 0;
    }
    return HI_SUCCESS;

exit: // ����ʧ��֮�󣬽����ڴ��ͷŵȲ������������⣬lint_t e801�澯����
    if (hash_info != HI_NULL) {
        hi_free(HI_MOD_ID_WIFI_DRV, hash_info);
    }
    if (hash_idx != HI_NULL) {
        hi_free(HI_MOD_ID_WIFI_DRV, hash_idx);
    }
    if (hash_cnt != HI_NULL) {
        hi_free(HI_MOD_ID_WIFI_DRV, hash_cnt);
    }
    return HI_FAIL;
}

/*****************************************************************************
 ��������  : �ͷŶ�ӦHASH���ڴ�
 �������  : ��ӦHASH�ڴ�����
 �� �� ֵ  : HI_SUCCESS/HI_FAIL
 �޸���ʷ      :
  1.��    ��   : 2013��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_res_free_hash(hi_u32 hash_idx)
{
    if (oal_unlikely(hash_idx >= (hi_u32)g_mac_hash_res.queue.max_elements)) {
        return HI_FAIL;
    }
    if (g_mac_hash_res.puc_user_cnt[hash_idx] == 0) {
        oam_error_log1(0, OAM_SF_ANY, "mac_res_free_hash::cnt==0! idx:%d", hash_idx);
        return HI_SUCCESS;
    }
    (g_mac_hash_res.puc_user_cnt[hash_idx])--;
    if (g_mac_hash_res.puc_user_cnt[hash_idx] != 0) {
        return HI_SUCCESS;
    }
    /* �������ֵ��Ҫ��1���� */
    oal_queue_enqueue(&(g_mac_hash_res.queue), (hi_void *)((uintptr_t)hash_idx + 1));
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡһ��HASH��Դ
 �������  : HASH�ڴ�����ֵ
 �� �� ֵ  : HI_SUCCESS/HI_FAIL
 �޸���ʷ      :
  1.��    ��   : 2013��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 mac_res_alloc_hash(hi_u8 *puc_hash_idx)
{
    hi_u32  hash_idx_temp;

    hash_idx_temp = (hi_u32)(uintptr_t)oal_queue_dequeue(&(g_mac_hash_res.queue));
    /* 0Ϊ��Чֵ */
    if (hash_idx_temp == 0) {
        return HI_FAIL;
    }
    *puc_hash_idx = (hi_u8)(hash_idx_temp - 1);
    (g_mac_hash_res.puc_user_cnt[hash_idx_temp - 1])++;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ��Ӧhash�������ڴ�
 �������  : ��Ӧhash�ڴ�����
 �� �� ֵ  : ��Ӧ�ڴ��ַ
 �޸���ʷ      :
  1.��    ��   : 2013��5��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
mac_res_user_hash_stru* mac_res_get_hash(hi_u8 dev_idx)
{
    return &(g_mac_hash_res.user_hash_info[dev_idx]);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

