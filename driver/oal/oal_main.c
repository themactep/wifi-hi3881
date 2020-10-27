/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: OAL module initialization.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_main.h"
#include "oal_mem.h"
#include "oal_net.h"
#include "oam_ext_if.h"
#include "hcc_hmac_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : �������õ���Դ������ʼ����Դ������
*****************************************************************************/
static hi_u32 oal_main_init_mem_pool_cfg(const hi_u8 vap_num, const hi_u8 user_num)
{
    hi_u16 mem_dog_size = OAL_MEM_INFO_SIZE + OAL_DOG_TAG_SIZE;

    /* ���ر����ڴ�ظ��ӳػ���ʹ������, �������ؼ�ʹ�õ����� */
    oal_mem_subpool_cfg_stru ast_base_cfg[WLAN_MEM_LOCAL_SUBPOOL_CNT] = {
        {WLAN_MEM_LOCAL_SIZE1 + mem_dog_size, 22}, {WLAN_MEM_LOCAL_SIZE2 + mem_dog_size, 10},
        {WLAN_MEM_LOCAL_SIZE3 + mem_dog_size, 3},  {WLAN_MEM_LOCAL_SIZE4 + mem_dog_size, 2},
        {WLAN_MEM_LOCAL_SIZE5 + mem_dog_size, 3},  {WLAN_MEM_LOCAL_SIZE6 + mem_dog_size, 0}};
    oal_mem_subpool_cfg_stru ast_event_cfg[WLAN_MEM_EVENT_SUBPOOL_CNT];
    oal_mem_subpool_cfg_stru ast_local_cfg[WLAN_MEM_LOCAL_SUBPOOL_CNT];
    oal_mem_subpool_cfg_stru ast_mib_cfg[WLAN_MEM_MIB_SUBPOOL_CNT] = {{WLAN_MEM_MIB_SIZE, vap_num}};
    hi_u8 user_base[] = {18, 0, 3, 1, 0, 2};  /* ���ر����ڴ�ظ��ӳ�:����û�ʱʹ������ */
    hi_u8 vap_base[]  = {15, 20, 2, 5, 0, 0};  /* ���ر����ڴ�ظ��ӳ�:���vapʱʹ������ */

    /* �¼���֧�ֵ��û������Լ���������ģʽ���� */
    ast_event_cfg[0].us_size = WLAN_MEM_EVENT_SIZE1 + mem_dog_size;
    ast_event_cfg[1].us_size = WLAN_MEM_EVENT_SIZE2 + mem_dog_size;
    ast_event_cfg[0].us_cnt  = (user_num == 1) ? WLAN_MEM_EVENT_CNT1 : WLAN_MEM_EVENT_MULTI_USER_CNT1;
    ast_event_cfg[1].us_cnt  = (user_num == 1) ? WLAN_MEM_EVENT_CNT2 : WLAN_MEM_EVENT_MULTI_USER_CNT2;

    hi_u32 ret = oal_mem_set_subpool_config(ast_event_cfg, OAL_MEM_POOL_ID_EVENT, WLAN_MEM_EVENT_SUBPOOL_CNT);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* 01:����֧�ֵ��û��������ñ��ر����ڴ�� */
    for (hi_u8 loop = 0; loop < WLAN_MEM_LOCAL_SUBPOOL_CNT; loop++) {
        ast_local_cfg[loop].us_size = ast_base_cfg[loop].us_size;

        /* ����vap��ʹ�������ڻ�׼ֵ���� */
        ast_local_cfg[loop].us_cnt = ast_base_cfg[loop].us_cnt + user_num * user_base[loop] + vap_num * vap_base[loop];
    }

    ret = oal_mem_set_subpool_config(ast_local_cfg, OAL_MEM_POOL_ID_LOCAL, WLAN_MEM_LOCAL_SUBPOOL_CNT);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    /* 02:����֧�ֵ�vap��������MIB�ڴ�� mib���ӳ�ֻ��һ�� ����vapû��mib,������vap��Դ��-1 */
    ret = oal_mem_set_subpool_config(ast_mib_cfg, OAL_MEM_POOL_ID_MIB, WLAN_MEM_MIB_SUBPOOL_CNT);
    if (ret != HI_SUCCESS) {
        return ret;
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : OALģ���ʼ������ڣ�����OALģ���ڲ��������Եĳ�ʼ����
 �� �� ֵ  : ��ʼ������ֵ���ɹ���ʧ��ԭ��
*****************************************************************************/
hi_u32 oal_main_init(const hi_u8 vap_num, const hi_u8 user_num)
{
    /* �����û����õ�vap ��user��Դ�� */
    if ((oal_mem_set_vap_res_num(vap_num, WLAN_SERVICE_VAP_NUM_PER_DEVICE) != HI_SUCCESS) ||
        (oal_mem_set_user_res_num(user_num, WLAN_ACTIVE_USER_MAX_NUM) != HI_SUCCESS)) {
        oam_error_log0(0, 0, "oal_main_init: set user/vap failed.");
        return HI_FAIL;
    }
    /* �ڴ�����ó�ʼ�� vap user����ǰ���Ѿ���У�� */
    if (oal_main_init_mem_pool_cfg(vap_num, user_num) != HI_SUCCESS) {
        oam_error_log0(0, 0, "oal_main_init: init mem pool cfg failed.");
        return HI_FAIL;
    }
    /* �ڴ�س�ʼ�� */
    if (oal_mem_init_pool() != HI_SUCCESS) {
        oam_error_log0(0, 0, "oal_main_init: oal_mem_init_pool failed.");
        return HI_FAIL;
    }
    printk("oal_main_init SUCCESSFULLY\r\n");
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : OALģ��ж��
 �� �� ֵ  : ģ��ж�ط���ֵ���ɹ���ʧ��ԭ��
*****************************************************************************/
hi_void oal_main_exit(hi_void)
{
#ifndef _PRE_LINUX_BUILTIN
    hcc_hmac_exit();
#endif
    /* �ڴ��ж�� */
    oal_mem_exit();

    printk("oal_main_exit SUCCESSFULLY\r\n");
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
