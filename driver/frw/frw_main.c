/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: FRW module initialization and uninstallation.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "frw_main.h"
#include "frw_event.h"
#include "frw_timer.h"
#include "frw_task.h"
#include "oam_ext_if.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
/* ROM������Ԥ���Ļص��ӿ� */
hi_void*     g_frw_rom_resv_func_cb[FRW_ROM_RESV_FUNC_BUTT] = {HI_NULL};
frw_init_enum_uint8 g_wlan_driver_init_state = FRW_INIT_STATE_BUTT;
hi_bool             g_frw_offload = HI_FALSE;    /* Ĭ�Ϸ�offloadģʽ */

/*****************************************************************************
 ��������  : ʵ��ROM��Ԥ����������ע�ᣬ�����ÿջ������ö�Ӧ�Ĺ��Ӻ���
*****************************************************************************/
hi_void frw_set_rom_resv_func(frw_rom_resv_func_enum_uint8 func_id, hi_void *func)
{
    if (func_id >= FRW_ROM_RESV_FUNC_BUTT) {
        return;
    }

    g_frw_rom_resv_func_cb[func_id] = func;
}

/*****************************************************************************
 ��������  : ��ȡ��Ӧ��Ԥ�����Ӻ���
*****************************************************************************/
hi_void *frw_get_rom_resv_func(frw_rom_resv_func_enum_uint8 func_id)
{
    if (func_id >= FRW_ROM_RESV_FUNC_BUTT) {
        return HI_NULL;
    }

    return g_frw_rom_resv_func_cb[func_id];
}

/*****************************************************************************
 ��������  : ����wifi�����ܹ�: OFFLOAD-TRUE ���߷�OFFLOAD-FALSE
*****************************************************************************/
hi_void frw_set_offload_mode(hi_bool mode)
{
    g_frw_offload = mode;
}

/*****************************************************************************
 ��������  : ��ȡwifi�����ܹ�: OFFLOAD-TRUE ���߷�OFFLOAD-FALSE
*****************************************************************************/
hi_bool frw_get_offload_mode(hi_void)
{
    return g_frw_offload;
}

/*****************************************************************************
 ��������  : FRWģ��ж��

 �޸���ʷ      :
  1.��    ��   : 2012��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void frw_main_exit(hi_void)
{
    /* ж���¼�����ģ�� */
    frw_event_exit();
    /* FRW Task exit */
    frw_task_exit();
    /* ж�سɹ�������״̬λ */
    frw_set_init_state(FRW_INIT_STATE_START);

    printk("frw_main_exit SUCCESSFULLY\r\n");
}

/*****************************************************************************
 ��������  : ���ó�ʼ��״̬
 �������  : ��ʼ��״̬
 �޸���ʷ      :
  1.��    ��   : 2012��11��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_void frw_set_init_state(frw_init_enum_uint8 init_state)
{
    if (init_state >= FRW_INIT_STATE_BUTT) {
        return;
    }
    g_wlan_driver_init_state = init_state;
}

/*****************************************************************************
 ��������  : ��ȡ��ʼ��״̬
 �������  : ��ʼ��״̬
 �޸���ʷ      :
  1.��    ��   : 2012��11��15��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
frw_init_enum_uint8 frw_get_init_state(hi_void)
{
    return g_wlan_driver_init_state;
}

/*****************************************************************************
 ��������  : FRWģ���ʼ������ڣ�����FRWģ���ڲ��������Եĳ�ʼ����
 �������  : TRUE-OFFLOADģʽ FALSE-��OFFLOADģʽ
 �� �� ֵ  : ��ʼ������ֵ���ɹ���ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��9��18��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 frw_main_init(hi_bool mode, hi_u32 task_size)
{
    hi_unref_param(task_size);
    frw_set_init_state(FRW_INIT_STATE_START);
    /* �¼�����ģ���ʼ�� */
    if (oal_unlikely(frw_event_init() != HI_SUCCESS)) {
        oam_error_log0(0, 0, "{frw_main_init:: frw_event_init fail.}");
        return HI_FAIL;
    }
    frw_timer_init();

    if (oal_unlikely(frw_task_init() != HI_SUCCESS)) {
        oam_error_log0(0, 0, "{frw_main_init:: frw_task_init fail.}");
        frw_main_exit();    /* ʧ�ܺ����ģ���˳������ͷ������ڴ� */
        return HI_FAIL;
    }
    frw_set_offload_mode(mode);
    /* �����ɹ��������ӡ ����״̬ʼ�շ���� */
    frw_set_init_state(FRW_INIT_STATE_FRW_SUCC);

    printk("frw_main_init SUCCESSFULLY!\r\n");
    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

