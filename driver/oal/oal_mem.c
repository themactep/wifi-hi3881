/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Memory management.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_mem.h"
#include "oam_ext_if.h"
#include "hcc_comm.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/* 2 �궨�� */
/*****************************************************************************
  2 �ṹ�嶨��
*****************************************************************************/
/*****************************************************************************
  �ṹ��  : oal_mem_subpool_stat
  �ṹ˵��: ���ڴ��ͳ�ƽṹ�壬ά��ʹ��
*****************************************************************************/
typedef struct {
    hi_u16   us_free_cnt;    /* �����ڴ�ؿ����ڴ���� */
    hi_u16   us_total_cnt;   /* �����ڴ���ڴ������ */
}oal_mem_subpool_stat;

/*****************************************************************************
  �ṹ��  : oal_mem_pool_stat
  �ṹ˵��: �����ڴ��ͳ�ƽṹ�壬ά��ʹ��
*****************************************************************************/
typedef struct {
    hi_u16             us_mem_used_cnt;    /* ���ڴ�������ڴ�� */
    hi_u16             us_mem_total_cnt;   /* ���ڴ��һ���ж����ڴ�� */

    oal_mem_subpool_stat   ast_subpool_stat[WLAN_MEM_MAX_SUBPOOL_NUM];
}oal_mem_pool_stat;

/*****************************************************************************
  �ṹ��  : oal_mem_stat
  �ṹ˵��: �ڴ��ͳ�ƽṹ�壬ά��ʹ��
*****************************************************************************/
typedef struct {
    oal_mem_pool_stat ast_mem_start_stat[OAL_MEM_POOL_ID_BUTT];   /* ��ʼͳ����Ϣ */
    oal_mem_pool_stat ast_mem_end_stat[OAL_MEM_POOL_ID_BUTT];     /* ��ֹͳ����Ϣ */
}oal_mem_stat;

/*****************************************************************************
  3 ȫ�ֱ�������
*****************************************************************************/
/******************************************************************************
    �����������ڴ��������Ϣȫ�ֱ���
*******************************************************************************/
oal_mem_subpool_cfg_stru g_ast_shared_dscr_cfg_table[WLAN_MEM_SHARE_DSCR_SUBPOOL_CNT];

/******************************************************************************
    ���������ڴ��������Ϣȫ�ֱ��� �޸�Ϊ���ݶ��ƻ��û���������
*******************************************************************************/
oal_mem_subpool_cfg_stru g_ast_local_cfg_table[WLAN_MEM_LOCAL_SUBPOOL_CNT];

/******************************************************************************
    �¼��ڴ��������Ϣȫ�ֱ���
*******************************************************************************/
oal_mem_subpool_cfg_stru g_ast_event_cfg_table[WLAN_MEM_EVENT_SUBPOOL_CNT];

/******************************************************************************
    MIB�ڴ��������Ϣȫ�ֱ���
*******************************************************************************/
oal_mem_subpool_cfg_stru g_ast_mib_cfg_table[WLAN_MEM_MIB_SUBPOOL_CNT];

/******************************************************************************
    netbuf�ڴ��������Ϣȫ�ֱ���
*******************************************************************************/
oal_mem_subpool_cfg_stru g_ast_netbuf_cfg_table[OAL_MEM_NETBUF_POOL_ID_BUTT];

/******************************************************************************
    �ܵ��ڴ��������Ϣȫ�ֱ���
*******************************************************************************/
const oal_mem_pool_cfg_stru g_ast_mem_pool_cfg_table[] = {
    /*       �ڴ��ID                           �ڴ�����ڴ�ظ���               ���ֽڶ���      �ڴ��������Ϣ */
    {OAL_MEM_POOL_ID_EVENT,           hi_array_size(g_ast_event_cfg_table),       {0, 0}, g_ast_event_cfg_table},
    {OAL_MEM_POOL_ID_LOCAL,           hi_array_size(g_ast_local_cfg_table),       {0, 0}, g_ast_local_cfg_table},
    {OAL_MEM_POOL_ID_MIB,             hi_array_size(g_ast_mib_cfg_table),         {0, 0}, g_ast_mib_cfg_table},
};

/******************************************************************************
    �ڴ����Ϣȫ�ֱ������洢�����ڴ�����������ڴ����Ϣ
    �����ڴ����ĺ��������ڴ�ȫ�ֱ������в���
*******************************************************************************/
oal_mem_pool_stru g_ast_mem_pool[OAL_MEM_POOL_ID_BUTT];
/******************************************************************************
    malloc�ڴ�ָ���¼
*******************************************************************************/
hi_u8 *g_pauc_pool_base_addr[OAL_MEM_POOL_ID_BUTT] = {HI_NULL};

/* һ���ڴ��ṹ��С + һ��ָ���С */
#define OAL_MEM_CTRL_BLK_SIZE   (sizeof(oal_mem_stru *) + sizeof(oal_mem_stru))

/******************************************************************************
    ���ƿ��ڴ�ռ䣬Ϊ�ڴ��ṹ���ָ���ڴ��ṹ���ָ�����ռ�
    �ɺ���oal_mem_ctrl_blk_alloc����
*******************************************************************************/
oal_mem_ctrl_blk_stru g_ctrl_blk;
hi_u8 g_vap_res_num;      /* vap��Դ���� �ڴ��� api���ָ�� */
hi_u8 g_user_res_num;     /* vap��Դ���� �ڴ��� api���ָ�� */

/*****************************************************************************
 ��������  : ��������֧��ͬʱ������vap���� �û����÷�Χ1-3, mac��̶�ռ��һ������vap,��vap��Դ��Ҫ+1
 �޸���ʷ      :
  1.��    ��   : 2019��6��28��
    ��    ��   : Hisilicon
*****************************************************************************/
hi_u32 oal_mem_set_vap_res_num(const hi_u8 vap_res_num, const hi_u8 vap_spec)
{
    if ((vap_res_num == 0) || (vap_res_num > vap_spec)) {
        hi_diag_log_msg_e1(0, "oal_mem_set_vap_res_num, invalid vap res num = %d!", vap_res_num);
        return HI_FAIL;
    }
    g_vap_res_num = vap_res_num + WLAN_CFG_VAP_NUM_PER_DEVICE;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ����֧��vap����
*****************************************************************************/
hi_u8 oal_mem_get_vap_res_num(hi_void)
{
    return g_vap_res_num;
}

/*****************************************************************************
 ��������  : ��������֧����������û�������VAPʱ���� ��Χ1-8
*****************************************************************************/
hi_u32 oal_mem_set_user_res_num(const hi_u8 user_res_num, const hi_u8 user_spec)
{
    if ((user_res_num == 0) || (user_res_num > user_spec)) {
        hi_diag_log_msg_e1(0, "oal_mem_set_user_res_num, invalid user res num = %d!", user_res_num);
        return HI_FAIL;
    }
    g_user_res_num = user_res_num;
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ����֧����������û�����
*****************************************************************************/
hi_u8 oal_mem_get_user_res_num(hi_void)
{
    return g_user_res_num;
}

/*****************************************************************************
 ��������  : ���ö�Ӧ�ڴ��size��cnt�������ƻ����ã��޸��ڴ������
*****************************************************************************/
hi_u32 oal_mem_set_subpool_config(const oal_mem_subpool_cfg_stru *subpool_cfg, oal_mem_pool_id_enum_uint8 pool_id,
                                  hi_u8 subpool_num)
{
    oal_mem_subpool_cfg_stru    *cfg = HI_NULL;
    hi_u8                       loop;

    if (pool_id >= OAL_MEM_POOL_ID_BUTT) {
        return HI_FAIL;
    }

    cfg = g_ast_mem_pool_cfg_table[pool_id].subpool_cfg_info;
    for (loop = 0; loop < subpool_num; loop++) {
        cfg[loop].us_size = subpool_cfg[loop].us_size;
        cfg[loop].us_cnt = subpool_cfg[loop].us_cnt;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ��Ӧ�ڴ��������ڴ����
 �������  : en_pool_id     : �ڴ��ID
 �������  : pul_total_cnt  : ��Ӧ�ڴ��ռ�õ��ܸ���
*****************************************************************************/
hi_u16 oal_mem_get_total_cnt_in_pool(oal_mem_pool_id_enum_uint8 pool_id)
{
    hi_u16                   us_subpool_idx;
    hi_u16                   us_total_cnt;         /* ���ڴ�����ֽ��� */
    const oal_mem_pool_cfg_stru *mem_pool_cfg = HI_NULL;

    mem_pool_cfg = &g_ast_mem_pool_cfg_table[pool_id];
    us_total_cnt = 0;
    for (us_subpool_idx = 0; us_subpool_idx < mem_pool_cfg->subpool_cnt; us_subpool_idx++) {
        us_total_cnt += mem_pool_cfg->subpool_cfg_info[us_subpool_idx].us_cnt;
    }
    return us_total_cnt;
}

/*****************************************************************************
 ��������  : Ϊÿ���ڴ��ṹ���ָ���ڴ��ṹ���ָ���ṩ�ڴ�
 �������  : ul_size:Ҫ�����ڴ�Ĵ�С
 �� �� ֵ  : ָ��һ���ڴ��ָ�� ���ָ��
*****************************************************************************/
hi_u8* oal_mem_ctrl_blk_alloc(hi_u32 size)
{
    hi_u8 *puc_alloc = HI_NULL;

    size = hi_byte_align(size, 4); /* 4: 4bytes ���� */
    if ((g_ctrl_blk.idx + size) > g_ctrl_blk.max_size) {
        hi_diag_log_msg_e1(0, "oal_mem_ctrl_blk_alloc, not_enough memory, size = %d!", size);
        return HI_NULL;
    }
    puc_alloc = g_ctrl_blk.puc_base_addr + g_ctrl_blk.idx;
    g_ctrl_blk.idx += size;
    return puc_alloc;
}

/*****************************************************************************
 ��������  : �������ڴ��
 �������  : en_pool_id   : �ڴ��ID
             puc_base_addr: �ڴ�ػ���ַ
 �� �� ֵ  : HI_SUCCESS������������
*****************************************************************************/
hi_u32 oal_mem_create_subpool(oal_mem_pool_id_enum_uint8 pool_id, hi_u8 *puc_base_addr)
{
    oal_mem_pool_stru      *mem_pool = HI_NULL;
    oal_mem_subpool_stru   *mem_subpool = HI_NULL;
    oal_mem_stru           *mem = HI_NULL;
    oal_mem_stru          **stack_mem = HI_NULL;
    hi_u8               subpool_id;
    hi_u32              blk_id;

    mem_pool = &g_ast_mem_pool[pool_id];
    /* ��������ڴ��ַ������ÿ���ڴ������һ�Σ�����ָ��ÿ�����ڴ��ʹ�� */
    stack_mem = (oal_mem_stru **)oal_mem_ctrl_blk_alloc(sizeof(oal_mem_stru *) * mem_pool->us_mem_total_cnt);
    if (stack_mem == HI_NULL) {
        hi_diag_log_msg_e0(0, "oal_mem_create_subpool, pointer is NULL!");
        return HI_ERR_CODE_MEM_ALLOC_CTRL_BLK_FAIL;
    }

    /* ����oal_mem_stru�ṹ�壬ÿ���ڴ������һ�Σ�����ָ��ÿ�����ڴ��ʹ�� */
    mem = (oal_mem_stru *)oal_mem_ctrl_blk_alloc(sizeof(oal_mem_stru) * mem_pool->us_mem_total_cnt);
    if (mem == HI_NULL) {
        hi_diag_log_msg_e0(0, "oal_mem_create_subpool, pointer is NULL!");
        return HI_ERR_CODE_MEM_ALLOC_CTRL_BLK_FAIL;
    }

    /* ��ȫ��̹���6.6����(3) �Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(stack_mem, sizeof(oal_mem_stru *) * mem_pool->us_mem_total_cnt, 0,
        sizeof(oal_mem_stru *) * mem_pool->us_mem_total_cnt);
    memset_s((hi_void *)mem, sizeof(oal_mem_stru) * mem_pool->us_mem_total_cnt, 0,
        sizeof(oal_mem_stru) * mem_pool->us_mem_total_cnt);

    /* ��¼���ڴ�س�ʼoal_mem_stru�ṹ��ָ�룬����ڴ���Ϣʱʹ�� */
    mem_pool->mem_start_addr = mem;

    /* ���ø��ӳ������ڴ��ṹ����Ϣ���������ڴ����payload�Ĺ�ϵ */
    for (subpool_id = 0; subpool_id < mem_pool->subpool_cnt; subpool_id++) {
        /* �õ�ÿһ�����ڴ����Ϣ */
        mem_subpool = &(mem_pool->ast_subpool_table[subpool_id]);
        /* �������ڴ���������Ϳ����ڴ�������Ĺ�ϵ */
        mem_subpool->free_stack = (hi_void **)stack_mem;
        oal_spin_lock_init(&mem_subpool->st_spinlock);
        for (blk_id = 0; blk_id < mem_subpool->us_total_cnt; blk_id++) {
            mem->pool_id        = pool_id;
            mem->subpool_id     = subpool_id;
            mem->us_len            = mem_subpool->us_len;
            mem->mem_state_flag = OAL_MEM_STATE_FREE;
            mem->user_cnt       = 0;
            mem->puc_origin_data   = puc_base_addr;       /* ����oal_mem_st���Ӧpayload�Ĺ�ϵ */
            mem->puc_data          = mem->puc_origin_data;
           *stack_mem = mem;
            stack_mem++;
            mem++;
            puc_base_addr += mem_subpool->us_len;
        }
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ����ÿ���ڴ�ص����ڴ�ؽṹ��
 �������  : en_pool_id       : �ڴ��ID
             puc_data_mem_addr: �ڴ�ػ���ַ
 �� �� ֵ  : HI_SUCCESS ������������
*****************************************************************************/
hi_u32 oal_mem_create_pool(oal_mem_pool_id_enum_uint8 pool_id, hi_u8 *puc_base_addr)
{
    hi_u8                           subpool_id = 0;
    hi_u8                           subpool_cnt;
    oal_mem_pool_stru              *mem_pool = HI_NULL;
    oal_mem_subpool_stru           *mem_subpool = HI_NULL;
    const oal_mem_pool_cfg_stru    *mem_pool_cfg = HI_NULL;
    oal_mem_subpool_cfg_stru       *mem_subpool_cfg = HI_NULL;

    mem_pool = &g_ast_mem_pool[pool_id];;
    mem_pool_cfg = &g_ast_mem_pool_cfg_table[pool_id];
    /* ��ʼ���ڴ�ص�ͨ�ñ��� */
    subpool_cnt = mem_pool_cfg->subpool_cnt;
    mem_pool->subpool_cnt  = mem_pool_cfg->subpool_cnt;
    mem_pool->us_mem_used_cnt = 0;
    mem_pool->us_max_byte_len = mem_pool_cfg->subpool_cfg_info[subpool_cnt - 1].us_size;

    if (mem_pool->subpool_cnt > WLAN_MEM_MAX_SUBPOOL_NUM) {
        hi_diag_log_msg_e0(0, "oal_mem_create_pool, exceeds the max subpool number!");
        return HI_ERR_CODE_MEM_EXCEED_SUBPOOL_CNT;
    }

    /* ����ÿһ�����ڴ�� */
    mem_pool->us_mem_total_cnt = 0;
    for (subpool_id = 0; subpool_id < subpool_cnt; subpool_id++)  {
        mem_subpool_cfg           = mem_pool_cfg->subpool_cfg_info + subpool_id;
        mem_subpool               = &(mem_pool->ast_subpool_table[subpool_id]);
        mem_subpool->us_free_cnt  = mem_subpool_cfg->us_cnt;
        mem_subpool->us_total_cnt = mem_subpool_cfg->us_cnt;
        mem_subpool->us_len       = mem_subpool_cfg->us_size;
        mem_pool->us_mem_total_cnt += mem_subpool_cfg->us_cnt;   /* �������ڴ���� */
    }
    return oal_mem_create_subpool(pool_id, puc_base_addr);
}

/*****************************************************************************
 ��������  : �����ڴ�
 �������  : uc_pool_id  : �������ڴ���ڴ��ID
             us_len      : �������ڴ�鳤��
 �� �� ֵ  : �ɹ�: ָ���������ڴ���ʼ��ַ��ָ��
             ʧ��: ��ָ��
*****************************************************************************/
hi_void* oal_mem_alloc(oal_mem_pool_id_enum_uint8 pool_id, hi_u16 us_len)
{
    oal_mem_stru *mem = HI_NULL;

    /* �쳣: ���볤��Ϊ�� */
    if (oal_unlikely(us_len == 0)) {
        return HI_NULL;
    }
    us_len += OAL_MEM_INFO_SIZE;
    mem = oal_mem_alloc_enhanced(pool_id, us_len);
    if (oal_unlikely(mem == HI_NULL)) {
        return HI_NULL;
    }
    mem->puc_data = mem->puc_origin_data + OAL_MEM_INFO_SIZE;
    *((uintptr_t *)(mem->puc_data - OAL_MEM_INFO_SIZE)) = (uintptr_t)mem;
    return (hi_void *)mem->puc_data;
}

/*****************************************************************************
 ��������  : �ͷ��ڴ�
 �������  : p_data      : Ҫ�ͷ��ڴ���ַ
 �� �� ֵ  : HI_SUCCESS ��������������
*****************************************************************************/
hi_u32 oal_mem_free(const hi_void *data)
{
    oal_mem_stru   *mem = HI_NULL;

    if (oal_unlikely(data == HI_NULL)) {
        return HI_ERR_CODE_PTR_NULL;
    }
    mem = (oal_mem_stru *)(*((uintptr_t *)((hi_u8 *)data - OAL_MEM_INFO_SIZE)));
    return oal_mem_free_enhanced(mem);
}

/*****************************************************************************
 ��������  : �ָ�(�ͷ�)�Ѿ�������ڴ�
*****************************************************************************/
hi_void oal_mem_release(hi_void)
{
    hi_u32  pool_id;

    if (g_ctrl_blk.puc_base_addr != HI_NULL) {
        hi_free(HI_MOD_ID_WIFI_DRV, (hi_void *)g_ctrl_blk.puc_base_addr);
        g_ctrl_blk.puc_base_addr = HI_NULL;
    }
    for (pool_id = 0; pool_id < OAL_MEM_POOL_ID_BUTT; pool_id++) {
        if (g_pauc_pool_base_addr[pool_id] != HI_NULL) {
            hi_free(HI_MOD_ID_WIFI_DRV, (hi_void *)g_pauc_pool_base_addr[pool_id]);
            g_pauc_pool_base_addr[pool_id] = HI_NULL;
        }
    }
}

/*****************************************************************************
 ��������  : ��ʼ�����ƿ��ڴ�
*****************************************************************************/
hi_u32 oal_mem_init_ctrl_blk(hi_void)
{
    hi_u16      us_total_cnt = 0;
    hi_u8      pool_id;

    g_ctrl_blk.idx = 0;
    for (pool_id = 0; pool_id < OAL_MEM_POOL_ID_BUTT; pool_id++) {
        us_total_cnt += oal_mem_get_total_cnt_in_pool(pool_id);
    }
    g_ctrl_blk.max_size = (hi_u32)(us_total_cnt * OAL_MEM_CTRL_BLK_SIZE);
    /* �����ڴ� */
    g_ctrl_blk.puc_base_addr = (hi_u8 *)hi_malloc(HI_MOD_ID_WIFI_DRV, g_ctrl_blk.max_size);
    if (g_ctrl_blk.puc_base_addr == HI_NULL) {
        return HI_ERR_CODE_PTR_NULL;
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �ڴ�ģ��ж�ؽӿ�
 �� �� ֵ  : HI_SUCCESS
*****************************************************************************/
hi_void oal_mem_exit(hi_void)
{
    /* ж����ͨ�ڴ�� */
    oal_mem_release();
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

/*****************************************************************************
 ��������  : �����ڴ�
 �������  : uc_pool_id  : �������ڴ���ڴ��ID
             us_len      : �������ڴ�鳤��
 �� �� ֵ  : ������ڴ��ṹ��ָ�룬���ָ��
*****************************************************************************/
oal_mem_stru* oal_mem_alloc_enhanced(oal_mem_pool_id_enum_uint8 pool_id, hi_u16 us_len)
{
    oal_mem_pool_stru    *mem_pool = HI_NULL;
    oal_mem_subpool_stru *mem_subpool = HI_NULL;
    oal_mem_stru         *mem = HI_NULL;
    unsigned long         irq_flag = 0;
    hi_u8                subpool_id;

    /* ��ȡ�ڴ�� */
    mem_pool = &g_ast_mem_pool[pool_id];
#ifdef _PRE_DEBUG_MODE
    us_len += OAL_DOG_TAG_SIZE;
#endif
    /* �쳣: ���볤�Ȳ��ڸ��ڴ����  */
    if (oal_unlikely(us_len > mem_pool->us_max_byte_len)) {
        return HI_NULL;
    }
    for (subpool_id = 0; subpool_id < mem_pool->subpool_cnt; subpool_id++) {
        mem_subpool = &(mem_pool->ast_subpool_table[subpool_id]);
        oal_spin_lock_irq_save(&mem_subpool->st_spinlock, &irq_flag);
        if ((mem_subpool->us_len < us_len) || (mem_subpool->us_free_cnt == 0)) {
            oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
            continue;
        }
        /* ��ȡһ��û��ʹ�õ�oal_mem_stru��� */
        mem_subpool->us_free_cnt--;
        mem = (oal_mem_stru *)mem_subpool->free_stack[mem_subpool->us_free_cnt];
        mem->puc_data          = mem->puc_origin_data;
        mem->user_cnt       = 1;
        mem->mem_state_flag = OAL_MEM_STATE_ALLOC;
        mem_pool->us_mem_used_cnt++;
        oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
        break;
    }
    return mem;
}

hi_u32 oal_mem_free_enhanced(oal_mem_stru *mem)
{
    oal_mem_pool_stru      *mem_pool = HI_NULL;
    oal_mem_subpool_stru   *mem_subpool = HI_NULL;
    unsigned long           irq_flag;

    if (oal_unlikely(mem == HI_NULL)) {
        return HI_ERR_CODE_PTR_NULL;
    }
    if (mem->pool_id >= OAL_MEM_POOL_ID_BUTT) {
        return HI_ERR_CODE_PTR_NULL;
    }
    mem_pool = &g_ast_mem_pool[mem->pool_id];
    if (mem->subpool_id >= mem_pool->subpool_cnt) {
        return HI_ERR_CODE_PTR_NULL;
    }
    mem_subpool = &(mem_pool->ast_subpool_table[mem->subpool_id]);
    oal_spin_lock_irq_save(&mem_subpool->st_spinlock, &irq_flag);
    /* �쳣: �ͷ�һ���Ѿ����ͷŵ��ڴ� */
    if (oal_unlikely(mem->mem_state_flag == OAL_MEM_STATE_FREE)) {
        oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
        return HI_ERR_CODE_MEM_ALREADY_FREE;
    }
    /* �쳣: �ͷ�һ�����ü���Ϊ0���ڴ� */
    if (oal_unlikely(mem->user_cnt == 0)) {
        oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
        return HI_ERR_CODE_MEM_USER_CNT_ERR;
    }
    mem->user_cnt--;
    /* ���ڴ�����Ƿ������������û���ֱ�ӷ��� */
    if (mem->user_cnt != 0) {
        oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
        return HI_SUCCESS;
    }
    /* �쳣: �����ڴ�ؿ����ڴ����Ŀ�����������ڴ�����ڴ���� */
    if (oal_unlikely(mem_subpool->us_free_cnt >= mem_subpool->us_total_cnt)) {
        oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
        return HI_ERR_CODE_MEM_EXCEED_TOTAL_CNT;
    }
    mem->mem_state_flag = OAL_MEM_STATE_FREE;
    mem_subpool->free_stack[mem_subpool->us_free_cnt] = (hi_void *)mem;
    mem_subpool->us_free_cnt++;
    mem_pool->us_mem_used_cnt--;
    oal_spin_unlock_irq_restore(&mem_subpool->st_spinlock, &irq_flag);
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : ��ȡ��Ӧ�ڴ��ռ�õ����ֽ���
 �������  : en_pool_id     : �ڴ��ID
 �������  : pul_total_bytes: ��Ӧ�ڴ��ռ�õ����ֽ���
*****************************************************************************/
hi_u32 oal_mem_get_total_bytes_in_pool(oal_mem_pool_id_enum_uint8 pool_id)
{
    hi_u32                      total_bytes = 0;         /* ���ڴ�����ֽ��� */
    oal_mem_subpool_cfg_stru    *mem_subpool_cfg = HI_NULL;
    hi_u16                      us_size;
    hi_u16                      us_cnt;
    hi_u8                       subpool_idx;
    hi_u8                       subpool_cnt;

    mem_subpool_cfg = g_ast_mem_pool_cfg_table[pool_id].subpool_cfg_info;
    subpool_cnt = g_ast_mem_pool_cfg_table[pool_id].subpool_cnt;

    for (subpool_idx = 0; subpool_idx < subpool_cnt; subpool_idx++) {
        us_size = mem_subpool_cfg[subpool_idx].us_size;
        us_cnt  = mem_subpool_cfg[subpool_idx].us_cnt;
        total_bytes += us_size * us_cnt;
    }
    return total_bytes;
}

/*****************************************************************************
 ��������  : ��ʼ��ȫ���ڴ��
 �� �� ֵ  : HI_SUCCESS ������������
*****************************************************************************/
hi_u32 oal_mem_init_pool(hi_void)
{
    hi_u32    total_bytes;
    hi_u32    pool_id;
    hi_u32    ret;
    hi_u8    *puc_base_addr = HI_NULL;

    if (oal_mem_init_ctrl_blk() != HI_SUCCESS) {
        hi_diag_log_msg_e0(0, "oal_mem_init_pool, init ctrl blk fail!");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    for (pool_id = 0; pool_id < OAL_MEM_POOL_ID_BUTT; pool_id++) {
        total_bytes = oal_mem_get_total_bytes_in_pool((hi_u8)pool_id);
        puc_base_addr = (hi_u8 *)hi_malloc(HI_MOD_ID_WIFI_DRV, total_bytes);
        if (puc_base_addr == HI_NULL) {
            oal_mem_release();
            hi_diag_log_msg_e1(0, "oal_mem_init_pool, memory allocation fail, size=%d!", total_bytes);
            return HI_ERR_CODE_ALLOC_MEM_FAIL;
        }
        /* ��¼ÿ���ڴ��oal_malloc����ĵ�ַ */
        g_pauc_pool_base_addr[pool_id] = puc_base_addr;
        puc_base_addr = (hi_u8 *)hi_byte_align((uintptr_t)puc_base_addr, 4); /* 4: 4bytes ���� */
        ret = oal_mem_create_pool((hi_u8)pool_id, puc_base_addr);
        if (ret != HI_SUCCESS)  {
            oal_mem_release();
            hi_diag_log_msg_e0(0, "oal_mem_init_pool, oal_mem_create_pool failed!");
            return ret;
        }
    }
    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
