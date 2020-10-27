/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Wal msg processing interface function.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "hmac_ext_if.h"
#include "wal_event_msg.h"
#include "wal_main.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
static wal_msg_queue g_wal_wid_msg_queue;

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
hi_atomic g_wal_config_seq_num = hi_atomic_init(0);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
hi_atomic g_wal_config_seq_num = hi_atomic_init(0);
#else
hi_atomic g_wal_config_seq_num = 0;
#endif
/* ��ȡmsg���кź� */
#define wal_get_msg_sn()    (hi_atomic_inc_return(&g_wal_config_seq_num))

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : wal_msg_queue_init
 ��������  : init the wid response queue
 �������  :
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��11��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_msg_queue_init(hi_void)
{
    if (memset_s((hi_void*)&g_wal_wid_msg_queue, sizeof(g_wal_wid_msg_queue), 0, sizeof(g_wal_wid_msg_queue)) != EOK) {
        oam_error_log0(0, 0, "{wal_msg_queue_init::mem safe func err!}");
        return;
    }
    hi_list_init(&g_wal_wid_msg_queue.head);
    g_wal_wid_msg_queue.count = 0;
    hi_wait_queue_init_head(&g_wal_wid_msg_queue.wait_queue);
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock_init(&g_wal_wid_msg_queue.st_lock);
#endif
}

static hi_void _wal_msg_request_add_queue_(wal_msg_request_stru* msg)
{
    hi_list_head_insert_optimize(&msg->entry, &g_wal_wid_msg_queue.head);
    g_wal_wid_msg_queue.count++;
}

hi_u32 wal_check_and_release_msg_resp(wal_msg_stru   *rsp_msg)
{
    wal_msg_write_rsp_stru     *write_rsp_msg = HI_NULL;
    if (rsp_msg != HI_NULL) {
        hi_u32 err_code;
        wlan_cfgid_enum_uint16 wid;
        write_rsp_msg = (wal_msg_write_rsp_stru *)(rsp_msg->auc_msg_data);
        err_code = write_rsp_msg->err_code;
        wid = write_rsp_msg->wid;

        oal_free(rsp_msg);

        if (err_code != HI_SUCCESS) {
            oam_warning_log2(0, OAM_SF_SCAN, "{wal_check_and_release_msg_resp::detect err code:[%u],wid:[%u]}",
                             err_code, wid);
            return err_code;
        }
    }

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_msg_request_add_queue
 ��������  : add the request message into queue
 �������  : wal_msg_request_stru* pst_msg
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��11��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_msg_request_add_queue(wal_msg_request_stru* msg)
{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
    _wal_msg_request_add_queue_(msg);
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock_bh(&g_wal_wid_msg_queue.st_lock);
    _wal_msg_request_add_queue_(msg);
    oal_spin_unlock_bh(&g_wal_wid_msg_queue.st_lock);
#endif
}

static hi_void _wal_msg_request_remove_queue_(wal_msg_request_stru* msg)
{
    g_wal_wid_msg_queue.count--;
    hi_list_delete_optimize(&msg->entry);
}

/*****************************************************************************
 �� �� ��  : wal_msg_request_remove_queue
 ��������  : remove the request message into queue
 �������  : wal_msg_request_stru* pst_msg
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��11��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void wal_msg_request_remove_queue(wal_msg_request_stru* msg)
{
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
    _wal_msg_request_remove_queue_(msg);
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock_bh(&g_wal_wid_msg_queue.st_lock);
    _wal_msg_request_remove_queue_(msg);
    oal_spin_unlock_bh(&g_wal_wid_msg_queue.st_lock);
#endif
}

/*****************************************************************************
 �� �� ��  : wal_set_msg_response_by_addr
 ��������  : set the request message response by the request message's address, the address is only
 �������  : wal_msg_request_stru* pst_msg
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��11��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_set_msg_response_by_addr(hi_u32 addr, hi_u8 *resp_mem, hi_u32 resp_ret, hi_u32 rsp_len)
{
    hi_u32                ret = HI_FAIL;
    hi_list              *pos = HI_NULL;
    hi_list              *entry_temp = HI_NULL;
    wal_msg_request_stru *request = HI_NULL;

#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock_bh(&g_wal_wid_msg_queue.st_lock);
#endif
    hi_list_for_each_safe(pos, entry_temp, (&g_wal_wid_msg_queue.head)) {
        request = (wal_msg_request_stru *)hi_list_entry(pos, wal_msg_request_stru, entry);
        if (request->request_address == (hi_u32)addr) {
            /* address match */
            if (oal_unlikely(request->resp_mem != NULL)) {
                oam_error_log0(0, OAM_SF_ANY,
                    "{wal_set_msg_response_by_addr::wal_set_msg_response_by_addr response had been set!");
            }
            request->resp_mem = resp_mem;
            request->ret = resp_ret;
            request->resp_len = rsp_len;
            ret = HI_SUCCESS;
            break;
        }
    }
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_unlock_bh(&g_wal_wid_msg_queue.st_lock);
#endif

    return ret;
}

/*****************************************************************************
 �� �� ��  : wal_alloc_cfg_event
 ��������  : WAL�����¼���������¼�ͷ
 �������  : pst_net_dev: net_device
 �������  : ppst_event_mem: ָ���¼��ڴ�
             ppst_cfg_priv : ָ��˽�����ýṹ
             ppst_cfg_msg  : ָ��������Ϣ
 �� �� ֵ  : ������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��1��17��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  wal_alloc_cfg_event(oal_net_device_stru *netdev, frw_event_mem_stru **event_mem,
                            hi_void* resp_addr, wal_msg_stru **cfg_msg, hi_u16 us_len)
{
    mac_vap_stru               *mac_vap = HI_NULL;
    frw_event_mem_stru         *event_mem_info = HI_NULL;
    frw_event_stru             *event = HI_NULL;
    hi_u16                  us_resp_len = 0;

    wal_msg_rep_hdr* rep_hdr = NULL;

    mac_vap = oal_net_dev_priv(netdev);
    if (oal_unlikely(mac_vap == HI_NULL)) {
        /* ���wifi�ر�״̬�£��·�hipriv������ʾerror��־ */
        oam_warning_log1(0, OAM_SF_ANY,
            "{wal_alloc_cfg_event::oal_net_dev_priv(pst_net_dev) is null ptr! pst_net_dev=[%p]}", (uintptr_t)netdev);
        return HI_ERR_CODE_PTR_NULL;
    }

    us_resp_len += sizeof(wal_msg_rep_hdr);
    us_len += us_resp_len;
    event_mem_info = frw_event_alloc(us_len);
    if (oal_unlikely(event_mem_info == HI_NULL)) {
        oam_error_log2(mac_vap->vap_id, OAM_SF_ANY,
            "{wal_alloc_cfg_event::event_mem null ptr error,request size:us_len:%d,resp_len:%d}",
            us_len, us_resp_len);
        return HI_ERR_CODE_PTR_NULL;
    }

    *event_mem = event_mem_info;    /* ���θ�ֵ */
    event = (frw_event_stru *)event_mem_info->puc_data;
    /* ��д�¼�ͷ */
    frw_event_hdr_init(&(event->event_hdr),
                       FRW_EVENT_TYPE_HOST_CRX,
                       WAL_HOST_CRX_SUBTYPE_CFG,
                       us_len,
                       FRW_EVENT_PIPELINE_STAGE_0,
                       mac_vap->vap_id);

    /* fill the resp hdr */
    rep_hdr = (wal_msg_rep_hdr*)event->auc_event_data;
    if (resp_addr == NULL) {
        /* no response */
        rep_hdr->request_address = (uintptr_t)0;
    } else {
        /* need response */
        rep_hdr->request_address = (uintptr_t)resp_addr;
    }

    *cfg_msg = (wal_msg_stru *)((hi_u8*)event->auc_event_data + us_resp_len);  /* ���θ�ֵ */

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_request_wait_event_condition
 ��������  : �ж�wal response ��������Ƿ�����
 �������  : wal_msg_request_stru *pst_msg_stru

 �������  :
 �� �� ֵ  : ������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��11��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static inline hi_u32 wal_request_wait_event_condition(const wal_msg_request_stru *msg_stru)
{
    hi_u32 l_ret = HI_FALSE;
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    hi_task_lock();
    if ((msg_stru->resp_mem != NULL) || (msg_stru->ret != HI_SUCCESS)) {
        l_ret = HI_TRUE;
    }
    hi_task_unlock();
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_spin_lock_bh(&g_wal_wid_msg_queue.st_lock);
    if ((msg_stru->resp_mem != NULL) || (msg_stru->ret != HI_SUCCESS)) {
        l_ret = HI_TRUE;
    }
    oal_spin_unlock_bh(&g_wal_wid_msg_queue.st_lock);
#endif
    return l_ret;
}

hi_void wal_cfg_msg_task_sched(hi_void)
{
    hi_wait_queue_wake_up(&g_wal_wid_msg_queue.wait_queue);
}

hi_u32 wal_send_cfg_wait_event(wal_msg_stru **rsp_msg, wal_msg_request_stru* msg_request)
{
    /***************************************************************************
        �ȴ��¼�����
    ***************************************************************************/
    wal_wake_lock();

    /* info, boolean argument to function */ /* ʹ�÷�wifiĿ¼����꺯��,�󱨸澯,lin_t e26�澯���� */
    hi_u32 wal_ret = (hi_u32)hi_wait_event_timeout(g_wal_wid_msg_queue.wait_queue,
        HI_TRUE == wal_request_wait_event_condition(msg_request), (10 * HZ)); /* 10 Ƶ�� */
    /* response had been set, remove it from the list */
    wal_msg_request_remove_queue(msg_request);

    if (oal_warn_on(wal_ret == 0)) {
        /* ��ʱ */
        oam_warning_log2(0, OAM_SF_ANY, "[E]timeout,request ret=%d,addr:0x%lx\n",
            msg_request->ret, msg_request->request_address);
        if (msg_request->resp_mem != HI_NULL) {
            oal_free(msg_request->resp_mem);
            msg_request->resp_mem = HI_NULL;
        }
        wal_wake_unlock();
        return HI_FAIL;
    }

    wal_msg_stru *rsp_msg_info = (wal_msg_stru *)(msg_request->resp_mem);
    if (rsp_msg_info == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_send_cfg_event:: msg mem null!}");
        /* ������need_rsp�ǿգ�����֤���rsp_msg�ǿգ��󱨸澯��lin_t e613�澯���� */
        *rsp_msg  = HI_NULL;

        wal_wake_unlock();
        return HI_FAIL;
    }

    if (rsp_msg_info->msg_hdr.us_msg_len == 0) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_send_cfg_event:: no msg resp!}");
        /* ������need_rsp�ǿգ�����֤���rsp_msg�ǿգ��󱨸澯��lin_t e613�澯���� */
        *rsp_msg  = HI_NULL;

        oal_free(rsp_msg_info);

        wal_wake_unlock();
        return HI_FAIL;
    }
    /* ���������¼����ص�״̬��Ϣ */
    /* ������need_rsp�ǿգ�����֤���rsp_msg�ǿգ��󱨸澯��lin_t e613�澯���� */
    *rsp_msg  = rsp_msg_info;

    wal_wake_unlock();
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : wal_send_cfg_event
 ��������  : WAL�����¼�
 �������  : pst_net_dev: net_device
             en_msg_type: ��Ϣ����
             uc_len:      ��Ϣ����
             puc_param:   ��Ϣ��ַ
             en_need_rsp: �Ƿ���Ҫ������Ϣ����: HI_TRUE-��; HI_FALSE-��

 �������  : ppst_rsp_msg ����ָ�룬���ص�response ��̬�ڴ���Ҫ��free�ͷ�!
 �� �� ֵ  : ������
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��6��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 wal_send_cfg_event(oal_net_device_stru *netdev, wal_msg_type_enum_uint8 msg_type,
                          hi_u16 us_len, const hi_u8 *puc_param, hi_u8 need_rsp,
                          wal_msg_stru **rsp_msg)
{
    wal_msg_stru                *cfg_msg = HI_NULL;
    frw_event_mem_stru          *event_mem = HI_NULL;
    wal_msg_request_stru         msg_request;

    /* ����6.6����ֹʹ���ڴ������Σ�պ��� ����(1)�Թ̶����ȵ�������г�ʼ������Թ̶����ȵĽṹ������ڴ��ʼ�� */
    memset_s((&msg_request), sizeof(msg_request), 0, sizeof(msg_request));
    msg_request.request_address = (uintptr_t)&msg_request;

    if (rsp_msg != NULL) {
        *rsp_msg = NULL;
    }

    if (oal_warn_on((need_rsp == HI_TRUE) && (rsp_msg == HI_NULL))) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_send_cfg_event::HI_NULL == ppst_rsp_msg!}\r\n");
        return HI_FAIL;
    }
    /* �����¼� */
    if (oal_unlikely(wal_alloc_cfg_event(netdev, &event_mem, ((need_rsp == HI_TRUE) ? &msg_request : NULL),
        &cfg_msg, WAL_MSG_WRITE_MSG_HDR_LENGTH + us_len) != HI_SUCCESS)) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_send_cfg_event::wal_alloc_cfg_event return err!}\r\n");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* ��д������Ϣ */
    wal_cfg_msg_hdr_init(&(cfg_msg->msg_hdr), msg_type, us_len, (hi_u8)wal_get_msg_sn());
    /* ��дWID��Ϣ */
    if (puc_param != HI_NULL) {
        /* cfg_msg->auc_msg_data, �ɱ�����,cfg_msg->auc_msg_data�����Ѿ�����us_len */
        if (memcpy_s(cfg_msg->auc_msg_data, us_len, puc_param, us_len) != EOK) {
            oam_error_log0(0, OAM_SF_ANY, "{wal_send_cfg_event::mem safe function err!}");
            frw_event_free(event_mem);
            return HI_FAIL;
        }
    }
    if (need_rsp == HI_TRUE) {
        /* add queue before post event! */
        wal_msg_request_add_queue(&msg_request);
    }
    /* �ַ��¼� */
    frw_event_dispatch_event(event_mem);
    frw_event_free(event_mem);

    if (need_rsp != HI_TRUE) {
        return HI_SUCCESS;
    }

    /* context can't in interrupt */
    if (oal_warn_on(oal_in_interrupt())) {
        oam_error_log0(0, OAM_SF_ANY, "oal_in_interrupt");
    }

    return wal_send_cfg_wait_event(rsp_msg, &msg_request);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

