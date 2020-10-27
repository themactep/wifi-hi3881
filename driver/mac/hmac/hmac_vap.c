/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hmac_vap.c
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oam_ext_if.h"
#include "mac_ie.h"
#include "frw_event.h"
#include "frw_timer.h"
#include "hmac_vap.h"
#include "hmac_tx_amsdu.h"
#include "hmac_mgmt_bss_comm.h"
#include "hmac_fsm.h"
#include "hmac_ext_if.h"
#include "hmac_chan_mgmt.h"
#include "hmac_edca_opt.h"
#include "hmac_p2p.h"
#include "hmac_mgmt_sta.h"
#include "hmac_mgmt_ap.h"
#include "wal_customize.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
#define HMAC_NETDEVICE_WDT_TIMEOUT      (5*HZ)
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static oal_net_device_ops_stru g_vap_net_dev_cfg_vap_ops = {
    };
#endif

#ifdef _PRE_WLAN_FEATURE_P2P
hi_void hmac_del_virtual_inf_worker(hi_work *del_virtual_inf_work);
#endif

hi_u8 *g_puc_hmac_vap_res = HI_NULL;

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : HMAC MAC VAP��Դ��ʼ������vap��Դ�����ƥ�䣬�������������
 �޸���ʷ      :
  1.��    ��   : 2019��5��27��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_vap_res_init(hi_void)
{
    hmac_vap_stru *hmac_vap = HI_NULL;
    mac_vap_stru  *mac_vap = HI_NULL;
    hi_u8         index;
    hi_u8         vap_res_num = oal_mem_get_vap_res_num();
    hi_u32        vap_size =  sizeof(hmac_vap_stru) * vap_res_num;

    if (mac_vap_res_init(vap_res_num) != HI_SUCCESS) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_vap_res_init::mac_vap_res_init failed.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    /* ��Ϊ��,�ظ����ó�ʼ������,������,ʧ�� */
    if (g_puc_hmac_vap_res != HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_vap_res_init::re-mem alloc vap res.}");
        return HI_FAIL;
    }
    /* ��̬�����û���Դ������ڴ� */
    g_puc_hmac_vap_res  = (hi_u8 *)oal_memalloc(vap_size);
    if (g_puc_hmac_vap_res == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_vap_res_init::mem alloc vap res null.}");
        return HI_ERR_CODE_ALLOC_MEM_FAIL;
    }
    /* ��ȫ��̹���6.6����(3)�Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(g_puc_hmac_vap_res, vap_size, 0, vap_size);

    for (index = 0; index < vap_res_num; index++) {
        hmac_vap = hmac_vap_get_vap_stru(index);
        mac_vap = mac_vap_get_vap_stru(index);
        if ((hmac_vap == HI_NULL) || (mac_vap == HI_NULL)) {
            oam_error_log0(WLAN_CFG_VAP_ID, OAM_SF_ANY, "{hmac_vap_res_init:: null ptr.}");
            return HI_FAIL;
        }

        hmac_vap->base_vap = mac_vap;
    }
    return HI_SUCCESS;
}

hi_u32 hmac_vap_res_exit(hi_void)
{
    mac_vap_res_exit();

    if (g_puc_hmac_vap_res != HI_NULL) {
        oal_free(g_puc_hmac_vap_res);
        g_puc_hmac_vap_res = HI_NULL;
    }

    return HI_SUCCESS;
}
/*****************************************************************************
 ��������  : ��ȡ��Ӧ��hmac vap�ṹ��
 �������  : vap��Դid
 �޸���ʷ      :
  1.��    ��   : 2019��5��25��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hmac_vap_stru *hmac_vap_get_vap_stru(hi_u8 idx)
{
    hi_u8  vap_res_num = oal_mem_get_vap_res_num();
    if (idx >= vap_res_num) {
        oam_error_log1(0, OAM_SF_CFG, "{hmac_vap_get_vap_stru::vap id [%d] is illegal.}", idx);
        return HI_NULL;
    }
    return (hmac_vap_stru *)(g_puc_hmac_vap_res + idx * sizeof(hmac_vap_stru));
}

hi_u32 hmac_vap_mesh_ap_sta_init(hmac_vap_stru *hmac_vap, const mac_cfg_add_vap_param_stru *param)
{
    switch (param->vap_mode) {
#ifdef _PRE_WLAN_FEATURE_MESH
        case WLAN_VAP_MODE_MESH:
#endif
        case WLAN_VAP_MODE_BSS_AP:
            /* ִ�����Գ�ʼ��vap�ĺ��� */
            hmac_vap->amsdu_active = HI_FALSE;

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
            hmac_vap->us_edca_opt_time_ms = HMAC_EDCA_OPT_TIME_MS;
            frw_timer_create_timer(&(hmac_vap->edca_opt_timer), hmac_edca_opt_timeout_fn,
                                   hmac_vap->us_edca_opt_time_ms, hmac_vap, HI_TRUE);
            hmac_vap->edca_opt_flag_ap = 1;
            frw_timer_restart_timer(&(hmac_vap->edca_opt_timer), hmac_vap->us_edca_opt_time_ms, HI_TRUE);
#endif

#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
            hmac_vap->tx_traffic_classify_flag = HI_SWITCH_ON;  /* APģʽĬ��ҵ��ʶ���ܿ��� */
#endif
            break;

        case WLAN_VAP_MODE_BSS_STA:
#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
            hmac_vap->edca_opt_flag_sta = 0;
#endif

#ifdef _PRE_WLAN_FEATURE_TX_CLASSIFY_LAN_TO_WLAN
            hmac_vap->tx_traffic_classify_flag = HI_SWITCH_ON;  /* STAģʽĬ��ҵ��ʶ���ܿ��� */
#endif
            break;

        case WLAN_VAP_MODE_WDS:
            break;

        case WLAN_VAP_MODE_CONFIG:
            return HI_SUCCESS; /* ����VAPֱ�ӷ��� */

        default:
            oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_ANY, "{hmac_vap_init::mod Err=%d.}", param->vap_mode);
            return HI_ERR_CODE_INVALID_CONFIG;
    }

    return HI_CONTINUE;
}

/*****************************************************************************
 ��������  : ��ʼ��Ҫ��ӵ�hmac vap��һЩ������Ϣ
 �������  : ָ��Ҫ��ӵ�vap��ָ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 �޸���ʷ      :
  1.��    ��   : 2012��10��24��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
  2.��    ��   : 2019��5��20��
    ��    ��   : Hisilicon
    �޸�����   : ���ó��ѽ���MEMZERO��ɾ��0��ʼ��
*****************************************************************************/
hi_u32 hmac_vap_init(hmac_vap_stru *hmac_vap, hi_u8 vap_id, const mac_cfg_add_vap_param_stru *param)
{
    /* mac vapָ�벻��0�豣��vapָ���ƥ�� */
    mac_vap_stru *mac_vap = hmac_vap->base_vap;
    if (memset_s(hmac_vap, sizeof(hmac_vap_stru), 0, sizeof(hmac_vap_stru)) != EOK) {
        return HI_FAIL;
    }
    hmac_vap->base_vap = mac_vap;
    /* ���»�ȡmac vapָ�벢�ж�ƥ���ϵ���ָ���Ƿ񱻸�д */
    mac_vap = mac_vap_get_vap_stru(vap_id);
    if ((mac_vap == HI_NULL) || (hmac_vap->base_vap != mac_vap)) {
        oam_error_log1(vap_id, OAM_SF_ANY, "{hmac_vap_init::invalid mac vap(%x).}", (uintptr_t)mac_vap);
        return HI_FAIL;
    }

    hi_u32 ret = mac_vap_init(hmac_vap->base_vap, vap_id, param);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(vap_id, OAM_SF_ANY, "{hmac_vap_init::mac_vap_init failed[%d].}", ret);
        return ret;
    }

    /* ��ʼ��Ԥ����� */
    hmac_vap->preset_para.protocol     = hmac_vap->base_vap->protocol;
    hmac_vap->preset_para.en_bandwidth = hmac_vap->base_vap->channel.en_bandwidth;
    hmac_vap->preset_para.band         = hmac_vap->base_vap->channel.band;

    /* ��ʼ������˽�нṹ�� */
    hi_wait_queue_init_head(&(hmac_vap->mgmt_tx.wait_queue));

    /* 1151Ĭ�ϲ�amsdu ampdu ���ϾۺϹ��ܲ����� 1102����С���Ż�
     * ��tplink/syslink���г�����������⣬�ȹر�02��ampdu+amsdu
     */
    hmac_vap->ampdu_tx_on_switch = HI_TRUE;

    /* ��ʼ����֤����ΪOPEN */
    hmac_vap->auth_mode = WLAN_WITP_AUTH_OPEN_SYSTEM;

    hmac_vap_stru *hmac_vap_temp = hmac_vap_get_vap_stru(WLAN_CFG_VAP_ID);
    /* h00378055 add ��ǰ���޶��ƻ���������д�� */
    hmac_vap->max_ampdu_num = (vap_id == WLAN_CFG_VAP_ID) ? WLAN_AMPDU_TX_MAX_BUF_SIZE :
        hmac_vap_temp->max_ampdu_num;

    hi_wait_queue_init_head(&hmac_vap->query_wait_q);

    /* ��������VAP������Ӧ�����ҽ���ҵ��VAP������AP��STA��WDSģʽ */
    ret = hmac_vap_mesh_ap_sta_init(hmac_vap, param);
    if (ret != HI_CONTINUE) {
        return ret;
    }

#ifdef _PRE_WLAN_FEATURE_SMP_SUPPORT
    OAL_NETBUF_QUEUE_HEAD_INIT(&(hmac_vap->tx_queue_head[0]));
    OAL_NETBUF_QUEUE_HEAD_INIT(&(hmac_vap->tx_queue_head[1]));
    hmac_vap->in_queue_id  = 0;
    hmac_vap->out_queue_id = 1;

    /* ul_tx_event_num��ʼֵ�޸�Ϊ1����ֹhmac_tx_post_event�������������������¼� */
    hi_atomic_set(&hmac_vap->tx_event_num, 1);

    /* DTS2015080703041����quata��1�޸�Ϊ256,Ŀ���Ƿ�ֹС�����������ͣ�
       �ĸ�vap����Ϊ0���ڴ�й¶�������ͨ������¼����ȼ���� */
    hmac_vap->tx_quata = 256; /* ��quata��1�޸�Ϊ256 */
#endif

    /* ����vapʱ ��ʼ״̬Ϊinit */
    mac_vap_state_change(hmac_vap->base_vap, MAC_VAP_STATE_INIT);

#ifdef _PRE_WLAN_FEATURE_P2P
    /* ��ʼ��ɾ����������ӿڹ������� */
    hi_workqueue_init_work(&(hmac_vap->del_virtual_inf_worker), hmac_del_virtual_inf_worker);
    hmac_vap->del_net_device = HI_NULL;
    hmac_vap->p2p0_net_device = HI_NULL;
#endif

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_vap_get_net_device
 ��������  : ͨ��vap id��ȡ net_device
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��9��6��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
oal_net_device_stru  *hmac_vap_get_net_device(hi_u8 vap_id)
{
    hmac_vap_stru   *hmac_vap = HI_NULL;

    hmac_vap = hmac_vap_get_vap_stru(vap_id);
    if (hmac_vap == HI_NULL) {
        oam_error_log0(vap_id, OAM_SF_ANY, "{hmac_vap_get_net_device::pst_hmac_vap null.}");
        return HI_NULL;
    }

    return (hmac_vap->net_device);
}

/*****************************************************************************
 �� �� ��  : hmac_vap_creat_netdev
 ��������  : ��ȡhmac_vap�ṹ���е�˽��������
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��12��11��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  hmac_vap_creat_netdev(hmac_vap_stru *hmac_vap, hi_char *puc_netdev_name,
    const hi_s8 *mac_addr, hi_u8 mac_addr_len)
{
    oal_net_device_stru *netdev = HI_NULL;
    hi_u32           return_code;
    mac_vap_stru        *mac_vap = HI_NULL;

    if (oal_unlikely((hmac_vap == HI_NULL) || (puc_netdev_name == HI_NULL))) {
        oam_error_log2(0, OAM_SF_ASSOC, "{hmac_vap_creat_netdev::param null %p %p.}",
                       (uintptr_t)hmac_vap, (uintptr_t)puc_netdev_name);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap = hmac_vap->base_vap;
#if (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    netdev = oal_net_alloc_netdev(puc_netdev_name, OAL_IF_NAME_SIZE);
#elif (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    netdev = oal_net_alloc_netdev(0, puc_netdev_name, oal_ether_setup);
#endif
    if (oal_unlikely(netdev == HI_NULL)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_vap_creat_netdev::pst_net_device null.}");

        return HI_ERR_CODE_PTR_NULL;
    }

    /* ���¶�netdevice�ĸ�ֵ��ʱ�����²��� */
#if (LINUX_VERSION_CODE >= kernel_version(4, 11, 9))
    /* destructor change to priv_destructor */
    netdev->priv_destructor               = oal_net_free_netdev;
    netdev->needs_free_netdev             = false;
#else
    oal_netdevice_destructor(netdev)      = oal_net_free_netdev;
#endif
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    oal_netdevice_ops(netdev)             = &g_vap_net_dev_cfg_vap_ops;
#else
    oal_netdevice_master(netdev)          = HI_NULL;
    oal_netdevice_ops(netdev)             = HI_NULL;
#endif

    oal_netdevice_ifalias(netdev)         = HI_NULL;
    oal_netdevice_watchdog_timeo(netdev)  = HMAC_NETDEVICE_WDT_TIMEOUT;
    if (memcpy_s(oal_netdevice_mac_addr(netdev), WLAN_MAC_ADDR_LEN, mac_addr, mac_addr_len) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_vap_creat_netdev:: puc_mac_addr memcpy_s fail.");
        oal_net_free_netdev(netdev);
        return HI_FAIL;
    }
    oal_net_dev_priv(netdev) = mac_vap;
    oal_netdevice_qdisc(netdev, HI_NULL);

    return_code = (hi_u32)oal_net_register_netdev(netdev);
    if (oal_unlikely(return_code != HI_SUCCESS)) {
        oam_warning_log0(mac_vap->vap_id, OAM_SF_ANY, "{hmac_vap_creat_netdev::oal_net_register_netdev failed.}");
        oal_net_free_netdev(netdev);
        return return_code;
    }
    hmac_vap->net_device = netdev;
    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_vap_destroy
 ��������  : ����hmac vap�Ĵ�����
 �������  : ָ��Ҫ���ٵ�vapָ��
 �������  : ��
 �� �� ֵ  : �ɹ�����ʧ��ԭ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��5��30��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32  hmac_vap_destroy(hmac_vap_stru *hmac_vap)
{
    mac_cfg_down_vap_param_stru   down_vap;
    mac_cfg_del_vap_param_stru    del_vap_param;
    hi_u32                    ret;

    if (oal_unlikely(hmac_vap == HI_NULL)) {
        oam_error_log0(0, OAM_SF_ANY, "{hmac_vap_destroy::pst_hmac_vap null.}");
        return HI_ERR_CODE_PTR_NULL;
    }

#ifdef _PRE_WLAN_FEATURE_EDCA_OPT_AP
    if ((hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        || (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_MESH)
#endif
    ) {
        hmac_vap->edca_opt_flag_ap   = 0;
        frw_timer_immediate_destroy_timer(&(hmac_vap->edca_opt_timer));
    } else if (hmac_vap->base_vap->vap_mode == WLAN_VAP_MODE_BSS_STA) {
        hmac_vap->edca_opt_flag_sta = 0;
    }
#endif
    /* ��down vap */
#ifdef _PRE_WLAN_FEATURE_P2P
    down_vap.p2p_mode = hmac_vap->base_vap->p2p_mode;
#endif
    down_vap.net_dev = hmac_vap->net_device;
    hmac_vap->net_device = HI_NULL;
    ret = hmac_config_down_vap(hmac_vap->base_vap, sizeof(mac_cfg_down_vap_param_stru), (hi_u8 *)&down_vap);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_ANY, "{hmac_vap_destroy::hmac_config_down_vap failed[%d].}",
            ret);
        return ret;
    }

    /* Ȼ����delete vap */
    del_vap_param.p2p_mode = hmac_vap->base_vap->p2p_mode;
    del_vap_param.vap_mode = hmac_vap->base_vap->vap_mode;
    ret = hmac_config_del_vap(hmac_vap->base_vap, sizeof(mac_cfg_del_vap_param_stru), (hi_u8 *)&del_vap_param);
    if (ret != HI_SUCCESS) {
        oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_ANY, "{hmac_vap_destroy::hmac_config_del_vap failed[%d].}",
            ret);
        return ret;
    }
    return HI_SUCCESS;
}

hi_void hmac_vap_check_ht_capabilities_ap_capable(const hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user,
    const mac_user_ht_hdl_stru *ht_hdl, hi_bool prev_asoc_ht, hi_bool prev_asoc_non_ht)
{
    mac_protection_stru *protection = &(hmac_vap->base_vap->protection);

    if (ht_hdl->ht_capable == HI_FALSE) { /* STA��֧��HT */
        /*  ���STA֮ǰû����AP���� */
        if (hmac_user->base_user->user_asoc_state != MAC_USER_STATE_ASSOC) {
            protection->sta_non_ht_num++;
        } else if (prev_asoc_ht == HI_TRUE) { /* ���STA֮ǰ�Ѿ���ΪHTվ����AP���� */
            protection->sta_non_ht_num++;

            if ((ht_hdl->ht_capinfo.supported_channel_width == HI_FALSE) && (protection->sta_20_m_only_num != 0)) {
                protection->sta_20_m_only_num--;
            }

            if ((ht_hdl->ht_capinfo.ht_green_field == HI_FALSE) && (protection->sta_non_gf_num != 0)) {
                protection->sta_non_gf_num--;
            }

            if ((ht_hdl->ht_capinfo.lsig_txop_protection == HI_FALSE) && (protection->sta_no_lsig_txop_num != 0)) {
                protection->sta_no_lsig_txop_num--;
            }
        } /* STA ֮ǰ�Ѿ���Ϊ��HTվ����AP���� */
    } else {
        for (hi_u32 amsdu_idx = 0; amsdu_idx < WLAN_WME_MAX_TID_NUM; amsdu_idx++) {
            /* ָ��Ϊ��˵��vap amsduδ����,����ʼ�� */
            if (hmac_user->past_hmac_amsdu[amsdu_idx] == HI_NULL) {
                continue;
            }
            hmac_amsdu_set_maxnum(hmac_user->past_hmac_amsdu[amsdu_idx], WLAN_AMSDU_MAX_NUM);
        }
        /* ����amsdu�� */
        hmac_user->amsdu_supported = 255;   /* 255: suppoted 255 */
        /*  ���STA֮ǰ�Ѿ���non-HTվ����AP����, ��uc_sta_non_ht_num��1 */
        if ((prev_asoc_non_ht == HI_TRUE) && (protection->sta_non_ht_num != 0)) {
            protection->sta_non_ht_num--;
        }
    }
}

/*****************************************************************************

 �� �� ��  : hmac_vap_check_ht_capabilities_ap
 ��������  : ������������STA�� HT Capabilities element
 �������  : ��
 �������  : ��
 �� �� ֵ  : hi_u32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��7��8��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u16 hmac_vap_check_ht_capabilities_ap(
    const hmac_vap_stru         *hmac_vap,
    hi_u8                       *puc_payload,
    hi_u16                       us_info_elem_offset,
    hi_u32                       msg_len,
    hmac_user_stru              *hmac_user)
{
    hi_u16                  us_index        = us_info_elem_offset;
    hi_bool                 prev_asoc_ht = HI_FALSE;
    hi_bool                 prev_asoc_non_ht = HI_FALSE;
    mac_user_ht_hdl_stru   *ht_hdl      = &(hmac_user->base_user->ht_hdl);
    hi_u8                   pcip_policy;

    if (mac_mib_get_high_throughput_option_implemented(hmac_vap->base_vap) == HI_FALSE) {
        return MAC_SUCCESSFUL_STATUSCODE;
    }
    /* ���STA�Ƿ�����Ϊһ��HT capable STA��AP���� */
    if ((hmac_user->base_user->user_asoc_state == MAC_USER_STATE_ASSOC) && (ht_hdl->ht_capable == HI_TRUE)) {
        mac_user_set_ht_capable(hmac_user->base_user, HI_FALSE);
        prev_asoc_ht = HI_TRUE;
    /* ���STA�Ƿ�����Ϊһ��non HT capable STA��AP���� */
    } else if (hmac_user->base_user->user_asoc_state == MAC_USER_STATE_ASSOC && ht_hdl->ht_capable == HI_FALSE) {
        prev_asoc_non_ht = HI_TRUE;
    }

    /* �ڹ�������֡������ HT Capabilities Element */
    while (us_index < (msg_len - WLAN_HDR_FCS_LENGTH)) {
        if (puc_payload[us_index] == MAC_EID_HT_CAP) {
            /* ������HT STA ʹ�� TKIP/WEP ���� */
            if (mac_is_wep_enabled(hmac_vap->base_vap)) {
                oam_warning_log1(0, OAM_SF_ANY, "{hmac_vap_check_ht_capabilities_ap::Rejecting a HT STA  Cipher %d}",
                    hmac_user->base_user->key_info.cipher_type);
                return MAC_MISMATCH_HTCAP;
            }
            pcip_policy = hmac_vap->base_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_pairwise_cipher_requested;

            if (pcip_policy == WLAN_80211_CIPHER_SUITE_TKIP) {
                oam_warning_log2(hmac_vap->base_vap->vap_id, OAM_SF_ANY,
                    "{hmac_vap_check_ht_capabilities_ap::uc_pcip_policy=%d uc_grp_policy=%d}", pcip_policy,
                    hmac_vap->base_vap->mib_info->wlan_mib_rsna_cfg.dot11_rsna_group_cipher_requested);
                break;
            }

            /* ���� HT Capabilities Element */
            hmac_search_ht_cap_ie_ap(hmac_vap, hmac_user, puc_payload, us_index, prev_asoc_ht);

            break;
        }
        /* ͨ��IE������������ֵ */
        us_index += puc_payload[us_index + 1] + MAC_IE_HDR_LEN;
    }

    /* �ߵ����˵��sta�Ѿ���ͳ�Ƶ�ht��ص�ͳ������ */
    hmac_user->user_stats_flag.no_ht_stats_flag = HI_TRUE;
    hmac_user->user_stats_flag.no_gf_stats_flag = HI_TRUE;
    hmac_user->user_stats_flag.m_only_stats_flag = HI_TRUE;
    hmac_user->user_stats_flag.no_lsig_txop_stats_flag = HI_TRUE;
    hmac_user->user_stats_flag.no_40dsss_stats_flag = HI_TRUE;

    hmac_vap_check_ht_capabilities_ap_capable(hmac_vap, hmac_user, ht_hdl, prev_asoc_ht, prev_asoc_non_ht);

    return MAC_SUCCESSFUL_STATUSCODE;
}


static inline hi_void hmac_parse_tx_beamforming(const hi_u8 *payload, hi_u16 offset,
    mac_user_ht_hdl_stru *ht_hdl, mac_user_stru *base_user)
{
    hi_u16 tmp_info_elem = hi_makeu16(payload[offset], payload[offset + 1]);

    hi_u16 tmp_txbf_low  = hi_makeu16(payload[offset + 2], payload[offset + 3]); /* 2/3 ���� */
    hi_u32 tmp_txbf_elem = hi_makeu32(tmp_info_elem, tmp_txbf_low);

    mac_ie_txbf_set_ht_hdl(ht_hdl, tmp_txbf_elem);
    mac_user_set_ht_hdl(base_user, ht_hdl);
}

/*****************************************************************************
 �� �� ��  : hmac_search_ht_cap_ie_ap
 ��������  : �ڹ�����������������HT Cap IE
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2013��7��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_search_ht_cap_ie_ap(const hmac_vap_stru *hmac_vap, hmac_user_stru *hmac_user,
                                hi_u8 *payload, hi_u16 current_offset, hi_bool prev_asoc_ht)
{
    mac_user_ht_hdl_stru  ht_hdl_value;

    hi_u8                *tmp_payload = payload;
    mac_user_ht_hdl_stru *ht_hdl      = &ht_hdl_value;
    mac_vap_stru         *mac_vap     = hmac_vap->base_vap;
    mac_user_stru        *mac_user    = hmac_user->base_user;

    mac_user_get_ht_hdl(hmac_user->base_user, ht_hdl);

    /* ���� HT Capability Element �� STA����ʾ������HT capable. */
    ht_hdl->ht_capable = 1;
    current_offset += MAC_IE_HDR_LEN;

    /***************************************************************************
                    ���� HT Capabilities Info Field
    ***************************************************************************/
    hi_u16 tmp_info_elem = hi_makeu16(tmp_payload[current_offset], tmp_payload[current_offset + 1]);

    /* ���STA��֧�ֵ�LDPC�������� B0��0:��֧�֣�1:֧�� */
    ht_hdl->ht_capinfo.ldpc_coding_cap = (tmp_info_elem & BIT0);

    /* ���STA��֧�ֵ��ŵ���� B1��0:��20M���У�1:20M��40M���� */
    ht_hdl->ht_capinfo.supported_channel_width = mac_ie_proc_ht_supported_channel_width(mac_user, mac_vap,
        ((tmp_info_elem & BIT1) >> 1), prev_asoc_ht);

    /* ���ռ临�ý���ģʽ B2~B3 */
    ht_hdl->ht_capinfo.sm_power_save = mac_ie_proc_sm_power_save_field((tmp_info_elem & (BIT2 | BIT3)) >> 2);

    /* ���Greenfield ֧����� B4�� 0:��֧�֣�1:֧�� */
    hi_u8 ht_green_field = (tmp_info_elem & BIT4) >> 4;
    ht_hdl->ht_capinfo.ht_green_field = mac_ie_proc_ht_green_field(mac_user, mac_vap, ht_green_field, prev_asoc_ht);

    /* ���20MHz Short-GI B5,  0:��֧�֣�1:֧�֣�֮����APȡ����  */
    ht_hdl->ht_capinfo.short_gi_20mhz = ((tmp_info_elem & BIT5) >> 5);
    ht_hdl->ht_capinfo.short_gi_20mhz &=
        (hi_u16)hmac_vap->base_vap->mib_info->phy_ht.dot11_short_gi_option_in_twenty_implemented;

    /* ���40MHz Short-GI B6,  0:��֧�֣�1:֧�֣�֮����APȡ���� */
    ht_hdl->ht_capinfo.short_gi_40mhz = ((tmp_info_elem & BIT6) >> 6);
    ht_hdl->ht_capinfo.short_gi_40mhz &= (hi_u16)mac_mib_get_shortgi_option_in_forty_implemented(hmac_vap->base_vap);

    /* ���֧�ֽ���STBC PPDU B8,  0:��֧�֣�1:֧�� */
    ht_hdl->ht_capinfo.rx_stbc = ((tmp_info_elem & 0x0300) >> 8);

    /* ������A-MSDU���� B11��0:3839�ֽ�, 1:7935�ֽ� */
    hmac_user->us_amsdu_maxsize =
        (0 == (tmp_info_elem & BIT11)) ? WLAN_MIB_MAX_AMSDU_LENGTH_SHORT : WLAN_MIB_MAX_AMSDU_LENGTH_LONG;

    /* �����40M��DSSS/CCK��֧����� B12 */
    /* �ڷ�Beacon֡��probe rsp֡��ʱ */
    /* 0: STA��40MHz�ϲ�ʹ��DSSS/CCK, 1: STA��40MHz��ʹ��DSSS/CCK */
    ht_hdl->ht_capinfo.dsss_cck_mode_40mhz = ((tmp_info_elem & BIT12) >> 12); /* ����12λ */

    if ((ht_hdl->ht_capinfo.dsss_cck_mode_40mhz == 0) && (ht_hdl->ht_capinfo.supported_channel_width == 1)) {
        hmac_vap->base_vap->protection.sta_no_40dsss_cck_num++;
    }

    /*  ����L-SIG TXOP ������֧����� B15, 0:��֧�֣�1:֧�� */
    ht_hdl->ht_capinfo.lsig_txop_protection = mac_ie_proc_lsig_txop_protection_support(mac_user, mac_vap,
        ((tmp_info_elem & BIT15) >> 15), prev_asoc_ht); /* 15: ����15λ */

    current_offset += MAC_HT_CAPINFO_LEN;

    /***************************************************************************
                        ���� A-MPDU Parameters Field
    ***************************************************************************/
    /* ��ȡ Maximum Rx A-MPDU factor (B1 - B0) */
    ht_hdl->max_rx_ampdu_factor = (tmp_payload[current_offset] & 0x03);

    /* ��ȡ the Minimum MPDU Start Spacing (B2 - B4) */
    ht_hdl->min_mpdu_start_spacing = (tmp_payload[current_offset] >> 2)  & 0x07;

    current_offset += MAC_HT_AMPDU_PARAMS_LEN;

    /***************************************************************************
                        ���� Supported MCS Set Field
    ***************************************************************************/
    for (hi_u8 mcs_bmp_index = 0; mcs_bmp_index < WLAN_HT_MCS_BITMASK_LEN; mcs_bmp_index++) {
        ht_hdl->rx_mcs_bitmask[mcs_bmp_index] = (*(hi_u8 *)(tmp_payload + current_offset + mcs_bmp_index)) &
            (hmac_vap->base_vap->mib_info->supported_mcstx.auc_dot11_supported_mcs_tx_value[mcs_bmp_index]);
    }

    ht_hdl->rx_mcs_bitmask[WLAN_HT_MCS_BITMASK_LEN - 1] &= 0x1F;

    current_offset += MAC_HT_SUP_MCS_SET_LEN;

    /***************************************************************************
                        ���� HT Extended Capabilities Info Field
    ***************************************************************************/
    tmp_info_elem = hi_makeu16(tmp_payload[current_offset], tmp_payload[current_offset + 1]);

    /* ��ȡ HTC support Information */
    ht_hdl->htc_support = ((tmp_info_elem & BIT10) != 0) ? 1 : ht_hdl->htc_support;

    current_offset += MAC_HT_EXT_CAP_LEN;

    /***************************************************************************
                        ���� Tx Beamforming Field
    ***************************************************************************/
    hmac_parse_tx_beamforming(tmp_payload, current_offset, ht_hdl, hmac_user->base_user);
    return HI_SUCCESS;
}

#ifdef _PRE_WLAN_FEATURE_OPMODE_NOTIFY
/*****************************************************************************
 �� �� ��  : hmac_check_opmode_notify
 ��������  : ������������STA��Operating Mode Notification
 �������  : hmac_vap_stru    *pst_hmac_vap --VAPָ��
             hi_u8        *puc_mac_hdr, --֡ͷָ��
             hi_u8        *puc_payload  --payloadָ��
             hi_u16        us_info_elem_offset--ƫ�Ƴ���
             hi_u32        ul_msg_len----��Ϣ����
             hmac_user_stru   *pst_hmac_user_sta --�û�ָ��
 �������  : ��
 �� �� ֵ  : hi_u16
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��6��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���
*****************************************************************************/
hi_u32 hmac_check_opmode_notify(
                hmac_vap_stru                   *hmac_vap,
                hi_u8                       *puc_mac_hdr,
                hi_u8                       *puc_payload,
                hi_u16                       us_info_elem_offset,
                hi_u32                       msg_len,
                hmac_user_stru                   *hmac_user)
{
    hi_u8                  *puc_opmode_notify_ie = HI_NULL;
    mac_opmode_notify_stru *opmode_notify = HI_NULL;
    hi_u8               mgmt_frm_type;
    hi_u32              relt;

    if ((hmac_vap == HI_NULL) || (puc_payload == HI_NULL) ||
        (hmac_user == HI_NULL) || (puc_mac_hdr == HI_NULL)) {
        oam_error_log4(0, OAM_SF_ANY,
            "{hmac_check_opmode_notify::param null! hmac_vap=%p, puc_payload=%p, hmac_user=%p, puc_mac_hdr=%p.}",
            (uintptr_t)hmac_vap, (uintptr_t)puc_payload, (uintptr_t)hmac_user, (uintptr_t)puc_mac_hdr);
        return HI_ERR_CODE_PTR_NULL;
    }

    mac_vap_stru *mac_vap   = hmac_vap->base_vap;
    mac_user_stru *mac_user  = hmac_user->base_user;

    if ((HI_FALSE == mac_mib_get_VHTOptionImplemented(mac_vap)) ||
        (HI_FALSE == mac_mib_get_operating_mode_notification_implemented(mac_vap))) {
        return HI_SUCCESS;
    }

    if (msg_len > us_info_elem_offset) {
        puc_opmode_notify_ie =
            mac_find_ie(MAC_EID_OPMODE_NOTIFY, puc_payload + us_info_elem_offset, (msg_len - us_info_elem_offset));
        if ((puc_opmode_notify_ie != HI_NULL) && (puc_opmode_notify_ie[1] >= MAC_OPMODE_NOTIFY_LEN)) {
            mgmt_frm_type  = mac_get_frame_sub_type(puc_mac_hdr);
            opmode_notify = (mac_opmode_notify_stru *)(puc_opmode_notify_ie + MAC_IE_HDR_LEN);
            relt = hmac_ie_proc_opmode_field(mac_vap, mac_user, opmode_notify, mgmt_frm_type);
            if (oal_unlikely(relt != HI_SUCCESS)) {
                oam_warning_log1(mac_user->vap_id, OAM_SF_CFG,
                    "{hmac_check_opmode_notify::hmac_ie_proc_opmode_field failed[%d].}", relt);
                return relt;
            }
            /* opmodeϢͬ��dmac */
            relt = hmac_config_update_opmode_event(mac_vap, mac_user, mgmt_frm_type);
            if (oal_unlikely(relt != HI_SUCCESS)) {
                oam_warning_log1(mac_user->vap_id, OAM_SF_CFG,
                                 "{hmac_check_opmode_notify::hmac_config_update_opmode_event failed[%d].}", relt);
                return relt;
            }
        }
    }
    return HI_SUCCESS;
}
#endif

#ifdef _PRE_WLAN_FEATURE_P2P
/*****************************************************************************
 �� �� ��  : hmac_del_virtual_inf_worker
 ��������  : cfg80211 ɾ������ӿڹ������У���ֹȥע�������豸ʱ���������
 �������  : hi_work *pst_del_virtual_inf_work
 �������  : ��
 �� �� ֵ  : hi_void
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��2��26��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void hmac_del_virtual_inf_worker(hi_work *del_virtual_inf_work)
{
    oal_net_device_stru         *netdev = HI_NULL;
    hmac_vap_stru               *hmac_vap = HI_NULL;
    hmac_device_stru            *hmac_dev = HI_NULL;

    hmac_vap     = oal_container_of(del_virtual_inf_work, hmac_vap_stru, del_virtual_inf_worker);
    netdev      = hmac_vap->del_net_device;

    /* ������rtnl_lock������ */
    oal_net_unregister_netdev(netdev);
    oal_net_free_netdev(netdev);

    hmac_vap->del_net_device = HI_NULL;
    hmac_dev = hmac_get_device_stru();
    hmac_p2p_clr_status(&hmac_dev->p2p_intf_status, P2P_STATUS_IF_DELETING);

    oam_warning_log1(hmac_vap->base_vap->vap_id, OAM_SF_P2P,
                     "{hmac_del_virtual_inf_worker::end !pst_hmac_device->ul_p2p_intf_status[%x]}",
                     hmac_dev->p2p_intf_status);
    oal_smp_mb();
    hi_wait_queue_wake_up_interrupt(&hmac_dev->netif_change_event);
}
#endif  /* _PRE_WLAN_FEATURE_P2P */

/*****************************************************************************
 �� �� ��  : hmac_handle_disconnect_rsp
 ��������  :
 �������  : ��
 �������  : ��
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2015��2��10��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_void hmac_handle_disconnect_rsp(hmac_vap_stru *hmac_vap, const hmac_user_stru *hmac_user,
                                   hmac_report_disasoc_reason_uint16  disasoc_reason)
{
     /* �޸� state & ɾ�� user */
    switch (hmac_vap->base_vap->vap_mode) {
        case WLAN_VAP_MODE_BSS_STA:
            {
                hmac_fsm_change_state(hmac_vap, MAC_VAP_STATE_STA_FAKE_UP);

                /* �ϱ��ں�sta�Ѿ���ĳ��apȥ���� */
                /* sta kick user  dmac_reason_code = 5 */
                hmac_sta_disassoc_rsp(hmac_vap, disasoc_reason, DMAC_DISASOC_MISC_KICKUSER);
            }
            break;
#ifdef _PRE_WLAN_FEATURE_MESH
        case WLAN_VAP_MODE_MESH:
#endif
        case WLAN_VAP_MODE_BSS_AP:
            {
                /* ���¼��ϱ��ںˣ��Ѿ�ȥ����ĳ��STA */
                hmac_handle_disconnect_rsp_ap(hmac_vap, hmac_user);
            }
            break;

        default:
            break;
    }
    return;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_get_mac_vap
 ��������  : ��ȡVAP�����ж�VAP״̬
 �������  : pst_event event�ṹ��
 �������  : pst_vap_stru VAP�ṹ��
 �� �� ֵ  :
 ���ú���  : hmac_tx_wlan_to_wlan_ap
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2012��11��14��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
hi_u32 hmac_tx_get_mac_vap(hi_u8 vap_id, mac_vap_stru **mac_vap)
{
    mac_vap_stru         *mac_vap_value = HI_NULL;

    /* ��ȡvap�ṹ��Ϣ */
    mac_vap_value = mac_vap_get_vap_stru(vap_id);
    if (oal_unlikely(mac_vap_value == HI_NULL)) {
        oam_error_log0(vap_id, OAM_SF_TX, "{hmac_tx_get_mac_vap::pst_vap null}");
        return HI_ERR_CODE_PTR_NULL;
    }

    /* VAPģʽ�ж� */
    if ((mac_vap_value->vap_mode != WLAN_VAP_MODE_BSS_AP)
#ifdef _PRE_WLAN_FEATURE_MESH
        && (mac_vap_value->vap_mode != WLAN_VAP_MODE_MESH)
#endif
    ) {
        oam_warning_log1(mac_vap_value->vap_id, OAM_SF_TX, "hmac_tx_get_mac_vap::vap_mode error[%d]",
            mac_vap_value->vap_mode);
        return HI_ERR_CODE_CONFIG_UNSUPPORT;
    }

    /* VAP״̬�ж� */
    if (mac_vap_value->vap_state == MAC_VAP_STATE_UP || mac_vap_value->vap_state == MAC_VAP_STATE_PAUSE) {
        *mac_vap = mac_vap_value;

        return HI_SUCCESS;
    }

    oam_warning_log1(mac_vap_value->vap_id, OAM_SF_TX, "hmac_tx_get_mac_vap::vap_state[%d] error",
        mac_vap_value->vap_state);

    return HI_ERR_CODE_CONFIG_UNSUPPORT;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

