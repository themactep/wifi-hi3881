/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Downstream data service identification.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1ͷ�ļ�����
*****************************************************************************/

#include "hmac_traffic_classify.h"
#include "hmac_user.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2�궨��
*****************************************************************************/
#define RTP_VERSION                 2           /* RTPЭ��汾�ţ�ռ2λ����ǰЭ��汾��Ϊ2 */
#define RTP_VER_SHIFT               6           /* RTPЭ��汾��λ���� */
#define RTP_CSRC_MASK               0x0f        /* CSRC��������ռ4λ��ָʾCSRC��ʶ���ĸ��� */
#define RTP_CSRC_LEN_BYTE           4           /* ÿ��CSRC��ʶ��ռ32λ��һ��4�ֽ� */
#define RTP_HDR_LEN_BYTE            12          /* RTP֡ͷ�̶��ֽ���(������CSRC�ֶ�) */
#define TCP_HTTP_VI_LEN_THR         1000        /* HTTP��Ƶ�����ĳ�����ֵ */
#define JUDGE_CACHE_LIFETIME        1           /* ��ʶ�����ʧЧʱ��: 1s */
#define IP_FRAGMENT_MASK            0x1FFF      /* IP��ƬFragment Offset�ֶ� */
/* RTP Payload_Type ���:RFC3551 */
#define RTP_PT_VO_G729              18          /* RTP�غ�����:18-Audio-G729 */
#define RTP_PT_VI_CELB              25          /* RTP�غ�����:25-Video-CelB */
#define RTP_PT_VI_JPEG              26          /* RTP�غ�����:26-Video-JPEG */
#define RTP_PT_VI_NV                28          /* RTP�غ�����:28-Video-nv */
#define RTP_PT_VI_H261              31          /* RTP�غ�����:31-Video-H261 */
#define RTP_PT_VI_MPV               32          /* RTP�غ�����:32-Video-MPV */
#define RTP_PT_VI_MP2T              33          /* RTP�غ�����:33-Video-MP2T */
#define RTP_PT_VI_H263              34          /* RTP�غ�����:34-Video-H263 */
/* HTTP��ý��˿� */
#define HTTP_PORT_80                80          /* HTTPЭ��Ĭ�϶˿ں�80 */
#define HTTP_PORT_8080              8080        /* HTTPЭ��Ĭ�϶˿ں�8080 */

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 �� �� ��  : hmac_tx_add_cfm_traffic
 ��������  : ���û���ʶ��ҵ�������ʶ���¼��
 �������  : hmac�û��ṹ��ָ�룬TIDָ�룬hmac_tx_major_flow_stru�ṹ��ָ��
 �������  :
 �� �� ֵ  : �ɹ�����HI_SUCCESS,ʧ�ܷ���HI_FAIL
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.����: 2015.09.16
    ����: wanghao(w00357635)
    �޸�����: �����º���
*****************************************************************************/
static hi_u32 hmac_tx_add_cfm_traffic(hmac_user_stru *hmac_user, hi_u8 tid, const hmac_tx_major_flow_stru *max)
{
    hi_u32  time_stamp;
    hi_u8   mark         = 0;
    hi_u8   traffic_idx  = 0;

    hmac_tx_cfm_flow_stru *cfm_info = HI_NULL;

    if (hmac_user->cfm_num == MAX_CONFIRMED_FLOW_NUM) {
        /* ��ʶ���б����������б����ʱ��û��������ҵ������滻 */
        time_stamp = hmac_user->ast_cfm_flow_list[traffic_idx].last_jiffies;

        for (traffic_idx = 1; traffic_idx < MAX_CONFIRMED_FLOW_NUM; traffic_idx++) {
            cfm_info = (hmac_user->ast_cfm_flow_list + traffic_idx);
            if (time_stamp > cfm_info->last_jiffies) {
                time_stamp = cfm_info->last_jiffies;
                mark = traffic_idx;
            }
        }
    } else {
        /* ��ʶ���б������ҵ��ɼ�¼��index */
        for (traffic_idx = 0; traffic_idx < MAX_CONFIRMED_FLOW_NUM; traffic_idx++) {
            cfm_info = (hmac_user->ast_cfm_flow_list + traffic_idx);
            if (cfm_info->us_cfm_flag == HI_FALSE) {
                mark = traffic_idx;
                hmac_user->cfm_num++;
                cfm_info->us_cfm_flag = HI_TRUE;
                break;
            }
        }
    }

    /* �����б� */
    cfm_info = (hmac_user->ast_cfm_flow_list + mark);

    if (memcpy_s(&cfm_info->cfm_flow_info, sizeof(hmac_tx_flow_info_stru), &max->flow_info,
        sizeof(hmac_tx_flow_info_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_tx_add_cfm_traffic:: st_flow_info memcpy_s fail.");
        return HI_FALSE;
    }

    cfm_info->us_cfm_tid      = tid;
    cfm_info->last_jiffies = hi_get_tick();

    return HI_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_traffic_judge
 ��������  : ����Ҫҵ�����ҵ��ʶ����
 �������  : hmac�û��ṹ��ָ�룬��Ҫҵ��ṹ��ָ�룬TIDָ��
 �������  : TID
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.����: 2015.11.26
    ����: wanghao(w00357635)
    �޸�����: �����º���
  2.����: 2015.12.26
    ����: wanghao(w00357635)
    �޸�����: TCPʶ���ܲü�
*****************************************************************************/
static hi_u32 hmac_tx_traffic_judge(
                hmac_user_stru *hmac_user,
                const hmac_tx_major_flow_stru *major_flow,
                hi_u8 *puc_tid)
{
    hi_u32                  ret = HI_FAIL;
    hi_u8                   cache_idx;
    hi_u32                  pt;

    hmac_tx_judge_list_stru     *judge_list = &(hmac_user->judge_list);
    hmac_tx_judge_info_stru     *judge_info = HI_NULL;

    /* ��Ҫҵ��֡ΪUDP֡������RTP֡��� */
    for (cache_idx = 0; cache_idx < MAX_JUDGE_CACHE_LENGTH; cache_idx++) {
        judge_info = (hmac_tx_judge_info_stru*)(judge_list->ast_judge_cache + cache_idx);

        if (!memcmp(&judge_info->flow_info, &major_flow->flow_info, sizeof(hmac_tx_flow_info_stru))) {
            /* RTP֡�жϱ�׼:versionλ����Ϊ2��SSRC��PT���ֲ��䣬��֡���ȴ���RTP��ͷ���� */
            if (((judge_info->rtpver >> RTP_VER_SHIFT) != RTP_VERSION) ||
                (major_flow->rtpssrc      != judge_info->rtpssrc) ||
                (major_flow->payload_type != judge_info->payload_type) ||
                (major_flow->average_len  <
                    (hi_u32)(judge_info->rtpver & RTP_CSRC_MASK) * RTP_CSRC_LEN_BYTE + RTP_HDR_LEN_BYTE)) {
                hmac_user->judge_list.to_judge_num = 0;   /* ʶ��ʧ�ܣ���ն��� */
                return HI_FAIL;
            }
        }
    }

    pt = (major_flow->payload_type & (~BIT7));
    if (pt <= RTP_PT_VO_G729) {   /* ����PayloadType�ж�RTP�غ����� */
        *puc_tid = WLAN_TIDNO_VOICE;
    } else if ((pt == RTP_PT_VI_CELB) ||
               (pt == RTP_PT_VI_JPEG) ||
               (pt == RTP_PT_VI_NV) ||
               ((pt >= RTP_PT_VI_H261) && (pt <= RTP_PT_VI_H263))) {
        *puc_tid = WLAN_TIDNO_VIDEO;
    }

    /* ʶ��ɹ��������û���ʶ�����б� */
    if ((*puc_tid == WLAN_TIDNO_VOICE) || (*puc_tid == WLAN_TIDNO_VIDEO)) {
        ret = hmac_tx_add_cfm_traffic(hmac_user, *puc_tid, major_flow);
    }
    hmac_user->judge_list.to_judge_num = 0;   /* ʶ����ɣ���ն��� */

    return ret;
}

/*****************************************************************************
 �� �� ��  : hmac_tx_find_major_traffic
 ��������  : �ҵ���ʶ���������Ҫҵ��
 �������  : hmac�û��ṹ��ָ�룬TIDָ��
 �������  :
 �� �� ֵ  : �ɹ�����HI_SUCCESS��ʧ�ܷ���HI_FAIL
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.����: 2015.11.26
    ����: wanghao(w00357635)
    �޸�����: �����º���
*****************************************************************************/
static hi_u32 hmac_tx_find_major_traffic(hmac_user_stru *hmac_user, hi_u8 *puc_tid)
{
    hmac_tx_major_flow_stru  mark = {0};
    hmac_tx_major_flow_stru  max = {0};
    hmac_tx_judge_list_stru *judge_list = &(hmac_user->judge_list);
    hmac_tx_judge_info_stru *judge_info = HI_NULL;

    /* ���г�ʱ����ն��м�¼ */
    if (((hi_s32)judge_list->jiffies_end - (hi_s32)judge_list->jiffies_st) > (hi_s32)(JUDGE_CACHE_LIFETIME * HZ)) {
        /* ǿ��ת��Ϊlong��ֹjiffies��� */
        hmac_user->judge_list.to_judge_num = 0;    /* ��ն��� */
        return HI_FAIL;
    }

    /* ����������δ��ʱ */
    for (hi_u8 cache_idx_i = 0; cache_idx_i < (MAX_JUDGE_CACHE_LENGTH >> 1); cache_idx_i++) {
        judge_info = (hmac_tx_judge_info_stru*)(judge_list->ast_judge_cache + cache_idx_i);

        if (judge_info->flag == HI_FALSE) {
            continue;
        }

        judge_info->flag = HI_FALSE;
        if (memcpy_s(&mark, sizeof(hmac_tx_judge_info_stru), judge_info, sizeof(hmac_tx_judge_info_stru)) != EOK) {
            oam_error_log0(0, OAM_SF_CFG, "hmac_tx_find_major_traffic:: pst_judge_info memcpy_s fail.");
            continue;
        }
        mark.wait_check_num = 1;

        for (hi_u8 cache_idx_j = 0; cache_idx_j < MAX_JUDGE_CACHE_LENGTH; cache_idx_j++) {
            judge_info = (hmac_tx_judge_info_stru*)(judge_list->ast_judge_cache + cache_idx_j);

            if ((judge_info->flag == HI_TRUE) &&
                !memcmp(&judge_info->flow_info, &mark.flow_info, sizeof(hmac_tx_flow_info_stru))) {
                judge_info->flag     = HI_FALSE;
                mark.average_len      += judge_info->len;
                mark.wait_check_num   += 1;
            }

            if (mark.wait_check_num <= max.wait_check_num) {
                continue;
            }
            if (memcpy_s(&max, sizeof(hmac_tx_major_flow_stru), &mark, sizeof(hmac_tx_major_flow_stru)) != EOK) {
                oam_error_log0(0, OAM_SF_CFG, "hmac_tx_find_major_traffic:: st_mark memcpy_s fail.");
                continue;
            }
            if (max.wait_check_num >= (MAX_JUDGE_CACHE_LENGTH >> 1)) {
                /* ���ҵ���Ҫҵ���������ؼ������� */
                max.average_len = max.average_len / max.wait_check_num;
                return hmac_tx_traffic_judge(hmac_user, &max, puc_tid);
            }
        }
    }

    if (max.wait_check_num < (MAX_JUDGE_CACHE_LENGTH >> 2)) { /* 2:����2λ */
        /* ��Ϊû����Ҫҵ���� */
        hmac_user->judge_list.to_judge_num = 0;    /* ��ն��� */
        return HI_FAIL;
    }

    max.average_len = max.average_len / max.wait_check_num;
    return hmac_tx_traffic_judge(hmac_user, &max, puc_tid);
}

hi_void hmac_tx_traffic_classify_list_proc(const mac_ip_header_stru *ip, hi_u8 *puc_tid,
    const hmac_tx_flow_info_stru *flow_info, hmac_user_stru *hmac_user, udp_hdr_stru *udp_hdr)
{
    /* ������δʶ�𣬴����û���ʶ����� */
    hmac_tx_judge_list_stru *judge_list = &(hmac_user->judge_list);
    hmac_tx_judge_info_stru *judge_info = (hmac_tx_judge_info_stru *)(judge_list->ast_judge_cache +
        judge_list->to_judge_num);

    if (judge_list->to_judge_num >= MAX_JUDGE_CACHE_LENGTH) { /* ����������ʶ������е�����������¼ */
        return;
    }

    judge_list->jiffies_end = hi_get_tick();       /* ������������ʱ�� */
    if (judge_list->to_judge_num == 0) {            /* ������Ϊ�� */
        judge_list->jiffies_st = hi_get_tick();    /* ���¶��в���ʱ�� */
    }
    judge_list->to_judge_num += 1;                   /* ���¶��г��� */

    if (memset_s(judge_info, sizeof(hmac_tx_judge_info_stru), 0, sizeof(hmac_tx_judge_info_stru)) != EOK) {
        return;
    }
    if (memcpy_s(&(judge_info->flow_info), sizeof(hmac_tx_flow_info_stru), flow_info,
                 sizeof(hmac_tx_flow_info_stru)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_tx_traffic_classify:: st_flow_info memcpy_s fail.");
        return;
    }

    hmac_tx_rtp_hdr *rtp_hdr = (hmac_tx_rtp_hdr *)(udp_hdr + 1);                 /* ƫ��һ��UDPͷ��ȡRTPͷ */

    judge_info->flag         = HI_TRUE;
    judge_info->len          = oal_net2host_short(ip->us_tot_len) - sizeof(mac_ip_header_stru) - sizeof(udp_hdr_stru);
    judge_info->rtpver       = rtp_hdr->version_and_csrc;
    judge_info->payload_type = (hi_u32)(rtp_hdr->payload_type);

    /* �˴�����2�ֽڶ���ָ������4�ֽڶ����������liteos�ϻ����������linux�ĺ������� */
    /* pst_rtp_hdr:Ϊ2�ֽڶ����ַ */
    if (memcpy_s(&(judge_info->rtpssrc), sizeof(hi_u32), &(rtp_hdr->ssrc), sizeof(hi_u32)) != EOK) {
        oam_error_log0(0, OAM_SF_CFG, "hmac_tx_traffic_classify:: ul_SSRC memcpy_s fail.");
        return;
    }

    /* ����ʶ�����������������ȡ������Ҫҵ�񲢽���ҵ��ʶ�� */ /* "<=":��ֹ���̲���ʹ��ֵ���ڴ�ʶ����г��ȶ����ڴ� */
    if ((judge_list->to_judge_num >= MAX_JUDGE_CACHE_LENGTH) &&
        (hmac_tx_find_major_traffic(hmac_user, puc_tid) != HI_SUCCESS)) {
        oam_info_log0(0, OAM_SF_TX, "hmac_tx_traffic_classify::the classify process failed.");
    }
}

/*****************************************************************************
 �� �� ��  : hmac_tx_traffic_classify
 ��������  : ���������ݰ����д���:
                ��ҵ���ѱ�ʶ��ֱ�ӷ���TID, ������ȡ��ͷ��Ϣ�������������
 �������  : netbuff CB�ֶ�ָ�룬ipͷָ�룬TIDָ��
 �������  :
 �� �� ֵ  :
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.����: 2015.11.26
    ����: wanghao(w00357635)
    �޸�����: �����º���
  2.����: 2015.12.26
    ����: wanghao(w00357635)
    �޸�����: TCPҵ��ʶ���ܲü�
*****************************************************************************/
hi_void hmac_tx_traffic_classify(const hmac_tx_ctl_stru *tx_ctl, mac_ip_header_stru *ip, hi_u8 *puc_tid)
{
    hmac_tx_flow_info_stru  flow_info;
    hmac_user_stru         *hmac_user = (hmac_user_stru *)hmac_user_get_user_stru(tx_ctl->us_tx_user_idx);

    if (hmac_user == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "hmac_tx_traffic_classify::cannot find hmac_user_stru!");
        return;
    }

    /* ���ܲü���ֻ����UDP���ģ��Լ�ʶ��WifiDisplay RTSPҵ��ΪVI */
    if (ip->protocol != MAC_UDP_PROTOCAL) {
        if (ip->protocol == MAC_TCP_PROTOCAL) {
            mac_tcp_header_stru *tcp_hdr = (mac_tcp_header_stru *)(ip + 1);

            /* ʶ��WifiDisplay RTSPҵ��ΪVI */
            if (oal_ntoh_16(MAC_WFD_RTSP_PORT) == tcp_hdr->us_sport) {
                *puc_tid = WLAN_TIDNO_VIDEO;
                return;
            }
        }
        return;
    }

    /* ��ΪIP��Ƭ֡��û�ж˿ںţ�ֱ�ӷ��� */
    if ((oal_ntoh_16(ip->us_frag_off) & IP_FRAGMENT_MASK) != 0) {
        return;
    }

    udp_hdr_stru *udp_hdr = (udp_hdr_stru *)(ip + 1);                         /* ƫ��һ��IPͷ��ȡUDPͷ */

    /* ��ȡ��Ԫ�� */
    flow_info.us_dport = udp_hdr->us_des_port;
    flow_info.us_sport = udp_hdr->us_src_port;
    flow_info.dip      = ip->daddr;
    flow_info.sip      = ip->saddr;
    flow_info.proto    = (hi_u32)(ip->protocol);

    /* �����������û���ʶ��ҵ��ֱ�ӷ���TID */
    for (hi_u8 loop = 0; loop < hmac_user->cfm_num; loop++) {
        hmac_tx_cfm_flow_stru *cfm_info = (hmac_tx_cfm_flow_stru *)(hmac_user->ast_cfm_flow_list + loop);
        if (!memcmp(&cfm_info->cfm_flow_info, &flow_info, sizeof(hmac_tx_flow_info_stru))) {
            *puc_tid = (hi_u8)(cfm_info->us_cfm_tid);
            cfm_info->last_jiffies = hi_get_tick();   /* ����ҵ����������ʱ�� */
            return;
        }
    }

    hmac_tx_traffic_classify_list_proc(ip, puc_tid, &flow_info, hmac_user, udp_hdr);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
