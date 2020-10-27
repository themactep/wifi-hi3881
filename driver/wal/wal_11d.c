/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: 11d interface function.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "oal_ext_if.h"
#include "wal_event_msg.h"
#include "wal_main.h"
#include "wal_regdb.h"
#include "wal_11d.h"
#include "wal_ioctl.h"
#include "wal_cfg80211.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 ȫ�ֱ�������
*****************************************************************************/
const wal_dfs_domain_entry_stru g_ast_dfs_domain_table[] = {
    {"AE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"AL", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"AM", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"AN", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"AR", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"AT", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"AU", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"AZ", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BA", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BG", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BH", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BL", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"BN", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BO", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BR", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"BY", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"BZ", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"CA", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"CH", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"CL", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"CN", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"CO", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"CR", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"CS", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"CY", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"CZ", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"DE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"DK", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"DO", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"DZ", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"EC", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"EE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"EG", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"ES", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"FI", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"FR", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"GB", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"GE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"GR", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"GT", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"HK", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"HN", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"HR", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"HU", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"ID", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"IE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"IL", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"IN", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"IQ", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"IR", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"IS", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"IT", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"JM", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"JO", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"JP", MAC_DFS_DOMAIN_MKK, {0, 0, 0}},
    {"KP", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"KR", MAC_DFS_DOMAIN_KOREA, {0, 0, 0}},
    {"KW", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"KZ", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"LB", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"LI", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"LK", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"LT", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"LU", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"LV", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"MA", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"MC", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"MK", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"MO", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"MT", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"MX", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"MY", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"NG", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"NL", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"NO", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"NP", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"NZ", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"OM", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"PA", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"PE", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"PG", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"PH", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"PK", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"PL", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"PR", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"PT", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"QA", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"RO", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"RU", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"SA", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"SE", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"SG", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"SI", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"SK", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"SV", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"SY", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"TH", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"TN", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"TR", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"TT", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"TW", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"UA", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"US", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"UY", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"UZ", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"VE", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"VN", MAC_DFS_DOMAIN_ETSI, {0, 0, 0}},
    {"YE", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
    {"ZA", MAC_DFS_DOMAIN_FCC, {0, 0, 0}},
    {"ZW", MAC_DFS_DOMAIN_NULL, {0, 0, 0}},
};

/*****************************************************************************
  3 ����ʵ��
*****************************************************************************/
/*****************************************************************************
 ��������  : ��ȡһ�����������ʼƵ��
 �������  : ul_start_freq: ��ʼƵ��
             ul_end_freq  : ����Ƶ��
*****************************************************************************/
static inline hi_u8 wal_regdomain_get_band(hi_u32 start_freq, hi_u32 end_freq)
{
    if (start_freq > 2400 && end_freq < 2500) { /* 2400 ��ʼƵ�ʵ���Сֵ 2500 ����Ƶ�ʵ����ֵ */
        return MAC_RC_START_FREQ_2;
    }
    return MAC_RC_START_FREQ_BUTT;
}

/*****************************************************************************
 ��������  : ��ȡһ��������Ĵ���
 �������  : uc_bw: linux�������еĴ���ֵ
*****************************************************************************/
static inline hi_u8 wal_regdomain_get_bw(hi_u8 bw)
{
    switch (bw) {
        case 40: /* 40 ����Ϊ40MHZ */
            return MAC_CH_SPACING_40MHZ;
        case 20: /* 20 ����Ϊ20MHZ */
            return MAC_CH_SPACING_20MHZ;
        default:
            return MAC_CH_SPACING_BUTT;
    }
}

/*****************************************************************************
 ��������  : ��ȡ�������ŵ�λͼ���ŵ���2gƵ����
 �������  : ul_start_freq: ��ʼƵ��
             ul_end_freq  : ����Ƶ��
*****************************************************************************/
static hi_u32 wal_regdomain_get_channel_2g(hi_u32 start_freq, hi_u32 end_freq)
{
    hi_u32 freq;
    hi_u32 i;
    hi_u32 ch_bmap = 0;
    mac_freq_channel_map_stru ast_freq_map_2g;

    for (freq = start_freq + 10; freq <= (end_freq - 10); freq++) { /* 10 ���� */
        for (i = 0; i < MAC_CHANNEL_FREQ_2_BUTT; i++) {
            ast_freq_map_2g = get_ast_freq_map_2g_elem(i);
            if (freq == ast_freq_map_2g.us_freq) {
                ch_bmap |= (1 << i);
            }
        }
    }

    return ch_bmap;
}

/*****************************************************************************
 ��������  : ��ȡ1����������ŵ�λͼ
 �������  : uc_band      : Ƶ��
             ul_start_freq: ��ʼƵ��
             ul_end_freq  : ��ֹƵ��
*****************************************************************************/
static inline hi_u32 wal_regdomain_get_channel(hi_u8 band, hi_u32 start_freq, hi_u32 end_freq)
{
    if (band == MAC_RC_START_FREQ_2) {
        return wal_regdomain_get_channel_2g(start_freq, end_freq);
    }
    return 0;
}

/*****************************************************************************
 �� �� ��  : wal_get_dfs_domain
 ��������  : ���ݹ����룬��ȡ��Ӧ���״����׼
 �������  : pst_mac_regdom: ������ָ��
             pc_country    : ������
 �������  : pst_mac_regdom: ������ָ��
 �� �� ֵ  : ��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2014��10��31��
    ��    ��   : Hisilicon
    �޸�����   : �����ɺ���

*****************************************************************************/
static inline hi_void wal_get_dfs_domain(mac_regdomain_info_stru *mac_regdom, const hi_char *pc_country)
{
    hi_u32    u_idx;

    for (u_idx = 0; u_idx < hi_array_size(g_ast_dfs_domain_table); u_idx++) {
        if (0 == strcmp(g_ast_dfs_domain_table[u_idx].pc_country, pc_country)) {
            mac_regdom->dfs_domain = g_ast_dfs_domain_table[u_idx].dfs_domain;
            return;
        }
    }

    mac_regdom->dfs_domain = MAC_DFS_DOMAIN_NULL;
}

/*****************************************************************************
 ��������  : �������·��Ĺ�������Ϣ
 �������  : pst_regdom    : ָ��linux�Ĺ�������Ϣ
             pst_mac_regdom: ָ��Ҫ�·��Ĺ�������Ϣ
*****************************************************************************/
static hi_u32 wal_regdomain_fill_info(const oal_ieee80211_regdomain_stru *regdom,
                                      mac_regdomain_info_stru *mac_regdom)
{
    hi_u32  i;
    hi_u32  start;
    hi_u32  end;
    hi_u8   band;
    hi_u8   bw;

    /* ���ƹ����ַ��� */
    mac_regdom->ac_country[0] = regdom->alpha2[0];
    mac_regdom->ac_country[1] = regdom->alpha2[1];
    mac_regdom->ac_country[2] = 0; /* 2 ������ĵ�3λ */
    /* ��ʼ������������Ϊ0 */
    mac_regdom->regclass_num = 0;
    /* ��ȡDFS��֤��׼���� */
    wal_get_dfs_domain(mac_regdom, regdom->alpha2);
    /* ����������Ϣ */
    for (i = 0; i < regdom->n_reg_rules; i++) {
        /* ��д�������Ƶ��(2.4G��5G) */
        start = regdom->reg_rules[i].freq_range.start_freq_khz / 1000; /* 1000 Ƶ�ʵ�λת�� */
        end   = regdom->reg_rules[i].freq_range.end_freq_khz / 1000; /* 1000 Ƶ�ʵ�λת�� */
        band  = wal_regdomain_get_band(start, end);
        mac_regdom->regclass_num++;
        if (mac_regdom->regclass_num > WLAN_MAX_RC_NUM) {
            oam_warning_log1(0, OAM_SF_CFG, "wal_regdomain_fill_info: regclass num[%d] overflow.",
                             mac_regdom->regclass_num);
            return HI_FAIL;
        }
        mac_regdom->ast_regclass[i].start_freq = band;
        /* ��д����������������� */
        bw = (hi_u8)(regdom->reg_rules[i].freq_range.max_bandwidth_khz / 1000); /* 1000 Ƶ�ʵ�λת�� */
        mac_regdom->ast_regclass[i].ch_spacing = wal_regdomain_get_bw(bw);
        /* ��д�������ŵ�λͼ */
        mac_regdom->ast_regclass[i].channel_bmap = wal_regdomain_get_channel(band, start, end);
        /* ��ǹ�������Ϊ */
        mac_regdom->ast_regclass[i].behaviour_bmap = 0;
        if (regdom->reg_rules[i].flags & NL80211_RRF_DFS) {
            mac_regdom->ast_regclass[i].behaviour_bmap |= MAC_RC_DFS;
        }
        /* ��串���������͹��� */
        mac_regdom->ast_regclass[i].coverage_class = 0;
        mac_regdom->ast_regclass[i].max_reg_tx_pwr =
            (hi_u8)(regdom->reg_rules[i].power_rule.max_eirp / 100); /* 100 ��λת�� */
        mac_regdom->ast_regclass[i].max_tx_pwr     =
            (hi_u8)(regdom->reg_rules[i].power_rule.max_eirp / 100); /* 100 ��λת�� */
    }
    return HI_SUCCESS;
}

/*****************************************************************************
 ��������  : �·����ù�������Ϣ
 �������  : pst_net_dev: net_device
             pc_country : Ҫ���õĹ����ַ���
*****************************************************************************/
hi_u32 wal_regdomain_update(oal_net_device_stru *netdev, const hi_char *pc_country, hi_u8 country_code_len)
{
    wal_msg_write_stru write_msg;

    hi_unref_param(country_code_len);
    if (!oal_is_alpha_upper(pc_country[0]) || !oal_is_alpha_upper(pc_country[1])) {
        if ((pc_country[0] == '9') && (pc_country[1] == '9')) {
            oam_info_log0(0, OAM_SF_ANY, "{wal_regdomain_update::set regdomain to 99!}");
        } else {
            oam_warning_log0(0, OAM_SF_ANY, "{wal_regdomain_update::country str is invalid!}");
            return HI_FAIL;
        }
    }

    const oal_ieee80211_regdomain_stru *regdom = wal_regdb_find_db(pc_country);
    if (regdom == HI_NULL) {
        oam_warning_log0(0, OAM_SF_ANY, "{wal_regdomain_update::no regdomain db was found!}");
        return HI_ERR_CODE_PTR_NULL;
    }

    wal_set_cfg_regdb(regdom);

    /* �����ڴ��Ź�������Ϣ�����ڴ�ָ����Ϊ�¼�payload����ȥ */
    /* �˴�������ڴ����¼��������ͷ�(hmac_config_set_country) */
    hi_u16 us_size = (hi_u16)sizeof(mac_regdomain_info_stru);
    mac_regdomain_info_stru *mac_regdom = oal_mem_alloc(OAL_MEM_POOL_ID_LOCAL, us_size);
    if (mac_regdom == HI_NULL) {
        oam_error_log0(0, OAM_SF_ANY, "{wal_regdomain_update::alloc regdom mem fail, return null ptr!}");
        return HI_FAIL;
    }

    if (wal_regdomain_fill_info(regdom, mac_regdom) != HI_SUCCESS) {
        oal_mem_free(mac_regdom);
        return HI_FAIL;
    }

    /***************************************************************************
        ���¼���wal�㴦��
    ***************************************************************************/
    wal_write_msg_hdr_init(&write_msg, WLAN_CFGID_COUNTRY, sizeof(mac_cfg_country_stru));

    /* ��дWID��Ӧ�Ĳ��� */
    mac_cfg_country_stru *param = (mac_cfg_country_stru *)(write_msg.auc_value);
    param->mac_regdom = mac_regdom;

    /* ������Ϣ */
    hi_u32 ret = wal_send_cfg_event(netdev, WAL_MSG_TYPE_WRITE,
        WAL_MSG_WRITE_MSG_HDR_LENGTH + sizeof(mac_cfg_country_stru), (hi_u8 *)&write_msg, HI_FALSE, HI_NULL);
    if (oal_unlikely(ret != HI_SUCCESS)) {
        oam_warning_log1(0, OAM_SF_ANY, "{wal_regdomain_update::return err code %d!}", ret);
        oal_mem_free(mac_regdom);
        return ret;
    }

    return HI_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

