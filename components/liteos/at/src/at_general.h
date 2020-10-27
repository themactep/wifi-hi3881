/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL layer external API interface implementation.
 * Author: Hisilicon
 * Create: 2019-11-11
 */

#ifndef __AT_GENERAL_H__
#define __AT_GENERAL_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define DEFAULT_IFNAME_LOCALHOST    "lo"
#define DEFAULT_IFNAME_AP           "ap0"
#define DEFAULT_IFNAME_STA          "wlan0"
#define DEFAULT_IFNAME_MESH         "mesh0"

unsigned int at_lwip_ifconfig(int argc, const char **argv);
void cmd_reset(void);
void board_power_on(void);
void board_power_off(void);
void LOS_Msleep(unsigned int ms);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif
