/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: include file
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#ifndef __PLAT_SDIO_H__
#define __PLAT_SDIO_H__
/*****************************************************************************
  1 Include other Head file
*****************************************************************************/
#include "hi_types.h"

/*****************************************************************************
  2 Define macro
*****************************************************************************/
/*****************************************************************************
  3 STRUCT DEFINE
*****************************************************************************/
/*****************************************************************************
  4 EXTERN VARIABLE
*****************************************************************************/
/*****************************************************************************
  5 EXTERN FUNCTION
*****************************************************************************/
extern hi_s32 sdio_patch_writesb(hi_u8* buf, hi_u32 len);
extern hi_s32 sdio_patch_readsb(hi_u8* buf, hi_u32 len, hi_u32 timeout);

#endif

