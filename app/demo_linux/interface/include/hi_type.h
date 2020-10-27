/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Common data types of the system.
 * Author: Hisilicon
 * Create: 2005-4-23
 */

#ifndef __HI_TYPE_H__
#define __HI_TYPE_H__

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------------------------------------------*
 * Defintion of basic data types. The data types are applicable to both the application layer and kernel codes. *
 * CNcomment: 基本数据类型定义，应用层和内核代码均使用  CNend                                                   *
 *--------------------------------------------------------------------------------------------------------------*/
/*************************** Structure Definition ****************************/
/** \addtogroup      Common_TYPE */
/** @{ */  /** <!-- [Common_TYPE] */

typedef unsigned char           hi_uchar;
typedef unsigned char           hi_u8;
typedef unsigned short          hi_u16;
typedef unsigned int            hi_u32;
typedef unsigned long long      hi_u64;
typedef unsigned long           hi_ulong;

typedef char                   *hi_pchar;
typedef char                    hi_char;
typedef signed char             hi_s8;
typedef short                   hi_s16;
typedef int                     hi_s32;
typedef long long               hi_s64;
typedef long                    hi_slong;

typedef float                   hi_float;
typedef double                  hi_double;

typedef unsigned long           hi_size_t;
typedef unsigned long           hi_length_t;
typedef unsigned int            hi_handle;
typedef void                    hi_void;

typedef unsigned int            hi_phys_addr_t;
#ifdef CONFIG_ARCH_LP64_MODE
typedef unsigned long long      hi_virt_addr_t;
#else
typedef unsigned int            hi_virt_addr_t;
#endif

/** Constant Definition */
/** CNcomment: 常量定义 */
typedef enum {
    HI_FALSE    = 0,
    HI_TRUE     = 1,
} hi_bool_t;
typedef hi_bool_t                 hi_bool;

#ifndef NULL
#define NULL                0L
#endif

#define HI_NULL             0L
#define HI_NULL_PTR         0L

#define HI_SUCCESS          0
#define HI_FAILURE          (-1)

#define HI_INVALID_HANDLE   (0xffffffff)

#define HI_INVALID_PTS      (0xffffffff)
#define HI_INVALID_TIME     (0xffffffff)

#define HI_OS_LINUX     0xabcd
#define HI_OS_WIN32     0xcdef

#ifdef _WIN32
#define HI_OS_TYPE      HI_OS_WIN32
#else
#define __OS_LINUX__
#define HI_OS_TYPE      HI_OS_LINUX
#endif

#ifdef HI_ADVCA_SUPPORT
#define __INIT__
#define __EXIT__
#else
#define __INIT__  __init
#define __EXIT__  __exit
#endif

/**
define of hi_handle :
bit31                                                           bit0
  |<----   16bit --------->|<---   8bit    --->|<---  8bit   --->|
  |--------------------------------------------------------------|
  |      HI_MOD_ID_E       |  mod defined data |     chnID       |
  |--------------------------------------------------------------|

mod defined data: private data define by each module(for example: sub-mod id), usually, set to 0.
*/
#define HI_HANDLE_MAKEHANDLE(mod, privatedata, chnid)  \
    (hi_handle)((((mod) & 0xffff) << 16) | ((((privatedata) & 0xff) << 8) ) | (((chnid) & 0xff)))

#define HI_HANDLE_GET_MODID(handle)     (((handle) >> 16) & 0xffff)
#define HI_HANDLE_GET_PriDATA(handle)   (((handle) >> 8) & 0xff)
#define HI_HANDLE_GET_CHNID(handle)     (((handle)) & 0xff)

#define hi_unused(x) ((x) = (x))

/* Linux动态库(.so)函数符号可见 */
#define HI_OPEN_API __attribute__((visibility ("default")))

/** @} */  /** <!-- ==== Structure Definition end ==== */
#ifdef __cplusplus
}
#endif

#endif /* __HI_TYPE_H__ */

