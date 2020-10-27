/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oal_file.h
 * Author: Hisilicon
 * Create: 2020-01-09
 */

#ifndef __OAL_FILE_H__
#define __OAL_FILE_H__

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#include <linux/fs.h>
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#include <fs/fs.h>
#include <fcntl.h>
#include <hi_types.h>
#include <fs/file.h>
#endif
#include "oal_mm.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 �궨��
*****************************************************************************/
/* �ļ����� */
#define OAL_O_ACCMODE           O_ACCMODE
#define OAL_O_RDONLY            O_RDONLY
#define OAL_O_WRONLY            O_WRONLY
#define OAL_O_RDWR              O_RDWR
#define OAL_O_CREAT             O_CREAT
#define OAL_O_TRUNC             O_TRUNC
#define OAL_O_APPEND            O_APPEND

#define OAL_SEEK_SET     SEEK_SET    /* Seek from beginning of file.  */
#define OAL_SEEK_CUR     SEEK_CUR    /* Seek from current position.  */
#define OAL_SEEK_END     SEEK_END    /* Set file pointer to EOF plus "offset" */

#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#define OAL_FILE_POS(pst_file)  (pst_file->fp->f_pos)
#define OAL_FILE_FAIL           HI_NULL
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
#define OAL_FILE_POS(pst_file)  oal_get_file_pos(pst_file)
#endif

/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
typedef struct _oal_file_stru_ {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    struct file *fp;
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    int fd;
#endif
} oal_file_stru;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
/*****************************************************************************
 ��������  : ���ļ�
 �������  : pc_path: �ļ�·����flags:�򿪷�ʽ,rights:��Ȩ��
 �������  : ��
 �� �� ֵ  : �ļ����
*****************************************************************************/
static inline oal_file_stru* oal_file_open(const hi_char *pc_path, hi_s32 flags, hi_s32 rights)
{
    oal_file_stru   *pst_file = NULL;
    pst_file = oal_kzalloc(sizeof(oal_file_stru), OAL_GFP_KERNEL);
    if (pst_file == NULL) {
        return HI_NULL;
    }
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    pst_file->fp = filp_open(pc_path, flags, rights);
    if (IS_ERR_OR_NULL(pst_file->fp)) {
        oal_free(pst_file);
        return HI_NULL;
    }
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    pst_file->fd = open(pc_path, flags, rights);
    if (pst_file->fd < 0) {
        oal_free(pst_file);
        return HI_NULL;
    }
#endif

    return pst_file;
}

/*****************************************************************************
 ��������  : д�ļ�
 �������  : file: �ļ����
           : pc_string: �������ݵ�ַ
           : ul_length: �������ݳ���
 �������  : ��
 �� �� ֵ  : �ļ����
*****************************************************************************/
static inline hi_u32 oal_file_write(const oal_file_stru *pst_file, const hi_char *pc_string, hi_u32 ul_length)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_u32 ul_ret;
    mm_segment_t fs;
    fs = get_fs();
    set_fs(KERNEL_DS);
#if (LINUX_VERSION_CODE >= kernel_version(4, 14, 14))
    ul_ret = kernel_write(pst_file->fp, pc_string, ul_length, &(pst_file->fp->f_pos));
#else
    ul_ret = vfs_write(pst_file->fp, pc_string, ul_length, &(pst_file->fp->f_pos));
#endif
    set_fs(fs);
    return ul_ret;
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return (hi_u32)write(pst_file->fd, pc_string, ul_length);
#endif
}

/*****************************************************************************
 ��������  : �ر��ļ�
 �������  : pc_path: �ļ�·��
 �������  : ��
 �� �� ֵ  : �ļ����
*****************************************************************************/
static inline hi_void oal_file_close(oal_file_stru *pst_file)
{
    if (pst_file != HI_NULL) {
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    filp_close(pst_file->fp, NULL);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    close(pst_file->fd);
#endif
        oal_free(pst_file);
        pst_file = NULL;
    }
}

/*****************************************************************************
 ��������  : �ں˶��ļ�����ͷ��ʼ��
 �������  : file:ָ��Ҫ��ȡ���ļ���ָ��
             puc_buf:���ļ��������ݺ��ŵ�buf
             ul_count:ָ��Ҫ��ȡ�ĳ���
 �������  : ��
 �� �� ֵ  :
*****************************************************************************/
static inline hi_s32  oal_file_read(const oal_file_stru *pst_file,
                                    hi_u8 *pc_buf,
                                    hi_u32 ul_count)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
#if (LINUX_VERSION_CODE >= kernel_version(4, 14, 0))
    return kernel_read(pst_file->fp, pc_buf, ul_count, &(pst_file->fp->f_pos));
#else
    return kernel_read(pst_file->fp, pst_file->fp->f_pos, pc_buf, ul_count);
#endif
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return read(pst_file->fd, pc_buf, ul_count);
#endif
}

static inline hi_s64  oal_file_lseek(const oal_file_stru *pst_file, hi_s64 offset, hi_s32 whence)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    return vfs_llseek(pst_file->fp, offset, whence);
#elif (_PRE_OS_VERSION_LITEOS == _PRE_OS_VERSION)
    return lseek(pst_file->fd, offset, whence);
#endif
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of oal_file.h */
