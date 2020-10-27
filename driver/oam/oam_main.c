/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: oam main implementation.(non-rom).
 * Author: Hisilicon
 * Create: 2018-08-04
 */

#include "oam_main.h"
#include "hi_types_base.h"
#ifdef _PRE_LINUX_BUILTIN
#include "plat_firmware.h"
#include "wal_net.h"
#endif
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  2 全局变量定义
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static struct kobject *g_sysfs_hi110x_oam = HI_NULL;
#endif

/*****************************************************************************
  3 函数实现
*****************************************************************************/
/*****************************************************************************
 功能描述  : OAM模块初始化总入口，包含OAM模块内部所有特性的初始化。
 返 回 值  : 初始化返回值，成功或失败原因
*****************************************************************************/
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
static ssize_t log_level_show(struct kobject *kobj,
                              struct kobj_attribute *attr, char *buf)
{
    if (buf == HI_NULL) {
        return -HI_FAIL;
    }

    return snprintf_s(buf, PAGE_SIZE, PAGE_SIZE - 1, "loglevel:             \n"
                     " 0    close log           \n"
                     " 1    ERROR               \n"
                     " 2    WARN                \n"
                     " 3    INFO                \n");
}

STATIC ssize_t store_log_level_set(struct device *dev, struct kobj_attribute *attr, const char *buf, size_t count)
{
    hi_s32 input;
    if (buf == HI_NULL) {
        return -HI_FAIL;
    }

    input = oal_atoi(buf);
    if (input < 0 || input > 5) {    /* input must range [0 5] */
        return -HI_FAIL;
    }

    g_level_log = (hi_u32)input;
    return count;
}
#ifdef _PRE_LINUX_BUILTIN
static ssize_t fw_show(struct kobject *kobj,
                              struct kobj_attribute *attr, char *buf)
{
    if (buf == HI_NULL) {
        return -HI_FAIL;
    }

    return snprintf_s(buf, PAGE_SIZE, PAGE_SIZE - 1, "state:    [%s]\n\n"
        "chose from:\n"
        "1:  install firmware\n", (wal_get_fw_install() == 1) ? "install" : "uninstall");
}

static ssize_t fw_set(struct device *dev, struct kobj_attribute *attr, const char *buf, size_t count)
{
    hi_s32 input;
    if (buf == HI_NULL) {
        return -HI_FAIL;
    }

    input = oal_atoi(buf);
    if (input != 1) {    /* input must range [1] */
        return -HI_FAIL;
    }
    if (input == 1) {
        if (wal_proc_installfw() != HI_SUCCESS) {
            printk("install firmware error\r\n");
        }
    }
    return count;
}

static ssize_t mfg_show(struct kobject *kobj,
                              struct kobj_attribute *attr, char *buf)
{
    if (buf == HI_NULL) {
        return -HI_FAIL;
    }

    return snprintf_s(buf, PAGE_SIZE, PAGE_SIZE - 1, "mfg:    [%d]\n\n"
        "chose from:\n"
        "0:  nonfactory mode\n"
        "1:  factory mode\n", firmware_get_fw_mode());
}

static ssize_t mfg_set(struct device *dev, struct kobj_attribute *attr, const char *buf, size_t count)
{
    hi_s32 input;
    if (buf == HI_NULL) {
        return -HI_FAIL;
    }

    input = oal_atoi(buf);
    if (input != 0 && input != 1) {    /* input must range [0 1] */
        return -HI_FAIL;
    }
    firmware_set_fw_mode(input);
    printk("set_fw_mode:%s\r\n", (input == 1) ? "factory" : "nonfactory");
    return count;
}

STATIC struct kobj_attribute host_load_fw_attr =
__ATTR(fw_load, 0664, (void *)fw_show, (void *)fw_set);    /* mode 0664 */
STATIC struct kobj_attribute host_fw_mode_attr =
__ATTR(fw_mode, 0664, (void *)mfg_show, (void *)mfg_set);    /* mode 0664 */
#endif

STATIC struct kobj_attribute g_oam_host_log_attr =
__ATTR(loglevel, 0664, (void *)log_level_show, (void *)store_log_level_set);    /* mode 0664 */

static struct attribute *g_oam_log_attrs[] = {
    &g_oam_host_log_attr.attr,
#ifdef _SDIO_TEST
    &oam_sdio_test_attr.attr,
#endif
#ifdef _PRE_LINUX_BUILTIN
    &host_load_fw_attr.attr,
    &host_fw_mode_attr.attr,
#endif
    NULL
};

static struct attribute_group g_oam_state_group = {
    .attrs = g_oam_log_attrs,
};

hi_s32 oam_user_ctrl_init(void)
{
    hi_s32 ret;
    g_sysfs_hi110x_oam = kobject_create_and_add("hi3881_debug", HI_NULL);
    if (g_sysfs_hi110x_oam == HI_NULL) {
        oam_print_err("kobject_create_and_add fail!ret=%d", -ENOMEM);
        return -ENOMEM;
    }

    ret = sysfs_create_group(g_sysfs_hi110x_oam, &g_oam_state_group);
    if (ret) {
        oam_print_err("sysfs_create_group fail!ret=%d", ret);
    }
    return ret;
}

static hi_s32 oam_user_ctrl_exit(hi_void)
{
    if (g_sysfs_hi110x_oam) {
        sysfs_remove_group(g_sysfs_hi110x_oam, &g_oam_state_group);
        kobject_put(g_sysfs_hi110x_oam);
    }
    return HI_SUCCESS;
}
#endif

hi_s32 oam_main_init(hi_void)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_s32 ret = oam_user_ctrl_init();
    if (ret != HI_SUCCESS) {
        return ret;
    }
#endif
    printk("oam_main_init SUCCESSFULLY!\r\n");
    return HI_SUCCESS;
}

#if (_PRE_MULTI_CORE_MODE_OFFLOAD_DMAC == _PRE_MULTI_CORE_MODE)
/*****************************************************************************
 功能描述  : OAM模块卸载
 返 回 值  : 模块卸载返回值，成功或失败原因
*****************************************************************************/
hi_void oam_main_exit(hi_void)
{
#if (_PRE_OS_VERSION_LINUX == _PRE_OS_VERSION)
    hi_s32 ret = oam_user_ctrl_exit();
    if (ret != HI_SUCCESS) {
        oam_warning_log0(0, 0, "oam_main_exit:: oam_user_ctrl_exit fail!");
    }
#endif
    return ;
}
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
