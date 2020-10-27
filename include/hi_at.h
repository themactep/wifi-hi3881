/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: AT command interfaces.
 * Author: hisilicon
 * Create: 2019-10-15
 */

/**
* @file hi_at.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: AT command interfaces.
*/

/** @defgroup iot_at  AT Command
 *  @ingroup dfx
 */
#ifndef __HI_AT_H__
#define __HI_AT_H__

typedef unsigned int (*at_call_back_func)(int argc, const char **argv);

typedef struct {
    char *at_cmd_name;
    char  at_cmd_len;
    at_call_back_func at_test_cmd;
    at_call_back_func at_query_cmd;
    at_call_back_func at_setup_cmd;
    at_call_back_func at_exe_cmd;
} at_cmd_func;

/**
* @ingroup  iot_at
* @brief  Registration command processing function.CNcomment:ע�����������CNend
*
* @par ����:
*           @li This command is invoked during initialization and cannot be invoked by multiple tasks.
CNcomment:�ڳ�ʼ���׶ε���, ��֧�ֶ�������á�CNend
*           @li A maximum of 20 different command tables can be registered.
CNcomment:�����ע��20����ͬ�������CNend
*
* @attention None
* @param  cmd_tbl    [IN] type #at_cmd_func*��Command table, which must be declared as a constant array and
*                    transferred to this parameter.CNcomment:�����
��������Ϊ�������鴫���ò�����CNend
* @param  cmd_num    [IN] type #hi_u16��The number of commands. The value must be equal to the actual number of
*                    commands in the command table. If it is less than the actual command number, only the number of
*                    commands equal to this value is registered. If it is greater than the actual command number,
*                    the command table will be accessed out of bounds.
CNcomment:�����������ĸ�������ֵ��������������ʵ�ʵ�������������С��ʵ������������ֻע����ڸ�ֵ�����������
          ����ʵ������������ᵼ��Խ����������CNend
*
* @retval #HI_ERR_SUCCESS         Success.
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3881_V100R001C00
*/
unsigned int hi_at_register_cmd(const at_cmd_func *cmd_tbl, unsigned short cmd_num);

/**
* @ingroup  iot_at
* @brief  Formats the data and outputs it to AT command terminal.
CNcomment:�����ݸ�ʽ�������AT�����նˡ�CNend
*
* @par ����: Formats the data and outputs it to AT command terminal.
CNcomment:�����ݸ�ʽ�������AT�����նˡ�CNend
* @attention None
*
* @param fmt      [IN]  type #const char *�� Formatting control string.CNcomment:��ʽ�������ַ�����CNend
* @param ...      [IN]  Optional parameter CNcomment:��ѡ������CNend
*
* @retval None
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see dprintf
* @since Hi3881_V100R001C00
*/
#define hi_at_printf(fmt, ...)                 \
    do {                                       \
        dprintf(fmt, ##__VA_ARGS__);           \
    } while (0)

/**
* @ingroup  iot_at
* @brief  Register factory test AT command. CNcomment:ע��������AT���CNend
*
* @par ����:
*           Register factory test AT command. CNcomment:�ú�������ע��������AT���CNend
* @param None
* @retval None
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3881_V100R001C00
*/
void hi_at_factory_shell_cmd_register(void);

/**
* @ingroup  iot_at
* @brief  Register wifi AT command. CNcomment:ע��wifi���AT���CNend
*
* @par ����:
*           Register wifi AT command. CNcomment:ע��wifi���AT���CNend
* @param None
* @retval None
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3881_V100R001C00
*/
void hi_at_wifi_shell_cmd_register(void);

/**
* @ingroup  iot_at
* @brief  Register general AT command. CNcomment:ע�᳣���AT���CNend
*
* @par ����:
*           Register general AT command. CNcomment:ע�᳣���AT���CNend
* @param None
* @retval None
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3881_V100R001C00
*/
void hi_at_general_cmd_register(void);

#endif
