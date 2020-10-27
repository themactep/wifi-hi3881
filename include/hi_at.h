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
* @brief  Registration command processing function.CNcomment:注册命令处理函数。CNend
*
* @par 描述:
*           @li This command is invoked during initialization and cannot be invoked by multiple tasks.
CNcomment:在初始化阶段调用, 不支持多任务调用。CNend
*           @li A maximum of 20 different command tables can be registered.
CNcomment:最多能注册20个不同的命令表。CNend
*
* @attention None
* @param  cmd_tbl    [IN] type #at_cmd_func*，Command table, which must be declared as a constant array and
*                    transferred to this parameter.CNcomment:命令表，
必须申明为常量数组传给该参数。CNend
* @param  cmd_num    [IN] type #hi_u16，The number of commands. The value must be equal to the actual number of
*                    commands in the command table. If it is less than the actual command number, only the number of
*                    commands equal to this value is registered. If it is greater than the actual command number,
*                    the command table will be accessed out of bounds.
CNcomment:命令表中命令的个数，该值必须等于命令表中实际的命令个数，如果小于实际命令数，则只注册等于该值的命令个数，
          大于实际命令个数将会导致越界访问命令表。CNend
*
* @retval #HI_ERR_SUCCESS         Success.
* @retval #Other     Failure. For details, see hi_errno.h.
* @par 依赖:
*           @li hi_at.h：Describes at command APIs. CNcomment:文件用于描述at指令相关接口。CNend
* @see  None
* @since Hi3881_V100R001C00
*/
unsigned int hi_at_register_cmd(const at_cmd_func *cmd_tbl, unsigned short cmd_num);

/**
* @ingroup  iot_at
* @brief  Formats the data and outputs it to AT command terminal.
CNcomment:将数据格式化输出到AT命令终端。CNend
*
* @par 描述: Formats the data and outputs it to AT command terminal.
CNcomment:将数据格式化输出到AT命令终端。CNend
* @attention None
*
* @param fmt      [IN]  type #const char *。 Formatting control string.CNcomment:格式化控制字符串。CNend
* @param ...      [IN]  Optional parameter CNcomment:可选参数。CNend
*
* @retval None
*
* @par 依赖:
*           @li hi_at.h：Describes at command APIs. CNcomment:文件用于描述at指令相关接口。CNend
* @see dprintf
* @since Hi3881_V100R001C00
*/
#define hi_at_printf(fmt, ...)                 \
    do {                                       \
        dprintf(fmt, ##__VA_ARGS__);           \
    } while (0)

/**
* @ingroup  iot_at
* @brief  Register factory test AT command. CNcomment:注册产测相关AT命令。CNend
*
* @par 描述:
*           Register factory test AT command. CNcomment:该函数用于注册产测相关AT命令。CNend
* @param None
* @retval None
*
* @par 依赖:
*           @li hi_at.h：Describes at command APIs. CNcomment:文件用于描述at指令相关接口。CNend
* @see  None
* @since Hi3881_V100R001C00
*/
void hi_at_factory_shell_cmd_register(void);

/**
* @ingroup  iot_at
* @brief  Register wifi AT command. CNcomment:注册wifi相关AT命令。CNend
*
* @par 描述:
*           Register wifi AT command. CNcomment:注册wifi相关AT命令。CNend
* @param None
* @retval None
*
* @par 依赖:
*           @li hi_at.h：Describes at command APIs. CNcomment:文件用于描述at指令相关接口。CNend
* @see  None
* @since Hi3881_V100R001C00
*/
void hi_at_wifi_shell_cmd_register(void);

/**
* @ingroup  iot_at
* @brief  Register general AT command. CNcomment:注册常规的AT命令。CNend
*
* @par 描述:
*           Register general AT command. CNcomment:注册常规的AT命令。CNend
* @param None
* @retval None
*
* @par 依赖:
*           @li hi_at.h：Describes at command APIs. CNcomment:文件用于描述at指令相关接口。CNend
* @see  None
* @since Hi3881_V100R001C00
*/
void hi_at_general_cmd_register(void);

#endif
