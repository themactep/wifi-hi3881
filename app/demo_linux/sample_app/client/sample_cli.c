/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sample cli file.
 * Author: Hisilicon
 * Create: 2018-08-04
 */

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hi_type.h"
#include "hi_wlan.h"
#include "securec.h"

/*****************************************************************************
  4 函数实现
*****************************************************************************/
hi_void client_send_cmd(hi_s32 sockfd, const hi_char *cmd)
{
    struct sockaddr_in servaddr;
    ssize_t recvbytes;
    hi_char buf[SOCK_BUF_MAX];
    struct sockaddr_in clientaddr;
    socklen_t addrlen = sizeof(clientaddr);

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(SOCK_PORT);

    if (sendto(sockfd, cmd, strlen(cmd), MSG_DONTWAIT, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        printf("SAMPLE_CLIENT: sendto error! file=%s,line=%d,func=%s error:%s\n", \
            __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return;
    }
    recvbytes = recvfrom(sockfd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&clientaddr, &addrlen);
    if (recvbytes < 0) {
        printf("SAMPLE_CLIENT: recvfrom error!file=%s,line=%d,func=%s, error:%s\n", \
            __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return;
    }

    if (strcmp("OK", buf) != 0) {
        printf("SAMPLE_CLIENT: sendto cmd error!\n");
        return;
    }
    printf("SAMPLE_CLIENT: send cmd ok!\n");
}

hi_s32 main(hi_s32 argc, const hi_char **argv)
{
    (void)argc;
    hi_char cmd[SOCK_BUF_MAX] = {0};
    if (argc < 2 || argv == NULL) { /* 2:参数个数 */
        printf("SAMPLE_CLIENT: usage sample_cli <cmd>\n");
        return -1;
    }
    if (strcpy_s(cmd, sizeof(cmd), argv[1]) < 0) {
        printf("SAMPLE_CLIENT: file=%s,line=%d,func=%s\n", __FILE__, __LINE__, __FUNCTION__);
    }
    cmd[strlen(argv[1])] = '\0';

    hi_s32 sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        printf("SAMPLE_CLIENT: file=%s,line=%d,func=%s error:%s\n", __FILE__, __LINE__, __FUNCTION__, strerror(errno));
        return -1;
    }
    client_send_cmd(sockfd, cmd);
    close(sockfd);
    return 0;
}

