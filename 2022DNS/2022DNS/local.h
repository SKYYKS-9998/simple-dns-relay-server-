#pragma once

#ifndef SOCKLIB
#include <WinSock2.h>
//#include <Ws2tcpip.h>
//#pragma comment(lib, "WS2_32.lib")
#define SOCKLIB
#endif // !SOCKLIB

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//解析项，IP地址以及对应域名，用于存储本地数据
typedef struct
{
    uint32_t ip;
    char* domain;
}Resolve;

//单链表节点形式的解析项，用于存储本地数据
typedef struct snode
{
    Resolve item;
    struct snode* next;
}resolveSingleP;

//本地文件数据
typedef struct
{
    resolveSingleP* localHead;
    int itemNum;
}LocalRecord;

extern LocalRecord localRec;			//本地dnsrelay.txt数据
