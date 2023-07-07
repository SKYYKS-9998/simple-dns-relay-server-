#pragma once
#ifndef SOCKLIB
#include <WinSock2.h>
//#include <Ws2tcpip.h>
//#pragma comment(lib, "WS2_32.lib")
#define SOCKLIB
#endif // !SOCKLIB

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ID_LEN 2                    //ID字段字节长度
#define BUF_SIZE 1024               //收发缓冲区大小
#define MAX_QUERY_SIZE 65536        //可等待响应的查询的最大数目，即可用ID的数量
#define MAX_CACHE_SIZE 1000         //Cache最大容量

//双向链表节点的解析项，用于存储cache
typedef struct dnode
{
    unsigned char* domain;
    unsigned char response[BUF_SIZE];
    struct dnode* prev;
    struct dnode* next;
}resolveTwowayP;

//Cache
typedef struct
{
    resolveTwowayP* cacheHead;
    int itemNum;
}Cache;

//等待响应的查询
typedef struct
{
    char* domain;
    uint16_t oldID;
    SOCKADDR_IN client;
}Query;

extern Cache cache;
extern Query query[MAX_QUERY_SIZE];
extern unsigned char recv_buf[BUF_SIZE];	