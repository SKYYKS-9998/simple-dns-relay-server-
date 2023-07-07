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

#define ID_LEN 2                    //ID�ֶ��ֽڳ���
#define BUF_SIZE 1024               //�շ���������С
#define MAX_QUERY_SIZE 65536        //�ɵȴ���Ӧ�Ĳ�ѯ�������Ŀ��������ID������
#define MAX_CACHE_SIZE 1000         //Cache�������

//˫������ڵ�Ľ�������ڴ洢cache
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

//�ȴ���Ӧ�Ĳ�ѯ
typedef struct
{
    char* domain;
    uint16_t oldID;
    SOCKADDR_IN client;
}Query;

extern Cache cache;
extern Query query[MAX_QUERY_SIZE];
extern unsigned char recv_buf[BUF_SIZE];	