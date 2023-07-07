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

//�����IP��ַ�Լ���Ӧ���������ڴ洢��������
typedef struct
{
    uint32_t ip;
    char* domain;
}Resolve;

//������ڵ���ʽ�Ľ�������ڴ洢��������
typedef struct snode
{
    Resolve item;
    struct snode* next;
}resolveSingleP;

//�����ļ�����
typedef struct
{
    resolveSingleP* localHead;
    int itemNum;
}LocalRecord;

extern LocalRecord localRec;			//����dnsrelay.txt����
