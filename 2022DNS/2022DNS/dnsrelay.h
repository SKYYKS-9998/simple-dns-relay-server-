#pragma once
#ifndef SOCKLIB
#include <WinSock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "WS2_32.lib")
#define SOCKLIB
#endif // !SOCKLIB

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "getopt.h"
#include <Windows.h>
#include <string.h> 
#include "cache.h"
#include "local.h"

#define ID_LEN 2                    //ID�ֶ��ֽڳ���
#define HEAD_LEN 12                 //DNS�ײ��ֽڳ���
#define BUF_SIZE 1024               //�շ���������С
#define MAX_NAME_LEN 256            //���������
#define MAX_QUERY_SIZE 65536        //�ɵȴ���Ӧ�Ĳ�ѯ�������Ŀ��������ID������
#define MAX_CACHE_SIZE 1000         //Cache�������
#define DOMAIN_OFFSET_PTR 0xC00C    //DNS������RR��NAME�ֶ����õ�ƫ������ָ��QUESTION���ֵ�QNAME�ֶ�
#define INTERNET_CLASS 1            //RR��CLASS�ֶΣ�ָInternet����
#define RR_TYPE_A 1                 //RR��������
#define RR_TYPE_A_LEN 4             //4�ֽڵ�IPv4��ַ
#define TWO_DAY_TTL 172800          //�������Դ��¼����ʱ��

//DNS�����ײ�
typedef struct
{
    unsigned id : 16;    /* query identification number */
    unsigned rd : 1;     /* recursion desired */
    unsigned tc : 1;     /* truncated message */
    unsigned aa : 1;     /* authoritive answer */
    unsigned opcode : 4; /* purpose of message */
    unsigned qr : 1;     /* response flag */
    unsigned rcode : 4;  /* response code */
    unsigned cd : 1;     /* checking disabled by resolver */
    unsigned ad : 1;     /* authentic data from named */
    unsigned z : 1;      /* unused bits, must be ZERO */
    unsigned ra : 1;     /* recursion available */
    
    uint16_t qdcount;       /* number of question entries */
    uint16_t ancount;       /* number of answer entries */
    uint16_t nscount;       /* number of authority entries */
    uint16_t arcount;       /* number of resource entries */
}DNSheader;

//DNS Question�ֶ�
typedef struct
{
    unsigned char qname[MAX_NAME_LEN];
    uint16_t qtype;
    uint16_t qclass;
}DNSquestion;

//DNS RR�ֶ�
typedef struct
{
    uint16_t name;
    uint16_t type;
    uint16_t _class;
    uint16_t ttl;
    uint16_t _ttl;
    uint16_t rdlen;
    uint32_t rdata;
}DNSrr;

/*
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

//˫������ڵ�Ľ�������ڴ洢cache
typedef struct dnode
{
    unsigned char* domain;
    unsigned char response[BUF_SIZE];
    struct dnode* prev;
    struct dnode* next;
}resolveTwowayP;

//�����ļ�����
typedef struct
{
    resolveSingleP* localHead;
    int itemNum;
}LocalRecord;

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
*/

extern void initCache();			//��ʼ��cache
extern unsigned char* searchCache(char* domain);		//��cache�������������ظ���������Ӧ
extern void updateCache(resolveTwowayP* target);		//���еĿ��Ƶ���һλ
extern void addCache(int fromID);						//���ⲿDNS�������յ���������������cache
extern void freeCache();			//�ͷ�Cache

extern void readTxt(char* path);	//���ļ����洢д��localRec
extern unsigned int* searchLocal(char* domain);		//��localRec��������������IP��ַ
extern void freeLocal();			//�ͷű�������