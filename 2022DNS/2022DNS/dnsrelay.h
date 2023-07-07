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

#define ID_LEN 2                    //ID字段字节长度
#define HEAD_LEN 12                 //DNS首部字节长度
#define BUF_SIZE 1024               //收发缓冲区大小
#define MAX_NAME_LEN 256            //域名最长长度
#define MAX_QUERY_SIZE 65536        //可等待响应的查询的最大数目，即可用ID的数量
#define MAX_CACHE_SIZE 1000         //Cache最大容量
#define DOMAIN_OFFSET_PTR 0xC00C    //DNS报文中RR的NAME字段所用的偏移量，指向QUESTION部分的QNAME字段
#define INTERNET_CLASS 1            //RR的CLASS字段，指Internet数据
#define RR_TYPE_A 1                 //RR的类型码
#define RR_TYPE_A_LEN 4             //4字节的IPv4地址
#define TWO_DAY_TTL 172800          //两天的资源记录生存时间

//DNS报文首部
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

//DNS Question字段
typedef struct
{
    unsigned char qname[MAX_NAME_LEN];
    uint16_t qtype;
    uint16_t qclass;
}DNSquestion;

//DNS RR字段
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

//双向链表节点的解析项，用于存储cache
typedef struct dnode
{
    unsigned char* domain;
    unsigned char response[BUF_SIZE];
    struct dnode* prev;
    struct dnode* next;
}resolveTwowayP;

//本地文件数据
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

//等待响应的查询
typedef struct
{
    char* domain;
    uint16_t oldID;
    SOCKADDR_IN client;
}Query;
*/

extern void initCache();			//初始化cache
extern unsigned char* searchCache(char* domain);		//在cache查找域名，返回该域名的响应
extern void updateCache(resolveTwowayP* target);		//命中的块移到第一位
extern void addCache(int fromID);						//从外部DNS服务器收到域名解析，加入cache
extern void freeCache();			//释放Cache

extern void readTxt(char* path);	//读文件，存储写入localRec
extern unsigned int* searchLocal(char* domain);		//在localRec查找域名，返回IP地址
extern void freeLocal();			//释放本地数据