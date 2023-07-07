#include "dnsrelay.h"

SOCKET sock;					
SOCKADDR_IN serverAddr;			//外部DNS服务器端口以及地址
SOCKADDR_IN localAddr;			//本机端口以及地址
Query query[MAX_QUERY_SIZE];	//待外部服务器响应的查询
LocalRecord localRec;			//本地dnsrelay.txt数据
Cache cache;					//Cache
int curID = 0;					//当前中继服务器可使用的ID
unsigned char send_buf[BUF_SIZE];	//发送缓冲区
unsigned char recv_buf[BUF_SIZE];	//接收缓冲区
char LOCAL_FILE_PATH[256] = "dnsrelay.txt";	//DNS本地配置文件路径
char DNS_SERVER[16] = "218.85.152.99";		//外部DNS服务器IP地址

void parsing_parameters(int argc, char* argv[]);	//使用命令行参数
void initSock();			//初始化socket							
unsigned char* getQuestionSection(DNSquestion* question, unsigned int* nameLen);//获取查询中的Question部分，返回在recv_buf中Question部分结束位置的指针
void octet2DomainName(char* domainOctet, unsigned int octetLen, char* domain);	//octet码转ASCII的域名
void saveQuery(DNSheader* header, SOCKADDR_IN from, char* domain);				//暂存待响应的查询
void formRR(DNSrr* rr, unsigned int* ip);		//组成响应客户端的DNS报文的RR部分
void sendDNS(SOCKADDR_IN dest);					//向dest发送DNS报文

int main(int argc, char* argv[])
{
	parsing_parameters(argc, argv);
	initSock();
	initCache();
	readTxt(LOCAL_FILE_PATH);
	SOCKADDR_IN from, clientTo;
	int fromlen = sizeof(from);
	int recv_len;

	while (1)
	{
		memset(send_buf, 0, BUF_SIZE);
		memset(recv_buf, 0, BUF_SIZE);		//重置为空
		recv_len = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (SOCKADDR*)&from, &fromlen);		//接收DNS报文
		
		if (recv_len == SOCKET_ERROR)
		{
			//printf("RECV SOCKET ERROR\n\n");
			continue;
		}
		else if (!recv_len)
		{
			printf("Receive DNS message failed.\n\n");
			break;
		}
		else
		{
			DNSheader* header = (DNSheader*)recv_buf;	//获取报文首部

			//获取并打印当前时间
			SYSTEMTIME time;
			GetLocalTime(&time);
			printf("%d-%02d-%02d ", time.wYear, time.wMonth, time.wDay);
			printf("%02d:%02d:%02d  \n", time.wHour, time.wMinute, time.wSecond);

			//获取来源IP地址，点分十进制
			char ipFrom[256];	
			inet_ntop(AF_INET, &from.sin_addr, ipFrom, 256);

			if (header->qr == 1)	//来自服务器响应
			{
				char clientIP[256];
				unsigned short fromID, sendID;

				//获取原来的ID和客户端地址
				fromID = ntohs(header->id);
				sendID = query[fromID].oldID;
				sendID = htons(sendID);
				clientTo = query[fromID].client;
				inet_ntop(AF_INET, &clientTo .sin_addr, clientIP, 256);
				//更改首部ID
				memcpy(send_buf, recv_buf, BUF_SIZE);
				memcpy(send_buf, &sendID, ID_LEN);

				if (!header->opcode && ntohs(header->qdcount))	//是标准查询的响应
				{
					//新的响应添加到cache中
					addCache(fromID);
					printf("DNS server %s responses to a standard query from client.\nClient query ID: %u\nQuestion name: %s\nClient IP address: %s\n", ipFrom, query[fromID].oldID, query[fromID].domain, clientIP);
				}
				else
				{
					printf("DNS server %s responses to a non-standard type of query from client.\nClient query ID: %u\nClient IP address: %s\n", ipFrom, query[fromID].oldID, clientIP);
				}

				//发送给客户端
				sendDNS(clientTo);
				continue;
			}
			else    //来自客户端
			{
				char domain[256];	//存储域名，ASCII字符形式

				if (!header->opcode && ntohs(header->qdcount))	//是标准查询
				{
					unsigned int nameLen;
					DNSquestion question;

					//获取Question字段
					unsigned char* questionOffset = getQuestionSection(&question, &nameLen);

					//将octet码形式的域名转换为ASCII
					octet2DomainName(question.qname, nameLen, domain);

					//在本地数据查找域名
					unsigned int* ip = NULL;
					ip = searchLocal(domain);

					if (ip == NULL)		//在本地找不到
					{
						//在cache中查找
						unsigned char* response = NULL;
						response = searchCache(domain);

						if (response == NULL)	//在cache中找不到
						{
							//暂存进query等待服务器响应
							saveQuery(header, from, domain);

							memcpy(send_buf, recv_buf, BUF_SIZE);
						}
						else    //在cache中找到
						{
							//更改为响应报文
							//除了ID以外，响应报文其他部分复制cache中的response
							header->qr = 1;
							memcpy(send_buf, recv_buf, ID_LEN);
							memcpy(send_buf + ID_LEN, response, BUF_SIZE - ID_LEN);

							//发送给客户端
							printf("Client's query hits cache.\nClient query ID: %u\nDomain name of query: %s\nClient IP address: %s\n", ntohs(header->id), domain, ipFrom);

							sendDNS(from);
							continue;
						}
					}
					else    //在本地数据找到
					{
						//更改为响应报文
						header->qr = 1;
						if (!*ip)	//ip结果是0.0.0.0，需屏蔽不良网站
						{
							header->rcode = 3;
							memcpy(send_buf, recv_buf, BUF_SIZE);
						}
						else    //制作rr字段并更改首部
						{
							DNSrr rr;
							formRR(&rr, ip);
							header->rcode = 0;
							header->ancount = htons(1);
							header->nscount = 0;
							header->arcount = 0;

							memcpy(questionOffset, &rr, sizeof(DNSrr));
							memcpy(send_buf, recv_buf, BUF_SIZE);
						}
						
						//发送给客户端
						printf("Client's query hits local records.\nClient query ID: %u\nDomain name of query: %s\nClient IP address: %s\n", ntohs(header->id), domain, ipFrom);

						sendDNS(from);
						continue;
					}

					printf("Fail to find answer in local records and cache for client query.\nClient query ID: %u\nClient IP address: %s\nQueried domain name: %s\n", ntohs(header->id), domain, ipFrom);
					printf("Send query to DNS Server.\nQuery ID %u\n", curID - 1);
				}
				else
				{
					//非标准查询的DNS报文也暂存进Query
					saveQuery(header, from, NULL);
					memcpy(send_buf, recv_buf, BUF_SIZE);

					printf("Send Client non-standard type of query to DNS server.\nClient query ID: %u\nClient IP address: %s\n", ntohs(header->id), ipFrom);
				}
				//在本地和cache都找不到的标准查询或其他类型的DNS报文，发送给服务器
				sendDNS(serverAddr);
			}
		}
	}

	freeCache();
	freeLocal();
	closesocket(sock);
	WSACleanup();
	system("pause");
	return 0;
}

//使用命令行参数
void parsing_parameters(int argc, char* argv[])
{
	int opt;
	const char* optstring = "dhs:f:";

	while ((opt = getopt(argc, argv, optstring)) != -1)
	{
		switch (opt)
		{
		case 's':
			strcpy_s(DNS_SERVER, 16, optarg);
			break;
		case 'f':
			strcpy_s(LOCAL_FILE_PATH, 256, optarg);
		case 'h':
		default:
			printf("dnsrelay [-s dns-server-ipaddr] [-f filename]\n");
			printf("-h			(输入帮助)\n");
			printf("-s			(使用指定DNS服务器，否则默认使用DNS服务器218.85.152.99)\n");
			printf("-f			(使用指定路径的DNS配置文件，否则默认使用当前目录下dnsrelay.txt)\n");
			exit(-1);
		}
	}
}

//初始化socket
void initSock()
{
	//初始化socket库
	WORD w_req = MAKEWORD(2, 2); //版本号
	WSADATA wsadata;
	int err;
	err = WSAStartup(w_req, &wsadata);
	if (err != 0)
	{
		printf("初始化socket库失败\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("初始化socket库成功\n");

	//检测版本号
	if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2)
	{
		printf("socket库版本号不符\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("socket库版本正确\n");

	//创建套接字
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
	{
		printf("创建Socket失败\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("创建Socket成功\n");

	//将套接口设置为非阻塞
	int unBlock = 1;
	ioctlsocket(sock, FIONBIO, (u_long FAR*) & unBlock);
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	memset(&serverAddr, 0, sizeof(serverAddr));
	memset(&localAddr, 0, sizeof(localAddr));
	//初始化DNS服务器地址信息
	serverAddr.sin_family = AF_INET;
	inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);
	serverAddr.sin_port = htons(53);
	//初始化本地地址信息
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = INADDR_ANY;
	localAddr.sin_port = htons(53);
	//绑定端口
	if (bind(sock, (SOCKADDR*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
	{
		printf("socket绑定失败\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("socket绑定成功\n");
}

//获取查询中的Question部分，返回在recv_buf中Question部分结束位置的指针
unsigned char* getQuestionSection(DNSquestion* question, unsigned int* nameLen)
{
	unsigned char* p = recv_buf + HEAD_LEN;
	for (*nameLen = 0; *p != 0; p++, (*nameLen)++)
	{
		question->qname[*nameLen] = *p;
	}
	question->qname[*nameLen + 1] = 0;
	p++;
	memcpy(&question->qtype, p, 2);
	memcpy(&question->qclass, p + 2, 2);
	p += 4;

	return p;
}

//octet码转ASCII的域名
void octet2DomainName(char* domainOctet, unsigned int octetLen, char* domain)	//octet码转url
{
	int i = 0, k = 0, j = 0;

	while (i < octetLen)
	{
		if (domainOctet[i] > 0 && domainOctet[i] <= 63)
			for (j = domainOctet[i], i++; j > 0; j--, i++, k++)
				domain[k] = domainOctet[i];

		if (domainOctet[i] != 0)
		{
			domain[k] = '.';
			k++;
		}
	}

	domain[k - 1] = 0;
}

//暂存待响应的查询
void saveQuery(DNSheader* header, SOCKADDR_IN from, char* domain)
{
	if (domain)
	{
		query[curID].domain = (char*)malloc(strlen(domain) + 1);
		strcpy_s(query[curID].domain, strlen(domain) + 1, domain);
	}
	query[curID].oldID = ntohs(header->id);
	query[curID].client = from;
	header->id = htons(curID);		//向服务器发送的DNS首部ID就是query的下标
	if (curID == MAX_QUERY_SIZE)
		curID = 0;
	else
		++curID;
}

//组成响应客户端的DNS报文的RR部分
void formRR(DNSrr* rr, unsigned int* ip)
{
	rr->name = htons(DOMAIN_OFFSET_PTR);
	rr->_class = htons(INTERNET_CLASS);
	rr->type = htons(RR_TYPE_A);

	*(uint32_t*)&rr->ttl = htonl(TWO_DAY_TTL);
	rr->rdlen = htons(RR_TYPE_A_LEN);
	rr->rdata = htonl(*ip);
}

//向dest发送DNS报文
void sendDNS(SOCKADDR_IN dest)
{
	int send_len;
	char ipDest[256];
	inet_ntop(AF_INET, &dest.sin_addr, ipDest, 256);

	send_len = sendto(sock, send_buf, sizeof(send_buf), 0, (SOCKADDR*)&dest, sizeof(dest));
	if (send_len == SOCKET_ERROR)
	{
		printf("SOCKET ERROR WHEN SENDING DNS MESSAGE TO %s.\n\n", ipDest);
		system("pause");
		exit(-1);
	}
	else if (!send_len)
	{
		printf("Sending DNS message to %s failed.\n\n", ipDest);
		system("pause");
		exit(-1);
	}
	else
	{
		printf("Send DNS message to %s successfully.\n\n", ipDest);
	}
}
