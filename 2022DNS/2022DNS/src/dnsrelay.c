#include "dnsrelay.h"

SOCKET sock;					
SOCKADDR_IN serverAddr;			//�ⲿDNS�������˿��Լ���ַ
SOCKADDR_IN localAddr;			//�����˿��Լ���ַ
Query query[MAX_QUERY_SIZE];	//���ⲿ��������Ӧ�Ĳ�ѯ
LocalRecord localRec;			//����dnsrelay.txt����
Cache cache;					//Cache
int curID = 0;					//��ǰ�м̷�������ʹ�õ�ID
unsigned char send_buf[BUF_SIZE];	//���ͻ�����
unsigned char recv_buf[BUF_SIZE];	//���ջ�����
char LOCAL_FILE_PATH[256] = "dnsrelay.txt";	//DNS���������ļ�·��
char DNS_SERVER[16] = "218.85.152.99";		//�ⲿDNS������IP��ַ

void parsing_parameters(int argc, char* argv[]);	//ʹ�������в���
void initSock();			//��ʼ��socket							
unsigned char* getQuestionSection(DNSquestion* question, unsigned int* nameLen);//��ȡ��ѯ�е�Question���֣�������recv_buf��Question���ֽ���λ�õ�ָ��
void octet2DomainName(char* domainOctet, unsigned int octetLen, char* domain);	//octet��תASCII������
void saveQuery(DNSheader* header, SOCKADDR_IN from, char* domain);				//�ݴ����Ӧ�Ĳ�ѯ
void formRR(DNSrr* rr, unsigned int* ip);		//�����Ӧ�ͻ��˵�DNS���ĵ�RR����
void sendDNS(SOCKADDR_IN dest);					//��dest����DNS����

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
		memset(recv_buf, 0, BUF_SIZE);		//����Ϊ��
		recv_len = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (SOCKADDR*)&from, &fromlen);		//����DNS����
		
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
			DNSheader* header = (DNSheader*)recv_buf;	//��ȡ�����ײ�

			//��ȡ����ӡ��ǰʱ��
			SYSTEMTIME time;
			GetLocalTime(&time);
			printf("%d-%02d-%02d ", time.wYear, time.wMonth, time.wDay);
			printf("%02d:%02d:%02d  \n", time.wHour, time.wMinute, time.wSecond);

			//��ȡ��ԴIP��ַ�����ʮ����
			char ipFrom[256];	
			inet_ntop(AF_INET, &from.sin_addr, ipFrom, 256);

			if (header->qr == 1)	//���Է�������Ӧ
			{
				char clientIP[256];
				unsigned short fromID, sendID;

				//��ȡԭ����ID�Ϳͻ��˵�ַ
				fromID = ntohs(header->id);
				sendID = query[fromID].oldID;
				sendID = htons(sendID);
				clientTo = query[fromID].client;
				inet_ntop(AF_INET, &clientTo .sin_addr, clientIP, 256);
				//�����ײ�ID
				memcpy(send_buf, recv_buf, BUF_SIZE);
				memcpy(send_buf, &sendID, ID_LEN);

				if (!header->opcode && ntohs(header->qdcount))	//�Ǳ�׼��ѯ����Ӧ
				{
					//�µ���Ӧ��ӵ�cache��
					addCache(fromID);
					printf("DNS server %s responses to a standard query from client.\nClient query ID: %u\nQuestion name: %s\nClient IP address: %s\n", ipFrom, query[fromID].oldID, query[fromID].domain, clientIP);
				}
				else
				{
					printf("DNS server %s responses to a non-standard type of query from client.\nClient query ID: %u\nClient IP address: %s\n", ipFrom, query[fromID].oldID, clientIP);
				}

				//���͸��ͻ���
				sendDNS(clientTo);
				continue;
			}
			else    //���Կͻ���
			{
				char domain[256];	//�洢������ASCII�ַ���ʽ

				if (!header->opcode && ntohs(header->qdcount))	//�Ǳ�׼��ѯ
				{
					unsigned int nameLen;
					DNSquestion question;

					//��ȡQuestion�ֶ�
					unsigned char* questionOffset = getQuestionSection(&question, &nameLen);

					//��octet����ʽ������ת��ΪASCII
					octet2DomainName(question.qname, nameLen, domain);

					//�ڱ������ݲ�������
					unsigned int* ip = NULL;
					ip = searchLocal(domain);

					if (ip == NULL)		//�ڱ����Ҳ���
					{
						//��cache�в���
						unsigned char* response = NULL;
						response = searchCache(domain);

						if (response == NULL)	//��cache���Ҳ���
						{
							//�ݴ��query�ȴ���������Ӧ
							saveQuery(header, from, domain);

							memcpy(send_buf, recv_buf, BUF_SIZE);
						}
						else    //��cache���ҵ�
						{
							//����Ϊ��Ӧ����
							//����ID���⣬��Ӧ�����������ָ���cache�е�response
							header->qr = 1;
							memcpy(send_buf, recv_buf, ID_LEN);
							memcpy(send_buf + ID_LEN, response, BUF_SIZE - ID_LEN);

							//���͸��ͻ���
							printf("Client's query hits cache.\nClient query ID: %u\nDomain name of query: %s\nClient IP address: %s\n", ntohs(header->id), domain, ipFrom);

							sendDNS(from);
							continue;
						}
					}
					else    //�ڱ��������ҵ�
					{
						//����Ϊ��Ӧ����
						header->qr = 1;
						if (!*ip)	//ip�����0.0.0.0�������β�����վ
						{
							header->rcode = 3;
							memcpy(send_buf, recv_buf, BUF_SIZE);
						}
						else    //����rr�ֶβ������ײ�
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
						
						//���͸��ͻ���
						printf("Client's query hits local records.\nClient query ID: %u\nDomain name of query: %s\nClient IP address: %s\n", ntohs(header->id), domain, ipFrom);

						sendDNS(from);
						continue;
					}

					printf("Fail to find answer in local records and cache for client query.\nClient query ID: %u\nClient IP address: %s\nQueried domain name: %s\n", ntohs(header->id), domain, ipFrom);
					printf("Send query to DNS Server.\nQuery ID %u\n", curID - 1);
				}
				else
				{
					//�Ǳ�׼��ѯ��DNS����Ҳ�ݴ��Query
					saveQuery(header, from, NULL);
					memcpy(send_buf, recv_buf, BUF_SIZE);

					printf("Send Client non-standard type of query to DNS server.\nClient query ID: %u\nClient IP address: %s\n", ntohs(header->id), ipFrom);
				}
				//�ڱ��غ�cache���Ҳ����ı�׼��ѯ���������͵�DNS���ģ����͸�������
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

//ʹ�������в���
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
			printf("-h			(�������)\n");
			printf("-s			(ʹ��ָ��DNS������������Ĭ��ʹ��DNS������218.85.152.99)\n");
			printf("-f			(ʹ��ָ��·����DNS�����ļ�������Ĭ��ʹ�õ�ǰĿ¼��dnsrelay.txt)\n");
			exit(-1);
		}
	}
}

//��ʼ��socket
void initSock()
{
	//��ʼ��socket��
	WORD w_req = MAKEWORD(2, 2); //�汾��
	WSADATA wsadata;
	int err;
	err = WSAStartup(w_req, &wsadata);
	if (err != 0)
	{
		printf("��ʼ��socket��ʧ��\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("��ʼ��socket��ɹ�\n");

	//���汾��
	if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wHighVersion) != 2)
	{
		printf("socket��汾�Ų���\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("socket��汾��ȷ\n");

	//�����׽���
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
	{
		printf("����Socketʧ��\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("����Socket�ɹ�\n");

	//���׽ӿ�����Ϊ������
	int unBlock = 1;
	ioctlsocket(sock, FIONBIO, (u_long FAR*) & unBlock);
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	memset(&serverAddr, 0, sizeof(serverAddr));
	memset(&localAddr, 0, sizeof(localAddr));
	//��ʼ��DNS��������ַ��Ϣ
	serverAddr.sin_family = AF_INET;
	inet_pton(AF_INET, DNS_SERVER, &serverAddr.sin_addr);
	serverAddr.sin_port = htons(53);
	//��ʼ�����ص�ַ��Ϣ
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = INADDR_ANY;
	localAddr.sin_port = htons(53);
	//�󶨶˿�
	if (bind(sock, (SOCKADDR*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
	{
		printf("socket��ʧ��\n");
		system("pause");
		WSACleanup();
		exit(-1);
	}
	else
		printf("socket�󶨳ɹ�\n");
}

//��ȡ��ѯ�е�Question���֣�������recv_buf��Question���ֽ���λ�õ�ָ��
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

//octet��תASCII������
void octet2DomainName(char* domainOctet, unsigned int octetLen, char* domain)	//octet��תurl
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

//�ݴ����Ӧ�Ĳ�ѯ
void saveQuery(DNSheader* header, SOCKADDR_IN from, char* domain)
{
	if (domain)
	{
		query[curID].domain = (char*)malloc(strlen(domain) + 1);
		strcpy_s(query[curID].domain, strlen(domain) + 1, domain);
	}
	query[curID].oldID = ntohs(header->id);
	query[curID].client = from;
	header->id = htons(curID);		//����������͵�DNS�ײ�ID����query���±�
	if (curID == MAX_QUERY_SIZE)
		curID = 0;
	else
		++curID;
}

//�����Ӧ�ͻ��˵�DNS���ĵ�RR����
void formRR(DNSrr* rr, unsigned int* ip)
{
	rr->name = htons(DOMAIN_OFFSET_PTR);
	rr->_class = htons(INTERNET_CLASS);
	rr->type = htons(RR_TYPE_A);

	*(uint32_t*)&rr->ttl = htonl(TWO_DAY_TTL);
	rr->rdlen = htons(RR_TYPE_A_LEN);
	rr->rdata = htonl(*ip);
}

//��dest����DNS����
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