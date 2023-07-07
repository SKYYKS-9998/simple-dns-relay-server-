#include "local.h"

void initCache();			//初始化cache
unsigned char* searchCache(char* domain);		//在cache查找域名，返回该域名的响应
void freeLocal();			//释放本地数据

//读文件，存储写入localRec
void readTxt(char* path)
{
	localRec.localHead = (resolveSingleP*)malloc(sizeof(resolveSingleP));
	localRec.localHead->next = NULL;
	localRec.itemNum = 0;

	FILE* fp = (FILE*)malloc(sizeof(FILE));
	fopen_s(&fp, path, "ab+");
	if (!fp)
	{
		printf("Open dnsrelay.txt failed\n");
		system("pause");
		exit(-1);
	}

	char tmp[256];
	resolveSingleP* cur = localRec.localHead;

	while (fgets(tmp, 255, fp))
	{
		char* domain, * ipStr;
		char* nextToken = NULL;
		ipStr = strtok_s(tmp, " ", &nextToken);
		domain = strtok_s(NULL, " ", &nextToken);

		unsigned char* ip[4];
		ip[0] = strtok_s(ipStr, ".", &nextToken);
		ip[0][0] = atoi(ip[0]);
		for (int i = 1; i < 4; i++)
		{
			ip[i] = strtok_s(NULL, ".", &nextToken);
			ip[i][0] = atoi(ip[i]);
		}

		unsigned int ip32;

		for (int i = 0, j = 3; i < 4; i++, j--)
		{
			memcpy((char*)&ip32 + i, ip[j], 1);
		}

		resolveSingleP* newRow = (resolveSingleP*)malloc(sizeof(resolveSingleP));
		newRow->next = NULL;
		newRow->item.domain = (char*)malloc(strlen(domain) + 1);
		strcpy_s(newRow->item.domain, strlen(domain) + 1, domain);
		if (newRow->item.domain[strlen(newRow->item.domain) - 1] == '\n')
			newRow->item.domain[strlen(newRow->item.domain) - 1] = '\0';
		newRow->item.ip = ip32;

		cur->next = newRow;
		cur = cur->next;
		++localRec.itemNum;
	}

	fclose(fp);
	free(fp);
}

//在localRec查找域名，返回IP地址
unsigned int* searchLocal(char* domain)		//在localRec搜
{
	resolveSingleP* cur = localRec.localHead->next;

	while (cur->next)
	{
		if (!strcmp(cur->item.domain, domain))
		{
			return &cur->item.ip;
		}
		else
			cur = cur->next;
	}

	return NULL;
}

//释放本地数据
void freeLocal()
{
	resolveSingleP* cur;

	for (int i = 0; i < localRec.itemNum; i++)
	{
		cur = localRec.localHead;
		localRec.localHead = localRec.localHead->next;
		free(cur->item.domain);
		free(cur);
	}
}