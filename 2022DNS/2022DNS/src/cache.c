#include "cache.h"

void readTxt(char* path);	//���ļ����洢д��localRec
unsigned int* searchLocal(char* domain);		//��localRec��������������IP��ַ
void updateCache(resolveTwowayP* target);		//���еĿ��Ƶ���һλ
void addCache(int fromID);						//���ⲿDNS�������յ���������������cache
void freeCache();			//�ͷ�Cache

//��ʼ��cache
void initCache()
{
	cache.cacheHead = (resolveTwowayP*)malloc(sizeof(resolveTwowayP));
	cache.cacheHead->next = cache.cacheHead;
	cache.cacheHead->prev = cache.cacheHead;
	cache.itemNum = 0;
}

//��cache�������������ظ���������Ӧ
unsigned char* searchCache(char* domain)		//��cache��
{
	resolveTwowayP* cur = cache.cacheHead->next;

	for (int i = 0; i < cache.itemNum; i++)
	{
		if (!strcmp(cur->domain, domain))
		{
			updateCache(cur);
			return cur->response;
		}
		else
			cur = cur->next;
	}

	return NULL;
}

//���еĿ��Ƶ���һλ
void updateCache(resolveTwowayP* target)	//���еĿ��Ƶ���һλ
{
	target->prev->next = target->next;
	target->next->prev = target->prev;

	target->next = cache.cacheHead->next;
	cache.cacheHead->next->prev = target;
	target->prev = cache.cacheHead;
	cache.cacheHead->next = target;
}

//���ⲿDNS�������յ���������������cache
void addCache(int fromID)			//�µģ�����cache
{
	resolveTwowayP* newCache = (resolveTwowayP*)malloc(sizeof(resolveTwowayP));
	newCache->domain = (char*)malloc(strlen(query[fromID].domain) + 1);
	strcpy_s(newCache->domain, strlen(query[fromID].domain) + 1, query[fromID].domain);
	//newCache->response = (unsigned char*)malloc(BUF_SIZE);
	memcpy(newCache->response, recv_buf + ID_LEN, BUF_SIZE - ID_LEN);

	if (cache.itemNum < MAX_CACHE_SIZE)
	{
		newCache->next = cache.cacheHead->next;
		cache.cacheHead->next->prev = newCache;
		newCache->prev = cache.cacheHead;
		cache.cacheHead->next = newCache;
		++cache.itemNum;
	}
	else
	{
		cache.cacheHead->prev->prev->next = cache.cacheHead;
		resolveTwowayP* tmp = cache.cacheHead->prev;
		cache.cacheHead->prev = cache.cacheHead->prev->prev;
		free(tmp);
		newCache->next = cache.cacheHead->next;
		cache.cacheHead->next->prev = newCache;
		newCache->prev = cache.cacheHead;
		cache.cacheHead->next = newCache;
	}
}

//�ͷ�Cache
void freeCache()
{
	resolveTwowayP* cur;

	for (int i = 0; i < cache.itemNum; i++)
	{
		cur = cache.cacheHead;
		cache.cacheHead = cache.cacheHead->next;
		free(cur->domain);
		free(cur->response);
		free(cur);
	}
}