#include "cache.h"

void readTxt(char* path);	//读文件，存储写入localRec
unsigned int* searchLocal(char* domain);		//在localRec查找域名，返回IP地址
void updateCache(resolveTwowayP* target);		//命中的块移到第一位
void addCache(int fromID);						//从外部DNS服务器收到域名解析，加入cache
void freeCache();			//释放Cache

//初始化cache
void initCache()
{
	cache.cacheHead = (resolveTwowayP*)malloc(sizeof(resolveTwowayP));
	cache.cacheHead->next = cache.cacheHead;
	cache.cacheHead->prev = cache.cacheHead;
	cache.itemNum = 0;
}

//在cache查找域名，返回该域名的响应
unsigned char* searchCache(char* domain)		//在cache搜
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

//命中的块移到第一位
void updateCache(resolveTwowayP* target)	//命中的块移到第一位
{
	target->prev->next = target->next;
	target->next->prev = target->prev;

	target->next = cache.cacheHead->next;
	cache.cacheHead->next->prev = target;
	target->prev = cache.cacheHead;
	cache.cacheHead->next = target;
}

//从外部DNS服务器收到域名解析，加入cache
void addCache(int fromID)			//新的，加入cache
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

//释放Cache
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