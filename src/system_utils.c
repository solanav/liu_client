#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

#include "../include/system_utils.h"
#include "../include/types.h"

#define MAX_FILE_NAME 256
#define MAX_FILES 256

char **list_files(char *dir_name)
{
	struct dirent *de;
	DIR *dr = opendir(dir_name);

	// Alloc the memory for 256 files with 256 byte names
	char **file_list = (char **)calloc(MAX_FILES, sizeof(char *));
	for (int i = 0; i < MAX_FILES; i++)
		file_list[i] = (char *)calloc(MAX_FILE_NAME, sizeof(char));

	if (!dr)
	{
#ifdef DEBUG
		printf(P_ERROR"Could not open directory (%s)\n", strerror(errno));
#endif
		return NULL;
	}

	int i = 0;
	while ((de = readdir(dr)) != NULL && i < MAX_FILES)
	{
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") && strcmp(de->d_name, "")) {
			strncpy(file_list[i], de->d_name, MAX_FILE_NAME);
			i++;
		}
	}

	closedir(dr);

	return file_list;
}

int already_running()
{
	FILE *fp;
	char output[STD_SIZE] = "";

	fp = popen("ps -C " NAME " | wc -l", "r");
	if (!fp)
	{
#ifdef DEBUG
		printf("Error\n");
#endif
	}

	while (fgets(output, sizeof(output) - 1, fp) != NULL)
	{
	}
	printf("%s\n", output);

	if (atoi(output) > 2)
	{
		return OK;
	}

	return ERROR;
}

int install()
{
	FILE *y_service = NULL;
	char service_data[] =
		"[Unit]\nDescription=" NAME " temperature monitor\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=always\nRestartSec=1\nExecStart=" BIN "\n\n[Install]\nWantedBy=multi-user.target\n";

	if (access(BIN, F_OK) != -1)
		return OTHER;

	y_service = fopen("/etc/systemd/system/" NAME ".service", "w");
	if (!y_service)
		return ERROR;

	// Create home and move there
	if (mkdir(HOME, S_IRWXU) != 0)
		return ERROR;

	if (rename(NAME, BIN) != 0)
		return ERROR;

	// Make a daemon
	fputs(service_data, y_service);
	fclose(y_service);
	system("systemctl daemon-reload; systemctl start " NAME "; systemctl enable " NAME);

	return OK;
}