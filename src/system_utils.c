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

/**
 * list_files. given a directory return the name of the files inside it
 * 
 * @param dir_name the name of the directory
 * 
 * @return char[256][256] with the names of the files
 */
char **list_files(char *dir_name)
{
	struct dirent *de;
	DIR *dr = opendir(dir_name);

	//check the directory has been oppened successfully
	if (!dr)
	{
#ifdef DEBUG
		printf(P_ERROR"Could not open directory (%s)\n", strerror(errno));
#endif
		return NULL;
	}

	// Alloc the memory for MAX_FILES file names
	char **file_list = (char **)calloc(MAX_FILES, sizeof(char *));

	if (!file_list)
	{
#ifdef DEBUG
		printf(P_ERROR"Could not alloc memory for file_list\n");
#endif
		return NULL;
	}

	//alloc memory for each file_name with size MAX_FILE_NAME
	for (int i = 0; i < MAX_FILES; i++){
		file_list[i] = (char *)calloc(MAX_FILE_NAME, sizeof(char));

		//check it has been allocated succesfully
		if (!file_list[i])
	{
#ifdef DEBUG
		printf(P_ERROR"Could not alloc memory for file number %d \n", i);
#endif
		for (int j = 0; j < i; j++){
			free(file_list[j]);
		}
		free (file_list);
		return NULL;
	}
		
	}
		

	

	int i = 0;
	//read the files names.
	while ((de = readdir(dr)) != NULL && i < MAX_FILES)
	{
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") && strcmp(de->d_name, "")) {
			strncpy(file_list[i], de->d_name, MAX_FILE_NAME);
			i++;
		}
	}

	//close the directory
	closedir(dr);

	return file_list;
}

/**
 * already_running. checks if its alreadt running.
 * if there are more than one processes called name stop the program
 * 
 * @return OK or ERROR
 */
int already_running()
{
	FILE *fp;
	char output[STD_SIZE] = "";

	//open the proccess
	fp = popen("ps -C " NAME " | wc -l", "r");
	if (!fp)
	{
#ifdef DEBUG
		printf("Error\n");
#endif
	}

	//get the info of the proccess for print it
	while (fgets(output, sizeof(output) - 1, fp) != NULL);

	printf("%s\n", output);

	//if it has info the proccess is running
	if (atoi(output) > 2)
	{
		return OK;
	}

	//Error case as default
	return ERROR;
}

/**
 * install install the program on the system
 * 
 * @return OK or ERROR
 */
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