#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"
#include "../include/network_utils.h"

#define PORT 9098

int main()
{
	start_server(PORT);
	exit(0);
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
		sleep(1);
		get_ip("127.0.0.1", PORT);
		sleep(1);

		stop_server("127.0.0.1", PORT);
	}

	return OK;
}
