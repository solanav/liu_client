#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

// Testing
#include <mqueue.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"
#include "../include/network_utils.h"

#define PORT 9114

int main()
{
	if (init_networking() == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Failed to initialize the networking module\n"));
		return ERROR;
	}

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

		// Register as a peer
		upload_data("127.0.0.1", PORT, "\x00\x04\x23\x8A", 4);
		sleep(3);

		// Send a ping
		upload_data("127.0.0.1", PORT, "\x00\x01", 4);
		sleep(1);

		stop_server("127.0.0.1", PORT);

	}

	// Wait for server to stop
	wait(NULL);

	// Clean
	if (clean_networking() == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Error cleaning networking"));
		return ERROR;
	}

	return OK;
}
