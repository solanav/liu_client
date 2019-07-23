#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Testing
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#include "../include/core.h"
#include "../include/network_active.h"

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
		return start_server(PORT);
	}
	else
	{
		sleep(1);

		// Register as a peer
		send_peerdata("127.0.0.1", PORT, PORT);
		sleep(3);

		// Send a ping
		send_ping("127.0.0.1", PORT);
		sleep(1);

		printf("Calling stop_server\n");
		stop_server("127.0.0.1", PORT);
	}

	// Wait for server to stop
	wait(NULL);

	// Clean
	clean_networking();

	return OK;
}
