#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"
#include "../include/network_utils.h"

#ifdef DEBUG

# define DEBUG_PRINT(x) printf x 
#else
# define DEBUG_PRINT(x) do {} while (0) 

#endif

#define PORT 9091

int main()
{
	pid_t pid = -1;

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
	}

	return OK;
}
