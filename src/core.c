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

#define PORT 9092

int main()
{
  pid_t pid = fork();
	
  /*All debugger uses PTRACE_TRACEME and it only can be called at once for each process.
	It indicate that the proccess is to be traced*/
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
	{
		printf("               __\n");
		printf("              / _) -You shouldn't be debuggin, stupid bitch |\n");
		printf("     _.----._/ /\n");
		printf("    /         /\n");
		printf(" __/ (  | (  |\n");
		printf("/__.-'|_|--|_|\n");
		return OTHER;
	}
	else{
		if(create_checknumber() == ERROR){
			DEBUG_PRINT((P_ERROR "Error creating the checknumber in shared memory\n"));
		}
	}

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
		sleep(2);

		stop_server("127.0.0.1", PORT);
	}

	return OK;
}
