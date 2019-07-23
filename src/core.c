#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/ptrace.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"
#include "../include/network_utils.h"

#define PORT 9092

int main()
{
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

	int len = 0;
	char **file_list = list_files("../plugins", &len);

	init_plugins(file_list, len);

	return OK;
}
