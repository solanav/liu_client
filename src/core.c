#include <stdio.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/core.h"
#include "../include/network_active.h"
#include "../include/system_utils.h"

int main()
{
	// Launch networking
	if (init_networking() == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Failed to initialize the networking module\n"));
		return ERROR;
	}

	return OK;
}
