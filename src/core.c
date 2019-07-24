#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/core.h"
#include "../include/network_active.h"

int main()
{
	if (init_networking() == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Failed to initialize the networking module\n"));
		return ERROR;
	}

	return OK;
}
