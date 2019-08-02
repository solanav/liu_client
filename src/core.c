#include "types.h"
#include "network/netcore.h"

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
