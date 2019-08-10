#include "types.h"
#include "network/netcore.h"

int main()
{
	// Init crypto
	if (hydro_init() != 0) {
        DEBUG_PRINT(P_ERROR "Failed to initialize libhydrogen\n");
		return ERROR;
    }

	// Launch networking
	if (init_networking() == ERROR)
	{
		DEBUG_PRINT(P_ERROR "Networking module failed\n");
		return ERROR;
	}

	return OK;
}
