#include "types.h"
#include "network/netcore.h"

#include <sys/random.h>
#include "kbucket.h"

int main()
{
	addr_space *as = init_kb();
	if (as == NULL)
		return ERROR;

	byte id[PEER_ID_LEN];

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.30"), 1111, id);

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.31"), 2222, id);

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.32"), 3333, id);

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.33"), 4444, id);

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.34"), 5555, id);

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.35"), 6666, id);

	getrandom(id, PEER_ID_LEN, 0);
	add_kpeer(as, ip_number("192.168.1.36"), 7777, id);
	print_as(as);

	clean_kb(as);

	/*

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
	}*/

	return OK;
}
