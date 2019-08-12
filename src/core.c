#include "types.h"
#include "network/netcore.h"

#include <sys/random.h>
#include "kbucket.h"

int main()
{
    addr_space *as = init_kb();
    if (as == NULL)
        return ERROR;

    kpeer peer;

    byte id[PEER_ID_LEN];

    for (int i = 0; i < 100; i++)
    {
        getrandom(id, PEER_ID_LEN, 0);
        create_kpeer(&peer, ip_number("192.168.1.30"), 1111, id);
        add_kpeer(as, &peer);
    }

    print_as(as);

    clean_kb(as);

    printf("%ld\n", sizeof(kpeer));

//	// Init crypto
//	if (hydro_init() != 0) {
//        DEBUG_PRINT(P_ERROR "Failed to initialize libhydrogen\n");
//		return ERROR;
//    }

//	// Launch networking
//	if (init_networking() == ERROR)
//	{
//		DEBUG_PRINT(P_ERROR "Networking module failed\n");
//		return ERROR;
//    }

	return OK;
}
