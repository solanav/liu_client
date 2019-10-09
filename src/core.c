#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "../include/plugin_utils.h"
#include "../include/system_utils.h"
#include "network/netcore.h"

#include <sys/random.h>
#include <string.h>

int anti_debug()
{
	//I am not capable of delete something from my check system so other people neither
	int fd_shm = shm_open(SHM_BASHPID, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd_shm == -1)
	{
		DEBUG_PRINT((P_ERROR " [BASHPID] Error creating the shared memory\n"));

		return ERROR;
	}

	// Resizing shared memory
	int error = ftruncate(fd_shm, sizeof(int));

	if (error == -1)
	{
		DEBUG_PRINT((P_ERROR " [BASHPID] Error resizing the shared memory segment\n"));

		shm_unlink(SHM_BASHPID);
		return ERROR;
	}

	// Mapping shared memory
	int *bashpid = mmap(NULL, sizeof(*bashpid),
						PROT_READ | PROT_WRITE, MAP_SHARED, fd_shm, 0);
	if (bashpid == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR " [BASHPID] Error mapping the shared memory segment\n"));

		shm_unlink(SHM_BASHPID);
		return ERROR;
	}

	*bashpid = getppid();

	/*All debugger uses PTRACE_TRACEME and it only can be called at once for each process.
	It indicate that the proccess is to be traced*/
	if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
	{
		DEBUG_PRINT((P_ERROR "You shouldn't be debuggin, stupid bitch\n"));
		return OTHER;
	}
	else
	{
		if(create_checknumber() == ERROR){
			DEBUG_PRINT((P_ERROR "Error creating the checknumber in shared memory\n"));
			return ERROR;
		}
	}

	if (get_random_number() != get_sharedmemory_current_number())
	{
		DEBUG_PRINT((P_ERROR "You are a cheater bruh\n"));
		return OTHER;
	}

	return 0;
}

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
        return  ERROR;
    }

    return OK;
}
