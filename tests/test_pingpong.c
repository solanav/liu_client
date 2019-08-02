#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "network/peers.h"
#include "network/reactive.h"
#include "network/active.h"

int main()
{
    assert(create_shared_variables() == OK);

	pid_t pid = fork();
    assert(pid >= 0);
	if (pid == 0)
	{
		start_server(PORT);
		exit(EXIT_SUCCESS);
	}
	else
	{
		sleep(1);
		assert(send_selfdata(LOCAL_IP, PORT, PORT) != -1);
		
        sleep(1);
		assert(send_ping(LOCAL_IP, PORT) != -1);

		sleep(1);
		assert(stop_server(PORT) == OK);
	}

	// Wait for server to stop
	wait(NULL);

    clean_networking();

    return 0;
}