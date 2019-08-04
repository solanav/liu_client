#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>

#include "network/peers.h"
#include "network/reactive.h"
#include "network/active.h"

int main()
{
    assert(create_shared_variables() == OK);

    sem_t *sem = NULL;
	shared_data *sd = NULL;
	assert(access_sd(&sem, &sd) == OK);

	pid_t pid = fork();
    assert(pid >= 0);
	if (pid == 0)
	{
		start_server(PORT, sem, sd);
		exit(EXIT_SUCCESS);
	}
	else
	{
		sleep(1);
		assert(send_selfdata(LOCAL_IP, PORT, PORT) != -1);
		
        sleep(1);
		assert(send_ping(LOCAL_IP, PORT, sem, sd) != -1);

		sleep(1);
		assert(stop_server(PORT, sem, sd) == OK);
	}

	// Wait for server to stop
	wait(NULL);

	sem_close(sem);
	munmap(sd, sizeof(shared_data));
    clean_networking();

    return 0;
}