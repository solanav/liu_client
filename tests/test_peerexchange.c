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
		
        sem_t *sem = NULL;
        shared_data *sd = NULL;
        if (access_sd(&sem, &sd) == ERROR)
            return ERROR;

        sem_wait(sem);
        memcpy(sd->peers.ip[0],  "1.0.0.0", INET_ADDRSTRLEN);
        memcpy(sd->peers.ip[3],  "0.2.0.0", INET_ADDRSTRLEN);
        memcpy(sd->peers.ip[7],  "0.0.3.0", INET_ADDRSTRLEN);
        memcpy(sd->peers.ip[15], "0.0.0.4", INET_ADDRSTRLEN); 
        sd->peers.port[0]  = 1224;
        sd->peers.port[3]  = 2223;
        sd->peers.port[7]  = 3222;
        sd->peers.port[15] = 4221;
        sem_post(sem);

        sleep(1);
		assert(send_peerdata(LOCAL_IP, PORT) != -1);

		sleep(1);
		assert(stop_server(LOCAL_IP, PORT) == OK);
	}

	// Wait for server to stop
	wait(NULL);

    clean_networking();

    return 0;
}
