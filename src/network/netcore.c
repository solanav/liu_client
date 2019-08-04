#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <mqueue.h>
#include <arpa/inet.h>

#include "network/netcore.h"
#include "network/reactive.h"
#include "network/active.h"

int peer_discovery(sem_t *sem, shared_data *sd);

int init_networking()
{
	if (create_shared_variables() == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Failed to create the shared variables\n"));
		return ERROR;
	}

	sem_t *sem = NULL;
	shared_data *sd = NULL;
	if (access_sd(&sem, &sd) == ERROR)
		return ERROR;

	pid_t pid = fork();

	if (pid < 0)
	{
		DEBUG_PRINT((P_ERROR "Fork failed\n"));
		return ERROR;
	}
	else if (pid == 0)
	{
		start_server(PORT, sem, sd);
		DEBUG_PRINT((P_OK "Exited server, closing process...\n"));
		exit(EXIT_SUCCESS);
	}
	else
	{
		// Look for peers until our list is full
		peer_discovery(sem, sd);

		sleep(1);
		stop_server(PORT, sem, sd);
	}

	// Wait for server to stop
	wait(NULL);

	sem_close(sem);
	munmap(sd, sizeof(shared_data));

	// Clean
	clean_networking();

	return OK;
}


int create_shared_variables()
{
	// TODO: create gotos to clean shit
	int ret = OK;
	// Create the semaphore to stop the server later
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, 1);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the semaphore for the server\n"));
		return ERROR;
	}

	// Shared memory for peer list
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the shared memory for the server\n"));
		ret = ERROR;
		goto SEM_CLEAN;
	}
	if (ftruncate(shared_data_fd, sizeof(shared_data)) == -1)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to truncate shared fd for shared_data\n"));
		ret = ERROR;
		goto SHM_CLEAN;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to map shared fd for sd\n"));
		ret = ERROR;
		goto SHM_CLEAN;
	}
	memset(sd, 0, sizeof(shared_data));
	sd->req_last = -1;

	// Create msg_queue for the server and handler
	struct mq_attr attr;
	attr.mq_flags = 0;
	attr.mq_maxmsg = MAX_MSG_QUEUE;
	attr.mq_msgsize = MAX_UDP;
	attr.mq_curmsgs = 0;

	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR, &attr);
	if (datagram_queue == -1)
	{
		DEBUG_PRINT((P_ERROR "Datagram queue failed to open %s\n", strerror(errno)));
		ret = ERROR;
		goto MAP_CLEAN;
	}

	//MQ_CLEAN:
	mq_close(datagram_queue);

MAP_CLEAN:
	munmap(sd, sizeof(shared_data));

SHM_CLEAN:
	close(shared_data_fd);

SEM_CLEAN:

	return ret;
}

void clean_networking()
{
	sem_unlink(SERVER_SEM);
	shm_unlink(SERVER_PEERS);
	mq_unlink(SERVER_QUEUE);

	DEBUG_PRINT((P_OK "Cleaning completed\n"));
}

int get_ip(const struct sockaddr_in *socket, char ip[INET_ADDRSTRLEN])
{
	if (inet_ntop(AF_INET, &(socket->sin_addr), ip, INET_ADDRSTRLEN) == NULL)
	{
		DEBUG_PRINT((P_ERROR "Address could not be converted to string\n"));
		return ERROR;
	}

	return OK;
}

int access_sd(sem_t **sem, shared_data **sd)
{
	// Open semaphore for shared memory
	*sem = sem_open(SERVER_SEM, 0);
	if (*sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[access_sd] Could not open semaphore to close server\n"));
		return ERROR;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[access_sd] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		sem_close(*sem);
		return ERROR;
	}
	*sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (*sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[access_sd] Failed to truncate shared fd for peers\n"));
		sem_close(*sem);
		close(shared_data_fd);
		return ERROR;
	}

	return OK;
}

int peer_discovery(sem_t *sem, shared_data *sd)
{
	sem_wait(sem);
	while (sd->peers.free[1] == 0)
	{
		sem_post(sem);
		for (int i = 0; i < 256; i++)
		{
			char ip[INET_ADDRSTRLEN];
			sprintf(ip, "10.8.0.%d", i);
			if (get_peer(ip, NULL, sem, sd) == ERROR) // If we have it already don't
				send_discover(ip, PORT, PORT);

			usleep(50000);
		}
		sem_wait(sem);
	}
	sem_post(sem);

	return OK;
}