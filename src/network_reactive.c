#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <mqueue.h>
#include <errno.h>

#include "../include/network_utils.h"
#include "../include/network_active.h"

#define MAX_THREADS 128
#define HANDLER_TIMEOUT 1 // in seconds

int start_server(in_port_t port)
{
	// Creating socket file descriptor
	int socket_desc;
	if ((socket_desc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		DEBUG_PRINT((P_ERROR "[start_server] The socket could not be created\n"));
		return ERROR;
	}

	struct sockaddr_in self_addr, other_addr;
	memset(&self_addr, 0, sizeof(self_addr));
	memset(&other_addr, 0, sizeof(other_addr));

	// Filling the self info
	self_addr.sin_family = AF_INET;
	self_addr.sin_addr.s_addr = INADDR_ANY;
	self_addr.sin_port = htons(port);

	// Bind the socket with the self address
	if (bind(socket_desc, (const struct sockaddr *)&self_addr,
			 sizeof(self_addr)) < 0)
	{
		DEBUG_PRINT((P_ERROR "The socket could not be opened\n"));

		return ERROR;
	}

	DEBUG_PRINT((P_INFO "Starting server...\n"));

	byte buf[MAX_UDP];
	pthread_t thread_ret;

	// Open semaphore to stop server
	int sem_value = SEM_INIT;
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to create the semaphore to stop the server\n"));
		return ERROR;
	}

	// Open semaphore to count threads
	int sem_value_threads = 0;
	sem_t *sem_threads = sem_open(THREADS_SEM, 0);
	if (sem_threads == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to create the semaphore to count threads\n"));
		return ERROR;
	}

	// Open message queue
	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_RDWR);
	if (datagram_queue == -1)
	{
		DEBUG_PRINT((P_ERROR "Failed to open message queue [%s]\n", strerror(errno)));
		return ERROR;
	}

	while (sem_value == SEM_INIT)
	{
		int len = sizeof(other_addr);
		int n = 0;

		n = recvfrom(socket_desc, buf, MAX_UDP,
					 MSG_WAITALL, (struct sockaddr *)&other_addr,
					 (socklen_t *)&len);

		// Check right after reciving the packet just in case its the last one
		if (sem_getvalue(sem, &sem_value) != 0)
		{
			DEBUG_PRINT((P_ERROR "Failed to get value of the stop semaphore\n"));
			return ERROR;
		}

		if (n == -1)
		{
			DEBUG_PRINT((P_ERROR "Failed to receive datagram from client\n"));
		}
		else if (sem_value == SEM_INIT)
		{
			// Add to message queue
			if (mq_send(datagram_queue, (char *)buf, 10, 0) == -1)
			{
				DEBUG_PRINT((P_ERROR "Failed to send data to message queue [%s]\n", strerror(errno)));
				return ERROR;
			}

			// Update the number of threads we have currently
			if (sem_getvalue(sem_threads, &sem_value_threads) != 0)
			{
				DEBUG_PRINT((P_ERROR "Failed to get value of the threads semaphore\n"));
				return ERROR;
			}

			// If there are too many messages in the queue, launch a new thread
			struct mq_attr attr;
			if (mq_getattr(datagram_queue, &attr) == -1)
			{
				DEBUG_PRINT((P_ERROR "Failed to get attributes of datagram queue [%s]\n", strerror(errno)));
				return ERROR;
			}

			if (attr.mq_curmsgs > (MAX_MSG_QUEUE / 2) || sem_value_threads == 0)
			{
				if (pthread_create(&thread_ret, NULL, handle_comm, &other_addr) != 0)
					DEBUG_PRINT((P_ERROR "Failed to launch new thread\n"));
				else
				{
					DEBUG_PRINT((P_INFO "Launching new thread\n"));
					sem_post(sem_threads);
				}
			}
		}
	}

	// Signal we are finished (sem_value will go from 1 to 2)
	sem_post(sem);

	sem_close(sem);
	sem_close(sem_threads);
	close(datagram_queue);

	DEBUG_PRINT((P_OK "The server has stopped correctly\n"));

	return 0;
}

int stop_server(char *ip, in_port_t port)
{
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "Could not open semaphore to close server\n"));
		return ERROR;
	}

	sem_t *sem_threads = sem_open(THREADS_SEM, 0);
	if (sem_threads == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the semaphore to count threads\n"));
		return ERROR;
	}

	sem_post(sem);

	// Message to update the server so it stops asap
	send_empty(ip, port);

	// Wait until the value from the semaphore goes up two times,
	// because that means server is out of the main loop
	int sem_value = 0;
	sem_getvalue(sem, &sem_value);
	while (sem_value != 2)
	{
		sleep(1);
		sem_getvalue(sem, &sem_value);
	}

	sem_close(sem);

	int sem_threads_value = 0;
	sem_getvalue(sem_threads, &sem_threads_value);
	while (sem_threads_value != 0)
	{
		sleep(1);
		sem_getvalue(sem_threads, &sem_threads_value);
	}

	sem_close(sem_threads);
	
	DEBUG_PRINT((P_OK "All threads have been closed correctly\n"));

	return OK;
}

void *handle_comm(void *socket)
{
	pthread_t self = pthread_self();

	// Open thread count semaphore 
	sem_t *sem_threads = sem_open(THREADS_SEM, 0);
	if (sem_threads == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the semaphore to count threads\n"));
		goto NONE_CLEAN;		
	}

	// Get memory for buffer
	char data[MAX_UDP];
	
	// Get socket
	const struct sockaddr_in *other = (struct sockaddr_in *)socket;

	// Open queue and consume one message
	mqd_t mq = mq_open(SERVER_QUEUE, O_RDWR);
	if (mq == -1)
	{
		DEBUG_PRINT((P_ERROR "Failed to open queue in handler\n"));
		goto SEMTHREADS_CLEAN;
	}
	
	// Get peer list from shared memory
	int peer_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (peer_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		goto MQ_CLEAN;
	}
	peer_list *peers = (peer_list *)mmap(NULL, sizeof(peer_list), PROT_WRITE | PROT_READ, MAP_SHARED, peer_fd, 0);
	if (peers == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to truncate shared fd for peers\n"));
		goto PEERFD_CLEAN;
	}

	struct timespec tm;
	int ret = 0;

	// Exit only when there are no messages on queue for HANDLER_TIMEOUT seconds
	while (1)
	{
		// Set timer
		memset(&tm, 0, sizeof(struct timespec));
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += HANDLER_TIMEOUT;
		tm.tv_nsec = 0;

		ret = mq_timedreceive(mq, data, MAX_UDP, NULL, &tm);
		if (ret == 0 || ret == -1)
		{
			DEBUG_PRINT((P_WARN "Handler timedout, stopping [%s]\n", strerror(errno)));
			goto MAP_CLEAN;
		}		

		DEBUG_PRINT((P_INFO "Datagram received, analyzing...\n"));

		// Check if the peer is trying to register
		if (memcmp(data, INIT, COMM_LEN) == 0)
		{
			add_peer(peers, other, (byte *) data);
		}

		// Get the peer index
		char peer_ip[INET_ADDRSTRLEN];
		get_ip(other, peer_ip); // TODO: ERROR CONTROL
		size_t peer_index;
		get_peer(peers, peer_ip, &peer_index);

		// TODO: turn this into a switch so gcc can optimize it to hash table
		if (memcmp(data, PING, COMM_LEN) == 0)
		{
			DEBUG_PRINT((P_INFO "Received a ping from [%s:%d]\n", peers->ip[peer_index], peers->port[peer_index]));
			DEBUG_PRINT((P_INFO "Sending a pong to [%s:%d]\n", peers->ip[peer_index], peers->port[peer_index]));

			send_pong(peers->ip[peer_index], peers->port[peer_index]);
		}
		else if (memcmp(data, PONG, COMM_LEN) == 0)
		{
			DEBUG_PRINT((P_INFO "Received a pong from [%s:%d]\n", peers->ip[peer_index], peers->port[peer_index]));
		}
		else if (memcmp(data, EMPTY, COMM_LEN) == 0)
		{
			DEBUG_PRINT((P_INFO "Received an empty message\n"));
		}

		memset(data, 0, MAX_UDP);
	}

MAP_CLEAN:
	munmap(peers, sizeof(peer_list));

PEERFD_CLEAN:
	close(peer_fd);

MQ_CLEAN:
	mq_close(mq);

SEMTHREADS_CLEAN:
	DEBUG_PRINT((P_OK "Closing thread correctly\n"));

	sem_trywait(sem_threads);
	sem_close(sem_threads);
	
NONE_CLEAN:
	DEBUG_PRINT((P_OK "Detaching and exiting thread\n"));

	pthread_detach(self);
	pthread_exit(NULL);
}