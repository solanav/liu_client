#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <signal.h>
#include <mqueue.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "../include/network_utils.h"
#include "../include/network_def.h"
#include "../include/types.h"

#define SERVER_SEM "/server_stop"
#define THREADS_SEM "/threads_count"
#define SERVER_QUEUE "/server_queue"
#define SERVER_PEERS "/peer_list"
#define SEM_INIT 0
#define MAX_THREADS 128
#define MAX_MSG_QUEUE 10
#define HANDLER_TIMEOUT 1 // in seconds

// Private functions
void latency_calculator(int signum);

typedef struct _peer_list
{
	char ip[MAX_PEERS][INET_ADDRSTRLEN];
	in_port_t port[MAX_PEERS];
	unsigned short trusted[MAX_PEERS];
	unsigned int next_free;
} peer_list;

int init_networking()
{
	// TODO: create gotos to clean shit
	int ret = OK;
	// Create the semaphore to stop the server later
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT, S_IRUSR | S_IWUSR, SEM_INIT);
	if (!sem)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the semaphore for the server\n"));
		return ERROR;
	}

	// Shared memory for peer list
	int peer_fd = shm_open(SERVER_PEERS, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (peer_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the shared memory for the server\n"));
		ret = ERROR;
		goto SEM_CLEAN;
	}
	if (ftruncate(peer_fd, sizeof(peer_list)) == -1)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to truncate shared fd for peers\n"));
		ret = ERROR;
		goto SHM_CLEAN;
	}
	peer_list *peers = (peer_list *)mmap(NULL, sizeof(peer_list), PROT_WRITE | PROT_READ, MAP_SHARED, peer_fd, 0);
	if (peers == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to map shared fd for peers\n"));
		ret = ERROR;
		goto SHM_CLEAN;
	}
	memset(peers, 0, sizeof(peer_list));

	// Create msg_queue for the server and handler
	struct mq_attr attr;
	attr.mq_flags = 0;
	attr.mq_maxmsg = MAX_MSG_QUEUE;
	attr.mq_msgsize = MAX_UDP;
	attr.mq_curmsgs = 0;

	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR, &attr);
	if (datagram_queue == -1)
	{
		DEBUG_PRINT((P_ERROR "Datagram queue failed to open %s\n", strerror(errno)));
		ret = ERROR;
		goto MAP_CLEAN;
	}

	// Create semaphore to keep count of threads that are alive
	sem_t *sem_threads = sem_open(THREADS_SEM, O_CREAT, S_IRUSR | S_IWUSR, SEM_INIT);
	if (!sem_threads)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the semaphore for the server\n"));
		ret = ERROR;
		goto MQ_CLEAN;
	}

// Close but don't unlink
SEM2_CLEAN:
	sem_close(sem_threads);

MQ_CLEAN:
	mq_close(datagram_queue);

MAP_CLEAN:
	munmap(peers, sizeof(peer_list));

SHM_CLEAN:
	close(peer_fd);

SEM_CLEAN:
	sem_close(sem);

	return ret;
}

int clean_networking()
{
	sem_unlink(SERVER_SEM);
	sem_unlink(THREADS_SEM);
	shm_unlink(SERVER_PEERS);
	mq_unlink(SERVER_QUEUE);

	return OK;
}

void encryption_testing()
{
	/**
	 * =================================================
	 * THIS IS A TEST FUNCTION, NOT FINAL. DO NOT TOUCH.
	 * =================================================
	 */
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char buf[] = "\x69\x69\x69\x69\x69\x69";
	SHA256_CTX sha_ctx;

	// Calculate the SHA256
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, buf, 6);
	SHA256_Final(digest, &sha_ctx);

	// Get private key
	FILE *pri_fp = fopen("/home/solanav/private.key", "r");
	RSA *pri_key = PEM_read_RSAPrivateKey(pri_fp, NULL, NULL, NULL);

	// Get public key
	FILE *pub_fp = fopen("/home/solanav/public.key", "r");
	RSA *pub_key = PEM_read_RSAPublicKey(pub_fp, NULL, NULL, NULL);

	// Signature the digest
	unsigned int len;
	unsigned char signature[RSA_size(pri_key)];
	RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, &len, pri_key);

	// Verify the signature
	unsigned char unencrypted[6];
	int res = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, RSA_size(pri_key), pri_key);

	// Clean
	RSA_free(pri_key);

	if (res == 1)
	{
		printf(P_OK "Signature is valid\n");
		return;
	}
	else
	{
		printf(P_ERROR "Signature is invalid\n");
		return;
	}
}

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
	pthread_t threads[MAX_THREADS];

	// Open semaphore to stop server
	int sem_value = SEM_INIT;
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (!sem)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to create the semaphore to stop the server\n"));
		return ERROR;
	}

	// Open semaphore to count threads
	int sem_value_threads = SEM_INIT;
	sem_t *sem_threads = sem_open(THREADS_SEM, 0);
	if (!sem_threads)
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
		if (n == -1)
		{
			DEBUG_PRINT((P_ERROR "Failed to receive datagram from client\n"));
		}
		else
		{
			// Add to message queue
			if (mq_send(datagram_queue, (char *)buf, 10, 0) == -1)
			{
				DEBUG_PRINT((P_ERROR "Failed to send data to message queue [%s]\n", strerror(errno)));
				return ERROR;
			}

			// Update the number of threads we have currently
			if (sem_getvalue(sem_threads, &sem_value_threads) == -1)
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
				sem_post(sem_threads);
				pthread_create(&threads[sem_value_threads], NULL, handle_comm, &other_addr);
			}
		}

		if (sem_getvalue(sem, &sem_value) == -1)
		{
			DEBUG_PRINT((P_ERROR "Failed to get value of the stop semaphore\n"));
			return ERROR;
		}
	}

	// Wait for threads to stop
	for (int i = 0; i < sem_value_threads; i++)
		pthread_join(threads[i], NULL);

	sem_close(sem);
	close(datagram_queue);

	DEBUG_PRINT((P_OK "The server has stopped correctly\n"));

	return 0;
}

int stop_server(char *ip, in_port_t port)
{
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT);
	if (!sem)
	{
		DEBUG_PRINT((P_ERROR "Could not open semaphore to close server\n"));
		return ERROR;
	}

	sem_post(sem);
	sem_close(sem);

	// Message to update the server so it stops
	upload_data(ip, port, EMPTY, COMM_LEN);

	// Open thread count semaphore 
	sem_t *sem_threads = sem_open(THREADS_SEM, 0);
	if (!sem_threads)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the semaphore to count threads\n"));
		pthread_exit(NULL);
	}

	int sem_value = 0;
	sem_getvalue(sem_threads, &sem_value);
	while (sem_value != 0)
	{
		sleep(1);
		sem_getvalue(sem_threads, &sem_value);
	}
	
	DEBUG_PRINT((P_OK "All threads have been closed correctly\n"));

	return OK;
}

void *handle_comm(void *socket)
{
	// TODO: Fix the fucking cleaning
	// Open thread count semaphore 
	sem_t *sem_threads = sem_open(THREADS_SEM, 0);
	if (!sem_threads)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the semaphore to count threads\n"));
		pthread_exit(NULL);
	}

	// Get memory for buffer
	char *data = calloc(MAX_UDP, sizeof(char));
	if (!data)
	{
		DEBUG_PRINT((P_ERROR "Failed to get memory for data in handler\n"));

		// Notify that we are closing this thread
		sem_trywait(sem_threads);

		sem_close(sem_threads);
		pthread_exit(NULL);
	}
	
	// Get socket
	const struct sockaddr_in *other = (struct sockaddr_in *)socket;

	// Open queue and consume one message
	mqd_t mq = mq_open(SERVER_QUEUE, O_RDWR);
	if (mq == -1)
	{
		DEBUG_PRINT((P_ERROR "Failed to open queue in handler\n"));
			
		// Notify that we are closing this thread
		sem_trywait(sem_threads);

		sem_close(sem_threads);
		free(data);
		pthread_exit(NULL);
	}
	
	// Get peer list from shared memory
	int peer_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (peer_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
			
		// Notify that we are closing this thread
		sem_trywait(sem_threads);

		sem_close(sem_threads);
		free(data);
		mq_close(mq);
		pthread_exit(NULL);
	}
	peer_list *peers = (peer_list *)mmap(NULL, sizeof(peer_list), PROT_WRITE | PROT_READ, MAP_SHARED, peer_fd, 0);
	if (peers == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to truncate shared fd for peers\n"));
			
		// Notify that we are closing this thread
		sem_trywait(sem_threads);

		sem_close(sem_threads);
		free(data);
		mq_close(mq);
		close(peer_fd);
		pthread_exit(NULL);
	}

	struct timespec tm;
	int ret = 0;

	// Exit only when there are no messages on queue for HANDLER_TIMEOUT seconds
	DEBUG_PRINT((P_INFO "Adding to queue data received...\n"));
	while (1)
	{	
		// Set timer
		clock_gettime(CLOCK_REALTIME, &tm);
		tm.tv_sec += HANDLER_TIMEOUT;

		ret = mq_timedreceive(mq, data, MAX_UDP, NULL, &tm);
		if (ret == 0 || ret == -1)
		{
			DEBUG_PRINT((P_WARN "Handler timedout, stopping [%s]\n", strerror(errno)));
			
			// Notify that we are closing this thread
			sem_trywait(sem_threads);

			sem_close(sem_threads);
			free(data);
			mq_close(mq);
			close(peer_fd);
			munmap(peers, sizeof(peer_list));
			pthread_exit(NULL);
		}

		// Check if the peer is trying to register
		if (memcmp(data, INIT, COMM_LEN) == 0)
		{
			add_peer(peers, other, data);
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
			upload_data(peers->ip[peer_index], peers->port[peer_index], PONG, COMM_LEN);
		}
		else if (memcmp(data, PONG, COMM_LEN) == 0)
		{
			DEBUG_PRINT((P_INFO "Received a pong from [%s:%d]\n", peers->ip[peer_index], peers->port[peer_index]));
		}

		memset(data, 0, MAX_UDP);
	}
}

int get_peer(const peer_list *peers, const char *other_ip, size_t *index)
{
	for (int i = 0; i < MAX_PEERS; i++)
	{
		if (strcmp(other_ip, peers->ip[i]) == 0)
		{
			if (index)
				*index = i;

			return OK;
		}
	}

	DEBUG_PRINT((P_WARN "Peer not found on peer_list\n"));

	return ERROR;
}

int get_ip(const struct sockaddr_in *socket, char *ip)
{
	if (inet_ntop(AF_INET, &(socket->sin_addr), ip, INET_ADDRSTRLEN) == NULL)
	{
		DEBUG_PRINT((P_ERROR "Address could not be converted to string\n"));
		return ERROR;
	}

	return OK;
}

int add_peer(peer_list *peers, const struct sockaddr_in *other, const byte *data)
{
	if (!peers || !other)
		return ERROR;

	int next = peers->next_free;

	// Get the ip of the peer
	char other_ip[INET_ADDRSTRLEN];
	if (get_ip(other, other_ip) == ERROR)
		return ERROR;

	// Check if peer already on list
	if (get_peer(peers, other_ip, NULL) == OK)
		return ERROR;

	// Check if peer list is full
	if (next == MAX_PEERS)
	{
		// TODO: remove oldest peer and insert this new and shiny one
		DEBUG_PRINT((P_ERROR "Peer list is full\n"));
		return ERROR;
	}

	// Update struct's data (the port we don't know yet)
	strncpy(peers->ip[next], other_ip, INET_ADDRSTRLEN);
	peers->port[next] = (data[2] << 8) + data[3];
	peers->trusted[next] = UNTRUSTED;

	DEBUG_PRINT((P_INFO "Added peer with data: [%s:%d]\n", peers->ip[next], peers->port[next]));

	peers->next_free += 1;

	return OK;
}

size_t upload_data(char *ip_addr, in_port_t port, byte *data, size_t len)
{
	// Create the socket
	int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc < 0)
	{
		DEBUG_PRINT((P_ERROR "The socket could not be opened\n"));
		return ERROR;
	}

	struct sockaddr_in other_addr;
	memset(&other_addr, 0, sizeof(other_addr));

	// Fill info for the other
	other_addr.sin_family = AF_INET;
	other_addr.sin_addr.s_addr = inet_addr(ip_addr);
	other_addr.sin_port = htons(port);

	return sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));
}