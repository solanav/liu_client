#include <arpa/inet.h>
#include <errno.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/network_active.h"
#include "../include/network_utils.h"

#define PORT 9114

// Private functions
int create_shared_variables();

int init_networking()
{
	if (create_shared_variables() == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Failed to create the shared variables\n"));
		return ERROR;
	}

	pid_t pid = fork();

	if (pid < 0)
	{
		DEBUG_PRINT((P_ERROR "Fork failed\n"));
		return ERROR;
	}
	else if (pid == 0)
	{
		start_server(PORT);
		DEBUG_PRINT((P_OK "Exited server, closing process...\n"));
		exit(EXIT_SUCCESS);
	}
	else
	{
		sleep(1);

		// Register as a peer
		send_peerdata("127.0.0.1", PORT, PORT);
		sleep(3);

		// Send a ping
		send_ping("127.0.0.1", PORT);
		sleep(1);

		// Send a ping
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);
		send_ping("127.0.0.1", PORT);

		sleep(5);
		stop_server("127.0.0.1", PORT);
	}

	// Wait for server to stop
	wait(NULL);

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
	//memset(sd->req.next, -1, sizeof(int) * MAX_DATAGRAMS);
	//memset(sd->req.prev, -1, sizeof(int) * MAX_DATAGRAMS);
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
	sem_close(sem);

	return ret;
}

void clean_networking()
{
	sem_unlink(SERVER_SEM);
	shm_unlink(SERVER_PEERS);
	mq_unlink(SERVER_QUEUE);

	DEBUG_PRINT((P_OK "Cleaning completed\n"));
}

void encryption_testing()
{
	/**
	 * =================================================
	 * THIS IS A TEST FUNCTION, NOT FINAL. DO NOT TOUCH.
	 * =================================================
	 *
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
		DEBUG_PRINT((P_OK "Signature is valid\n"));
		return;
	}
	else
	{
		DEBUG_PRINT((P_ERROR "Signature is invalid\n"));
		return;
	}*/
}

int get_peer(const char *other_ip, size_t *index)
{
	sem_t *mutex = sem_open(SERVER_SEM, 0);
	if (mutex == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "Failed to open the semaphore for shared memory"));
		return ERROR;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		return ERROR;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to truncate shared fd for peers\n"));
		return ERROR;
	}

	sem_wait(mutex);

	for (int i = 0; i < MAX_PEERS; i++)
	{
		if (strcmp(other_ip, sd->peers.ip[i]) == 0)
		{
			if (index)
				*index = i;

			sem_post(mutex);
			return OK;
		}
	}

	sem_post(mutex);
	sem_close(mutex);
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

int add_peer(const struct sockaddr_in *other, const byte *data)
{
	if (!other)
		return ERROR;

	sem_t *mutex = sem_open(SERVER_SEM, 0);
	if (mutex == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "Failed to open the semaphore for shared memory"));
		return ERROR;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		return ERROR;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to truncate shared fd for peers\n"));
		return ERROR;
	}

	sem_wait(mutex);
	int next = sd->peers.next_free;
	sem_post(mutex);

	// Get the ip of the peer
	char other_ip[INET_ADDRSTRLEN];
	if (get_ip(other, other_ip) == ERROR)
		return ERROR;

	// Check if peer already on list
	if (get_peer(other_ip, NULL) == OK)
		return ERROR;

	// Check if peer list is full
	if (next == MAX_PEERS)
	{
		// TODO: remove oldest peer and insert this new and shiny one
		DEBUG_PRINT((P_ERROR "Peer list is full\n"));
		return ERROR;
	}

	// Update struct's data
	sem_wait(mutex);

	strncpy(sd->peers.ip[next], other_ip, INET_ADDRSTRLEN);
	sd->peers.port[next] = (data[PORTH] << 8) + data[PORTL];
	sd->peers.trusted[next] = UNTRUSTED;

	DEBUG_PRINT((P_INFO "Added peer with data: [%s:%d]\n", sd->peers.ip[next], sd->peers.port[next]));

	sd->peers.next_free += 1;

	sem_post(mutex);
	sem_close(mutex);

	return OK;
}

int add_req(const char *ip, const byte *header)
{
	// Open semaphore for shared memory
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Could not open semaphore to close server\n"));
		return ERROR;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		return ERROR;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Failed to truncate shared fd for peers\n"));
		return ERROR;
	}

	// Save datagram in shared memory with timestamp
	sem_wait(sem);

	// Get an empty space to save the request in
	int index = -1;
	for (int i = 0; i < MAX_DATAGRAMS && index == -1; i++)
	{
		if (sd->req.free[i] == 0)
			index = i;
	}

	if (index == -1)
	{
		DEBUG_PRINT((P_ERROR "No memory for new requests\n"));
		sem_post(sem);
		return ERROR;
	}

	// Copy data to req[index]
	clock_gettime(CLOCK_MONOTONIC, &(sd->req.timestamp[index]));
	strncpy(sd->req.ip[index], ip, INET_ADDRSTRLEN);
	sd->req.header[index][0] = header[0];
	sd->req.header[index][1] = header[1];

	// Update variables of the list
	if (sd->req_last != -1)
	{
		sd->req.next[sd->req_last] = index;
		sd->req.next[index] = -1;
		sd->req.prev[index] = sd->req_last;
	}

	sd->req_last = index;
	sd->req.free[index] = 1;

	sem_post(sem);

	return OK;
}

int rm_req(int index)
{
	// Open semaphore for shared memory
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Could not open semaphore to close server\n"));
		return ERROR;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		return ERROR;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Failed to truncate shared fd for peers\n"));
		return ERROR;
	}

	sem_wait(sem);

	if (index == sd->req_first)
		sd->req_first = sd->req.next[index];

	int prev_index = sd->req.prev[index];
	int next_index = sd->req.next[index];

	sd->req.next[prev_index] = next_index;
	sd->req.prev[next_index] = prev_index;

	memset(sd->req.header[index], 0, COMM_LEN);
	memset(sd->req.ip[index], 0, INET_ADDRSTRLEN);
	sd->req.prev[index] = -1;
	sd->req.next[index] = -1;
	sd->req.free[index] = 0;

	sem_post(sem);

	return OK;
}

int get_req(const char *ip, const byte *header)
{
	// Open semaphore for shared memory
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Could not open semaphore to close server\n"));
		return -1;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		return -1;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[send_ping] Failed to truncate shared fd for peers\n"));
		return -1;
	}

	struct _request req_copy;

	sem_wait(sem);
	req_copy = sd->req;
	sem_post(sem);

	int cont = sd->req_first;
	int found = 0;
	while (req_copy.next[cont] != -1 && found == 0)
	{
		if (strncmp((const char *) sd->req.ip[cont], (const char *) ip, INET_ADDRSTRLEN) == 0 &&
			strncmp((const char *) sd->req.header[cont], (const char *) header, COMM_LEN) == 0)
			found = 1;
		else
			cont = sd->req.next[cont];
	}

	if (found == 0)
	{
		DEBUG_PRINT((P_ERROR "Failed to find the request\n"));
		return -1;
	}

	return cont;
}