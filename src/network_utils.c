#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mqueue.h>

#include <openssl/pem.h>

#include "../include/network_active.h"
#include "../include/network_utils.h"

// Private functions
int latency_calculator(latency *lat);

int init_networking()
{
	// TODO: create gotos to clean shit
	int ret = OK;
	// Create the semaphore to stop the server later
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, SEM_INIT);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the semaphore for the server\n"));
		return ERROR;
	}

	// Shared memory for peer list
	int peer_fd = shm_open(SERVER_PEERS, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
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

	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR, &attr);
	if (datagram_queue == -1)
	{
		DEBUG_PRINT((P_ERROR "Datagram queue failed to open %s\n", strerror(errno)));
		ret = ERROR;
		goto MAP_CLEAN;
	}

	// Create semaphore to keep count of threads that are alive
	sem_t *sem_threads = sem_open(THREADS_SEM, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, 0);
	if (!sem_threads)
	{
		DEBUG_PRINT((P_ERROR "[init_networking] Failed to create the semaphore for the server\n"));
		ret = ERROR;
		goto MQ_CLEAN;
	}

// Close but don't unlink
//SEM2_CLEAN:
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

void clean_networking()
{

	sem_unlink(SERVER_SEM);
	sem_unlink(THREADS_SEM);
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
	peers->port[next] = (data[PORTH] << 8) + data[PORTL];
	peers->trusted[next] = UNTRUSTED;

	DEBUG_PRINT((P_INFO "Added peer with data: [%s:%d]\n", peers->ip[next], peers->port[next]));

	peers->next_free += 1;

	return OK;
}