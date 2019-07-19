#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "../include/network_utils.h"
#include "../include/types.h"

#define MAX_UDP 512
#define SERVER_SEM "/server_stop"
#define PEER_SHM "/peer_list"
#define SEM_INIT 0
#define MAX_PEERS 16

#define UNTRUSTED 0
#define TRUSTED 1
#define COMM_LEN 2
#define EMPTY "\x00\x00"
#define PING "\x00\x01"
#define PONG "\x00\x02"
#define GETIP "\x00\x03"

typedef struct _peer_list
{
	char ip[MAX_PEERS][INET_ADDRSTRLEN];
	unsigned int port[MAX_PEERS];
	unsigned short trusted[MAX_PEERS];
	unsigned int next_free;
} peer_list;

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

int start_server(int port)
{
	// Create the semaphore to stop it later
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT, S_IRUSR | S_IWUSR, SEM_INIT);
	if (!sem)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to create the semaphore for the server\n"));
		return ERROR;
	}

	// Create shared memory to store the peers
	int peer_fd = shm_open(PEER_SHM, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (peer_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to create the shared memory for the server\n"));
		return ERROR;
	}
	if (ftruncate(peer_fd, sizeof(peer_list)) == -1)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to truncate shared fd for peers\n"));
		return ERROR;
	}
	peer_list *peers = (peer_list *)mmap(NULL, sizeof(peer_list), PROT_WRITE | PROT_READ, MAP_SHARED, peer_fd, 0);
	memset(peers, 0, sizeof(peer_list));

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

	int sem_value = SEM_INIT;
	char buf[MAX_UDP];
	while (sem_value == SEM_INIT)
	{
		int len = sizeof(other_addr);
		int n = 0;
		n = recvfrom(socket_desc, (char *)buf, MAX_UDP,
					 MSG_WAITALL, (struct sockaddr *)&other_addr,
					 (socklen_t *)&len);
		if (n == -1)
		{
			DEBUG_PRINT((P_ERROR "Failed to receive datagram from client\n"));
		}
		else
		{
			buf[n] = '\0';

			add_peer(peers, &other_addr);

			DEBUG_PRINT((P_INFO "Client : [%s][%s][%d]\n", buf,
						 peers->ip[peers->next_free - 1], peers->next_free));
		}
		sem_getvalue(sem, &sem_value);
	}
	return 0;
}

int add_peer(peer_list *peers, const struct sockaddr_in *other)
{
	if (!peers)
		return ERROR;

	int next = peers->next_free;

	// Get the ip of the peer
	char other_ip[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &(other->sin_addr), other_ip, INET_ADDRSTRLEN) == NULL)
	{
		DEBUG_PRINT((P_ERROR "Address could not be converted to string\n"));
		return ERROR;
	}

	// Check if peer already on list
	for (int i = 0; i < MAX_PEERS; i++)
	{
		if (strcmp(other_ip, peers->ip[i]) == 0)
		{
			DEBUG_PRINT((P_WARN "Peer already in peer_list, stopping\n"));
			return ERROR;
		}
	}

	// Check if peer list is full
	if (next == MAX_PEERS)
	{
		// TODO: remove oldest peer and insert this new and shiny one
		DEBUG_PRINT((P_ERROR "Peer list is full\n"));
		return ERROR;
	}

	// Update struct's data (the port we don't know yet)
	strncpy(peers->ip[next], other_ip, INET_ADDRSTRLEN);
	//peers->port[next] = ask the peer;
	peers->trusted[next] = UNTRUSTED;
	peers->next_free += 1;

	return OK;
}

int stop_server(char *ip, int port)
{
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT);
	if (!sem)
	{
		DEBUG_PRINT((P_ERROR "Could not open semaphore to close server\n"));
		return ERROR;
	}

	sem_post(sem);
	sem_close(sem);
	sem_unlink(SERVER_SEM);

	// Message to update the server so it stops
	upload_data(ip, port, EMPTY, COMM_LEN);

	return OK;
}

void get_ip(char *ip_addr, int port)
{
	upload_data(ip_addr, port, GETIP, COMM_LEN);
}

size_t upload_data(char *ip_addr, int port, unsigned char *data, size_t len)
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