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
#define SERVER_QUEUE "/server_queue"
#define SERVER_PEERS "/peer_list"
#define SEM_INIT 0

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
	// Create the semaphore to stop the server later
	sem_t *sem = sem_open(SERVER_SEM, O_CREAT, S_IRUSR | S_IWUSR, SEM_INIT);
	if (!sem)
	{
		DEBUG_PRINT((P_ERROR "[start_server] Failed to create the semaphore for the server\n"));
		return ERROR;
	}

	// Shared memory for peer list
	int peer_fd = shm_open(SERVER_PEERS, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
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

	// Create msg_queue for the server and handler
	struct mq_attr attr;  
	attr.mq_flags = 0;  
	attr.mq_maxmsg = 10;  
	attr.mq_msgsize = MAX_UDP;  
	attr.mq_curmsgs = 0;

	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR, &attr);
	if (datagram_queue == -1)
	{
		DEBUG_PRINT((P_ERROR"Datagram queue failed to open %s\n", strerror(errno)));
		return ERROR;
	}

	// Close but don't unlink
	sem_close(sem);
	close(peer_fd);
	mq_close(datagram_queue);

	DEBUG_PRINT((P_OK "Networking is fine for now\n"));

	return OK;
}

int clean_networking()
{
	sem_unlink(SERVER_SEM);
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

static void test_function(union sigval sv)
{
	printf("Received message \n");
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
	
	// Open semaphore
	int sem_value = SEM_INIT;
	sem_t *sem = sem_open(SERVER_SEM, 0);
	
	// Open message queue
	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_WRONLY);

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
			DEBUG_PRINT((P_INFO "Adding to queue data received...\n"));
			if (mq_send(datagram_queue, (char *) buf, 10, 0) == -1)
			{
				DEBUG_PRINT((P_ERROR "Failed to send data to message queue [%s]\n", strerror(errno)));
				return ERROR;
			}
			DEBUG_PRINT((P_INFO "Sent data to message queue\n"));
		}
		
		if (sem_getvalue(sem, &sem_value) == -1)
		{
			DEBUG_PRINT((P_ERROR "Failed to get value of the semaphore\n"));
			return ERROR;
		}
	}

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

	return OK;
}

int handle_comm(peer_list *peers, const struct sockaddr_in *other, const byte *data)
{
	if (!data)
		return ERROR;

	// TODO: turn this into a switch so gcc can optimize it to hash table
	if (memcmp(data, INIT, COMM_LEN) == 0)
	{
		add_peer(peers, other, data);
		return OK;
	}

	// Get the peer index
	char peer_ip[INET_ADDRSTRLEN];
	get_ip(other, peer_ip); // TODO: ERROR CONTROL
	size_t peer_index;
	get_peer(peers, peer_ip, &peer_index);

	if (memcmp(data, PING, COMM_LEN) == 0)
	{
		DEBUG_PRINT((P_INFO "Received a ping from [%s:%d]\n", peers->ip[peer_index], peers->port[peer_index]));
		upload_data(peers->ip[peer_index], peers->port[peer_index], PONG, COMM_LEN);
	}
	else if (memcmp(data, PONG, COMM_LEN) == 0)
	{
		DEBUG_PRINT((P_INFO "Received a pong from [%s:%d]\n", peers->ip[peer_index], peers->port[peer_index]));
	}

	return OK;
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