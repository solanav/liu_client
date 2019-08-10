#include <arpa/inet.h>
#include <errno.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_THREADS 128
#define HANDLER_TIMEOUT 1 // in seconds

#include "network/active.h"
#include "network/netcore.h"
#include "network/reactive.h"
#include "types.h"

// Private functions
int handle_unknown(const byte data[MAX_UDP], const struct sockaddr_in *other, sem_t *sem, shared_data *sd);
int handle_known(const byte data[MAX_UDP], char *peer_ip, in_port_t port, int peer_index, sem_t *sem, shared_data *sd);

// We can pass the pointer because threads share address space
struct handler_data
{
	struct sockaddr_in *socket;
	sem_t *sem;
	shared_data *sd;
};

int start_server(in_port_t port, sem_t *sem, shared_data *sd)
{
	// Creating socket file descriptor
	int socket_desc;
	if ((socket_desc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		DEBUG_PRINT(P_ERROR "[start_server] The socket could not be created\n");
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
		DEBUG_PRINT(P_ERROR "The socket could not be opened\n");

		return ERROR;
	}

	DEBUG_PRINT(P_INFO "Starting server...\n");

	byte buf[MAX_UDP];
	pthread_t thread_ret;

	// Open message queue
	mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_RDWR);
	if (datagram_queue == -1)
	{
		DEBUG_PRINT(P_ERROR "Failed to open message queue [%s]\n", strerror(errno));
		return ERROR;
	}

	// Get stop signal
	sem_wait(sem);
	int stop = sd->server_info.stop;
	sem_post(sem);

	while (stop == 0)
	{
		int len = sizeof(other_addr);
		int n = 0;

		memset(buf, 0, MAX_UDP * sizeof(byte));
		n = recvfrom(socket_desc, buf, MAX_UDP,
					 MSG_WAITALL, (struct sockaddr *)&other_addr,
					 (socklen_t *)&len);

		// Get stop signal
		sem_wait(sem);
		stop = sd->server_info.stop;
		sem_post(sem);

		if (n == -1)
		{
			DEBUG_PRINT(P_ERROR "Failed to receive datagram from client\n");
		}
		else if (stop == 0)
		{
			// Add to message queue
			if (mq_send(datagram_queue, (char *)buf, MAX_UDP, 0) == -1)
			{
				DEBUG_PRINT(P_ERROR "Failed to send data to message queue [%s]\n", strerror(errno));
				return ERROR;
			}

			// If there are too many messages in the queue, launch a new thread
			struct mq_attr attr;
			if (mq_getattr(datagram_queue, &attr) == -1)
			{
				DEBUG_PRINT(P_ERROR "Failed to get attributes of datagram queue [%s]\n", strerror(errno));
				return ERROR;
			}

			sem_wait(sem);
			int num_threads = sd->server_info.num_threads;
			sem_post(sem);

			if ((attr.mq_curmsgs > (MAX_MSG_QUEUE / 2) || num_threads == 0) && num_threads < MAX_THREADS)
			{
				// Pack data for thread
				struct handler_data hd;
				hd.socket = &other_addr;
				hd.sem = sem;
				hd.sd = sd;

				if (pthread_create(&thread_ret, NULL, handle_comm, &hd) != 0)
					DEBUG_PRINT(P_ERROR "Failed to launch new thread\n");
				else
				{
					DEBUG_PRINT(P_INFO "Launching new thread\n");

					// Save pthread_t and add one to number of threads
					sem_wait(sem);
					sd->server_info.threads[sd->server_info.num_threads] = thread_ret;
					sd->server_info.num_threads++;
					sem_post(sem);
				}
			}
		}
	}

	close(datagram_queue);

	// Wait for all threads to close
	int val = 0;
	do
	{
		sleep(1);
		sem_wait(sem);
		val = sd->server_info.num_threads;
		sem_post(sem);
	} while (val != 0);

	DEBUG_PRINT(P_OK "The server and threads have stopped correctly\n");

	// Set stop to 2 to signal we are done
	sem_wait(sem);
	sd->server_info.stop = 2;
	sem_post(sem);

	return OK;
}

int stop_server(in_port_t port, sem_t *sem, shared_data *sd)
{
	DEBUG_PRINT(P_INFO "Closing everything down...\n");

	// Activate signal to stop server
	sem_wait(sem);
	sd->server_info.stop = 1;
	sem_post(sem);

	// Message to update the server so it stops asap
	send_empty(LOCAL_IP, port);

	// Wait for the server to exit the main loop
	int val = 0;
	do
	{
		sleep(1);
		sem_wait(sem);
		val = sd->server_info.stop;
		sem_post(sem);
	} while (val != 2);

	DEBUG_PRINT(P_OK "All threads have been closed correctly\n");

	return OK;
}

void *handle_comm(void *hdata)
{
	// Extract data
	struct handler_data *hd = (struct handler_data *)hdata;
	const struct sockaddr_in *other = hd->socket;
	sem_t *sem = hd->sem;
	shared_data *sd = hd->sd;

	// Open queue and consume one message
	mqd_t mq = mq_open(SERVER_QUEUE, O_RDWR);
	if (mq == -1)
	{
		DEBUG_PRINT(P_ERROR "Failed to open queue in handler\n");
		goto SHARED_CLEAN;
	}
	// Exit only when there are no messages on queue for HANDLER_TIMEOUT seconds
	while (1)
	{
		// Set timer
		struct timespec tm;
		memset(&tm, 0, sizeof(struct timespec));
		clock_gettime(CLOCK_MONOTONIC, &tm);
		tm.tv_sec += HANDLER_TIMEOUT;
		tm.tv_nsec = 0;

		DEBUG_PRINT(P_INFO "Waiting for datagram...\n");

		// Get memory for buffer
		byte data[MAX_UDP] = {0};
		memset(data, 0, MAX_UDP * sizeof(char));
		int ret = mq_timedreceive(mq, (char *)data, MAX_UDP, NULL, &tm);
		if (ret == 0 || ret == -1)
		{
			DEBUG_PRINT(P_WARN "Handler timedout, stopping [%s]\n", strerror(errno));
			goto MQ_CLEAN;
		}

		DEBUG_PRINT(P_INFO "Datagram received, analyzing...\n");

		// Requests coming from unknown peers
		int send_info = handle_unknown(data, other, sem, sd);

		// Get a copy of the peer list
		sem_wait(sem);
		peer_list peers = sd->peers;
		sem_post(sem);

		// Get ip from packet
		char peer_ip[INET_ADDRSTRLEN];
		get_ip(other, peer_ip);

		// Get the peer index
		int peer_index = get_peer(peer_ip, sem, sd);
		if (peer_index == ERROR)
			continue;

		// Get the port
		sem_wait(sem);
		in_port_t peer_port = peers.port[peer_index];
		sem_post(sem);

		// Unknown peer consecuences
		if (send_info == 1)
		{
			DEBUG_PRINT(P_INFO "Sending self data to [%s:%d]\n", peer_ip, peer_port);
			send_selfdata(peer_ip, peer_port, PORT);
		}
		else if (send_info == 2)
		{
			DEBUG_PRINT(P_INFO "Starting DTLS handshake with [%s:%d]\n", peer_ip, peer_port);
			send_dtls1(peer_ip, peer_port, sem, sd);
		}
		else
		{
			// Requests coming from known peers
			handle_known(data, peer_ip, peer_port, peer_index, sem, sd);
		}
	}

MQ_CLEAN:
	mq_close(mq);

SHARED_CLEAN:
	DEBUG_PRINT(P_OK "Closing thread correctly\n");

	sem_wait(sem);
	if (sd->server_info.num_threads > 0)
		sd->server_info.num_threads--;
	sem_post(sem);

	DEBUG_PRINT(P_OK "Detaching and exiting thread\n");

	pthread_detach(pthread_self());
	pthread_exit(NULL);
}

int handle_unknown(const byte data[MAX_UDP], const struct sockaddr_in *other, sem_t *sem, shared_data *sd)
{
	// Check if the peer is trying to register
	if (memcmp(data, DISCOVER, COMM_LEN) == 0) // Add peer and send an INIT
	{
		DEBUG_PRINT(P_INFO "Received a discovery message, adding peer\n");
		if (add_peer(other, (byte *)data, sem, sd) != ERROR)
			return 1;
	}
	else if (memcmp(data, INIT, COMM_LEN) == 0) // Add peer and try to stablish DTLS
	{
		DEBUG_PRINT(P_INFO "New peer found, going to register it on the list\n");
		if (add_peer(other, (byte *)data, sem, sd) != ERROR)
			return 2;
	}

	return OK;
}

int handle_known(const byte data[MAX_UDP], char *peer_ip, in_port_t peer_port, int peer_index, sem_t *sem, shared_data *sd)
{
	// Get timestamp of received datagram
	struct timespec current;
	memset(&current, 0, sizeof(struct timespec));
	clock_gettime(CLOCK_MONOTONIC, &current);

	// Decrypt data
	sem_wait(sem);
	int encrypted = sd->peers.secure[peer_index];
	sem_post(sem);

	uint8_t decrypted_data[MAX_UDP - hydro_secretbox_HEADERBYTES];
	if (encrypted == 1)
	{
		uint8_t key[hydro_secretbox_KEYBYTES];

		sem_wait(sem);
		memcpy(key, sd->peers.kp[peer_index].rx, hydro_secretbox_KEYBYTES);
		sem_post(sem);

		for (int i = 0; i < 32; i += 8)
			printf("KEY >> [%02x][%02x][%02x][%02x] [%02x][%02x][%02x][%02x]\n",
				key[i], key[i + 1], key[i + 2], key[i + 3],
				key[i + 4], key[i + 5], key[i + 6], key[i + 7]);

		for (int i = 0; i < MAX_UDP; i += 8)
			printf("RECEIVED >> [%02x][%02x][%02x][%02x] [%02x][%02x][%02x][%02x]\n",
				data[i], data[i + 1], data[i + 2], data[i + 3],
				data[i + 4], data[i + 5], data[i + 6], data[i + 7]);

		if (hydro_secretbox_decrypt(decrypted_data, data,
									MAX_UDP, 0,
									"debug", key) != 0)
		{
			DEBUG_PRINT(P_ERROR "Failed to decrypt the message\n");
			return ERROR;
		}
	}
	else
	{
		memcpy(decrypted_data, data, MAX_UDP - hydro_secretbox_HEADERBYTES);
	}

	if (memcmp(decrypted_data, PING, COMM_LEN) == 0) // Peer wants info about our latency and online status
	{
		DEBUG_PRINT(P_INFO "Received a ping from [%s:%d]\n", peer_ip, peer_port);
		DEBUG_PRINT(P_INFO "Sending a pong to [%s:%d]\n", peer_ip, peer_port);

		byte cookie[COOKIE_SIZE];
		memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);

		// Send pong with the cookie from the ping
		send_pong(peer_ip, peer_port, cookie);
	}
	else if (memcmp(decrypted_data, PONG, COMM_LEN) == 0) // We sent a ping, now we get the info we wanted
	{
		DEBUG_PRINT(P_INFO "Received a pong from [%s:%d]\n", peer_ip, peer_port);

		byte cookie[COOKIE_SIZE];
		memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);

		int req_index = get_req(cookie, sem, sd);
		if (req_index == -1)
		{
			DEBUG_PRINT(P_ERROR "Failed to find request for the pong we received\n");
			return ERROR;
		}

		DEBUG_PRINT(P_INFO "Found corresponding ping\n");

		// Calculating latency
		sem_wait(sem);

		sd->peers.latency[peer_index].tv_sec += current.tv_sec - sd->req.timestamp[req_index].tv_sec;
		sd->peers.latency[peer_index].tv_nsec += current.tv_nsec - sd->req.timestamp[req_index].tv_nsec;

		if (sd->peers.latency[peer_index].tv_sec != 0 && sd->peers.latency[peer_index].tv_nsec != 0)
		{
			sd->peers.latency[peer_index].tv_sec /= 2;
			sd->peers.latency[peer_index].tv_nsec /= 2;
		}

		DEBUG_PRINT(P_INFO "Peer %d has a latency of %ld.%ldms\n",
					peer_index,
					sd->peers.latency[peer_index].tv_sec,
					sd->peers.latency[peer_index].tv_nsec);

		sem_post(sem);
	}
	else if (memcmp(decrypted_data, GETPEERS, COMM_LEN) == 0) // Peer wants to get our peer_list
	{
		DEBUG_PRINT(P_INFO "Received a peer request from [%s:%d]\n", peer_ip, peer_port);

		send_peerdata(peer_ip, peer_port, sem, sd);
	}
	else if (memcmp(decrypted_data, SENDPEERS, COMM_LEN) == 0) // Peer sent us their peer_list (step 1)
	{
		DEBUG_PRINT(P_INFO "Received a peer_list from [%s:%d]\n", peer_ip, peer_port);

		sem_wait(sem);
		memcpy(sd->req.data.other_peers_buf, decrypted_data + C_UDP_HEADER, C_UDP_LEN);
		sem_post(sem);
	}
	else if (memcmp(decrypted_data, SENDPEERSC, COMM_LEN) == 0) // Peer sent us their peer_list (step 2)
	{
		DEBUG_PRINT(P_INFO "Received a peer_list from [%s:%d]\n", peer_ip, peer_port);

		sem_wait(sem);
		memcpy(sd->req.data.other_peers_buf + C_UDP_LEN, decrypted_data + C_UDP_HEADER, sizeof(peer_list) - C_UDP_LEN);
		sem_post(sem);

		peer_list test;
		memcpy(&test, sd->req.data.other_peers_buf, sizeof(peer_list));
		printf(">> %s:%d\n", test.ip[0], test.port[0]);
	}
	else if (memcmp(decrypted_data, DTLS1, COMM_LEN) == 0) // Peer sent DTLS1, respond with DTLS2
	{
		DEBUG_PRINT(P_INFO "Received DTLS step 1 from [%s:%d]\n", peer_ip, peer_port);

		// Extract cookie and packet data
		uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
		byte cookie[COOKIE_SIZE];
		memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
		memcpy(packet1, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET1BYTES);

		if (send_dtls2(peer_ip, peer_port, packet1, cookie, sem, sd) == ERROR)
		{
			DEBUG_PRINT(P_ERROR "Send_dtls2 failed\n");
			return ERROR;
		}
	}
	else if (memcmp(decrypted_data, DTLS2, COMM_LEN) == 0) // Peer sent DTLS2, respond with DTLS3
	{
		DEBUG_PRINT(P_INFO "Received DTLS step 2 from [%s:%d]\n", peer_ip, peer_port);

		// Extract cookie and packet data
		uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
		byte cookie[COOKIE_SIZE];
		memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
		memcpy(packet2, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET2BYTES);

		if (send_dtls3(peer_ip, peer_port, packet2, cookie, sem, sd) == ERROR)
		{
			DEBUG_PRINT(P_ERROR "Send_dtls3 failed\n");
			return ERROR;
		}

		// Indicate this connection is now secure
		sem_wait(sem);
		sd->peers.secure[peer_index] = 1;
		sem_post(sem);

		// Delete request
		int req_index = get_req(cookie, sem, sd);
		if (req_index == ERROR)
			DEBUG_PRINT(P_ERROR "Failed to get request of DTLS");

		rm_req(req_index, sem, sd);

		DEBUG_PRINT(P_OK "Secure connection has been established with [%s:%d]\n", peer_ip, peer_port);
	}
	else if (memcmp(decrypted_data, DTLS3, COMM_LEN) == 0) // Peer sent DTLS3, process and save key
	{
		DEBUG_PRINT(P_INFO "Received DTLS step 3 from [%s:%d]\n", peer_ip, peer_port);

		// Extract cookie and packet data
		uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
		byte cookie[COOKIE_SIZE];
		memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
		memcpy(packet3, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET2BYTES);

		if (hydro_kx_xx_4(&(sd->dtls.state), &(sd->peers.kp[peer_index]), NULL, packet3, NULL) != 0)
		{
			DEBUG_PRINT(P_ERROR "Failed to execute step 4 of DTLS\n");
			return ERROR;
		}

		// Indicate this connection is now secure
		sem_wait(sem);
		sd->peers.secure[peer_index] = 1;
		sem_post(sem);

		// Delete request
		int req_index = get_req(cookie, sem, sd);
		if (req_index == ERROR)
		{
			DEBUG_PRINT(P_ERROR "Failed to get request of DTLS");
			return ERROR;
		}

		rm_req(req_index, sem, sd);

		DEBUG_PRINT(P_OK "Secure connection has been established with [%s:%d]\n", peer_ip, peer_port);
	}
	else if (memcmp(decrypted_data, DEBUG_MSG, COMM_LEN) == 0) // Used to debug
	{
		DEBUG_PRINT(P_OK "Debug message from [%s:%d]\n", peer_ip, peer_port);

		printf("DECRYPTED >> [%02x][%02x][%02x][%02x]\n",
			   decrypted_data[8], decrypted_data[9], decrypted_data[10], decrypted_data[11]);
	}
	else if (memcmp(decrypted_data, EMPTY, COMM_LEN) == 0) // Used by the stop_server function
	{
		DEBUG_PRINT(P_INFO "Received an empty message\n");
	}

	return OK;
}