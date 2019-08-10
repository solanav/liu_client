#ifndef NETCORE_H
#define NETCORE_H

#include "hydrogen.h"

#define LOCAL_IP "127.0.0.1"
#define PORT 9121

#define MAX_UDP 512 // Max size of a packet
#define MAX_THREADS 128 // Max number of threads
#define MAX_DATAGRAMS 128 // Max number of requests

#define EMPTY      "\x00\x00"
#define INIT       "\x00\x01"
#define PING       "\x00\x02"
#define PONG       "\x00\x03"
#define GETPEERS   "\x00\x04"
#define SENDPEERS  "\x00\x05"
#define SENDPEERSC "\x00\x06"
#define DISCOVER   "\x00\x07"
#define DTLS1	   "\x00\x08"
#define DTLS2	   "\x00\x09"
#define DTLS3	   "\x00\x0A"
#define DTLS4	   "\x00\x0B"
#define DEBUG_MSG  "\x00\x0C"

#define COOKIE_SIZE 4

#define COMM_LEN 2
#define PORT_LEN 2
#define PACKET_NUM_LEN 2

#define C_UDP_HEADER (COMM_LEN + PACKET_NUM_LEN + COOKIE_SIZE)
#define C_UDP_LEN (MAX_UDP - C_UDP_HEADER - hydro_secretbox_HEADERBYTES)

#define SSL_CTX "jfu9m3wy"

typedef struct _double_peer_list double_peer_list;
typedef struct _shared_data shared_data;

#include "network/peers.h"

typedef struct _peer_list
{
	char ip[MAX_PEERS][INET_ADDRSTRLEN]; 	// Ip of the peer
	in_port_t port[MAX_PEERS];				// Port of the peer
	unsigned int free[MAX_PEERS];			// 1 if the space is free
	struct timespec latency[MAX_PEERS];		// Latency with the peer
	hydro_kx_session_keypair kp[MAX_PEERS]; // Keypair for DTLS
	unsigned int secure[MAX_PEERS];			// 1 if DTLS has been established
} peer_list;

union _request_data
{
	byte other_peers_buf[sizeof(peer_list)];   // Buffer for receiving a peer_list
};

struct _request
{
	char ip[MAX_DATAGRAMS][INET_ADDRSTRLEN];
	byte comm[MAX_DATAGRAMS][COMM_LEN];
	struct timespec timestamp[MAX_DATAGRAMS];
	int prev[MAX_DATAGRAMS];
	int next[MAX_DATAGRAMS];
	unsigned short free[MAX_DATAGRAMS];
	union _request_data data;
	byte cookie[MAX_DATAGRAMS][COOKIE_SIZE];
};

struct _dtls_data
{
	hydro_kx_keypair kp;
	hydro_kx_state state;
};

struct _server_info
{
	unsigned int num_threads;
	pthread_t threads[MAX_THREADS];
    int stop;
};

typedef struct _shared_data
{
	peer_list peers;
	struct _server_info server_info;
	struct _dtls_data dtls; 
	struct _request req;
	int req_first;
	int req_last;
} shared_data;

int init_networking();
int create_shared_variables();
void clean_networking();
int access_sd(sem_t **sem, shared_data **sd);
int get_ip(const struct sockaddr_in *socket, char ip[INET_ADDRSTRLEN]);

#endif