#ifndef NETCORE_H
#define NETCORE_H

#define LOCAL_IP "127.0.0.1"
#define PORT 9117

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

#define COOKIE_SIZE 4

#define COMM_LEN 2
#define PORT_LEN 2
#define PACKET_NUM_LEN 2

#define C_UDP_HEADER (COMM_LEN + PACKET_NUM_LEN + COOKIE_SIZE)
#define C_UDP_LEN (MAX_UDP - C_UDP_HEADER)

typedef struct _double_peer_list double_peer_list;
typedef struct _shared_data shared_data;

#include "network/peers.h"

typedef struct _double_peer_list
{
	char ip[MAX_PEERS * 2][INET_ADDRSTRLEN];
	in_port_t port[MAX_PEERS * 2];
	int free[MAX_PEERS * 2];
	struct timespec latency[MAX_PEERS * 2];
} double_peer_list;

typedef struct _peer_list
{
	char ip[MAX_PEERS][INET_ADDRSTRLEN];
	in_port_t port[MAX_PEERS];
	int free[MAX_PEERS];
	struct timespec latency[MAX_PEERS];
} peer_list;

union _request_data
{
	byte other_peers_buf[sizeof(peer_list)];
};

struct _request
{
	char ip[MAX_DATAGRAMS][INET_ADDRSTRLEN];
	byte header[MAX_DATAGRAMS][COMM_LEN];
	struct timespec timestamp[MAX_DATAGRAMS];
	int prev[MAX_DATAGRAMS];
	int next[MAX_DATAGRAMS];
	unsigned short free[MAX_DATAGRAMS];
	union _request_data data;
	byte cookie[MAX_DATAGRAMS][COOKIE_SIZE];
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