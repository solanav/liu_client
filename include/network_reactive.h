#ifndef NETWORK_REACTIVE_H
#define NETWORK_REACTIVE_H

#include <sys/socket.h>
#include <netinet/in.h>

#include "../include/network_utils.h"

#define SERVER_SEM "/server_mutex"
#define THREADS_SEM "/threads_count"
#define SERVER_QUEUE "/server_queue"
#define SERVER_PEERS "/peer_list"
#define MAX_MSG_QUEUE 10
#define SEM_INIT 0

#define MAX_PEERS 16

#define UNTRUSTED 0
#define TRUSTED 1

typedef struct _peer_list
{
	char ip[MAX_PEERS][INET_ADDRSTRLEN];
	in_port_t port[MAX_PEERS];
	unsigned short trusted[MAX_PEERS];
	unsigned int next_free;
	struct timespec latency[MAX_PEERS];
} peer_list;

int start_server(in_port_t port);
void *handle_comm(void *socket);

#endif