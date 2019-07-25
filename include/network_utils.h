#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "../include/network_utils.h"
#include "../include/system_utils.h"
#include "../include/network_reactive.h"
#include "../include/network_active.h"
#include "../include/types.h"

#define MAX_UDP 512
#define MAX_THREADS 128
#define MAX_DATAGRAMS 128

struct _request
{
	char ip[MAX_DATAGRAMS][INET_ADDRSTRLEN];
	byte header[MAX_DATAGRAMS][COMM_LEN];
	struct timespec timestamp[MAX_DATAGRAMS];
	int prev[MAX_DATAGRAMS];
	int next[MAX_DATAGRAMS];
	unsigned short free[MAX_DATAGRAMS];
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

/**
 * Stop the server
 * 
 * Changes the value of the semaphore to stop the server
 * 
 * Returns - OK or ERROR
 */
int stop_server(char *ip, in_port_t port);

/**
 * UDP Server
 *
 * Waits for instructions from the server
 *
 * port - Integer with the port we want to use
 *
 * Returns - The data or NULL in case of error
*/

int init_networking();
void clean_networking();
int get_ip(const struct sockaddr_in *socket, char *ip);
int add_peer(const struct sockaddr_in *other, const byte *data);
int get_peer(const char *other_ip, size_t *index);
int add_req(const char *ip, const byte *header);
int rm_req(int index);
int get_req(const char *ip, const byte *header);

#endif