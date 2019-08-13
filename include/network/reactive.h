#ifndef NETWORK_REACTIVE_H
#define NETWORK_REACTIVE_H

#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_SEM "/server_mutex"
#define THREADS_SEM "/threads_count"
#define SERVER_QUEUE "/server_queue"
#define SERVER_PEERS "/peer_list"
#define MAX_MSG_QUEUE 10
#define SEM_INIT 0

#define UNTRUSTED 0
#define TRUSTED 1

#include "network/netcore.h"

int start_server(sem_t *sem, shared_data *sd);
void *handle_comm(void *socket);

#endif
