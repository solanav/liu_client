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

/**
 * Starts the server
 *
 * Waits for packets and launches new threads when necessary.
 */
int start_server(sem_t *sem, shared_data *sd);

/**
 * Stop the server
 *
 * Changes the value of the semaphore to stop the server
 *
 * Returns - OK or ERROR
 */
int stop_server(in_port_t port, sem_t *sem, shared_data *sd);

/**
 * Handle messages
 *
 * Given a socket, extracts the data and processes it accordingly.
 */
void *handle_comm(void *socket);

#endif
