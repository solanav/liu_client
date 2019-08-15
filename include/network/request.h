#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <semaphore.h>

#define MAX_PEERS 16

typedef struct _peer_list peer_list;

#include "types.h"
#include "network/netcore.h"

/**
 * Stop the server
 * 
 * Changes the value of the semaphore to stop the server
 * 
 * Returns - OK or ERROR
 */
int stop_server(in_port_t port, sem_t *sem, shared_data *sd);

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

int add_req(const in_addr_t ip, const byte header[C_UDP_HEADER], const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd);
int get_req(const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd);
int rm_req(int index, sem_t *sem, shared_data *sd);

int access_sd(sem_t **sem, shared_data **sd);

#endif
