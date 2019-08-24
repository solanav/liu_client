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
 * Add new request
 *
 * Adds request without breaking the linked list, fails if request is already added.
 */
int add_req(const in_addr_t ip, const byte header[C_UDP_HEADER], const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd);

/**
 * Get a request
 *
 * Given a cookie, it spits out an index of a request or ERROR.
 */
int get_req(const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd);

/**
 * Remove a request
 *
 * Deltes a request without breaking the linked list.
 */
int rm_req(int index, sem_t *sem, shared_data *sd);

#endif
