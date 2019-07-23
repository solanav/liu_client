#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <sys/socket.h>
#include <netinet/in.h>

#include "../include/system_utils.h"
#include "../include/network_reactive.h"
#include "../include/types.h"

#define MAX_UDP 512

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
int add_peer(peer_list *peers, const struct sockaddr_in *other, const byte *data);
int get_peer(const peer_list *peers, const char *other_ip, size_t *index);

#endif