#ifndef NETWORK_ACTIVE_H
#define NETWORK_ACTIVE_H

#include <netinet/in.h>
#include <sys/socket.h>

#include "types.h"
#include "network/netcore.h"

/**
 * Create package
 * 
 * Creates a standard package so that all messages are equal as they should.
 * If a zero-cookie is provided, the function will fill it and use it.
 * If a NULL is provided as cookie, the function will generate a new cookie and use that.
 * If a cookie is provided that is not "\x00\x00\x00\x00", then that cookie will be used.
 */
int forge_packet(byte datagram[MAX_UDP], byte cookie[COOKIE_SIZE], const byte type[COMM_LEN], int packet_num, const byte *data, size_t data_size);

/**
 * Empty send
 * 
 * Send an empty datagram, should activate nothing on the other end.
 */
int send_empty(char *ip, in_port_t port);

/**
 * Send your data to a peer
 *  
 * Sends your port to a peer so it can add you as peer. It uses ip and port
 * instead of peer_index because you will be asked your info by non-peers
 * and should be able to answer their requests.
 */
int send_selfdata(char *ip, in_port_t port, in_port_t self_port);

/**
 * Send a ping
 * 
 * The peer should respond with a pong. Saves the time of the ping in a shm.
 */
int send_ping(char *ip, in_port_t port);

/**
 * Send a pong
 * 
 * The peer has received a ping, responds with a pong if the computer who has sent
 * this request is in our peer list. This is to prevent access from external
 * agents.
 */
int send_pong(char *ip, in_port_t port, byte cookie[COOKIE_SIZE]);

/**
 * Asks a peer for other peers
 * 
 * The peer should respond with a peer_list. We will use this to fill our list.
 */
int send_peerrequest(char *ip, in_port_t port);

/**
 * Sends the peer_list to a peer
 * 
 * This is a response to a peer request, it serves as a peer discovery method.
 */
int send_peerdata(char *ip, in_port_t port);

#endif