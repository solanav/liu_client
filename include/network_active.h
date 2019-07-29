#ifndef NETWORK_ACTIVE_H
#define NETWORK_ACTIVE_H

#include <sys/socket.h>
#include <netinet/in.h>

#define EMPTY "\x00\x00"
#define PING "\x00\x01"
#define PONG "\x00\x02"
#define GETPEERS "\x00\x03"
#define INIT "\x00\x04" 

#define INIT_LEN 4
#define COMM_LEN 2

#define PORTH 2
#define PORTL 3

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
int send_peerdata(char *ip, in_port_t port, in_port_t self_port);

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
int send_pong(char *ip, in_port_t port);

/**
 * Asks a peer for other peers
 * 
 * The peer should respond with a peer_list. We will use this to fill our list.
 */
int send_peerrequest(char *ip, in_port_t port);

#endif