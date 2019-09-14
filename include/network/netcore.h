#ifndef NETCORE_H
#define NETCORE_H

#include "hydrogen.h"

#define LOCAL_IP "127.0.0.1"
#define LOCAL_IP_NUM 2130706433

#define MAX_UDP 512 // Max size of a packet
#define MAX_THREADS 128 // Max number of threads
#define MAX_REQUESTS 128 // Max number of requests
#define MAX_TKP 32 // Max number of concurrent DTLS connections

#define EMPTY      "\x00\x00"
#define INIT       "\x00\x01"
#define PING       "\x00\x02"
#define PONG       "\x00\x03"
#define FINDNODE   "\x00\x04"
#define SENDNODE   "\x00\x05"
#define DISCOVER   "\x00\x06"
#define DTLS1	   "\x00\x07"
#define DTLS2	   "\x00\x08"
#define DTLS3	   "\x00\x09"
#define DTLS4	   "\x00\x0A"
#define DEBUG_MSG  "\x00\x0B"

#define COOKIE_SIZE 4

#define COMM_LEN 2
#define PORT_LEN 2
#define PACKET_NUM_LEN 2

#define C_UDP_HEADER (COMM_LEN + PACKET_NUM_LEN + COOKIE_SIZE)
#define C_UDP_LEN (MAX_UDP - C_UDP_HEADER - hydro_secretbox_HEADERBYTES)

#define SSL_CTX "jfu9m3wy" // random context (needs to be 8 bytes)
#define DTLS_NO 0
#define DTLS_ING 1
#define DTLS_OK 2

typedef struct _double_peer_list double_peer_list;
typedef struct _shared_data shared_data;
struct _tmp_kpeer;

#include "network/request.h"
#include "network/kpeer.h"
#include "network/tmp_kpeer.h"

// Useful for saving request specific data
union _data
{
    in_addr_t find_ip;
};

struct _request
{
    in_addr_t ip[MAX_REQUESTS];
    byte comm[MAX_REQUESTS][COMM_LEN];
    struct timespec timestamp[MAX_REQUESTS];
    int prev[MAX_REQUESTS];
    int next[MAX_REQUESTS];
    unsigned short free[MAX_REQUESTS];
    byte cookie[MAX_REQUESTS][COOKIE_SIZE];
    union _data data;
};

struct _tmp_kpeer
{
    kpeer kp[MAX_TKP];
    int prev[MAX_TKP];
    int next[MAX_TKP];
    unsigned short free[MAX_TKP];
};

struct _dtls_data
{
    hydro_kx_keypair key; // Our own keypair
    hydro_kx_state state[MAX_KPEERS * MAX_KBUCKETS + MAX_TKP]; // State for dtls handshake (one for each peer)
};

struct _server_info
{
    in_addr_t ip; // Our own ip
    in_port_t port; // Our own port
    byte id[PEER_ID_LEN]; // Our own kademlia ID
    unsigned int num_threads; // Current number of threads running
    pthread_t threads[MAX_THREADS]; // Storage to interact with threads
    int stop; // Signal to stop running the server
};

typedef struct _shared_data
{
    addr_space as;
    struct _server_info server_info;
    struct _dtls_data dtls;

    struct _request req;
    int req_first;
    int req_last;

    struct _tmp_kpeer tkp;
    int tkp_first;
    int tkp_last;
} shared_data;

/**
 * Init the server and client
 *
 * Creates a fork to run the server and executes commands from the client such as sending data.
 */
int init_networking();

/**
 * Init the shared memory
 * 
 * You must clean after using this function.
 */
int init_sd();

/**
 * Clean shared data
 *
 * Unlinks and removes all created assets used for networking.
 */
void clean_networking();

/**
 * Get access to sd
 *
 * Wrapper to facilitate the use of shared memory
 */
int access_sd(sem_t **sem, shared_data **sd);

/**
 * Get ip from socket
 *
 * Wrapper to extract the ip from a socket, instead of doing it manually.
 */
int get_ip(const struct sockaddr_in *socket, char ip[INET_ADDRSTRLEN]);


/**
 * IP translation
 *
 * Translates ipv4 from text to decimal and viceversa.
 */
in_addr_t ip_number(char *ip);
void ip_string(in_addr_t ip, char ip_string[INET_ADDRSTRLEN]);

#endif
