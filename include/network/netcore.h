#ifndef NETCORE_H
#define NETCORE_H

#include "hydrogen.h"

#define LOCAL_IP "127.0.0.1"
#define LOCAL_IP_NUM 2130706433

#define MAX_UDP 512 // Max size of a packet
#define MAX_THREADS 128 // Max number of threads
#define MAX_DATAGRAMS 128 // Max number of requests

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

#define SSL_CTX "jfu9m3wy"
#define DTLS_NO 0
#define DTLS_ING 1
#define DTLS_OK 2

typedef struct _double_peer_list double_peer_list;
typedef struct _shared_data shared_data;

#include "network/request.h"
#include "network/kpeer.h"

struct _request
{
    in_addr_t ip[MAX_DATAGRAMS];
    byte comm[MAX_DATAGRAMS][COMM_LEN];
    struct timespec timestamp[MAX_DATAGRAMS];
    int prev[MAX_DATAGRAMS];
    int next[MAX_DATAGRAMS];
    unsigned short free[MAX_DATAGRAMS];
    byte cookie[MAX_DATAGRAMS][COOKIE_SIZE];
};

struct _dtls_data
{
    hydro_kx_keypair kp; // Our own keypair
    hydro_kx_state state[MAX_KPEERS * MAX_KBUCKETS]; // State for dtls handshake (one for each peer)
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
} shared_data;

int init_networking();
void clean_networking();
int access_sd(sem_t **sem, shared_data **sd);
int get_ip(const struct sockaddr_in *socket, char ip[INET_ADDRSTRLEN]);
in_addr_t ip_number(char *ip);
void ip_string(in_addr_t ip, char ip_string[INET_ADDRSTRLEN]);

#endif
