#ifndef KBUCKET_H
#define KBUCKET_H

#define MAX_KPEERS 2
#define PEER_ID_LEN 20

#include "types.h"

typedef struct _kbucket {
    in_addr_t ip[MAX_KPEERS];
    in_port_t port[MAX_KPEERS];
    byte id[MAX_KPEERS][PEER_ID_LEN];
    unsigned int free[MAX_KPEERS];
    byte start[PEER_ID_LEN];
    byte end[PEER_ID_LEN];
} kbucket;

typedef struct _addr_space {
    kbucket **kb_list;
    unsigned int num;
} addr_space;

addr_space *init_kb();
void clean_kb(addr_space *as);
void print_id(byte id[PEER_ID_LEN]);
void print_kb(kbucket *kb, char c);
void print_as(addr_space *as);
int add_kpeer(addr_space *as, in_addr_t ip, in_port_t port, byte id[PEER_ID_LEN]);
int add_kb(addr_space *as);
int half_id(byte id[PEER_ID_LEN]);
int inc_id(byte id[PEER_ID_LEN]);
int diff_id(byte diff[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);
int add_id(byte total[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);
int reorder_kpeer(addr_space *as);

#endif