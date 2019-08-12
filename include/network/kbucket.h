#ifndef KBUCKET_H
#define KBUCKET_H

#define MAX_KPEERS 16
#define PEER_ID_LEN 20
#define KPEER(bucket_i, peer_i) kb_list[bucket_i]->peer[peer_i]

#include "types.h"

typedef struct _kpeer {
    in_addr_t ip;
    in_port_t port;
    byte id[PEER_ID_LEN];
} kpeer;

typedef struct _kbucket {
    kpeer peer[MAX_KPEERS];
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

void print_id(const byte id[PEER_ID_LEN]);
void print_kp(const kpeer *peer);
void print_kb(const kbucket *kb);
void print_as(const addr_space *as);

int add_kpeer(addr_space *as, const kpeer *peer);
int add_kb(addr_space *as);
int half_id(byte id[PEER_ID_LEN]);
int inc_id(byte id[PEER_ID_LEN]);
int diff_id(byte diff[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);
int add_id(byte total[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);
int reorder_kpeer(addr_space *as);
int create_kpeer(kpeer *dst, const in_addr_t ip, const in_port_t port, const byte id[PEER_ID_LEN]);

#endif
