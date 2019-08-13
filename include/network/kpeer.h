#ifndef KBUCKET_H
#define KBUCKET_H

#define MAX_KPEERS 4
#define MAX_KBUCKETS 4
#define PEER_ID_LEN 20

#define _KPEER(bucket_i, peer_i) kb_list[bucket_i].peer[peer_i]
#define KPEER(bucket_i, peer_i) as._KPEER(bucket_i, peer_i)

#include "types.h"
#include "hydrogen.h"

typedef struct _k_index {
    unsigned int p;
    unsigned int b;
} k_index;

typedef struct _kpeer {
    in_addr_t ip; // Ip of the peer
    in_port_t port; // Port of the peer
    byte id[PEER_ID_LEN]; // Kademlia ID to identify peer
    struct timespec latency; // Latency with the peer
    hydro_kx_session_keypair kp; // Keypair for DTLS
    unsigned int secure; // 1 if DTLS has been established
} kpeer;

typedef struct _kbucket {
    kpeer peer[MAX_KPEERS]; // Peers in the bucket
    unsigned int free[MAX_KPEERS]; // 1 if there is no peer
    byte start[PEER_ID_LEN]; // First ID that can fit in this bucket (included)
    byte end[PEER_ID_LEN]; // Last ID that can fit in this bucket (included)
} kbucket;

typedef struct _addr_space {
    kbucket kb_list[MAX_KBUCKETS]; // List of all buckets
    unsigned int free[MAX_KPEERS]; // 1 if there is no bucket
    unsigned int b_num; // Number of buckets
    unsigned int p_num; // Number of peers
} addr_space;

void init_as(addr_space *as);

void print_id(const byte id[PEER_ID_LEN]);
void print_kp(const kpeer *peer);
void print_kb(const kbucket *kb);
void print_as(const addr_space *as);

int add_kb(addr_space *as);

int half_id(byte id[PEER_ID_LEN]);
int inc_id(byte id[PEER_ID_LEN]);
int diff_id(byte diff[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);
int add_id(byte total[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);

int create_kpeer(kpeer *dst, const in_addr_t ip, const in_port_t port, const byte id[PEER_ID_LEN]);
int add_kpeer(addr_space *as, const kpeer *peer, unsigned int self);
int get_kpeer(const addr_space *as, const in_addr_t ip, k_index *ki);
int reorder_kpeer(addr_space *as);

#endif
