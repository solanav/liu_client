#ifndef KBUCKET_H
#define KBUCKET_H

#define MAX_KPEERS 16
#define MAX_KBUCKETS 16
#define PEER_ID_LEN 20

#define _KPEER(bucket_i, peer_i) kb_list[bucket_i].peer[peer_i]
#define KPEER(bucket_i, peer_i) as._KPEER(bucket_i, peer_i)

#include "types.h"
#include "hydrogen.h"

typedef struct {
    unsigned int p;
    unsigned int b;
} k_index;

typedef struct {
    in_addr_t ip; // Ip of the peer
    in_port_t port; // Port of the peer
    byte id[PEER_ID_LEN]; // Kademlia ID to identify peer
    struct timespec latency; // Latency with the peer
    hydro_kx_session_keypair key; // Keypair for DTLS
    unsigned short secure; // 1 if DTLS has been established
} kpeer;

typedef struct {
    kpeer peer[MAX_KPEERS]; // Peers in the bucket
    unsigned short free[MAX_KPEERS]; // 1 if there is no peer
    byte start[PEER_ID_LEN]; // First ID that can fit in this bucket (included)
    byte end[PEER_ID_LEN]; // Last ID that can fit in this bucket (included)
} kbucket;

typedef struct {
    kbucket kb_list[MAX_KBUCKETS]; // List of all buckets
    unsigned short free[MAX_KPEERS]; // 1 if there is no bucket
    unsigned int b_num; // Number of buckets
    unsigned int p_num; // Number of peers
} addr_space;

#include "netcore.h"

void init_as(addr_space *as);

/**
 * Printing functions
 *
 * They just display information about the different structures for debug porpouses
 */
void print_id(const byte id[PEER_ID_LEN]);
void print_kp(const kpeer *peer);
void print_kb(const kbucket *kb);
void print_as(const addr_space *as);

/**
 * Add k-bucket
 *
 * Creates a new k-bucket and handles the reordering of all peers inside the address
 * space.
 */
int add_kb(addr_space *as);

/**
 * Getk-bucket
 *
 * Get the index of the bucket where an ID should go
 */
int get_kb(addr_space *as, const byte id[PEER_ID_LEN]);

/**
 * ID arithmetic
 *
 * These are used mainly to create a new k-bucket. The space has to be distributed
 * and the starting and ending id of the bucket has to be modified.
 */
int half_id(byte id[PEER_ID_LEN]);
int inc_id(byte id[PEER_ID_LEN]);
int diff_id(byte diff[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);
int add_id(byte total[PEER_ID_LEN], const byte id1[PEER_ID_LEN], const byte id2[PEER_ID_LEN]);

/**
 * Asks a peer for other peers
 *
 * The peer should respond with a peer_list. We will use this to fill our list.
 */
int create_kpeer(kpeer *dst, const in_addr_t ip, const in_port_t port, const byte id[PEER_ID_LEN]);
int add_kpeer(addr_space *as, const kpeer *peer, unsigned int self);
int get_kpeer(const addr_space *as, const in_addr_t ip, k_index *ki);
int reorder_kpeer(addr_space *as);
int rm_kpeer(addr_space *as, const in_addr_t ip);

/**
 * Get list of peers by distance
 *
 * Using xor, returns a list in binary of the closest peers to a given address, ordered
 * by distance to the given id.
 */
int distance_peer_list(byte list[C_UDP_LEN], const byte id[INET_ADDRSTRLEN], addr_space *as);

/**
 * Export and import address space
 *
 * Used for the local cache bootstrapping.
 */
int import_bin(addr_space *as);
int export_bin(addr_space *as);

#endif
