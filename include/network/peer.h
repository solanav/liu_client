#ifndef PEER_H
#define PEER_H

#include "network/kpeer.h"
#include "network/tmp_kpeer.h"
#include "network/netcore.h"

#define PER_PEER 0
#define TMP_PEER 1

union _pi {
    k_index ki;
    int tmp_ki;
};

typedef struct _peer {
    kpeer *kp; // Data of the peer
    union _pi pi; // Index of the peer 
    int type; // 0 if permanent, 1 if temp
    hydro_kx_state *state; // Pointer to the DTLS state of this peer
} peer;

int get_peer(peer *p, in_addr_t ip, sem_t *sem, shared_data *sd);

#endif