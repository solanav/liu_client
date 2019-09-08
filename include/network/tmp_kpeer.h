#ifndef TMP_KPEER_H
#define TMP_KPEER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <semaphore.h>

typedef struct _peer_list peer_list;

#include "types.h"
#include "network/netcore.h"

/**
 * Add new tkp
 *
 * Adds tkp without breaking the linked list, fails if tkp is already added.
 */
int add_tkp(const kpeer *kp, sem_t *sem, shared_data *sd);

/**
 * Get a tkp
 *
 * Given a cookie, it spits out an index of a tkp or ERROR.
 */
int get_tkp(const in_addr_t ip, struct _tmp_kpeer tkp_copy, int tkp_first);

/**
 * Remove a tkp
 *
 * Deltes a tkp without breaking the linked list.
 */
int rm_tkp(int index, sem_t *sem, shared_data *sd);

#endif
