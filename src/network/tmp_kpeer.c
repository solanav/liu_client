#include <arpa/inet.h>
#include <errno.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "network/tmp_kpeer.h"
#include "types.h"
#include "network/netcore.h"

int add_tkp(const kpeer *kp, sem_t *sem, shared_data *sd)
{
    // Check if tkp is already there
    sem_wait(sem);
    if (get_tkp(kp->ip, sd->tkp, sd->tkp_first) != -1)
    {
        sem_post(sem);
        DEBUG_PRINT(P_ERROR "kpeer already there\n");
        return ERROR;
    }
    sem_post(sem);

    // Get an empty space to save the kpeer in
    int index = -1;
    for (int i = 0; i < MAX_TKP && index == -1; i++)
    {
        sem_wait(sem);
        if (sd->tkp.free[i] == 0)
            index = i;
        sem_post(sem);
    }

    // Check if we have space
    if (index == -1)
    {
        DEBUG_PRINT(P_WARN "No memory for new kpeers, removing oldest\n");
        sem_wait(sem);
        int oldest_tkp = sd->tkp_first;
        sem_post(sem);
        rm_tkp(oldest_tkp, sem, sd);
        index = oldest_tkp;
    }

    sem_wait(sem);

    // Copy kpeer to kp[index]
    memcpy(&(sd->tkp.kp[index]), kp, sizeof(kpeer));

    // Update variables of the list
    if (sd->tkp_last == -1) // If this is the first insertion
        sd->tkp_first = index;
    else
        sd->tkp.next[sd->tkp_last] = index;

    sd->tkp.prev[index] = sd->tkp_last;
    sd->tkp.next[index] = -1;
    sd->tkp_last = index;
    sd->tkp.free[index] = 1;

    sem_post(sem);

    return OK;
}

int rm_tkp(int index, sem_t *sem, shared_data *sd)
{
    sem_wait(sem);

    if (index == sd->tkp_first)
        sd->tkp_first = sd->tkp.next[index];

    int prev_index = sd->tkp.prev[index];
    int next_index = sd->tkp.next[index];

    if (index == sd->tkp_last)
        sd->tkp_last = prev_index;

    if (prev_index != -1)
        sd->tkp.next[prev_index] = next_index;
    
    if (next_index != -1)
        sd->tkp.prev[next_index] = prev_index;

    // Set all to zero
    memset(&(sd->tkp.kp[index]), 0, sizeof(kpeer));
    sd->tkp.prev[index] = 0;
    sd->tkp.next[index] = 0;
    sd->tkp.free[index] = 0;

    sem_post(sem);

    return OK;
}

int get_tkp(const in_addr_t ip, struct _tmp_kpeer tkp_copy, int tkp_first)
{
    int cont = tkp_first;

    int found = 0;
    while (found == 0)
    {
        if (tkp_copy.kp[cont].ip == ip)
            found = 1;
        else
            cont = tkp_copy.next[cont];

        // Check the next is ok
        if (cont == -1 || cont == tkp_copy.next[cont])
            break;
    }

    if (found == 0)
    {
        return ERROR;
    }

    return cont;
}
