#include <semaphore.h>
#include <netinet/in.h>

#include "network/peer.h"

int get_peer(peer *p, in_addr_t ip, sem_t *sem, shared_data *sd)
{
    k_index ki;
    
    // Get permanent kpeer
    sem_wait(sem);
    int res = get_kpeer(&(sd->as), ip, &ki);
    sem_post(sem);
    
    if (res != ERROR)
    {
        sem_wait(sem);
        p->kp = &(sd->KPEER(ki.b, ki.p));
        p->state = &(sd->dtls.state[(ki.b * MAX_KPEERS) + ki.p]);
        sem_post(sem);

        p->pi.ki = ki;
        p->type = PER_PEER;

        return OK;
    }
    
    // Get temporal kpeer
    sem_wait(sem);
    res = get_tkp(ip, &(sd->tkp), sd->tkp_first);
    sem_post(sem);

    if (res == ERROR)
        return ERROR;

    sem_wait(sem);
    p->kp = &(sd->tkp.kp[res]);
    p->state = &(sd->dtls.state[MAX_KBUCKETS * MAX_KPEERS + res]);
    sem_post(sem);
    
    p->pi.tmp_ki = res;
    p->type = TMP_PEER;

    return OK;
}