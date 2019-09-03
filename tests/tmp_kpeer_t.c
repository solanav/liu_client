#include <stdio.h>
#include <assert.h>

#include <semaphore.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <string.h>

#include "network/netcore.h"
#include "network/kpeer.h"
#include "network/tmp_kpeer.h"
#include "types.h"

int main()
{
    // Initialize network
    if (init_sd() == ERROR)
    {
        DEBUG_PRINT(P_ERROR "Failed to create the shared variables\n");
        return ERROR;
    }

    sem_t *sem = NULL;
    shared_data *sd = NULL;
    if (access_sd(&sem, &sd) == ERROR)
        return ERROR;

    kpeer test;

    for (int i = 0; i < MAX_TKP + 5; i++)
    {
        getrandom(test.id, PEER_ID_LEN, 0);
        test.ip = LOCAL_IP_NUM + i;
        test.port = 1024;

        add_tkp(&test, sem, sd);
    }

    // Print
    for (int i = 0; i < MAX_TKP; i++)
    {
        printf("[%02d] < ", sd->tkp.prev[i]);
        print_kp(&(sd->tkp.kp[i]));
        printf(" > [%02d]", sd->tkp.next[i]);
        printf("\n");
    }

    // Clean all
    sem_close(sem);
    munmap(sd, sizeof(shared_data));

    clean_networking();

    return OK;
}