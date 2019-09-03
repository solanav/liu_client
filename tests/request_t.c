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

    for (int i = 0; i < MAX_REQUESTS + 5; i++)
    {
        byte header[COMM_LEN];
        byte cookie[COOKIE_SIZE];
        getrandom(header, COMM_LEN, 0);
        getrandom(cookie, COOKIE_SIZE, 0);
        
        add_req(LOCAL_IP_NUM + i, header, cookie, sem, sd);
    }

    // Print
    for (int i = 0; i < MAX_REQUESTS; i++)
    {
        char tmp[INET_ADDRSTRLEN];
        ip_string(sd->req.ip[i], tmp);

        printf("[%3d] < ", sd->req.prev[i]);
        printf("[%16s] [%02x%02x] [%02x%02x%02x%02x]",
            tmp, sd->req.comm[i][0], sd->req.comm[i][1],
            sd->req.cookie[i][0], sd->req.cookie[i][1], sd->req.cookie[i][2], sd->req.cookie[i][3]);
        printf(" > [%3d]\n", sd->req.next[i]);
    }

    // Clean all
    sem_close(sem);
    munmap(sd, sizeof(shared_data));

    clean_networking();

    return OK;
}