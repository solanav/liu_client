#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <mqueue.h>
#include <arpa/inet.h>
#include <sys/random.h>

#include "network/netcore.h"
#include "network/reactive.h"
#include "network/active.h"

#define MIN_PEERS 1

int peer_discovery(sem_t *sem, shared_data *sd);
int init_sd();

#ifdef DEBUG
void debug_bootstrap_vpn(in_port_t self_port, sem_t *sem, shared_data *sd)
{
    in_addr_t start_ip = ip_number("10.8.0.0");
    in_port_t start_port = 1024;

    sem_wait(sem);
    in_addr_t self_ip = sd->server_info.ip;
    sem_post(sem);

    // Keep pinging till you got peers
    while(1)
    {
        for (int i = 0; i < 50; i++)
        {
            if (start_ip + i != self_ip)
                send_ping(start_ip + i, start_port, self_port, 0, sem, sd);

            usleep(10000);

            sem_wait(sem);
            if (sd->as.p_num >= 2)
            {
                sem_post(sem);
                return;
            }
            sem_post(sem);
        }
    }
}
#endif

int init_networking()
{
    if (init_sd() == ERROR)
    {
        DEBUG_PRINT(P_ERROR "Failed to create the shared variables\n");
        return ERROR;
    }

    sem_t *sem = NULL;
    shared_data *sd = NULL;
    if (access_sd(&sem, &sd) == ERROR)
        return ERROR;

    pid_t pid = fork();

    if (pid < 0)
    {
        DEBUG_PRINT(P_ERROR "Fork failed\n");
        return ERROR;
    }
    else if (pid == 0)
    {
        start_server(sem, sd);
        DEBUG_PRINT(P_OK "Exited server, closing process...\n");
        exit(EXIT_SUCCESS);
    }
    else
    {
        sleep(1);

        sem_wait(sem);
        in_port_t self_port = sd->server_info.port;
        sem_post(sem);

        debug_bootstrap_vpn(self_port, sem, sd);

        sem_wait(sem);
        in_addr_t other_ip = sd->KPEER(0, 1).ip;
        in_addr_t self_ip = sd->server_info.ip;
        sem_post(sem);

        sleep(5);

        k_index ki;
        ki.b = 0;
        ki.p = 1;

        // Only start if my ip is bigger
        if (self_ip > other_ip)
            send_dtls1(ki, sem, sd);

        sleep(10);

        stop_server(self_port, sem, sd);
    }

    // Wait for server to stop
    wait(NULL);

    sem_close(sem);
    munmap(sd, sizeof(shared_data));

    // Clean
    clean_networking();

    return OK;
}


int init_sd()
{
    // TODO: create gotos to clean shit
    int ret = OK;
    // Create the semaphore to stop the server later
    sem_t *sem = sem_open(SERVER_SEM, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR, 1);
    if (sem == SEM_FAILED)
    {
        DEBUG_PRINT(P_ERROR "[init_networking] Failed to create the semaphore for the server\n");
        return ERROR;
    }

    // Shared memory for peer list
    int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (shared_data_fd == -1)
    {
        DEBUG_PRINT(P_ERROR "[init_networking] Failed to create the shared memory for the server\n");
        ret = ERROR;
        goto SEM_CLEAN;
    }
    if (ftruncate(shared_data_fd, sizeof(shared_data)) == -1)
    {
        DEBUG_PRINT(P_ERROR "[init_networking] Failed to truncate shared fd for shared_data\n");
        ret = ERROR;
        goto SHM_CLEAN;
    }
    shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
    if (sd == MAP_FAILED)
    {
        DEBUG_PRINT(P_ERROR "[init_networking] Failed to map shared fd for sd\n");
        ret = ERROR;
        goto SHM_CLEAN;
    }
    memset(sd, 0, sizeof(shared_data));

    // Create msg_queue for the server and handler
    struct mq_attr attr;
    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MSG_QUEUE;
    attr.mq_msgsize = MAX_UDP;
    attr.mq_curmsgs = 0;

    mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR, &attr);
    if (datagram_queue == -1)
    {
        DEBUG_PRINT(P_ERROR "Datagram queue failed to open %s\n", strerror(errno));
        ret = ERROR;
        goto MAP_CLEAN;
    }

    // Create keys for dtls
    sem_wait(sem);
    hydro_kx_keygen(&(sd->dtls.kp));
    sem_post(sem);

    // Initialize the address space located in shared memory
    init_as(&(sd->as));

    // Initialize self data
    sd->server_info.ip = 0;
    sd->server_info.port = 1024;
    getrandom(sd->server_info.id, PEER_ID_LEN, 0);

    // Initialize requests data
    sd->req_last = -1;

    //MQ_CLEAN:
    mq_close(datagram_queue);

MAP_CLEAN:
    munmap(sd, sizeof(shared_data));

SHM_CLEAN:
    close(shared_data_fd);

SEM_CLEAN:

    return ret;
}

void clean_networking()
{
    sem_unlink(SERVER_SEM);
    shm_unlink(SERVER_PEERS);
    mq_unlink(SERVER_QUEUE);

    DEBUG_PRINT(P_OK "Cleaning completed\n");
}

int get_ip(const struct sockaddr_in *socket, char ip[INET_ADDRSTRLEN])
{
    if (inet_ntop(AF_INET, &(socket->sin_addr), ip, INET_ADDRSTRLEN) == NULL)
    {
        DEBUG_PRINT(P_ERROR "Address could not be converted to string\n");
        return ERROR;
    }

    return OK;
}

int access_sd(sem_t **sem, shared_data **sd)
{
    // Open semaphore for shared memory
    *sem = sem_open(SERVER_SEM, 0);
    if (*sem == SEM_FAILED)
    {
        DEBUG_PRINT(P_ERROR "[access_sd] Could not open semaphore to close server\n");
        return ERROR;
    }

    // Open shared memory
    int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
    if (shared_data_fd == -1)
    {
        DEBUG_PRINT(P_ERROR "[access_sd] Failed to open the shared memory for the server [%s]\n", strerror(errno));
        sem_close(*sem);
        return ERROR;
    }
    *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
    if (*sd == MAP_FAILED)
    {
        DEBUG_PRINT(P_ERROR "[access_sd] Failed to truncate shared fd for peers\n");
        sem_close(*sem);
        close(shared_data_fd);
        return ERROR;
    }

    return OK;
}

in_addr_t ip_number(char *ip)
{
    in_addr_t ip_number;
    unsigned int data[4] = {0};

    sscanf(ip, "%u.%u.%u.%u", &(data[0]), &(data[1]), &(data[2]), &(data[3]));

    ip_number = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];

    return ip_number;
}

void ip_string(in_addr_t ip, char ip_string[INET_ADDRSTRLEN])
{
    byte data[4];
    data[0] = (ip >> 24) & 0xFF;
    data[1] = (ip >> 16) & 0xFF;
    data[2] = (ip >> 8) & 0xFF;
    data[3] = ip & 0xFF;

    sprintf(ip_string, "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
}
