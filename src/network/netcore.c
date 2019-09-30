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
#include "hydrogen.h"

#define MIN_PEERS 1
#define PRIV_NETWORK "172.21.0.0"

#ifdef DEBUG
void debug_dtls_vpn(sem_t *sem, shared_data *sd)
{
    // Send dtls requests to all peers
    for (int i = 0; i < MAX_KBUCKETS; i++)
    {
        for (int j = 0; j < MAX_KPEERS; j++)
        {
            k_index ki;
            ki.b = i;
            ki.p = j;

            sem_wait(sem);
            in_addr_t other_free = sd->as.kb_list[i].free[j];
            in_addr_t other_ip = sd->KPEER(ki.b, ki.p).ip;
            in_addr_t other_port = sd->KPEER(ki.b, ki.p).port;
            sem_post(sem);

            // If its not empty and its not us, stablish DTLS
            if (other_free == 1)
                send_dtls1(other_ip, other_port, sem, sd);

            usleep(10000);
        }
    }
}
#endif

#ifdef DEBUG
void debug_tmpdtls_vpn(in_port_t other_port, sem_t *sem, shared_data *sd)
{
    in_addr_t start_ip = ip_number(PRIV_NETWORK);

    sem_wait(sem);
    in_addr_t self_ip = sd->server_info.ip;
    in_port_t self_port = sd->server_info.port;
    sem_post(sem);

    // Send DTLS connection to 172.18.0.0/24
    for (int i = 0; i < 30; i++)
    {
        if (start_ip + i != self_ip)
        {
            kpeer tmp_dtls_peer;
            memset(&(tmp_dtls_peer.id), 0, PEER_ID_LEN);
            create_kpeer(&tmp_dtls_peer, start_ip + i, other_port, NULL);

            if (add_tkp(&tmp_dtls_peer, sem, sd) == OK)
            {
                char string_ip[INET_ADDRSTRLEN];
                ip_string(start_ip + i, string_ip);
                DEBUG_PRINT(P_INFO "Added peer [%s:%d], sending ping with DTLS request\n", string_ip, other_port);

                send_ping(start_ip + i, other_port, self_port, AC_DTLS, sem, sd);
            }
        }

        usleep(10000);
    }
}
#endif

#ifdef DEBUG
void debug_bootstrap_vpn(in_port_t other_port, sem_t *sem, shared_data *sd)
{
    in_addr_t start_ip = ip_number(PRIV_NETWORK);

    sem_wait(sem);
    in_addr_t self_ip = sd->server_info.ip;
    in_port_t self_port = sd->server_info.port;
    sem_post(sem);

    // Ping 172.18.0.0/24
    for (int i = 0; i < 10; i++)
    {
        if (start_ip + i != self_ip)
            send_ping(start_ip + i, other_port, self_port, 0, sem, sd);

        usleep(10000);
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

        // Network discovery
        debug_bootstrap_vpn(1024, sem, sd);

        // Sleep random time (because of DTLS bug)
        char r;
        getrandom(&r, 1, 0);
        srand(r);
        int rand_time = rand() % 10;
        DEBUG_PRINT(P_INFO "Sleeping for %d\n", rand_time);
        sleep(rand_time);

        // Create secure connections
        debug_dtls_vpn(sem, sd);

        // Send pings to all peers
        for (int i = 0; i < MAX_KBUCKETS; i++)
        {
            for (int j = 0; j < MAX_KPEERS; j++)
            {
                sem_wait(sem);
                kpeer curr = sd->KPEER(i, j);
                if (sd->as.kb_list[i].free[j] == 0)
                {
                    sem_post(sem);
                    continue;
                }
                sem_post(sem);

                char tmp[INET_ADDRSTRLEN];
                ip_string(curr.ip, tmp);
                DEBUG_PRINT(P_INFO "Sending ping to [%s:%d] [%d:%d]\n", tmp, curr.port, i, j);
                send_ping(curr.ip, curr.port, self_port, AC_REQ, sem, sd);

                sleep(1);
            }
        }

        DEBUG_PRINT(P_INFO "Ending connection...\n");
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
    hydro_kx_keygen(&(sd->dtls.key));
    sem_post(sem);

    // Initialize the address space located in shared memory
    init_as(&(sd->as));

    // Initialize self data
    sd->server_info.ip = 0;
    sd->server_info.port = 1024;
    getrandom(sd->server_info.id, PEER_ID_LEN, 0);

    // Initialize requests data
    sd->req_last = -1;

    // Initialize tkp data
    sd->tkp_last = -1;

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
