#include <arpa/inet.h>
#include <errno.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_THREADS 128
#define HANDLER_TIMEOUT 1 // in seconds

#include "network/active.h"
#include "network/netcore.h"
#include "network/reactive.h"
#include "network/kpeer.h"
#include "types.h"

// Private functions
int handle_reply(const byte data[MAX_UDP], const in_addr_t other_ip, sem_t *sem, shared_data *sd);

// We can pass the pointer because threads share address space
struct handler_data
{
    struct sockaddr_in *socket;
    sem_t *sem;
    shared_data *sd;
};

int start_server(sem_t *sem, shared_data *sd)
{
    // Creating socket file descriptor
    int socket_desc;
    if ((socket_desc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        DEBUG_PRINT(P_ERROR "[start_server] The socket could not be created\n");
        return ERROR;
    }

    struct sockaddr_in self_addr, other_addr;
    memset(&self_addr, 0, sizeof(self_addr));
    memset(&other_addr, 0, sizeof(other_addr));

    // Filling the self info and binding
    self_addr.sin_family = AF_INET;
    self_addr.sin_addr.s_addr = INADDR_ANY;

    sem_wait(sem);
    self_addr.sin_port = htons(sd->server_info.port);
    while (bind(socket_desc, (const struct sockaddr *)&self_addr,
             sizeof(self_addr)) < 0)
    {
        sd->server_info.port++;
        self_addr.sin_port = htons(sd->server_info.port);
        DEBUG_PRINT(P_ERROR "Bind failed, trying with %d\n", sd->server_info.port);
    }
    sem_post(sem);

    DEBUG_PRINT(P_INFO "Starting server...\n");

    byte buf[MAX_UDP];
    pthread_t thread_ret;

    // Open message queue
    mqd_t datagram_queue = mq_open(SERVER_QUEUE, O_RDWR);
    if (datagram_queue == -1)
    {
        DEBUG_PRINT(P_ERROR "Failed to open message queue [%s]\n", strerror(errno));
        return ERROR;
    }

    // Get stop signal
    sem_wait(sem);
    int stop = sd->server_info.stop;
    sem_post(sem);

    while (stop == 0)
    {
        int len = sizeof(other_addr);
        int n = 0;

        memset(buf, 0, MAX_UDP * sizeof(byte));
        n = recvfrom(socket_desc, buf, MAX_UDP,
                     MSG_WAITALL, (struct sockaddr *)&other_addr,
                     (socklen_t *)&len);

        // Get stop signal
        sem_wait(sem);
        stop = sd->server_info.stop;
        sem_post(sem);

        if (n == -1)
        {
            DEBUG_PRINT(P_ERROR "Failed to receive datagram from client\n");
        }
        else if (stop == 0)
        {
            // Add to message queue
            if (mq_send(datagram_queue, (char *)buf, MAX_UDP, 0) == -1)
            {
                DEBUG_PRINT(P_ERROR "Failed to send data to message queue [%s]\n", strerror(errno));
                return ERROR;
            }

            // If there are too many messages in the queue, launch a new thread
            struct mq_attr attr;
            if (mq_getattr(datagram_queue, &attr) == -1)
            {
                DEBUG_PRINT(P_ERROR "Failed to get attributes of datagram queue [%s]\n", strerror(errno));
                return ERROR;
            }

            sem_wait(sem);
            int num_threads = sd->server_info.num_threads;
            sem_post(sem);

            if ((attr.mq_curmsgs > (MAX_MSG_QUEUE / 2) || num_threads == 0) && num_threads < MAX_THREADS)
            {
                // Pack data for thread
                struct handler_data hd;
                hd.socket = &other_addr;
                hd.sem = sem;
                hd.sd = sd;

                if (pthread_create(&thread_ret, NULL, handle_comm, &hd) != 0)
                    DEBUG_PRINT(P_ERROR "Failed to launch new thread\n");
                else
                {
                    DEBUG_PRINT(P_INFO "Launching new thread\n");

                    // Save pthread_t and add one to number of threads
                    sem_wait(sem);
                    sd->server_info.threads[sd->server_info.num_threads] = thread_ret;
                    sd->server_info.num_threads++;
                    sem_post(sem);
                }
            }
        }
    }

    close(datagram_queue);

    // Wait for all threads to close
    int val = 0;
    do
    {
        sem_wait(sem);
        val = sd->server_info.num_threads;
        sem_post(sem);
        sleep(1);
    } while (val != 0);

    DEBUG_PRINT(P_OK "The server and threads have stopped correctly\n");

    // Set stop to 2 to signal we are done
    sem_wait(sem);
    sd->server_info.stop = 2;
    sem_post(sem);

    return OK;
}

int stop_server(in_port_t port, sem_t *sem, shared_data *sd)
{
    DEBUG_PRINT(P_INFO "Closing everything down...\n");

    // Activate signal to stop server
    sem_wait(sem);
    sd->server_info.stop = 1;
    sem_post(sem);

    // Message to update the server so it stops asap
    send_empty(LOCAL_IP_NUM, port);

    // Wait for the server to exit the main loop
    int val = 0;
    do
    {
        sleep(1);
        sem_wait(sem);
        val = sd->server_info.stop;
        sem_post(sem);
    } while (val != 2);

    DEBUG_PRINT(P_OK "All threads have been closed correctly\n");

    return OK;
}

void *handle_comm(void *hdata)
{
    // Extract data
    struct handler_data *hd = (struct handler_data *)hdata;
    const struct sockaddr_in *other = hd->socket;
    sem_t *sem = hd->sem;
    shared_data *sd = hd->sd;

    // Open queue and consume one message
    mqd_t mq = mq_open(SERVER_QUEUE, O_RDWR);
    if (mq == -1)
    {
        DEBUG_PRINT(P_ERROR "Failed to open queue in handler\n");
        goto SHARED_CLEAN;
    }
    // Exit only when there are no messages on queue for HANDLER_TIMEOUT seconds
    while (1)
    {
        // Set timer
        struct timespec tm;
        memset(&tm, 0, sizeof(struct timespec));
        clock_gettime(CLOCK_MONOTONIC, &tm);
        tm.tv_sec += HANDLER_TIMEOUT;
        tm.tv_nsec = 0;

        DEBUG_PRINT(P_INFO "Waiting for datagram...\n");

        // Get memory for buffer
        byte data[MAX_UDP] = {0};
        memset(data, 0, MAX_UDP * sizeof(char));
        int ret = mq_timedreceive(mq, (char *)data, MAX_UDP, NULL, &tm);
        if (ret == 0 || ret == -1)
        {
            DEBUG_PRINT(P_WARN "Handler timedout, stopping [%s]\n", strerror(errno));
            goto MQ_CLEAN;
        }

        DEBUG_PRINT(P_INFO "Datagram received, analyzing...\n");

        // Reply to request
        handle_reply(data, ntohl(other->sin_addr.s_addr), sem, sd);
    }

MQ_CLEAN:
    mq_close(mq);

SHARED_CLEAN:
    DEBUG_PRINT(P_OK "Closing thread correctly\n");

    sem_wait(sem);
    if (sd->server_info.num_threads > 0)
        sd->server_info.num_threads--;
    sem_post(sem);

    DEBUG_PRINT(P_OK "Detaching and exiting thread\n");

    pthread_detach(pthread_self());
    pthread_exit(NULL);
}

int handle_reply(const byte data[MAX_UDP], const in_addr_t other_ip, sem_t *sem, shared_data *sd)
{
    // Get timestamp of received datagram
    struct timespec current;
    memset(&current, 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC, &current);

    // Get copy of peer
    sem_wait(sem);
    k_index ki;
    get_kpeer(&(sd->as), other_ip, &ki);
    kpeer peer = sd->KPEER(ki.b, ki.p);
    sem_post(sem);

#ifdef DEBUG
    char string_ip[INET_ADDRSTRLEN];
    ip_string(peer.ip, string_ip);
#endif

    int encrypted = peer.secure;
    uint8_t decrypted_data[MAX_UDP - hydro_secretbox_HEADERBYTES];
    if (encrypted == 1)
    {
        uint8_t key[hydro_secretbox_KEYBYTES];

        sem_wait(sem);
        memcpy(key, peer.kp.rx, hydro_secretbox_KEYBYTES);
        sem_post(sem);

        if (hydro_secretbox_decrypt(decrypted_data, data,
                                    MAX_UDP, 0,
                                    SSL_CTX, key) == -1)
        {
            DEBUG_PRINT(P_ERROR "Failed to decrypt the message\n");
            return ERROR;
        }
    }
    else
    {
        memcpy(decrypted_data, data, MAX_UDP - hydro_secretbox_HEADERBYTES);
    }

    // Switch for message comm
    if (memcmp(decrypted_data, PING, COMM_LEN) == 0) // Peer wants info about our latency and online status
    {
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);

        in_addr_t self_ip = ((data[C_UDP_HEADER + 0] & 0xFF) << 24) +
                ((data[C_UDP_HEADER + 1] & 0xFF) << 16) +
                ((data[C_UDP_HEADER + 2] & 0xFF) << 8) +
                ((data[C_UDP_HEADER + 3] & 0xFF) << 0);

        sem_wait(sem);
        sd->server_info.ip = self_ip;
        sem_post(sem);

        // Get peer data
        kpeer other_peer;
        other_peer.ip = other_ip;
        other_peer.port = ((data[C_UDP_HEADER + 4] & 0xFF) << 8) +
                ((data[C_UDP_HEADER + 5] & 0xFF) << 0);

        ip_string(other_peer.ip, string_ip);

        DEBUG_PRINT(P_INFO "Received a ping from [%s:%d]\n", string_ip, other_peer.port);
        DEBUG_PRINT(P_INFO "Sending a pong to [%s:%d]\n", string_ip, other_peer.port);

        // Get self data
        sem_wait(sem);
        in_port_t self_port = sd->server_info.port;
        byte self_id[PEER_ID_LEN];
        memcpy(self_id, sd->server_info.id, PEER_ID_LEN);
        sem_post(sem);

        kpeer self_peer;
        create_kpeer(&self_peer, self_ip, self_port, self_id);

        // First add yourself then the other
        sem_wait(sem);
        add_kpeer(&(sd->as), &self_peer, 1);
        add_kpeer(&(sd->as), &other_peer, 0);
        sem_post(sem);

        // Send pong with the cookie from the ping
        send_pong(other_peer.ip, other_peer.port, self_port, cookie, sem, sd);
    }
    else if (memcmp(decrypted_data, PONG, COMM_LEN) == 0) // We sent a ping, now we get the info we wanted
    {
        DEBUG_PRINT(P_INFO "Received a pong from [%s:%d]\n", string_ip, peer.port);

        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);

        int req_index = get_req(cookie, sem, sd);
        if (req_index == -1)
        {
            DEBUG_PRINT(P_ERROR "Failed to find request for the pong we received\n");
            return ERROR;
        }

        DEBUG_PRINT(P_INFO "Found corresponding ping\n");
    }
    else if (memcmp(decrypted_data, FINDNODE, COMM_LEN) == 0) // Peer wants to get our peer_list
    {
        DEBUG_PRINT(P_INFO "Received a node request from [%s:%d]\n", string_ip, peer.port);

        // Extract cookie from packet
        byte cookie[COOKIE_SIZE];
        cookie[0] = data[COMM_LEN + PACKET_NUM_LEN + 0];
        cookie[1] = data[COMM_LEN + PACKET_NUM_LEN + 1];
        cookie[2] = data[COMM_LEN + PACKET_NUM_LEN + 2];
        cookie[3] = data[COMM_LEN + PACKET_NUM_LEN + 3];

        // Respond with closest nodes you know
        send_node(peer.ip, peer.port, cookie, sem, sd);
    }
    else if (memcmp(decrypted_data, SENDNODE, COMM_LEN) == 0) // Peer sent us their peer_list (step 1)
    {
        DEBUG_PRINT(P_INFO "Received nodes from [%s:%d]\n", string_ip, peer.port);

        //memcpy(decrypted_data + C_UDP_HEADER, C_UDP_LEN);
    }/*
    else if (memcmp(decrypted_data, DTLS1, COMM_LEN) == 0) // Peer sent DTLS1, respond with DTLS2
    {
        DEBUG_PRINT(P_INFO "Received DTLS step 1 from [%s:%d]\n", string_ip, peer.port);

        // Extract cookie and packet data
        uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
        memcpy(packet1, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET1BYTES);

        if (send_dtls2(peer_ip, peer.port, packet1, cookie, sem, sd) == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Send_dtls2 failed\n");
            return ERROR;
        }
    }
    else if (memcmp(decrypted_data, DTLS2, COMM_LEN) == 0) // Peer sent DTLS2, respond with DTLS3
    {
        DEBUG_PRINT(P_INFO "Received DTLS step 2 from [%s:%d]\n", string_ip, peer.port);

        // Extract cookie and packet data
        uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
        memcpy(packet2, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET2BYTES);

        if (send_dtls3(peer_ip, peer.port, packet2, cookie, sem, sd) == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Send_dtls3 failed\n");
            return ERROR;
        }

        // Indicate this connection is now secure
        sem_wait(sem);
        sd->peers.secure[peer_index] = 1;
        sem_post(sem);

        // Delete request
        int req_index = get_req(cookie, sem, sd);
        if (req_index == ERROR)
            DEBUG_PRINT(P_ERROR "Failed to get request of DTLS");

        rm_req(req_index, sem, sd);

        DEBUG_PRINT(P_OK "Secure connection has been established with [%s:%d]\n", string_ip, peer.port);
    }
    else if (memcmp(decrypted_data, DTLS3, COMM_LEN) == 0) // Peer sent DTLS3, process and save key
    {
        DEBUG_PRINT(P_INFO "Received DTLS step 3 from [%s:%d]\n", string_ip, peer.port);

        // Extract cookie and packet data
        uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
        memcpy(packet3, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET2BYTES);

        if (hydro_kx_xx_4(&(sd->dtls.state), &(sd->peers.kp[peer_index]), NULL, packet3, NULL) != 0)
        {
            DEBUG_PRINT(P_ERROR "Failed to execute step 4 of DTLS\n");
            return ERROR;
        }

        // Indicate this connection is now secure
        sem_wait(sem);
        sd->peers.secure[peer_index] = 1;
        sem_post(sem);

        // Delete request
        int req_index = get_req(cookie, sem, sd);
        if (req_index == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Failed to get request of DTLS");
            return ERROR;
        }

        rm_req(req_index, sem, sd);

        DEBUG_PRINT(P_OK "Secure connection has been established with [%s:%d]\n", string_ip, peer.port);
    }
    else if (memcmp(decrypted_data, DEBUG_MSG, COMM_LEN) == 0) // Used to debug
    {
        DEBUG_PRINT(P_OK "Debug message from [%s:%d]\n", string_ip, peer.port);

        DEBUG_PRINT(P_INFO "[%02x][%02x][%02x][%02x]\n",
               decrypted_data[8], decrypted_data[9], decrypted_data[10], decrypted_data[11]);
    }*/
    else if (memcmp(decrypted_data, EMPTY, COMM_LEN) == 0) // Used by the stop_server function
    {
        DEBUG_PRINT(P_INFO "Received an empty message\n");
    }

    return OK;
}
