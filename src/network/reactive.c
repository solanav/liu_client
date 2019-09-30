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
#include "network/peer.h"
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

    int value;
    sem_getvalue(sem, &value);

    // Activate signal to stop server
    sem_wait(sem);
    DEBUG_PRINT(P_INFO "Sending empty message...\n");
    sd->server_info.stop = 1;
    sem_post(sem);

    // Message to update the server so it stops asap
    send_empty(LOCAL_IP_NUM, port);

    DEBUG_PRINT(P_INFO "Waiting for server to exit...\n");

    // Wait for the server to exit the main loop
    int val = 0;
    do
    {
        sem_wait(sem);
        val = sd->server_info.stop;
        sem_post(sem);
        sleep(1);
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

        DEBUG_PRINT(P_INFO "New thread, waiting for datagram...\n");

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
        int h_res = handle_reply(data, ntohl(other->sin_addr.s_addr), sem, sd);
        DEBUG_PRINT(P_INFO "Handler result: %s\n", h_res == OK ? "OK" : "ERROR");
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
    // Check if message is from self
    sem_wait(sem);
    if (other_ip == sd->server_info.ip)
    {
        sem_post(sem);
        DEBUG_PRINT(P_INFO "Received message from self, ignoring\n");
        return ERROR;
    }
    sem_post(sem);

    // Get timestamp of received datagram
    struct timespec current;
    memset(&current, 0, sizeof(struct timespec));
    clock_gettime(CLOCK_MONOTONIC, &current);

    peer p;
    int peer_found = get_peer(&p, other_ip, sem, sd);
    in_port_t other_port = 0;
    int other_secure = DTLS_NO;
    if (peer_found == OK)
    {
        sem_wait(sem);
        other_port = p.kp->port;
        other_secure = p.kp->secure;
        sem_post(sem);
    }

#ifdef DEBUG
    char string_ip[INET_ADDRSTRLEN];
    ip_string(other_ip, string_ip);
#endif

    uint8_t decrypted_data[MAX_UDP - hydro_secretbox_HEADERBYTES];
    if (peer_found == OK && other_secure == DTLS_OK)
    {
        uint8_t key[hydro_secretbox_KEYBYTES];

        DEBUG_PRINT(P_INFO "Decrypting message\n");

        sem_wait(sem);
        memcpy(key, p.kp->key.rx, hydro_secretbox_KEYBYTES);
        sem_post(sem);

        if (hydro_secretbox_decrypt(decrypted_data, data,
                                    MAX_UDP, 0,
                                    SSL_CTX, key) == -1)
        {
            DEBUG_PRINT(P_ERROR "Failed to decrypt the message\n");
            return ERROR;
        }

        DEBUG_PRINT(P_OK "Message decrypted correctly\n");
    }
    else
        memcpy(decrypted_data, data, MAX_UDP - hydro_secretbox_HEADERBYTES);

    // Switch for message comm
    if (memcmp(decrypted_data, PING, COMM_LEN) == 0) // Peer wants info about our latency and online status
    {
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);

        in_port_t extracted_port = ((decrypted_data[C_UDP_HEADER + 4] & 0xFF) << 8) +
                                   ((decrypted_data[C_UDP_HEADER + 5] & 0xFF) << 0);

        DEBUG_PRINT(P_INFO "Received a ping from [%s:%d]\n", string_ip, extracted_port);

        kpeer tmp;
        byte other_id[PEER_ID_LEN];
        memcpy(other_id, decrypted_data + C_UDP_HEADER + sizeof(in_addr_t) + sizeof(in_port_t), PEER_ID_LEN);
        create_kpeer(&tmp, other_ip, extracted_port, other_id);

        // Check if they want DTLS
        unsigned char flags = *(decrypted_data + C_UDP_HEADER + sizeof(in_addr_t) + sizeof(in_port_t) + PEER_ID_LEN);
        if ((flags & AC_DTLS) == AC_DTLS)
        {
            DEBUG_PRINT(P_INFO "Sending a dtls to [%s:%d]\n", string_ip, extracted_port);

            add_tkp(&tmp, sem, sd);
            send_dtls1(other_ip, extracted_port, sem, sd);
        }
        else
        {
            DEBUG_PRINT(P_INFO "Sending a pong to [%s:%d]\n", string_ip, extracted_port);

            // Get self port
            sem_wait(sem);
            in_port_t self_port = sd->server_info.port;
            sem_post(sem);

            // Send pong with the cookie from the ping
            send_pong(other_ip, extracted_port, self_port, cookie, sem, sd);
        }
    }
    else if (memcmp(decrypted_data, PONG, COMM_LEN) == 0) // We sent a ping, now we get the info we wanted
    {
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);

        int req_index = get_req(cookie, sem, sd);
        if (req_index == -1)
        {
            DEBUG_PRINT(P_WARN "Pong received but failed to find request\n");

            if (peer_found == OK && other_secure == DTLS_OK)
                return ERROR;
        }
        else
            DEBUG_PRINT(P_INFO "Pong received and found the request\n");

        static unsigned short no_ip = 0;

        // If we don't have our IP yet
        if (no_ip == 0)
        {
            // Execute this piece only once
            no_ip = 1;

            // Get ip in the packet (our's)
            in_addr_t self_ip = ((decrypted_data[C_UDP_HEADER + 0] & 0xFF) << 24) +
                                ((decrypted_data[C_UDP_HEADER + 1] & 0xFF) << 16) +
                                ((decrypted_data[C_UDP_HEADER + 2] & 0xFF) << 8) +
                                ((decrypted_data[C_UDP_HEADER + 3] & 0xFF) << 0);

            // Save ip on shared data
            sem_wait(sem);
            sd->server_info.ip = self_ip;
            sem_post(sem);

            // Get self data and create peer
            sem_wait(sem);
            in_port_t self_port = sd->server_info.port;
            byte self_id[PEER_ID_LEN];
            memcpy(self_id, sd->server_info.id, PEER_ID_LEN);
            sem_post(sem);

            kpeer self_peer;
            create_kpeer(&self_peer, self_ip, self_port, self_id);

            sem_wait(sem);
            add_kpeer(&(sd->as), &self_peer, 1);
            sem_post(sem);

            DEBUG_PRINT(P_OK "Extracted our IP, saving self peer and IP\n");
        }

        // Get other data and create peer
        kpeer other_peer;
        byte other_id[PEER_ID_LEN];
        memcpy(other_id, decrypted_data + C_UDP_HEADER + sizeof(in_addr_t) + sizeof(in_port_t), PEER_ID_LEN);
        in_port_t extracted_port = ((decrypted_data[C_UDP_HEADER + 4] & 0xFF) << 8) +
                                   ((decrypted_data[C_UDP_HEADER + 5] & 0xFF) << 0);

        DEBUG_PRINT(P_INFO "The pong came from [%s:%d]\n", string_ip, extracted_port);

        create_kpeer(&other_peer, other_ip, extracted_port, other_id);

        // First add yourself then the other
        sem_wait(sem);
        add_kpeer(&(sd->as), &other_peer, 0);
        sem_post(sem);
    }
    else if (memcmp(decrypted_data, FINDNODE, COMM_LEN) == 0 && peer_found == OK) // Peer wants to get our peer_list
    {
        DEBUG_PRINT(P_INFO "Received a node request from [%s:%d]\n", string_ip, other_port);

        // Extract cookie from packet
        byte cookie[COOKIE_SIZE];
        cookie[0] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 0];
        cookie[1] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 1];
        cookie[2] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 2];
        cookie[3] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 3];

        // Extract the ID from packet
        byte id[PEER_ID_LEN];
        memcpy(id, decrypted_data + C_UDP_HEADER, PEER_ID_LEN);

        // Respond with closest nodes you know
        send_node(other_ip, other_port, id, cookie, sem, sd);
    }
    else if (memcmp(decrypted_data, SENDNODE, COMM_LEN) == 0 && peer_found == OK) // Peer sent us their peer_list (step 1)
    {
        DEBUG_PRINT(P_INFO "Received nodes from [%s:%d]\n", string_ip, other_port);

        // Extract cookie from packet
        byte cookie[COOKIE_SIZE];
        cookie[0] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 0];
        cookie[1] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 1];
        cookie[2] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 2];
        cookie[3] = decrypted_data[COMM_LEN + PACKET_NUM_LEN + 3];

        // Get the request
        int req_index = get_req(cookie, sem, sd);
        if (req_index == -1)
        {
            DEBUG_PRINT(P_WARN "Failed to find request for the send_node, ignoring\n");
            return ERROR;
        }

        // Check if this is the peer we were looking for
        sem_wait(sem);
        in_addr_t find_ip = sd->req.data.find_ip;
        sem_post(sem);

        if (find_ip == other_ip)
        {
            // Delete the request
            rm_req(req_index, sem, sd);

            DEBUG_PRINT(P_OK "FOUND THE PEER");
            return OK;
        }

        // If we didn't find the objective yet
        in_addr_t tmp_ip;
        in_port_t tmp_port;
        byte tmp_id[PEER_ID_LEN];

        byte *offset = decrypted_data + C_UDP_HEADER;
        for (int i = 0; i < C_UDP_LEN; i += 26)
        {
            // Copy to tmp
            memcpy(&tmp_ip, offset + i, sizeof(in_addr_t));
            memcpy(&tmp_port, offset + i + sizeof(in_addr_t), sizeof(in_port_t));
            memcpy(&tmp_id, offset + i + sizeof(in_addr_t) + sizeof(in_port_t), PEER_ID_LEN);

            kpeer tmp_peer;
            create_kpeer(&tmp_peer, tmp_ip, tmp_port, tmp_id);

            send_node(tmp_ip, tmp_port, tmp_id, cookie, sem, sd);
        }
    }
    else if (memcmp(decrypted_data, DTLS1, COMM_LEN) == 0 && peer_found == OK) // Peer sent DTLS1, respond with DTLS2
    {
        DEBUG_PRINT(P_INFO "Received DTLS step 1 from [%s:%d]\n", string_ip, other_port);

        // Dont try to start if already in progress
        sem_wait(sem);
        if (p.kp->secure != DTLS_NO)
        {
            DEBUG_PRINT(P_WARN "Connection already secure or in progress [reactive]\n");
            sem_post(sem);
            return ERROR;
        }
        p.kp->secure = DTLS_ING;
        sem_post(sem);

        // Extract cookie and packet data
        uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
        memcpy(packet1, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET1BYTES);

        if (send_dtls2(other_ip, other_port, packet1, cookie, sem, sd) == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Send_dtls2 failed\n");

            // Reset connection status to insecure
            sem_wait(sem);
            p.kp->secure = DTLS_NO;
            sem_post(sem);

            return ERROR;
        }
    }
    else if (memcmp(decrypted_data, DTLS2, COMM_LEN) == 0 && peer_found == OK) // Peer sent DTLS2, respond with DTLS3
    {
        DEBUG_PRINT(P_INFO "Received DTLS step 2 from [%s:%d]\n", string_ip, other_port);

        // Extract cookie and packet data
        uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
        memcpy(packet2, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET2BYTES);

        if (send_dtls3(other_ip, other_port, packet2, cookie, sem, sd) == ERROR)
        {
            DEBUG_PRINT(P_ERROR "Send_dtls3 failed\n");

            // Reset connection status to insecure
            sem_wait(sem);
            p.kp->secure = DTLS_NO;
            sem_post(sem);

            return ERROR;
        }

        // Indicate this connection is now secure
        sem_wait(sem);
        p.kp->secure = DTLS_OK;
        sem_post(sem);

        // Delete request
        int req_index = get_req(cookie, sem, sd);
        if (req_index == ERROR)
            DEBUG_PRINT(P_ERROR "Failed to get request of DTLS");

        rm_req(req_index, sem, sd);

        DEBUG_PRINT(P_OK "DTLS established with [%s:%d]\n", string_ip, other_port);
    }
    else if (memcmp(decrypted_data, DTLS3, COMM_LEN) == 0 && peer_found == OK) // Peer sent DTLS3, process and save key
    {
        DEBUG_PRINT(P_INFO "Received DTLS step 3 from [%s:%d]\n", string_ip, other_port);

        // Extract cookie and packet data
        uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
        byte cookie[COOKIE_SIZE];
        memcpy(cookie, decrypted_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE);
        memcpy(packet3, decrypted_data + C_UDP_HEADER, hydro_kx_XX_PACKET2BYTES);

        sem_wait(sem);
        int res = hydro_kx_xx_4(p.state, &(p.kp->key), NULL, packet3, NULL);
        sem_post(sem);
        if (res != 0)
        {
            DEBUG_PRINT(P_ERROR "Failed to execute step 4 of DTLS\n");

            // Reset connection status to insecure
            sem_wait(sem);
            p.kp->secure = DTLS_NO;
            sem_post(sem);

            return ERROR;
        }

        // Indicate this connection is now secure
        sem_wait(sem);
        p.kp->secure = DTLS_OK;
        sem_post(sem);

        // Delete request
        int req_index = get_req(cookie, sem, sd);
        if (req_index == ERROR)
            DEBUG_PRINT(P_ERROR "Failed to get request of DTLS");

        rm_req(req_index, sem, sd);

        DEBUG_PRINT(P_OK "DTLS established with [%s:%d]\n", string_ip, other_port);
    }
    else if (memcmp(decrypted_data, DEBUG_MSG, COMM_LEN) == 0 && peer_found == OK) // Used to debug
    {
        DEBUG_PRINT(P_OK "Debug message from [%s:%d]\n", string_ip, other_port);

        DEBUG_PRINT(P_INFO "[%02x][%02x][%02x][%02x]\n",
                    decrypted_data[8], decrypted_data[9], decrypted_data[10], decrypted_data[11]);
    }
    else if (memcmp(decrypted_data, EMPTY, COMM_LEN) == 0) // Used by the stop_server function
    {
        DEBUG_PRINT(P_INFO "Received an empty message\n");
    }
    else
    {
        DEBUG_PRINT(P_ERROR "Received unknown message from [%s:%d]\n", string_ip, other_port);
        return ERROR;
    }

    return OK;
}
