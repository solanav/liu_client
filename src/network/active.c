#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "network/active.h"
#include "types.h"
#include "hydrogen.h"

// Private functions

int e_forge_packet(byte datagram[MAX_UDP], byte cookie[COOKIE_SIZE], const byte type[COMM_LEN], int packet_num, const byte *data, size_t data_size, uint8_t key[hydro_secretbox_KEYBYTES]);

/**
 * Data uploader
 *
 * It uploads generic data to the specified ip
 *
 * ip - String with ip address of the listener
 * port - port where the peer is listening
 * data - Data to send to the server
 * len - lenght of the data to send
 *
 * Returns - The number of bytes sent or -1 in case of error with errno set appropriately
*/
size_t upload_data(const in_addr_t ip, const in_port_t port, byte *data, size_t len);

/**
 * Data uploader xtra
 *
 * It uploads big data
 */
size_t upload_data_x(const in_addr_t ip, const in_port_t port, byte *data, size_t len, byte *header, byte *cont_header);

int send_ping(const in_addr_t ip, const in_port_t port, const in_port_t self_port, unsigned short req_bit, sem_t *sem, shared_data *sd)
{
    // Create cookie with zeros to get a new one and add it to requests
    byte cookie[COOKIE_SIZE] = {0};
    byte data[27];

    // First 4 bytes are the IP
    data[0] = ip >> 24;
    data[1] = (ip >> 16) & 0xFF;
    data[2] = (ip >> 8) & 0xFF;
    data[3] = ip & 0xFF;

    // Next 2 bytes are the PORT
    data[4] = self_port >> 8;
    data[5] = self_port & 0xFF;

    // Next 20 bytes are the ID
    sem_wait(sem);
    memcpy(data + 6, sd->server_info.id, PEER_ID_LEN);
    k_index ki;
    int peer_res = get_kpeer(&(sd->as), ip, &ki);
    sem_post(sem);

    // Next byte is to check if you need a request
    data[26] = req_bit;

    // If our connection has DTLS, encrypt the message
    byte packet[MAX_UDP];
    if (peer_res == OK)
    {
        sem_wait(sem);
        if (sd->KPEER(ki.b, ki.p).secure == DTLS_OK)
        {
            uint8_t key[hydro_secretbox_KEYBYTES];
            memcpy(key, sd->KPEER(ki.b, ki.p).kp.tx, hydro_secretbox_KEYBYTES);
            char tmp[INET_ADDRSTRLEN];
            ip_string(sd->KPEER(ki.b, ki.p).ip, tmp);
            DEBUG_PRINT(P_OK "Peer found with secure connection [%d] [%s:%d]\n", sd->KPEER(ki.b, ki.p).secure, tmp, sd->KPEER(ki.b, ki.p).port);
            sem_post(sem);

            e_forge_packet(packet, cookie, (byte *)PING, 0, data, sizeof(data), key);
        }
        else
        {
            char tmp[INET_ADDRSTRLEN];
            ip_string(sd->KPEER(ki.b, ki.p).ip, tmp);
            DEBUG_PRINT(P_OK "Peer found but NO secure connection [%d] [%s:%d]\n", sd->KPEER(ki.b, ki.p).secure, tmp, sd->KPEER(ki.b, ki.p).port);
            sem_post(sem);
            forge_packet(packet, cookie, (byte *)PING, 0, data, sizeof(data));
        }
    }
    else
    {
        forge_packet(packet, cookie, (byte *)PING, 0, data, sizeof(data));
    }

    if (req_bit == 1)
        if (add_req(ip, (byte *)PING, cookie, sem, sd) == ERROR)
            return ERROR;

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_pong(const in_addr_t ip, const in_port_t port, const in_port_t self_port, byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    // Create cookie with zeros to get a new one and add it to requests
    byte data[26];

    // First 4 bytes are the IP
    data[0] = ip >> 24;
    data[1] = (ip >> 16) & 0xFF;
    data[2] = (ip >> 8) & 0xFF;
    data[3] = ip & 0xFF;

    // Next 2 bytes are the PORT
    data[4] = self_port >> 8;
    data[5] = self_port & 0xFF;

    // Next 20 bytes are the ID
    sem_wait(sem);
    memcpy(data + 6, sd->server_info.id, PEER_ID_LEN);
    k_index ki;
    int peer_res = get_kpeer(&(sd->as), ip, &ki);
    sem_post(sem);

    byte packet[MAX_UDP];
    if (peer_res == OK)
    {
        sem_wait(sem);
        if (sd->KPEER(ki.b, ki.p).secure == DTLS_OK)
        {
            uint8_t key[hydro_secretbox_KEYBYTES];
            memcpy(key, sd->KPEER(ki.b, ki.p).kp.tx, hydro_secretbox_KEYBYTES);
            char tmp[INET_ADDRSTRLEN];
            ip_string(sd->KPEER(ki.b, ki.p).ip, tmp);
            DEBUG_PRINT(P_OK "Peer found with secure connection [%d] [%s:%d]\n", sd->KPEER(ki.b, ki.p).secure, tmp, sd->KPEER(ki.b, ki.p).port);
            sem_post(sem);

            e_forge_packet(packet, cookie, (byte *)PONG, 0, data, sizeof(data), key);

            byte *offset = packet;
            printf(">>>\n");
            for (int i = 0; i < MAX_UDP; i+=8)
                printf("[%02x%02x%02x%02x %02x%02x%02x%02x]\n",
                    offset[i], offset[i+1], offset[i+2], offset[i+3],
                    offset[i+4], offset[i+5], offset[i+6], offset[i+7]);
        }
        else
        {
            char tmp[INET_ADDRSTRLEN];
            ip_string(sd->KPEER(ki.b, ki.p).ip, tmp);
            DEBUG_PRINT(P_OK "Peer found but NO secure connection [%d] [%s:%d]\n", sd->KPEER(ki.b, ki.p).secure, tmp, sd->KPEER(ki.b, ki.p).port);
            sem_post(sem);
            forge_packet(packet, cookie, (byte *)PONG, 0, data, sizeof(data));
        }
    }
    else
    {
        forge_packet(packet, cookie, (byte *)PONG, 0, data, sizeof(data));
    }

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_findnode(const k_index ki, byte id[PEER_ID_LEN], sem_t *sem, shared_data *sd)
{
    // Get the tx key
    uint8_t key[hydro_secretbox_KEYBYTES];
    sem_wait(sem);
    in_addr_t ip = sd->KPEER(ki.b, ki.p).ip;
    in_addr_t port = sd->KPEER(ki.b, ki.p).port;
    memcpy(key, sd->KPEER(ki.b, ki.p).kp.tx, hydro_secretbox_KEYBYTES);
    sem_post(sem);

    byte cookie[COOKIE_SIZE] = {0};
    byte packet[MAX_UDP];
    e_forge_packet(packet, cookie, (byte *)FINDNODE, 0, id, PEER_ID_LEN, key);

    if (add_req(ip, (byte *)FINDNODE, cookie, sem, sd) == ERROR)
        return ERROR;

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_node(const in_addr_t ip, const in_port_t port, byte id[PEER_ID_LEN], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    byte data[C_UDP_LEN] = {0};

    sem_wait(sem);
    addr_space as_copy;
    memcpy(&as_copy, &(sd->as), sizeof(addr_space));
    distance_peer_list(data, id, &(as_copy));
    sem_post(sem);

    // Check if peer is known
    k_index ki;
    unsigned short peer_found = get_kpeer(&as_copy, ip, &ki);

    // Check if connection is secure
    sem_wait(sem);
    unsigned short peer_secure = sd->KPEER(ki.b, ki.p).secure;
    sem_post(sem);

    byte packet[MAX_UDP];
    if (peer_found == OK && peer_secure == DTLS_OK)
    {
        uint8_t key[hydro_secretbox_KEYBYTES];
        sem_wait(sem);
        memcpy(key, sd->KPEER(ki.b, ki.p).kp.tx, hydro_secretbox_KEYBYTES);
        sem_post(sem);

        e_forge_packet(packet, cookie, (byte *)SENDNODE, 0, data, C_UDP_LEN, key);
    }
    else
        forge_packet(packet, cookie, (byte *)SENDNODE, 0, data, C_UDP_LEN);

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_dtls1(k_index ki, sem_t *sem, shared_data *sd)
{
    // Dont try to start if already in progress
    sem_wait(sem);
    if (sd->KPEER(ki.b, ki.p).secure != DTLS_NO)
    {
        DEBUG_PRINT(P_WARN "Connection already secure or in progress [active]\n");
        sem_post(sem);
        return ERROR;
    }
    DEBUG_PRINT(P_INFO "CONNECTION STATUS %d\n", sd->KPEER(ki.b, ki.p).secure);
    sd->KPEER(ki.b, ki.p).secure = DTLS_ING;
    sem_post(sem);

    // Create packet for dtls handshake and update state
    uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
    sem_wait(sem);
    hydro_kx_xx_1(&(sd->dtls.state[(ki.b * MAX_KPEERS) + ki.p]), packet1, NULL);
    in_addr_t ip = sd->KPEER(ki.b, ki.p).ip;
    in_addr_t port = sd->KPEER(ki.b, ki.p).port;
    sem_post(sem);

    // Create udp packet with cookie and packet1 as data
    byte cookie[COOKIE_SIZE] = {0}; // Create new cookie for dtls
    byte packet[MAX_UDP];
    forge_packet(packet, cookie, (byte *)DTLS1, 0, packet1, hydro_kx_XX_PACKET1BYTES);

    // Add a request (removed in step 3)
    if (add_req(ip, (byte *)DTLS1, cookie, sem, sd) == ERROR)
        return ERROR;

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_dtls2(k_index ki, uint8_t packet1[hydro_kx_XX_PACKET1BYTES], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
    sem_wait(sem);
    if (hydro_kx_xx_2(&(sd->dtls.state[(ki.b * MAX_KPEERS) + ki.p]), packet2, packet1, NULL, &(sd->dtls.kp)) != 0) {
        DEBUG_PRINT(P_ERROR "Failed step 2 of dtls handshake\n");
        sem_post(sem);
        return ERROR;
    }
    in_addr_t ip = sd->KPEER(ki.b, ki.p).ip;
    in_addr_t port = sd->KPEER(ki.b, ki.p).port;
    sem_post(sem);

    // Create packet with the cookie from dtls1 and add packet2 as data
    byte packet[MAX_UDP];
    forge_packet(packet, cookie, (byte *)DTLS2, 0, packet2, hydro_kx_XX_PACKET2BYTES);

    // Add a request (removed in step 4)
    if (add_req(ip, (byte *)DTLS2, cookie, sem, sd) == ERROR)
        return ERROR;

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_dtls3(k_index ki, uint8_t packet2[hydro_kx_XX_PACKET1BYTES], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    sem_wait(sem);
    in_addr_t ip = sd->KPEER(ki.b, ki.p).ip;
    in_addr_t port = sd->KPEER(ki.b, ki.p).port;
    sem_post(sem);

    uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
    sem_wait(sem);
    if (hydro_kx_xx_3(&(sd->dtls.state[(ki.b * MAX_KPEERS) + ki.p]), &(sd->KPEER(ki.b, ki.p).kp), packet3, NULL, packet2, NULL,
                  &(sd->dtls.kp)) != 0) {
        DEBUG_PRINT(P_ERROR "Failed step 3 of dtls handshake\n");
        sem_post(sem);
        return ERROR;
    }
    sem_post(sem);

    // Create packet with the cookie from dtls1 and add packet3 as data
    byte packet[MAX_UDP];
    forge_packet(packet, cookie, (byte *)DTLS3, 0, packet3, hydro_kx_XX_PACKET3BYTES);

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_debug(k_index ki, const byte *data, size_t len, sem_t *sem, shared_data *sd)
{
    if (len > C_UDP_LEN)
    {
        DEBUG_PRINT(P_ERROR "Message too long to send as debug\n");
        return ERROR;
    }

    // Get the tx key
    uint8_t key[hydro_secretbox_KEYBYTES];
    sem_wait(sem);
    in_addr_t ip = sd->KPEER(ki.b, ki.p).ip;
    in_addr_t port = sd->KPEER(ki.b, ki.p).port;
    memcpy(key, sd->KPEER(ki.b, ki.p).kp.tx, hydro_secretbox_KEYBYTES);
    sem_post(sem);

    // Create packet with the data provided
    byte packet[MAX_UDP];
    e_forge_packet(packet, NULL, (byte *)DEBUG_MSG, 0, data, len, key);

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_empty(const in_addr_t ip, const in_port_t port)
{
    byte packet[MAX_UDP] = {0};

    return upload_data(ip, port, packet, MAX_UDP);
}

size_t upload_data(const in_addr_t ip, const in_port_t port, byte *data, size_t len)
{
    if (len > MAX_UDP)
    {
        DEBUG_PRINT(P_ERROR "Use upload_data_x for packets larger than MAX_UDP bytes\n");
        return ERROR;
    }

    // Create the socket
    int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_desc < 0)
    {
        DEBUG_PRINT(P_ERROR "The socket could not be opened: %s\n", strerror(errno));
        return ERROR;
    }

    struct sockaddr_in other_addr;
    memset(&other_addr, 0, sizeof(other_addr));

    // Fill info for the other
    other_addr.sin_family = AF_INET;
    other_addr.sin_addr.s_addr = htonl(ip);
    other_addr.sin_port = htons(port);

    int res = sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));

    close(socket_desc);

    return res;
}

int forge_packet(byte datagram[MAX_UDP], byte cookie[COOKIE_SIZE], const byte type[COMM_LEN], int packet_num, const byte *data, size_t data_size)
{
    if (!type)
        return ERROR;

    // Copy type
    memcpy(datagram, type, COMM_LEN);

    // Copy packet num
    datagram[COMM_LEN] = (packet_num >> 8) & 0x00ff;
    datagram[COMM_LEN + 1] = packet_num & 0x00ff;

    // Create cookie
    if (cookie)
    {
        if (strcmp((char *)cookie, "\x00\x00\x00\x00") == 0)
        {
            getrandom(cookie, COOKIE_SIZE, 0);
        }

        memcpy(datagram + COMM_LEN + PACKET_NUM_LEN, cookie, COOKIE_SIZE);
    }
    else
    {
        getrandom(datagram + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE, 0);
    }

    // Copy data if any
    if (data && data_size <= (size_t)(C_UDP_LEN))
    {
        memcpy(datagram + C_UDP_HEADER, data, data_size);

        // Fill the rest with random bytes
        getrandom(datagram + C_UDP_HEADER + data_size, C_UDP_LEN - data_size, 0);
    }
    else if (data_size > (size_t)C_UDP_LEN)
    {
        DEBUG_PRINT(P_WARN "Data too big [%ld]\n", data_size);
        return ERROR;
    }

    return OK;
}

int e_forge_packet(byte datagram[MAX_UDP], byte cookie[COOKIE_SIZE], const byte type[COMM_LEN], int packet_num, const byte *data, size_t data_size, uint8_t key[hydro_secretbox_KEYBYTES])
{
    if (!type)
        return ERROR;

    byte all_data[MAX_UDP - hydro_secretbox_HEADERBYTES];

    // Copy type
    memcpy(all_data, type, COMM_LEN);

    // Copy packet num
    all_data[COMM_LEN] = (packet_num >> 8) & 0x00ff;
    all_data[COMM_LEN + 1] = packet_num & 0x00ff;

    // Create cookie
    if (cookie)
    {
        if (strcmp((char *)cookie, "\x00\x00\x00\x00") == 0)
        {
            DEBUG_PRINT(P_WARN "Cookie was empty, so we create a new one\n");
            getrandom(cookie, COOKIE_SIZE, 0);
        }

        memcpy(all_data + COMM_LEN + PACKET_NUM_LEN, cookie, COOKIE_SIZE);
    }
    else
    {
        getrandom(all_data + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE, 0);
    }

    // Copy data if any
    if (data && data_size <= (size_t)(C_UDP_LEN))
    {
        memcpy(all_data + C_UDP_HEADER, data, data_size);

        // Fill the rest with random bytes
        getrandom(all_data + C_UDP_HEADER + data_size, C_UDP_LEN - data_size, 0);

        uint8_t encrypted_data[MAX_UDP];
        hydro_secretbox_encrypt(encrypted_data, all_data, MAX_UDP - hydro_secretbox_HEADERBYTES, 0, SSL_CTX, key);
        memcpy(datagram, encrypted_data, MAX_UDP);
    }
    else if (data_size > (size_t)C_UDP_LEN)
    {
        DEBUG_PRINT(P_WARN "Data too big [%ld]\n", data_size);
        return ERROR;
    }

    return OK;
}
