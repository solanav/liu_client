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

#include "hydrogen.h"
#include "network/active.h"
#include "types.h"
#include "peer.h"

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
 * Can upload big files by dividing them and labeling them with the packet number
 */
size_t upload_data_x(const in_addr_t ip, const in_port_t port, byte *data, size_t len, byte *header, byte *cont_header);

int send_ping(const in_addr_t ip, const in_port_t port, const in_port_t self_port, unsigned short flags, sem_t *sem, shared_data *sd)
{
    peer p;
    int peer_res = get_peer(&p, ip, sem, sd);

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
    int secure = p.kp->secure;
    sem_post(sem);

    // Next byte is for flags
    data[26] = flags;

    // If our connection has DTLS, encrypt the message
    byte packet[MAX_UDP];
    if (peer_res == OK && secure == DTLS_OK)
    {
        uint8_t key[hydro_secretbox_KEYBYTES];
        sem_wait(sem);
        memcpy(key, p.kp->key.tx, hydro_secretbox_KEYBYTES);
        sem_post(sem);
        e_forge_packet(packet, cookie, (byte *)PING, 0, data, sizeof(data), key);
    }
    else
        forge_packet(packet, cookie, (byte *)PING, 0, data, sizeof(data));

    if ((flags & AC_REQ) == AC_REQ)
        if (add_req(ip, (byte *)PING, cookie, sem, sd) == ERROR)
            return ERROR;

    ;

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_pong(const in_addr_t ip, const in_port_t port, const in_port_t self_port, byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    peer p;
    int peer_res = get_peer(&p, ip, sem, sd);

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
    int secure = p.kp->secure;
    sem_post(sem);

    byte packet[MAX_UDP];
    if (peer_res == OK && secure == DTLS_OK)
    {
        uint8_t key[hydro_secretbox_KEYBYTES];
        sem_wait(sem);
        memcpy(key, p.kp->key.tx, hydro_secretbox_KEYBYTES);
        sem_post(sem);

        e_forge_packet(packet, cookie, (byte *)PONG, 0, data, sizeof(data), key);
    }
    else
        forge_packet(packet, cookie, (byte *)PONG, 0, data, sizeof(data));

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_findnode(const in_addr_t ip, const in_port_t port, byte id[PEER_ID_LEN], sem_t *sem, shared_data *sd)
{
    peer p;
    if (get_peer(&p, ip, sem, sd) == ERROR)
    {
        DEBUG_PRINT("Could not find the peer to send the nodes\n");
        return ERROR;
    }

    // Get the tx key
    uint8_t key[hydro_secretbox_KEYBYTES];
    sem_wait(sem);
    memcpy(key, p.kp->key.tx, hydro_secretbox_KEYBYTES);
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
    peer p;
    int peer_found = get_peer(&p, ip, sem, sd);

    // Check if connection is secure
    sem_wait(sem);
    unsigned short peer_secure = p.kp->secure;
    sem_post(sem);

    byte packet[MAX_UDP];
    if (peer_found == OK && peer_secure == DTLS_OK)
    {
        uint8_t key[hydro_secretbox_KEYBYTES];
        sem_wait(sem);
        memcpy(key, p.kp->key.tx, hydro_secretbox_KEYBYTES);
        sem_post(sem);

        e_forge_packet(packet, cookie, (byte *)SENDNODE, 0, data, C_UDP_LEN, key);
    }
    else
        forge_packet(packet, cookie, (byte *)SENDNODE, 0, data, C_UDP_LEN);

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_dtls1(const in_addr_t ip, const in_port_t port, sem_t *sem, shared_data *sd)
{
    peer p;
    if (get_peer(&p, ip, sem, sd) == ERROR)
    {
        DEBUG_PRINT("Could not find the peer to send dtls1\n");
        return ERROR;
    }

    sem_wait(sem);
    if (p.kp->secure != DTLS_NO)
    {
        DEBUG_PRINT(P_WARN "Connection already secure or in progress [active]\n");
        sem_post(sem);
        return ERROR;
    }
    p.kp->secure = DTLS_ING;
    sem_post(sem);

    // Create packet for dtls handshake and update state
    uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
    sem_wait(sem);
    hydro_kx_xx_1(p.state, packet1, NULL);
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

int send_dtls2(const in_addr_t ip, const in_port_t port, uint8_t packet1[hydro_kx_XX_PACKET1BYTES], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    peer p;
    if (get_peer(&p, ip, sem, sd) == ERROR)
    {
        DEBUG_PRINT("Could not find the peer to send dtls2\n");
        return ERROR;
    }

    uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
    sem_wait(sem);
    if (hydro_kx_xx_2(p.state, packet2, packet1, NULL, &(sd->dtls.key)) != 0)
    {
        DEBUG_PRINT(P_ERROR "Failed step 2 of dtls handshake\n");
        sem_post(sem);
        return ERROR;
    }
    sem_post(sem);

    ;

    // Create packet with the cookie from dtls1 and add packet2 as data
    byte packet[MAX_UDP];
    forge_packet(packet, cookie, (byte *)DTLS2, 0, packet2, hydro_kx_XX_PACKET2BYTES);

    // Add a request (removed in step 4)
    if (add_req(ip, (byte *)DTLS2, cookie, sem, sd) == ERROR)
        return ERROR;

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_dtls3(const in_addr_t ip, const in_port_t port, uint8_t packet2[hydro_kx_XX_PACKET1BYTES], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
    peer p;
    if (get_peer(&p, ip, sem, sd) == ERROR)
    {
        DEBUG_PRINT("Could not find the peer to send dtls2\n");
        return ERROR;
    }

    uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
    sem_wait(sem);
    if (hydro_kx_xx_3(p.state, &(p.kp->key), packet3, NULL, packet2, NULL,
                      &(sd->dtls.key)) != 0)
    {
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

int send_exec(const in_addr_t ip, const in_port_t port, const byte *data, size_t len, sem_t *sem, shared_data *sd)
{
    if (len > C_UDP_LEN - 1)
    {
        DEBUG_PRINT(P_ERROR "Message too long to send as exec com\n");
        return ERROR;
    }

    peer p;
    if (get_peer(&p, ip, sem, sd) == ERROR)
    {
        DEBUG_PRINT("Could not find the peer to send exec com\n");
        return ERROR;
    }

    sem_wait(sem);
    int secure = p.kp->secure;
    sem_post(sem);

    if (secure != DTLS_OK)
    {
        DEBUG_PRINT("The exec command cannot be sent through insecure connections\n");
        return ERROR;
    }

    // Get the tx key
    uint8_t key[hydro_secretbox_KEYBYTES];
    sem_wait(sem);
    memcpy(key, p.kp->key.tx, hydro_secretbox_KEYBYTES);
    sem_post(sem);

    // Create packet with the data provided
    byte data_with_len[C_UDP_LEN];
    data_with_len[0] = len;
    memcpy((char *) data_with_len + 1, data, len);

    byte packet[MAX_UDP];
    e_forge_packet(packet, NULL, (byte *)EXEC_COM, 0, data, len, key);

    return upload_data(ip, port, packet, MAX_UDP);
}

int send_debug(const in_addr_t ip, const in_port_t port, const byte *data, size_t len, sem_t *sem, shared_data *sd)
{
    if (len > C_UDP_LEN)
    {
        DEBUG_PRINT(P_ERROR "Message too long to send as debug\n");
        return ERROR;
    }

    peer p;
    if (get_peer(&p, ip, sem, sd) == ERROR)
    {
        DEBUG_PRINT("Could not find the peer to send debug\n");
        return ERROR;
    }

    sem_wait(sem);
    int secure = p.kp->secure;
    sem_post(sem);

    if (secure != DTLS_OK)
    {
        DEBUG_PRINT("The debug message cannot be sent through insecure connections\n");
        return ERROR;
    }

    // Get the tx key
    uint8_t key[hydro_secretbox_KEYBYTES];
    sem_wait(sem);
    memcpy(key, p.kp->key.tx, hydro_secretbox_KEYBYTES);
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
            getrandom(cookie, COOKIE_SIZE, 0);

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
