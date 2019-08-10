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
size_t upload_data(const char *ip, const in_port_t port, byte *data, size_t len);

/**
 * Data uploader xtra
 * 
 * It uploads big data
 */
size_t upload_data_x(const char *ip, const in_port_t port, byte *data, size_t len, byte *header, byte *cont_header);

int send_ping(const char *ip, const in_port_t port, sem_t *sem, shared_data *sd)
{
	// Create cookie with zeros to get a new one and add it to requests
	byte cookie[COOKIE_SIZE] = {0};
	byte packet[MAX_UDP];
	forge_packet(packet, cookie, (byte *)PING, 0, NULL, 0);

	if (add_req(ip, (byte *)PING, cookie, sem, sd) == ERROR)
		return ERROR;

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_pong(const char *ip, const in_port_t port, byte cookie[COOKIE_SIZE])
{
	byte packet[MAX_UDP];
	
	forge_packet(packet, cookie, (byte *)PONG, 0, NULL, 4);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_empty(const char *ip, const in_port_t port)
{
	byte packet[MAX_UDP] = {0};
	forge_packet(packet, NULL, (byte *)EMPTY, 0, NULL, 0);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_discover(const char *ip, const in_port_t port, const in_port_t self_port)
{
	byte data[2];
	data[0] = (self_port & 0xff00) >> 8;
	data[1] = (self_port & 0x00ff);

	byte packet[MAX_UDP];
	forge_packet(packet, NULL, (byte *)DISCOVER, 0, data, PORT_LEN);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_selfdata(const char *ip, const in_port_t port, in_port_t self_port)
{
	byte data[2];
	data[0] = (self_port >> 8) & 0x00ff;
	data[1] = self_port & 0x00ff;

	byte packet[MAX_UDP];
	forge_packet(packet, NULL, (byte *)INIT, 0, data, PORT_LEN);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_peerdata(const char *ip, const in_port_t port, sem_t *sem, shared_data *sd)
{
	sem_wait(sem);
	peer_list copy = sd->peers;
	sem_post(sem);

	size_t trans = upload_data_x(ip, port,
								 (byte *)&copy,
								 sizeof(peer_list),
								 (byte *)SENDPEERS,
								 (byte *)SENDPEERSC);

	DEBUG_PRINT(P_OK "Uploaded %ld bytes\n", trans);

	return OK;
}

int send_peerrequest(const char *ip, const in_port_t port, sem_t *sem, shared_data *sd)
{
	byte cookie[COOKIE_SIZE];

	if (add_req(ip, (byte *)GETPEERS, cookie, sem, sd) == ERROR)
		return ERROR;

	return upload_data(ip, port, (byte *)GETPEERS, COMM_LEN);
}

int send_dtls1(const char *ip, const in_port_t port, sem_t *sem, shared_data *sd)
{
	// Create packet for dtls handshake and update state
	uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
	sem_wait(sem);
	hydro_kx_xx_1(&(sd->dtls.state), packet1, NULL);
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

int send_dtls2(const char *ip, const in_port_t port, uint8_t packet1[hydro_kx_XX_PACKET1BYTES], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
	uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
	sem_wait(sem);
	if (hydro_kx_xx_2(&(sd->dtls.state), packet2, packet1, NULL, &(sd->dtls.kp)) != 0) {
		DEBUG_PRINT(P_ERROR "Failed step 2 of dtls handshake\n");
		sem_post(sem);
		return ERROR;
	}
	sem_post(sem);

	// Create packet with the cookie from dtls1 and add packet2 as data
	byte packet[MAX_UDP];
	forge_packet(packet, cookie, (byte *)DTLS2, 0, packet2, hydro_kx_XX_PACKET2BYTES);

	// Add a request (removed in step 4)
	if (add_req(ip, (byte *)DTLS2, cookie, sem, sd) == ERROR)
		return ERROR;

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_dtls3(const char *ip, const in_port_t port, uint8_t packet2[hydro_kx_XX_PACKET1BYTES], byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
	int peer_index = get_peer(ip, sem, sd);
	if (peer_index == ERROR)
	{
		DEBUG_PRINT(P_ERROR "Failed to find peer in peer_list in dtls step 3\n");
		return ERROR;
	}
	
	uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
	sem_wait(sem);
	if (hydro_kx_xx_3(&(sd->dtls.state), &(sd->peers.kp[peer_index]), packet3, NULL, packet2, NULL,
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

int send_debug(const char *ip, const in_port_t port, const byte *data, size_t len, sem_t *sem, shared_data *sd)
{
	if (len > C_UDP_LEN)
	{
		DEBUG_PRINT(P_ERROR "Message too long to send as debug\n");
		return ERROR;
	}

	int peer_index = get_peer(ip, sem, sd);
	if (peer_index == -1)
	{
		sem_post(sem);
		return ERROR;
	}

	// Get the tx key
	uint8_t key[hydro_secretbox_KEYBYTES];
	sem_wait(sem);
	memcpy(key, sd->peers.kp[peer_index].tx, hydro_secretbox_KEYBYTES);
	sem_post(sem);

	// Create packet with the data provided
	byte packet[MAX_UDP];
	e_forge_packet(packet, NULL, (byte *)DEBUG_MSG, 0, data, len, key);

	return upload_data(ip, port, packet, MAX_UDP);
}

size_t upload_data(const char *ip, const in_port_t port, byte *data, size_t len)
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
	other_addr.sin_addr.s_addr = inet_addr(ip);
	other_addr.sin_port = htons(port);

	int res = sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));

	close(socket_desc);

	return res;
}

size_t upload_data_x(const char *ip, const in_port_t port, byte *data, size_t len, byte *header, byte *cont_header)
{
	size_t packet_num;
	size_t sent = 0;
	byte datagram[MAX_UDP] = {0};

	for (packet_num = 0; sent < len; packet_num++)
	{
		if (sent == 0 && len > C_UDP_LEN)
		{
			forge_packet(datagram, NULL, header, packet_num, data + sent, C_UDP_LEN);
			sent += C_UDP_LEN;
		}
		else
		{
			forge_packet(datagram, NULL, cont_header, packet_num, data + sent, len - sent);
			sent += len - sent;
		}

		upload_data(ip, port, datagram, MAX_UDP);

		// Clean
		memset(datagram, 0, MAX_UDP * sizeof(byte));
	}

	return sent;
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
			DEBUG_PRINT(P_WARN "Cookie was empty, so we create a new one\n");
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