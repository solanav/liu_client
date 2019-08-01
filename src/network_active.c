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

#include "../include/network_active.h"
#include "../include/network_utils.h"

// Private functions

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
size_t upload_data(char *ip, in_port_t port, byte *data, size_t len);

/**
 * Data uploader xtra
 * 
 * It uploads big data
 */
size_t upload_data_x(char *ip, in_port_t port, byte *data, size_t len, byte *header, byte *cont_header);

int send_ping(char *ip, in_port_t port)
{
	byte cookie[COOKIE_SIZE] = {0};
	byte packet[MAX_UDP];
	forge_packet(packet, cookie, (byte *)PING, 0, NULL, 0);

	if (add_req(ip, (byte *)PING, cookie) == ERROR)
		return ERROR;

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_pong(char *ip, in_port_t port, byte cookie[COOKIE_SIZE])
{
	byte packet[MAX_UDP];
	forge_packet(packet, cookie, (byte *)PONG, 0, NULL, 0);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_empty(char *ip, in_port_t port)
{
	byte packet[MAX_UDP];
	forge_packet(packet, NULL, (byte *)EMPTY, 0, NULL, 0);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_selfdata(char *ip, in_port_t port, in_port_t self_port)
{
	byte data[2];
	data[0] = (self_port >> 8) & 0x00ff;
	data[1] = self_port & 0x00ff;

	byte packet[MAX_UDP];
	forge_packet(packet, NULL, (byte *)INIT, 0, data, PORT_LEN);

	return upload_data(ip, port, packet, MAX_UDP);
}

int send_peerdata(char *ip, in_port_t port)
{
	sem_t *sem = NULL;
	shared_data *sd = NULL;
	if (access_sd(&sem, &sd) == ERROR)
		return ERROR;

	sem_wait(sem);
	peer_list copy = sd->peers;
	sem_post(sem);

	size_t trans = upload_data_x(ip, port,
								 (byte *)&copy,
								 sizeof(peer_list),
								 (byte *)SENDPEERS,
								 (byte *)SENDPEERSC);

	DEBUG_PRINT((P_OK "Uploaded %ld bytes\n", trans));

	return OK;
}

int send_peerrequest(char *ip, in_port_t port)
{
	byte cookie[COOKIE_SIZE];

	if (add_req(ip, (byte *)GETPEERS, cookie) == ERROR)
		return ERROR;

	return upload_data(ip, port, (byte *)GETPEERS, COMM_LEN);
}

size_t upload_data(char *ip, in_port_t port, byte data[], size_t len)
{
	if (len > MAX_UDP)
	{
		DEBUG_PRINT((P_ERROR "Use upload_data_x for packets larger than MAX_UDP bytes\n"));
		return ERROR;
	}

	// Create the socket
	int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc < 0)
	{
		DEBUG_PRINT((P_ERROR "The socket could not be opened: %s\n", strerror(errno)));
		return ERROR;
	}

	struct sockaddr_in other_addr;
	memset(&other_addr, 0, sizeof(other_addr));

	// Fill info for the other
	other_addr.sin_family = AF_INET;
	other_addr.sin_addr.s_addr = inet_addr(ip);
	other_addr.sin_port = htons(port);

	return sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));
}

size_t upload_data_x(char *ip, in_port_t port, byte *data, size_t len, byte *header, byte *cont_header)
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
		if (strcmp((char *) cookie, "\x00\x00\x00\x00") == 0)
		{
			DEBUG_PRINT((P_WARN "Cookie was empty, so we create a new one\n"));
			getrandom(cookie, COOKIE_SIZE, 0);
		}

		memcpy(datagram + COMM_LEN + PACKET_NUM_LEN, cookie, COOKIE_SIZE);
	}
	else
	{
		getrandom(datagram + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE, 0);
	}

	// Copy data if any
	if (data && data_size <= (size_t)C_UDP_LEN)
	{
		memcpy(datagram + C_UDP_HEADER, data, data_size);

		// Fill the rest with zeros
		// TODO: It's probably better to fill with noise or leave it with memory trash
		memset(datagram + C_UDP_HEADER + data_size, 0, C_UDP_LEN - data_size);
	}
	else if (!data)
	{
		DEBUG_PRINT((P_WARN "No data\n"));
		return ERROR;
	}
	else
	{
		DEBUG_PRINT((P_WARN "Data too big\n"));
		return ERROR;
	}

	return OK;
}