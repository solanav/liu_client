#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
size_t upload_data(char *ip, in_port_t port, unsigned char *data, size_t len);

int send_ping(char *ip, in_port_t port)
{
	if (add_req(ip, (byte *)PING) == ERROR)
		return ERROR;

	return upload_data(ip, port, (byte *)PING, COMM_LEN);
}

int send_pong(char *ip, in_port_t port)
{
	return upload_data(ip, port, (byte *)PONG, COMM_LEN);
}

int send_empty(char *ip, in_port_t port)
{
	return upload_data(ip, port, (byte *)EMPTY, COMM_LEN);
}

int send_peerdata(char *ip, in_port_t port, in_port_t self_port)
{
	unsigned char data[4] = {0};
	memcpy(data, INIT, COMM_LEN);

	data[PORTH] = (self_port >> 8) & 0x00ff;
	data[PORTL] = self_port & 0x00ff;

	return upload_data(ip, port, data, INIT_LEN);
}

int send_peerrequest(char *ip, in_port_t port)
{
	if (add_req(ip, (byte *)GETPEERS) == ERROR)
		return ERROR;

	return upload_data(ip, port, (byte *)GETPEERS, COMM_LEN);
}

size_t upload_data(char *ip, in_port_t port, byte *data, size_t len)
{
	// Create the socket
	int socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc < 0)
	{
		DEBUG_PRINT((P_ERROR "The socket could not be opened\n"));
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