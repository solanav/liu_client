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
size_t upload_data_x(char *ip, in_port_t port, byte *data, size_t len, byte *header, byte *cont_header, size_t header_len, size_t cont_header_len);

/**
 * Create a packet
 * 
 * Handles the creation of a standard packet
 */
//char *forge_package(byte *type, int packet_num, byte *data);

int send_ping(char *ip, in_port_t port)
{
	byte cookie[COOKIE_SIZE];
	byte packet[MAX_UDP];
	forge_package((byte *)&packet, (byte *)PING, 0, NULL, 0);

	if (add_req(ip, (byte *)PING, (byte *)&cookie) == ERROR)
		return ERROR;

	return upload_data(ip, port, (byte *)&packet, MAX_UDP);
}

int send_pong(char *ip, in_port_t port)
{
	byte packet[MAX_UDP];
	forge_package((byte *)&packet, (byte *)PONG, 0, NULL, 0);

	return upload_data(ip, port, (byte *)&packet, MAX_UDP);
}

int send_empty(char *ip, in_port_t port)
{
	byte packet[MAX_UDP];
	forge_package((byte *)&packet, (byte *)EMPTY, 0, NULL, 0);

	return upload_data(ip, port, (byte *)packet, MAX_UDP);
}

int send_selfdata(char *ip, in_port_t port, in_port_t self_port)
{
	byte data[2];
	data[0] = (self_port >> 8) & 0x00ff;
	data[1] = self_port & 0x00ff;

	byte packet[MAX_UDP];
	forge_package((byte *)&packet, (byte *)EMPTY, 0, data, PORT_LEN);

	return upload_data(ip, port, (byte *)&packet, MAX_UDP);
}

int send_peerdata(char *ip, in_port_t port)
{
	// Open semaphore for shared memory
	sem_t *sem = sem_open(SERVER_SEM, 0);
	if (sem == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR "Could not open semaphore to close server\n"));
		return ERROR;
	}

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	if (shared_data_fd == -1)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to open the shared memory for the server [%s]\n", strerror(errno)));
		return ERROR;
	}
	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	if (sd == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR "[handle_comm] Failed to truncate shared fd for peers\n"));
		return ERROR;
	}

	sem_wait(sem);
	peer_list copy = sd->peers;
	sem_post(sem);

	size_t trans = upload_data_x(ip, port,
								 (byte *)&copy,
								 sizeof(peer_list),
								 (byte *)SENDPEERS,
								 (byte *)SENDPEERSC,
								 COMM_LEN, COMM_LEN);

	DEBUG_PRINT((P_OK "Uploaded %ld bytes\n", trans));

	return OK;
}

int send_peerrequest(char *ip, in_port_t port)
{
	byte cookie[COOKIE_SIZE];

	if (add_req(ip, (byte *)GETPEERS, (byte *)&cookie) == ERROR)
		return ERROR;

	return upload_data(ip, port, (byte *)GETPEERS, COMM_LEN);
}

size_t upload_data(char *ip, in_port_t port, byte *data, size_t len)
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

size_t upload_data_x(char *ip, in_port_t port, byte *data, size_t len, byte *header, byte *cont_header, size_t header_len, size_t cont_header_len)
{
	//TODO Forge packets

	byte datagram[MAX_UDP] = {0};
	int packet_size = MAX_UDP - (header_len + cont_header_len);
	int packet_num;
	size_t sent = 0;

	for (packet_num = 0; sent < len; packet_num++)
	{
		// Choose header or continuation header
		if (packet_num == 0)
			memcpy(datagram, header, header_len);
		else
			memcpy(datagram, cont_header, cont_header_len);

		// Add number of the packet
		datagram[2] = (packet_num >> 8) & 0x00ff;
		datagram[3] = packet_num & 0x00ff;

		// Add the main data
		if ((len - sent) >= MAX_UDP)
		{
			memcpy(datagram + header_len + PACKET_NUM_LEN,
				   data + sent,
				   packet_size);

			DEBUG_PRINT((P_INFO "DEBUG0 PACKET [%x][%x][%x][%x]\n",
						 datagram[0], datagram[1], datagram[2], datagram[3]));

			// Upload packet
			upload_data(ip, port, datagram, packet_size);

			sent += packet_size;
		}
		else
		{
			memcpy(datagram + header_len + PACKET_NUM_LEN,
				   data + sent,
				   len - sent);

			DEBUG_PRINT((P_INFO "(%ld) DEBUG1 PACKET [%x][%x][%x][%x]\n",
						 len - sent, datagram[0], datagram[1], datagram[2], datagram[3]));

			// Upload packet
			upload_data(ip, port, datagram, len - sent);

			sent += len - sent;
		}

		// Clean
		memset(datagram, 0, MAX_UDP * sizeof(byte));
	}

	return sent;
}

int forge_package(byte *datagram, byte *type, int packet_num, byte *data, size_t data_size)
{
	if (!type)
		return ERROR;

	// Copy type
	memcpy(datagram, type, COMM_LEN);

	// Copy packet num
	datagram[2] = (packet_num >> 8) & 0x00ff;
	datagram[3] = packet_num & 0x00ff;

	// Create cookie
	getrandom(datagram + COMM_LEN + PACKET_NUM_LEN, COOKIE_SIZE, 0);

	// Copy data if any
	size_t data_offset = COMM_LEN + PACKET_NUM_LEN + COOKIE_SIZE;
	if (data && data_size < (size_t)MAX_UDP - data_offset)
	{
		memcpy(datagram + data_offset, data, data_size);

		// Fill the rest with zeros
		memset(datagram + data_offset + data_size, 0, C_UDP_LEN - data_size);
	}
	else
	{
		DEBUG_PRINT((P_ERROR "No data or data too big\n"));
		return ERROR;
	}

	return OK;
}