#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/types.h"

#define MAX_UDP 512

int start_server(int port)
{
	int socket_desc;
	struct sockaddr_in self_addr, other_addr;
	char buf[MAX_UDP];

	socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc < 0)
	{
#ifdef DEBUG
		printf(P_ERROR "The socket could not be opened\n");
#endif
		return ERROR;
	}

	memset(&other_addr, 0, sizeof(other_addr));
	memset(&self_addr, 0, sizeof(self_addr));
	self_addr.sin_family = AF_INET;
	self_addr.sin_addr.s_addr = INADDR_ANY;
	self_addr.sin_port = htons(port);

	// Bind to port
	int bind_result = bind(sizeof(socket_desc), 
		(const struct sockaddr *)&self_addr, 
		sizeof(self_addr));

	if (bind_result < -1)
	{
#ifdef DEBUG
		printf(P_ERROR "Binding failed, try to use root\n");
#endif
		return ERROR;
	}

	int len, n;

	while (1) {
		printf("Starting to listen");
		n = recvfrom(socket_desc, (char *)buf, 
			10, 
			MSG_WAITALL, 
			(struct sockaddr *)&other_addr, 
			&len);

		printf("gotit");

		buf[n] = '\0';

		printf("Received: [%s]\n", buf);
		memset(buf, 0, MAX_UDP);
	}
}

size_t upload_data(char *ip_addr, int port, unsigned char *data, size_t len)
{
	int socket_desc;
	struct sockaddr_in other_addr;

	socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc < 0)
	{
#ifdef DEBUG
		printf(P_ERROR "The socket could not be opened\n");
#endif
		return ERROR;
	}

	memset(&other_addr, 0, sizeof(other_addr));
	other_addr.sin_family = AF_INET;
	other_addr.sin_addr.s_addr = inet_addr(ip_addr);
	other_addr.sin_port = htons(port);

	char test_msg[] = "test";

	return sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));
	;
}