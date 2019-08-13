#include <arpa/inet.h>
#include <errno.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "network/request.h"
#include "types.h"
#include "network/netcore.h"

int add_req(const in_addr_t ip, const byte header[C_UDP_HEADER], const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
	// Check if request is already there
	if (get_req(cookie, sem, sd) != -1)
	{
		DEBUG_PRINT(P_ERROR "Request already there\n");
		return ERROR;
	}

	// Save datagram in shared memory with timestamp
	
	// Get an empty space to save the request in
	int index = -1;
	for (int i = 0; i < MAX_DATAGRAMS && index == -1; i++)
	{
		sem_wait(sem);
		if (sd->req.free[i] == 0)
			index = i;
		sem_post(sem);
	}

	if (index == -1)
	{
		DEBUG_PRINT(P_ERROR "No memory for new requests\n");
		return ERROR;
	}

	sem_wait(sem);
	
	// Copy data to req[index]
    clock_gettime(CLOCK_MONOTONIC, &(sd->req.timestamp[index]));
    sd->req.ip[index] = ip;
	sd->req.comm[index][0] = header[0];
	sd->req.comm[index][1] = header[1];
	memcpy(sd->req.cookie[index], cookie, COOKIE_SIZE);

	// Update variables of the list
	if (sd->req_last == -1) // If this is the first insertion
		sd->req_first = index;
	else
		sd->req.next[sd->req_last] = index;

	sd->req.prev[index] = sd->req_last;
	sd->req.next[index] = -1;
	sd->req_last = index;
	sd->req.free[index] = 1;

	sem_post(sem);

	return OK;
}

int rm_req(int index, sem_t *sem, shared_data *sd)
{
	sem_wait(sem);

	if (index == sd->req_first)
		sd->req_first = sd->req.next[index];

	int prev_index = sd->req.prev[index];
	int next_index = sd->req.next[index];

	if (index == sd->req_last)
		sd->req_last = prev_index;

	sd->req.next[prev_index] = next_index;
	sd->req.prev[next_index] = prev_index;

    memset(sd->req.comm[index], 0, COMM_LEN * sizeof(char));
    sd->req.ip[index] = 0;
	sd->req.prev[index] = -1;
	sd->req.next[index] = -1;
	sd->req.free[index] = 0;

	sem_post(sem);

	return OK;
}

int get_req(const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
	struct _request req_copy;

	sem_wait(sem);
	req_copy = sd->req;
	int cont = sd->req_first;
	sem_post(sem);

	int found = 0;
	while (found == 0)
	{
		if (memcmp(req_copy.cookie[cont], cookie, COOKIE_SIZE) == 0)
			found = 1;
		else
			cont = req_copy.next[cont];

		// Check the next is ok
		if (cont == -1 || cont == req_copy.next[cont])
			break;
	}

    if (found == 0)
    {
        return -1;
    }

	return cont;
}
