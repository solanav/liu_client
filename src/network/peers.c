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

#include "network/peers.h"
#include "types.h"
#include "network/netcore.h"

int comp_peers(struct timespec p1, struct timespec p2) 
{   
	// Return 0 if equal	
	if (p1.tv_sec == p2.tv_sec && p1.tv_nsec == p2.tv_nsec)
		return 0;

	// If one is empty, return the other
	if (p1.tv_sec == 0 && p1.tv_nsec == 0)
		return 1;

	if (p2.tv_sec == 0 && p2.tv_nsec == 0)
		return -1;

	// Return 1 if p1 is bigger (slower)
	if (p1.tv_sec > p2.tv_sec)
		return 1;
	else if (p1.tv_sec < p2.tv_sec)
		return -1;
	else
	{
		if (p1.tv_nsec > p2.tv_nsec)
			return 1;
		else if (p1.tv_nsec < p2.tv_nsec)
			return -1;
	}

	return 0;
}
/*
int sort_peers(double_peer_list *peers)
{
	int max;
	for (int i = 0; i < MAX_PEERS * 2; i++)
	{
		max = i;
		for (int j = i; j < MAX_PEERS * 2; j++)
		{
			if (comp_peers(peers->latency[max], peers->latency[j]) == 1)
				max = j;
		}

		// Save to tmp
		struct timespec tmp0;
		tmp0.tv_sec = peers->latency[i].tv_sec;
		tmp0.tv_nsec = peers->latency[i].tv_nsec;
		int tmp1 = peers->port[i];	
		char tmp2[INET_ADDRSTRLEN];
		memcpy(tmp2, peers->ip[i], INET_ADDRSTRLEN);
		int tmp3 = peers->free[i];
	
		// Save max in i
		peers->latency[i].tv_sec = peers->latency[max].tv_sec;
		peers->latency[i].tv_nsec = peers->latency[max].tv_nsec;
		peers->port[i] = peers->port[max];	
		memcpy(peers->ip[i], peers->ip[max], INET_ADDRSTRLEN);
		peers->free[i] = peers->free[max];
		
		// Save tmp in max
		peers->latency[max].tv_sec = tmp0.tv_sec;
		peers->latency[max].tv_nsec = tmp0.tv_nsec;
		peers->port[max] = tmp1;	
		memcpy(peers->ip[max], tmp2, INET_ADDRSTRLEN);
		peers->free[max] = tmp3;
	}

	return OK;
} */

int get_peer(const char other_ip[INET_ADDRSTRLEN], size_t *index, sem_t *sem, shared_data *sd)
{
	for (int i = 0; i < MAX_PEERS; i++)
	{
		sem_wait(sem);
		if (strcmp(other_ip, sd->peers.ip[i]) == 0)
		{
			sem_post(sem);

			if (index)
				*index = i;

			return OK;
		}
		else
		{
			sem_post(sem);
		}
	}

	return ERROR;
}

int add_peer(const struct sockaddr_in *other, const byte *data, sem_t *sem, shared_data *sd)
{
	if (!other)
		return ERROR;

	// Get the ip of the peer
	char other_ip[INET_ADDRSTRLEN];
	if (get_ip(other, other_ip) == ERROR)
	{
		DEBUG_PRINT((P_ERROR "Could not get the ip of the peer\n"));
		return ERROR;
	}

	// Check if peer already on list
	if (get_peer(other_ip, NULL, sem, sd) == OK)
	{
		DEBUG_PRINT((P_ERROR "Peer found on the list already\n"));
		return ERROR;
	}

	// Search for empty space
	int free = -1;
	for (int i = 0; i < MAX_PEERS && free == -1; i++)
	{
		sem_wait(sem);
		if (sd->peers.free[i] == 0)
		{
			free = i;
			sd->peers.free[i] = 1;
		}
		sem_post(sem);
	}

	if (free == -1)
	{
		DEBUG_PRINT((P_ERROR "Peer list is full\n"));
		return ERROR;
	}

	// Update struct's data
	sem_wait(sem);
	strncpy(sd->peers.ip[free], other_ip, INET_ADDRSTRLEN);
	sd->peers.port[free] = (((uint32_t) data[C_UDP_HEADER]) << 8) + data[C_UDP_HEADER + 1];
	DEBUG_PRINT((P_INFO "Added peer with data: [%s:%d]\n", sd->peers.ip[free], sd->peers.port[free]));
	sem_post(sem);

	return OK;
}

int add_req(const char ip[INET_ADDRSTRLEN], const byte header[C_UDP_HEADER], const byte cookie[COOKIE_SIZE], sem_t *sem, shared_data *sd)
{
	// Check if request is already there
	if (get_req(cookie, sem, sd) != -1)
	{
		DEBUG_PRINT((P_ERROR "Request already there\n"));
		return ERROR;
	}

	// Save datagram in shared memory with timestamp
	sem_wait(sem);
	
	// Get an empty space to save the request in
	int index = -1;
	for (int i = 0; i < MAX_DATAGRAMS && index == -1; i++)
	{
		if (sd->req.free[i] == 0)
			index = i;
	}

	if (index == -1)
	{
		DEBUG_PRINT((P_ERROR "No memory for new requests\n"));
		sem_post(sem);
		return ERROR;
	}

	// Copy data to req[index]
	clock_gettime(CLOCK_MONOTONIC, &(sd->req.timestamp[index]));
	strncpy(sd->req.ip[index], ip, INET_ADDRSTRLEN);
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

	for (int i = 0; i < MAX_DATAGRAMS; i++)
		printf("(%2d) < [%15s:%02x|%02x] [%02x][%02x][%02x][%02x] {%d} > (%2d)\n",
			   sd->req.prev[i],
			   sd->req.ip[i],
			   sd->req.comm[i][0],
			   sd->req.comm[i][1],
			   sd->req.cookie[i][0],
			   sd->req.cookie[i][1],
			   sd->req.cookie[i][2],
			   sd->req.cookie[i][3],
			   sd->req.free[i],
			   sd->req.next[i]);

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
	memset(sd->req.ip[index], 0, INET_ADDRSTRLEN * sizeof(char));
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
		for (int i = 0; i < COOKIE_SIZE; i++)
			printf("[%x]", req_copy.cookie[cont][i]);
		printf(" ? ");

		for (int i = 0; i < COOKIE_SIZE; i++)
			printf("[%x]", cookie[i]);
		printf("\n");

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
		DEBUG_PRINT((P_ERROR "Failed to find the request\n"));
		return -1;
	}

	return cont;
}

/*
int merge_peerlist(peer_list *new, sem_t *sem, shared_data *sd)
{
	// Sort the new peer_list
	double_peer_list all_peers;
	sem_wait(sem);
	for (int i = 0; i < MAX_PEERS; i++)
	{
		memcpy(all_peers.ip[i], sd->peers.ip[i], INET_ADDRSTRLEN);
		all_peers.port[i] = sd->peers.port[i];
		all_peers.free[i] = sd->peers.free[i];
		all_peers.latency[i].tv_sec = sd->peers.latency[i].tv_sec;
		all_peers.latency[i].tv_nsec = sd->peers.latency[i].tv_nsec;
	}
	sem_post(sem);

	for (int i = MAX_PEERS; i < MAX_PEERS * 2; i++)
	{
		memcpy(all_peers.ip[i], new->ip[i - MAX_PEERS], INET_ADDRSTRLEN);
		all_peers.port[i] = new->port[i - MAX_PEERS];
		all_peers.free[i] = new->free[i - MAX_PEERS];
		all_peers.latency[i].tv_sec = new->latency[i - MAX_PEERS].tv_sec;
		all_peers.latency[i].tv_nsec = new->latency[i - MAX_PEERS].tv_nsec;
	}

	sort_peers(&all_peers);

    printf("\n\n");

    for (int i = 0; i < MAX_PEERS * 2; i++)
    {
        printf("[%2d] [%15s : %05d] [%ld.%ld]\n", i, 
            all_peers.ip[i],
            all_peers.port[i],
            all_peers.latency[i].tv_sec,
            all_peers.latency[i].tv_nsec);
    }
	
	return OK;
}*/