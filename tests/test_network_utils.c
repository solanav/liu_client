#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

// rmdir
#include <unistd.h>

// mkdir
#include <sys/stat.h>
#include <sys/types.h>

// mmap
#include <sys/mman.h>

// semaphore
#include <semaphore.h>

// socket
#include <netinet/in.h>

// timestamps
#include <time.h>

#include "network/peers.h"

void test_requests();
void test_peers();
void test_mergepeers();

int main()
{
    // Create shared variables for the rest of the tests
    assert(create_shared_variables() == OK);

    test_requests();
    
    // Test to add peers
    test_peers();

    // Create more peers and try to merge them
    test_mergepeers();

    clean_networking();

    return 0;
}

void test_mergepeers()
{
    sem_t *sem = NULL;
	shared_data *sd = NULL;
	assert(access_sd(&sem, &sd) == OK);
    
    peer_list new;
    memset(&new, 0, sizeof(peer_list));

    memcpy(new.ip[0], "0.1.2.1", INET_ADDRSTRLEN);
    memcpy(new.ip[3], "0.1.2.2", INET_ADDRSTRLEN);
    memcpy(new.ip[7], "0.1.2.3", INET_ADDRSTRLEN);
    memcpy(new.ip[15], "0.1.2.4", INET_ADDRSTRLEN);

    new.port[0] = 9098;
    new.port[3] = 9099;
    new.port[7] = 9100;
    new.port[15] = 9101;

    struct timespec small_latency;
    small_latency.tv_sec = 0;
    small_latency.tv_nsec = 1;

    new.latency[0] = small_latency;
    new.latency[3] = small_latency;
    new.latency[7] = small_latency;
    new.latency[15] = small_latency;

    for (int i = 0; i < MAX_PEERS; i++)
    {
        sem_wait(sem);
        printf("[%2d] [%15s : %05d] [%ld.%ld]\n", i, 
            new.ip[i],
            new.port[i],
            new.latency[i].tv_sec,
            new.latency[i].tv_nsec);
        sem_post(sem);
    }

    //merge_peerlist(&new, sem, sd);

    sem_close(sem);
    munmap(sd, sizeof(shared_data));
}

void test_peers()
{
    sem_t *sem = NULL;
	shared_data *sd = NULL;
	assert(access_sd(&sem, &sd) == OK);

    struct sockaddr_in test;
    test.sin_addr.s_addr = 16777343;
    char ip[INET_ADDRSTRLEN];

    // Test get_ip
    get_ip(&test, ip);
    assert(memcmp("127.0.0.1", ip, 9) == 0);

    for (size_t i = 0; i < MAX_PEERS; i++)
    {
        test.sin_addr.s_addr = 16777343 + 1 + i;
        assert(add_peer(&test, (byte *)"\x23\x89", sem, sd) == OK);
        size_t index;
        get_ip(&test, ip);
        assert(get_peer(ip, sem, sd) != ERROR);
        assert(index == i);
    }

    // Not enough space
    test.sin_addr.s_addr = 16777544;
    assert(add_peer(&test, (byte *)"\x23\x89", sem, sd) == ERROR);

    sem_close(sem);
    munmap(sd, sizeof(shared_data));
}

void test_requests()
{
    sem_t *sem = NULL;
	shared_data *sd = NULL;
	assert(access_sd(&sem, &sd) == OK);

    byte cookie[COOKIE_SIZE];
    assert(add_req("127.0.0.1", (byte *)PONG, cookie, sem, sd) == OK);
    int req_index = get_req(cookie, sem, sd);
    printf("req > %d\n", req_index);
    assert(req_index == 0);

    sem_wait(sem);
    assert(memcmp(sd->req.cookie[req_index], cookie, COOKIE_SIZE) == 0);
    assert(memcmp(sd->req.ip[req_index], "127.0.0.1", 9) == 0);
    assert(memcmp(sd->req.comm[req_index], PONG, COMM_LEN) == 0);
    assert(sd->req.free[req_index] == 1);
    assert(sd->req.free[1] == 0);
    assert(sd->req.next[req_index] == -1); // Because we are the first req
    assert(sd->req.prev[req_index] == -1); // Same as before
    assert(sd->req.timestamp != NULL);
    sem_post(sem);

    // Remove first and last (edge case)
    assert(rm_req(0, sem, sd) == OK);
    assert(get_req(cookie, sem, sd) == ERROR);
    
    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, cookie, sem, sd) == OK);
    assert(get_req(cookie, sem, sd) == 0);

    // Check cookies are ok
    byte cookie2[COOKIE_SIZE] = "\x12\x34\x56\x78";
    assert(add_req("999.999.999.999", (byte *)PING, cookie2, sem, sd) == OK);
    
    req_index = get_req(cookie2, sem, sd);
    assert(req_index == 1);
    assert(memcmp(cookie, cookie2, COOKIE_SIZE) != 0);

    sem_wait(sem);
    assert(memcmp(sd->req.cookie[req_index], cookie2, COOKIE_SIZE) == 0);
    assert(memcmp(sd->req.ip[req_index], "999.999.999.999", 15) == 0);
    assert(memcmp(sd->req.comm[req_index], PING, COMM_LEN) == 0);
    assert(sd->req.free[req_index] == 1);
    assert(sd->req.next[req_index] == -1);
    assert(sd->req.prev[req_index] == 0);
    assert(sd->req.next[0] == req_index);
    assert(sd->req.timestamp != NULL);
    sem_post(sem);

    // Remove first (edge case)
    assert(rm_req(0, sem, sd) == OK);
    assert(get_req(cookie, sem, sd) == ERROR);
    
    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, cookie, sem, sd) == OK);
    assert(get_req(cookie, sem, sd) == 0);

    // Remove last
    assert(rm_req(0, sem, sd) == 0);
    assert(get_req(cookie, sem, sd) == ERROR);

    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, cookie, sem, sd) == OK);
    assert(get_req(cookie, sem, sd) == 0);

    for (int i = 0; i < MAX_DATAGRAMS - 2; i++)
        assert(add_req("127.0.0.1", (byte *)PONG, cookie, sem, sd) == OK);

    // Too many requests
    assert(add_req("127.0.0.1", (byte *)PONG, cookie, sem, sd) == ERROR);

    sem_close(sem);
    munmap(sd, sizeof(shared_data));
}