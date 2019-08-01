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

#include "../include/network_utils.h"

void test_requests();
void test_peers();

int main()
{
    // Create shared variables for the rest of the tests
    assert(create_shared_variables() == OK);

    test_requests();
    test_peers();

    clean_networking();

    return 0;
}

void test_peers()
{
    struct sockaddr_in test;
    test.sin_addr.s_addr = 16777343;
    char ip[INET_ADDRSTRLEN];

    // Test get_ip
    get_ip(&test, ip);
    assert(memcmp("127.0.0.1", ip, 9) == 0);

    for (size_t i = 0; i < MAX_PEERS; i++)
    {
        test.sin_addr.s_addr = 16777343 + 1 + i;
        assert(add_peer(&test, (byte *)"\x23\x89") == OK);
        size_t index;
        get_ip(&test, ip);
        assert(get_peer(ip, &index) == OK);
        assert(index == i);
    }

    // Not enough space
    test.sin_addr.s_addr = 16777544;
    assert(add_peer(&test, (byte *)"\x23\x89") == ERROR);
}

void test_requests()
{
    byte cookie[COOKIE_SIZE];
    assert(add_req("127.0.0.1", (byte *)PONG, cookie) == OK);
    int req_index = get_req(cookie);
    printf("req > %d\n", req_index);
    assert(req_index == 0);
    
    sem_t *sem = NULL;
	shared_data *sd = NULL;
	assert(access_sd(&sem, &sd) == OK);

    sem_wait(sem);
    assert(memcmp(sd->req.cookie[req_index], cookie, COOKIE_SIZE) == 0);
    assert(memcmp(sd->req.ip[req_index], "127.0.0.1", 9) == 0);
    assert(memcmp(sd->req.header[req_index], PONG, COMM_LEN) == 0);
    assert(sd->req.free[req_index] == 1);
    assert(sd->req.free[1] == 0);
    assert(sd->req.next[req_index] == -1); // Because we are the first req
    assert(sd->req.prev[req_index] == -1); // Same as before
    assert(sd->req.timestamp != NULL);
    sem_post(sem);

    // Remove first and last (edge case)
    assert(rm_req(0) == OK);
    assert(get_req(cookie) == ERROR);
    
    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, cookie) == OK);
    assert(get_req(cookie) == 0);

    // Check cookies are ok
    byte cookie2[COOKIE_SIZE] = "\x12\x34\x56\x78";
    assert(add_req("999.999.999.999", (byte *)PING, cookie2) == OK);
    
    req_index = get_req(cookie2);
    assert(req_index == 1);
    assert(memcmp(cookie, cookie2, COOKIE_SIZE) != 0);

    sem_wait(sem);
    assert(memcmp(sd->req.cookie[req_index], cookie2, COOKIE_SIZE) == 0);
    assert(memcmp(sd->req.ip[req_index], "999.999.999.999", 15) == 0);
    assert(memcmp(sd->req.header[req_index], PING, COMM_LEN) == 0);
    assert(sd->req.free[req_index] == 1);
    assert(sd->req.next[req_index] == -1);
    assert(sd->req.prev[req_index] == 0);
    assert(sd->req.next[0] == req_index);
    assert(sd->req.timestamp != NULL);
    sem_post(sem);

    // Remove first (edge case)
    assert(rm_req(0) == OK);
    assert(get_req(cookie) == ERROR);
    
    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, cookie) == OK);
    assert(get_req(cookie) == 0);

    // Remove last
    assert(rm_req(0) == 0);
    assert(get_req(cookie) == ERROR);

    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, cookie) == OK);
    assert(get_req(cookie) == 0);

    for (int i = 0; i < MAX_DATAGRAMS - 2; i++)
        assert(add_req("127.0.0.1", (byte *)PONG, cookie) == OK);

    // Too many requests
    assert(add_req("127.0.0.1", (byte *)PONG, cookie) == ERROR);
}