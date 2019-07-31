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
    get_ip(&test, (char *) &ip);
    assert(memcmp("127.0.0.1", ip, 9) == 0);

    for (size_t i = 0; i < MAX_PEERS; i++)
    {
        test.sin_addr.s_addr = 16777343 + 1 + i;
        assert(add_peer(&test, (byte *)"\x23\x89") == OK);
        size_t index;
        get_ip(&test, (char *) &ip);
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
    assert(add_req("127.0.0.1", (byte *)PONG, (byte *)&cookie) == OK);
    int req_index = get_req(cookie);
    assert(req_index == 0);
    
    // Open semaphore for shared memory
	sem_t *sem = sem_open(SERVER_SEM, 0);
	assert(sem != SEM_FAILED);

	// Open shared memory
	int shared_data_fd = shm_open(SERVER_PEERS, O_RDWR, S_IRUSR | S_IWUSR);
	assert(shared_data_fd != -1);

	shared_data *sd = (shared_data *)mmap(NULL, sizeof(shared_data), PROT_WRITE | PROT_READ, MAP_SHARED, shared_data_fd, 0);
	assert(sd != MAP_FAILED);

    assert(memcmp(sd->req.cookie[req_index], cookie, COOKIE_SIZE) == 0);
    assert(memcmp(sd->req.ip[req_index], "127.0.0.1", 9) == 0);
    assert(memcmp(sd->req.header[req_index], PONG, COMM_LEN) == 0);
    assert(sd->req.free[req_index] == 1);
    assert(sd->req.free[1] == 0);
    assert(sd->req.next[req_index] == 0); // Because we are the first req
    assert(sd->req.prev[req_index] == 0); // Same as before
    assert(sd->req.timestamp != NULL);

    // Check cookies are ok
    byte cookie2[COOKIE_SIZE];
    assert(add_req("999.999.999.999", (byte *)PING, (byte *)&cookie2) == OK);
    
    req_index = get_req(cookie2);
    assert(req_index == 1);
    assert(memcmp(cookie, cookie2, COOKIE_SIZE) != 0);

    assert(memcmp(sd->req.cookie[req_index], cookie2, COOKIE_SIZE) == 0);
    assert(memcmp(sd->req.ip[req_index], "999.999.999.999", 15) == 0);
    assert(memcmp(sd->req.header[req_index], PING, COMM_LEN) == 0);
    assert(sd->req.free[req_index] == 1);
    assert(sd->req.next[req_index] == -1);
    assert(sd->req.prev[req_index] == 0);
    assert(sd->req.next[0] == req_index);
    assert(sd->req.timestamp != NULL);

    // Remove one and check
    assert(rm_req(0) == OK);
    assert(get_req(cookie) == ERROR);
    
    // Add it again
    assert(add_req("127.0.0.1", (byte *)PONG, (byte *)&cookie) == OK);
    assert(get_req(cookie) == 0);
}