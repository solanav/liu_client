#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../include/network_active.h"

void test_forge_packet();

int main()
{
    test_forge_packet();

    return 0;
}

void test_forge_packet()
{
    byte cookie[COOKIE_SIZE] = {0};
    byte packet[MAX_UDP];
    byte expected_header[C_UDP_HEADER - COOKIE_SIZE] = "\x00\x03\x00\x31";
    byte expected_body[C_UDP_LEN] = "\xDE\xAD\xBE\xEF";
    assert(forge_packet(packet, cookie, (byte *) PONG, 49, (byte *) "\xDE\xAD\xBE\xEF", 4) != ERROR);
    
    // Test header
    assert(memcmp(packet, expected_header, C_UDP_HEADER - COOKIE_SIZE) == 0);
    
    // Test that the body is clean
    assert(memcmp(packet + C_UDP_HEADER, expected_body, 4) == 0);
} 