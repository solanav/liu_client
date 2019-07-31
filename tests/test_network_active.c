#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../include/network_active.h"

void test_forge_package();

int main()
{
    test_forge_package();

    return 0;
}

void test_forge_package()
{
    byte packet[MAX_UDP];
    byte expected_header[C_UDP_HEADER] = "\x00\x03\x00\x31\xDE\xAD\xBE\xEF";
    assert(forge_package((byte *) &packet, (byte *) PONG, 49, (byte *) "\xDE\xAD\xBE\xEF", 4) != ERROR);
    
    // Test header
    assert(memcmp(packet, expected_header, C_UDP_HEADER));
} 