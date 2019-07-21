#ifndef NETWORK_DEF_H
#define NETWORK_DEF_H

#define MAX_UDP 512
#define MAX_PEERS 16

#define UNTRUSTED 0
#define TRUSTED 1

#define COMM_LEN 2

#define EMPTY "\x00\x00"
#define PING "\x00\x01"
#define PONG "\x00\x02"
#define GETIP "\x00\x03"

#define INIT "\x00\x04" 
#define PORTH 2
#define PORTL 3


#endif