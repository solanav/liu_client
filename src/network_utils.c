#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "../include/types.h"

#define MAX_UDP 512

void encryption_testing()
{
	/**
	 * =================================================
	 * THIS IS A TEST FUNCTION, NOT FINAL. DO NOT TOUCH.
	 * =================================================
	 */
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned char buf[] = "\x69\x69\x69\x69\x69\x69";
	SHA256_CTX sha_ctx;

	// Calculate the SHA256
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, buf, 6);
	SHA256_Final(digest, &sha_ctx);

	// Get private key
	FILE *pri_fp = fopen("/home/solanav/private.key", "r");
	RSA *pri_key = PEM_read_RSAPrivateKey(pri_fp, NULL, NULL, NULL);

	// Get public key
	FILE *pub_fp = fopen("/home/solanav/public.key", "r");
	RSA *pub_key = PEM_read_RSAPublicKey(pub_fp, NULL, NULL, NULL);

	// Signature the digest
	unsigned int len;
	unsigned char signature[RSA_size(pri_key)];
	RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, &len, pri_key);

	// Verify the signature
	unsigned char unencrypted[6];
	int res = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, RSA_size(pri_key), pri_key);

	// Clean
	RSA_free(pri_key);
	

	if(res == 1)
    {
        printf(P_OK"Signature is valid\n");
        return;
    }
    else
    {
        printf(P_ERROR"Signature is invalid\n");
        return;
    }
}

int start_server(int port)
{
	int socket_desc;
	char buf[MAX_UDP];
	struct sockaddr_in servaddr, cliaddr;

	// Creating socket file descriptor
	if ((socket_desc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	// Filling server information
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(port);

	// Bind the socket with the server address
	if (bind(socket_desc, (const struct sockaddr *)&servaddr,
			 sizeof(servaddr)) < 0)
	{
		DEBUG_PRINT((P_ERROR "The socket could not be opened\n"));
		return ERROR;
	}

	while (1)
	{
		int len, n;
		n = recvfrom(socket_desc, (char *)buf, MAX_UDP,
					 MSG_WAITALL, (struct sockaddr *)&cliaddr,
					 &len);
		buf[n] = '\0';

		printf("Client : %s\n", buf);
	}
	return 0;
}

size_t upload_data(char *ip_addr, int port, unsigned char *data, size_t len)
{
	int socket_desc;
	struct sockaddr_in other_addr;

	// Create the socket
	socket_desc = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_desc < 0)
	{
		DEBUG_PRINT((P_ERROR "The socket could not be opened\n"));
		return ERROR;
	}

	memset(&other_addr, 0, sizeof(other_addr));
	
	// Fill info for the other
	other_addr.sin_family = AF_INET;
	other_addr.sin_addr.s_addr = inet_addr(ip_addr);
	other_addr.sin_port = htons(port);

	return sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));
}