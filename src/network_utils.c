#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "../include/types.h"

#define MAX_UDP 512

typedef struct {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
} dtls_params;

// TODO: Error handling
int dtls_create(dtls_params *params, const char* keyname)
{
	int result = 0;

	params->ctx = SSL_CTX_new(DTLS_method());
	result = SSL_CTX_set_cipher_list(params->ctx, "ALL:!ADG:!LOW:!EXP:!MDF:@STRENGTH");

	char certfile[1024];
	char keyfile[1024];

	sprintf(certfile, "~/%s-cert.pem", keyname);
	sprintf(keyfile, "~/%s-key.pem", keyname);

	result = SSL_CTX_use_certificate_file(params->ctx, certfile, SSL_FILETYPE_PEM);
	result = SSL_CTX_use_PrivateKey_file(params->ctx, keyfile, SSL_FILETYPE_PEM);
	result = SSL_CTX_check_private_key(params->ctx);

	return OK;
}

int dtls_init_server(dtls_params *params)
{
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL) {
        fprintf(stderr, "error connecting with BIOs\n");
        return ERROR;
    }

    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL) {
        fprintf(stderr, "error, exit\n");
        return ERROR;
    }

    SSL_set_accept_state(params->ssl);

    return OK;
}

int dtls_init_client(dtls_params *params, const char *address)
{
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL) {
        fprintf(stderr, "error connecting to server\n");
        return -1;
    }

    BIO_set_conn_hostname(params->bio, address);
    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL) {
        fprintf(stderr, "error, exit\n");
        return -1;
    }

    SSL_set_connect_state(params->ssl);
    SSL_set_mode(params->ssl, SSL_MODE_AUTO_RETRY);

    return 0;
}

int start_server(int port)
{
	int socket_desc;
	char buf[MAX_UDP];
	struct sockaddr_in self_addr, other_addr;
	dtls_params params;

	// Get params for DTLS
	if (dtls_create(&params, "server") != OK)
	{
#ifdef DEBUG
		printf(P_ERROR "[start_server] DTLS failed starting server\n");
#endif
		return ERROR;
	}

	if (dtls_init_server(&params) != OK)
	{
#ifdef DEBUG
		printf(P_ERROR "[start_server] DTLS init failed starting server\n");
#endif
		return ERROR;
	}

	// Creating socket file descriptor
	if ((socket_desc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
#ifdef DEBUG
		printf(P_ERROR "[start_server] The socket could not be created\n");
#endif
		return ERROR;
	}

	memset(&self_addr, 0, sizeof(self_addr));
	memset(&other_addr, 0, sizeof(other_addr));

	// Filling the self info
	self_addr.sin_family = AF_INET;
	self_addr.sin_addr.s_addr = INADDR_ANY;
	self_addr.sin_port = htons(port);

	// Bind the socket with the self address
	if (bind(socket_desc, (const struct sockaddr *)&self_addr,
			 sizeof(self_addr)) < 0)
	{
#ifdef DEBUG
		printf(P_ERROR "[start_server] The socket could not be opened\n");
#endif
		return ERROR;
	}

	while (1)
	{
		size_t len;
		int other_fd;

		len = sizeof(self_addr);

		// Accept UDP datagram
		other_fd = accept(socket_desc, (struct sockaddr*) &self_addr, &len);
		if (other_fd < 0)
		{
#ifdef DEBUG
			printf(P_ERROR "[start_server] Error accepting UDP datagram\n");
#endif
			return ERROR;
		}

		// Setup SSL fd and accept datagram
		SSL_set_fd(params.ssl, other_fd);

		if (SSL_accept(params.ssl) <= 0)
		{
#ifdef DEBUG
			ERR_print_errors_fp(stdin);
#endif
			close(other_fd);
			return ERROR;
		}

		int other_data = SSL_read(params.ssl, buf, sizeof(buf));

		printf("Client : %s\n", buf);
		memset(buf, 0, sizeof(buf));
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
#ifdef DEBUG
		printf(P_ERROR "The socket could not be opened\n");
#endif
		return ERROR;
	}

	memset(&other_addr, 0, sizeof(other_addr));
	
	// Fill info for the other
	other_addr.sin_family = AF_INET;
	other_addr.sin_addr.s_addr = inet_addr(ip_addr);
	other_addr.sin_port = htons(port);

	return sendto(socket_desc, data, len, 0, (struct sockaddr *)&other_addr, sizeof(other_addr));
}