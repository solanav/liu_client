#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "../include/hydrogen.h"

int encrypt_file(char *file_name, uint8_t **key);
int dencrypt_file(char *file_name, uint8_t *key);

#endif
