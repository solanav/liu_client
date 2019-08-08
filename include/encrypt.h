#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "hydrogen.h"

/**
 * Encrypts a file
 *
 * Given a file name and a place to save the key,
 * it encrypts some bytes at the start of the file
 * and then returns saving the encryption (and 
 * decryption) key inside 'key'
 *
 * Returns - OK or ERROR
*/
int encrypt_file(char *file_name, uint8_t *key);

/**
 * Decrypts a file
 *
 * Given a file name and a key, it removes the .liu
 * extension from the file and saves the decrypted
 * content.
 *
 * Returns - OK or ERROR
*/
int decrypt_file(char *file_name, uint8_t *key);

#endif
