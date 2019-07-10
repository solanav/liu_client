#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

/**
 * Frees a list of files
 *
 * We use a wrapper because of the realloc and MAX_FILES
 *
 * Returns - OK or ERROR
*/
void free_list_files(char **list, int len);

/**
 * Lists files
 *
 * Given a directory, returns a list of files inside it
 *
 * Returns - OK or ERROR
*/
char **list_files(char *dir_name, int *len);

/**
 * Deobfuscates strings
 *
 * Does its shit
 *
 * Returns - OK or ERROR
*/
char *decrypt_string(char *data, size_t len);

/**
 * Checks if its already running
 *
 * Checks for processes called NAME, if there are 2 or
 * more (you + 1) then we stop the program
 *
 * Returns - OK or ERROR
*/
int already_running();

/**
 * Install on the system
 *
 * Installs itself on the system
 *
 * Returns - OK or ERROR
*/
int install();

#endif