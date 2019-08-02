#ifndef TYPES_H
#define TYPES_H

typedef unsigned char byte;

#define OTHER 1
#define OK 0
#define ERROR -1

#define TRUE 1
#define FALSE 0

#define STD_SIZE 1024

#define UPDATE_READY 200
#define NO_UPDATE 204

#define NAME "liu_client"
#define HOME "/etc/" NAME
#define BIN HOME "/" NAME
#define BL HOME "/data.bl"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define P_ERROR ANSI_COLOR_RED      "[ERRO] "ANSI_COLOR_RESET
#define P_WARN  ANSI_COLOR_YELLOW   "[WARN] "ANSI_COLOR_RESET
#define P_INFO  ANSI_COLOR_CYAN     "[INFO] "ANSI_COLOR_RESET
#define P_OK    ANSI_COLOR_GREEN    "[OK  ] "ANSI_COLOR_RESET

#define TERMINAL_BLACK "0;30"     
#define TERMINAL_DARK_GRAY "1;30"
#define TERMINAL_RED "0;31"     
#define TERMINAL_LIGHT_RED "1;31"
#define TERMINAL_GREEN "0;32"     
#define TERMINAL_LIGHT_GREEN "1;32"
#define TERMINAL_ORANGE "0;33"  
#define TERMINAL_YELLOW "1;33"
#define TERMINAL_BLUE "0;34"     
#define TERMINAL_LIGHT_BLUE "1;34"
#define TERMINAL_PURPLE "0;35"     
#define TERMINAL_LIGHT_PURPLE "1;35"
#define TERMINAL_CYAN "0;36"     
#define TERMINAL_LIGHT_CYAN "1;36"
#define TERMINAL_LIGHT_GRAY "0;37"     
#define TERMINAL_WHITE "1;37"

#ifdef DEBUG

#include <stdio.h>
# define DEBUG_PRINT(x) printf x 
#else
# define DEBUG_PRINT(x) do {} while (0) 

#endif

#endif