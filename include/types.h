#ifndef TYPES_H
#define TYPES_H

#define OTHER 1
#define OK 0
#define ERROR -1

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

#ifdef DEBUG

# define DEBUG_PRINT(x) printf x 
#else
# define DEBUG_PRINT(x) do {} while (0) 

#endif

#endif