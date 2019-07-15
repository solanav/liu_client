#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"
#include "../include/network_utils.h"

#define PORT 9092

int main()
{
	int len = 0;
	char **file_list = list_files("../plugins", &len);
	
	init_plugins(file_list, len);

	return OK;
}
