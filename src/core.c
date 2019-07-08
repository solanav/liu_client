#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"

int main()
{
	int len = 0;
	char **list = list_files("plugins", &len);
	
	init_plugins(list, len);

	for (int i = 0; i < len; i++)
	{
		free(list[i]);
	}
	free(list);

	return OK;
}
