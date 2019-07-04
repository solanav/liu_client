#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"

int main()
{
	char **list = list_files("plugins");

	for (int i = 0; i < 256 && strcmp(list[i], ""); i++)
		printf("%s\n", list[i]);

	init_plugins(list);

	return OK;
}
