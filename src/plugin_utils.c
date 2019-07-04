#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"

#define PLUGINS_DIR "plugins/"
#define MAX_PLUGINS 256
#define PLUGIN_NAME 256
#define PLUGIN_PATH_LEN PLUGIN_NAME + strlen(PLUGINS_DIR)

int init_plugins(char **file_list)
{
	char *error;
	char *plugin_path = (char *)calloc(PLUGIN_PATH_LEN, sizeof(char));
	void (*init_plugin)();
	void *handle;

	for (int i = 0; i < MAX_PLUGINS && strcmp(file_list[i], ""); i++)
	{
		plugin_path = strncat(plugin_path, PLUGINS_DIR, PLUGIN_PATH_LEN);
		plugin_path = strncat(plugin_path, file_list[i], PLUGIN_PATH_LEN);
		printf("Init plugin %s\n", plugin_path);
		
		// Get handle for function
		handle = dlopen(plugin_path, RTLD_LAZY);
		if (!handle)
		{
#ifdef DEBUG
			printf("[ERROR] Could not load handle number %d\n", i);
#endif
			return ERROR;
		}
		
		// Get function and call it
		init_plugin = dlsym(handle, "init_plugin");
		error = dlerror();
		if (error != NULL)
		{
			printf("%s\n", error);
			return ERROR;
		}

		init_plugin();
	}

	return OK;
}
