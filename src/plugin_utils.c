#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "../include/core.h"

#define PLUGINS_DIR "plugins/"
#define PLUGIN_EXT ".so"
#define PLUGIN_NAME 256
#define PLUGIN_PATH_LEN PLUGIN_NAME + strlen(PLUGINS_DIR)

int init_plugins(char **file_list, int len)
{
	char *error;
	char *plugin_path = (char *)calloc(PLUGIN_PATH_LEN + 1, sizeof(char));
	int (*init_plugin)();
	void *handle;

	for (int i = 0; i < len; i++)
	{
		char *file_extension = strrchr(file_list[i], '.');

		if (!file_extension || strncmp(file_extension, PLUGIN_EXT, strlen(PLUGIN_EXT))) {
			DEBUG_PRINT((P_WARN"Extension is not the expected\n"));
			continue;
		}

		plugin_path = strncat(plugin_path, PLUGINS_DIR, PLUGIN_PATH_LEN);
		plugin_path = strncat(plugin_path, file_list[i], PLUGIN_PATH_LEN);
		DEBUG_PRINT((P_INFO"Init plugin %s\n", plugin_path));

		// Get handle for function
		handle = dlopen(plugin_path, RTLD_NOW);
		if (!handle)
		{
			DEBUG_PRINT((P_ERROR"Could not load handle [%s]\n", dlerror()));
			free(plugin_path);
			return ERROR;
		}

		// Clear any remaining errors
		dlerror();

		// Get function and call it
		*(int **) (&init_plugin) = dlsym(handle, "init_plugin");
				
		if ((error = dlerror()) != NULL)
		{
			DEBUG_PRINT((P_ERROR"In dlsym [%s]\n", error));
			
			dlclose(handle);
			free(plugin_path);
			return ERROR;
		}


		if (init_plugin() == ERROR)
		{
			DEBUG_PRINT((P_ERROR"Plugin failed the execution and returned error\n"));
		}

		dlclose(handle);
		memset(plugin_path, 0, strlen(plugin_path) * sizeof(char));
	}

	free(plugin_path);

	return OK;
}
