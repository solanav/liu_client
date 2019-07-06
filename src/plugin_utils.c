#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"

#define PLUGINS_DIR "plugins/"
#define PLUGIN_EXT ".so"
#define MAX_PLUGINS 256
#define PLUGIN_NAME 256
#define PLUGIN_PATH_LEN PLUGIN_NAME + strlen(PLUGINS_DIR)

int init_plugins(char **file_list)
{
	char *error;
	char *plugin_path = (char *)calloc(PLUGIN_PATH_LEN + 1, sizeof(char));
	int (*init_plugin)();
	void *handle;

	for (int i = 0; i < MAX_PLUGINS && strcmp(file_list[i], ""); i++)
	{
		char *file_extension = strrchr(file_list[i], '.');

		if (!file_extension || strncmp(file_extension, PLUGIN_EXT, strlen(PLUGIN_EXT))) {
#ifdef DEBUG
			printf("[WARNING] Extension is not the expected\n");
#endif
			continue;
		}

		plugin_path = strncat(plugin_path, PLUGINS_DIR, PLUGIN_PATH_LEN);
		plugin_path = strncat(plugin_path, file_list[i], PLUGIN_PATH_LEN);
#ifdef DEBUG
		printf("[INFO] Init plugin %s\n", plugin_path);
#endif

		// Get handle for function
		handle = dlopen(plugin_path, RTLD_NOW);
		if (!handle)
		{
#ifdef DEBUG
			printf("[ERROR] Could not load handle [%s]\n", dlerror());
#endif
			free(plugin_path);
			return ERROR;
		}

		// Clear any remaining errors
		dlerror();

		// Get function and call it
		init_plugin = dlsym(handle, "init_plugin");
		
		if ((error = dlerror()) != NULL)
		{
#ifdef DEBUG
			printf("[ERROR] In dlsym [%s]\n", error);
#endif
			
			dlclose(handle);
			free(plugin_path);
			return ERROR;
		}


		if (init_plugin() == ERROR)
		{
#ifdef DEBUG
			printf("[ERROR] Plugin failed the execution and returned error\n");
#endif
		}

		dlclose(handle);
		memset(plugin_path, '\0', strlen(plugin_path));
	}

	free(plugin_path);

	return OK;
}
