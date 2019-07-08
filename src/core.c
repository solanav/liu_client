#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

#include "../include/core.h"
#include "../include/plugin_utils.h"

int main()
{
	char **list = list_files("/home/solanav/back");
	
	return OK;
}
