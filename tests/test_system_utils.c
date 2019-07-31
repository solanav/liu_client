#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// rmdir
#include <unistd.h>

// mkdir
#include <sys/stat.h>
#include <sys/types.h>

#include "../include/system_utils.h"

void test_list_files();

int main()
{
    test_list_files();

    return 0;
}

void test_list_files()
{
    // Create a folder and files
    assert(mkdir("./testing", S_IRWXU) == 0);
    
    // Create files
    char name[15] = {0};
    memcpy(name, "./testing/", 10);
    for (int i = 0; i < 500; i++)
    {
        memset(name + 10, 0, 3);
        snprintf(name + 10, 4, "%d", i);
        fopen(name, "w");
    }

    // Get list of files
    int num_files;
    char **file_list = list_files("./testing", &num_files);
    assert(file_list != NULL);
    assert(num_files == 500);

    // Remove files
    for (int i = 0; i < 500; i++)
    {
        memset(name + 10, 0, 3);
        snprintf(name + 10, 4, "%d", i);
        assert(remove(name) == 0);
    }

    // Remove folder and files
    assert(rmdir("./testing") == 0);
    free_list_files(file_list, num_files);
}