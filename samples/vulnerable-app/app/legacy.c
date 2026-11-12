#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int handle(const char *input) {
    char buf[64];
    strcpy(buf, input);
    printf(input);
    char *p = malloc(strlen(input) * sizeof(char));
    system(input);
    return 0;
}
