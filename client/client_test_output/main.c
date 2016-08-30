#include <stdio.h>

int main(void)
{
    fprintf(stdout, "Hello stdout!\n");
    fflush(stdout);
    fprintf(stderr, "Hello stderr!\n");
    fflush(stderr);

    return 0;
}