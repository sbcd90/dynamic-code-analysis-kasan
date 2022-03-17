#include <stdio.h>
#include <stdlib.h>

int main() {
    char *ptr = malloc(10 * sizeof(char));
    ptr[20] = 'a';
    printf("%c\n", ptr[20]);
    free(ptr);
    return 0;
}