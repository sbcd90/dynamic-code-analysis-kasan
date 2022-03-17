#include <iostream>
#include <stdlib.h>
#include <string>

void simple_func(int idx) {
    std::cout << idx << std::endl;
    char *ptr = static_cast<char*>(malloc(10 * sizeof(char)));
    ptr[idx] = 'a';
    free(ptr);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return -1;
    }
    
    simple_func(std::stoi(argv[1]));
    return 0;
}