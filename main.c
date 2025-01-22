#include "def.h"


#define KEY_SIZE 16

void generate_key(char *key) {
    if (!key) {
        perror("no key");
        exit(1);
    }
    if (strlen(key) != KEY_SIZE) {
        fprintf(stderr, "Error: Key must be exactly %d characters long.\n", KEY_SIZE);
        exit(1);
    }
}

int main(int ac, char **av) {
    generate_key(av[2]);

    printf("You entered the key: %s\n", key);

    return 0;
}