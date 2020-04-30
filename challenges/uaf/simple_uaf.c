#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){

    char *msg;
    int size = 6;
    msg = (char*) malloc(size);
    strcpy(msg, "aaaaaa");
    // read(0, msg, size);
    // scanf("%s", msg);
    printf("msg is %s\n", msg);
    if (strcmp(msg, "aaaaaa") == 0) {
        printf("good job!\n");
        free(msg);
        free(msg); // tcache dup
        printf("double free\n");
        // read(0, msg, size);
    }
    
    return 0;
}