#include <stdio.h>
#define BUFFER_SIZE 1024
#define SIZE 1000000

int buf[BUFFER_SIZE];

void perf_0()
{
    int i = 0;
    for (i = 0; i < SIZE; ++i)
    {
        buf[i % BUFFER_SIZE] = i % 0x1337;
    }
}

int main()
{
    perf_0();
}

