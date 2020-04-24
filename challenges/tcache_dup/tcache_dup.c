#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void init(){
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
    setvbuf(stderr,0,2,0);
}

// We want to get here
// 0x400607
void win() {
    printf("Win function executed.");
}

void (*func)() = exit;

int main()
{
	init();
	// Unbuffering to make things clearer
    
	char *a = malloc(0x8);

	free(a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p ].\n", a, a);
	printf("func at [%p] value %x str %s\n", &func, func, func);
	char *b = malloc(0x8);
	/* where to overwrite */
	printf("b at %p: %s\n", b, b);
	memcpy(b, *func, 0x8);
	printf("b: %s\n", b);
	char *c = malloc(0x20);

	read(0, c, 0x8);
	char *d = malloc(0x8);
	fprintf(stderr, "Next allocated buffers will be same: [ %p, %p, %p ].\n", b, c, d);
	/* what to overwrite */
	strncpy(d ,"aaaaaaaa", 8);
	printf("func at [%p] value %x\n", &func, func);

	func = win;
	func();

	return 0;
}
