/*
 * Example to make compilers generate spectre mitigations.
 */

#include <stdio.h>

void test() {
    printf("Hello!\n");
}

int main() {
 	void (*what)() = test;
	what();
    return 0;
}
