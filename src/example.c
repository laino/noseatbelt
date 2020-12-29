/*
 * Example to make compilers generate spectre mitigations.
 */

#include <stdio.h>

void test() {
    printf("Hello!\n");
    return;
}
     
void (*what)() = test;

int main() {
    __asm("nop");
    what();
    __asm("nop");
    return 0;
}
