/*
 * Example to make compilers generate spectre mitigations.
 */

#include <stdio.h>

// No fancy LD_PRELOAD for windows
#ifdef WIN32
#include "remove-all-win32.c"
#endif

void test() {
    printf("Hello!\n");
    return;
}
     
void (*what)();

void call_indirect() {
    what = test;
    what();
}

int main() {
#ifdef WIN32
    remove_all_seatbelts();
#endif
    call_indirect();
    return 0;
}