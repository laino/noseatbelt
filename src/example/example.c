/*
 * Example to make compilers generate spectre mitigations.
 */

#include <stdio.h>

#include <noseatbelt/noseatbelt.h>

void test() {
    printf("Hello!\n");
    return;
}

void (*what)();

void call_indirect() {
    what = test;
    what();
}

void inlineable_jumps() {
    goto bottom;
middle:
    printf("You!");
    return;
bottom:
    goto middle;
}


int main() {
    remove_all_seatbelts_auto();
    call_indirect();
    inlineable_jumps();
    return 0;
}
