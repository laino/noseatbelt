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

int main() {
    remove_all_seatbelts();
    call_indirect();
    return 0;
}
