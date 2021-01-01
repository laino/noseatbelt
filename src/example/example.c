/*
 * Example to make compilers generate spectre mitigations.
 */

#include <stdio.h>
#include <noseatbelt/noseatbelt.h>

void test() {
    printf("Indirect\n");
    return;
}

void (*what)();

void call_indirect() {
    what = test;
    what();
}

void redirect_target() {
    goto next;
next:
    printf("Redirect\n");
}

void call_redirect() {
    redirect_target();
}

void inlineable_jumps() {
    goto bottom;
middle:
    printf("Jump\n");
    return;
bottom:
    goto middle;
}

int main() {
    remove_all_seatbelts_auto();
    call_indirect();
    call_redirect();
    inlineable_jumps();
    return 0;
}
