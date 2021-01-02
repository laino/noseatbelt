/*
 * Example to make compilers generate spectre mitigations.
 */

#include <stdio.h>
#include <noseatbelt/noseatbelt.h>

#if defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__ ((noinline))
#else
#define NOINLINE
#endif

void test1() {
    printf("Indirect 1\n");
    return;
}

void test2() {
    printf("Indirect 2\n");
    return;
}

static void (*what)();

static void NOINLINE call_indirect1() {
    what();
}

static void NOINLINE call_indirect2() {
    what();
    printf("After Indirect\n");
}

static void NOINLINE call_redirect() {
    call_indirect1();
}

int main() {
    remove_all_seatbelts_auto();
    what = test1;
    call_indirect1();
    call_indirect2();
    what = test2;
    call_redirect();
    printf("Goodbye\n");
    return 0;
}
