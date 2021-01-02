/*
 * Library for use with LD_PRELOAD.
 *
 * See also:
 *      https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1
 *
 * Hook main() using LD_PRELOAD.
 */
#ifdef UNIX

#define _GNU_SOURCE

#include <dlfcn.h>
#include <limits.h>

#include <noseatbelt/noseatbelt.h>

/* Trampoline for the real main() */
static int (*main_orig)(int, char**, char**);

/* Our fake main() that gets called by __libc_start_main() */
static int main_hook(int argc, char **argv, char **envp)
{
    SeatbeltState state;

    remove_all_seatbelts_auto(&state);

    int ret = main_orig(argc, argv, envp);

    return ret;
}

/*
 * Wrapper for __libc_start_main() that replaces the real main
 * function with our hooked version.
 */
int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end) {
    /* Save the real main function address */
    main_orig = main;

    /* Find the real __libc_start_main()... */
    __typeof__(&__libc_start_main)
        orig = dlsym(RTLD_NEXT, "__libc_start_main");

    /* ... and call it with our custom main function */
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}

#endif
