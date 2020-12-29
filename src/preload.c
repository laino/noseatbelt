/*
 * Library for use with LD_PRELOAD.
 *
 * See also:
 *      https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1
 *      https://github.com/cbbrowne/pmap/blob/master/pmap.c
 *
 * Hook main() using LD_PRELOAD.
 *
 * Compile using 'gcc hax.c -o hax.so -fPIC -shared -ldl'
 * Then run your program as 'LD_PRELOAD=$PWD/hax.so ./a.out'
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>

#include "noseatbelt.c"

static int remove_all_seatbelts() {
    SeatbeltState state;

    init_seatbelt(&state, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    FILE *fp = fopen("/proc/self/maps", "r");

    if (!fp) {
        return 1;
    }

    while (!feof(fp)) {
        char buf[PATH_MAX+100], perm[5], dev[6], mapname[PATH_MAX];
        unsigned long start, end, inode, foo;
        int prot = 0;

        if(fgets(buf, sizeof(buf), fp) == 0) {
            break;
        }

        mapname[0] = '\0';

        sscanf(buf, "%lx-%lx %4s %lx %5s %ld %s", &start, &end, perm, &foo, dev, &inode, mapname);

        if (perm[0] == 'r') {
            prot |= PROT_READ;
        }
        
        if (perm[1] == 'w') {
            prot |= PROT_WRITE;
        }
        
        if (perm[2] == 'x') {
            prot |= PROT_EXEC;
        }

        if (!(prot & PROT_EXEC) || !(prot & PROT_READ)) {
            continue;
        }
        
        mprotect((void*) start, end - start, PROT_WRITE | PROT_WRITE | PROT_EXEC);

        remove_seatbelts(&state, (void*) start, (void*) end);
        
        mprotect((void*) start, end - start, prot);
    }

    fclose(fp);

    printf("> Removed %lu trampolines.\n", state.trampolines);

    return 0;
}

/* Trampoline for the real main() */
static int (*main_orig)(int, char**, char**);

/* Our fake main() that gets called by __libc_start_main() */
static int main_hook(int argc, char **argv, char **envp)
{
    remove_all_seatbelts();

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
