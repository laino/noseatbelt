#ifdef UNIX

#include <stdio.h>
#include <limits.h>
#include <sys/mman.h>

#include <noseatbelt/noseatbelt.h>

static void _remove_all_seatbelts(SeatbeltState *state) {
    FILE *fp = fopen("/proc/self/maps", "r");

    if (!fp) {
        return;
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

        remove_seatbelts(state, (void*) start, (void*) end);

        mprotect((void*) start, end - start, prot);
    }

    fclose(fp);
}

#endif
