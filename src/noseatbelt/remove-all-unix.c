#ifdef UNIX

#include <malloc.h>
#include <stdio.h>
#include <limits.h>
#include <sys/mman.h>

#include <noseatbelt/noseatbelt.h>

#define MAX_REGIONS 512

void _remove_all_seatbelts(SeatbeltState *state) {
    SeatbeltMemory* memory, *old_memory;
    SeatbeltMemoryRegion *region;
    FILE *fp;
    int i;

    fp = fopen("/proc/self/maps", "r");

    if (!fp) {
        return;
    }

    old_memory = state->memory;

    memory = malloc(sizeof(SeatbeltMemory) + sizeof(SeatbeltMemoryRegion) * MAX_REGIONS);
    memory->num_regions = 0;
    state->memory = memory;

    int OLD_FLAGS[MAX_REGIONS];

    while ((!feof(fp)) && memory->num_regions < MAX_REGIONS) {
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

        region = &memory->regions[memory->num_regions];
        region->start = (ZyanU8*) start;
        region->end = (ZyanU8*) end;

        OLD_FLAGS[memory->num_regions] = prot;

        mprotect(region->start, region->end - region->start, PROT_WRITE | PROT_WRITE | PROT_EXEC);

        memory->num_regions++;
    }

    for (i = 0; i < memory->num_regions; i++) {
        region = &memory->regions[i];

        remove_seatbelts(state, region->start, region->end);
    }

    for (i = 0; i < memory->num_regions; i++) {
        region = &memory->regions[i];

        mprotect(region->start, region->end - region->start, OLD_FLAGS[i]);
    }

    state->memory = old_memory;

    free(memory);

    fclose(fp);
}

#endif
