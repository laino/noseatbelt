#ifdef WIN32

#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <noseatbelt/noseatbelt.h>
#include <noseatbelt/debug.h>

FILE* debug_fd;

#ifndef NDEBUG
static void open_logfile() {
    if (debug_fd) {
        return;
    }
    
    char debug_filename[100];
    char attempt = 0;

    while (!debug_fd) {
        snprintf(debug_filename, 100, "noseatbelt-auto-log-%llu-%u.txt", time(NULL), attempt);
        debug_fd = fopen(debug_filename, "wx+");
        attempt++;
    }

    noseatbelt_debug_set_fd(debug_fd);
}

static void close_logfile() {
    if (!debug_fd) {
        return;
    }

    noseatbelt_debug_set_fd(0);
    fclose(debug_fd);
    debug_fd = 0;
}
#else
static void open_logfile() {}
static void close_logfile() {}
#endif


BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved )  // reserved
{

    SeatbeltState state;

    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            open_logfile();
            remove_all_seatbelts_auto(&state);
            break;
        case DLL_PROCESS_DETACH:
            close_logfile();
            break;
        default:
            break;
    }
    return TRUE;
}

#endif