#include <stdio.h>
#include <stdarg.h>

#include <noseatbelt/debug.h>

static FILE* debug_out_fd = 0;

void noseatbelt_debug_set_fd(FILE* fd) {
    debug_out_fd = fd;
}

void noseatbelt_debug_print(const char* fmt, ...) {
    va_list arg;
    va_start(arg, fmt);

    if (debug_out_fd) {
        vfprintf(debug_out_fd, fmt, arg);
    } else {
        vprintf(fmt, arg);
    }

    va_end(arg);
}