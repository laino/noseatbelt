#pragma once

#include <stdio.h>
#include "dll-helper.h"

#define NOSEATBELT_DEBUG_LEVEL 1

DllExport void noseatbelt_debug_set_fd(FILE* fd);
DllExport void noseatbelt_debug_print(const char* fmt, ...);

#ifndef NDEBUG
#define DEBUG_PRINT(level, fmt, ...) \
    if (NOSEATBELT_DEBUG_LEVEL >= level) noseatbelt_debug_print(fmt, ##__VA_ARGS__ )
#else
#define DEBUG_PRINT(level, fmt, ...) /* Don't do anything in release builds */
#endif
