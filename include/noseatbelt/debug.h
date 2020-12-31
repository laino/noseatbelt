
#define NOSEATBELT_DEBUG_LEVEL 1

#ifndef NDEBUG
 #define DEBUG_PRINT(level, fmt, ...) \
     if (NOSEATBELT_DEBUG_LEVEL >= level) printf(fmt, ##__VA_ARGS__ )
#else
 #define DEBUG_PRINT(level, fmt, ...) /* Don't do anything in release builds */
#endif
