#define DEBUG 1

#ifndef NDEBUG
#if defined(DEBUG) && DEBUG >= 2
 #define DEBUG_PRINT(level, fmt, ...) \
     if (DEBUG >= level) printf("DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, __VA_ARGS__)
#elif defined(DEBUG)
 #define DEBUG_PRINT(level, fmt, ...) \
     if (DEBUG >= level) printf( fmt, __VA_ARGS__)
#endif
#else
 #define DEBUG_PRINT(level, fmt, ...) /* Don't do anything in release builds */
#endif
