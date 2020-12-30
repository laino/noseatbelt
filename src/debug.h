#define DEBUG 1

#ifndef NDEBUG
#if defined(DEBUG) && DEBUG >= 2
 #define DEBUG_PRINT(level, fmt, args...) \
     if (DEBUG >= level) printf("DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##args)
#elif defined(DEBUG)
 #define DEBUG_PRINT(level, fmt, args...) \
     if (DEBUG >= level) printf( fmt, ##args)
#endif
#else
 #define DEBUG_PRINT(level, fmt, args...) /* Don't do anything in release builds */
#endif
