#define DEBUG 0

#if defined(DEBUG) && DEBUG >= 2
 #define DEBUG_PRINT(level, fmt, args...) \
     if (DEBUG >= level) printf("DEBUG: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##args)
#elif defined(DEBUG) && DEBUG >= 1
 #define DEBUG_PRINT(level, fmt, args...) \
     if (DEBUG >= level) printf( fmt, ##args)
#else
 #define DEBUG_PRINT(level, fmt, args...) /* Don't do anything in release builds */
#endif
