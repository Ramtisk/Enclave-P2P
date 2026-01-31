#ifndef P2P_LOGGING_H
#define P2P_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

// ============================================
// LOG LEVELS
// ============================================
typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG = 1,
    LOG_INFO  = 2,
    LOG_WARN  = 3,
    LOG_ERROR = 4,
    LOG_FATAL = 5
} log_level_t;

// ============================================
// COLORS (ANSI)
// ============================================
#define COLOR_RESET   "\033[0m"
#define COLOR_TRACE   "\033[90m"      // Gray
#define COLOR_DEBUG   "\033[36m"      // Cyan
#define COLOR_INFO    "\033[32m"      // Green
#define COLOR_WARN    "\033[33m"      // Yellow
#define COLOR_ERROR   "\033[31m"      // Red
#define COLOR_FATAL   "\033[35m"      // Magenta

// ============================================
// GLOBAL STATE
// ============================================
static log_level_t g_log_level = LOG_INFO;
static FILE* g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================
// HELPER FUNCTIONS
// ============================================
static inline const char* log_level_string(log_level_t level) {
    switch (level) {
        case LOG_TRACE: return "TRACE";
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        case LOG_FATAL: return "FATAL";
        default:        return "?????";
    }
}

static inline const char* log_level_color(log_level_t level) {
    switch (level) {
        case LOG_TRACE: return COLOR_TRACE;
        case LOG_DEBUG: return COLOR_DEBUG;
        case LOG_INFO:  return COLOR_INFO;
        case LOG_WARN:  return COLOR_WARN;
        case LOG_ERROR: return COLOR_ERROR;
        case LOG_FATAL: return COLOR_FATAL;
        default:        return COLOR_RESET;
    }
}

static inline void log_init(log_level_t level, const char* file_path) {
    g_log_level = level;
    if (file_path) {
        g_log_file = fopen(file_path, "a");
    }
}

static inline void log_shutdown(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

static inline void log_write(log_level_t level, const char* file, int line, 
                             const char* fmt, ...) {
    if (level < g_log_level) return;
    
    pthread_mutex_lock(&g_log_mutex);
    
    // Timestamp
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Extract filename from path
    const char* filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;
    
    // Format message
    va_list args;
    va_start(args, fmt);
    
    // Console output (with colors)
    fprintf(stderr, "%s[%s] %s %s:%d: ", 
            log_level_color(level), time_buf, 
            log_level_string(level), filename, line);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "%s\n", COLOR_RESET);
    
    // File output (without colors)
    if (g_log_file) {
        fprintf(g_log_file, "[%s] %s %s:%d: ", 
                time_buf, log_level_string(level), filename, line);
        va_start(args, fmt);
        vfprintf(g_log_file, fmt, args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }
    
    va_end(args);
    pthread_mutex_unlock(&g_log_mutex);
}

// ============================================
// MACROS
// ============================================
#define LOG_TRACE(...) log_write(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_write(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  log_write(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_write(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_write(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) log_write(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#endif // P2P_LOGGING_H