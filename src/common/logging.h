#ifndef P2P_LOGGING_H
#define P2P_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

/*  ============================================
    LOG LEVELS

    Note: Defines the available log levels for the logging system.
    Levels range from TRACE (most verbose) to FATAL (least verbose).
    Used to filter log messages based on importance/severity.

    ============================================ */
typedef enum {
    LOG_TRACE = 0,  // Detailed debug information
    LOG_DEBUG = 1,  // Debug-level messages
    LOG_INFO  = 2,  // Informational messages
    LOG_WARN  = 3,  // Warning conditions
    LOG_ERROR = 4,  // Error conditions
    LOG_FATAL = 5   // Critical errors causing program termination
} log_level_t;

/*  ============================================
    LOGGING FUNCTIONS

    Note: API for initializing, shutting down, and writing log messages.
    - log_init: Initializes logging system with a log level and directory for log files.
    - log_shutdown: Closes log file and cleans up resources.
    - log_write: Writes a formatted log message to console and log file.

    ============================================ */
void log_init(log_level_t level, const char* log_dir);
void log_shutdown(void);
void log_write(log_level_t level, const char* file, int line, const char* format, ...);

/*  ============================================
    LOG MACROS

    Note: Convenience macros for logging at different levels.
    Automatically include the source file and line number.
    Usage example: LOG_INFO("Message: %d", value);
    
    ============================================ */
#define LOG_TRACE(...) log_write(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...) log_write(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  log_write(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_write(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_write(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_FATAL(...) log_write(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#endif // P2P_LOGGING_H