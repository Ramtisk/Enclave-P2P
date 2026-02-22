#include "logging.h"
#include "config.h"

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/*  ============================================
    COLORS (ANSI)

    Note: Defines ANSI color codes for log output.
    Each log level is mapped to a different color for better readability
    in the terminal. These colors are only used for console output.

    ============================================ */
#define COLOR_RESET   "\033[0m"
#define COLOR_TRACE   "\033[90m"      // Gray
#define COLOR_DEBUG   "\033[36m"      // Cyan
#define COLOR_INFO    "\033[32m"      // Green
#define COLOR_WARN    "\033[33m"      // Yellow
#define COLOR_ERROR   "\033[31m"      // Red
#define COLOR_FATAL   "\033[35m"      // Magenta

/*  ============================================
    GLOBAL STATE

    Note: Holds the current log level, log file pointer, and mutex for thread safety.
    - g_log_level: Minimum level to print.
    - g_log_file: File pointer for log file output (if enabled).
    - g_log_mutex: Ensures thread-safe logging.

    ============================================ */
static log_level_t g_log_level = LOG_INFO;
static FILE* g_log_file = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

/*  ============================================
    HELPER FUNCTIONS

    Note: Internal static functions for log formatting and output.
    - log_level_string: Returns string representation of log level.
    - log_level_color: Returns ANSI color code for log level.
    - log_init: Initializes logging system (level and optional file).
    - log_shutdown: Closes log file if open.
    - log_write: Formats and writes log messages to console and file.
    
    ============================================ */

/*  Function: log_level_string
    Description: Returns a string representation of the given log level.

    Parameters:
    - level: The log level (enum log_level_t).

    Returns:
    - A constant string such as "TRACE", "DEBUG", etc., corresponding to the log level.
    - Returns "?????" if the level is unknown which will end up read as COLOR_RESET and printed with no color (Default).
*/
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

/*  Function: log_level_color
    Description: Returns the ANSI color code string for the given log level, used for colored terminal output.

    Parameters:
    - level: The log level (enum log_level_t).

    Returns:
    - A string with the ANSI color code for the log level.
    - Returns COLOR_RESET if the level is unknown.
*/
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

/*  Function: log_init
    Description:
    Initializes the logging system with the specified log level and sets up file logging with unique filenames per day.

    Parameters:
    - level: The minimum log level to display.
    - file_path: Directory path for log files (if NULL, uses DEFAULT_LOG_PATH).

    Steps:
    1. Sets the global log level.
    2. Determines the log directory (uses DEFAULT_LOG_PATH if file_path is NULL).
    3. Ensures the log directory exists (creates it if needed).
    4. Builds a log file name using the current date and a counter to avoid overwriting existing logs.
    5. Opens the log file in append mode for logging.
    6. If unable to open a file, logging will only occur on the console.
*/
void log_init(log_level_t level, const char* log_dir) {
    g_log_level = level;

    const char* dir_path = (log_dir != NULL) ? log_dir : DEFAULT_LOG_DIR;

    mkdir(dir_path, 0755);

    char date_buf[20];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(date_buf, sizeof(date_buf), "%d-%m-%y", tm_info);

    char log_file_buf[256];
    int counter_files_path = 1;
    while (counter_files_path < 100) {
        snprintf(log_file_buf, sizeof(log_file_buf), "%s/log_%s_%d.txt", dir_path, date_buf, counter_files_path);
        if (access(log_file_buf, F_OK) == -1) {
            break;
        }
        counter_files_path++;
    }
    g_log_file = fopen(log_file_buf, "a");
}


/*  Function: log_shutdown
    Description: Safely shuts down the logging system by closing the log file if it is open.

    Steps:
    1. Checks if the global log file pointer (g_log_file) is not NULL.
    2. If a log file is open, it closes the file and sets the pointer to NULL.
    3. No return value (void function).
*/
void log_shutdown(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

/*  Function: log_write
    Description:
    Formats and writes a log message to both the console (with color) and the log file (if enabled), ensuring thread safety.

    Parameters:
    - level: The log level of the message (enum log_level_t).
    - file: The source file name where the log is called.
    - line: The line number in the source file.
    - fmt: The printf-style format string for the log message.
    - ...: Additional arguments for formatting.

    Steps:
    1. Checks if the message level is above or equal to the current global log level.
    2. Locks the mutex for thread safety.
    3. Gets the current timestamp and formats it.
    4. Extracts the filename from the full path for concise output.
    5. Formats and prints the message to stderr with color codes for the log level.
    6. If a log file is open, writes the message to the file (without color codes).
    7. Flushes the log file to ensure the message is written immediately.
    8. Unlocks the mutex.
    9. Returns nothing (void function).
    Note: va_start is called twice for console and file output.
*/
void log_write(log_level_t level, const char* file, int line, const char* fmt, ...) {
    if (level < g_log_level) return;

    pthread_mutex_lock(&g_log_mutex);

    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    const char* filename = strrchr(file, '/');
    filename = filename ? filename + 1 : file;

    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "%s[%s] %s %s:%d: ",
            log_level_color(level), time_buf,
            log_level_string(level), filename, line);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "%s\n", COLOR_RESET);

    va_end(args);

    if (g_log_file) {
        va_list args2;
        va_start(args2, fmt);
        fprintf(g_log_file, "[%s] %s %s:%d: ",
                time_buf, log_level_string(level), filename, line);
        vfprintf(g_log_file, fmt, args2);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
        va_end(args2);
    }

    pthread_mutex_unlock(&g_log_mutex);
}