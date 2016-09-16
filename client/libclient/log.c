#define _CRT_SECURE_NO_WARNINGS

#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <Windows.h>
#include "log.h"

FILE *log_file;
CRITICAL_SECTION log_lock;

void
log_init(const char *log_path)
{
    log_file = fopen(log_path, "a");
    InitializeCriticalSection(&log_lock);
    atexit(log_shutdown);
}

void
log_shutdown()
{
    EnterCriticalSection(&log_lock);

    if (log_file == NULL)
    {
        LeaveCriticalSection(&log_lock);
        return;
    }

    fflush(log_file);
    fclose(log_file);
    log_file = NULL;

    LeaveCriticalSection(&log_lock);
}

static void
log_write_string(const char *string)
{
    size_t string_length;

    string_length = strlen(string);

    EnterCriticalSection(&log_lock);
    fwrite(string, 1, string_length, log_file);
    fflush(log_file);
    LeaveCriticalSection(&log_lock);
}

#define CHECK_SUCCESS_AND_RESIZE()  \
    if (rv >= buffer_size)          \
    {                               \
        _freea(buffer);             \
        buffer_size = buffer_size * 2;\
        continue;                   \
    }

void
log_write_os_error(const char *file, int line, int error, const char *format, ...)
{
    time_t current_time;
    struct tm local_time;
    LPSTR system_error_message;
    HANDLE process_heap;
    int buffer_size = 1024;
    char *buffer = NULL;
    int rv;
    va_list format_parameters;

    time(&current_time);
    localtime_s(&local_time, &current_time);

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&system_error_message,
        0,
        NULL);

    process_heap = GetProcessHeap();

    for (;;)
    {
        buffer = _malloca(buffer_size);

        if (buffer == NULL)
        {
            goto cleanup;
        }

        rv = snprintf(buffer, buffer_size, "[%04d-%02d-%02d:%02d:%02d:%02d] %s(%d): ",
            local_time.tm_year + 1900,
            local_time.tm_mon + 1,
            local_time.tm_mday,
            local_time.tm_hour,
            local_time.tm_min,
            local_time.tm_sec,
            file,
            line);

        CHECK_SUCCESS_AND_RESIZE();

        va_start(format_parameters, format);
        rv += vsnprintf(buffer + rv, (sizeof buffer) - rv, format, format_parameters);
        va_end(format_parameters);

        CHECK_SUCCESS_AND_RESIZE();

        rv += snprintf(buffer + rv, (sizeof buffer) - rv, ": (%d) %s\n", error, system_error_message);

        CHECK_SUCCESS_AND_RESIZE();

        break;
    }

    if (buffer)
    {
        log_write_string(buffer);
        _freea(buffer);
    }

cleanup:
    HeapFree(process_heap, 0, system_error_message);
}

void
log_write(const char *file, int line, const char *format, ...)
{
    time_t current_time;
    struct tm local_time;
    int buffer_size = 1024;
    char *buffer = NULL;
    int rv;
    va_list format_parameters;

    time(&current_time);
    localtime_s(&local_time, &current_time);

    for (;;)
    {
        buffer = _malloca(buffer_size);

        if (buffer == NULL)
        {
            goto cleanup;
        }

        rv = snprintf(buffer, buffer_size, "[%04d-%02d-%02d:%02d:%02d:%02d] %s(%d): ",
            local_time.tm_year + 1900,
            local_time.tm_mon + 1,
            local_time.tm_mday,
            local_time.tm_hour,
            local_time.tm_min,
            local_time.tm_sec,
            file,
            line);

        CHECK_SUCCESS_AND_RESIZE();

        va_start(format_parameters, format);
        rv += vsnprintf(buffer + rv, (sizeof buffer) - rv, format, format_parameters);
        va_end(format_parameters);

        CHECK_SUCCESS_AND_RESIZE();

        break;
    }

    if (buffer)
    {
        log_write_string(buffer);
        log_write_string("\n");
        _freea(buffer);
    }

cleanup:
    ;
}
