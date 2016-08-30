#pragma once

void
log_init(const char *log_path);

void
log_shutdown(void);

void
log_write_os_error(const char *file, int line, int error, const char *format, ...);

void
log_write(const char *file, int line, const char *format, ...);

#define log(...) log_write(__FILE__, __LINE__, __VA_ARGS__)
#define log_os_error(error_code, ...) log_write_os_error(__FILE__, __LINE__, error_code, __VA_ARGS__)
