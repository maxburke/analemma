#include <assert.h>
#include <stddef.h>

#include <Windows.h>

#include "log.h"
#include "process.h"

#ifndef ARRAY_COUNT
#define ARRAY_COUNT(x) (sizeof((x)) / sizeof((x)[0]))
#endif

struct process_wide_key_value_pair_t
{
    WCHAR *key;
    WCHAR *value;
};

struct process_handle_t
{
    WCHAR *program;
    WCHAR *args;
    WCHAR *working_dir;
    WCHAR *environment_block;
    WCHAR log_file_name[MAX_PATH];
    STARTUPINFOW startup_info;
    PROCESS_INFORMATION process_information;

    HANDLE read_pipe;
    HANDLE write_pipe;
//    HANDLE process_handle;
    HANDLE log_file_handle;

    HANDLE job_object;
    HANDLE thread_handle;
    HANDLE timeout_thread_handle;
    HANDLE process_started_event;

    enum process_state_t process_state;
    int process_error;
    int timeout_ms;
};

int
process_wchar_strlen_with_null(const char8_t *string)
{
    return MultiByteToWideChar(CP_UTF8, 0, string, -1, NULL, 0);
}

WCHAR *
process_utf8_to_wide(const char8_t *string)
{
    int alloc_size;
    int rv;
    WCHAR *wide_string;

    if (string == NULL)
    {
        return NULL;
    }
    
    alloc_size = process_wchar_strlen_with_null(string);
    wide_string = calloc(alloc_size, sizeof(WCHAR));

    if (wide_string == NULL)
    {
        return NULL;
    }

    rv = MultiByteToWideChar(CP_UTF8, 0, string, -1, wide_string, alloc_size);
    assert(rv == alloc_size);
    assert(wide_string[alloc_size - 1] == L'\0');

    return wide_string;
}

WCHAR *
process_build_environment_block(struct process_key_value_pair_t *environment, int num_environment_variables)
{
    int i;
    intptr_t alloc_size;
    WCHAR *environment_block;
    WCHAR *ptr;

    if (!environment || num_environment_variables == 0)
    {
        return NULL;
    }
   
    alloc_size = 0;
    for (i = 0; i < num_environment_variables; ++i)
    {
        alloc_size += process_wchar_strlen_with_null(environment[i].key);
        alloc_size += process_wchar_strlen_with_null(environment[i].value);
    }

    /*
     * Environment blocks are terminated with an extra null character which
     * is factored into our allocation below.
     */
    ptr = environment_block = calloc(alloc_size + 1, sizeof(WCHAR));

    for (i = 0; i < num_environment_variables; ++i)
    {
        ptr += MultiByteToWideChar(
            CP_UTF8,
            0,
            environment[i].key,
            -1,
            ptr,
            (int)(alloc_size - (ptr - environment_block)));

        *(ptr - 1) = L'=';

        ptr += MultiByteToWideChar(
            CP_UTF8,
            0,
            environment[i].value,
            -1,
            ptr,
            (int)(alloc_size - (ptr - environment_block)));
    }

    return environment_block;
}

int
process_setup_io_handles(struct process_handle_t *handle)
{
    SECURITY_ATTRIBUTES security_attributes;
    security_attributes.bInheritHandle = TRUE;
    security_attributes.lpSecurityDescriptor = NULL;
    security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);

    if (CreatePipe(&handle->read_pipe, &handle->write_pipe, &security_attributes, 0) == 0)
    {
        return 0;
    }

    handle->startup_info.hStdError = handle->write_pipe;
    handle->startup_info.hStdOutput = handle->write_pipe;
    handle->startup_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    handle->startup_info.dwFlags |= STARTF_USESTDHANDLES;

    return 1;
}

static int
process_open_log_file(struct process_handle_t *handle)
{
    BOOL rv;
    WCHAR temp_dir[MAX_PATH];

    rv = GetTempPathW(ARRAY_COUNT(temp_dir), temp_dir);
    if (rv == FALSE)
    {
        log_os_error(GetLastError(), "Unable to get temp path");
        return 1;
    }

    rv = GetTempFileNameW(temp_dir, L"ana", 0, handle->log_file_name);
    if (rv == FALSE)
    {
        log_os_error(GetLastError(), "Unable to get temp filename for log file");
        return 1;
    }

    handle->log_file_handle = CreateFileW(
        handle->log_file_name,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (handle->log_file_handle == INVALID_HANDLE_VALUE)
    {
        log_os_error(GetLastError(), "Unable to open log file for writing");
        DeleteFileW(handle->log_file_name);
        return 1;
    }

    return 0;
}

static DWORD WINAPI
process_thread(LPVOID parameter)
{
    BOOL rv;
    DWORD resume_thread_rv;
    struct process_handle_t *handle;
    char *output_buffer;
    static const SIZE_T output_buffer_size = 4096;

    handle = parameter;

    if (process_open_log_file(handle))
    {
        goto failed;
    }

    rv = CreateProcessW(
        handle->program,
        handle->args,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        handle->environment_block,
        handle->working_dir,
        &handle->startup_info,
        &handle->process_information);

    if (rv == FALSE)
    {
        log_os_error(GetLastError(), "Unable to create process");
        goto failed;
    }

    rv = AssignProcessToJobObject(handle->job_object, handle->process_information.hProcess);
    if (rv == FALSE)
    {
        log_os_error(GetLastError(), "Unable to assign process to job object");
        goto failed_process_cleanup;
    }

    resume_thread_rv = ResumeThread(handle->process_information.hThread);
    if (resume_thread_rv == (DWORD)-1)
    {
        log_os_error(GetLastError(), "Unable to resume thread of spawned process");
        goto failed_process_cleanup;
    }

    handle->process_state = PROCESS_STATUS_RUNNING;

    rv = SetEvent(handle->process_started_event);
    if (rv == FALSE)
    {
        log_os_error(GetLastError(), "Could not resume main thread");
        goto failed_process_cleanup;
    }

    output_buffer = VirtualAlloc(0, output_buffer_size, MEM_COMMIT, PAGE_READWRITE);
    if (output_buffer == NULL)
    {
        log_os_error(GetLastError(), "Could not allocate output buffer");
        goto failed_process_cleanup;
    }

    for (;;)
    {
        BOOL read_success;
        DWORD bytes_read;
        DWORD total_bytes_written;

        read_success = ReadFile(
            handle->read_pipe,
            output_buffer,
            (DWORD)output_buffer_size,
            &bytes_read,
            NULL);

        if (!read_success || bytes_read == 0)
        {
            DWORD process_complete;

            process_complete = WaitForSingleObject(handle->process_information.hProcess, 0);
            if (process_complete == WAIT_TIMEOUT)
            {
                /*
                 * Process is still running.
                 */
                continue;
            }

            if (process_complete == WAIT_OBJECT_0)
            {
                /*
                 * Process has completed.
                 */
                break;
            }
            
            if (process_complete == WAIT_FAILED)
            {
                goto failed_process_cleanup;
            }
        }

        total_bytes_written = 0;
        do
        {
            DWORD bytes_written;

            rv = WriteFile(handle->log_file_handle, output_buffer + total_bytes_written, bytes_read - total_bytes_written, &bytes_written, NULL);

            if (!rv)
            {
                log_os_error(GetLastError(), "Error writing to log file");
                break;
            }

            total_bytes_written += bytes_written;
        } while (total_bytes_written < bytes_read);
    }

    VirtualFree(output_buffer, 0, MEM_RELEASE);

    return 0;

failed_process_cleanup:
    TerminateProcess(handle->process_information.hProcess, 1);
    CloseHandle(handle->process_information.hThread);
    CloseHandle(handle->process_information.hProcess);

failed:
    handle->process_state = PROCESS_STATUS_FAILED_TO_LAUNCH;
    handle->process_error = GetLastError();
    /* RV CHECK */ SetEvent(handle->process_started_event);
    return ~(DWORD)0;
}

static DWORD WINAPI
timeout_thread(LPVOID parameter)
{
    struct process_handle_t *handle;
    DWORD timeout;
    HANDLE process_handle;
    DWORD rv;

    handle = parameter;
    process_handle = handle->process_information.hProcess;
    timeout = (DWORD)handle->timeout_ms;

    rv = WaitForSingleObject(process_handle, timeout);
    if (rv == WAIT_TIMEOUT)
    {
        if (!TerminateJobObject(handle->job_object, (UINT)-1))
        {
            log_os_error(GetLastError(), "TerminateJobObject failed");
        }

        handle->process_state = PROCESS_STATUS_TIMED_OUT;
    }

    return 0;
}

struct process_handle_t *
process_start(struct process_start_info_t *start_info)
{
    struct process_handle_t *handle;

    handle = calloc(sizeof(struct process_handle_t), 1);

    if (handle == NULL)
    {
        return NULL;
    }

    handle->program = process_utf8_to_wide(start_info->program);
    handle->args = process_utf8_to_wide(start_info->args);
    handle->working_dir = process_utf8_to_wide(start_info->working_dir);
    handle->environment_block = process_build_environment_block(start_info->environment, start_info->num_environment_variables);
    handle->timeout_ms = start_info->timeout_ms;

    if (!process_setup_io_handles(handle))
    {
        process_free(handle);
        return NULL;
    }

    handle->job_object = CreateJobObjectW(NULL, L"analemma");
    handle->process_started_event = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (handle->process_started_event == NULL)
    {
        process_free(handle);
        return NULL;
    }

    handle->thread_handle = CreateThread(
        NULL,
        0,
        process_thread,
        handle,
        0,
        NULL);

    /* RV CHECK */ WaitForSingleObject(handle->process_started_event, INFINITE);

    if (start_info->timeout_ms > 0)
    {
        handle->timeout_thread_handle = CreateThread(
            NULL,
            0,
            timeout_thread,
            handle,
            0,
            NULL);
    }

    return handle;
}

void
process_get_status(struct process_status_t *status, struct process_handle_t *handle, unsigned int exit_wait_ms)
{
    DWORD rv;
    DWORD process_exit_code = 0;

    if (!process_finished(handle->process_state))
    {
        rv = WaitForSingleObject(handle->process_information.hProcess, exit_wait_ms);
        if (rv == WAIT_FAILED)
        {
            log_os_error(GetLastError(), "Unable to wait for process to exit");
        }

        if (rv == WAIT_OBJECT_0)
        {
            handle->process_state = PROCESS_STATUS_EXITED;
        }
    }

    /*
     * This is not handled in an else case as it may not trigger if the process
     * exit is handled in the block above.
     */
    if (process_finished(handle->process_state))
    {
        if (!GetExitCodeProcess(handle->process_information.hProcess, &process_exit_code))
        {
            log_os_error(GetLastError(), "Unable to get process exit code");
        }
    }

    status->exit_code = (int)process_exit_code;
    status->state = handle->process_state;
    WideCharToMultiByte(CP_UTF8, 0, handle->log_file_name, -1, status->log_path, sizeof status->log_path, NULL, NULL);
}

int
process_kill(struct process_handle_t *handle)
{
    TerminateJobObject(handle->job_object, (UINT)-2);
    handle->process_state = PROCESS_STATUS_KILLED;

    return 0;
}

void
process_free(struct process_handle_t *handle)
{
    WaitForSingleObject(handle->thread_handle, INFINITE);
    CloseHandle(handle->thread_handle);

    if (handle->timeout_thread_handle != NULL)
    {
        WaitForSingleObject(handle->timeout_thread_handle, INFINITE);
        CloseHandle(handle->timeout_thread_handle);
    }

    free(handle->program);
    free(handle->args);
    free(handle->working_dir);

    CloseHandle(handle->read_pipe);
    CloseHandle(handle->write_pipe);
    CloseHandle(handle->process_information.hThread);
    CloseHandle(handle->process_information.hProcess);
    CloseHandle(handle->log_file_handle);
    CloseHandle(handle->job_object);
    CloseHandle(handle->process_started_event);
}

