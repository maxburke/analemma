#ifdef _MSC_VER
#pragma warning(push, 0)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <time.h>

#ifdef _MSC_VER
#include <WinSock2.h>
#include <MSWSock.h>
#include <Windows.h>
#pragma warning(pop)
#endif

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4820)
#pragma warning(disable:4710)
#pragma warning(disable:4204)
#endif

#include "http_server.h"

#ifndef MIN
#define MIN(a, b) ((a)<(b)?(a):(b))
#endif

#define UNUSED(x) (void)x
#define ARRAY_COUNT(x) ((sizeof(x))/sizeof(x[0]))

FILE *g_log;
HANDLE g_work_available;
HANDLE g_shutdown;
DWORD g_num_threads;
HANDLE *g_threads;
__declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) SLIST_HEADER g_work_list;
__declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) SLIST_HEADER g_free_list;

void
error_log_close(void)
{
    if (!g_log)
    {
        return;
    }

    fflush(g_log);
    fclose(g_log);
}

void
error_log_open(void)
{
    g_log = fopen("analemma_client.log", "w");
    atexit(error_log_close);
}

void
error_log(const char *format, ...)
{
    if (!g_log)
    {
        return;
    }

    time_t current_time;
    struct tm local_time;
    time(&current_time);
    localtime_s(&local_time, &current_time);

    va_list args;
    va_start(args, format);

    fprintf(g_log, "%4d-%02d-%02dT%02d:%02d:%02d - ",
        local_time.tm_year + 1900,
        local_time.tm_mon + 1,
        local_time.tm_mday,
        local_time.tm_hour,
        local_time.tm_min,
        local_time.tm_sec);

    vfprintf(g_log, format, args);
    va_end(args);
}

#define ENFORCE(x, ...) if (!(x)) { error_log(__VA_ARGS__); exit(-1);} else (void)0

struct work_item_t
{
    SLIST_ENTRY entry;
    SOCKET connection;
    struct sockaddr_storage name;
    int name_length;
};

static void
client_shutdown_connection(SOCKET connection)
{
    static char scratch[256];
    int rv;

    rv = shutdown(connection, SD_SEND);
    if (rv == SOCKET_ERROR)
    {
        error_log("Unable to shutdown socket: %d", WSAGetLastError());
        closesocket(connection);

        return;
    }

    do
    {
        rv = recv(connection, scratch, sizeof scratch, 0);
    } while (rv > 0);

    closesocket(connection);
}

static int
client_receive_request(SOCKET connection, char **buffer)
{
    int total_bytes_received;
    char *request_buffer;
    int buffer_size;
    int bytes_received;

    total_bytes_received = 0;
    buffer_size = 0;
    request_buffer = NULL;

    do
    {
        int alloc_size;

        buffer_size += 4096;
        alloc_size = buffer_size + 1;
        request_buffer = realloc(request_buffer, alloc_size);

        if (request_buffer == NULL)
        {
            return -1;
        }

        bytes_received = recv(connection, request_buffer + total_bytes_received, buffer_size - total_bytes_received, 0);
        total_bytes_received += bytes_received;

        assert(total_bytes_received < alloc_size);
        request_buffer[total_bytes_received] = 0;
    } while (bytes_received != 0);

    *buffer = request_buffer;

    return total_bytes_received;
}

static void
client_reset_work_item(struct work_item_t *work_item)
{
    memset(work_item, 0, sizeof(struct work_item_t));
}

static void
client_send_response(SOCKET connection, enum http_status_t status, char *response, int response_length)
{
    UNUSED(connection);
    UNUSED(status);
    UNUSED(response);
    UNUSED(response_length);

    __debugbreak();
}

static void
client_send_error(SOCKET connection, int status)
{
    UNUSED(connection);
    UNUSED(status);

    __debugbreak();
}

static DWORD WINAPI 
client_worker_thread(LPVOID parameter)
{
    UNUSED(parameter);

    for (;;)
    {
        struct work_item_t *work_item;
        SOCKET connection;
        HANDLE handles[] = { g_shutdown, g_work_available };
        DWORD wait_result;
        char *request_buffer;
        int request_length;
        int rv;
        struct http_request_t *request;

        wait_result = WaitForMultipleObjects(ARRAY_COUNT(handles), handles, FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0)
        {
            break;
        }

        work_item = (struct work_item_t *)InterlockedPopEntrySList(&g_work_list);

        if (work_item == NULL)
        {
            continue;
        }

        connection = work_item->connection;

        request_length = client_receive_request(connection, &request_buffer);
        if (request_length < 0)
        {
            client_shutdown_connection(connection);
            SetEvent(g_shutdown);

            return 1;
        }

        rv = http_parse_request(&request, request_buffer, request_length);

        if (rv != HTTP_SUCCESS)
        {
            client_send_error(connection, HTTP_STATUS_BAD_REQUEST);
        }
        else
        {
            struct http_response_t *response;
            char response_buffer[512];
            enum http_status_t status;

            status = http_dispatch_request(&response, request);
            while (http_response_copy_data(response_buffer, sizeof response_buffer, response) == HTTP_ERROR_MORE_DATA)
            {
                int send_rv;

                send_rv = send(connection, response_buffer, sizeof response_buffer, 0);

                if (send_rv == SOCKET_ERROR)
                {
                    break;
                }
            }

            http_response_free(response);
        }

        client_shutdown_connection(connection);

        free(request_buffer);
        client_reset_work_item(work_item);
        InterlockedPushEntrySList(&g_free_list, (PSLIST_ENTRY)work_item);
    }

    return 0;
}

static void
spawn_worker_threads(void)
{
    SYSTEM_INFO system_info;
    DWORD num_threads;
    const DWORD max_threads = 4;
    DWORD i;

    GetSystemInfo(&system_info);

    num_threads = MIN(system_info.dwNumberOfProcessors, max_threads);
    g_work_available = CreateSemaphore(NULL, 0, 65535, NULL);

    ENFORCE(g_work_available != NULL, "Unable to initialize semaphore: %d", GetLastError());

    g_threads = calloc(num_threads, sizeof(HANDLE));
    g_num_threads = num_threads;

    for (i = 0; i < num_threads; ++i)
    {
        g_threads[i] = CreateThread(NULL, 0, client_worker_thread, NULL, 0, NULL);
    }
}

void
client_begin(void)
{
    SOCKET incoming_socket;
    struct sockaddr_in incoming_name = { 0 };
    int rv;

    InitializeSListHead(&g_work_list);
    InitializeSListHead(&g_free_list);

    g_shutdown = CreateEvent(NULL, TRUE, FALSE, NULL);

    spawn_worker_threads();

    incoming_socket = socket(AF_INET, SOCK_STREAM, 0);
    ENFORCE(incoming_socket != INVALID_SOCKET, "Unable to create listening socket");

    incoming_name.sin_family = AF_INET;
    incoming_name.sin_addr.s_addr = INADDR_ANY;
    incoming_name.sin_port = htons(13240);

    rv = bind(incoming_socket, (struct sockaddr *)&incoming_name, sizeof incoming_name);
    ENFORCE(rv != SOCKET_ERROR, "Unable to bind listening socket to local port");

    rv = listen(incoming_socket, 16);
    ENFORCE(rv != SOCKET_ERROR, "Unable to start listening");

    for (;;)
    {
        struct sockaddr_storage connecting_name;
        int connecting_name_length = sizeof connecting_name;
        SOCKET incoming_connection;
        struct work_item_t *work_item;

        incoming_connection = accept(incoming_socket, (struct sockaddr *)&connecting_name, &connecting_name_length);

        if (incoming_socket == INVALID_SOCKET)
        {
            continue;
        }

        work_item = (struct work_item_t *)InterlockedPopEntrySList(&g_free_list);
        if (work_item == NULL)
        {
            work_item = _aligned_malloc(sizeof(struct work_item_t), MEMORY_ALLOCATION_ALIGNMENT);

            // Unable to allocate a new connection, unable to recycle an existing
            // connection structure, attempt a graceful shutdown.
            if (work_item == NULL)
            {
                client_shutdown_connection(incoming_connection);

                break;
            }
        }

        work_item->connection = incoming_connection;
        work_item->name = connecting_name;
        work_item->name_length = connecting_name_length;

        InterlockedPushEntrySList(&g_work_list, (PSLIST_ENTRY)work_item);

        // Failing to release a semaphore is an error condition, but one that we
        // can attempt a graceful shutdown from.
        rv = ReleaseSemaphore(g_work_available, 1, NULL);
        if (!rv)
        {
            DWORD last_error;

            last_error = GetLastError();
            error_log("Unable to release semaphore, error: %d", last_error);

            break;
        }

        // Check to see if any threads have aborted. If so, initiate a graceful shutdown.
        if (WaitForMultipleObjects(g_num_threads, g_threads, FALSE, 0) != WAIT_TIMEOUT)
        {
            break;
        }
    }

    closesocket(incoming_socket);
    SetEvent(g_shutdown);
    WaitForMultipleObjects(g_num_threads, g_threads, TRUE, INFINITE);
}

static enum http_status_t
overview_handler(struct http_response_t *response, struct http_request_t *request)
{
    UNUSED(response);
    UNUSED(request);

    return HTTP_STATUS_OK;
}

int
main(void)
{
    struct WSAData wsa_data;
    int rv;

    error_log_open();

    rv = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    ENFORCE(rv == NO_ERROR, "Unable to start winsock");

    client_begin();

    return 0;
}
