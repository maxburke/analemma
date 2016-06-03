#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "http_server.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4710)
#pragma warning(disable:4204)
#endif

#define UNUSED(x) (void)x
#define ARRAY_COUNT(x) ((sizeof(x))/sizeof(x[0]))

struct http_response_t
{
    struct header_field_t *headers;
    char *body;
    int body_length;
};

static const char NEW_LINE[] = "\x0d\x0a";
static const char ENTRY_SEPARATOR[] = ": ";
static const char HEADER_TERMINATOR[] = "\x0d\x0a\x0d\x0a";
static const size_t NEW_LINE_LENGTH = ((sizeof NEW_LINE) - 1);
static const size_t ENTRY_SEPARATOR_LENGTH = ((sizeof ENTRY_SEPARATOR) - 1);
static const size_t HEADER_TERMINATOR_LENGTH = ((sizeof HEADER_TERMINATOR) - 1);

static int g_num_endpoints;
static struct http_endpoint_t *g_endpoints;

static int
http_parse_method(char **buf, struct http_request_t *request, char *ptr, char *end)
{
    int i;

    struct method_strings_t {
        enum http_method_t method;
        const char *string;
        int length;
    };

    struct method_strings_t methods[] = {
        { HTTP_METHOD_GET, "GET", 3 },
        { HTTP_METHOD_PUT, "PUT", 3 },
        { HTTP_METHOD_POST, "POST", 4 },
        { HTTP_METHOD_DELETE, "DELETE", 6 }
    };

    assert(buf != NULL);

    for (i = 0; i < ARRAY_COUNT(methods); ++i)
    {
        if (ptr + methods[i].length > end)
        {
            return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
        }

        if (memcmp(ptr, methods[i].string, methods[i].length) == 0)
        {
            request->method = methods[i].method;
            *buf = ptr + methods[i].length + 1;
            return HTTP_SUCCESS;
        }
    }

    return HTTP_ERROR_UNKNOWN_METHOD;
}

static int
http_parse_uri(char **buf, struct http_request_t *request, char *ptr, char *end)
{
    char *uri_end;

    assert(buf != NULL);

    uri_end = strstr(ptr, " ");
    if (uri_end >= end || uri_end == NULL)
    {
        return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
    }

    request->uri = ptr;

    *uri_end = 0;
    *buf = uri_end + 1;

    return HTTP_SUCCESS;
}

static int
http_parse_http_version(char **buf, struct http_request_t *request, char *ptr, char *end)
{
    char *line_end;

    if ((line_end = strstr(ptr, NEW_LINE)) == NULL)
    {
        return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
    }

    if (line_end >= end)
    {
        return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
    }

    *line_end = 0;
    *(line_end + 1) = 0;

    if (strcmp(ptr, "HTTP/1.1") == 0)
    {
        request->version = HTTP_VERSION_1_1;
    }
    else if (strcmp(ptr, "HTTP/1.0") == 0)
    {
        request->version = HTTP_VERSION_1_0;
    }
    else
    {
        return HTTP_ERROR_UNSUPPORTED_HTTP_VERSION;
    }

    *buf = line_end + 2;
    return HTTP_SUCCESS;
}

static int
http_count_header_fields(const char *ptr)
{
    int num_header_fields = 0;
    const char *p = ptr;

    while ((p = strstr(p, ENTRY_SEPARATOR)) != NULL)
    {
        ++num_header_fields;

        p = strstr(p, NEW_LINE);

        if (p == NULL)
        {
            return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
        }

        p += NEW_LINE_LENGTH;
    }

    return num_header_fields;
}

static int
http_parse_headers(char **buf, struct http_request_t *request, char *ptr, char *end)
{
    char *header_end;
    int num_header_fields;
    int i;
    int error;

    error = HTTP_SUCCESS;

    if ((header_end = strstr(ptr, HEADER_TERMINATOR)) == NULL)
    {
        return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
    }

    if (header_end >= end)
    {
        return HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
    }

    /*
    * The header is terminated by two Windows-style newlines.
    * Zeroing out the second set of newlines allows us to assume
    * that every header entry block follows the format of:
    *
    * KEY ':' SP VALUE NEWLINE
    *
    * while ensuring that any string functions (strstr) terminate
    * execution before they get to the potential HTTP request body.
    *
    * The first newline is zeroed out as part of the header field
    * parsing below.
    */
    header_end[2] = 0;
    header_end[3] = 0;

    num_header_fields = http_count_header_fields(ptr);

    if (num_header_fields < 0)
    {
        /*
         * http_count_header_fields returns the number of header
         * fields, but will also return an error value indicated
         * by a negative number if the request appears to be
         * malformed
         */
        return num_header_fields;
    }

    request->num_header_fields = num_header_fields;
    request->headers = calloc(num_header_fields, sizeof(struct header_field_t));

    for (i = 0; i < num_header_fields; ++i)
    {
        char *entry_separator;
        char *entry_end;
        struct header_field_t *field;

        field = request->headers + i;
        entry_separator = strstr(ptr, ENTRY_SEPARATOR);
        entry_end = strstr(ptr, NEW_LINE);

        if (entry_separator == NULL)
        {
            error = HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
            goto header_parse_failed;
        }

        if (entry_end == NULL)
        {
            error = HTTP_ERROR_INCOMPLETE_OR_MALFORMED;
            goto header_parse_failed;
        }

        memset(entry_separator, 0, ENTRY_SEPARATOR_LENGTH);
        memset(entry_end, 0, NEW_LINE_LENGTH);

        field->key = ptr;
        field->value = entry_separator + ENTRY_SEPARATOR_LENGTH;

        ptr = entry_end + NEW_LINE_LENGTH;
    }

    *buf = header_end + HEADER_TERMINATOR_LENGTH;
    return HTTP_SUCCESS;

header_parse_failed:
    if (request->headers)
    {
        free(request->headers);
    }

    return error;
}

int
http_parse_request(struct http_request_t **request_ptr, char *request_buffer, int request_length)
{
    struct http_request_t *request;
    int rv;
    char *ptr;
    char *end;

    assert(request_ptr != NULL);

    request = calloc(1, sizeof(struct http_request_t));
    ptr = request_buffer;
    end = request_buffer + request_length;

    if ((rv = http_parse_method(&ptr, request, ptr, end)) != HTTP_SUCCESS)
    {
        goto parse_request_failed;
    }

    if ((rv = http_parse_uri(&ptr, request, ptr, end)) != HTTP_SUCCESS)
    {
        goto parse_request_failed;
    }

    if ((rv = http_parse_http_version(&ptr, request, ptr, end)) != HTTP_SUCCESS)
    {
        goto parse_request_failed;
    }

    if ((rv = http_parse_headers(&ptr, request, ptr, end)) != HTTP_SUCCESS)
    {
        goto parse_request_failed;
    }

    __debugbreak();

    *request_ptr = request;

parse_request_failed:
    client_free_request(request);
    *request_ptr = NULL;
    return rv;
}

void
client_free_request(struct http_request_t *request)
{
    free(request);
}

enum http_status_t
http_dispatch_request(struct http_response_t **response_ptr, struct http_request_t *request)
{
    int i;
    const char *uri;
    enum http_method_t method;

    uri = request->uri;
    method = request->method;
    *response_ptr = NULL;

    for (i = 0; i < g_num_endpoints; ++i)
    {
        struct http_endpoint_t *endpoint = g_endpoints + i;

        if (strstr(uri, endpoint->path_prefix) == uri)
        {
            if (method & endpoint->supported_methods)
            {
                struct http_response_t *response;

                response = calloc(1, sizeof(struct http_response_t));
                *response_ptr = response;

                return endpoint->handler(response, request);
            }
        }
    }

    return HTTP_STATUS_NOT_FOUND;
}

int
http_response_copy_data(char *buf, size_t buffer_size, struct http_response_t *response)
{
    UNUSED(buf);
    UNUSED(buffer_size);
    UNUSED(response);

    return HTTP_SUCCESS;
}

void
http_response_free(struct http_response_t *response)
{
    UNUSED(response);
}

void
http_register_endpoints(struct http_endpoint_t *endpoints, int num_endpoints)
{
    g_num_endpoints = num_endpoints;
    g_endpoints = calloc(num_endpoints, sizeof(struct http_endpoint_t));
    memmove(g_endpoints, endpoints, sizeof(struct http_endpoint_t) * num_endpoints);
}

