#ifdef _MSC_VER
#pragma warning(push, 0)
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _MSC_VER
#pragma warning(pop)
#define strdup _strdup
#define snprintf _snprintf
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
#define MIN(a,b) ((a)<(b)?(a):(b))

struct linked_header_field_t
{
    struct header_field_t header;
    struct linked_header_field_t *next;
};

struct http_response_t
{
    struct linked_header_field_t *headers;
    const char *body;
    int body_length;
    char *raw_headers;
    int raw_headers_length;
    enum http_status_t status;

    int serializing;
    struct linked_header_field_t *current_header;
    const char *body_ptr;
};

struct http_status_string_t
{
    int status;
    const char *text;
};

struct http_status_string_t g_status_strings[] = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 102, "Processing" },
    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 203, "Non Authoritative Information" },
    { 204, "No Content" },
    { 205, "Reset Content" },
    { 206, "Partial Content" },
    { 207, "Multi Status" },
    { 208, "Already Reported" },
    { 226, "Im Used" },
    { 300, "Multiple Choices" },
    { 301, "Moved Permanently" },
    { 302, "Found" },
    { 303, "See Other" },
    { 304, "Not Modified" },
    { 305, "Use Proxy" },
    { 306, "Switch Proxy" },
    { 307, "Temporary Redirect" },
    { 308, "Permanent Redirect" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },
    { 408, "Request Timeout" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 412, "Precondition Failed" },
    { 413, "Request Entity Too Large" },
    { 414, "Request Uri Too Long" },
    { 415, "Unsupported Media Type" },
    { 416, "Requested Range Not Satisfiable" },
    { 417, "Expectation Failed" },
    { 419, "Authentication Timeout" },
    { 422, "Unprocessable Entity" },
    { 423, "Locked" },
    { 424, "Failed Dependency" },
    { 426, "Upgrade Required" },
    { 428, "Precondition Required" },
    { 429, "Too Many Requests" },
    { 431, "Request Header Fields Too Large" },
    { 495, "Cert Error" },
    { 496, "No Cert" },
    { 497, "Http To Https" },
    { 498, "Token Expired" },
    { 499, "Client Closed Request" },
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Gateway Timeout" },
    { 505, "Httpversion Not Supported" },
    { 506, "Variant Also Negotiates" },
    { 507, "Insufficient Storage" },
    { 508, "Loop Detected" },
    { 510, "Not Extended" },
    { 511, "Network Authentication Required" },
};

static const char NEW_LINE[] = "\x0d\x0a";
static const char ENTRY_SEPARATOR[] = ": ";
static const char HEADER_TERMINATOR[] = "\x0d\x0a\x0d\x0a";
static const size_t NEW_LINE_LENGTH = ((sizeof NEW_LINE) - 1);
static const size_t ENTRY_SEPARATOR_LENGTH = ((sizeof ENTRY_SEPARATOR) - 1);
static const size_t HEADER_TERMINATOR_LENGTH = ((sizeof HEADER_TERMINATOR) - 1);

static int g_num_endpoints;
static struct http_endpoint_t *g_endpoints;

const char *
http_strnstr(const char *haystack, size_t haystack_length, const char *needle)
{
    size_t needle_length;
    size_t i;

    needle_length = strlen(needle);

    /*
     * Is Boyer-Moore needed for this? Probably not.
     */

    /*
     * Early out if the needle can't be contained in the haystack.
     */
    if (haystack_length < needle_length)
    {
        return NULL;
    }

    for (i = 0; i <= haystack_length - needle_length; ++i)
    {
        size_t ii;

        for (ii = 0; ii < needle_length; ++ii)
        {
            if (haystack[i + ii] != needle[ii])
                goto no_match;
        }

        return haystack + i;

    no_match:;
    }

    return NULL;
}

int
http_expecting_more(const char *buffer, size_t buffer_length)
{
    const char *terminator;
    const char *content_length;
    /*
     * Search for the header terminator first.
     */

    terminator = http_strnstr(buffer, buffer_length, HEADER_TERMINATOR);
    if (terminator == NULL)
    {
        /*
         * No header terminator? Need more data.
         */
        return 1;
    }

    /*
     * Does the request have a body? Search for a Content-Length header
     */

    content_length = http_strnstr(buffer, buffer_length, "Content-Length");
    if (content_length == NULL)
    {
        /*
         * No content length? We're done!
         */
        return 0;
    }

    /*
     * TODO: Examine content following header to see if it's all here.
     */
    __debugbreak();
    return 1;
}

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

    assert(request->headers != NULL);

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

    *request_ptr = request;

    return HTTP_SUCCESS;

parse_request_failed:
    http_request_free(request);
    *request_ptr = NULL;
    return rv;
}

void
http_request_free(struct http_request_t *request)
{
    if (!request)
        return;
    free(request->headers);
    free(request);
}

void
http_dispatch_request(struct http_response_t **response_ptr, struct http_request_t *request)
{
    int i;
    const char *uri;
    enum http_method_t method;
    struct http_response_t *response;

    uri = request->uri;
    method = request->method;
    *response_ptr = NULL;

    response = calloc(1, sizeof(struct http_response_t));
    http_response_add_header(response, "Connection", "close");
    http_response_add_header(response, "Content-Type", "text/html");
    http_response_set_status(response, HTTP_STATUS_OK);

    *response_ptr = response;

    for (i = 0; i < g_num_endpoints; ++i)
    {
        struct http_endpoint_t *endpoint = g_endpoints + i;

        if (strstr(uri, endpoint->path_prefix) == uri)
        {
            if (method & endpoint->supported_methods)
            {
                endpoint->handler(response, request);

                return;
            }
        }
    }

    http_response_set_status(response, HTTP_STATUS_NOT_FOUND);
}

int
http_response_add_header(struct http_response_t *response, const char *key, const char *value)
{
    struct linked_header_field_t *header;

    if (response->serializing)
    {
        return HTTP_ERROR_ALREADY_SERIALIZING;
    }

    for (header = response->headers; header != NULL; header = header->next)
    {
        if (strcmp(header->header.key, key) != 0)
        {
            continue;
        }

        /*
         * If a header key exists in the current response the behavior is to
         * replace it with a new value but return a warning that this action
         * has taken place.
         */
        free((char *)header->header.value);
        header->header.value = strdup(value);

        return HTTP_WARNING_HEADER_ALREADY_SET;
    }

    header = calloc(1, sizeof(struct header_field_t));
    assert(header != NULL);

    header->header.key = strdup(key);
    header->header.value = strdup(value);
    header->next = response->headers;
    response->headers = header;

    return HTTP_SUCCESS;
}

int
http_response_set_body(struct http_response_t *response, const void **previous_body, const void *body, int body_length)
{
    int rv;
    char content_length_string[11];

    if (response->serializing)
    {
        return HTTP_ERROR_ALREADY_SERIALIZING;
    }

    /*
     * Because replacing the response body with a different one may lead to a
     * resource leak, this function will return a warning indicating that this
     * happened.
     */
    if (response->body)
    {
        if (previous_body)
        {
            *previous_body = response->body;
        }

        rv = HTTP_WARNING_BODY_ALREADY_SET;
    }
    else
    {
        rv = HTTP_SUCCESS;
    }

    response->body = body;
    response->body_length = body_length;

    snprintf(content_length_string, sizeof content_length_string, "%d", body_length);
    http_response_add_header(response, "Content-Length", content_length_string);

    return rv;
}

int
http_response_set_status(struct http_response_t *response, enum http_status_t status)
{
    if (response->serializing)
    {
        return HTTP_ERROR_ALREADY_SERIALIZING;
    }

    response->status = status;
    
    return HTTP_SUCCESS;
}

static int
status_comparer(const void *p1, const void *p2)
{
    const struct http_status_string_t *s1 = p1;
    const struct http_status_string_t *s2 = p2;
    
    return s1->status - s2->status;
}

int
http_response_serialize_data(char *buf, size_t buffer_size, size_t *bytes_serialized, struct http_response_t *response)
{
    char *ptr;
    size_t bytes_remaining;
    const char *end;
    size_t bytes_to_copy;

    *bytes_serialized = 0;

    if (!response->serializing)
    {
        struct http_status_string_t key;
        struct http_status_string_t *result;
        size_t rv;

        key.status = response->status;
        result = bsearch(&key, g_status_strings, ARRAY_COUNT(g_status_strings), sizeof(struct http_status_string_t), status_comparer);

        rv = snprintf(buf, buffer_size, "HTTP/1.1 %d %s%s", result->status, result->text, NEW_LINE);
        if (rv >= buffer_size)
        {
            return HTTP_ERROR_INSUFFICIENT_BUFFER_SIZE;
        }

        *bytes_serialized = rv;
        ptr = buf + rv;
        bytes_remaining = buffer_size - rv;

        response->serializing = 1;
        response->current_header = response->headers;
    }
    else
    {
        ptr = buf;
        bytes_remaining = buffer_size;
    }

    /*
     * Serialize headers
     */
    while (response->current_header != NULL)
    {
        size_t header_length;
        size_t rv;

        header_length = strlen(response->current_header->header.key)
            + ENTRY_SEPARATOR_LENGTH
            + strlen(response->current_header->header.value)
            + NEW_LINE_LENGTH;

        if (header_length > bytes_remaining)
        {
            if (*bytes_serialized == 0)
            {
                return HTTP_ERROR_INSUFFICIENT_BUFFER_SIZE;
            }

            return HTTP_MORE_DATA;
        }

        rv = snprintf(
            ptr,
            bytes_remaining,
            "%s%s%s%s",
            response->current_header->header.key,
            ENTRY_SEPARATOR,
            response->current_header->header.value,
            NEW_LINE);

        assert(rv == header_length);

        ptr += rv;
        *bytes_serialized += rv;
        bytes_remaining -= rv;

        response->current_header = response->current_header->next;
    }

    /*
     * A second newline is required after the headers and before the body.
     */
    if (response->body_ptr == NULL)
    {
        size_t rv;

        if (bytes_remaining < NEW_LINE_LENGTH)
        {
            if (*bytes_serialized == 0)
            {
                return HTTP_ERROR_INSUFFICIENT_BUFFER_SIZE;
            }

            return HTTP_MORE_DATA;
        }

        rv = snprintf(ptr, bytes_remaining, "%s", NEW_LINE);
        assert(rv == 2);

        ptr += rv;
        bytes_remaining -= rv;
        *bytes_serialized += NEW_LINE_LENGTH;

        response->body_ptr = response->body;
    }

    /*
     * Serialize body
     */

    end = response->body + response->body_length;
    assert(end >= response->body_ptr);
    bytes_to_copy = MIN(bytes_remaining, (size_t)(end - response->body_ptr));
    memmove(ptr, response->body_ptr, bytes_to_copy);
    response->body_ptr += bytes_to_copy;
    *bytes_serialized += bytes_to_copy;

    if (response->body_ptr != end)
    {
        if (*bytes_serialized == 0)
        {
            return HTTP_ERROR_INSUFFICIENT_BUFFER_SIZE;
        }

        return HTTP_MORE_DATA;
    }

    return HTTP_SUCCESS;
}

void
http_response_free(struct http_response_t *response)
{
    free(response);
}

void
http_register_endpoints(struct http_endpoint_t *endpoints, int num_endpoints)
{
    g_num_endpoints = num_endpoints;
    g_endpoints = calloc(num_endpoints, sizeof(struct http_endpoint_t));
    memmove(g_endpoints, endpoints, sizeof(struct http_endpoint_t) * num_endpoints);
}
