#pragma once

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4820)
#pragma warning(disable:4710)
#pragma warning(disable:4204)
#endif

enum http_status_t
{
    /*
    * Informational
    */
    HTTP_STATUS_CONTINUE = 100,
    HTTP_STATUS_SWITCHING_PROTOCOLS = 101,
    HTTP_STATUS_PROCESSING = 102,

    /*
    * Success
    */
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_ACCEPTED = 202,
    HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
    HTTP_STATUS_NO_CONTENT = 204,
    HTTP_STATUS_RESET_CONTENT = 205,
    HTTP_STATUS_PARTIAL_CONTENT = 206,
    HTTP_STATUS_MULTI_STATUS = 207,
    HTTP_STATUS_ALREADY_REPORTED = 208,
    HTTP_STATUS_IM_USED = 226,

    /*
    * 3xx errors are for redirecting users to other resources.
    */
    HTTP_STATUS_MULTIPLE_CHOICES = 300,
    HTTP_STATUS_MOVED_PERMANENTLY = 301,
    HTTP_STATUS_FOUND = 302,
    HTTP_STATUS_SEE_OTHER = 303,
    HTTP_STATUS_NOT_MODIFIED = 304,
    HTTP_STATUS_USE_PROXY = 305,
    HTTP_STATUS_SWITCH_PROXY = 306,
    HTTP_STATUS_TEMPORARY_REDIRECT = 307,
    HTTP_STATUS_PERMANENT_REDIRECT = 308,

    /*
    * 4xx series codes are for errors in the user request.
    */
    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_UNAUTHORIZED = 401,
    HTTP_STATUS_PAYMENT_REQUIRED = 402,
    HTTP_STATUS_FORBIDDEN = 403,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED = 405,
    HTTP_STATUS_NOT_ACCEPTABLE = 406,
    HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_STATUS_REQUEST_TIMEOUT = 408,
    HTTP_STATUS_CONFLICT = 409,
    HTTP_STATUS_GONE = 410,
    HTTP_STATUS_LENGTH_REQUIRED = 411,
    HTTP_STATUS_PRECONDITION_FAILED = 412,
    HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
    HTTP_STATUS_REQUEST_URI_TOO_LONG = 414,
    HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
    HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
    HTTP_STATUS_EXPECTATION_FAILED = 417,
    HTTP_STATUS_AUTHENTICATION_TIMEOUT = 419,
    HTTP_STATUS_UNPROCESSABLE_ENTITY = 422,
    HTTP_STATUS_LOCKED = 423,
    HTTP_STATUS_FAILED_DEPENDENCY = 424,
    HTTP_STATUS_UPGRADE_REQUIRED = 426,
    HTTP_STATUS_PRECONDITION_REQUIRED = 428,
    HTTP_STATUS_TOO_MANY_REQUESTS = 429,
    HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    HTTP_STATUS_CERT_ERROR = 495,
    HTTP_STATUS_NO_CERT = 496,
    HTTP_STATUS_HTTP_TO_HTTPS = 497,
    HTTP_STATUS_TOKEN_EXPIRED = 498,
    HTTP_STATUS_CLIENT_CLOSED_REQUEST = 499,

    /*
    * 5xx series codes are server faults.
    */
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_NOT_IMPLEMENTED = 501,
    HTTP_STATUS_BAD_GATEWAY = 502,
    HTTP_STATUS_SERVICE_UNAVAILABLE = 503,
    HTTP_STATUS_GATEWAY_TIMEOUT = 504,
    HTTP_STATUS_HTTPVERSION_NOT_SUPPORTED = 505,
    HTTP_STATUS_VARIANT_ALSO_NEGOTIATES = 506,
    HTTP_STATUS_INSUFFICIENT_STORAGE = 507,
    HTTP_STATUS_LOOP_DETECTED = 508,
    HTTP_STATUS_NOT_EXTENDED = 510,
    HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511
};

enum http_method_t
{
    HTTP_METHOD_GET = 1 << 0,
    HTTP_METHOD_PUT = 1 << 1,
    HTTP_METHOD_POST = 1 << 2,
    HTTP_METHOD_DELETE = 1 << 3
};

enum http_version_t
{
    HTTP_VERSION_1_0,
    HTTP_VERSION_1_1
};

struct header_field_t
{
    const char *key;
    const char *value;
};

struct http_request_t
{
    enum http_method_t method;
    const char *uri;
    enum http_version_t version;
    int num_header_fields;
    struct header_field_t *headers;
};

struct http_response_t;

typedef void (*http_handler_t)(struct http_response_t *response, const struct http_request_t *request);

struct http_endpoint_t
{
    const char *path_prefix;
    int supported_methods;
    http_handler_t handler;
};

enum http_error_t
{
    HTTP_SUCCESS = 0,

    HTTP_ERROR_UNKNOWN_METHOD = -1,
    HTTP_ERROR_INCOMPLETE_OR_MALFORMED = -2,
    HTTP_ERROR_UNSUPPORTED_HTTP_VERSION = -3,
    HTTP_ERROR_ALREADY_SERIALIZING = -4,
    HTTP_ERROR_INSUFFICIENT_BUFFER_SIZE = -5,

    HTTP_WARNING_BODY_ALREADY_SET = -6,
    HTTP_WARNING_HEADER_ALREADY_SET = -7,

    HTTP_MORE_DATA = -8
};

int
http_expecting_more(const char *buffer, size_t buffer_length);

/*
 * Returns one of http_error_t enumerated values
 */
int
http_parse_request(struct http_request_t **request_ptr, char *request_buffer, int request_length);

void
http_request_free(struct http_request_t *request);

void
http_dispatch_request(struct http_response_t **response, struct http_request_t *request);

void
http_register_endpoints(struct http_endpoint_t *endpoints, int num_endpoints);

int
http_response_add_header(struct http_response_t *response, const char *key, const char *value);

int
http_response_set_body(struct http_response_t *response, const void **previous_body, const void *body, int body_length);

int
http_response_set_status(struct http_response_t *response, enum http_status_t status);

int
http_response_serialize_data(char *buf, size_t buffer_size, size_t *bytes_serialized, struct http_response_t *response);

void
http_response_free(struct http_response_t *response);

#ifdef _MSC_VER
#pragma warning(pop)
#endif
