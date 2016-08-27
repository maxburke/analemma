#pragma once

typedef char char8_t;

struct process_key_value_pair_t
{
    const char8_t *key;
    const char8_t *value;
};

struct process_start_info_t
{
    const char8_t *program;
    const char8_t *args;
    const char8_t *working_dir;
    struct process_key_value_pair_t *environment;
    int num_environment_variables;
    int timeout_ms;
};

enum process_status_t
{
    PROCESS_STATUS_NOT_STARTED      = 0x00,
    PROCESS_STATUS_RUNNING          = 0x01,

    PROCESS_STATUS_FINISHED_BIT     = 0x10,
    PROCESS_STATUS_FAILED_TO_LAUNCH = 0x11,
    PROCESS_STATUS_KILLED           = 0x12,
    PROCESS_STATUS_TIMED_OUT        = 0x13,
    PROCESS_STATUS_EXITED           = 0x14,
};

#define process_finished(x) ((x) & PROCESS_STATUS_FINISHED_BIT)

struct process_handle_t;

struct process_handle_t *
process_start(struct process_start_info_t *start_info);

enum process_status_t
process_done(struct process_handle_t *handle, int *exit_code);

int
process_kill(struct process_handle_t *handle);

void
process_free(struct process_handle_t *handle);
