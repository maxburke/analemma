#pragma once

struct job_t
{
    struct process_start_info_t *start_info;
};
struct job_reverse_iterator_t;

void
job_init(void);

void
job_shutdown(void);

struct job_t *
job_create(struct process_start_info_t *start_info);

struct job_reverse_iterator_t *
job_r_begin(void);

struct job_reverse_iterator_t *
job_r_next(struct job_reverse_iterator_t *iterator);

struct job_t *
job_r_dereference(struct job_reverse_iterator_t *iterator);