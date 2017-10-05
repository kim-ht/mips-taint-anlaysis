/* base.h
 * by kimht
 */
#ifndef _BASE_BASE_H_
#define _BASE_BASE_H_

#define _GNU_SOURCE

////////////////////////////////////////////////////////////////////////////////
/// includes
////////////////////////////////////////////////////////////////////////////////
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>

/*
 * HANDLE_ERROR - Handles error. perror() and return a value.
 */
#define HANDLE_ERROR(msg, ret_val) {  \
    perror(msg);  \
    return ret_val;  \
}

#endif

