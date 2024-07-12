#pragma once

#include <stddef.h>
#include <sys/types.h>

size_t PTraceRead(pid_t pid, void *buf, const void *addr, size_t len);
size_t PTraceWrite(pid_t pid, void *addr, const void *buf, size_t len);
