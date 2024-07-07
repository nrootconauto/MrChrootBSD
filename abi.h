#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

void ABISetReturn(pid_t pid, int64_t r, bool failed);
int64_t ABIGetReturn(pid_t pid, bool *failed);
int64_t ABIGetArg(pid_t pid, int64_t arg);
void ABISetArg(pid_t pid, int64_t arg, uint64_t val);
void ABISetSyscall(pid_t pid, int64_t num);
