#ifndef EASYPTRACE_H
#define EASYPTRACE_H

#include <sys/ptrace.h>
#include <sys/types.h>

/* only necessary functions ... :p */

void ptrace_attach(pid_t pid);
void ptrace_detach(pid_t pid);
long ptrace_peektext(pid_t pid, void *addr);
void ptrace_poketext(pid_t pid, void *addr, void *data);


#endif
