#include "easyptrace.h"
#include <stdlib.h>

void ptrace_attach(pid_t pid){
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0){
		perror("ptrace_attach");
		exit(EXIT_FAILURE);
	}
}

void ptrace_detach(pid_t pid){
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0){
		perror("ptrace_detach");
		exit(EXIT_FAILURE);
	}
}

void ptrace_poketext(pid_t pid, void *addr, void *data){
	if(ptrace(PTRACE_POKETEXT, pid, addr, data) < 0){
		perror("ptrace_poketext");
		exit(EXIT_FAILURE);
	}
}

long ptrace_peektext(pid_t pid, void *addr){
	return ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
}
