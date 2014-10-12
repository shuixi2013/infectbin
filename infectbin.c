/*
* 	infectbin.c  
* 
* 	Joao Guilherme Victorino aka pl4nkt0n
* 	jgvictorino1 [at] gmail
* 
* 	This program is free software: you can redistribute it and/or modify
* 	it under the terms of the GNU General Public License as published by
* 	the Free Software Foundation, either version 3 of the License, or
* 	(at your option) any later version.
* 
* 	This program is distributed in the hope that it will be useful,
* 	but WITHOUT ANY WARRANTY; without even the implied warranty of
* 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* 	GNU General Public License for more details.
* 
* 	You should have received a copy of the GNU General Public License
* 	along with this program. If not, see <http://www.gnu.org/licenses/>.
* 
*/
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <elf.h>
#include <link.h>
#include <errno.h>
#include "easyptrace.h"
#include "list.h"

//default apps
#define ASSEMBLER	"/usr/bin/as"
#define OBJCOPY		"/usr/bin/objcopy"

//default flags
#define AS_FLAGS	"-o"
#define OBJ_FLAGS	"--output-target=binary"

#define MAX_OFFSET	0xffffffffffffffff
#define MAX_OFFNAME	18
#define OFFBASE		16

#define ASSUFIX		".s"
#define OBJSUFIX	".o"

/* Global list of bin files */
static List *binfiles = NULL;


#define open_error(f){				\
	char __err[64];				\
	sprintf(__err, "open : %s", f);		\
	perror(__err);				\
	exit_error();				\
}

#define exit_error(){				\
	ListElmt *e;				\
		foreach(binfiles, e)		\
		      unlink(e->data);		\
						\
	exit(EXIT_FAILURE);			\
}

#define __malloc(var, size){				\
	if((var = malloc(size)) == NULL){		\
		fprintf(stderr, "malloc failed :/\n");	\
		exit_error();				\
	}						\
}

	  
	  
static void __assemble(char *input, char *output){
	int status;
	
	if(fork() == 0){
		char *argv[] = {ASSEMBLER, input, AS_FLAGS, output, NULL};
		execv(ASSEMBLER, argv);

		fprintf(stderr, "execv has failed :/\n");
		exit(EXIT_FAILURE);
	}
	wait(&status);
	if(status){
		 unlink(input);
		 exit_error();
	}
}

static void __copy_text(char *input, char *output){
	int status;
  
	if(fork() == 0){
		char *argv[] = {OBJCOPY, OBJ_FLAGS, input, output, NULL};
		execv(OBJCOPY, argv);

		fprintf(stderr, "execv has failed :/\n");
		exit(EXIT_FAILURE);
	}

	wait(&status);
	if(status){
		unlink(input);
		exit_error();
	}
}

static void __make_binfile(int fd_input){
	int fdasfile, i = 0;
	char c, offname[MAX_OFFNAME], asname[MAX_OFFNAME + sizeof(ASSUFIX)], objname[MAX_OFFNAME + sizeof(OBJSUFIX)], *binname;

	
	//drop '0' e 'x'
 	for(c = '0'; c == '0' || c == 'x' || c == 'X'; read(fd_input, &c, 1))
	;
	
	bzero(offname, MAX_OFFNAME);
	bzero(asname, sizeof(asname));
	bzero(objname, sizeof(objname));

	do{
		if(i == MAX_OFFNAME){
			fprintf(stderr, "error: offset %s... to long\n", offname);
			_exit(EXIT_FAILURE);
		}
		  
		offname[i] = c;
		i++;
		read(fd_input, &c, 1);
		
	}while(c != '>');

	strncpy(asname, offname, strlen(offname));
	strcat(asname, ASSUFIX);
	strncpy(objname, offname, strlen(offname));
	strcat(objname, OBJSUFIX);
	
	__malloc(binname, strlen(offname));
	strncpy(binname, offname, strlen(offname));
		
	if((fdasfile = open(asname, O_RDWR | O_CREAT | O_TRUNC, 0666)) < 0)
		open_error(offname);

	while(read(fd_input, &c, 1) > 0){
		if(c == '<'){
			__make_binfile(fd_input);
			break;
		}
		
		write(fdasfile, &c, 1);
	}

	close(fdasfile);

	__assemble(asname, objname);
	unlink(asname);
	__copy_text(objname, binname);
	unlink(objname);

	list_ins(binfiles, binname);
}

void parse_offset(const char *inputfile){
	int fd_input;
	char c;

	if((fd_input = open(inputfile, O_RDONLY)) < 0)
		open_error(inputfile);

	while(read(fd_input, &c, 1) > 0)
		if(c == '<')
			__make_binfile(fd_input);
	close(fd_input);
}


void infect_pid(pid_t pid){
	int fd_bin;
	unsigned long *off = NULL, word, opcode, n;
	ListElmt *e;

	printf("[*] Attach to process [%d]\n", pid);
	ptrace_attach(pid);

	printf("[*] Inserting instructions... ");
	foreach(binfiles, e){
		if((fd_bin = open(e->data, O_RDONLY)) < 0)
			open_error(e->data);

		errno = 0;
		off = (unsigned long *) strtoul(e->data, NULL, OFFBASE);
		if(errno){
			fprintf(stderr, "strtoul has failed :/\n");
			exit_error();
		}

		while((n = read(fd_bin, (char *) &opcode, sizeof(long))) > 0){
			word = ptrace_peektext(pid, off);
			for( ; n > 0; n--)
				((char *) &word)[n-1] = ((char *) &opcode)[n-1];

			ptrace_poketext(pid, off, (void *)word);
			off++;
		}

		close(fd_bin);
	}
	
	puts(" DONE");
	puts("[*] Detach process");
	ptrace_detach(pid);
}


void infect_bin(const char *pathname){
	#define EHDR_SIZE	sizeof(ElfW(Ehdr))
	#define SHDR_SIZE	sizeof(ElfW(Shdr))
	
	int fd_target, fd_bin, i;
	unsigned long off;
	unsigned char opcode;
	ListElmt *e;

	char ebuf[EHDR_SIZE];
	char sbuf[SHDR_SIZE];
	
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) ebuf;
	ElfW(Shdr) *shdr = (ElfW(Shdr) *) sbuf;

	printf("[*] Open %s to path\n", pathname);
	if((fd_target = open(pathname, O_RDWR)) < 0)
		open_error(pathname);

	
	printf("[*] Inserting instructions... ");
	foreach(binfiles, e){
		lseek(fd_target, 0, SEEK_SET);
		bzero(ebuf, sizeof(ebuf));
		bzero(sbuf, sizeof(sbuf));

		if((fd_bin = open(e->data, O_RDONLY)) < 0)
			open_error(e->data);

		errno = 0;
		off = strtoul(e->data, NULL, OFFBASE);
		if(errno){
			fprintf(stderr, "strtoul has failed :/\n");
			exit_error();
		}
		
		read(fd_target, ebuf, EHDR_SIZE);
		if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
			fprintf(stderr, "File %s is not ELF\n", pathname);
			exit_error();
		}
		
		lseek(fd_target, ehdr->e_shoff + SHDR_SIZE, SEEK_SET);

		for(i = ehdr->e_shnum; i > 0; i--){
			read(fd_target, sbuf, SHDR_SIZE);

			if(shdr->sh_addr > off){
				lseek(fd_target, -(SHDR_SIZE * 2), SEEK_CUR);
				read(fd_target, sbuf, SHDR_SIZE);
				break;
			}

			if(shdr->sh_addr == off)
				break;
		}

		lseek(fd_target, shdr->sh_offset + (off - shdr->sh_addr), SEEK_SET);

		while(read(fd_bin, &opcode, 1) > 0)
			write(fd_target, &opcode, 1);

		close(fd_bin);
	}
	
	puts(" DONE");
	close(fd_target);
}

void usage(){
	puts("Usage:");
	puts("infectbin [file | -p <pid>] <script>\n");
	exit(EXIT_SUCCESS);
}



int main(int argc, char *argv[]){
	__malloc(binfiles, sizeof(List));
	list_init(binfiles, free);

	if(argc < 3)
		usage();
	  
	printf("[*] Assemble instructions... ");
	parse_offset(argv[argc - 1]);
	puts(" DONE");
	
	if(!strcmp(argv[1], "-p"))
		infect_pid(atoi(argv[2]));
	
	else
		infect_bin(argv[1]);

	
	ListElmt *e;
	foreach(binfiles, e)
		unlink(e->data);
	
	list_destroy(binfiles);
	free(binfiles);

	return 0;
}
