infectbin
=========

Infectbin is a tool that allows changing the instructions in a ELF file.

You can modify a runtime process, with some caveats:  
- you must have permission. In general, the process should be yours.
- what else?

[Compile]:  
$ make

[Run]:  
$ infectbin \<file\> \<script\>	  *To patch a ELF file*   
$ infectbin -p \<pid\> \<script\>	*To patch a  runtime process*

Script is a file in the following format:

\<offset_in_hex\>   
\# assembly code

\<other_offset\>  
\# more assembly code

- Mandatory the use of '< >'.
- The code will be compiled using the GNU assembler (AS) - for this reason you can only use AT&T syntax.
- The opcodes are inserted in the specified offsets.
- Support x86 and x86_64 [require test]

Joao Guilherme aka pl4nkt0n
jg.victorino1 [at] gmail
