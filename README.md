infectbin
=========
Infectbin is a tool for changing a binary ELF quickly and easily. Just make a file with the proposed changes (with assembly language) and the offsets where they will be applied. This tool will assemble the code and insert it at the desired locations.

Compiling Options
-----------------
make  
make clean

Usage
-----
infectbin \<elf_file\> \<input_file\>   
infectbin -p \<pid\>   \<input_file\>

This is how input_file looks like (see samples for more details):

\<offset_in_hex\>   
assembly code

\<offset_in_hex\>  
assembly code

Note
----
- Use AT&T syntax
- You can't modify a process that isn't yours
