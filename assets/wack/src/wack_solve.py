#!/usr/bin/python
from pwn import *

for line in open('data.awk').readlines():
    coord = line.strip().split(' ')
    x = int(coord[0],16)
    y = int(coord[1],16)
    z = int(coord[2],16)

    if z > 0:
        print u16(struct.pack(">H",x)),u16(struct.pack(">H",y))
