---
title: "Test"
date: 2022-10-23T15:44:19-07:00
draft: false
categories: ["CTF"]
tags: ["css"]
---

### My first post

Here I am testing a post

Here I am testing a postHere I am testing a postHere I am testing a postHere I am testing a postHere I am testing a postHere I am testing a postHere I am testing a postHere I am testing a postHere I am testing a postHere I am testing a post
Here I am testing a post

Here I am testing a postHere I am testing a post

Here I am testing a post

```python
import time
import ipinfo
from pwn import *
from geopy.geocoders import Nominatim

# init ipinfo
at = 'INSERT ACCESS TOKEN'
h = ipinfo.getHandler(at)

# init geo locator
geolocator = Nominatim(user_agent="geoapiExercises")

r = remote('137.184.215.151', 22606)
r.recvuntil(b'wrong.\n')
log.info('Solving...')
for i in range(50):
    time.sleep(0.2)
    q = r.clean()
    if b'IP' in q:
        ip = q.split(b'IP: ')[-1].split(b'\n')[0].decode('latin')
        d = h.getDetails(ip)
        r.sendline(d.city.encode())
    else:
        coor = q.split(b'lon): ')[-1].split(b'\n')[0].decode('latin')
        location = geolocator.reverse(coor)
        try:
            city = location.raw['address']['city']
        except:
            city = 'failed'
        r.sendline(city.encode())
r.interactive()
```