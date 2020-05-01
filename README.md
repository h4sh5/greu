# greu

GRE Tunnel over UDP

To compile:

```
./configure
make
```

This program can act both as a server and as a client, and can establish ETH (tap) or IP (tun) links between *nix machines. 
It doesn't work on OSX or Windows, due to the way it interacts with network drivers (tuntap).

It can create a VPN-like environment (without the "P") because there is no encryption. It's like a basic implementation of RFC 8086 (https://tools.ietf.org/html/rfc8086)

