# greu

GRE Tunnel over UDP

Prerequisites for linux:

`apt install libevent-dev make -y`

To compile:

```
./configure
make
```

This program can act both as a server and as a client, and can establish ETH (tap) or IP (tun) links between unix machines. 
It doesn't work on OSX or Windows, due to the way it interacts with network drivers (tuntap).

It can create a VPN-like environment. It's like a basic implementation of RFC 8086 (https://tools.ietf.org/html/rfc8086)

## Usage

### Linux usage

Server mode with TAP (the generated encryption key will be printed to terminal):

```
sudo ./greu -e tap0 -l 0.0.0.0
```

Client mode with TAP:

```
./greu -e tap0 -K <encryption key> server_ip
```




