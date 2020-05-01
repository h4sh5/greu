set -x
# create device
#sudo ifconfig tun0 create

# 10.0.3.1 is where you want to send packets to
#sudo ifconfig tun0 10.0.3.2 10.0.3.1 netmask 255.255.255.0 mtu 1500 up

sudo ifconfig tun0 192.168.1.2 192.168.1.1 -arp
