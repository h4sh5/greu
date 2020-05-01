set -x
# all you need to do is call it with the interface name; it will be created.
echo ./greu -d -e tap0 server port
sudo ifconfig tap0 up
sudo ifconfig tap0 inet 10.5.5.1 netmask 255.255.255.224
