set -x
sudo pkill greu ; make && sudo ./greu -d -i /dev/tun0 -e /dev/tap0 192.168.56.1 1234