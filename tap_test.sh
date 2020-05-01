set -x
# create device
sudo ifconfig tap0 create
#sudo ifconfig tap0 10.0.4.1/24 mtu 1500 up
sudo ifconfig tap0 mtu 1500 up
