# orca linux driver
This driver is indended to be used with Degirum ORCA boards
## Compilation/ Installation via DKMS
The driver is compilable using DKMS
``bash
sudo apt-get install -y curl dkms mokutil
make dkms
``
## Compilation/Installing from source

Install linux-headers for the running kernel
``bash
sudo apt-get install -y "linux-headers-$(uname -r)"
make all
``
