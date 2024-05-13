#!/usr/bin/bash
kernel_ver=$1
majno=${kernel_ver%%.*}
minno=${kernel_ver#*.}
minno=${minno%%.*}

if [ "x$majno" == "x6" ]; then
	sudo apt-get install -y build-essential libncurses-dev\
		bison flex libssl-dev libelf-dev gcc-aarch64-linux-gnu
	sudo apt update
	exit
fi

if [ "x$majno" == "x5" ] && [ $minno -gt 5 ]; then
	sudo apt-get install -y build-essential libncurses-dev\
		bison flex libssl-dev libelf-dev gcc-aarch64-linux-gnu
	sudo apt update
	exit
fi
echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu focal main universe" | sudo tee -a /etc/apt/sources.list
sudo apt update
sudo apt-get install gcc-8 g++-8 gcc-8-aarch64-linux-gnu libelf-dev
sudo update-alternatives --install /usr/bin/aarch64-linux-gnu-gcc aarch64-linux-gnu-gcc /usr/bin/aarch64-linux-gnu-gcc-8 10
