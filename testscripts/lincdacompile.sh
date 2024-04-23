#Would be run on a new vm instance everytime. So no need to clean up

[ $# != 2 ] && echo "$0 <kernel_version> <drvr_path>" && exit
kernel_ver=$1
drvr_path=$2
majno=${kernel_ver%%.*}
ws=$(pwd)
install -d ${ws}/download ${ws}/src ${ws}/output
cd ${ws}/src
install -d ${ws}/kbuild/amd64 ${ws}/kbuild/arm64
rm -rf ${ws}/kbuild/{arm64,amd64}
function download_and_extract() {
	[ -d ${ws}/src/linux-${kernel_ver} ] && return
	cd ${ws}/download
	curl -L https://cdn.kernel.org/pub/linux/kernel/v${majno}.x/linux-${kernel_ver}.tar.xz --output linux-${kernel_ver}.tar.xz
	rv=$?
	[ $rv != 0 ] && return 1
	cd ${ws}/src
	echo "extracting kernel sources"
	tar -xvf ${ws}/download/linux-${kernel_ver}.tar.xz 2>/dev/null 1>/dev/null
	[ $rv != 0 ] && return 1
	echo "extracting kernel done"
	return 0
}

function configure() {
	cd ${ws}/src/linux-${kernel_ver}
	echo "configuring  linux-${kernel_ver}"
	if [ $1 == "amd64" ];then
		[ -f ${ws}/kbuild/amd64/.config ] && return 0
		make ARCH=x86 O=${ws}/kbuild/amd64 x86_64_defconfig 
		[ $rv != 0 ] && echo "error configuring kernel" && return $rv
	elif [ $1 == "arm64" ]; then
		[ -f ${ws}/kbuild/amd64/.config ] && return 0
		make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=${ws}/kbuild/arm64 defconfig
		[ $rv != 0 ] && echo "error configuring kernel" && return $rv
	fi
	echo "configuration linux-${kernel_ver} done"
	return 0
}

function build() {
	return 0
	echo "Building  linux-${kernel_ver} for $1"
	if [ $1 == "amd64" ]; then
		cd ${ws}/kbuild/amd64
		make ARCH=x86 -j 4 
	elif [ $1 == "arm64" ];then
		cd ${ws}/kbuild/arm64
		make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-  -j 4
	fi
	[ ! -f vmlinux ] && return 1
	echo "Building  linux-${kernel_ver} done"
	return 0
}

function build_cdapci() {
	echo "${ws} --> ${drvr_path}"
	ls -l ${ws}
	ls -l ${drvr_path}
	return 0
	cp ${ws}/lincda.mk ${drvr_path}
	cd ${drvr_path}
	make -f lincda.mk clean
	if [ $1 == "amd64" ]; then
		make -f lincda.mk KERNEL_SRC=${ws}/kbuild/amd64 all
		[ ! -f cdapci.ko ] && echo "error compiling lincdadrv " && return 1
		cp cdapci.ko ${ws}/output/cdapci_amd64.ko
		return 0
	elif [ $1 == "arm64" ]; then
		CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64 make -f lincda.mk KERNEL_SRC=${ws}/kbuild/arm64 all
		cp cdapci.ko ${ws}/output/cdapci_arm64.ko
		[ ! -f cdapci.ko ] && echo "error compiling lincdadrv " && return 1
		return 0
	fi
	return 1
}

download_and_extract
rv=$?
[ $rv != 0 ] && echo "error downloading/extracting kernel src" && exit
#compile and build for arm
configure arm64
rv=$?
[ $rv != 0 ] && echo "error configuring kernel" && exit
build arm64
rv=$?
[ $rv != 0 ] && echo "error building  kernel" && exit
build_cdapci arm64
rv=$?
[ $rv != 0 ] && echo "error building  cdapci kernel module " && exit
echo "cdapci driver compiled successfully. output placed in ${ws}/output with appended architecture"

#compile and build for amd64
configure amd64
rv=$?
[ $rv != 0 ] && echo "error configuring kernel" && exit
build amd64
rv=$?
[ $rv != 0 ] && echo "error building  kernel" && exit
build_cdapci amd64
rv=$?
[ $rv != 0 ] && echo "error building  cdapci kernel module " && exit
echo "cdapci driver compiled successfully. output placed in ${ws}/output with appended architecture"
exit
