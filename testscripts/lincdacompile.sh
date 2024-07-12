#!/usr/bin/bash

#Would be run on a new vm instance everytime. So no need to clean up

[ $# != 2 ] && echo "$0 <kernel_version> <drvr_path>" && exit
kernel_ver=$1
drvr_path=$2
majno=${kernel_ver%%.*}
minno=${kernel_ver#*.}
minno=${minno%%.*}
ws=$(pwd)
install -d ${ws}/download ${ws}/src ${ws}/output
cd ${ws}/src
rm -rf ${ws}/kbuild/{arm64,amd64}
install -d ${ws}/kbuild/amd64 ${ws}/kbuild/arm64

#binutils updated to the latest which need elfpatch
#yyalloc multiple declaration ( dtc patch to change the lex file)
#yyalloc multiple declaration ( dtc patch to change the lex.shipped file)

# ver 6.x no patchfiles needed
# ver 5.6 thru 5.19 (elf patch due to binutils upgrade)
# ver 4.17 thru 5.5 (elf patch + dtc_1 + cf_protection )
# ver 4.9 thru 4.16 ( elf + dtc_2 )

function getpatchfiles() {
	maj=$1
	min=$2
	if [ ${maj} == 6 ]; then
		echo ""
		return
	fi
	if [ ${maj} == 5 ]; then
	       if  [ ${min} -gt 5 ]; then
		echo "elf.patch"
		else 
			echo "dtc_1.patch elf.patch cf_protection.patch"
		fi
		return
	fi
	if [ ${maj} == 4 ]; then
		if [ ${min} -eq 12 ] || [ ${min} -eq 13 ]; then
			echo -ne " secclass_12.patch"
		fi
		if [ ${min} -gt 13 ]; then
			echo -ne " secclass.patch"
		fi
		if [ ${min} -gt 16 ]; then
			echo -ne " dtc_1.patch elf.patch"
		else
			echo -ne " dtc_2.patch elf.patch log2_gcc7.patch"
		fi
		if [ ${min} -gt 18 ]; then
			echo -ne " cf_protection.patch"
		fi
		echo " "
	fi
}

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
	cd ${ws}/src/linux-${kernel_ver}
	patchfiles=$(getpatchfiles $majno $minno)
	for i in ${patchfiles}; do
		echo "Patching kernel with $i"
		patch -p1 < ${ws}/$i
	done
	return 0
}

function configure() {
	cd ${ws}/src/linux-${kernel_ver}
	echo "configuring  linux-${kernel_ver}"
	if [ $1 == "amd64" ];then
		[ -f ${ws}/kbuild/amd64/.config ] && return 0
		make ARCH=x86 O=${ws}/kbuild/amd64 x86_64_defconfig 
		rv=$?
		[ $rv != 0 ] && echo "error configuring kernel" && return $rv
	elif [ $1 == "arm64" ]; then #arm is called first the src is shared so we patch it one time
		[ -f ${ws}/kbuild/arm64/.config ] && return 0
		make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=${ws}/kbuild/arm64 defconfig
		rv=$?
		[ $rv != 0 ] && echo "error configuring kernel" && return $rv
	fi
	echo "configuration linux-${kernel_ver} done"
	return 0
}

function build() {
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
		[ ! -f cdapci.ko ] && echo "error compiling lincdadrv " && return 1
		cp cdapci.ko ${ws}/output/cdapci_arm64.ko
		return 0
	fi
	return 1
}

download_and_extract
rv=$?
[ $rv != 0 ] && echo "error downloading/extracting kernel src" && exit -1

#compile and build for amd64
configure amd64
rv=$?
[ $rv != 0 ] && echo "error configuring kernel" && exit -1
build amd64
rv=$?
[ $rv != 0 ] && echo "error building  kernel" && exit -1
build_cdapci amd64
rv=$?
[ $rv != 0 ] && echo "error building  cdapci kernel module " && exit -1
echo "cdapci driver compiled successfully for amd64 architecure . output placed in ${ws}/output"

#compile and build for arm
configure arm64
rv=$?
[ $rv != 0 ] && echo "error configuring kernel" && exit -1
build arm64
rv=$?
[ $rv != 0 ] && echo "error building  kernel" && exit -1
build_cdapci arm64
rv=$?
[ $rv != 0 ] && echo "error building  cdapci kernel module " && exit -1
echo "cdapci driver compiled successfully for arm64 architecure . output placed in ${ws}/output"
exit 
