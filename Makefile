# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Egor Pomozov.
#
# CDA linux driver to access pci devices
TARGET_MODULE := cdapci

BUILDDIR ?= /lib/modules/$(shell uname -r)/build

THIS_MKFILE := $(lastword $(MAKEFILE_LIST))
THIS_MKFILE_DIR := $(dir $(abspath $(THIS_MKFILE)))

ifneq ($(KERNELRELEASE),)
	obj-m := $(TARGET_MODULE).o
	$(TARGET_MODULE)-objs := cdadrv.o cdamem.o cdares.o
endif
.PHONY: all
all:
	$(MAKE) -C $(BUILDDIR) M=$(THIS_MKFILE_DIR) modules
clean:
	$(MAKE) -C $(BUILDDIR) M=$(THIS_MKFILE_DIR) clean
install:
	sudo -E $(MAKE) -C $(BUILDDIR) M=$(THIS_MKFILE_DIR) modules_install
	sudo -E depmod
uninstall:
	sudo -E modprobe -r $(TARGET_MODULE)
	sudo -E rm -f $(shell modinfo -n $(TARGET_MODULE))
	sudo -E depmod
