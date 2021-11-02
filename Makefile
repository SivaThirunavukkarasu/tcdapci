# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 DeGirum Corp., Egor Pomozov.
#
# CDA linux driver mem blocks/mem maps and interrupt request handler
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
TARGET_MODULE := cdapci

BUILDDIR ?= /lib/modules/$(shell uname -r)/build

THIS_MKFILE := $(lastword $(MAKEFILE_LIST))
THIS_MKFILE_DIR := $(dir $(abspath $(THIS_MKFILE)))

IS_SYSTEMD_USED=$(shell pidof systemd && echo "systemd" || echo "other")
IS_THERE_CDA_GROUP=$(shell getent group dg_orca && echo "yes" || echo "no")
IS_USER_IN_CDA_GROUP=$(shell groups | grep dg_orca && echo "yes" || echo "no")

DG_VID="1f0d"
DG_GROUP=dg_orca

UDEV_RULE0='SUBSYSTEM=="cda", MODE="0660", GROUP="$(DG_GROUP)"'
UDEV_RULE1='SUBSYSTEM=="cda", ACTION=="add", RUN+="/usr/local/bin/force_usr_mode.sh"'
#
FORCE_USR_MODE0="\#!/bin/sh"
FORCE_USR_MODE1='for d in $$(dirname -- $$(find /sys/devices/* -name "vendor" -exec grep -H $(DG_VID) {} \;)); do /bin/chmod ug+rw $$d/resource* ; /bin/chown root:$(DG_GROUP) $$d/resource* ; done'
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
	@sudo -E depmod
ifneq ($(IS_SYSTEMD_USED),other)
	@echo $(TARGET_MODULE) | sudo -E tee -i /etc/modules-load.d/cdapci.conf > /dev/null
else
	$(warning "No module autostart on reboot")
endif
ifeq ($(IS_THERE_CDA_GROUP),no)
	$(warning "No group cda. Create it. And add current user")
	@sudo -E groupadd $(DG_GROUP)
	@sudo -E usermod -a -G $(DG_GROUP) $$(whoami)
else
ifeq ($(IS_USER_IN_CDA_GROUP),no)
	$(warning "Group cda exists. Add current user")
	@sudo -E usermod -a -G $(DG_GROUP) $$(whoami)
endif
endif
	@echo $(FORCE_USR_MODE0) | sudo -E tee -i /usr/local/bin/force_usr_mode.sh > /dev/null
	@echo $(FORCE_USR_MODE1) | sudo -E tee -a /usr/local/bin/force_usr_mode.sh > /dev/null
	@sudo -E chmod +x /usr/local/bin/force_usr_mode.sh > /dev/null
	@echo $(UDEV_RULE0) | sudo -E tee -i /etc/udev/rules.d/66-cdapci.rules > /dev/null
	@echo $(UDEV_RULE1) | sudo -E tee -a /etc/udev/rules.d/66-cdapci.rules > /dev/null
	@sudo -E udevadm control --reload-rules
uninstall:
ifneq ($(IS_SYSTEMD_USED),other)
	@sudo -E rm -f /etc/modules-load.d/cdapci.conf
endif
	-sudo -E modprobe -r $(TARGET_MODULE)
	@sudo -E rm -f /usr/local/bin/force_usr_mode.sh
	@sudo -E rm -f /etc/udev/rules.d/66-cdapci.rules
	@sudo -E rm -f $(shell modinfo -n $(TARGET_MODULE))
	@sudo -E depmod
