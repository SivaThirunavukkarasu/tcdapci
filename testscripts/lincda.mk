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
obj-m := $(TARGET_MODULE).o

SRC := $(shell pwd)

$(TARGET_MODULE)-objs := cdadrv.o cdamem.o cdares.o

.PHONY: all
all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	$(RM) .*.cmd *.o *.ko modules.order cdapci.mod cdapci.mod.c Module.sym*

