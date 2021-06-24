// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2020 Egor Pomozov.
//
// CDA linux driver common header
//
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/version.h>

struct cda_interrupts;
struct cda_dev {
    struct cdev cdev;
    struct device dev;

	int minor;
	struct list_head devices;

	struct pci_dev *pcidev;
	unsigned long stored_flags[PCI_ROM_RESOURCE];
	
	struct mutex ilock;
	struct cda_interrupts *ints;

	struct kobject *kobj_mems;
	struct idr mblk_idr;
	spinlock_t mblk_sl;
	struct list_head mem_blocks;
	struct list_head mem_maps;
};

int cda_alloc_mem(struct cda_dev *dev, void __user *arg);
int cda_free_mem_by_idx(struct cda_dev *dev, void __user *ureq);
int cda_map_mem(struct cda_dev *dev, void __user *arg);
int cda_unmap_mem_by_idx(struct cda_dev *dev, void __user *ureq);
void cda_unmmap_dev_mem(struct cda_dev *dev);
void cda_free_dev_mem(struct cda_dev *dev);
int cda_init_interrupts(struct cda_dev *dev, void __user *ureq);
int cda_mems_create(struct cda_dev *dev);
int cda_free_irqs(struct cda_dev *dev);
void cda_mems_release(struct cda_dev *dev);
int cda_req_int(struct cda_dev *dev, void __user *ureq);
int cda_cancel_req(struct cda_dev *dev);
int cda_check_bars(struct cda_dev *cdadev);
void cda_restore_bars(struct cda_dev *cdadev);
