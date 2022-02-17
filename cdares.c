// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2020 DeGirum Corp., Egor Pomozov.
//
// CDA linux driver mem blocks/mem maps and interrupt request handler
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/uaccess.h>

#include "cdadrv.h"
#include "cdaioctl.h"

struct cda_vector {
	volatile bool busy;
	wait_queue_head_t wait;
	atomic_t count;
	unsigned irq;
};

struct cda_interrupts {
	int num;
	enum int_type type;
	void *owner;
	struct cda_vector *vecs;
	struct msix_entry *msix_entries;
};

static int cda_alloc_msix(struct cda_dev *cdadev, uint32_t rvecs, struct cda_interrupts *ints)
{
	int i, ret;
	struct msix_entry *entries;
	entries = kcalloc(rvecs, sizeof(struct msix_entry), GFP_KERNEL);
	if( !entries ) {
		return -ENOMEM;
	}

	for (i = 0; i < rvecs; i++) {
		entries[i].entry = i;
		entries[i].vector = 0;
	}

	ret = pci_enable_msix_exact(cdadev->pcidev, entries, rvecs);
	if( !ret ) {
		ints->num = rvecs;
		ints->msix_entries = entries;
		ints->type = MSIX;
	} else {
		kfree(entries);
	}
	return ret;
}

static irqreturn_t cda_isr(int irq, void *priv)
{
	struct cda_vector *vec = priv;
	atomic_inc_return(&vec->count);
	wake_up(&vec->wait);
	return IRQ_HANDLED;
}

int cda_init_interrupts(struct cda_dev *cdadev, void *owner, void __user *ureq)
{
	int ret = 0;
	int nvecs, i;
	struct cda_vector *vec;
	struct cda_int_lock req;
	struct cda_interrupts *ints;

	if( cdadev->ints ) {
		//printk("Interrupts are already attached");
		return -EINVAL; // Already attached
	}
	if( copy_from_user(&req, (void __user *)ureq, sizeof(req)) )
		return -EFAULT;

	ints = kcalloc(1, sizeof(struct cda_interrupts), GFP_KERNEL);
	if( !ints )
		return -ENOMEM;

	ints->owner = owner;
	switch( req.inttype ) {
	case MSIX:
		ret = cda_alloc_msix(cdadev, req.vectors, ints);
		if( !ret ) {
			nvecs = req.vectors;
			break;
		}
		if( ret == -ENOMEM ) {
			kfree(ints);
			return ret;
		}
		dev_warn(&cdadev->pcidev->dev, "No MSI-X vectors, try MSI. Error %x\n", ret);
		// fall-through
	case MSI:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
		nvecs = pci_alloc_irq_vectors(cdadev->pcidev, 1, req.vectors, PCI_IRQ_MSI);
#else
		nvecs = pci_alloc_irq_vectors_affinity(cdadev->pcidev, 1, req.vectors, PCI_IRQ_MSI, NULL);
#endif
		if( nvecs > 0 ) {
			ints->num = nvecs;
			ints->type = MSI;
			break;
		}
		dev_warn(&cdadev->pcidev->dev, "No MSI vectors, try legacy. Error %x\n", nvecs);
		// fall-through
	case LEGACY_INTERRUPT:
		ints->num = 1;
		ints->type = LEGACY_INTERRUPT;
		break;
	}

	ints->vecs = kcalloc(ints->num, sizeof(struct cda_vector), GFP_KERNEL);
	if( !ints->vecs ) {
		ret = -ENOMEM;
		goto err_alloc_vecs;
	}

	for( i = 0; i < ints->num; i++ ) {
		char name[10];
		vec = &ints->vecs[i];
		vec->irq = ints->type == MSIX ? 
					cdadev->ints->msix_entries[i].vector : 
					cdadev->pcidev->irq + i;
		snprintf(name, sizeof(name), "cda%02d-%x", cdadev->minor, i);
		init_waitqueue_head(&vec->wait);
		atomic_set(&vec->count, 0);
		ret = request_irq(vec->irq, cda_isr, ints->type == LEGACY_INTERRUPT ? IRQF_SHARED : 0, name, vec);
		if( ret ) {
			dev_err(&cdadev->pcidev->dev, "request_irq failed for vector %d: %d", i, ret);
			break;
		}
	}

	// Return interrupt type and vector count to user
	if( !ret ) {
		req.inttype = ints->type;
		req.vectors = ints->num;
		if( copy_to_user(ureq, &req, sizeof(req)) )
			ret = -EFAULT;
	}

	if( !ret ) {
		cdadev->ints = ints;
		return ret;
	}
	// Fail. Release
	for( i -= 1; i >= 0; i-- ) {
		struct cda_vector *vec = &ints->vecs[i];
		free_irq(vec->irq, vec);
	}
	kfree(ints->vecs);

err_alloc_vecs:
	pci_free_irq_vectors(cdadev->pcidev);
	kfree(ints->msix_entries);
	kfree(ints);

	return ret;
}

int cda_free_irqs(struct cda_dev *cdadev, void *owner)
{
	int i;
	struct cda_interrupts *ints;
	if( cdadev->ints == NULL )
		return -EINVAL;
	if( cdadev->ints->owner != owner ) {
		//dev_err(&cdadev->pcidev->dev, "Interrupts are not owned by %p", owner);
		return -EINVAL;
	}
	mutex_lock(&cdadev->ilock);
	ints = cdadev->ints;
	cdadev->ints = NULL;
	mutex_unlock(&cdadev->ilock);
	if( ints && ints->num > 0 ) {
		for( i = 0; i < ints->num; i++ ) {
			struct cda_vector *vec = &ints->vecs[i];
			while( vec->busy ) {
				wake_up(&vec->wait);
				udelay(1);
			}
			free_irq(vec->irq, vec);
		}
		pci_free_irq_vectors(cdadev->pcidev);
		kfree(ints->vecs);
		kfree(ints->msix_entries);
		kfree(ints);
	}
	return 0;
}

int cda_req_int(struct cda_dev *cdadev, void *owner, void __user *ureq)
{
	struct cda_interrupts *ints;
	struct cda_req_int req;
	struct cda_vector *vec;
	unsigned long timeout;
	unsigned count;

	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	if( cdadev->ints == NULL )
		return -EINVAL;

	if( cdadev->ints->owner != owner ) {
		dev_err(&cdadev->pcidev->dev, "Interrupts are not owned by %p", owner);
		return -EINVAL;
	}

	mutex_lock(&cdadev->ilock);
	ints = cdadev->ints;
	if( !ints || (req.vector > ints->num) ) {
		mutex_unlock(&cdadev->ilock);
		return -EINVAL;
	}

	vec = &ints->vecs[req.vector];
	if (req.reset)
		atomic_set(&vec->count, 0);

	timeout = nsecs_to_jiffies(req.timeout);
	count = atomic_xchg(&vec->count, 0);
	if( !count )
	{
		vec->busy = true;
		mutex_unlock(&cdadev->ilock);
		timeout = wait_event_interruptible_timeout(vec->wait,
							(count = atomic_xchg(&vec->count, 0)),
							timeout);
		mutex_lock(&cdadev->ilock);
		vec->busy = false;
	}
	mutex_unlock(&cdadev->ilock);
	//printk("Interrupt vector %d timeout: %ld count %u reset %d\n", req.vector, timeout, count, req.reset);
	return timeout > 0 ? 0 : timeout == 0 ? -ETIME : timeout;
}

int cda_cancel_req(struct cda_dev *cdadev, void *owner)
{
	int i;
	struct cda_interrupts *ints;
	if( cdadev->ints == NULL )
		return -EINVAL;

	if( cdadev->ints->owner != owner ) {
		//dev_err(&cdadev->pcidev->dev, "Interrupts are not owned by %p", owner);
		return -EINVAL;
	}

	mutex_lock(&cdadev->ilock);
	ints = cdadev->ints;
	for (i = 0; ints && i < ints->num; i++) {
		if( ints->vecs[i].busy )
			wake_up(&ints->vecs[i].wait);
	}
	mutex_unlock(&cdadev->ilock);
	return 0;
}

int cda_check_bars(struct cda_dev *cdadev)
{
	int i;
	struct resource *res_child;
	int bars = pci_select_bars(cdadev->pcidev, IORESOURCE_MEM);

	for( i = 0; i < PCI_ROM_RESOURCE; i++ ) {
		// Drop busy bit
		if( bars & (1 << i) ) {
			res_child = cdadev->pcidev->resource[i].child;
			cdadev->stored_flags[i] = res_child->flags;
			printk("Store resource %d flag: 0x%lx\n", i, res_child->flags);
			if( IORESOURCE_BUSY & res_child->flags ) {
				res_child->flags &= ~IORESOURCE_BUSY;
				//printk("Drop busy bit for resource %d", i);
			}
		}
	}
	return 0;
}

void cda_restore_bars(struct cda_dev *cdadev)
{
	int i;
	int bars = pci_select_bars(cdadev->pcidev, IORESOURCE_MEM);
	for( i = 0; i < PCI_ROM_RESOURCE; i++ ) {
		if( bars & (1 << i) ) {
			cdadev->pcidev->resource[i].child->flags = cdadev->stored_flags[i];
			printk("Restore resource %d flag: %lx\n", i, cdadev->stored_flags[i]);
		}
	}
}

int cda_sem_aq(struct cda_dev *cdadev, void *owner, void __user *ureq)
{
	int res = 0;
	struct cda_sem_aq req;
	u64 cur_time;
	if (copy_from_user(&req, ureq, sizeof(req)))
		return -EFAULT;

	mutex_lock(&cdadev->ilock);
	cur_time = ktime_get_ns();
	if( cdadev->semaphores[req.sem_id] < cur_time ) {
		cdadev->semaphores[req.sem_id] = cur_time + req.time_ns > cur_time ? cur_time + req.time_ns : 0xFFFFFFFFFFFFFFFFULL;
		cdadev->sem_owner[req.sem_id] = owner;
	} else {
		res = 1;
	}
	mutex_unlock(&cdadev->ilock);
	return res;
}

int cda_sem_rel(struct cda_dev *cdadev, void *owner, void __user *ureq)
{
	int res = 0;
	int req_sem;
	if (copy_from_user(&req_sem, ureq, sizeof(req_sem)))
		return -EFAULT;
	if( cdadev->sem_owner[req_sem] != owner ) {
		dev_warn(&cdadev->pcidev->dev, "Semaphore %d is not owned by %p", req_sem, owner);
	} else {
		mutex_lock(&cdadev->ilock);
		cdadev->semaphores[req_sem] = 0ULL;
		cdadev->sem_owner[req_sem] = NULL;
		mutex_unlock(&cdadev->ilock);
	}
	return res;
}

void cda_sem_rel_by_owner(struct cda_dev *dev, void *owner)
{
	uint32_t i;
	mutex_lock(&dev->ilock);
	for( i = 0; i < CDA_MAX_DRV_SEMAPHORES; i++ ) {
		if( dev->sem_owner[i] == owner ) {
			dev->semaphores[i] = 0ULL;
			dev->sem_owner[i] = NULL;
		}
	}
	mutex_unlock(&dev->ilock);
}
