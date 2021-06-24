/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef LINUX_VERSION_CODE
#include <stdint.h> // only include if we're not compiling against the kernel
#endif

#define CDA_IOCTL_MAGIC 'C'
#define CDA_ALLOC_MEM _IOWR(CDA_IOCTL_MAGIC, 0x1, long)
#define CDA_FREE_MEM _IOW(CDA_IOCTL_MAGIC, 0x2, long)
#define CDA_MAP_MEM _IOWR(CDA_IOCTL_MAGIC, 0x3, long)
#define CDA_UNMAP_MEM _IOW(CDA_IOCTL_MAGIC, 0x4, long)
#define CDA_INIT_INT _IOWR(CDA_IOCTL_MAGIC, 0x5, long)
#define CDA_FREE_INT _IOW(CDA_IOCTL_MAGIC, 0x6, long)
#define CDA_REQ_INT _IOWR(CDA_IOCTL_MAGIC, 0x7, long)
#define CDA_INT_CANCEL _IOWR(CDA_IOCTL_MAGIC, 0x8, long)

struct cda_alloc_mem {
	uint32_t size;
	uint32_t index;
};

struct cda_map_mem {
	uintptr_t vaddr;
	uint32_t size;
	uint32_t index;
};

struct cda_drv_sg_item {
	uint64_t paddr;
	uint32_t size;
};

struct cda_req_int {
	uint32_t vector;
	uint64_t timeout;
	uint32_t reset;
};

enum int_type {
    LEGACY_INTERRUPT = 0,
    MSI = 1,
    MSIX = 2
};

struct cda_int_lock {
	uint32_t inttype;
	uint32_t vectors;
};
