#ifndef _KP_KPMALLOC_H_
#define _KP_KPMALLOC_H_

#include <tlsf.h>
#include <linux/spinlock.h>

extern tlsf_t kp_rw_mem;
extern tlsf_t kp_rox_mem;

// Global locks for TLSF allocators to ensure thread safety
extern spinlock_t kp_rox_mem_lock;
extern spinlock_t kp_rw_mem_lock;

static inline void *kp_malloc_exec(size_t bytes)
{
    unsigned long flags;
    void *ptr;

    spin_lock_irqsave(&kp_rox_mem_lock, flags);
    ptr = tlsf_malloc(kp_rox_mem, bytes);
    spin_unlock_irqrestore(&kp_rox_mem_lock, flags);

    return ptr;
}

static inline void *kp_memalign_exec(size_t align, size_t bytes)
{
    unsigned long flags;
    void *ptr;

    spin_lock_irqsave(&kp_rox_mem_lock, flags);
    ptr = tlsf_memalign(kp_rox_mem, align, bytes);
    spin_unlock_irqrestore(&kp_rox_mem_lock, flags);

    return ptr;
}

static inline void *kp_realloc_exec(void *ptr, size_t size)
{
    unsigned long flags;
    void *new_ptr;

    spin_lock_irqsave(&kp_rox_mem_lock, flags);
    new_ptr = tlsf_realloc(kp_rox_mem, ptr, size);
    spin_unlock_irqrestore(&kp_rox_mem_lock, flags);

    return new_ptr;
}

static inline void kp_free_exec(void *ptr)
{
    unsigned long flags;

    if (!ptr) return;

    spin_lock_irqsave(&kp_rox_mem_lock, flags);
    tlsf_free(kp_rox_mem, ptr);
    spin_unlock_irqrestore(&kp_rox_mem_lock, flags);
}

static inline void *kp_malloc(size_t bytes)
{
    unsigned long flags;
    void *ptr;

    spin_lock_irqsave(&kp_rw_mem_lock, flags);
    ptr = tlsf_malloc(kp_rw_mem, bytes);
    spin_unlock_irqrestore(&kp_rw_mem_lock, flags);

    return ptr;
}

static inline void *kp_memalign(size_t align, size_t bytes)
{
    unsigned long flags;
    void *ptr;

    spin_lock_irqsave(&kp_rw_mem_lock, flags);
    ptr = tlsf_memalign(kp_rw_mem, align, bytes);
    spin_unlock_irqrestore(&kp_rw_mem_lock, flags);

    return ptr;
}

static inline void *kp_realloc(void *ptr, size_t size)
{
    unsigned long flags;
    void *new_ptr;

    spin_lock_irqsave(&kp_rw_mem_lock, flags);
    new_ptr = tlsf_realloc(kp_rw_mem, ptr, size);
    spin_unlock_irqrestore(&kp_rw_mem_lock, flags);

    return new_ptr;
}

static inline void kp_free(void *ptr)
{
    unsigned long flags;

    if (!ptr) return;

    spin_lock_irqsave(&kp_rw_mem_lock, flags);
    tlsf_free(kp_rw_mem, ptr);
    spin_unlock_irqrestore(&kp_rw_mem_lock, flags);
}

#endif