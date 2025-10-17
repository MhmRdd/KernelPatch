#ifndef _KP_SPINLOCK_H_
#define _KP_SPINLOCK_H_

#include <ktypes.h>
#include <barrier.h>

/* Compiler barrier and memory access macros */
#ifndef barrier
#define barrier() asm volatile("" ::: "memory")
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(var, val) \
    do { \
        barrier(); \
        (var) = (val); \
        barrier(); \
    } while (0)
#endif

#ifndef READ_ONCE
#define READ_ONCE(var) ({ \
    typeof(var) _val; \
    barrier(); \
    _val = (var); \
    barrier(); \
    _val; \
})
#endif

/* Compile-time atomic type assertion - simplified for bare-metal */
#ifndef compiletime_assert_atomic_type
#define compiletime_assert_atomic_type(var) \
    do { \
        (void)(var); \
    } while (0)
#endif

/* Simple bare-metal spinlock implementation using ARM64 exclusive operations */

typedef struct {
    volatile int locked;
} spinlock_t;

#define DEFINE_SPINLOCK(name) spinlock_t name = { .locked = 0 }

static inline void spin_lock_init(spinlock_t *lock)
{
    smp_store_release(&lock->locked, 0);
}

static inline void spin_lock(spinlock_t *lock)
{
    int tmp;

    asm volatile(
    "1: ldxr    %w0, %1\n"
    "   cbnz    %w0, 2f\n"
    "   stxr    %w0, %w2, %1\n"
    "   cbnz    %w0, 1b\n"
    "   b       3f\n"
    "2: yield\n"
    "   b       1b\n"
    "3:"
    : "=&r" (tmp), "+Q" (lock->locked)
    : "r" (1)
    : "memory");
}

static inline void spin_unlock(spinlock_t *lock)
{
    smp_store_release(&lock->locked, 0);
}

static inline int spin_trylock(spinlock_t *lock)
{
    int tmp;
    int result = 0;

    asm volatile(
    "   ldxr    %w0, %2\n"
    "   cbnz    %w0, 1f\n"
    "   stxr    %w0, %w3, %2\n"
    "   cbnz    %w0, 1f\n"
    "   mov     %w1, #1\n"
    "1:"
    : "=&r" (tmp), "=&r" (result), "+Q" (lock->locked)
    : "r" (1)
    : "memory");

    return result;
}

/* IRQ-safe spinlocks (disable local interrupts) */
static inline unsigned long arch_local_save_flags(void)
{
    unsigned long flags;
    asm volatile("mrs %0, daif" : "=r" (flags) :: "memory");
    return flags;
}

static inline void arch_local_irq_disable(void)
{
    asm volatile("msr daifset, #2" ::: "memory");
}

static inline void arch_local_irq_restore(unsigned long flags)
{
    asm volatile("msr daif, %0" :: "r" (flags) : "memory");
}

static inline void spin_lock_irqsave(spinlock_t *lock, unsigned long *flags)
{
    *flags = arch_local_save_flags();
    arch_local_irq_disable();
    spin_lock(lock);
}

static inline void spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
    spin_unlock(lock);
    arch_local_irq_restore(flags);
}

/* Simple mutex implementation using spinlock */
typedef struct {
    spinlock_t lock;
    volatile int owner;
} mutex_t;

#define DEFINE_MUTEX(name) mutex_t name = { .lock = { .locked = 0 }, .owner = 0 }

static inline void mutex_init(mutex_t *mutex)
{
    spin_lock_init(&mutex->lock);
    smp_store_release(&mutex->owner, 0);
}

static inline void mutex_lock(mutex_t *mutex)
{
    while (1) {
        spin_lock(&mutex->lock);
        if (!mutex->owner) {
            mutex->owner = 1;
            spin_unlock(&mutex->lock);
            break;
        }
        spin_unlock(&mutex->lock);
        /* Simple backoff - could be improved */
        asm volatile("yield" ::: "memory");
    }
}

static inline void mutex_unlock(mutex_t *mutex)
{
    spin_lock(&mutex->lock);
    mutex->owner = 0;
    spin_unlock(&mutex->lock);
}

#endif