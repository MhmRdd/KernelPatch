#ifndef _KP_ATOMIC_H_
#define _KP_ATOMIC_H_

#include <ktypes.h>
#include <barrier.h>

/* Bare-metal atomic operations using ARM64 exclusive load/store */

static inline int atomic_read(const atomic_t *v)
{
    return smp_load_acquire(&v->counter);
}

static inline void atomic_set(atomic_t *v, int i)
{
    smp_store_release(&v->counter, i);
}

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
    int tmp;
    int result;

    asm volatile(
    "1: ldxr    %w0, %2\n"
    "   cmp     %w0, %w3\n"
    "   b.ne    2f\n"
    "   stxr    %w1, %w4, %2\n"
    "   cbnz    %w1, 1b\n"
    "2:"
    : "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
    : "r" (old), "r" (new)
    : "cc", "memory");

    return result;
}

static inline int atomic_xchg(atomic_t *v, int new)
{
    int tmp;
    int result;

    asm volatile(
    "1: ldxr    %w0, %2\n"
    "   stxr    %w1, %w3, %2\n"
    "   cbnz    %w1, 1b\n"
    : "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
    : "r" (new)
    : "memory");

    return result;
}

static inline int atomic_add_return(int i, atomic_t *v)
{
    int tmp;
    int result;

    asm volatile(
    "1: ldxr    %w0, %2\n"
    "   add     %w0, %w0, %w3\n"
    "   stxr    %w1, %w0, %2\n"
    "   cbnz    %w1, 1b\n"
    : "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
    : "r" (i)
    : "memory");

    return result;
}

static inline int atomic_sub_return(int i, atomic_t *v)
{
    return atomic_add_return(-i, v);
}

static inline void atomic_add(int i, atomic_t *v)
{
    atomic_add_return(i, v);
}

static inline void atomic_sub(int i, atomic_t *v)
{
    atomic_sub_return(i, v);
}

static inline void atomic_inc(atomic_t *v)
{
    atomic_add(1, v);
}

static inline void atomic_dec(atomic_t *v)
{
    atomic_sub(1, v);
}

/* 64-bit atomic operations */
static inline long atomic64_read(const atomic64_t *v)
{
    return smp_load_acquire(&v->counter);
}

static inline void atomic64_set(atomic64_t *v, long i)
{
    smp_store_release(&v->counter, i);
}

static inline long atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
    long tmp;
    long result;

    asm volatile(
    "1: ldxr    %0, %2\n"
    "   cmp     %0, %3\n"
    "   b.ne    2f\n"
    "   stxr    %w1, %4, %2\n"
    "   cbnz    %w1, 1b\n"
    "2:"
    : "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
    : "r" (old), "r" (new)
    : "cc", "memory");

    return result;
}

#endif