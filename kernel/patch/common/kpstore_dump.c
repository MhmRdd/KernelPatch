/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 *
 * kpstore crash capture: a self-contained, fault-safe kernel "tombstone" built
 * on any oops/panic, independent of pstore/ramoops. Triggered by the die
 * notifier and the panic hook. The structured sections are written first into
 * a bounded record (so they are never clobbered), the dmesg tail fills the rest.
 */

#include <ktypes.h>
#include <stdarg.h>
#include <common.h>
#include <log.h>
#include <baselib.h>
#include <kallsyms.h>
#include <linux/ptrace.h>
#include <linux/list.h>
#include <pgtable.h>
#include <cache.h>

#include "module.h"
#include "kpstore.h"

extern int (*vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern struct module modules;

#define REC_SIZE (48 * 1024)
#define DMESG_MAX (32 * 1024)
#define BT_MAX_FRAMES 64
#define STACK_WORDS 48
#define SYM_MAX 200
#define LINE_MAX 512

// Tier-2: a self-reserved DRAM region that survives a warm reboot, so the
// tombstone of a panic can be read back on the next boot (pstore-independent)
#define KPSTORE_PERSIST_SIZE 0x10000
#define KPSTORE_PERSIST_MAGIC 0x4b505354

// minimal ABI-compatible kernel structs (no kdebug.h/notifier.h in the engine)
struct kp_notifier_block
{
    int (*notifier_call)(struct kp_notifier_block *, unsigned long, void *);
    struct kp_notifier_block *next;
    int priority;
};

struct kp_die_args
{
    struct pt_regs *regs;
    const char *str;
    long err;
    int trapnr;
    int signr;
};

static char crash_record[REC_SIZE];
static int rec_pos;
static long (*kp_nofault_read)(void *dst, const void *src, size_t size);
static int capturing;
static bool have_regs_record;

static uint64_t persist_pa;
static int persist_size;

struct kpstore_persist_hdr
{
    uint32_t magic;
    uint32_t len;
    uint32_t sum;
    uint32_t resv;
};

static uint32_t persist_sum(const char *p, int n)
{
    uint32_t s = 0x12345678;
    for (int i = 0; i < n; i++) s = s * 31 + (unsigned char)p[i];
    return s;
}

// mirror the freshly built record into the persistent region and flush to DRAM
static void persist_write(void)
{
    if (!persist_pa) return;
    uint64_t va = phys_to_virt(persist_pa);
    struct kpstore_persist_hdr *h = (struct kpstore_persist_hdr *)va;
    int max = persist_size - (int)sizeof(*h);
    int len = rec_pos;
    if (len > max) len = max;
    if (len < 0) len = 0;
    lib_memcpy((char *)(h + 1), crash_record, len);
    h->magic = KPSTORE_PERSIST_MAGIC;
    h->len = len;
    h->sum = persist_sum((char *)(h + 1), len);
    h->resv = 0;
    __flush_dcache_area((void *)va, sizeof(*h) + len);
}

// append bytes to the record, truncating at the end (never wraps)
static void rec_putn(const char *s, int n)
{
    if (rec_pos >= REC_SIZE) return;
    if (n > REC_SIZE - rec_pos) n = REC_SIZE - rec_pos;
    lib_memcpy(crash_record + rec_pos, s, n);
    rec_pos += n;
}

// formatted line into the record, also echoed to the console
static void rec_printf(const char *fmt, ...)
{
    char line[LINE_MAX];
    va_list ap;
    int n;
    if (!vsnprintf) return;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    rec_putn(line, n);
    if (printk) printk("%s", line);
}

static bool safe_read(void *dst, unsigned long src, unsigned long n)
{
    if (!kp_nofault_read) {
        unsigned long a = kallsyms_lookup_name("copy_from_kernel_nofault");
        if (!a) a = kallsyms_lookup_name("__copy_from_kernel_nofault");
        if (!a) a = kallsyms_lookup_name("probe_kernel_read");
        if (!a) a = kallsyms_lookup_name("__probe_kernel_read");
        kp_nofault_read = (typeof(kp_nofault_read))a;
    }
    if (!kp_nofault_read) return false;
    return kp_nofault_read(dst, (const void *)src, n) == 0;
}

static int kp_snprintf(char *buf, int size, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (!vsnprintf) return 0;
    va_start(ap, fmt);
    n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

static bool plausible_ptr(unsigned long a)
{
    return a >= 0xffff000000000000UL;
}

static struct module *owner_module(unsigned long addr)
{
    struct module *mod;
    list_for_each_entry(mod, &modules.list, list)
    {
        unsigned long s = (unsigned long)mod->start;
        if (s && addr >= s && addr < s + mod->size) return mod;
    }
    return 0;
}

static void sym_line(unsigned long addr, char *out, int len)
{
    const char *owner = "kernel";
    char tag[KPM_NAME_LEN + 8];
    struct module *mod;

    if (addr >= _kp_region_start && addr < _kp_region_end) {
        owner = "KP";
    } else if ((mod = owner_module(addr))) {
        kp_snprintf(tag, sizeof(tag), "KPM:%s", mod->info.name);
        owner = tag;
    }
    char sym[SYM_MAX];
    kp_snprintf(sym, sizeof(sym), "%pS", (void *)addr);
    kp_snprintf(out, len, "%-10s %s", owner, sym);
}

static void dump_context(const char *reason)
{
    extern uint32_t kver;
    extern uint32_t kpver;
    unsigned long mpidr = 0;
    asm volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    rec_printf("==== KernelPatch tombstone ====\n");
    rec_printf("reason : %s\n", reason ? reason : "(unknown)");
    rec_printf("kver   : %x  kpver: %x\n", kver, kpver);
    rec_printf("cpu    : %lx (mpidr)\n", mpidr & 0xffffff);
}

static void dump_sysregs(void)
{
    unsigned long esr = 0, far = 0, elr = 0, spsr = 0, sctlr = 0, midr = 0;
    asm volatile("mrs %0, esr_el1" : "=r"(esr));
    asm volatile("mrs %0, far_el1" : "=r"(far));
    asm volatile("mrs %0, elr_el1" : "=r"(elr));
    asm volatile("mrs %0, spsr_el1" : "=r"(spsr));
    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    asm volatile("mrs %0, midr_el1" : "=r"(midr));
    rec_printf("--- sysregs (current EL1) ---\n");
    rec_printf("ESR  : %016lx  FAR : %016lx\n", esr, far);
    rec_printf("ELR  : %016lx  SPSR: %016lx\n", elr, spsr);
    rec_printf("SCTLR: %016lx  MIDR: %016lx\n", sctlr, midr);
}

static void dump_regs(struct pt_regs *regs)
{
    char sym[SYM_MAX];
    rec_printf("--- registers ---\n");
    for (int i = 0; i < 30; i += 2)
        rec_printf("x%-2d: %016lx  x%-2d: %016lx\n", i, (unsigned long)regs->regs[i], i + 1,
                   (unsigned long)regs->regs[i + 1]);
    rec_printf("x30: %016lx\n", (unsigned long)regs->regs[30]);
    rec_printf("sp : %016lx  pc : %016lx  pstate: %08lx\n", (unsigned long)regs->sp, (unsigned long)regs->pc,
               (unsigned long)regs->pstate);
    sym_line(regs->pc, sym, sizeof(sym));
    rec_printf("pc  -> %s\n", sym);
    sym_line(regs->regs[30], sym, sizeof(sym));
    rec_printf("lr  -> %s\n", sym);
}

static void dump_code(unsigned long pc)
{
    unsigned long start = pc - 8 * 4;
    rec_printf("--- code around pc ---\n");
    for (int i = 0; i < 16; i++) {
        unsigned long a = start + i * 4;
        unsigned int v = 0;
        if (safe_read(&v, a, 4)) rec_printf("%016lx: %08x%s\n", a, v, a == pc ? "  <-- pc" : "");
    }
}

static void dump_backtrace(unsigned long fp, unsigned long pc)
{
    char sym[SYM_MAX];
    int n = 0;
    rec_printf("--- backtrace ---\n");
    if (pc) {
        sym_line(pc, sym, sizeof(sym));
        rec_printf("#%02d %016lx %s\n", n++, pc, sym);
    }
    for (int i = 0; i < BT_MAX_FRAMES && fp; i++) {
        unsigned long next = 0, lr = 0;
        if (!safe_read(&next, fp, 8) || !safe_read(&lr, fp + 8, 8)) break;
        if (!plausible_ptr(lr)) break;
        sym_line(lr, sym, sizeof(sym));
        rec_printf("#%02d %016lx %s\n", n++, lr, sym);
        if (next <= fp) break;
        fp = next;
    }
}

static void dump_stack(unsigned long sp)
{
    char sym[SYM_MAX];
    rec_printf("--- stack ---\n");
    for (int i = 0; i < STACK_WORDS; i++) {
        unsigned long a = sp + i * 8, v = 0;
        if (!safe_read(&v, a, 8)) break;
        if (plausible_ptr(v)) {
            sym_line(v, sym, sizeof(sym));
            rec_printf("%016lx: %016lx %s\n", a, v, sym);
        } else {
            rec_printf("%016lx: %016lx\n", a, v);
        }
    }
}

static void dump_mem_near_regs(struct pt_regs *regs)
{
    rec_printf("--- memory near registers ---\n");
    for (int r = 0; r <= 30; r++) {
        unsigned long a = regs->regs[r];
        if (!plausible_ptr(a)) continue;
        unsigned long base = (a & ~0xfUL) - 0x20;
        unsigned char buf[64];
        if (!safe_read(buf, base, sizeof(buf))) continue;
        rec_printf("x%d = %016lx\n", r, a);
        for (int o = 0; o < (int)sizeof(buf); o += 16) rec_printf("  %016lx: %*ph\n", base + o, 16, buf + o);
    }
}

static void dump_maps(void)
{
    struct module *mod;
    unsigned long st = kallsyms_lookup_name("_stext");
    unsigned long et = kallsyms_lookup_name("_etext");
    rec_printf("--- maps ---\n");
    rec_printf("KP     : %016lx-%016lx  text %016lx-%016lx\n", _kp_region_start, _kp_region_end,
               (unsigned long)_kp_text_start, (unsigned long)_kp_text_end);
    if (st) rec_printf("kernel : %016lx-%016lx (_stext.._etext)\n", st, et);
    list_for_each_entry(mod, &modules.list, list)
    {
        rec_printf("KPM %s: %016lx + %x\n", mod->info.name, (unsigned long)mod->start, mod->size);
    }
}

// kernel log tail via kmsg_dump_get_buffer, written raw into the record tail.
// A zeroed scratch + kmsg_dump_rewind works for both the pre-5.10 kmsg_dumper
// and the >=5.10 kmsg_dump_iter (only the first arg type differs).
static void dump_dmesg(void)
{
    void (*kd_rewind)(void *) = (typeof(kd_rewind))kallsyms_lookup_name("kmsg_dump_rewind");
    bool (*kd_getbuf)(void *, bool, char *, size_t, size_t *) =
        (typeof(kd_getbuf))kallsyms_lookup_name("kmsg_dump_get_buffer");
    if (!kd_getbuf) return;

    int avail = REC_SIZE - rec_pos - 64;
    if (avail > DMESG_MAX) avail = DMESG_MAX;
    if (avail <= 0) return;

    char iter[128];
    lib_memset(iter, 0, sizeof(iter));
    if (kd_rewind) kd_rewind(iter);

    rec_printf("--- dmesg tail ---\n");
    size_t len = 0;
    if (kd_getbuf(iter, true, crash_record + rec_pos, avail, &len)) {
        if ((int)len > avail) len = avail;
        rec_pos += (int)len;
    }
}

void kpstore_tombstone(const char *reason, struct pt_regs *regs)
{
    if (__atomic_exchange_n(&capturing, 1, __ATOMIC_SEQ_CST)) return;
    // keep the richest record: do not let a regs-less capture clobber a regs-ful one
    if (!regs && have_regs_record) {
        __atomic_store_n(&capturing, 0, __ATOMIC_SEQ_CST);
        return;
    }
    rec_pos = 0;

    dump_context(reason);
    dump_sysregs();
    if (regs) {
        dump_regs(regs);
        dump_code(regs->pc);
        dump_backtrace(regs->regs[29], regs->pc);
        dump_stack(regs->sp);
        dump_mem_near_regs(regs);
    } else {
        unsigned long fp = 0;
        asm volatile("mov %0, x29" : "=r"(fp));
        dump_backtrace(fp, 0);
    }
    dump_maps();
    dump_dmesg();
    rec_printf("==== end tombstone ====\n");

    if (regs) have_regs_record = true;
    persist_write();
    __atomic_store_n(&capturing, 0, __ATOMIC_SEQ_CST);
}

int kpstore_record_read(char *buf, int size)
{
    int n = rec_pos;
    if (size <= 0) return 0;
    if (n > size - 1) n = size - 1;
    lib_memcpy(buf, crash_record, n);
    buf[n] = '\0';
    return n;
}

const char *kpstore_record_data(int *len)
{
    if (len) *len = rec_pos;
    return crash_record;
}

// reserve the persistent region from memblock, before the buddy handoff. The
// kernel has already parsed /memory and /reserved-memory into memblock, so we
// pick the highest free DRAM-resident slot, which is deterministic per device
void kpstore_persist_reserve(void)
{
    typedef int (*reserve_t)(uint64_t base, uint64_t size);
    typedef uint64_t (*bound_t)(void);
    typedef int (*region_t)(uint64_t base, uint64_t size);

    reserve_t memblock_reserve = (reserve_t)kallsyms_lookup_name("memblock_reserve");
    bound_t memblock_end_of_DRAM = (bound_t)kallsyms_lookup_name("memblock_end_of_DRAM");
    if (!memblock_reserve || !memblock_end_of_DRAM) return;

    bound_t memblock_start_of_DRAM = (bound_t)kallsyms_lookup_name("memblock_start_of_DRAM");
    region_t is_memory = (region_t)kallsyms_lookup_name("memblock_is_region_memory");
    region_t is_reserved = (region_t)kallsyms_lookup_name("memblock_is_region_reserved");

    uint64_t size = KPSTORE_PERSIST_SIZE;
    uint64_t end = memblock_end_of_DRAM();
    uint64_t lo = memblock_start_of_DRAM ? memblock_start_of_DRAM() : 0;
    uint64_t base = (end - size) & ~(size - 1);

    for (int i = 0; i < 32 && base >= lo + size; i++, base -= size) {
        if (is_memory && !is_memory(base, size)) continue;
        if (is_reserved && is_reserved(base, size)) continue;
        if (memblock_reserve(base, size) == 0) {
            persist_pa = base;
            persist_size = (int)size;
            break;
        }
    }
}

// validate and return the persistent record (the previous boot's panic, if any)
const char *kpstore_persist_data(int *len)
{
    if (len) *len = 0;
    if (!persist_pa) return 0;

    uint64_t va = phys_to_virt(persist_pa);
    struct kpstore_persist_hdr *h = (struct kpstore_persist_hdr *)va;
    if (h->magic != KPSTORE_PERSIST_MAGIC) return 0;

    int n = h->len;
    if (n < 0 || n > persist_size - (int)sizeof(*h)) return 0;
    if (persist_sum((char *)(h + 1), n) != h->sum) return 0;

    if (len) *len = n;
    return (const char *)(h + 1);
}

static int kp_die_cb(struct kp_notifier_block *nb, unsigned long action, void *data)
{
    struct kp_die_args *a = (struct kp_die_args *)data;
    (void)nb;
    (void)action;
    if (a && a->regs) kpstore_tombstone(a->str ? a->str : "die", a->regs);
    return 0; // NOTIFY_DONE
}

static struct kp_notifier_block kp_die_nb = { kp_die_cb, 0, 0 };

// die notifier covers oopses/faults with regs. The panic path is captured from
// KP's existing before_panic hook (a function hook, no data-symbol dependency).
void kpstore_crash_init(void)
{
    int (*reg_die)(struct kp_notifier_block *) = (typeof(reg_die))kallsyms_lookup_name("register_die_notifier");
    if (reg_die) reg_die(&kp_die_nb);
}
