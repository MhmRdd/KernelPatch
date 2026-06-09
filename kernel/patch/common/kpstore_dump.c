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
#include <hook.h>
#include <symbol.h>
#include <preset.h>
#include <kpmalloc.h>
#include <kplz4.h>
#include <kpstore_persist.h>

#include "module.h"
#include "kpstore.h"

extern int (*vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
extern struct module modules;
extern void _kp_symbol_start();
extern void _kp_symbol_end();

#define REC_SIZE (288 * 1024)
#define DMESG_MAX (256 * 1024)
#define BT_MAX_FRAMES 64
#define STACK_WORDS 48
#define SYM_MAX 200
#define LINE_MAX 512

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

// mirrors the per-hook bookkeeping in base/hmem.c (it has no shared header)
typedef struct
{
    int using;
    enum hook_type type;
    uintptr_t addr;
    union
    {
        hook_t inl;
        hook_chain_t inl_chain;
        fp_hook_chain_t fp_chain;
    } chain __attribute__((aligned(8)));
} hook_mem_warp_t __attribute__((aligned(16)));

// the live tombstone (Tier-1), allocated from the RW pool at init. rec_buf is
// reused only for assembly, never as a persisted-read target
static char *rec_buf;
static int rec_cap;
static int rec_pos;
static void *lz4_ws;
static char *dec_buf;
static long (*kp_nofault_read)(void *dst, const void *src, size_t size);
static int capturing;
static bool have_regs_record;

// Tier-2 persistent ring: base/size of the reserved DRAM region (0 if disabled)
static uint64_t persist_pa;
static int persist_size;

static void persist_write(void);

static uint32_t kpstore_sum(const void *p, int n)
{
    const unsigned char *b = (const unsigned char *)p;
    uint32_t s = 0x12345678u;
    for (int i = 0; i < n; i++) s = s * 31u + b[i];
    return s;
}

// append bytes to the record, truncating at the end (never wraps)
static void rec_putn(const char *s, int n)
{
    if (!rec_buf || rec_pos >= rec_cap) return;
    if (n > rec_cap - rec_pos) n = rec_cap - rec_pos;
    lib_memcpy(rec_buf + rec_pos, s, n);
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
    int g = 0;
    list_for_each_entry(mod, &modules.list, list)
    {
        if (++g > 64) break;
        unsigned long s = (unsigned long)mod->start;
        if (s && addr >= s && addr < s + mod->size) return mod;
    }
    return 0;
}

// nearest KP-exported symbol at or below addr, so a PC inside the KP engine
// (which the kernel kallsyms cannot name) still resolves to a name + offset
static const char *kp_export_nearest(unsigned long addr, unsigned long *off)
{
    uint64_t s = (uint64_t)_kp_symbol_start, e = (uint64_t)_kp_symbol_end;
    const char *best = 0;
    unsigned long best_addr = 0;
    for (uint64_t a = s; a + sizeof(kp_symbol_t) <= e; a += sizeof(kp_symbol_t)) {
        kp_symbol_t *sym = (kp_symbol_t *)a;
        if (sym->addr <= addr && sym->addr >= best_addr) {
            best_addr = sym->addr;
            best = sym->name;
        }
    }
    if (best && off) *off = addr - best_addr;
    return best;
}

static void sym_line(unsigned long addr, char *out, int len)
{
    struct module *mod;
    unsigned long off = 0;

    if (addr >= _kp_region_start && addr < _kp_region_end) {
        const char *nm = kp_export_nearest(addr, &off);
        if (nm) kp_snprintf(out, len, "KP         %s+0x%lx", nm, off);
        else kp_snprintf(out, len, "KP         +0x%lx", addr - _kp_region_start);
    } else if ((mod = owner_module(addr))) {
        const char *fn = module_symbol(mod, addr, &off);
        if (fn)
            kp_snprintf(out, len, "KPM:%-8s %s+0x%lx", mod->info.name, fn, off);
        else
            kp_snprintf(out, len, "KPM:%-8s +0x%lx", mod->info.name, addr - (unsigned long)mod->start);
    } else {
        char sym[SYM_MAX];
        kp_snprintf(sym, sizeof(sym), "%pS", (void *)addr);
        kp_snprintf(out, len, "kernel     %s", sym);
    }
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

// KernelPatch core: version, config flags, kernel anchors and the full KP
// memory layout, so a fault anywhere in the engine can be located by region
static void dump_kp(void)
{
    extern uint32_t kver, kpver;
    extern uint64_t kernel_va, kernel_pa, link_base_addr, runtime_base_addr;
    extern int64_t kernel_size;
    extern setup_header_t *setup_header;

    unsigned long st = kallsyms_lookup_name("_stext");
    unsigned long et = kallsyms_lookup_name("_etext");
    unsigned long flags = setup_header ? (unsigned long)setup_header->config_flags : 0;
    int nexp = (int)(((uint64_t)_kp_symbol_end - (uint64_t)_kp_symbol_start) / sizeof(kp_symbol_t));

    rec_printf("--- kernelpatch ---\n");
    rec_printf("kpver  : %x   kver: %x   config: %lx%s%s\n", kpver, kver, flags,
               (flags & CONFIG_ANDROID) ? " android" : "", (flags & CONFIG_DEBUG) ? " debug" : "");
    rec_printf("kernel : pa %016lx va %016lx size %lx\n", kernel_pa, kernel_va, (unsigned long)kernel_size);
    if (st) rec_printf("ktext  : %016lx-%016lx (_stext.._etext)\n", st, et);
    rec_printf("klookup: %016lx (kallsyms_lookup_name)\n", (unsigned long)kallsyms_lookup_name);
    rec_printf("kp base: link %016lx runtime %016lx  exports %d\n", link_base_addr, runtime_base_addr, nexp);
    rec_printf("region : %016lx-%016lx\n", _kp_region_start, _kp_region_end);
    rec_printf("  text : %016lx-%016lx\n", (unsigned long)_kp_text_start, (unsigned long)_kp_text_end);
    rec_printf("  extra: %016lx-%016lx\n", _kp_extra_start, _kp_extra_end);
    rec_printf("  hook : %016lx-%016lx\n", _kp_hook_start, _kp_hook_end);
    rec_printf("  rw   : %016lx-%016lx\n", _kp_rw_start, _kp_rw_end);
    rec_printf("  rox  : %016lx-%016lx\n", _kp_rox_start, _kp_rox_end);
    rec_printf("persist: pa %016lx size %x slots %d\n", persist_pa, persist_size, KPSTORE_SLOT_COUNT);
}

// every loaded KPM with its identity, runtime range and callback addresses
static void dump_modules(void)
{
    struct module *mod;
    int n = 0;
    rec_printf("--- kpms ---\n");
    list_for_each_entry(mod, &modules.list, list)
    {
        if (++n > 64) break;
        rec_printf("[%d] %s  v%s  by %s\n", n, mod->info.name, mod->info.version ? mod->info.version : "?",
                   mod->info.author ? mod->info.author : "?");
        rec_printf("    base %016lx size %x (text %x ro %x)\n", (unsigned long)mod->start, mod->size,
                   mod->text_size, mod->ro_size);
        rec_printf("    init %016lx ctl0 %016lx ctl1 %016lx exit %016lx\n", (unsigned long)mod->init,
                   (unsigned long)mod->ctl0, (unsigned long)mod->ctl1, (unsigned long)mod->exit);
        if (mod->args) rec_printf("    args: %s\n", mod->args);
    }
    if (!n) rec_printf("(none)\n");
}

static const char *hook_type_name(int t)
{
    switch (t) {
    case INLINE: return "inline";
    case INLINE_CHAIN: return "inline-chain";
    case FUNCTION_POINTER_CHAIN: return "fp-chain";
    default: return "none";
    }
}

// list the before/after callbacks of a hook chain, symbolized to their owner
static void dump_hook_chain(int max, chain_item_state *states, void **befores, void **afters)
{
    char sym[SYM_MAX];
    if (max > FP_HOOK_CHAIN_NUM) max = FP_HOOK_CHAIN_NUM;
    for (int i = 0; i < max; i++) {
        if (states[i] == CHAIN_ITEM_STATE_EMPTY) continue;
        if (befores[i]) {
            sym_line((unsigned long)befores[i], sym, sizeof(sym));
            rec_printf("    before[%d] %s\n", i, sym);
        }
        if (afters[i]) {
            sym_line((unsigned long)afters[i], sym, sizeof(sym));
            rec_printf("    after [%d] %s\n", i, sym);
        }
    }
}

// every hook KP installed (its own and those placed by KPMs), the hooked
// target and the handlers, so the active interception graph is on record
static void dump_hooks(void)
{
    char tsym[SYM_MAX], rsym[SYM_MAX];
    int count = 0;
    rec_printf("--- hooks ---\n");
    for (uint64_t a = _kp_hook_start; a + sizeof(hook_mem_warp_t) <= _kp_hook_end; a += sizeof(hook_mem_warp_t)) {
        hook_mem_warp_t *w = (hook_mem_warp_t *)a;
        if (!w->using) continue;
        count++;
        if (w->type == FUNCTION_POINTER_CHAIN) {
            fp_hook_chain_t *c = &w->chain.fp_chain;
            sym_line(c->hook.fp_addr, tsym, sizeof(tsym));
            sym_line(c->hook.replace_addr, rsym, sizeof(rsym));
            rec_printf("[%d] %-12s fp %016lx %s -> %s\n", count, hook_type_name(w->type),
                       (unsigned long)c->hook.fp_addr, tsym, rsym);
            dump_hook_chain(c->chain_items_max, c->states, c->befores, c->afters);
        } else if (w->type == INLINE_CHAIN) {
            hook_chain_t *c = &w->chain.inl_chain;
            sym_line(c->hook.func_addr, tsym, sizeof(tsym));
            rec_printf("[%d] %-12s fn %016lx %s\n", count, hook_type_name(w->type),
                       (unsigned long)c->hook.func_addr, tsym);
            dump_hook_chain(c->chain_items_max, c->states, c->befores, c->afters);
        } else {
            hook_t *h = &w->chain.inl;
            sym_line(h->func_addr, tsym, sizeof(tsym));
            sym_line(h->replace_addr, rsym, sizeof(rsym));
            rec_printf("[%d] %-12s fn %016lx %s -> %s\n", count, hook_type_name(w->type),
                       (unsigned long)h->func_addr, tsym, rsym);
        }
    }
    if (!count) rec_printf("(none)\n");
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

    int avail = rec_cap - rec_pos - 64;
    if (avail > DMESG_MAX) avail = DMESG_MAX;
    if (avail <= 0) return;

    char iter[128];
    lib_memset(iter, 0, sizeof(iter));
    if (kd_rewind) kd_rewind(iter);

    rec_printf("--- dmesg tail ---\n");
    size_t len = 0;
    if (kd_getbuf(iter, true, rec_buf + rec_pos, avail, &len)) {
        if ((int)len > avail) len = avail;
        rec_pos += (int)len;
    }
}

void kpstore_tombstone(const char *reason, struct pt_regs *regs)
{
    if (__atomic_exchange_n(&capturing, 1, __ATOMIC_SEQ_CST)) return;
    if (!rec_buf) {
        __atomic_store_n(&capturing, 0, __ATOMIC_SEQ_CST);
        return;
    }
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
    dump_kp();
    dump_modules();
    dump_hooks();
    dump_dmesg();
    rec_printf("==== end tombstone ====\n");

    if (regs) have_regs_record = true;
    persist_write();
    __atomic_store_n(&capturing, 0, __ATOMIC_SEQ_CST);
}

int kpstore_record_read(char *buf, int size)
{
    int n = rec_pos;
    if (size <= 0 || !rec_buf) return 0;
    if (n > size - 1) n = size - 1;
    lib_memcpy(buf, rec_buf, n);
    buf[n] = '\0';
    return n;
}

const char *kpstore_record_data(int *len)
{
    if (len) *len = rec_pos;
    return rec_buf;
}

static kpstore_slot_hdr_t *slot_at(uint64_t base, int i)
{
    return (kpstore_slot_hdr_t *)(base + KPSTORE_HDR_SIZE + (uint64_t)i * KPSTORE_SLOT_SIZE);
}

static uint32_t region_hdr_sum(kpstore_region_hdr_t *rh)
{
    return kpstore_sum(rh, (int)((char *)&rh->sum - (char *)rh));
}

static bool slot_valid(kpstore_slot_hdr_t *sh)
{
    return sh->magic == KPSTORE_SLOT_MAGIC && sh->seq != 0 && sh->comp_len <= KPSTORE_SLOT_PAYLOAD &&
           kpstore_sum((unsigned char *)(sh + 1), sh->comp_len) == sh->sum;
}

static kpstore_region_hdr_t *region_hdr(void)
{
    if (!persist_pa) return 0;
    return (kpstore_region_hdr_t *)phys_to_virt(persist_pa);
}

// the k-th newest valid slot (k = 0 is newest), selecting by monotonic seq
static kpstore_slot_hdr_t *find_level(kpstore_region_hdr_t *rh, int k)
{
    uint64_t threshold = ~0ull;
    kpstore_slot_hdr_t *chosen = 0;
    for (int rank = 0; rank <= k; rank++) {
        kpstore_slot_hdr_t *best = 0;
        uint64_t best_seq = 0;
        for (int i = 0; i < (int)rh->slot_count && i < KPSTORE_SLOT_COUNT; i++) {
            kpstore_slot_hdr_t *sh = slot_at((uint64_t)rh, i);
            if (!slot_valid(sh) || sh->seq >= threshold || sh->seq <= best_seq) continue;
            best = sh;
            best_seq = sh->seq;
        }
        if (!best) return 0;
        chosen = best;
        threshold = best_seq;
    }
    return chosen;
}

// compress the freshly built record into the next ring slot and flush to DRAM
static void persist_write(void)
{
    kpstore_region_hdr_t *rh = region_hdr();
    if (!rh || !rec_buf || !lz4_ws) return;

    if (rh->magic != KPSTORE_REGION_MAGIC || rh->version != KPSTORE_PERSIST_VERSION ||
        rh->slot_size != KPSTORE_SLOT_SIZE || rh->slot_count != KPSTORE_SLOT_COUNT ||
        rh->sum != region_hdr_sum(rh)) {
        rh->magic = KPSTORE_REGION_MAGIC;
        rh->version = KPSTORE_PERSIST_VERSION;
        rh->slot_size = KPSTORE_SLOT_SIZE;
        rh->slot_count = KPSTORE_SLOT_COUNT;
        rh->seq = 0;
        rh->resv = 0;
        rh->sum = region_hdr_sum(rh);
        for (int i = 0; i < KPSTORE_SLOT_COUNT; i++) {
            kpstore_slot_hdr_t *sh = slot_at((uint64_t)rh, i);
            sh->magic = 0;
            sh->seq = 0;
        }
    }

    uint64_t seq = rh->seq;
    kpstore_slot_hdr_t *sh = slot_at((uint64_t)rh, (int)(seq % KPSTORE_SLOT_COUNT));
    unsigned char *payload = (unsigned char *)(sh + 1);
    int cap = (int)KPSTORE_SLOT_PAYLOAD;
    int orig = rec_pos < 0 ? 0 : rec_pos;

    int comp = kp_lz4_compress(rec_buf, orig, payload, cap, lz4_ws);
    uint32_t flags;
    int stored;
    if (comp > 0) {
        flags = KPSTORE_F_LZ4;
        stored = comp;
        sh->orig_len = (uint32_t)orig;
    } else {
        flags = 0;
        stored = orig > cap ? cap : orig;
        lib_memcpy(payload, rec_buf, stored);
        sh->orig_len = (uint32_t)stored;
    }

    sh->flags = flags;
    sh->seq = seq + 1;
    sh->comp_len = (uint32_t)stored;
    sh->sum = kpstore_sum(payload, stored);
    sh->resv = 0;
    sh->magic = KPSTORE_SLOT_MAGIC;

    rh->seq = seq + 1;
    rh->sum = region_hdr_sum(rh);

    __flush_dcache_area(sh, sizeof(*sh) + stored);
    __flush_dcache_area(rh, sizeof(*rh));
}

// decompress the k-th newest persisted record into dec_buf, returns it + len
const char *kpstore_persist_read(int level, int *len)
{
    if (len) *len = 0;
    kpstore_region_hdr_t *rh = region_hdr();
    if (!rh || rh->magic != KPSTORE_REGION_MAGIC || level < 0) return 0;

    kpstore_slot_hdr_t *sh = find_level(rh, level);
    if (!sh) return 0;

    if (!dec_buf) {
        dec_buf = kp_malloc(REC_SIZE);
        if (!dec_buf) return 0;
    }

    unsigned char *payload = (unsigned char *)(sh + 1);
    int n;
    if (sh->flags & KPSTORE_F_LZ4) {
        n = kp_lz4_decompress(payload, (int)sh->comp_len, dec_buf, REC_SIZE);
        if (n < 0) return 0;
    } else {
        n = (int)sh->comp_len;
        if (n > REC_SIZE) n = REC_SIZE;
        lib_memcpy(dec_buf, payload, n);
    }
    if (len) *len = n;
    return dec_buf;
}

// newest persisted record (level 0)
const char *kpstore_persist_data(int *len)
{
    return kpstore_persist_read(0, len);
}

// number of valid persisted records
int kpstore_persist_count(void)
{
    kpstore_region_hdr_t *rh = region_hdr();
    if (!rh || rh->magic != KPSTORE_REGION_MAGIC) return 0;
    int n = 0;
    for (int i = 0; i < (int)rh->slot_count && i < KPSTORE_SLOT_COUNT; i++)
        if (slot_valid(slot_at((uint64_t)rh, i))) n++;
    return n;
}

// erase the k-th newest record, or all of them if level < 0, returns count erased
int kpstore_persist_erase(int level)
{
    kpstore_region_hdr_t *rh = region_hdr();
    if (!rh || rh->magic != KPSTORE_REGION_MAGIC) return 0;

    if (level < 0) {
        int n = 0;
        for (int i = 0; i < KPSTORE_SLOT_COUNT; i++) {
            kpstore_slot_hdr_t *sh = slot_at((uint64_t)rh, i);
            if (sh->magic == KPSTORE_SLOT_MAGIC && sh->seq) {
                sh->magic = 0;
                sh->seq = 0;
                __flush_dcache_area(sh, sizeof(*sh));
                n++;
            }
        }
        return n;
    }

    kpstore_slot_hdr_t *sh = find_level(rh, level);
    if (!sh) return 0;
    sh->magic = 0;
    sh->seq = 0;
    __flush_dcache_area(sh, sizeof(*sh));
    return 1;
}

// reserve the persistent region from memblock, before the buddy handoff. The
// base is a deterministic top-of-DRAM slot derived only from the physical DRAM
// extent -- a hardware constant unaffected by KASLR -- so it is the same
// physical address on every boot, which is what lets the next boot find the
// previous boot's records. The live memblock is the authority for whether it is
// free, and reserving before the buddy handoff keeps the kernel off it
void kpstore_persist_reserve(void)
{
    typedef int (*reserve_t)(uint64_t base, uint64_t size);
    typedef uint64_t (*bound_t)(void);
    typedef int (*region_t)(uint64_t base, uint64_t size);

    reserve_t memblock_reserve = (reserve_t)kallsyms_lookup_name("memblock_reserve");
    bound_t memblock_end_of_DRAM = (bound_t)kallsyms_lookup_name("memblock_end_of_DRAM");
    if (!memblock_reserve || !memblock_end_of_DRAM) return;
    bound_t memblock_start_of_DRAM = (bound_t)kallsyms_lookup_name("memblock_start_of_DRAM");
    region_t is_reserved = (region_t)kallsyms_lookup_name("memblock_is_region_reserved");
    region_t is_memory = (region_t)kallsyms_lookup_name("memblock_is_region_memory");

    uint64_t size = KPSTORE_REGION_SIZE;
    uint64_t align = 0x200000;
    uint64_t end = memblock_end_of_DRAM();
    uint64_t floor = memblock_start_of_DRAM ? memblock_start_of_DRAM() : 0;
    // The top of DRAM is not necessarily free general RAM: on modern Qualcomm/Gunyah
    // SoCs the high banks are secure/hypervisor carveouts, so the old end-of-DRAM slot
    // landed in reserved memory and nothing got reserved. Walk down from the top in
    // align steps and take the highest slot that is real RAM (memblock_is_region_memory)
    // and not already reserved. The memblock layout is stable across boots, so the chosen
    // physical address is deterministic - which is what lets the next boot find it again.
    if (end > size + align && end - size > floor) {
        for (uint64_t base = (end - size) & ~(align - 1); base >= floor && base >= align; base -= align) {
            if (is_memory && !is_memory(base, size)) continue;
            if (is_reserved && is_reserved(base, size)) continue;
            if (memblock_reserve(base, size) == 0) {
                persist_pa = base;
                persist_size = (int)size;
                break;
            }
        }
    }

    if (persist_pa)
        log_boot("kpstore: region pa=%llx size=%x slots=%d\n", persist_pa, persist_size, KPSTORE_SLOT_COUNT);
    else
        log_boot("kpstore: no persistent region reserved\n");
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

// panic() does not walk the die chain - it walks panic_notifier_list with the panic
// message as data (no regs). Capture a tombstone there too, otherwise an explicit
// panic (e.g. SUPERCALL_PANIC) records nothing and survives no reboot.
static int kp_panic_cb(struct kp_notifier_block *nb, unsigned long action, void *data)
{
    (void)nb;
    (void)action;
    kpstore_tombstone(data ? (const char *)data : "panic", 0);
    return 0; // NOTIFY_DONE
}

static struct kp_notifier_block kp_panic_nb = { kp_panic_cb, 0, 0 };

// die notifier covers oopses/faults (with regs); panic notifier covers panic().
void kpstore_crash_init(void)
{
    if (!rec_buf) {
        rec_buf = (char *)kp_malloc(REC_SIZE);
        rec_cap = rec_buf ? REC_SIZE : 0;
    }
    if (!lz4_ws) lz4_ws = kp_malloc(KPLZ4_WORKSPACE_SIZE);

    int (*reg_die)(struct kp_notifier_block *) = (typeof(reg_die))kallsyms_lookup_name("register_die_notifier");
    if (reg_die) reg_die(&kp_die_nb);

    // panic_notifier_list is a struct atomic_notifier_head; the symbol address is the head.
    int (*reg_atomic)(void *, struct kp_notifier_block *) =
        (typeof(reg_atomic))kallsyms_lookup_name("atomic_notifier_chain_register");
    void *panic_list = (void *)kallsyms_lookup_name("panic_notifier_list");
    if (reg_atomic && panic_list) reg_atomic(panic_list, &kp_panic_nb);
}
