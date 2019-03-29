/*
 *  arch/s390/kernel/time.c
 *    Time of day based timer functions.
 *
 *  S390 version
 *    Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Hartmut Penner (hp@de.ibm.com),
 *               Martin Schwidefsky (schwidefsky@de.ibm.com),
 *               Denis Joseph Barrow (djbarrow@de.ibm.com,barrow_dj@yahoo.com)
 *
 *  Derived from "arch/i386/kernel/time.c"
 *    Copyright (C) 1991, 1992, 1995  Linus Torvalds
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/profile.h>
#include <linux/timex.h>
#include <linux/notifier.h>
#include <linux/clocksource.h>

#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/s390_ext.h>
#include <asm/div64.h>
#include <asm/irq.h>
#include <asm/irq_regs.h>
#include <asm/timer.h>

/* change this if you have some constant time drift */
#define USECS_PER_JIFFY     ((unsigned long) 1000000/HZ)
#define CLK_TICKS_PER_JIFFY ((unsigned long) USECS_PER_JIFFY << 12)

/*
 * Create a small time difference between the timer interrupts
 * on the different cpus to avoid lock contention.
 */
#define CPU_DEVIATION       (smp_processor_id() << 12)

#define TICK_SIZE tick

static ext_int_info_t ext_int_info_cc;
static u64 init_timer_cc;
static u64 jiffies_timer_cc;
static u64 xtime_cc;

/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	return ((get_clock() - jiffies_timer_cc) * 125) >> 9;
}

/*
 * Monotonic_clock - returns # of nanoseconds passed since time_init()
 */
unsigned long long monotonic_clock(void)
{
	return sched_clock();
}
EXPORT_SYMBOL(monotonic_clock);

void tod_to_timeval(__u64 todval, struct timespec *xtime)
{
	unsigned long long sec;

	sec = todval >> 12;
	do_div(sec, 1000000);
	xtime->tv_sec = sec;
	todval -= (sec * 1000000) << 12;
	xtime->tv_nsec = ((todval * 1000) >> 12);
}

#ifdef CONFIG_PROFILING
#define s390_do_profile()	profile_tick(CPU_PROFILING)
#else
#define s390_do_profile()	do { ; } while(0)
#endif /* CONFIG_PROFILING */


/*
 * timer_interrupt() needs to keep up the real-time clock,
 * as well as call the "do_timer()" routine every clocktick
 */
void account_ticks(void)
{
	__u64 tmp;
	__u32 ticks;

	/* Calculate how many ticks have passed. */
	if (S390_lowcore.int_clock < S390_lowcore.jiffy_timer) {
		/*
		 * We have to program the clock comparator even if
		 * no tick has passed. That happens if e.g. an i/o
		 * interrupt wakes up an idle processor that has
		 * switched off its hz timer.
		 */
		tmp = S390_lowcore.jiffy_timer + CPU_DEVIATION;
		asm volatile ("SCKC %0" : : "m" (tmp));
		return;
	}
	tmp = S390_lowcore.int_clock - S390_lowcore.jiffy_timer;
	if (tmp >= 2*CLK_TICKS_PER_JIFFY) {  /* more than two ticks ? */
		ticks = __div(tmp, CLK_TICKS_PER_JIFFY) + 1;
		S390_lowcore.jiffy_timer +=
			CLK_TICKS_PER_JIFFY * (__u64) ticks;
	} else if (tmp >= CLK_TICKS_PER_JIFFY) {
		ticks = 2;
		S390_lowcore.jiffy_timer += 2*CLK_TICKS_PER_JIFFY;
	} else {
		ticks = 1;
		S390_lowcore.jiffy_timer += CLK_TICKS_PER_JIFFY;
	}

	/* set clock comparator for next tick */
	tmp = S390_lowcore.jiffy_timer + CPU_DEVIATION;
        asm volatile ("SCKC %0" : : "m" (tmp));

#ifdef CONFIG_SMP
	/*
	 * Do not rely on the boot cpu to do the calls to do_timer.
	 * Spread it over all cpus instead.
	 */
	write_seqlock(&xtime_lock);
	if (S390_lowcore.jiffy_timer > xtime_cc) {
		__u32 xticks;
		tmp = S390_lowcore.jiffy_timer - xtime_cc;
		if (tmp >= 2*CLK_TICKS_PER_JIFFY) {
			xticks = __div(tmp, CLK_TICKS_PER_JIFFY);
			xtime_cc += (__u64) xticks * CLK_TICKS_PER_JIFFY;
		} else {
			xticks = 1;
			xtime_cc += CLK_TICKS_PER_JIFFY;
		}
		do_timer(xticks);
	}
	write_sequnlock(&xtime_lock);
#else
	do_timer(ticks);
#endif

#ifdef CONFIG_VIRT_CPU_ACCOUNTING
	account_tick_vtime(current);
#else
	while (ticks--)
		update_process_times(user_mode(get_irq_regs()));
#endif

	s390_do_profile();
}

#ifdef CONFIG_NO_IDLE_HZ

#ifdef CONFIG_NO_IDLE_HZ_INIT
int sysctl_hz_timer = 0;
#else
int sysctl_hz_timer = 1;
#endif

/*
 * Stop the HZ tick on the current CPU.
 * Only cpu_idle may call this function.
 */
static inline void stop_hz_timer(void)
{
	unsigned long flags;
	unsigned long seq, next;
	__u64 timer, todval;
	int cpu = smp_processor_id();

	if (sysctl_hz_timer != 0)
		return;

	cpu_set(cpu, nohz_cpu_mask);

	/*
	 * Leave the clock comparator set up for the next timer
	 * tick if either rcu or a softirq is pending.
	 */
	if (rcu_needs_cpu(cpu) || local_softirq_pending()) {
		cpu_clear(cpu, nohz_cpu_mask);
		return;
	}

	/*
	 * This cpu is going really idle. Set up the clock comparator
	 * for the next event.
	 */
	next = next_timer_interrupt();
	do {
		seq = read_seqbegin_irqsave(&xtime_lock, flags);
		timer = ((__u64) next) - ((__u64) jiffies) + jiffies_64;
	} while (read_seqretry_irqrestore(&xtime_lock, seq, flags));
	todval = -1ULL;
	/* Be careful about overflows. */
	if (timer < (-1ULL / CLK_TICKS_PER_JIFFY)) {
		timer = jiffies_timer_cc + timer * CLK_TICKS_PER_JIFFY;
		if (timer >= jiffies_timer_cc)
			todval = timer;
	}
	asm volatile ("SCKC %0" : : "m" (todval));
}

/*
 * Start the HZ tick on the current CPU.
 * Only cpu_idle may call this function.
 */
static inline void start_hz_timer(void)
{
	BUG_ON(!in_interrupt());

	if (!cpu_isset(smp_processor_id(), nohz_cpu_mask))
		return;
	account_ticks();
	cpu_clear(smp_processor_id(), nohz_cpu_mask);
}

static int nohz_idle_notify(struct notifier_block *self,
			    unsigned long action, void *hcpu)
{
	switch (action) {
	case CPU_IDLE:
		stop_hz_timer();
		break;
	case CPU_NOT_IDLE:
		start_hz_timer();
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block nohz_idle_nb = {
	.notifier_call = nohz_idle_notify,
};

void __init nohz_init(void)
{
	if (register_idle_notifier(&nohz_idle_nb))
		panic("Couldn't register idle notifier");
}

#endif

/*
 * Start the clock comparator on the current CPU.
 */
void init_cpu_timer(void)
{
	unsigned long cr0;
	__u64 timer;

	timer = jiffies_timer_cc + jiffies_64 * CLK_TICKS_PER_JIFFY;
	S390_lowcore.jiffy_timer = timer + CLK_TICKS_PER_JIFFY;
	timer += CLK_TICKS_PER_JIFFY + CPU_DEVIATION;
	asm volatile ("SCKC %0" : : "m" (timer));
        /* allow clock comparator timer interrupt */
	__ctl_store(cr0, 0, 0);
        cr0 |= 0x800;
	__ctl_load(cr0, 0, 0);
}

extern void vtime_init(void);

static cycle_t read_tod_clock(void)
{
	return get_clock();
}

static struct clocksource clocksource_tod = {
	.name		= "tod",
	.rating		= 100,
	.read		= read_tod_clock,
	.mask		= -1ULL,
	.mult		= 1000,
	.shift		= 12,
	.is_continuous	= 1,
};


/*
 * Initialize the TOD clock and the CPU timer of
 * the boot cpu.
 */
void __init time_init(void)
{
	__u64 set_time_cc;
	int cc;

        /* kick the TOD clock */
	asm volatile(
		"	stck	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc), "=m" (init_timer_cc)
		: "a" (&init_timer_cc) : "cc");
        switch (cc) {
        case 0: /* clock in set state: all is fine */
                break;
        case 1: /* clock in non-set state: FIXME */
                printk("time_init: TOD clock in non-set state\n");
                break;
        case 2: /* clock in error state: FIXME */
                printk("time_init: TOD clock in error state\n");
                break;
        case 3: /* clock in stopped or not-operational state: FIXME */
                printk("time_init: TOD clock stopped/non-operational\n");
                break;
        }
	jiffies_timer_cc = init_timer_cc - jiffies_64 * CLK_TICKS_PER_JIFFY;

	/* set xtime */
	xtime_cc = init_timer_cc + CLK_TICKS_PER_JIFFY;
	set_time_cc = init_timer_cc - 0x8126d60e46000000LL +
		(0x3c26700LL*1000000*4096);
        tod_to_timeval(set_time_cc, &xtime);
        set_normalized_timespec(&wall_to_monotonic,
                                -xtime.tv_sec, -xtime.tv_nsec);

	/* request the clock comparator external interrupt */
	if (register_early_external_interrupt(0x1004, NULL,
					      &ext_int_info_cc) != 0)
                panic("Couldn't request external interrupt 0x1004");

	if (clocksource_register(&clocksource_tod) != 0)
		panic("Could not register TOD clock source");

        init_cpu_timer();

#ifdef CONFIG_NO_IDLE_HZ
	nohz_init();
#endif

#ifdef CONFIG_VIRT_TIMER
	vtime_init();
#endif
}

