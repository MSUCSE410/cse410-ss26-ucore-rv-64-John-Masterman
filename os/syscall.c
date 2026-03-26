#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

uint64 sys_write(int fd, char *str, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, str, len);
	if (fd != STDOUT)
		return -1;

	uint64 pa = useraddr(curr_proc()->pagetable, (uint64)str);
	if (pa == 0)
		return -1;

	char *kstr = (char *)pa;
	for (int i = 0; i < len; ++i) {
		console_putchar(kstr[i]);
	}
	return len;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	uint64 pa = useraddr(curr_proc()->pagetable, (uint64)val);
	if (pa == 0)
		return -1;

	TimeVal *kval = (TimeVal *)pa;
	uint64 cycle = get_cycle();
	kval->sec = cycle / CPU_FREQ;
	kval->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

uint64 sys_getpid(void)
{
	return curr_proc()->pid;
}

uint64 sys_task_info(TaskInfo *ti)
{
	struct proc *p = curr_proc();

	uint64 pa = useraddr(p->pagetable, (uint64)ti);
	if (pa == 0)
		return -1;

	TaskInfo *kti = (TaskInfo *)pa;
	kti->status = Running;

	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		kti->syscall_times[i] = p->syscall_times[i];
	}

	uint64 now = get_cycle();
	if (p->start_cycle_inited) {
		uint64 elapsed = now - p->start_cycle;
		kti->time = (int)((elapsed * 1000 + CPU_FREQ - 1) / CPU_FREQ);
	} else {
		kti->time = 0;
	}

	return 0;
}


uint64 sys_mmap(uint64 addr, uint64 len, int prot)
{
    struct proc *p = curr_proc();

    if (len == 0)
        return 0;

    if (addr % PAGE_SIZE != 0)
        return -1;

    if ((prot & ~0x7) != 0)
        return -1;

    if ((prot & 0x7) == 0)
        return -1;

    if (addr + len < addr)
        return -1;

    if (addr + len > MAXVA)
        return -1;

    uint64 end = PGROUNDUP(addr + len);
    int perm = PTE_V | PTE_U;
    if (prot & PROT_READ)  perm |= PTE_R;
    if (prot & PROT_WRITE) perm |= PTE_W;
    if (prot & PROT_EXEC)  perm |= PTE_X;

    for (uint64 va = addr; va < end; va += PAGE_SIZE) {
        if (walkaddr(p->pagetable, va) != 0)
            return -1;
    }

    for (uint64 va = addr; va < end; va += PAGE_SIZE) {
        void *mem = kalloc();
        if (mem == 0)
            return -1;

        memset(mem, 0, PAGE_SIZE);

        if (mappages(p->pagetable, va, PAGE_SIZE, (uint64)mem, perm) != 0)
            return -1;
    }

    return 0;
}

uint64 sys_munmap(uint64 addr, uint64 len)
{
    struct proc *p = curr_proc();

    if (len == 0)
        return 0;

    if (addr % PAGE_SIZE != 0)
        return -1;

    if (addr + len < addr)
        return -1;

    if (addr + len > MAXVA)
        return -1;

    uint64 end = PGROUNDUP(addr + len);

    for (uint64 va = addr; va < end; va += PAGE_SIZE) {
        if (walkaddr(p->pagetable, va) == 0)
            return -1;
    }

    for (uint64 va = addr; va < end; va += PAGE_SIZE) {
        uvmunmap(p->pagetable, va, 1, 1);
    }

    return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], (char *)args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}