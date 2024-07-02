#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "syscount.h"
 //#include "maps.bpf.h"

#define PF_KTHREAD		0x00200000

#define FUTEX_SC_NUMBER 98

char LICENSE[] SEC("license") = "GPL";  

const volatile pid_t filter_pid = 0;			//set to PID of monitor if you want to exclude these messages
const volatile pid_t monitor_pid = 0; 			//set to PID if you only want to monitor that particular process
const volatile pid_t min_pid_to_monitor = 0;	//set to the minimum pid to monitor
const volatile bool include_monitor_events = false;
const volatile bool use_pid_filter_table = true;
const volatile bool montior_everything = false;
const volatile bool dynamic_pid_service = false;
const volatile bool eliminate_futex = true;

const volatile bool log_enter_exit = false;
const volatile bool log_syscall = false;

volatile __u64 kernal_sc_count = 0;


#define MAX_ENTRIES 512
#define MAX_PID_ENTRIES 1024

const struct event *unused __attribute__((unused)); 


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} sc_rb SEC(".maps");

#define MAX_ENTRIES 512

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} pid_filter_table SEC(".maps"); 

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PID_ENTRIES);
	__type(key, pid_t);
	__type(value, u32);
} pid_monitor_table SEC(".maps"); 




//Note these are not supported on the rasberry pi, so you need to use the makefile.pi that sets this macro properly
#ifndef _RPI_

static __always_inline pid_t get_userspace_pid() {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
	pid_t upid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);
	return upid;
}

//SEC("tp/sched/sched_process_exit")
//int handle_exit(struct trace_event_raw_sched_process_template* ctx)
SEC("kprobe/do_exit")
int do_exit(struct pt_regs *ctx)
{
	if (!dynamic_pid_service)
		return 0;

    pid_t pid = get_userspace_pid();
	long rc = bpf_map_delete_elem(&pid_monitor_table, &pid);

	if (log_enter_exit){
		if (rc == 0)
			bpf_printk("[DELETE] pid = %d\n", pid);
		else
			bpf_printk("[ERR-DEL] pid = %d, rc = %d\n", pid, rc);
	}

	return 0;
}

//currently SEC("kprobe/do_execve") does not work on arm, need to fall back to syscall
//SEC("kprobe/do_execve")
//int do_exceve(struct pt_regs *ctx)
// //➜  ebpf-streamer git:(main) ✗ sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
struct execve_entry_args_t {
    __u64 _unused;
    __u64 _unused2;

    const char* filename;
    const char* const* argv;
    const char* const* envp;
};
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *ctx)
{
	if (!dynamic_pid_service)
		return 0;

	pid_t pid = get_userspace_pid();
	u32 on = 1;
	
	long rc = bpf_map_update_elem(&pid_monitor_table, &pid, &on, BPF_ANY);

	if (log_enter_exit){
		if (rc == 0)
			bpf_printk("[ADD] pid = %d\n", pid);
		else
			bpf_printk("[ERR-ADD] pid = %d, rc = %d\n", pid, rc);
	}
	return 0;
}
#endif

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
	//At this point we know the pid in the kernel space, we need to get
	//the pid in userland to do useful stuff, this will be collected
	//below and pladed in the upid variable
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
	unsigned int upid = BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

	//here is the system call number
	u32 syscall_id = args->id;


	//DO SOME UP FRONT FILTERING
	//filter out when we get a -1 for a syscall, dont know why this happens but its documented
	//that sometimes ebpf returns -1 for a syscall identifier basically 0xFFFFFFFF
	if(syscall_id == (u32)-1)
		return 0;

	//handle filtering out of the monitor syscalls if enabled
	if (monitor_pid == upid){
		if (!include_monitor_events){
			return 0;
		}
	}

		
	//if monitor everthing is true, montior all syscalls, likely not
	//reccomended but maybe useful for debugging
	if (montior_everything == false){

		//check for more details if we have a min filter flag set.  If the
		//upid is not set aka 0 or is below the min threshold see if some of the
		//other filters hit, if not this is something we want to include
		if ((min_pid_to_monitor == 0) || (upid < min_pid_to_monitor)){
			//quicly short circuit if a value not set, then if it is set check if this is the filter
			//of interest
			if ((filter_pid != 0) && (filter_pid != upid)){
					return 0;
			}

			

			//now lets look if the pid is in the filter table
			if (use_pid_filter_table){
				u32 *val = bpf_map_lookup_elem(&pid_monitor_table, &upid);
				if (!val || *val == 0){
					return 0;
				}
				if (log_syscall){
					bpf_printk("[SYSCALL] pid: %d sc: %d\n", upid, syscall_id);
				}
			}
		}
	}

	if (eliminate_futex && syscall_id == FUTEX_SC_NUMBER){
		return 0;
	}
			
	//END OF FILTERING, this is something we want to stream back to userland
	u64 *task_info;
	task_info = bpf_ringbuf_reserve(&sc_rb, sizeof(u64), 0);
	if (!task_info) {
		return 0;		//problem accessing ringbufer
	}
    //We write into the ringbuffer a 32 bit value, the pid is the upper 32 bits and the
    //syscall is the lower 32 bits
	u64 data = (((u64)upid) << 32) | syscall_id;

	//Now ship it to the ring buffer and exit
	*task_info = data;
	bpf_ringbuf_submit(task_info,0);
	
    //We are now done
	return 0;
}