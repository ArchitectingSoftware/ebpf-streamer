#include "vmlinux.h"
//#include <linux/bpf.h>
//#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// #include "syscount.h"
 //#include "maps.bpf.h"

char LICENSE[] SEC("license") = "GPL";  

const volatile pid_t filter_pid = 0;			//set to PID of monitor if you want to exclude these messages
const volatile pid_t monitor_pid = 0; 			//set to PID if you only want to monitor that particular process
const volatile pid_t min_pid_to_monitor = 0;	//set to the minimum pid to monitor
const volatile bool include_monitor_events = false;
const volatile bool use_pid_filter_table = true;
const volatile bool montior_everything = false;


#define MAX_ENTRIES 512

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

			//handle filtering out of the monitor syscalls if enabled
			if (monitor_pid == upid){
				if (!include_monitor_events){
					return 0;
				}
			}

			//now lets look if the pid is in the filter table
			if (use_pid_filter_table){
				u64 upid64 = upid;
				u64 *val;
				
				val = bpf_map_lookup_elem(&pid_filter_table, &upid64);
				if (!val || *val == 0){
					return 0;
				}
			}
		}
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