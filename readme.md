## SysStream - an eBPF Utility

Run `systream -h`:  

```bash
Usage: ./sysstream [-f <file>] [-m] [-v] [-h] [PID_LIST...]
Options:
  -f <file>  : Output file name (default: sysstream.log)
  -m         : Include monitor events
  -v         : Display verbose output
  -h         : Display this help message

  PID_LIST   : Comma seperated list of PIDs to monitor
```

This program will use eBPF to monitor system calls from the processes that are specified on the command line.  You really dont want to blindly monitor all processes, you want to filter them.

All output is sent to a log file that can be renamed with the `-f` option. The
default delimeter for the output file records is a `\t`.  This can be altered in the `sc_callback()` function.

There is a lot of room for improvement with the code (e.g., global variables) but its a helpful utility that I thought I would share.

Example:

```bash
sudo ./sysstream 32076 31996 
```

The above will run the utility and monitor system calls for processes `32076` and `31996`.  It will write to the default log file `sysstream.log`.

#### Building
The provided `makefile` should handle everything.  Basically it first generates `vmlinux.h` which is a header specific to the linux kernel version you are using.  From there it compiles the `sysstream.bpf.c` program.  After that it takes the output elf file `sysstream.bpf.o` and via the `bpftool` generates helper functions via creating the `sysstream.skel.h` file.  At this point everything is created to compile the userspace program `sysstream.c`. Simply run `make` to build, and `make clean` to clean up all of the generated files. 

### Log output format
As mentioned above the log output format is delimited by a tab.  The log records record a stream of events from the linux kernel.   You can assume the events are in order.  Each log record is a 64 bit hex number.  The upper 32 bits are the process id and the lower 32 bits are the system call numeber.  For example a log record: of `7cfc00000062` would be split into `0x7cfc` and `0x62`.  Converting to decimal would result in `pid:31996` making `system_call:98`

### Requirements
This code assumes you have a working eBPF development environment on your system including tools like `gcc`, `clang`, `bpftool`, etc.  There are many references out there, but you will need to have this done before compiling and using this tool.  Not to mention you need admin rights, `sudo` to run this program given it uses eBPF.

