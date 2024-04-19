#include "sysstream.skel.h"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

static volatile sig_atomic_t exiting = 0;

#define MAX_PIDS 512
#define WRITE_BUFFER_SIZE 1024 * 16

char WRITE_BUFF[WRITE_BUFFER_SIZE];
FILE *OUTPUT_FP;

//GLOBALS & defaults
int MY_PID = 0;
pid_t MIN_PROCESS_ID = 0;
uint64_t SC_COUNTER = 0;
bool INCLUDE_MONITOR_EVENTS = false;
bool VERBOSE_OUTPUT = false;
bool MONITOR_EVERYTHING = false;
bool USE_PID_FILTER_TABLE = true;
bool DYNAMIC_MONITOR=false;
char DEFAULT_FILE_NAME[128] = "sysstream.log";
uint32_t PID_FILTER_TABLE[MAX_PIDS];
uint32_t PID_FILTER_TABLE_SIZE = 0;


struct rb_event{
  uint64_t evnt;
};

static bool check_log_file_overrite(char *filename){
  bool file_exists = false;
  if (access(filename, F_OK) != -1) 
    file_exists = true;

  if (file_exists){
    printf("File %s already exists, do you want to overwrite? (Y/n): ", filename);
    char c = getchar();
    if ((c == 'Y')||(c == 'y')){
      scanf("%*c"); //clear buffer
      printf("\nAre you sure? (Y/n): ");
      c = getchar();
      printf("\n");
      if ((c == 'Y')||(c == 'y'))
        return true;
      else
        return false;
    } 
  }
  //file did not exist, just overwrite
  return true;
}

static void initParams(int argc, char *argv[]){
  int option;
  int count = 1;
  while ((option = getopt(argc, argv, ":f:l:mphvad")) != -1){
    printf("OPTION %c\n", option);
    switch(option) {
        case 'f':
            strncpy(DEFAULT_FILE_NAME, 
                optarg, sizeof(DEFAULT_FILE_NAME) - 1);
            count += 2;
            break;
        case 'l':
            MIN_PROCESS_ID = atoi(optarg);
            count += 2;
            break;
        case 'm':
            INCLUDE_MONITOR_EVENTS = true;
            count++;
            break;
        case 'p':
            USE_PID_FILTER_TABLE = false;
            count++;
            break;
        case 'v':
            VERBOSE_OUTPUT = true;
            count++;
            break;
        case 'a':
            MONITOR_EVERYTHING = true;
            count++;
            break;
        case 'd':
            DYNAMIC_MONITOR = true;
            count++;
            break;
        case 'h':
            printf("Usage: %s [-f <file>] [-m] [-v] [-h] [PID_LIST...]\n", argv[0]);
            printf("Options:\n");
            printf("  -f <file>  : Output file name (default: sysstream.log)\n");
            printf("  -l <pid>   : Lower bound pid to monitor, all pid above will be collected\n");
            printf("  -m         : Include monitor events (by default always excluded) \n");
            printf("  -v         : Display verbose output\n");
            printf("  -a         : Monitor everything overrides all filters\n");
            printf("  -d         : Dynamic all new processes created\n");
            printf("  -h         : Display this help message\n\n");
            printf("  PID_LIST   : Comma seperated list of PIDs to monitor\n\n");
            exit(0);
            break;
        case ':':
            fprintf(stderr, "Option -%c requires an argument\n", optopt);
            exit(1);
            break;
        case '?':
            fprintf(stderr, "Unrecognized option: -%c\n", optopt);
            exit(1);
            break;
    }
  }
  PID_FILTER_TABLE_SIZE = argc - count;

  for (int i = count; i < argc; i++){
    PID_FILTER_TABLE[i-count] = atoi(argv[i]); //argv[0] is the program name
  }
  printf("DUMPING ARGS \n");
  printf("DEFAULT_FILE_NAME: %s\n", DEFAULT_FILE_NAME);
  printf("INCLUDE_MONITOR_EVENTS: %d\n", INCLUDE_MONITOR_EVENTS);
  printf("USE_PID_FILTER_TABLE: %d\n", USE_PID_FILTER_TABLE);
  printf("PID_FILTER_TABLE_SIZE: %d\n", PID_FILTER_TABLE_SIZE);
  printf("MONITOR_EVERYTHING: %d\n", MONITOR_EVERYTHING);
  printf("VERBOSE_OUTPUT: %d\n", VERBOSE_OUTPUT);
  printf("MIN_PROCESS_ID: %d\n", MIN_PROCESS_ID);
  for (int i = 0; i < PID_FILTER_TABLE_SIZE; i++){
    printf("\t- %d. pid to monitor: %d\n", i,PID_FILTER_TABLE[i]);
  }

  OUTPUT_FP = fopen(DEFAULT_FILE_NAME, "w");
}

//THIS IS THE CALLBACK WHENEVER A SYSTEMCALL IS MADE
static int sc_callback(void *ctx, void *data, size_t len) {
  struct rb_event *evt = (struct rb_event *)data;
  
  uint64_t edata = evt->evnt;
  uint32_t pid = edata >> 32;
  uint32_t syscall_id = edata & 0xFFFFFFFF;

  //NOTE YOU CAN CHANGE THE DELIMITER IF YOU WANT, I SET IT TO TAB
  fprintf(OUTPUT_FP, "%lx\t", edata);

  SC_COUNTER++;
  if (VERBOSE_OUTPUT)
    printf("pid: %d sc: %d log:%lx\n", pid, syscall_id, edata);
  else
    if (SC_COUNTER % 100 == 0)
      printf("Total system calls processed: %ld\r", SC_COUNTER);
  return 0;
}

//ADD PID TO THE LIST OF FILTERS BEING WATCHED BY THE EBPF PROGRAM
int add_pid__to_filter_DELETE(struct sysstream_bpf *skel, uint32_t pid){
  uint64_t constant_one = 1;
  uint64_t u64sz = sizeof(uint64_t);
  uint64_t u64pid = pid;
  
  return bpf_map__update_elem(skel->maps.pid_filter_table, 
      &u64pid, u64sz, &constant_one, u64sz, BPF_ANY);
}

int add_pid__to_filter(struct sysstream_bpf *skel, pid_t pid){
  uint32_t constant_one = 1;
  size_t pid_sz = sizeof(pid_t);
  size_t u32_sz = sizeof(uint32_t);
  pid_t mpid = pid;
  
  return bpf_map__update_elem(skel->maps.pid_monitor_table, 
      &mpid, pid_sz, &constant_one, u32_sz, BPF_ANY);
}


int main(int argc, char **argv) {
  int err;
  struct sysstream_bpf *skel;
  struct ring_buffer *rb = NULL;
  int ret;

  //SET MY_PID GLOBAL, INITIALIZE
  MY_PID = getpid();
  printf("MY PID: %d\n", getpid());
  initParams(argc, argv);       //get command line info

  //CHECK IF FILE EXISTS, PROMPT TO OVERWRITE
  if (!check_log_file_overrite(DEFAULT_FILE_NAME)){
    printf("\nExiting to avoid overrite of log file...\n");
    return 0;
  }

  //1. OPEN the EBPF Handler
  skel = sysstream_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF program\n");
    return 1;
  }

  //1.a PRE-Initialize the EBPF Handler BEFORE Loading
  skel->rodata->monitor_pid = getpid(); 
  skel->rodata->include_monitor_events = INCLUDE_MONITOR_EVENTS;
  skel->rodata->montior_everything = MONITOR_EVERYTHING;
  skel->rodata->min_pid_to_monitor = MIN_PROCESS_ID;
  skel->rodata->dynamic_pid_service = DYNAMIC_MONITOR;
  
  //2. LOAD the EBPF Handler INTO Kernel
  err = sysstream_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF program: %d\n", err);
    return 1;
  }

  //2a. SETUP THE PID FILTERS AFTER LOADED INTO KERNEL
  for(int i = 0; i < PID_FILTER_TABLE_SIZE; i++){
    int rc = add_pid__to_filter(skel, PID_FILTER_TABLE[i]);
    if(rc < 0){
      fprintf(stderr, "Failed to add pid to filter\n");
      return 1;
    }
  } 

  

  //3. ATTACH the EBPF Handler
  err = sysstream_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF program: %d\n", err);
    return 1;
  }

  //4. Hook onto the ring buffer, set the callback handler
  rb = ring_buffer__new(bpf_map__fd(skel->maps.sc_rb), sc_callback, NULL, NULL);
  if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		sysstream_bpf__destroy(skel);
        return 1;
	}
  

  //NOW START CONSUMING EVENTS
  printf("Successfully started tracing, hit Ctrl-C to terminate\n");
  //CONSUME Events until interrupted
  while (!exiting) {
    ret = ring_buffer__consume(rb);
    if (ret < 0) {
      if (ret == -EINTR) {
          // Interrupted, maybe by a signal
          break;
      }
      perror("Failed to consume data from ring buffer");
      break;
    }
    sleep(1);
  }
  printf("\n");
  printf("Cleaning up...\n ");
  //CLEANUP
  //Free the resources
  ring_buffer__free(rb);
  sysstream_bpf__detach(skel);
  sysstream_bpf__destroy(skel);

  printf("Total system calls processed: %ld\n", SC_COUNTER);

  //close output file
  fflush(OUTPUT_FP);
  fclose(OUTPUT_FP);
  return 0;
}
