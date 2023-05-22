/******************************************************************************\
 *                                                                            *
 *                    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     *
 *                    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗                    *
 *                    ██╔██╗ ██║██║   ██║██║   ██║███████║                    *
 *                    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    *
 *                    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    *
 *                    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    *
 *              Written By: Kris Nóva    <admin@krisnova.net>                 *
 *                                                                            *
\******************************************************************************/

#include "tcpjack.h"

struct TraceReport trace_ino(ino_t ino){
  struct ProcEntry proc_entry = proc_entry_from_ino(ino);
  return trace_proc_entry(proc_entry);
}

struct TraceReport trace_pid(pid_t pid){
  struct ProcEntry proc_entry = proc_entry_from_pid(pid);
  return trace_proc_entry(proc_entry);
}

struct TraceReport trace_proc_entry(struct ProcEntry proc_entry){
  struct TraceReport tps_report = {
      .proc_entry = proc_entry
  };
  return tps_report;
}

void print_trace_report(struct TraceReport tps_report) {
  printf("%s\n", tps_report.proc_entry.comm);
}
