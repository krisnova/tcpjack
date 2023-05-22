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

#include <pthread.h>
#include <unistd.h>

#include "tcpjack.h"

/**
 * Wrapper function for trace_proc_entry
 *
 * @param ino
 * @return
 */
struct TraceReport trace_ino(ino_t ino) {
  struct ProcEntry proc_entry = proc_entry_from_ino(ino);
  return trace_proc_entry(proc_entry);
}

/**
 * Wrapper function for trace_proc_entry
 *
 * @param pid
 * @return
 */
struct TraceReport trace_pid(pid_t pid) {
  struct ProcEntry proc_entry = proc_entry_from_pid(pid);
  return trace_proc_entry(proc_entry);
}

void *trace_spoof(void *vc) {
  int *cp = (int *)vc;
  int c = *cp;
  for (int i = 0; i <= c; i++) {
    // Send TTL packet here
    usleep(TIME_MS * 100);  // 100ms
  }
  return NULL;
}

/**
 * The main tracing system.
 *
 * Will send spoofed packets across an established TCP connection.
 * Will attempt to sniff the responses off the wire to form a TraceReport.
 *
 * Build on a ProcEntry and network and TCP values will be inferred.
 *
 * @param proc_entry
 * @return
 */
struct TraceReport trace_proc_entry(struct ProcEntry proc_entry) {
  struct TraceReport tps_report = {.proc_entry = proc_entry};
  printf("Tracing [%s] (%d)\n", proc_entry.comm, proc_entry.pid);

  // Begin to send spoofed packets
  pthread_t th;
  int c = TRACE_SPOOF_COUNT;
  pthread_create(&th, NULL, trace_spoof, (void *)&c);

  // Loop and sniff responses
  pthread_join(th, NULL);

  // Assemble trace

  return tps_report;
}

void print_trace_report(struct TraceReport tps_report) {
  //  printf("%s\n", tps_report.proc_entry.comm);
}
