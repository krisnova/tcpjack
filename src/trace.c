/******************************************************************************\
*                                                                             *
*                     ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗                     *
*                     ████╗  ██║██╔═══██╗██║   ██║██╔══██╗                    *
*                     ██╔██╗ ██║██║   ██║██║   ██║███████║                    *
*                     ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║                    *
*                     ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║                    *
*                     ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝                    *
*               Written By: Kris Nóva    <admin@krisnova.net>                 *
*                                                                             *
\******************************************************************************/

#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "tcpjack.h"

struct TraceEmitionContext {
  int count;
  int jacked_fd;
};

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

/**
 * Emit TCP SYN packets to find the route path.
 *
 * @param vctx
 * @return
 */
void *emit_trace_packets(void *vctx) {
  struct TraceEmitionContext *ctxp = (struct TraceEmitionContext *)vctx;
  struct TraceEmitionContext ctx = *ctxp;
  int ttl = ctx.count;
  for (int i = 0; i <= ctx.count; i++) {
    char *packet;
    struct sockaddr_in saddr = {}; // TODO pull from proc
    struct sockaddr_in daddr = {}; // TODO pull from proc
    int packet_len;
    packet_tcp_syn_ttl(&saddr, &daddr, &packet, &packet_len, ttl--);
    if (sendto(ctx.jacked_fd, packet, packet_len, 0, (struct sockaddr *)&daddr,
               sizeof(struct sockaddr)) != 0) {
      printf("Sent packet=%d, ttl=%d\n", i, ttl);
    } else {
      printf("Error! Unable to send promiscuous TCP SYN packet: %d\n", errno);
    }
    usleep(TIME_MS * 100); // 100ms
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

  // Build our trace context
  struct TraceEmitionContext ctx = {.count = TRACE_SPOOF_COUNT,
                                    .jacked_fd = proc_entry.jacked_fd};

  // Spawn the emit thread
  pthread_create(&th, NULL, emit_trace_packets, (void *)&ctx);

  // Loop and sniff responses
  pthread_join(th, NULL);

  // Assemble trace

  return tps_report;
}

void print_trace_report(struct TraceReport tps_report) {
  //  printf("%s\n", tps_report.proc_entry.comm);
}
