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
  struct TCPConn conn;
};

/**
 * Wrapper function for trace_proc_entry
 *
 * @param ino
 * @return
 */
struct TraceReport trace_ino(ino_t ino) {
  struct TCPConn tcpconn = tcpconn_from_ino(ino);
  return trace_tcpconn(tcpconn);
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
  // TTL is set to i + 1
  for (int i = 0; i <= ctx.count; i++) {
    printf("iter=%d\n", i);
    char *packet;
    struct sockaddr_in saddr = {
        .sin_addr = ctx.conn.local_addr,
        .sin_port = ctx.conn.local_port
    };
    struct sockaddr_in daddr = {
        .sin_addr = ctx.conn.remote_addr,
        .sin_port = ctx.conn.remote_port,
    };
    int packet_len;
    packet_tcp_keepalive_ttl(&saddr, &daddr, &packet, &packet_len, i + 1);
    printf("-\n");
    if (sendto(ctx.conn.proc_entry.jacked_fd, packet, packet_len, 0, (struct sockaddr *)&daddr,
               sizeof(struct sockaddr)) != 0) {
      printf("Sent packet ttl=%d\n", i + 1);
    } else {
      printf("Error!\n");
      printf("Unable to send promiscuous TCP SYN packet: %d\n", errno);
    }
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
 * @param tcpconn
 * @return
 */
struct TraceReport trace_tcpconn(struct TCPConn tcpconn) {
  struct TraceReport tps_report = {
      .proc_entry = tcpconn.proc_entry,
      .pid = tcpconn.proc_entry.pid,
      .ino = tcpconn.ino,
  };
  printf("Tracing [%s] (%d)\n", tcpconn.proc_entry.comm, tcpconn.proc_entry.pid);

  // Begin to send spoofed packets
  pthread_t th;

  // Build our trace context
  struct TraceEmitionContext ctx = {.count = TRACE_SPOOF_COUNT, .conn = tcpconn};

  // Spawn the emit thread
  pthread_create(&th, NULL, emit_trace_packets, (void *)&ctx);

  // Loop and sniff responses
  pthread_join(th, NULL);

  // Assemble trace
  // TODO libpcap

  return tps_report;
}

void print_trace_report(struct TraceReport tps_report) {
  //  printf("%s\n", tps_report.proc_entry.comm);
}
