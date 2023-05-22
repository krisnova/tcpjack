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

#ifndef TCPJACK_H
#define TCPJACK_H

#define VERSION "0.0.2"
#define TCP_LIST_SIZE 1024
#define TRACE_HOP_MAX 32
#define TRACE_SPOOF_COUNT 32
#define TIME_MS 1000

#include <arpa/inet.h>
#include <dirent.h>

#include "libnet.h"
#include "pcap.h"

/**
 * List all TCP connections which can be instrumented.
 *
 * @return TCPList A structure containing a list of ESTABLISHED TCP connections
 */
struct TCPList list();

/**
 * Print a TCP list using tcpjack default printing semantics.
 *
 * @param tcplist
 */
void print_list(struct TCPList tcplist);

/**
 * ProcEntry is a entry from procfs for a given process at runtime.
 */
struct ProcEntry {
  pid_t pid;
  char *comm;
  int tcp_fd;
};

/**
 * A TCP connection which can be instrumented, also
 * an associated ProcEntry for the corresponding process.
 */
struct TCPConn {
  ino_t ino;
  struct in_addr local_addr;
  int local_port;
  struct in_addr remote_addr;
  int remote_port;
  uid_t uid;
  struct ProcEntry proc_entry;
};

/**
 * A set of valid TCP connections which can be instrumented.
 */
struct TCPList {
  int numconns;
  struct TCPConn conns[TCP_LIST_SIZE];
};

struct Hop {
  //
};

struct TraceReport {
  pid_t pid;
  ino_t ino;
  struct ProcEntry proc_entry;
  int numhops;
  struct Hop hops[TRACE_HOP_MAX];
};

struct TraceReport trace_ino(ino_t ino);
struct TraceReport trace_pid(pid_t pid);
struct TraceReport trace_proc_entry(struct ProcEntry proc_entry);
void print_trace_report(struct TraceReport tps_report);

/**
 * Hijack a file descriptor to use for a TCP connection from an inode.
 *
 * @param ino
 * @return
 */
int fd_from_ino(ino_t ino);

/**
 * Will lookup a ProcEntry for a given inode (fd) found in /proc/net/tcp
 *
 * @param ino
 * @return
 */
struct ProcEntry proc_entry_from_ino(ino_t ino);

/**
 * Will lookup a ProcEntry for a give pid.
 *
 * @param pid
 * @return
 */
struct ProcEntry proc_entry_from_pid(pid_t pid);

/**
 * Print a ProcEntry using tcpjack default printing semantics.
 *
 * @param proc_entry
 */
void print_proc_entry(struct ProcEntry proc_entry);

/**
 * Print the asciiheader and version number to stdout.
 */
void asciiheader();

#endif