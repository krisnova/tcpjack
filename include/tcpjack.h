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
#define TCP_LIST_SIZE SIZE_1024
#define TRACE_HOP_MAX 32
#define TRACE_SPOOF_COUNT 32
#define TIME_MS 1000
#define DATAGRAM_LEN 4096
#define OPT_SIZE 20

#define SIZE_64 64
#define SIZE_1024 1024

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
  /**
   * The jacked_fd is a 1 to many mapping of socket FDs to a given pid.
   * If this is parsed via an inode it is a specific FD.
   * If this is parsed via a pid, it is the first one found at runtime!
   */
  int jacked_fd;
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

/**
 * Trace by inode
 *
 * @param ino
 * @return
 */
struct TraceReport trace_ino(ino_t ino);

/**
 * Trace by pid (will select the first "socket" in /proc)
 *
 * @param pid
 * @return
 */
struct TraceReport trace_pid(pid_t pid);  // TODO implement this

/**
 * Trace an established TCP connection.
 *
 * @param tcpconn
 * @return
 */
struct TraceReport trace_tcpconn(struct TCPConn tcpconn);

/**
 * Print a tps_report to standard out.
 *
 * @param tps_report
 */
void print_trace_report(struct TraceReport tps_report);

/**
 * Hijack a file descriptor to use for a TCP connection from an inode.
 *
 * @param ino
 * @return
 */
int fd_from_ino(ino_t ino);

/**
 * Hijack a file descriptor to use for a TCP connection from a pid.
 *
 * @param pid
 * @return
 */
int fd_from_pid(pid_t pid);

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
 * Load a TCPConn structure from a given ino.
 *
 * @param ino
 * @return
 */
struct TCPConn tcpconn_from_ino(ino_t ino);

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

/**
 * Create a TCP SYN packet (valid, ttl=64).
 *
 * @param src
 * @param dst
 * @param out_packet
 * @param out_packet_len
 */
void packet_tcp_syn(struct sockaddr_in *src, struct sockaddr_in *dst,
                    char **out_packet, int *out_packet_len);

/**
 * Create a TCP SYN packet with a custom TTL value.
 *
 * @param src
 * @param dst
 * @param out_packet
 * @param out_packet_len
 * @param ttl
 */
void packet_tcp_syn_ttl(struct sockaddr_in *src, struct sockaddr_in *dst,
                        char **out_packet, int *out_packet_len, int ttl);

/**
 * Create a TCP SYN keep-alive packet with a custom TTL value.
 *
 * @param src
 * @param dst
 * @param out_packet
 * @param out_packet_len
 * @param ttl
 */
void packet_tcp_keepalive_ttl(struct sockaddr_in *src, struct sockaddr_in *dst,
                              char **out_packet, int *out_packet_len,
                              uint16_t id, uint32_t known_seq, int ttl);
#endif