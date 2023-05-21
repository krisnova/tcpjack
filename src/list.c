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

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>

#include "tcpjack.h"

//            46: 010310AC:9C4C 030310AC:1770 01
//        |      |      |      |      |   |--> connection state
//        |      |      |      |      |------> remote TCP port number
//        |      |      |      |-------------> remote IPv4 address
//        |      |      |--------------------> local TCP port number
//        |      |---------------------------> local IPv4 address
//        |----------------------------------> number of entry
//
//              00000150:00000000 01:00000019 00000000
//        |        |     |     |       |--> number of unrecovered RTO timeouts
//        |        |     |     |----------> number of jiffies until timer
//        expires |        |     |----------------> timer_active (see below) |
//        |----------------------> receive-queue
//        |-------------------------------> transmit-queue

/**
 * Implementation for the list() function.
 * Currently only returns connections in TCP_ESTABLISHED state.
 * @return  TCPList
 */
struct TCPList list() {
  struct TCPList tcplist = {};
  char proc_net_tcp[13] = "/proc/net/tcp";
  FILE *f = fopen(proc_net_tcp, "r");
  char line[1024];
  int line_num = 0;  // Line number in the proc file
  int numconns = 0;  // Count of TCP_ESTABLISHED connections
  while (fgets(line, sizeof(line), f)) {
    if (line_num == 0) {
      line_num++;
      continue;
    }
    char sl[4];
    uint32_t local_addr_ipv4;
    int local_addr_port;
    uint32_t rem_addr_ipv4;
    int rem_addr_port;
    unsigned int st;  // TCP Enums are unsigned int
    int tx_queue;
    int rx_queue;
    int tr;
    int tm_when;
    int retrnsmt;
    uid_t uid;
    int timeout;
    ino_t ino;
    fscanf(f, "%s %x:%x %x:%x %i %x:%x %x:%x %x %d %x %lu", sl,
           &local_addr_ipv4, &local_addr_port, &rem_addr_ipv4, &rem_addr_port,
           &st, &tx_queue, &rx_queue, &tr, &tm_when, &retrnsmt, &uid, &timeout,
           &ino);
    // Map TCP_ESTABLISHED conns to API
    if (st == TCP_ESTABLISHED) {
      struct in_addr local_ip;
      local_ip.s_addr = local_addr_ipv4;
      struct in_addr remote_ip;
      remote_ip.s_addr = rem_addr_ipv4;
      struct TCPConn conn = {.ino = ino,
                             .local_addr = local_ip,
                             .local_port = local_addr_port,
                             .remote_addr = remote_ip,
                             .remote_port = rem_addr_port,
                             .uid = uid,
                             .proc_entry = proc_entry_from_ino(ino)};
      tcplist.conns[numconns] = conn;
      numconns++;
    }
  }
  fclose(f);
  tcplist.numconns = numconns;
  return tcplist;
}

/**
 * Simple stdout printing function for the TCPList struct.
 *
 * @param tcplist
 */
void print_list(struct TCPList tcplist) {
  for (int i = 0; i < tcplist.numconns; i++) {
    struct TCPConn conn = tcplist.conns[i];
    struct ProcEntry pentry = conn.proc_entry;
    printf("\x1B[32m%16s (%#06d)\x1B[0m ", pentry.comm, pentry.pid);
    printf("[\x1B[33m%lu\x1B[0m] ", conn.ino);
    printf("%s:%d ", inet_ntoa(conn.local_addr), conn.local_port);
    printf("%2s", " \x1B[33m->\x1B[0m ");
    printf("%s:%d ", inet_ntoa(conn.remote_addr), conn.remote_port);
    printf("\n");
  }
}
