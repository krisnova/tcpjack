// =========================================================================== //
//             Apache2.0 Copyright (c) 2022 Kris Nóva <krisnova@krisnova.net>       //
//                                                                             //
//                 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                 //
//                 ┃   ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗   ┃                 //
//                 ┃   ████╗  ██║██╔═████╗██║   ██║██╔══██╗  ┃                 //
//                 ┃   ██╔██╗ ██║██║██╔██║██║   ██║███████║  ┃                 //
//                 ┃   ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║  ┃                 //
//                 ┃   ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║  ┃                 //
//                 ┃   ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝  ┃                 //
//                 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                 //
//                                                                             //
//                        This machine kills fascists.                         //
//                                                                             //
// =========================================================================== //

#include "tcpjack.h"
#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


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
//        |        |     |     |----------> number of jiffies until timer expires
//        |        |     |----------------> timer_active (see below)
//        |        |----------------------> receive-queue
//        |-------------------------------> transmit-queue

/**
 * Implementation for the list() function.
 * Currently only returns connections in TCP_ESTABLISHED state.
 * @return  TCPList
 */
struct TCPList list(){
  struct TCPList tcplist = {};
  char proc_net_tcp[13] = "/proc/net/tcp";
  FILE *f = fopen(proc_net_tcp, "r");
  char line[1024];
  int line_num = 0; // Line number in the proc file
  int nummconns = 0; // Count of TCP_ESTABLISHED connections
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
    unsigned int st; // TCP Enums are unsigned int
    int tx_queue;
    int rx_queue;
    int tr;
    int tm_when;
    int retrnsmt;
    uid_t uid;
    int timeout;
    unsigned long long inode; // st_ino from asm-generic/stat.h will not support 32 bit
    fscanf(f, "%s %x:%x %x:%x %x %d:%d %d:%d %d %d %d %llu",
           sl, &local_addr_ipv4, &local_addr_port,
           &rem_addr_ipv4, &rem_addr_port, &st,
           &tx_queue, &rx_queue, &tr, &tm_when,
           &retrnsmt, &uid, &timeout, &inode);
    if (st == TCP_ESTABLISHED) {
      struct in_addr local_ip;
      local_ip.s_addr = local_addr_ipv4;
      struct in_addr remote_ip;
      remote_ip.s_addr = rem_addr_ipv4;
      nummconns++;
    }
  }
  fclose(f);

//  // Sample code
//  struct TCPConn c0 = {
//      .name = "sample"
//  };
//  tcplist.conns[0] = c0;
//  tcplist.numconns = 1;
//  // Sample code
//
//
  tcplist.numconns = nummconns;
  return tcplist;
}

void print_list(struct TCPList tcplist) {
  for (int i = 0; i < tcplist.numconns; i++) {
    //      printf("local_address=%s:%d\n", inet_ntoa(local_ip), local_addr_port);
    //      printf("rem_address=%s:%d\n", inet_ntoa(remote_ip), rem_addr_port);
    //      printf("state=TCP_ESTABLISHED\n");
    //      printf("----\n");
    printf("%s\n", tcplist.conns[i].name);
  }
}
