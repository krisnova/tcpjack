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


struct TCPList list(){
  struct TCPList tcplist = {};

  // Proc
  //   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
  //    0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23292 1 0000000094a97aa1 99 0 0 10 0
  char proc_net_tcp[13] = "/proc/net/tcp";
  FILE *f = fopen(proc_net_tcp, "r");

  char line[1024];
  int line_num = 0;
  while (fgets(line, sizeof(line), f)) {
    if (line_num == 0) {
      line_num++;
      continue;
    }
    // TCP Proc API
    char sl[4];
    char local_address[32];
    char rem_address[32];
    unsigned int st; // TCP Enums are unsigned int
    int tx_queue;
    int rx_queue;
    int tr;
    int tm_when;
    int retrnsmt;
    int uid;
    int timeout;
    int inode;
    fscanf(f, "%s %s %s %x %d:%d %d:%d %d %d  %d %d",
           sl, local_address, rem_address, &st,
           &tx_queue, &rx_queue, &tr, &tm_when,
           &retrnsmt, &uid, &timeout, &inode);
    if (st == TCP_ESTABLISHED) {
      // Found a valid TCP connection
      printf("local_address=%s\n", local_address);
      printf("rem_address=%s\n", rem_address);
      printf("state=TCP_ESTABLISHED\n");
    }
  }

  fclose(f);

  // Sample code
  struct TCPConn c0 = {
      .name = "sample"
  };
  tcplist.conns[0] = c0;
  tcplist.numconns = 1;
  // Sample code



  return tcplist;
}

void print_list(struct TCPList tcplist) {
  for (int i = 0; i < tcplist.numconns; i++) {
    printf("%s\n", tcplist.conns[i].name);
  }
}
