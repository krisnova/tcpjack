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

#ifndef TCPJACK_H
#define TCPJACK_H

#define VERSION "1.0.0"
#define TCP_LIST_SIZE 1024

#include <arpa/inet.h>

#include "libnet.h"
#include "pcap.h"

/**
 * A TCP connection which can be instrumented.
 */
struct TCPConn {
  unsigned long long inode;
  struct in_addr local_addr;
  int local_port;
  struct in_addr remote_addr;
  int remote_port;
  uid_t uid;
};

/**
 * A set of valid TCP connections which can be instrumented.
 */
struct TCPList {
  int numconns;
  struct TCPConn conns[TCP_LIST_SIZE];
};

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

#endif