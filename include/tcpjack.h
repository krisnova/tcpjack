// =========================================================================== //
//             Apache2.0 Copyright (c) 2022 Kris Nóva <kris@nivenly.com>       //
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

#ifndef TCPJACK_H
#define TCPJACK_H

#define VERSION "1.0.0"
#define TCP_LIST_SIZE 1024

#include "libnet.h"
#include "pcap.h"

/**
 * A TCP connection which can be instrumented.
 */
struct TCPConn {

};

/**
 * A set of valid TCP connections which can be instrumented.
 */
struct TCPList {
  struct TCPConn conns[TCP_LIST_SIZE];
};

/**
 * List all TCP connections which can be instrumented.
 *
 * @return TCPList A structure containing a list of ESTABLISHED TCP connections
 */
struct TCPList list();

#endif