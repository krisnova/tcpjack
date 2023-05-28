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
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <pthread.h>
#include <unistd.h>

#include "tcpjack.h"

#define DEVICE_CAPTURE_FILTER ""  // TODO consider adding "icmp" filter

struct TraceEmitionContext {
  int count;
  struct TCPConn conn;
};

struct TraceSniffContext {
  pcap_t *handle;
  char *dev;
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

void *sniff_replies(void *vctx) {
  struct TraceSniffContext *ctxp = (struct TraceSniffContext *)vctx;
  struct TraceSniffContext ctx = *ctxp;
  struct pcap_pkthdr header;
  pcap_t *handle = ctx.handle;
  char *dev = ctx.dev;
  const u_char *packet;
  int sniff = 1;
  printf(" <- Sniffing the wire on [%s].\n", dev);
  while (sniff) {
    packet = pcap_next(handle, &header);
    printf("?\n");
    int packet_length = header.len;
    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
      struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
      if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp =
            (struct icmphdr *)(packet + sizeof(struct ether_header) +
                               sizeof(struct iphdr));
        printf(" Protocol: ICMP\n");
        printf("     From: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("       To: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

        if (icmp->type == ICMP_TIME_EXCEEDED) {
          if (packet_length > (sizeof(struct ether_header) +
                               sizeof(struct iphdr) + sizeof(struct icmphdr))) {
            printf("  TTL Exceeded Payload: ");
            puts((char *)packet +
                 (sizeof(struct ether_header) + sizeof(struct iphdr) +
                  sizeof(struct icmphdr)));
          }
        }
        printf("\n");

        //        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        //          if (icmp->type == ICMP_ECHO) {
        //            printf("ping request\n");
        //          } else if (icmp->type == ICMP_ECHOREPLY) {
        //            printf("ping reply\n");
        //          }

        //        }else {
        //            printf("Unknown type: %d", icmp->type);
        //        }
      } else {
        printf("Non ICMP packet %d\n", ip->protocol);
      }
    } else {
      printf("Non ethertype IP packet\n");
    }
  }

  return NULL;
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
  printf(" -> Instrumenting the wire using %s TCP connection [%lu]\n",
         ctx.conn.proc_entry.comm, ctx.conn.ino);
  // TTL is set to i + 1
  for (int i = 0; i < ctx.count; i++) {
    // Spoof receiving data from the remote.
    struct msghdr *msg = NULL;
    int size;
    size = recvmsg(ctx.conn.proc_entry.jacked_fd, msg, 0);

    char *packet;
    struct sockaddr_in saddr = {.sin_addr = ctx.conn.local_addr,
                                .sin_port = ctx.conn.local_port};
    struct sockaddr_in daddr = {
        .sin_addr = ctx.conn.remote_addr,
        .sin_port = ctx.conn.remote_port,
    };
    int packet_len;
    packet_tcp_keepalive_ttl(&saddr, &daddr, &packet, &packet_len, i + 1);
    if (ctx.conn.proc_entry.jacked_fd <= 0) {
      printf("Connection dropped!\n");
    }
    if (sendto(ctx.conn.proc_entry.jacked_fd, packet, packet_len, MSG_NOSIGNAL,
               (struct sockaddr *)&daddr, sizeof(struct sockaddr)) <= 0) {
      int err = errno;
      printf("Error: %s\n", strerror(errno));
      if (err == 32) {
        // Broken pipe
        break;
      }
    }
    printf(" -> Emit Packet TTL %d\n", i + 1);
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
  printf("Tracing [%s] (%d)\n", tcpconn.proc_entry.comm,
         tcpconn.proc_entry.pid);

  // Set up pcap
  char error[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  char error_buffer[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  char filter_exp[] = DEVICE_CAPTURE_FILTER;
  bpf_u_int32 subnet_mask, ip;
  pcap_if_t *interfaces, *i;

  // Find a device
  if (pcap_findalldevs(&interfaces, error) == -1) {
    printf("Unable to find default device: %s\n", error);
    return tps_report;
  }
  char *dev;
  int found = 0;
  for (i = interfaces; i != NULL; i = i->next) {
    if (found) break;
    pcap_addr_t *dev_addr;
    for (dev_addr = i->addresses; dev_addr != NULL; dev_addr = dev_addr->next) {
      dev = i->name;

      // Search criteria for interfaces
      if (strstr(dev, "br") != NULL) continue;      // Ignore bridge interfaces
      if (strstr(dev, "docker") != NULL) continue;  // Ignore docker interfaces
      if (strstr(dev, "docker") != NULL) continue;  // Ignore docker interfaces
      if (strstr(dev, "veth") != NULL) continue;    // Ignore veth interfaces
      if (strcmp(dev, "lo") == 0) continue;         // Ignore loopback

      // Quickly filter valid interfaces
      if (dev_addr->addr->sa_family == AF_INET && dev_addr->addr &&
          dev_addr->netmask) {
        found = 1;  // Found it!
        break;
      }
    }
  }
  if (!found) {
    printf("Unable to find suitable device to sniff.\n");
    return tps_report;
  }

  // Start to sniff
  if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
    printf("Could not get information for device: %s\n", dev);
    ip = 0;
    subnet_mask = 0;
  }
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
  if (handle == NULL) {
    printf("Could not open %s - %s\n", dev, error_buffer);
    return tps_report;
  }
  if (pcap_set_promisc(handle, 1) == -1) {
    printf("Unable to set promiscuous mode.\n");
    return tps_report;
  }
  if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
    printf("Bad filter - %s\n", pcap_geterr(handle));
    return tps_report;
  }
  if (pcap_setfilter(handle, &filter) == -1) {
    printf("Error setting filter - %s\n", pcap_geterr(handle));
    return tps_report;
  }

  pthread_t th_emit;
  pthread_t th_sniff;

  // Sniff a packet off the wire, so we can find a sequence number
  int searching = 1;
  const u_char *packet;

  struct pcap_pkthdr header;
  printf("Sniffing existing TCP stream...\n");
  while (searching) {
    packet = pcap_next(handle, &header);
    int packet_length = header.len;
    struct ether_header *eth = (struct ether_header *)packet;
    struct tcphdr *tcp = (struct tcphdr *)packet;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
      struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
      if (ip->protocol == IPPROTO_TCP ) {

          // Compare our IP packet details to what we know is in proc
          // TODO left off here

          // Found a TCP packet
          searching = 0;

      }
    }

  }

  // Spawn the sniff thread
  struct TraceSniffContext sctx = {.handle = handle, .dev = dev};
  pthread_create(&th_sniff, NULL, sniff_replies, (void *)&sctx);

  // Spawn the emit thread
  struct TraceEmitionContext ectx = {.count = TRACE_SPOOF_COUNT,
                                     .conn = tcpconn};
  pthread_create(&th_emit, NULL, emit_trace_packets, (void *)&ectx);

  // Loop and sniff responses
  pthread_join(th_emit, NULL);
  pthread_join(th_sniff, NULL);

  return tps_report;
}

void print_trace_report(struct TraceReport tps_report) {
  //  printf("%s\n", tps_report.proc_entry.comm);
}
