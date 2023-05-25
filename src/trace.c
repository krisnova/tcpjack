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
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
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

void *sniff_replies(void *v) {
  char error[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces, *i;
  pcap_t *handle;
  char error_buffer[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  char filter_exp[] = "icmp";
  bpf_u_int32 subnet_mask, ip;

  // Find a device
  if (pcap_findalldevs(&interfaces, error) == -1) {
    printf("Unable to find default device: %s\n", error);
    return NULL;
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
    return NULL;
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
    return NULL;
  }
  if (pcap_set_promisc(handle, 1) == -1) {
    printf("Unable to set promiscuous mode.\n");
    return NULL;
  }
  if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
    printf("Bad filter - %s\n", pcap_geterr(handle));
    return NULL;
  }
  if (pcap_setfilter(handle, &filter) == -1) {
    printf("Error setting filter - %s\n", pcap_geterr(handle));
    return NULL;
  }

  struct pcap_pkthdr header;
  const u_char *packet;
  int sniff = 1;
  printf(" <- Sniffing the wire for device: %s.\n", dev);
  while (sniff) {
    packet = pcap_next(handle, &header);
    printf(".\n");
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
        printf("     Type: ");

        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
          if (icmp->type == ICMP_ECHO) {
            printf("ping request\n");
          } else if (icmp->type == ICMP_ECHOREPLY) {
            printf("ping reply\n");
          }
          if (packet_length > (sizeof(struct ether_header) +
                               sizeof(struct iphdr) + sizeof(struct icmphdr))) {
            printf("  Payload: ");
            puts((char *)packet +
                 (sizeof(struct ether_header) + sizeof(struct iphdr) +
                  sizeof(struct icmphdr)));
          }
        }
        printf("\n");
      }
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
  printf(" -> Instrumenting the wire.\n");
  struct TraceEmitionContext *ctxp = (struct TraceEmitionContext *)vctx;
  struct TraceEmitionContext ctx = *ctxp;
  // TTL is set to i + 1
  for (int i = 0; i <= ctx.count; i++) {
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

  // Begin to send spoofed packets and listen for replies.
  pthread_t th_emit;
  pthread_t th_sniff;

  // Build our trace context
  struct TraceEmitionContext ctx = {.count = TRACE_SPOOF_COUNT,
                                    .conn = tcpconn};

  // Spawn the emit thread
  pthread_create(&th_emit, NULL, emit_trace_packets, (void *)&ctx);

  // Spawn the sniff thread
  pthread_create(&th_sniff, NULL, sniff_replies, (void *)NULL);

  // Loop and sniff responses
  pthread_join(th_emit, NULL);
  pthread_join(th_sniff, NULL);

  return tps_report;
}

void print_trace_report(struct TraceReport tps_report) {
  //  printf("%s\n", tps_report.proc_entry.comm);
}
