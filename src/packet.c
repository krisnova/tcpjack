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
/*
 * Original code taken from boopkit packet.c
 *
 * This file is a simplified alternative to libnet that allows for quick work
 * of creating custom TCP packets.
 */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>

#include "tcpjack.h"

struct pseudo_header {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

unsigned short csum(const char *buf, unsigned size) {
  unsigned sum = 0, i;
  for (i = 0; i < size - 1; i += 2) {
    unsigned short word16 = *(unsigned short *)&buf[i];
    sum += word16;
  }
  if (size & 1) {
    unsigned short word16 = (unsigned char)buf[i];
    sum += word16;
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

void packet_tcp_syn(struct sockaddr_in *src, struct sockaddr_in *dst,
                    char **out_packet, int *out_packet_len) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48);  // mss value
  memcpy(datagram + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;
  // do the same for the pseudo header
  pseudogram[32] = 0x02;
  pseudogram[33] = 0x04;
  memcpy(pseudogram + 34, &mss, sizeof(int16_t));
  pseudogram[36] = 0x04;
  pseudogram[37] = 0x02;

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void packet_tcp_syn_ttl(struct sockaddr_in *src, struct sockaddr_in *dst,
                        char **out_packet, int *out_packet_len, int ttl) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = ttl;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48);  // mss value
  memcpy(datagram + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;
  // do the same for the pseudo header
  pseudogram[32] = 0x02;
  pseudogram[33] = 0x04;
  memcpy(pseudogram + 34, &mss, sizeof(int16_t));
  pseudogram[36] = 0x04;
  pseudogram[37] = 0x02;

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void packet_tcp_keepalive_ttl(struct sockaddr_in *src, struct sockaddr_in *dst,
                        char **out_packet, int *out_packet_len, int ttl) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = ttl;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0; // keepalive
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}