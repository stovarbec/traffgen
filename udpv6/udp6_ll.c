// Send an IPv6 UDP packet via raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// Includes some UDP data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_UDP, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

// Define header length
#define ETH_HDRLEN 14  // Ethernet header length
#define IP6_HDRLEN 40  // IPv6 header length
#define UDP_HDRLEN  8  // UDP header length, no data

#define NOPACKETS 1
// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t udp6_checksum (struct ip6_hdr, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (int argc, char **argv)
{
  int nPack = NOPACKETS;
  nPack = atoi(argv[1]);

  int i, status, datalen, frame_length, sd, bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct udphdr udphdr;
  uint8_t *data, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (INET6_ADDRSTRLEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);

  // Interface to send packet through.
  strcpy (interface, "eth0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: you need to fill these out
  dst_mac[0] = 0xff;
  dst_mac[1] = 0xff;
  dst_mac[2] = 0xff;
  dst_mac[3] = 0xff;
  dst_mac[4] = 0xff;
  dst_mac[5] = 0xff;

  // Source IPv6 address: you need to fill this out
  //strcpy (src_ip, "2001:db8::214:51ff:fe2f:1556");
  strcpy (src_ip, "1111:2222:3333:4444:5555:6666:7777:8888");

  // Destination URL or IPv6 address: you need to fill this out
  strcpy (target, "ipv6.google.com");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = htons (6);

  // UDP data
  datalen = 5;
  data[0] = 'h';
  data[1] = 'o';
  data[2] = 'l';
  data[3] = 'a';
  data[4] = 's';

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): UDP header + UDP data
  iphdr.ip6_plen = htons (UDP_HDRLEN + datalen);

  // Next header (8 bits): 17 for UDP
  iphdr.ip6_nxt = IPPROTO_UDP;

  // Hop limit (8 bits): default to maximum value
  iphdr.ip6_hops = 255;

  // Source IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // UDP header

  // Source port number (16 bits): pick a number
  udphdr.source = htons (12345);

  // Destination port number (16 bits): pick a number
  udphdr.dest = htons (6789);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.len = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits)
  udphdr.check = udp6_checksum (iphdr, udphdr, data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + UDP header + UDP data)
  frame_length = 6 + 6 + 2 + IP6_HDRLEN + UDP_HDRLEN + datalen;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_IPV6 for IPv6).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IPV6 / 256;
  ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is ethernet frame data (IPv6 header + UDP header + UDP data).

  // IPv6 header
  memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

  // UDP header
  memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));

  // UDP data
  memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }
//while(nPack > 0){
int ii;
for (ii=0; ii < nPack; ii++){
  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }
  //nPack--;
}
  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);

  return (EXIT_SUCCESS);
}

// Checksum function
uint16_t
checksum (uint16_t *addr, int len)
{
  int nleft = len;
  int sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (uint16_t);
  }

  if (nleft == 1) {
    *(uint8_t *) (&answer) = *(uint8_t *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

// Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}
