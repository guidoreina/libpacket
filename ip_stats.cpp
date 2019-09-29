#include <stdlib.h>
#include <stdio.h>
#include "pcap/ip/analyzer.h"

int main(int argc, const char** argv)
{
  if (argc == 2) {
    pcap::ip::analyzer analyzer;

    // Open PCAP file.
    if (analyzer.open(argv[1])) {
      // Read all packets.
      if (!analyzer.read_all()) {
        fprintf(stderr, "Error reading packets.\n");
        return -1;
      }

      pcap::ip::analyzer::const_iterator it;
      if (analyzer.begin(it)) {
        size_t ipv4 = 0;
        size_t ipv6 = 0;

        size_t tcp = 0;
        size_t udp = 0;
        size_t icmp = 0;
        size_t icmpv6 = 0;

        size_t count = 0;

        do {
          count++;

          if (it->version() == net::ip::version::v4) {
            ipv4++;
          } else {
            ipv6++;
          }

          if (it->is_tcp()) {
            tcp++;
          } else if (it->is_udp()) {
            udp++;
          } else if (it->is_icmp()) {
            icmp++;
          } else if (it->is_icmpv6()) {
            icmpv6++;
          }
        } while (analyzer.next(it));

        printf("# IPv4 packets: %zu (%.2f %%)\n",
               ipv4,
               (static_cast<float>(ipv4) / count) * 100.0);

        printf("# IPv6 packets: %zu (%.2f %%)\n",
               ipv6,
               (static_cast<float>(ipv6) / count) * 100.0);

        printf("# TCP segments: %zu (%.2f %%)\n",
               tcp,
               (static_cast<float>(tcp) / count) * 100.0);

        printf("# UDP datagrams: %zu (%.2f %%)\n",
               udp,
               (static_cast<float>(udp) / count) * 100.0);

        printf("# ICMP datagrams: %zu (%.2f %%)\n",
               icmp,
               (static_cast<float>(icmp) / count) * 100.0);

        printf("# ICMPv6 datagrams: %zu (%.2f %%)\n",
               icmpv6,
               (static_cast<float>(icmpv6) / count) * 100.0);
      } else {
        printf("No packets.\n");
      }

      return 0;
    } else {
      fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return -1;
}
