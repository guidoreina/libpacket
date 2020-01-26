#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include "net/ip/services.h"
#include "net/ip/dns/message.h"
#include "net/ip/address.h"
#include "pcap/ip/analyzer.h"

template<typename IpAddress, typename L2Header, typename L3Header>
static void process_packet(const net::ip::services& services,
                           const IpAddress& saddr,
                           const IpAddress& daddr,
                           const L2Header* l2hdr,
                           const L3Header* l3hdr,
                           uint16_t payloadlen,
                           uint64_t timestamp,
                           const char* protocol,
                           uint64_t npkt);

static const char* timestamp_to_string(uint64_t timestamp, char* s, size_t len);

int main(int argc, const char** argv)
{
  if (argc == 3) {
    // Load services.
    net::ip::services services;
    if (services.load(argv[1])) {
      // Open PCAP file.
      pcap::ip::analyzer analyzer;
      if (analyzer.open(argv[2])) {
        pcap::ip::analyzer::const_iterator it;
        if (analyzer.begin(it)) {
          uint64_t npkt = 0;

          do {
            npkt++;

            // IPv4?
            if (it->version() == net::ip::version::v4) {
              // TCP?
              if (it->is_tcp()) {
                // If there is payload...
                if (it->has_payload()) {
                  // Process packet.
                  process_packet(services,
                                 it->ipv4()->saddr,
                                 it->ipv4()->daddr,
                                 it->ipv4(),
                                 it->tcp(),
                                 it->l4length(),
                                 it->timestamp(),
                                 "TCP",
                                 npkt);
                }
              } else if (it->is_udp()) {
                // If there is payload...
                if (it->has_payload()) {
                  // DNS response?
                  if (it->udp()->source == net::ip::dns::port) {
                    // Process DNS message.
                    services.process_dns(it->l4(), it->l4length());
                  } else {
                    // Process packet.
                    process_packet(services,
                                   it->ipv4()->saddr,
                                   it->ipv4()->daddr,
                                   it->ipv4(),
                                   it->udp(),
                                   it->l4length(),
                                   it->timestamp(),
                                   "UDP",
                                   npkt);
                  }
                }
              }
            } else {
              // TCP?
              if (it->is_tcp()) {
                // If there is payload...
                if (it->has_payload()) {
                  // Process packet.
                  process_packet(services,
                                 it->ipv6()->ip6_src,
                                 it->ipv6()->ip6_dst,
                                 it->ipv6(),
                                 it->tcp(),
                                 it->l4length(),
                                 it->timestamp(),
                                 "TCP",
                                 npkt);
                }
              } else if (it->is_udp()) {
                // If there is payload...
                if (it->has_payload()) {
                  // DNS response?
                  if (it->udp()->source == net::ip::dns::port) {
                    // Process DNS message.
                    services.process_dns(it->l4(), it->l4length());
                  } else {
                    // Process packet.
                    process_packet(services,
                                   it->ipv6()->ip6_src,
                                   it->ipv6()->ip6_dst,
                                   it->ipv6(),
                                   it->udp(),
                                   it->l4length(),
                                   it->timestamp(),
                                   "UDP",
                                   npkt);
                  }
                }
              }
            }
          } while (analyzer.next(it));
        }

        return 0;
      } else {
        fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[2]);
      }
    }
  } else {
    fprintf(stderr, "Usage: %s <directory> <pcap-file>\n", argv[0]);
  }

  return -1;
}

template<typename IpAddress, typename L2Header, typename L3Header>
void process_packet(const net::ip::services& services,
                    const IpAddress& saddr,
                    const IpAddress& daddr,
                    const L2Header* l2hdr,
                    const L3Header* l3hdr,
                    uint16_t payloadlen,
                    uint64_t timestamp,
                    const char* protocol,
                    uint64_t npkt)
{
  // Find service.
  net::ip::service::identifier id;
  net::ip::service::direction dir;
  if (services.find(l2hdr, l3hdr, id, dir)) {
    const net::ip::address addr((dir == net::ip::service::direction::download) ?
                                  saddr :
                                  daddr);

    // Convert IP address to string.
    char addrstr[INET6_ADDRSTRLEN];
    addr.to_string(addrstr, sizeof(addrstr));

    char timestr[64];

    if (dir == net::ip::service::direction::download) {
      printf("[#%" PRIu64 "] [%s] [%s] %u byte(s) were downloaded from %s "
             "(%s).\n",
             npkt,
             timestamp_to_string(timestamp, timestr, sizeof(timestr)),
             protocol,
             payloadlen,
             services.name(id),
             addrstr);
    } else {
      printf("[#%" PRIu64 "] [%s] [%s] %u byte(s) were uploaded to %s "
             "(%s).\n",
             npkt,
             timestamp_to_string(timestamp, timestr, sizeof(timestr)),
             protocol,
             payloadlen,
             services.name(id),
             addrstr);
    }
  }
}

const char* timestamp_to_string(uint64_t timestamp, char* s, size_t len)
{
  const time_t t = timestamp / 1000000ull;
  struct tm tm;
  localtime_r(&t, &tm);

  snprintf(s,
           len,
           "%04u/%02u/%02u %02u:%02u:%02u.%06u",
           1900 + tm.tm_year,
           1 + tm.tm_mon,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           static_cast<unsigned>(timestamp % 1000000ull));

  return s;
}
