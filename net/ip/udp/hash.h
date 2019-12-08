#ifndef NET_IP_UDP_HASH_H
#define NET_IP_UDP_HASH_H

#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include "net/ip/address.h"

namespace net {
  namespace ip {
    namespace udp {
      // Compute hash.
      static uint32_t hash(const struct iphdr* iphdr,
                           const struct udphdr* udphdr)
      {
        static constexpr const uint32_t initval = 0;

        if (udphdr->source < udphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->saddr),
                   address::hash(iphdr->daddr),
                   (static_cast<uint32_t>(udphdr->source) << 16) | udphdr->dest,
                   initval
                 );
        } else if (udphdr->source > udphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->daddr),
                   address::hash(iphdr->saddr),
                   (static_cast<uint32_t>(udphdr->dest) << 16) | udphdr->source,
                   initval
                 );
        } else {
          if (iphdr->saddr <= iphdr->daddr) {
            return util::hash::hash_3words(
                     address::hash(iphdr->saddr),
                     address::hash(iphdr->daddr),
                     (static_cast<uint32_t>(udphdr->source) << 16) |
                       udphdr->dest,
                     initval
                   );
          } else {
            return util::hash::hash_3words(
                     address::hash(iphdr->daddr),
                     address::hash(iphdr->saddr),
                     (static_cast<uint32_t>(udphdr->dest) << 16) |
                       udphdr->source,
                     initval
                   );
          }
        }
      }

      // Compute hash.
      static uint32_t hash(const struct ip6_hdr* iphdr,
                           const struct udphdr* udphdr)
      {
        static constexpr const uint32_t initval = 0;

        if (udphdr->source < udphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->ip6_src),
                   address::hash(iphdr->ip6_dst),
                   (static_cast<uint32_t>(udphdr->source) << 16) | udphdr->dest,
                   initval
                 );
        } else if (udphdr->source > udphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->ip6_dst),
                   address::hash(iphdr->ip6_src),
                   (static_cast<uint32_t>(udphdr->dest) << 16) | udphdr->source,
                   initval
                 );
        } else {
          if (memcmp(&iphdr->ip6_src,
                     &iphdr->ip6_dst,
                     sizeof(struct in6_addr)) <= 0) {
            return util::hash::hash_3words(
                     address::hash(iphdr->ip6_src),
                     address::hash(iphdr->ip6_dst),
                     (static_cast<uint32_t>(udphdr->source) << 16) |
                       udphdr->dest,
                     initval
                   );
          } else {
            return util::hash::hash_3words(
                     address::hash(iphdr->ip6_dst),
                     address::hash(iphdr->ip6_src),
                     (static_cast<uint32_t>(udphdr->dest) << 16) |
                       udphdr->source,
                     initval
                   );
          }
        }
      }
    }
  }
}

#endif // NET_IP_UDP_HASH_H
