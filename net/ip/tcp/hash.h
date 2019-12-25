#ifndef NET_IP_TCP_HASH_H
#define NET_IP_TCP_HASH_H

#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include "net/ip/address.h"

namespace net {
  namespace ip {
    namespace tcp {
      // Compute hash.
      static inline uint32_t hash(const struct iphdr* iphdr,
                                  const struct tcphdr* tcphdr)
      {
        static constexpr const uint32_t initval = 0;

        if (tcphdr->source < tcphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->saddr),
                   address::hash(iphdr->daddr),
                   (static_cast<uint32_t>(tcphdr->source) << 16) | tcphdr->dest,
                   initval
                 );
        } else if (tcphdr->source > tcphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->daddr),
                   address::hash(iphdr->saddr),
                   (static_cast<uint32_t>(tcphdr->dest) << 16) | tcphdr->source,
                   initval
                 );
        } else {
          if (iphdr->saddr <= iphdr->daddr) {
            return util::hash::hash_3words(
                     address::hash(iphdr->saddr),
                     address::hash(iphdr->daddr),
                     (static_cast<uint32_t>(tcphdr->source) << 16) |
                       tcphdr->dest,
                     initval
                   );
          } else {
            return util::hash::hash_3words(
                     address::hash(iphdr->daddr),
                     address::hash(iphdr->saddr),
                     (static_cast<uint32_t>(tcphdr->dest) << 16) |
                       tcphdr->source,
                     initval
                   );
          }
        }
      }

      // Compute hash.
      static inline uint32_t hash(const struct ip6_hdr* iphdr,
                                  const struct tcphdr* tcphdr)
      {
        static constexpr const uint32_t initval = 0;

        if (tcphdr->source < tcphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->ip6_src),
                   address::hash(iphdr->ip6_dst),
                   (static_cast<uint32_t>(tcphdr->source) << 16) | tcphdr->dest,
                   initval
                 );
        } else if (tcphdr->source > tcphdr->dest) {
          return util::hash::hash_3words(
                   address::hash(iphdr->ip6_dst),
                   address::hash(iphdr->ip6_src),
                   (static_cast<uint32_t>(tcphdr->dest) << 16) | tcphdr->source,
                   initval
                 );
        } else {
          if (memcmp(&iphdr->ip6_src,
                     &iphdr->ip6_dst,
                     sizeof(struct in6_addr)) <= 0) {
            return util::hash::hash_3words(
                     address::hash(iphdr->ip6_src),
                     address::hash(iphdr->ip6_dst),
                     (static_cast<uint32_t>(tcphdr->source) << 16) |
                       tcphdr->dest,
                     initval
                   );
          } else {
            return util::hash::hash_3words(
                     address::hash(iphdr->ip6_dst),
                     address::hash(iphdr->ip6_src),
                     (static_cast<uint32_t>(tcphdr->dest) << 16) |
                       tcphdr->source,
                     initval
                   );
          }
        }
      }
    }
  }
}

#endif // NET_IP_TCP_HASH_H
