#include <stddef.h>
#include <string.h>
#include <net/ethernet.h>
#include "net/ip/parser.h"

#ifndef IP_MF
  #define IP_MF      0x2000 // More fragments flag.
#endif

#ifndef IP_OFFMASK
  #define IP_OFFMASK 0x1fff // Mask for fragmenting bits.
#endif

static inline uint16_t fragment_offset(const struct iphdr* iphdr)
{
  return ((ntohs(iphdr->frag_off) & IP_OFFMASK) << 3);
}

static inline bool last_fragment(const struct iphdr* iphdr)
{
  return ((ntohs(iphdr->frag_off) & IP_MF) == 0);
}

static inline uint16_t fragment_offset(const struct ip6_frag* frag)
{
  return ntohs(frag->ip6f_offlg & IP6F_OFF_MASK);
}

static inline bool last_fragment(const struct ip6_frag* frag)
{
  return (ntohs(frag->ip6f_offlg & IP6F_MORE_FRAG) == 0);
}

bool net::ip::parser::process_ethernet(const void* buf,
                                       uint16_t len,
                                       uint64_t timestamp,
                                       packet* pkt)
{
  // If the frame is big enough...
  if (len > sizeof(struct ether_header)) {
    // Make 'b' point to the ether_type.
    const uint8_t* b = static_cast<const uint8_t*>(buf) +
                       (sizeof(struct ether_addr) << 1);

    // Subtract length of the ethernet header.
    len -= sizeof(struct ether_header);

    do {
      // Check ether_type.
      switch ((static_cast<uint16_t>(*b) << 8) | b[1]) {
        case ETH_P_IP:
          return process_ipv4(b + 2, len, timestamp, pkt);
        case ETH_P_IPV6:
          return process_ipv6(b + 2, len, timestamp, pkt);
        case ETH_P_8021Q:
        case ETH_P_8021AD:
          // If the frame is big enough...
          if (len > 4) {
            // Make 'b' point to the ether_type.
            b += 4;

            len -= 4;
          } else {
            return false;
          }

          break;
        case ETH_P_MPLS_UC:
        case ETH_P_MPLS_MC:
          // Skip ether_type.
          b += 2;

          do {
            // If the frame is big enough...
            if (len > 4) {
              // Bottom of the stack?
              if (b[2] & 0x01) {
                switch (((static_cast<uint32_t>(*b) << 12) |
                         (static_cast<uint32_t>(b[1]) << 8) |
                         (static_cast<uint32_t>(b[2]) >> 4)) & 0x0fffff) {
                  case 0: // IPv4.
                    return process_ipv4(b + 4, len - 4, timestamp, pkt);
                  case 2: // IPv6.
                    return process_ipv6(b + 4, len - 4, timestamp, pkt);
                  default:
                    // Check IP version.
                    switch (b[4] & 0xf0) {
                      case 0x40: // IPv4.
                        return process_ipv4(b + 4, len - 4, timestamp, pkt);
                      case 0x60: // IPv6.
                        return process_ipv6(b + 4, len - 4, timestamp, pkt);
                      default:
                        return false;
                    }
                }
              } else {
                // Skip MPLS label.
                b += 4;

                len -= 4;
              }
            } else {
              return false;
            }
          } while (true);

          break;
        default:
          return false;
      }
    } while (true);
  }

  return false;
}

bool net::ip::parser::process_ipv4(const void* buf,
                                   uint16_t len,
                                   uint64_t timestamp,
                                   packet* pkt)
{
  // If the packet is big enough...
  if (len > sizeof(struct iphdr)) {
    const struct iphdr* const iphdr = static_cast<const struct iphdr*>(buf);

    // Compute IP header length.
    const uint16_t iphdrlen = static_cast<uint16_t>(iphdr->ihl) << 2;

    // Compute length of the IP packet.
    const uint16_t iplen = ntohs(iphdr->tot_len);

    // Sanity check.
    if ((iphdrlen >= sizeof(struct iphdr)) &&
        (iphdrlen < len) &&
        (len >= iplen)) {
      // If the packet is not fragmented...
      if ((ntohs(iphdr->frag_off) & (IP_MF | IP_OFFMASK)) == 0) {
        // Save timestamp.
        pkt->_M_timestamp = timestamp;

        // Save length of the IP packet.
        pkt->_M_length = iplen;

        // Save IP version.
        pkt->_M_version = ip::version::v4;

        // Save pointer to the layer 2 protocol.
        pkt->_M_l2.ipv4 = iphdr;

        switch (iphdr->protocol) {
          case IPPROTO_TCP:
            return process_tcp(pkt, iphdrlen);
          case IPPROTO_UDP:
            return process_udp(pkt, iphdrlen);
          case IPPROTO_ICMP:
            return process_icmp(pkt, iphdrlen);
        }
      } else {
        const fragmented_packet* const
          fp = _M_fragmented_packets.add(iphdr,
                                         iphdrlen,
                                         iphdr->id,
                                         timestamp,
                                         fragment_offset(iphdr),
                                         static_cast<const uint8_t*>(buf) +
                                         iphdrlen,
                                         iplen - iphdrlen,
                                         last_fragment(iphdr));

        // If the fragmented packet is now complete and can be built from the
        // individual fragments...
        if ((fp) && (build(fp, pkt))) {
          struct iphdr* iphdr = static_cast<struct iphdr*>(pkt->_M_buf);

          // Set packet length.
          iphdr->tot_len = htons(pkt->_M_length);

          // Clear fragmentation bits.
          iphdr->frag_off = 0;

          // Save IP version.
          pkt->_M_version = ip::version::v4;

          // Save pointer to the layer 2 protocol.
          pkt->_M_l2.ipv4 = iphdr;

          switch (iphdr->protocol) {
            case IPPROTO_TCP:
              return process_tcp(pkt, fp->ip_header_length());
            case IPPROTO_UDP:
              return process_udp(pkt, fp->ip_header_length());
            case IPPROTO_ICMP:
              return process_icmp(pkt, fp->ip_header_length());
          }
        }
      }
    }
  }

  return false;
}

bool net::ip::parser::process_ipv6(const void* buf,
                                   uint16_t len,
                                   uint64_t timestamp,
                                   packet* pkt)
{
  // If the packet is big enough...
  if (len > sizeof(struct ip6_hdr)) {
    // Save timestamp.
    pkt->_M_timestamp = timestamp;

    // Save IP version.
    pkt->_M_version = ip::version::v6;

    do {
      const struct ip6_hdr* const
        iphdr = static_cast<const struct ip6_hdr*>(buf);

      // Get payload length (including extension headers).
      uint16_t payload_length = ntohs(iphdr->ip6_plen);

      // Compute length of the IP packet.
      const uint16_t iplen = sizeof(struct ip6_hdr) + payload_length;

      // Sanity check.
      if (iplen <= len) {
        // Save length of the IP packet.
        pkt->_M_length = iplen;

        // Save pointer to the layer 2 protocol.
        pkt->_M_l2.ipv6 = iphdr;

        uint8_t nxt;
        switch (nxt = iphdr->ip6_nxt) {
          case IPPROTO_TCP:
            return process_tcp(pkt, sizeof(struct ip6_hdr));
          case IPPROTO_UDP:
            return process_udp(pkt, sizeof(struct ip6_hdr));
          case IPPROTO_ICMPV6:
            return process_icmpv6(pkt, sizeof(struct ip6_hdr));
          default:
            if ((is_extension_header(nxt)) &&
                (payload_length >= sizeof(struct ip6_ext))) {
              const struct ip6_frag* frag = nullptr;

              uint16_t off = sizeof(struct ip6_hdr);

              do {
                const struct ip6_ext* const
                  ext = reinterpret_cast<const struct ip6_ext*>(
                          static_cast<const uint8_t*>(buf) + off
                        );

                // Compute length of the extension header.
                const uint16_t extlen = (ext->ip6e_len + 1) << 3;

                if (extlen <= payload_length) {
                  // Make 'off' point after the extension header.
                  off += extlen;

                  // IPv6 fragment?
                  if (nxt == IPPROTO_FRAGMENT) {
                    frag = reinterpret_cast<const struct ip6_frag*>(ext);

                    // Add fragment.
                    const fragmented_packet* const
                      fp = _M_fragmented_packets.add(
                             iphdr,
                             sizeof(struct ip6_hdr),
                             frag->ip6f_ident,
                             timestamp,
                             fragment_offset(frag),
                             static_cast<const uint8_t*>(buf) + off,
                             iplen - off,
                             last_fragment(frag)
                           );

                    // If the fragmented packet is now complete and can be built
                    // from the individual fragments...
                    if ((fp) && (build(fp, pkt))) {
                      struct ip6_hdr*
                        iphdr = static_cast<struct ip6_hdr*>(pkt->_M_buf);

                      // Set payload length.
                      iphdr->ip6_plen = htons(pkt->_M_length -
                                              sizeof(struct ip6_hdr));

                      // Set next protocol.
                      iphdr->ip6_nxt = frag->ip6f_nxt;

                      buf = pkt->_M_buf;
                      len = pkt->_M_length;

                      break;
                    } else {
                      return false;
                    }
                  } else {
                    payload_length -= extlen;

                    nxt = ext->ip6e_nxt;
                  }
                } else {
                  return false;
                }
              } while (is_extension_header(nxt));

              // If it was not a fragment...
              if (!frag) {
                switch (nxt) {
                  case IPPROTO_TCP:
                    return process_tcp(pkt, off);
                  case IPPROTO_UDP:
                    return process_udp(pkt, off);
                  case IPPROTO_ICMPV6:
                    return process_icmpv6(pkt, off);
                  default:
                    return false;
                }
              }
            } else {
              return false;
            }
        }
      } else {
        return false;
      }
    } while (true);
  }

  return false;
}

bool net::ip::parser::process_tcp(packet* pkt, uint16_t iphdrlen)
{
  // If the TCP segment is big enough...
  const uint16_t tcplen = pkt->_M_length - iphdrlen;
  if (tcplen >= sizeof(struct tcphdr)) {
    const struct tcphdr* const
      tcphdr = reinterpret_cast<const struct tcphdr*>(
                 static_cast<const uint8_t*>(pkt->_M_l2.buf) + iphdrlen
               );

    // Compute TCP header length.
    const uint16_t tcphdrlen = static_cast<uint16_t>(tcphdr->doff) << 2;

    // Sanity check.
    if ((tcphdrlen >= sizeof(struct tcphdr)) && (tcphdrlen <= tcplen)) {
      // Save protocol.
      pkt->_M_protocol = IPPROTO_TCP;

      // Save pointer to the layer 3 protocol.
      pkt->_M_l3.tcp = tcphdr;

      // Save pointer to the layer 4 protocol.
      pkt->_M_l4 = reinterpret_cast<const uint8_t*>(tcphdr) + tcphdrlen;

      return true;
    }
  }

  return false;
}

bool net::ip::parser::process_udp(packet* pkt, uint16_t iphdrlen)
{
  // If the UDP datagram is big enough...
  const uint16_t udplen = pkt->_M_length - iphdrlen;
  if (udplen >= sizeof(struct udphdr)) {
    const struct udphdr* const
      udphdr = reinterpret_cast<const struct udphdr*>(
                 static_cast<const uint8_t*>(pkt->_M_l2.buf) + iphdrlen
               );

    // Sanity check.
    if (udplen == ntohs(udphdr->len)) {
      // Save protocol.
      pkt->_M_protocol = IPPROTO_UDP;

      // Save pointer to the layer 3 protocol.
      pkt->_M_l3.udp = udphdr;

      // Save pointer to the layer 4 protocol.
      pkt->_M_l4 = reinterpret_cast<const uint8_t*>(udphdr) +
                   sizeof(struct udphdr);

      return true;
    }
  }

  return false;
}

bool net::ip::parser::process_icmp(packet* pkt, uint16_t iphdrlen)
{
  // If the ICMP datagram is big enough...
  if (static_cast<size_t>(pkt->_M_length - iphdrlen) >=
      sizeof(struct icmphdr)) {
    // Save protocol.
    pkt->_M_protocol = IPPROTO_ICMP;

    // Save pointer to the layer 3 protocol.
    pkt->_M_l3.icmp = reinterpret_cast<const struct icmphdr*>(
                        static_cast<const uint8_t*>(pkt->_M_l2.buf) + iphdrlen
                      );

    // Save pointer to the layer 4 protocol.
    pkt->_M_l4 = static_cast<const uint8_t*>(pkt->_M_l3.buf) +
                 sizeof(struct icmphdr);

    return true;
  }

  return false;
}

bool net::ip::parser::process_icmpv6(packet* pkt, uint16_t iphdrlen)
{
  // If the ICMPv6 datagram is big enough...
  if (static_cast<size_t>(pkt->_M_length - iphdrlen) >=
      sizeof(struct icmp6_hdr)) {
    // Save protocol.
    pkt->_M_protocol = IPPROTO_ICMPV6;

    // Save pointer to the layer 3 protocol.
    pkt->_M_l3.icmpv6 = reinterpret_cast<const struct icmp6_hdr*>(
                          static_cast<const uint8_t*>(pkt->_M_l2.buf) + iphdrlen
                        );

    // Save pointer to the layer 4 protocol.
    pkt->_M_l4 = static_cast<const uint8_t*>(pkt->_M_l3.buf) +
                 sizeof(struct icmp6_hdr);

    return true;
  }

  return false;
}

bool net::ip::parser::build(const fragmented_packet* fp, packet* pkt)
{
  uint8_t* buf;
  if ((buf = static_cast<uint8_t*>(
               realloc(pkt->_M_buf, fp->total_length())
             )) != nullptr) {
    pkt->_M_buf = buf;

    // Copy IP header.
    memcpy(buf, fp->ip_header(), fp->ip_header_length());

    uint16_t len = fp->ip_header_length();

    // For each fragment...
    const fragment* frag;
    for (size_t i = 0; (frag = fp->get(i)) != nullptr; i++) {
      memcpy(buf + len, frag->data(), frag->length());
      len += frag->length();
    }

    pkt->_M_length = len;

    pkt->_M_timestamp = fp->timestamp();

    return true;
  }

  return false;
}
