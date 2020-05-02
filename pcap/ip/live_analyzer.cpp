#include <net/ethernet.h>
#include <net/if_arp.h>
#include "pcap/ip/live_analyzer.h"

bool pcap::ip::live_analyzer::read(net::ip::packet& ippkt)
{
  packet pcappkt;
  if (_M_reader.read(pcappkt)) {
    // First packet?
    if (!_M_process) {
      switch (static_cast<linklayer_header>(_M_reader.linktype())) {
        case linklayer_header::ethernet:
          _M_process = &live_analyzer::process_ethernet;
          break;
        case linklayer_header::raw:
          _M_process = &live_analyzer::process_raw;
          break;
        case linklayer_header::linux_sll:
          _M_process = &live_analyzer::process_linux_sll;
          break;
        default:
          _M_error = true;
          return false;
      }
    }

    // Process packet.
    return (this->*_M_process)(pcappkt, &ippkt);
  }

  return false;
}

bool pcap::ip::live_analyzer::process_raw(const packet& pcappkt,
                                          net::ip::packet* ippkt)
{
  // If the packet is not too big...
  if (pcappkt.length() <= net::ip::packet_max_len) {
    // Check IP version.
    switch (*static_cast<const uint8_t*>(pcappkt.data()) & 0xf0) {
      case 0x40: // IPv4.
        // Process IPv4 packet.
        return _M_parser.process_ipv4(pcappkt.data(),
                                      pcappkt.length(),
                                      pcappkt.timestamp(),
                                      ippkt);
      case 0x60: // IPv6.
        // Process IPv6 packet.
        return _M_parser.process_ipv6(pcappkt.data(),
                                      pcappkt.length(),
                                      pcappkt.timestamp(),
                                      ippkt);
    }
  }

  return false;
}

bool pcap::ip::live_analyzer::process_linux_sll(const packet& pcappkt,
                                                net::ip::packet* ippkt)
{
  // If the packet is neither too small nor too big...
  if ((pcappkt.length() > 16) &&
      (pcappkt.length() <= net::ip::packet_max_len)) {
    const uint8_t* const b = static_cast<const uint8_t*>(pcappkt.data());

    if ((((static_cast<uint16_t>(b[2]) << 8) | b[3]) == ARPHRD_ETHER) &&
        (((static_cast<uint16_t>(b[4]) << 8) | b[5]) == ETH_ALEN)) {
      // The Linux SLL header is two bytes longer than the ethernet header.

      // Process ethernet frame.
      return _M_parser.process_ethernet(b + 2,
                                        pcappkt.length() - 2,
                                        pcappkt.timestamp(),
                                        ippkt);
    }
  }

  return false;
}
