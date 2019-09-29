#include <net/ethernet.h>
#include <net/if_arp.h>
#include "pcap/ip/analyzer.h"

bool pcap::ip::analyzer::open(const char* filename)
{
  // Open PCAP file.
  if (_M_reader.open(filename)) {
    _M_begin = &analyzer::begin_iterator;
    _M_next = &analyzer::next_iterator;
    _M_end = &analyzer::end_iterator;
    _M_prev = &analyzer::prev_iterator;

    // Check link-layer header type.
    switch (static_cast<linklayer_header>(_M_reader.linktype())) {
      case linklayer_header::ethernet:
        _M_process = &analyzer::process_ethernet;
        return true;
      case linklayer_header::raw:
        _M_process = &analyzer::process_raw;
        return true;
      case linklayer_header::linux_sll:
        _M_process = &analyzer::process_linux_sll;
        return true;
    }
  }

  return false;
}

bool pcap::ip::analyzer::read_all()
{
  // Get first packet of the PCAP file.
  packet pcappkt;
  if (_M_reader.begin(pcappkt)) {
    net::ip::packet* ippkt = nullptr;

    do {
      // Get a new packet (if needed).
      if ((ippkt) || ((ippkt = _M_packets.get()) != nullptr)) {
        // Process packet.
        if ((this->*_M_process)(pcappkt, ippkt)) {
          // Add packet.
          if (_M_packets.add(ippkt)) {
            ippkt = nullptr;
          } else {
            delete ippkt;

            return false;
          }
        }
      } else {
        return false;
      }
    } while (_M_reader.next(pcappkt));

    if (ippkt) {
      delete ippkt;
    }

    _M_begin = &analyzer::begin_index;
    _M_next = &analyzer::next_index;
    _M_end = &analyzer::end_index;
    _M_prev = &analyzer::prev_index;

    return true;
  }

  return false;
}

bool pcap::ip::analyzer::process_raw(const packet& pcappkt,
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

bool pcap::ip::analyzer::process_linux_sll(const packet& pcappkt,
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

bool pcap::ip::analyzer::begin_iterator(const_iterator& it)
{
  // Get first packet of the PCAP file.
  if (_M_reader.begin(it._M_pcap_packet)) {
    // If the packet can be processed...
    if ((this->*_M_process)(it._M_pcap_packet, &it._M_ip_packet)) {
      // Save a pointer to the IP packet.
      it._M_ippkt = &it._M_ip_packet;

      return true;
    } else {
      return next_iterator(it);
    }
  }

  return false;
}

bool pcap::ip::analyzer::next_iterator(const_iterator& it)
{
  // Get next packet of the PCAP file.
  while (_M_reader.next(it._M_pcap_packet)) {
    // If the packet can be processed...
    if ((this->*_M_process)(it._M_pcap_packet, &it._M_ip_packet)) {
      // Save a pointer to the IP packet.
      it._M_ippkt = &it._M_ip_packet;

      return true;
    }
  }

  return false;
}
