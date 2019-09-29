#ifndef PCAP_PACKET_H
#define PCAP_PACKET_H

#include "pcap/pcap.h"

namespace pcap {
  // PCAP packet.
  class packet {
    friend class reader;

    public:
      // Constructor.
      packet() = default;

      // Destructor.
      ~packet() = default;

      // Get packet header.
      const pkthdr* header() const;

      // Get packet data.
      const void* data() const;

      // Get packet length.
      uint32_t length() const;

      // Get packet timestamp.
      uint64_t timestamp() const;

    private:
      // Pointer to the next packet in the PCAP file.
      const uint8_t* _M_next;

      // Packet data.
      const void* _M_data;

      // Packet length.
      uint32_t _M_length;

      // Packet timestamp, as the number of microseconds since the Epoch,
      // 1970-01-01 00:00:00 +0000 (UTC).
      uint64_t _M_timestamp;
  };

  inline const pkthdr* packet::header() const
  {
    return reinterpret_cast<const pkthdr*>(
             static_cast<const uint8_t*>(_M_data) - sizeof(pkthdr)
           );
  }

  inline const void* packet::data() const
  {
    return _M_data;
  }

  inline uint32_t packet::length() const
  {
    return _M_length;
  }

  inline uint64_t packet::timestamp() const
  {
    return _M_timestamp;
  }
}

#endif // PCAP_PACKET_H
