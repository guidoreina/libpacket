#ifndef PCAP_IP_ANALYZER_H
#define PCAP_IP_ANALYZER_H

#include "pcap/reader.h"
#include "net/ip/parser.h"
#include "net/ip/packets.h"
#include "net/ip/protocol.h"
#include "net/ip/limits.h"

namespace pcap {
  namespace ip {
    // IP analyzer.
    class analyzer {
      public:
        // Constructor.
        analyzer() = default;

        // Destructor.
        ~analyzer() = default;

        // Open PCAP file.
        bool open(const char* filename);

        // Close PCAP file.
        void close();

        // Read all packets.
        // Parses all the packets in the PCAP file and builds a list of
        // IP packets.
        // It is not mandatory to call this method.
        bool read_all();

        // Get number of packets (available when the method read_all() has been
        // called).
        size_t count() const;

        // Get packet at position (available when the method read_all() has been
        // called).
        const net::ip::packet* get(size_t idx) const;

        // Constant iterator.
        class const_iterator {
          friend class analyzer;

          public:
            // Constructor.
            const_iterator() = default;

            // Copy constructor.
            const_iterator(const const_iterator& it);

            // Destructor.
            ~const_iterator() = default;

            // Assignment operator.
            const_iterator& operator=(const const_iterator& it);

            // Get a pointer to the IP packet.
            const net::ip::packet* operator->() const;

            // Get a reference to the IP packet.
            const net::ip::packet& operator*() const;

          private:
            // PCAP packet (used to iterate the packets when the method
            // read_all() has not been called).
            packet _M_pcap_packet;

            // Packet index (used to iterate the packets when the method
            // read_all() has been called).
            size_t _M_pktidx = 0;

            // IP packet (set when the method read_all() has not been called).
            net::ip::packet _M_ip_packet;

            // Pointer to the IP packet.
            const net::ip::packet* _M_ippkt = nullptr;
        };

        // Get first packet.
        bool begin(const_iterator& it);

        // Get next packet.
        bool next(const_iterator& it);

        // Get first packet which matches the protocol.
        bool begin(net::ip::protocol protocol, const_iterator& it);

        // Get next packet which matches the protocol.
        bool next(net::ip::protocol protocol, const_iterator& it);

        // Get last packet (available when the method read_all() has been
        // called).
        bool end(const_iterator& it);

        // Get previous packet (available when the method read_all() has been
        // called).
        bool prev(const_iterator& it);

      private:
        // PCAP reader.
        reader _M_reader;

        // IP parser.
        net::ip::parser _M_parser;

        // IP packets (filled when the method read_all() has been called).
        net::ip::packets _M_packets;

        // Process function.
        typedef bool (analyzer::*fnprocess)(const packet& pcappkt,
                                            net::ip::packet* ippkt);

        fnprocess _M_process;

        // Iterate function.
        typedef bool (analyzer::*fniterate)(const_iterator& it);
        fniterate _M_begin;
        fniterate _M_next;
        fniterate _M_end;
        fniterate _M_prev;

        // Process ethernet packet.
        bool process_ethernet(const packet& pcappkt, net::ip::packet* ippkt);

        // Process raw packet.
        bool process_raw(const packet& pcappkt, net::ip::packet* ippkt);

        // Process Linux SLL packet.
        bool process_linux_sll(const packet& pcappkt, net::ip::packet* ippkt);

        // Get first packet based on iterator.
        bool begin_iterator(const_iterator& it);

        // Get next packet based on iterator.
        bool next_iterator(const_iterator& it);

        // Get last packet based on iterator (not supported).
        bool end_iterator(const_iterator& it);

        // Get previous packet based on iterator (not supported).
        bool prev_iterator(const_iterator& it);

        // Get first packet based on index.
        bool begin_index(const_iterator& it);

        // Get next packet based on index.
        bool next_index(const_iterator& it);

        // Get last packet based on index.
        bool end_index(const_iterator& it);

        // Get previous packet based on index.
        bool prev_index(const_iterator& it);

        // Disable copy constructor and assignment operator.
        analyzer(const analyzer&) = delete;
        analyzer& operator=(const analyzer&) = delete;
    };

    inline void analyzer::close()
    {
      _M_reader.close();
    }

    inline size_t analyzer::count() const
    {
      return _M_packets.count();
    }

    inline const net::ip::packet* analyzer::get(size_t idx) const
    {
      return _M_packets.get(idx);
    }

    inline analyzer::const_iterator::const_iterator(const const_iterator& it)
      : _M_pcap_packet(it._M_pcap_packet),
        _M_pktidx(it._M_pktidx)
    {
    }

    inline analyzer::const_iterator&
    analyzer::const_iterator::operator=(const const_iterator& it)
    {
      _M_pcap_packet = it._M_pcap_packet;
      _M_pktidx = it._M_pktidx;

      return *this;
    }

    inline const net::ip::packet* analyzer::const_iterator::operator->() const
    {
      return _M_ippkt;
    }

    inline const net::ip::packet& analyzer::const_iterator::operator*() const
    {
      return *_M_ippkt;
    }

    inline bool analyzer::begin(const_iterator& it)
    {
      return (this->*_M_begin)(it);
    }

    inline bool analyzer::next(const_iterator& it)
    {
      return (this->*_M_next)(it);
    }

    inline bool analyzer::begin(net::ip::protocol protocol, const_iterator& it)
    {
      // Get first packet of the PCAP file.
      if (begin(it)) {
        return (it._M_ippkt->protocol() == static_cast<uint8_t>(protocol)) ?
                 true :
                 next(protocol, it);
      }

      return false;
    }

    inline bool analyzer::next(net::ip::protocol protocol, const_iterator& it)
    {
      while (next(it)) {
        // If it is the protocol we are searching for...
        if (it._M_ippkt->protocol() == static_cast<uint8_t>(protocol)) {
          return true;
        }
      }

      return false;
    }

    inline bool analyzer::end(const_iterator& it)
    {
      return (this->*_M_end)(it);
    }

    inline bool analyzer::prev(const_iterator& it)
    {
      return (this->*_M_prev)(it);
    }

    inline bool analyzer::process_ethernet(const packet& pcappkt,
                                           net::ip::packet* ippkt)
    {
      return ((pcappkt.length() <= net::ip::packet_max_len) &&
              (_M_parser.process_ethernet(pcappkt.data(),
                                          pcappkt.length(),
                                          pcappkt.timestamp(),
                                          ippkt)));
    }

    inline bool analyzer::end_iterator(const_iterator& it)
    {
      // Not supported.
      return false;
    }

    inline bool analyzer::prev_iterator(const_iterator& it)
    {
      // Not supported.
      return false;
    }

    inline bool analyzer::begin_index(const_iterator& it)
    {
      return ((it._M_ippkt = _M_packets.get(it._M_pktidx = 0)) != nullptr);
    }

    inline bool analyzer::next_index(const_iterator& it)
    {
      return ((it._M_ippkt = _M_packets.get(++it._M_pktidx)) != nullptr);
    }

    inline bool analyzer::end_index(const_iterator& it)
    {
      return (count() > 0) ?
               ((it._M_ippkt = _M_packets.get(it._M_pktidx = count() - 1)) !=
                nullptr) :
               false;
    }

    inline bool analyzer::prev_index(const_iterator& it)
    {
      return (it._M_pktidx > 0) ?
               ((it._M_ippkt = _M_packets.get(--it._M_pktidx)) != nullptr) :
               false;
    }
  }
}

#endif // PCAP_IP_ANALYZER_H
