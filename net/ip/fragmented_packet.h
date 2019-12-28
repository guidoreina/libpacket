#ifndef NET_IP_FRAGMENTED_PACKET_H
#define NET_IP_FRAGMENTED_PACKET_H

#include "net/ip/fragment.h"

namespace net {
  namespace ip {
    // IP fragmented packet.
    class fragmented_packet {
      public:
        // Maximum age of a fragmented packet (in microseconds).
        static constexpr const uint64_t max_age = 30 * 1000000ull;

        // Constructor.
        fragmented_packet() = default;

        // Destructor.
        ~fragmented_packet();

        // Clear.
        void clear();

        // Add fragment.
        enum class result {
          invalid_fragment,
          duplicated_fragment,
          no_memory,
          success,
          complete
        };

        result add(const void* iphdr,
                   uint16_t iphdrlen,
                   uint32_t id,
                   uint64_t timestamp,
                   uint16_t offset,
                   const void* data,
                   uint16_t len,
                   bool last);

        // Get IP header of the first fragment.
        const void* ip_header() const;

        // Get length of the IP header of the first fragment.
        uint16_t ip_header_length() const;

        // Get identifier.
        uint32_t id() const;

        // Get timestamp.
        uint64_t timestamp() const;

        // Get fragment.
        const fragment* get(size_t idx) const;

        // Get total length of the fragmented packet.
        uint16_t total_length() const;

      private:
        // Maximum number of fragments.
        static constexpr const size_t max_fragments = 8 * 1024;

        // Fragment allocation.
        static constexpr const size_t fragment_allocation = 8;

        // IP header of the first fragment.
        const void* _M_iphdr;

        // Length of the IP header of the first fragment.
        uint16_t _M_iphdrlen = 0;

        // Identifier.
        uint32_t _M_id;

        // Timestamp of the first fragment.
        uint64_t _M_timestamp;

        // Fragments.
        fragment* _M_fragments[max_fragments];

        // Number of allocated fragments.
        size_t _M_size = 0;

        // Number of fragments in use.
        size_t _M_used = 0;

        // Data length.
        uint16_t _M_length = 0;

        // Allocate fragments.
        bool allocate();

        // Disable copy constructor and assignment operator.
        fragmented_packet(const fragmented_packet&) = delete;
        fragmented_packet& operator=(const fragmented_packet&) = delete;
    };

    inline fragmented_packet::~fragmented_packet()
    {
      for (size_t i = _M_size; i > 0; i--) {
        delete _M_fragments[i - 1];
      }
    }

    inline void fragmented_packet::clear()
    {
      _M_iphdrlen = 0;
      _M_used = 0;
      _M_length = 0;
    }

    inline const void* fragmented_packet::ip_header() const
    {
      return _M_iphdr;
    }

    inline uint16_t fragmented_packet::ip_header_length() const
    {
      return _M_iphdrlen;
    }

    inline uint32_t fragmented_packet::id() const
    {
      return _M_id;
    }

    inline uint64_t fragmented_packet::timestamp() const
    {
      return _M_timestamp;
    }

    inline const fragment* fragmented_packet::get(size_t idx) const
    {
      return (idx < _M_used) ? _M_fragments[idx] : nullptr;
    }

    inline uint16_t fragmented_packet::total_length() const
    {
      return _M_iphdrlen + _M_length;
    }
  }
}

#endif // NET_IP_FRAGMENTED_PACKET_H
