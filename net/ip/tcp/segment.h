#ifndef NET_IP_TCP_SEGMENT_H
#define NET_IP_TCP_SEGMENT_H

#include <stdint.h>
#include <stdlib.h>

namespace net {
  namespace ip {
    namespace tcp {
      // TCP segment.
      class segment {
        public:
          // Constructor.
          segment() = default;

          // Destructor.
          ~segment();

          // Clear segment.
          void clear();

          // Initialize.
          bool init(uint32_t seq, const void* payload, uint16_t payloadlen);

          // Get sequence number.
          uint32_t seq() const;

          // Get payload.
          const void* payload() const;

          // Get payload length.
          uint16_t length() const;

          // Get previous segment.
          const segment* prev() const;
          segment* prev();

          // Set previous segment.
          void prev(segment* s);

          // Get next segment.
          const segment* next() const;
          segment* next();

          // Set next segment.
          void next(segment* s);

        private:
          // Sequence number.
          uint32_t _M_seq;

          // Payload.
          void* _M_payload = nullptr;
          uint16_t _M_payloadlen;

          // Previous segment.
          segment* _M_prev;

          // Next segment.
          segment* _M_next;

          // Disable copy constructor and assignment operator.
          segment(const segment&) = delete;
          segment& operator=(const segment&) = delete;
      };

      inline segment::~segment()
      {
        clear();
      }

      inline void segment::clear()
      {
        if (_M_payload) {
          free(_M_payload);
          _M_payload = nullptr;
        }
      }

      inline uint32_t segment::seq() const
      {
        return _M_seq;
      }

      inline const void* segment::payload() const
      {
        return _M_payload;
      }

      inline uint16_t segment::length() const
      {
        return _M_payloadlen;
      }

      inline const segment* segment::prev() const
      {
        return _M_prev;
      }

      inline segment* segment::prev()
      {
        return _M_prev;
      }

      inline void segment::prev(segment* s)
      {
        _M_prev = s;
      }

      inline const segment* segment::next() const
      {
        return _M_next;
      }

      inline segment* segment::next()
      {
        return _M_next;
      }

      inline void segment::next(segment* s)
      {
        _M_next = s;
      }
    }
  }
}

#endif // NET_IP_TCP_SEGMENT_H
