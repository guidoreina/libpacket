#ifndef NET_IP_TCP_SEGMENTS_H
#define NET_IP_TCP_SEGMENTS_H

#include "net/ip/tcp/segment.h"

namespace net {
  namespace ip {
    namespace tcp {
      // Segment allocator.
      class segments {
        public:
          // Constructor.
          segments() = default;

          // Destructor.
          ~segments();

          // Clear.
          void clear();

          // Push segment.
          void push(segment* s);

          // Pop segment.
          segment* pop();

        private:
          // Segment allocation.
          static constexpr const size_t segment_allocation = 1024;

          segment* _M_segments = nullptr;

          // Allocate segments.
          bool allocate();

          // Disable copy constructor and assignment operator.
          segments(const segments&) = delete;
          segments& operator=(const segments&) = delete;
      };

      inline segments::~segments()
      {
        clear();
      }

      inline void segments::push(segment* s)
      {
        s->next(_M_segments);
        _M_segments = s;
      }

      inline segment* segments::pop()
      {
        if ((_M_segments) || (allocate())) {
          segment* s = _M_segments;
          _M_segments = _M_segments->next();

          return s;
        }

        return nullptr;
      }
    }
  }
}

#endif // NET_IP_TCP_SEGMENTS_H
