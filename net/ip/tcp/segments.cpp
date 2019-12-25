#include <new>
#include "net/ip/tcp/segments.h"

void net::ip::tcp::segments::clear()
{
  while (_M_segments) {
    segment* next = _M_segments->next();

    delete _M_segments;

    _M_segments = next;
  }
}

bool net::ip::tcp::segments::allocate()
{
  for (size_t i = segment_allocation; i > 0; i--) {
    // Create segment.
    segment* s = new (std::nothrow) segment();

    // If the segment could be allocated...
    if (s) {
      // Push segment.
      push(s);
    } else {
      break;
    }
  }

  return (_M_segments != nullptr);
}
