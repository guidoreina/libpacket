#include <string.h>
#include <sys/param.h>
#include <new>
#include "net/ip/fragmented_packet.h"
#include "net/ip/limits.h"

net::ip::fragmented_packet::result
net::ip::fragmented_packet::add(const void* iphdr,
                                uint16_t iphdrlen,
                                uint32_t id,
                                uint64_t timestamp,
                                uint16_t offset,
                                const void* data,
                                uint16_t len,
                                bool last)
{
  // Start from the end.
  size_t idx = _M_used;
  while (idx > 0) {
    const fragment* cur = _M_fragments[idx - 1];

    // If the offset of the new fragment is bigger than the offset of the
    // current fragment...
    if (offset > cur->offset()) {
      // If the current fragment is not the last fragment and it doesn't overlap
      // with the new fragment...
      if ((!cur->last()) && (cur->offset() + cur->length() <= offset)) {
        break;
      } else {
        return result::invalid_fragment;
      }
    } else if (offset < cur->offset()) {
      // If the new fragment is not the last fragment and it doesn't overlap
      // with the current fragment...
      if ((!last) && (offset + len <= cur->offset())) {
        idx--;
      } else {
        return result::invalid_fragment;
      }
    } else {
      // Return 'duplicated fragment' if the fragments are identical.
      return ((len == cur->length()) && (last == cur->last())) ?
               result::duplicated_fragment :
               result::invalid_fragment;
    }
  }

  // If the packet is not too big...
  if (static_cast<size_t>(
        ((_M_iphdrlen != 0) ? _M_iphdrlen : iphdrlen) + _M_length + len
      ) <= packet_max_len) {
    // Allocate fragment.
    if (allocate()) {
      // Get first free fragment.
      fragment* frag = _M_fragments[_M_used];

      // Fill fragment.
      if (frag->assign(offset, data, len, last)) {
        // If it is the first fragment...
        if (offset == 0) {
          // Save IP header.
          _M_iphdr = iphdr;

          // Save length of the IP header.
          _M_iphdrlen = iphdrlen;

          // Save identifier.
          _M_id = id;

          // Save timestamp.
          _M_timestamp = timestamp;
        } else if (_M_used == 0) {
          // Save identifier.
          _M_id = id;

          // Save timestamp.
          _M_timestamp = timestamp;
        }

        // If not the last fragment...
        if (idx < _M_used) {
          // Make space for the new fragment (move fragments to the right).
          memmove(_M_fragments + idx + 1,
                  _M_fragments + idx,
                  (_M_used - idx) * sizeof(fragment*));
        }

        _M_fragments[idx] = frag;

        // Increment number of fragments.
        _M_used++;

        // Increment total length of the fragmented packet.
        _M_length += len;

        // Get a pointer to the last fragment.
        const fragment* last = _M_fragments[_M_used - 1];

        return ((!last->last()) ||
                (_M_length < last->offset() + last->length())) ?
                 result::success :
                 result::complete;
      } else {
        return result::no_memory;
      }
    } else {
      return result::no_memory;
    }
  } else {
    return result::invalid_fragment;
  }
}

bool net::ip::fragmented_packet::allocate()
{
  // If there are available fragments...
  if (_M_used < _M_size) {
    return true;
  } else {
    for (size_t count = MIN(fragment_allocation, max_fragments - _M_used);
         count > 0;
         count--) {
      if ((_M_fragments[_M_size] = new (std::nothrow) fragment()) != nullptr) {
        _M_size++;
      } else {
        break;
      }
    }

    return (_M_used < _M_size);
  }
}
