#include <string.h>
#include "net/ip/tcp/segment.h"

bool net::ip::tcp::segment::init(uint32_t seq,
                                 const void* payload,
                                 uint16_t payloadlen)
{
  void* buf = realloc(_M_payload, payloadlen);
  if (buf) {
    memcpy(buf, payload, payloadlen);

    _M_payload = buf;
    _M_payloadlen = payloadlen;

    _M_seq = seq;

    return true;
  }

  return false;
}
