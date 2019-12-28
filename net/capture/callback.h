#ifndef NET_CAPTURE_CALLBACK_H
#define NET_CAPTURE_CALLBACK_H

#include <stdint.h>
#include <time.h>

namespace net {
  namespace capture {
    // Ethernet frame callback.
    typedef void (*ethernetfn_t)(const void* buf,
                                 uint32_t len,
                                 const struct timeval& timestamp,
                                 void* user);
  }
}

#endif // NET_CAPTURE_CALLBACK_H
