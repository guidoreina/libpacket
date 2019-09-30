#ifndef NET_IP_TCP_DIRECTION_H
#define NET_IP_TCP_DIRECTION_H

namespace net {
  namespace ip {
    namespace tcp {
      // Originator.
      enum class originator {
        client,
        server
      };

      // Direction.
      enum class direction {
        from_client = static_cast<int>(originator::client),
        from_server = static_cast<int>(originator::server)
      };
    }
  }
}

#endif // NET_IP_TCP_DIRECTION_H
