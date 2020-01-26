#ifndef NET_IP_DNS_MESSAGE_H
#define NET_IP_DNS_MESSAGE_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "net/ip/limits.h"

namespace net {
  namespace ip {
    namespace dns {
      // DNS port in network byte order.
      static constexpr const uint16_t port = static_cast<uint16_t>(53) << 8;

      // DNS message.
      class message {
        public:
          // Maximum number of responses.
          static constexpr const size_t max_responses = 32;

          // Constructor.
          message() = default;

          // Destructor.
          ~message() = default;

          // Parse DNS message.
          bool parse(const void* buf, size_t len);

          // Get query type.
          uint8_t qtype() const;

          // Get domain.
          const char* domain() const;
          const char* domain(size_t& len) const;

          // Get number of responses.
          size_t number_responses() const;

          // DNS response.
          struct response {
            int family; // AF_INET or AF_INET6.

            union {
              uint8_t addr[sizeof(struct in6_addr)];
              uint32_t addr4;
              struct in6_addr addr6;
            };
          };

          // Get response.
          const struct response* response(size_t idx) const;

        private:
          // Maximum length of a DNS message.
          static constexpr const size_t max_len = 512;

          // Length of the DNS header.
          static constexpr const size_t header_len = 12;

          // Maximum number of DNS pointers.
          static constexpr const size_t max_pointers = 64;

          // Message buffer.
          const uint8_t* _M_buf;

          // Message length.
          size_t _M_len;

          // Current offset.
          size_t _M_off;

          // Query type.
          uint8_t _M_qtype = 0;

          // Domain length.
          uint8_t _M_domainlen = 0;

          // Domain.
          char _M_domain[domain_name_max_len + 1] = {0};

          // # of DNS responses.
          uint8_t _M_nresponses = 0;

          // DNS responses.
          struct response _M_responses[max_responses];

          // Skip question.
          bool skip_question();

          // Parse domain-name.
          bool parse_domain_name();

          // Skip domain-name.
          bool skip_domain_name();
      };

      inline uint8_t message::qtype() const
      {
        return _M_qtype;
      }

      inline const char* message::domain() const
      {
        return _M_domain;
      }

      inline const char* message::domain(size_t& len) const
      {
        len = _M_domainlen;
        return _M_domain;
      }

      inline size_t message::number_responses() const
      {
        return _M_nresponses;
      }

      inline const struct message::response* message::response(size_t idx) const
      {
        return (idx < _M_nresponses) ? &_M_responses[idx] : nullptr;
      }

      inline bool message::skip_question()
      {
        if ((skip_domain_name()) && (_M_off + 4 <= _M_len)) {
          _M_off += 4;

          return true;
        } else {
          return false;
        }
      }
    }
  }
}

#endif // NET_IP_DNS_MESSAGE_H
