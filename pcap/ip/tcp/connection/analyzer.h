#ifndef PCAP_IP_TCP_CONNECTION_ANALYZER_H
#define PCAP_IP_TCP_CONNECTION_ANALYZER_H

#include "pcap/ip/analyzer.h"
#include "net/ip/tcp/connection.h"
#include "net/ip/tcp/message.h"

namespace pcap {
  namespace ip {
    namespace tcp {
      namespace connection {
        // TCP connection analyzer.
        class analyzer {
          public:
            // Constructor.
            analyzer(ip::analyzer& analyzer);

            // Destructor.
            ~analyzer() = default;

            // Constant connection iterator.
            class const_iterator {
              friend class analyzer;

              public:
                // Constructor.
                const_iterator();

                // Destructor.
                ~const_iterator() = default;

                // Get a pointer to the TCP connection.
                const net::ip::tcp::connection* operator->() const;

                // Get a reference to the TCP connection.
                const net::ip::tcp::connection& operator*() const;

                // Get a pointer to the SYN packet.
                const net::ip::packet* syn() const;

                // Get a pointer to the SYN + ACK packet.
                const net::ip::packet* syn_ack() const;

                // Get a pointer to the ACK packet.
                const net::ip::packet* ack() const;

                // Get client message.
                const net::ip::tcp::message*
                client_message(ip::analyzer& analyzer);

                const net::ip::tcp::message*
                client_message(ip::analyzer& analyzer,
                               const char* dir,
                               const char* filename = nullptr);

                // Get server message.
                const net::ip::tcp::message*
                server_message(ip::analyzer& analyzer);

                const net::ip::tcp::message*
                server_message(ip::analyzer& analyzer,
                               const char* dir,
                               const char* filename = nullptr);

              private:
                // Iterator for the SYN packet.
                ip::analyzer::const_iterator _M_it_syn;

                // Iterator for the SYN + ACK packet.
                ip::analyzer::const_iterator _M_it_syn_ack;

                // Iterator for the ACK packet.
                ip::analyzer::const_iterator _M_it_ack;

                // TCP connection.
                net::ip::tcp::connection _M_connection;

                // Client message.
                net::ip::tcp::message _M_client_message;

                // Server message.
                net::ip::tcp::message _M_server_message;

                // Get message.
                const net::ip::tcp::message*
                message(ip::analyzer& analyzer,
                        net::ip::tcp::direction dir,
                        net::ip::tcp::message* msg);

                // Disable copy constructor and assignment operator.
                const_iterator(const const_iterator&) = delete;
                const_iterator& operator=(const const_iterator&) = delete;
            };

            // Get first connection.
            bool begin(const_iterator& it);

            // Get next connection.
            bool next(const_iterator& it);

          private:
            // Maximum delay in seconds between two packets of the three-way
            // handshake.
            static constexpr const uint64_t max_delay = 30;

            // IP analyzer.
            ip::analyzer& _M_analyzer;

            // Find next SYN segment.
            bool find_syn(const_iterator& it);

            // Find next SYN + ACK segment.
            bool find_syn_ack(const_iterator& it);

            // Find next ACK segment.
            bool find_ack(const_iterator& it);

            // Disable copy constructor and assignment operator.
            analyzer(const analyzer&) = delete;
            analyzer& operator=(const analyzer&) = delete;
        };

        inline analyzer::analyzer(ip::analyzer& analyzer)
          : _M_analyzer(analyzer)
        {
        }

        inline analyzer::const_iterator::const_iterator()
          : _M_client_message(_M_connection.client(),
                              _M_connection.server(),
                              net::ip::tcp::direction::from_client),
            _M_server_message(_M_connection.client(),
                              _M_connection.server(),
                              net::ip::tcp::direction::from_server)
        {
        }

        inline const net::ip::tcp::connection*
        analyzer::const_iterator::operator->() const
        {
          return &_M_connection;
        }

        inline const net::ip::tcp::connection&
        analyzer::const_iterator::operator*() const
        {
          return _M_connection;
        }

        inline const net::ip::packet* analyzer::const_iterator::syn() const
        {
          return _M_it_syn.operator->();
        }

        inline const net::ip::packet* analyzer::const_iterator::syn_ack() const
        {
          return _M_it_syn_ack.operator->();
        }

        inline const net::ip::packet* analyzer::const_iterator::ack() const
        {
          return _M_it_ack.operator->();
        }

        inline const net::ip::tcp::message*
        analyzer::const_iterator::client_message(ip::analyzer& analyzer)
        {
          // Clear message.
          _M_client_message.clear();

          return message(analyzer,
                         net::ip::tcp::direction::from_client,
                         &_M_client_message);
        }

        inline const net::ip::tcp::message*
        analyzer::const_iterator::client_message(ip::analyzer& analyzer,
                                                 const char* dir,
                                                 const char* filename)
        {
          // Clear message.
          _M_client_message.clear();

          return _M_client_message.pathname(dir, filename) ?
                   message(analyzer,
                           net::ip::tcp::direction::from_client,
                           &_M_client_message) :
                   nullptr;
        }

        inline const net::ip::tcp::message*
        analyzer::const_iterator::server_message(ip::analyzer& analyzer)
        {
          // Clear message.
          _M_server_message.clear();

          return message(analyzer,
                         net::ip::tcp::direction::from_server,
                         &_M_server_message);
        }

        inline const net::ip::tcp::message*
        analyzer::const_iterator::server_message(ip::analyzer& analyzer,
                                                 const char* dir,
                                                 const char* filename)
        {
          // Clear message.
          _M_server_message.clear();

          return _M_server_message.pathname(dir, filename) ?
                   message(analyzer,
                           net::ip::tcp::direction::from_server,
                           &_M_server_message) :
                   nullptr;
        }
      }
    }
  }
}

#endif // PCAP_IP_TCP_CONNECTION_ANALYZER_H
