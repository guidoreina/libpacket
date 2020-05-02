#ifndef PCAP_IP_LIVE_ANALYZER_H
#define PCAP_IP_LIVE_ANALYZER_H

#include "pcap/live_reader.h"
#include "net/ip/parser.h"

namespace pcap {
  namespace ip {
    // IP live analyzer.
    class live_analyzer {
      public:
        // Constructor.
        live_analyzer() = default;

        // Destructor.
        ~live_analyzer() = default;

        // Open PCAP file.
        bool open(const char* filename);

        // Close PCAP file.
        void close();

        // Read packet.
        bool read(net::ip::packet& ippkt);

        // Clear error.
        void clearerr();

        // End of file?
        bool feof() const;

        // Error?
        bool ferror() const;

        // Get file descriptor.
        int fileno() const;

      private:
        // PCAP live reader.
        live_reader _M_reader;

        // IP parser.
        net::ip::parser _M_parser;

        // Error?
        bool _M_error;

        // Process function.
        typedef bool (live_analyzer::*fnprocess)(const packet& pcappkt,
                                                 net::ip::packet* ippkt);

        fnprocess _M_process = nullptr;

        // Process ethernet packet.
        bool process_ethernet(const packet& pcappkt, net::ip::packet* ippkt);

        // Process raw packet.
        bool process_raw(const packet& pcappkt, net::ip::packet* ippkt);

        // Process Linux SLL packet.
        bool process_linux_sll(const packet& pcappkt, net::ip::packet* ippkt);

        // Disable copy constructor and assignment operator.
        live_analyzer(const live_analyzer&) = delete;
        live_analyzer& operator=(const live_analyzer&) = delete;
    };

    inline bool live_analyzer::open(const char* filename)
    {
      // Open PCAP file.
      if (_M_reader.open(filename)) {
        _M_error = false;
        return true;
      }

      return false;
    }

    inline void live_analyzer::close()
    {
      _M_reader.close();
    }

    inline void live_analyzer::clearerr()
    {
      _M_reader.clearerr();
      _M_error = false;
    }

    inline bool live_analyzer::feof() const
    {
      return _M_reader.feof();
    }

    inline bool live_analyzer::ferror() const
    {
      return ((_M_reader.ferror()) || (_M_error));
    }

    inline int live_analyzer::fileno() const
    {
      return _M_reader.fileno();
    }

    inline bool live_analyzer::process_ethernet(const packet& pcappkt,
                                                net::ip::packet* ippkt)
    {
      return ((pcappkt.length() <= net::ip::packet_max_len) &&
              (_M_parser.process_ethernet(pcappkt.data(),
                                          pcappkt.length(),
                                          pcappkt.timestamp(),
                                          ippkt)));
    }
  }
}

#endif // PCAP_IP_LIVE_ANALYZER_H
