#ifndef NET_IP_STATISTICS_H
#define NET_IP_STATISTICS_H

#include <stdio.h>
#include <time.h>
#include <limits.h>
#include "net/ip/services.h"

namespace net {
  namespace ip {
    // IP statistics.
    class statistics {
      public:
        // Constructor.
        statistics();

        // Destructor.
        ~statistics();

        // Load services from directory.
        bool load(const char* dirname);

        // Generate a CSV file per service?
        bool generate_csv_files(const char* dirname = ".");

        // Generate a PCAP file per service?
        bool generate_pcap_files(const char* dirname = ".");

        // Process packet.
        bool process(const struct iphdr* iphdr,
                     const struct tcphdr* tcphdr,
                     uint16_t pktlen,
                     uint16_t l4len,
                     uint64_t timestamp);

        bool process(const struct iphdr* iphdr,
                     const struct udphdr* udphdr,
                     uint16_t pktlen,
                     uint16_t l4len,
                     uint64_t timestamp);

        bool process(const struct ip6_hdr* iphdr,
                     const struct tcphdr* tcphdr,
                     uint16_t pktlen,
                     uint16_t l4len,
                     uint64_t timestamp);

        bool process(const struct ip6_hdr* iphdr,
                     const struct udphdr* udphdr,
                     uint16_t pktlen,
                     uint16_t l4len,
                     uint64_t timestamp);

        // Print statistics.
        void print() const;

      private:
        // Statistics allocation.
        static constexpr const size_t allocation = 64;

        // CSV field separator.
        static constexpr const char csv_separator = ',';

        // Services.
        services _M_services;

        // Transferred.
        struct transferred {
          // Number of packets transferred.
          uint64_t npackets;

          // Number of bytes transferred.
          uint64_t bytes;

          // Number of bytes of payload transferred.
          uint64_t payload;

          // Clear.
          void clear();
        };

        // Global statistics.
        class global_statistics {
          public:
            // Constructor.
            global_statistics(const char* csv_directory);

            // Destructor.
            ~global_statistics();

            // Process packet.
            bool process(const struct iphdr* iphdr,
                         const struct tcphdr* tcphdr,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            bool process(const struct iphdr* iphdr,
                         const struct udphdr* udphdr,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            bool process(const struct ip6_hdr* iphdr,
                         const struct tcphdr* tcphdr,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            bool process(const struct ip6_hdr* iphdr,
                         const struct udphdr* udphdr,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            // Print global statistics.
            void print() const;

            // Get total transferred.
            const transferred& total_transferred() const;

          private:
            // Directory for the CSV files.
            const char* const _M_csv_directory;

            // Timestamp of the first packet.
            uint64_t _M_timestamp_first_packet = 0;

            // Timestamp of the last packet.
            uint64_t _M_timestamp_last_packet = 0;

            // Total transferred.
            transferred _M_total_transferred = {0, 0, 0};

            // Number of IPv4 packets.
            uint64_t _M_ipv4 = 0;

            // Number of IPv6 packets.
            uint64_t _M_ipv6 = 0;

            // Number of TCP segments.
            uint64_t _M_tcp = 0;

            // Number of UDP datagrams.
            uint64_t _M_udp = 0;

            // Timestamp.
            time_t _M_timestamp = 0;

            // Transferred in the last second.
            transferred _M_transferred = {0, 0, 0};

            // CSV file.
            FILE* _M_csvfile = nullptr;

            // Process packet.
            bool process(uint16_t pktlen, uint16_t l4len, uint64_t timestamp);

            // Open CSV file.
            bool open_csv_file();

            // Dump statistics.
            void dump();

            // Disable copy constructor and assignment operator.
            global_statistics(const global_statistics&) = delete;
            global_statistics& operator=(const global_statistics&) = delete;
        };

        global_statistics _M_global_statistics;

        // Service statistics.
        struct service_statistics {
          service::identifier id;

          // Timestamp of the first packet.
          uint64_t timestamp_first_packet;

          // Timestamp of the last packet.
          uint64_t timestamp_last_packet;

          // Total upload.
          transferred total_upload;

          // Total download.
          transferred total_download;

          // Timestamp.
          time_t timestamp;

          // Upload in the last second.
          transferred upload;

          // Download in the last second.
          transferred download;

          // CSV file.
          FILE* csvfile;

          // PCAP file.
          FILE* pcapfile;
        };

        service_statistics* _M_statistics = nullptr;
        size_t _M_size = 0;
        size_t _M_used = 0;

        // Directory for the CSV files.
        char _M_csv_directory[PATH_MAX] = {0};

        // Directory for the PCAP files.
        char _M_pcap_directory[PATH_MAX] = {0};

        // Process packet.
        bool process(service::identifier id,
                     service::direction dir,
                     const void* pkt,
                     uint16_t pktlen,
                     uint16_t l4len,
                     uint64_t timestamp);

        // Find service.
        bool find(service::identifier id, size_t& pos) const;

        // Allocate service statistics.
        bool allocate();

        // Add CSV header.
        static void add_csv_header(FILE* file);

        // Add line to the CSV file.
        static void add(time_t timestamp,
                        const transferred& upload,
                        const transferred& download,
                        FILE* file);

        // Add PCAP file header.
        static void add_pcap_file_header(FILE* file);

        // Add packet.
        static void add(const void* pkt,
                        uint32_t pktlen,
                        uint64_t timestamp,
                        FILE* file);

        // Timestamp to string.
        static const char* timestamp_to_string(uint64_t timestamp,
                                               char* s,
                                               size_t n);

        static const char* timestamp_to_string(time_t timestamp,
                                               char* s,
                                               size_t n);

        // Compute percentage.
        static float percentage(uint64_t count, uint64_t total);

        // Disable copy constructor and assignment operator.
        statistics(const statistics&) = delete;
        statistics& operator=(const statistics&) = delete;
    };

    inline statistics::statistics()
      : _M_global_statistics(_M_csv_directory)
    {
    }

    inline bool statistics::load(const char* dirname)
    {
      return _M_services.load(dirname);
    }

    inline void statistics::transferred::clear()
    {
      npackets = 0;
      bytes = 0;
      payload = 0;
    }

    inline
    statistics::global_statistics::global_statistics(const char* csv_directory)
      : _M_csv_directory(csv_directory)
    {
    }

    inline statistics::global_statistics::~global_statistics()
    {
      // If the CSV file has been opened...
      if (_M_csvfile) {
        // If some packet was sent or received lately...
        if (_M_transferred.npackets != 0) {
          // Dump statistics.
          dump();
        }

        // Close CSV file.
        fclose(_M_csvfile);
      }
    }

    inline const statistics::transferred&
    statistics::global_statistics::total_transferred() const
    {
      return _M_total_transferred;
    }

    inline float statistics::percentage(uint64_t count, uint64_t total)
    {
      return static_cast<float>((count * 100.0) / total);
    }
  }
}

#endif // NET_IP_STATISTICS_H
