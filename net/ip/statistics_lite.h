#ifndef NET_IP_STATISTICS_LITE_H
#define NET_IP_STATISTICS_LITE_H

#include <stdio.h>
#include <time.h>
#include "net/ip/services.h"
#include "net/ip/address_list.h"

namespace net {
  namespace ip {
    // IP statistics lite.
    // Generates a single CSV file for all the services.
    class statistics_lite {
      public:
        // Constructor.
        statistics_lite() = default;

        // Destructor.
        ~statistics_lite() = default;

        // Load services from directory.
        bool load(const char* dirname);

        // Open CSV file.
        bool open(const char* filename);

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

        // Dump statistics (if needed).
        void dump(time_t t);

        // Print statistics.
        void print() const;

      private:
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
            global_statistics() = default;

            // Destructor.
            ~global_statistics() = default;

            // Process packet.
            void process(uint16_t pktlen, uint16_t l4len, uint64_t timestamp);

            // Print global statistics.
            void print() const;

            // Get transferred.
            const statistics_lite::transferred& transferred() const;

          private:
            // Timestamp of the first packet.
            uint64_t _M_timestamp_first_packet = 0;

            // Timestamp of the last packet.
            uint64_t _M_timestamp_last_packet = 0;

            // Transferred.
            statistics_lite::transferred _M_transferred = {0, 0, 0};
        };

        global_statistics _M_global_statistics;

        // Service statistics.
        class service_statistics {
          public:
            // Constructor.
            service_statistics() = default;

            // Destructor.
            ~service_statistics();

            // Open CSV file.
            bool open(const char* filename);

            // Process packet.
            bool process(service::direction dir,
                         const struct iphdr* iphdr,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            bool process(service::direction dir,
                         const struct ip6_hdr* iphdr,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            // Dump statistics (if needed).
            void dump(time_t t);

            // Print statistics.
            void print(const transferred& transferred) const;

            // Empty?
            bool empty() const;

          private:
            // CSV file.
            FILE* _M_csvfile = nullptr;

            // Timestamp of the first packet.
            uint64_t _M_timestamp_first_packet = 0;

            // Timestamp of the last packet.
            uint64_t _M_timestamp_last_packet = 0;

            // Total upload.
            transferred _M_total_upload = {0, 0, 0};

            // Total download.
            transferred _M_total_download = {0, 0, 0};

            // Timestamp.
            time_t _M_timestamp = 0;

            // Upload in the last second.
            transferred _M_upload = {0, 0, 0};

            // Download in the last second.
            transferred _M_download = {0, 0, 0};

            // IP addresses.
            address_list _M_addresses;

            // Process packet.
            void process(service::direction dir,
                         uint16_t pktlen,
                         uint16_t l4len,
                         uint64_t timestamp);

            // Add CSV header.
            void add_csv_header();

            // Add line to the CSV file.
            void add_line();

            // Disable copy constructor and assignment operator.
            service_statistics(const service_statistics&) = delete;
            service_statistics& operator=(const service_statistics&) = delete;
        };

        service_statistics _M_statistics;

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
        statistics_lite(const statistics_lite&) = delete;
        statistics_lite& operator=(const statistics_lite&) = delete;
    };

    inline bool statistics_lite::load(const char* dirname)
    {
      return _M_services.load(dirname);
    }

    inline bool statistics_lite::open(const char* filename)
    {
      return _M_statistics.open(filename);
    }

    inline void statistics_lite::dump(time_t t)
    {
      _M_statistics.dump(t);
    }

    inline void statistics_lite::transferred::clear()
    {
      npackets = 0;
      bytes = 0;
      payload = 0;
    }

    inline const statistics_lite::transferred&
    statistics_lite::global_statistics::transferred() const
    {
      return _M_transferred;
    }

    inline bool statistics_lite::service_statistics::empty() const
    {
      return ((_M_total_upload.npackets == 0) &&
              (_M_total_download.npackets == 0));
    }

    inline float statistics_lite::percentage(uint64_t count, uint64_t total)
    {
      return static_cast<float>((count * 100.0) / total);
    }
  }
}

#endif // NET_IP_STATISTICS_LITE_H
