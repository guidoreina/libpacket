#ifndef PCAP_LIVE_READER_H
#define PCAP_LIVE_READER_H

#include <stdlib.h>
#include <unistd.h>
#include "pcap/packet.h"
#include "net/ip/limits.h"

namespace pcap {
  // PCAP file live reader.
  class live_reader {
    public:
      // Constructor.
      live_reader() = default;

      // Destructor.
      ~live_reader();

      // Open PCAP file.
      bool open(const char* filename);

      // Close PCAP file.
      void close();

      // Get link-layer header type.
      uint32_t linktype() const;

      // Read packet.
      bool read(packet& pkt);

      // Clear error.
      void clearerr();

      // End of file?
      bool feof() const;

      // Error?
      bool ferror() const;

      // Get file descriptor.
      int fileno() const;

    private:
      // Buffer size.
      static constexpr const size_t buffer_size = sizeof(pkthdr) +
                                                  net::ip::packet_max_len;

      // File descriptor.
      int _M_fd = -1;

      // End of file?
      bool _M_eof;

      // Error?
      bool _M_error;

      // Buffer where to read from the file.
      uint8_t* _M_buf = nullptr;

      // Buffer end.
      const uint8_t* _M_bufend;

      // Data begin.
      const uint8_t* _M_begin;

      // Data end.
      uint8_t* _M_end;

      // State.
      enum class state {
        reading_file_header,
        reading_packet_header,
        reading_packet_data
      };

      state _M_state;

      // Link-layer header type.
      uint32_t _M_link_type;

      // Resolution.
      resolution _M_resolution;

      // Total length of the record.
      uint32_t _M_record_length;

      // Read file header.
      bool read_file_header();

      // Read packet header.
      bool read_packet_header();

      // Read packet data.
      bool read_packet_data();

      // Read from the file.
      bool read();

      // Shift data to the left.
      void shift_data_left();

      // Is a PCAP file?
      bool is_pcap();

      // Disable copy constructor and assignment operator.
      live_reader(const live_reader&) = delete;
      live_reader& operator=(const live_reader&) = delete;
  };

  inline live_reader::~live_reader()
  {
    // Close file.
    close();

    if (_M_buf) {
      free(_M_buf);
    }
  }

  inline void live_reader::close()
  {
    if (_M_fd != -1) {
      ::close(_M_fd);
      _M_fd = -1;
    }
  }

  inline uint32_t live_reader::linktype() const
  {
    return _M_link_type;
  }

  inline void live_reader::clearerr()
  {
    _M_eof = false;
    _M_error = false;
  }

  inline bool live_reader::feof() const
  {
    return _M_eof;
  }

  inline bool live_reader::ferror() const
  {
    return _M_error;
  }

  inline int live_reader::fileno() const
  {
    return _M_fd;
  }
}

#endif // PCAP_LIVE_READER_H
