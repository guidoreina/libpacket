#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <sys/mman.h>
#include "pcap/packet.h"

namespace pcap {
  // PCAP reader.
  class reader {
    public:
      // Constructor.
      reader() = default;

      // Destructor.
      ~reader();

      // Open PCAP file.
      bool open(const char* filename);

      // Close PCAP file.
      void close();

      // Get file size.
      size_t filesize() const;

      // Get PCAP file header.
      const pcap::file_header* file_header() const;

      // Get link-layer header type.
      uint32_t linktype() const;

      // Get first packet.
      bool begin(packet& pkt) const;

      // Get next packet.
      bool next(packet& pkt) const;

    private:
      // File descriptor.
      int _M_fd = -1;

      // Pointer to the mapped area.
      void* _M_base = MAP_FAILED;

      // Size of the file.
      size_t _M_filesize;

      // Pointer to the end.
      const uint8_t* _M_end;

      // Pointer to the first packet.
      const uint8_t* _M_begin;

      // Resolution.
      resolution _M_resolution;

      // Disable copy constructor and assignment operator.
      reader(const reader&) = delete;
      reader& operator=(const reader&) = delete;
  };

  inline reader::~reader()
  {
    close();
  }

  inline size_t reader::filesize() const
  {
    return _M_filesize;
  }

  inline const pcap::file_header* reader::file_header() const
  {
    return static_cast<const pcap::file_header*>(_M_base);
  }

  inline uint32_t reader::linktype() const
  {
    return file_header()->linktype;
  }

  inline bool reader::begin(packet& pkt) const
  {
    pkt._M_next = _M_begin;

    return next(pkt);
  }
}

#endif // PCAP_READER_H
