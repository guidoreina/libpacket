#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <stdlib.h>
#include <sys/mman.h>
#include "pcap/packet.h"

namespace pcap {
  // PCAP reader.
  class reader {
    public:
      // Constructor.
      reader() = default;

      // Destructor.
      ~reader() = default;

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
      bool begin(packet& pkt);

      // Get next packet.
      bool next(packet& pkt);

    private:
      // PCAP file.
      class file {
        public:
          // Constructor.
          file() = default;

          // Destructor.
          ~file();

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
          bool begin(packet& pkt);

          // Get next packet.
          bool next(packet& pkt);

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
          file(const file&) = delete;
          file& operator=(const file&) = delete;
      };

      // PCAP stream.
      class stream {
        public:
          // Constructor.
          stream() = default;

          // Destructor.
          ~stream();

          // Open PCAP stream.
          bool open(int fd);

          // Close PCAP stream.
          void close();

          // Get file size.
          size_t filesize() const;

          // Get PCAP file header.
          const pcap::file_header* file_header() const;

          // Get link-layer header type.
          uint32_t linktype() const;

          // Get first packet.
          bool begin(packet& pkt);

          // Get next packet.
          bool next(packet& pkt);

        private:
          // Buffer size.
          static constexpr const size_t buffer_size = 256 * 1024;

          // File descriptor.
          int _M_fd = -1;

          // PCAP file header.
          pcap::file_header _M_file_header;

          // Buffer.
          uint8_t* _M_buf = nullptr;

          // Pointer to the end of the buffer.
          const uint8_t* _M_bufend;

          // Pointer to the end of the data.
          uint8_t* _M_dataend;

          // Pointer to the current packet.
          const uint8_t* _M_pkt = nullptr;

          // Resolution.
          resolution _M_resolution;

          // Read from the stream.
          bool read();

          // Disable copy constructor and assignment operator.
          stream(const stream&) = delete;
          stream& operator=(const stream&) = delete;
      };

      // PCAP file.
      file _M_file;

      // PCAP stream.
      stream _M_stream;

      // Close PCAP file.
      typedef void (reader::*fnclose)();
      fnclose _M_close;

      void file_close();
      void stream_close();

      // Get file size.
      typedef size_t (reader::*fnfilesize)() const;
      fnfilesize _M_filesize;

      size_t file_filesize() const;
      size_t stream_filesize() const;

      // Get PCAP file header.
      typedef const pcap::file_header* (reader::*fnfile_header)() const;
      fnfile_header _M_file_header;

      const pcap::file_header* file_file_header() const;
      const pcap::file_header* stream_file_header() const;

      // Get link-layer header type.
      typedef uint32_t (reader::*fnlinktype)() const;
      fnlinktype _M_linktype;

      uint32_t file_linktype() const;
      uint32_t stream_linktype() const;

      // Get first packet.
      typedef bool (reader::*fnbegin)(packet&);
      fnbegin _M_begin;

      bool file_begin(packet& pkt);
      bool stream_begin(packet& pkt);

      // Get next packet.
      typedef bool (reader::*fnnext)(packet&);
      fnnext _M_next;

      bool file_next(packet& pkt);
      bool stream_next(packet& pkt);

      // Disable copy constructor and assignment operator.
      reader(const reader&) = delete;
      reader& operator=(const reader&) = delete;
  };

  inline void reader::close()
  {
    (this->*_M_close)();
  }

  inline size_t reader::filesize() const
  {
    return (this->*_M_filesize)();
  }

  inline const pcap::file_header* reader::file_header() const
  {
    return (this->*_M_file_header)();
  }

  inline uint32_t reader::linktype() const
  {
    return (this->*_M_linktype)();
  }

  inline bool reader::begin(packet& pkt)
  {
    return (this->*_M_begin)(pkt);
  }

  inline bool reader::next(packet& pkt)
  {
    return (this->*_M_next)(pkt);
  }

  inline reader::file::~file()
  {
    close();
  }

  inline size_t reader::file::filesize() const
  {
    return _M_filesize;
  }

  inline const pcap::file_header* reader::file::file_header() const
  {
    return static_cast<const pcap::file_header*>(_M_base);
  }

  inline uint32_t reader::file::linktype() const
  {
    return file_header()->linktype;
  }

  inline bool reader::file::begin(packet& pkt)
  {
    pkt._M_next = _M_begin;

    return next(pkt);
  }

  inline reader::stream::~stream()
  {
    close();
  }

  inline void reader::stream::close()
  {
    _M_fd = -1;

    if (_M_buf) {
      free(_M_buf);
      _M_buf = nullptr;
    }

    _M_pkt = nullptr;
  }

  inline size_t reader::stream::filesize() const
  {
    return 0;
  }

  inline const pcap::file_header* reader::stream::file_header() const
  {
    return &_M_file_header;
  }

  inline uint32_t reader::stream::linktype() const
  {
    return _M_file_header.linktype;
  }

  inline bool reader::stream::begin(packet& pkt)
  {
    if (!_M_pkt) {
      _M_pkt = _M_buf;
      return next(pkt);
    } else {
      return false;
    }
  }

  inline void reader::file_close()
  {
    _M_file.close();
  }

  inline void reader::stream_close()
  {
    _M_stream.close();
  }

  inline size_t reader::file_filesize() const
  {
    return _M_file.filesize();
  }

  inline size_t reader::stream_filesize() const
  {
    return _M_stream.filesize();
  }

  inline const pcap::file_header* reader::file_file_header() const
  {
    return _M_file.file_header();
  }

  inline const pcap::file_header* reader::stream_file_header() const
  {
    return _M_stream.file_header();
  }

  inline uint32_t reader::file_linktype() const
  {
    return _M_file.linktype();
  }

  inline uint32_t reader::stream_linktype() const
  {
    return _M_stream.linktype();
  }

  inline bool reader::file_begin(packet& pkt)
  {
    return _M_file.begin(pkt);
  }

  inline bool reader::stream_begin(packet& pkt)
  {
    return _M_stream.begin(pkt);
  }

  inline bool reader::file_next(packet& pkt)
  {
    return _M_file.next(pkt);
  }

  inline bool reader::stream_next(packet& pkt)
  {
    return _M_stream.next(pkt);
  }
}

#endif // PCAP_READER_H
