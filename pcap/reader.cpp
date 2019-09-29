#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "pcap/reader.h"

bool pcap::reader::open(const char* filename)
{
  // If the file exists and is big enough to contain the PCAP file header...
  struct stat sbuf;
  if ((stat(filename, &sbuf) == 0) &&
      (S_ISREG(sbuf.st_mode)) &&
      (sbuf.st_size >= static_cast<off_t>(sizeof(pcap::file_header)))) {
    // Open file for reading.
    if ((_M_fd = ::open(filename, O_RDONLY)) != -1) {
      // Map file into memory.
      if ((_M_base = mmap(nullptr,
                          sbuf.st_size,
                          PROT_READ,
                          MAP_SHARED,
                          _M_fd,
                          0)) != MAP_FAILED) {
        // Save file size.
        _M_filesize = sbuf.st_size;

        // Check magic.
        switch (static_cast<magic>(file_header()->magic)) {
          case magic::microseconds:
            _M_resolution = resolution::microseconds;
            break;
          case magic::nanoseconds:
            _M_resolution = resolution::nanoseconds;
            break;
          default:
            return false;
        }

        // Version 2.4?
        if ((file_header()->version_major == version_major) &&
            (file_header()->version_minor == version_minor)) {
          // Make '_M_begin' point to the first packet.
          _M_begin = static_cast<const uint8_t*>(_M_base) +
                     sizeof(pcap::file_header);

          // Make '_M_end' point to the end.
          _M_end = static_cast<const uint8_t*>(_M_base) + _M_filesize;

          return true;
        }
      }
    }
  }

  return false;
}

void pcap::reader::close()
{
  if (_M_base != MAP_FAILED) {
    munmap(_M_base, _M_filesize);
    _M_base = MAP_FAILED;
  }

  if (_M_fd != -1) {
    ::close(_M_fd);
    _M_fd = -1;
  }
}

bool pcap::reader::next(packet& pkt) const
{
  // Make 'data' point to the packet data.
  const uint8_t* const data = pkt._M_next + sizeof(pkthdr);

  // If the packet data is not beyond the end of the file...
  if (data <= _M_end) {
    const pkthdr* const hdr = reinterpret_cast<const pkthdr*>(pkt._M_next);

    // Make 'next' point to the next packet.
    const uint8_t* const next = data + hdr->caplen;

    // If the next packet is not beyond the end of the file...
    if (next <= _M_end) {
      pkt._M_data = data;
      pkt._M_length = hdr->caplen;

      if (_M_resolution == resolution::microseconds) {
        pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) + hdr->ts.tv_usec;
      } else {
        pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) +
                           (hdr->ts.tv_usec / 1000);
      }

      pkt._M_next = next;

      return true;
    }
  }

  return false;
}
